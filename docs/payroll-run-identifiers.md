# Payroll Run Identifiers

This document explains how payroll run IDs are generated, what uniqueness guarantees
they carry, how they map to on-chain events, and how consumers (SDK, dashboard) should
and should not use them.

## Generation

Run IDs are assigned by the `derive_run_id` function inside the payroll contract. A
monotonically increasing counter stored under `DataKey::RunCounter` is read, incremented
by one, persisted back, and returned as the run ID.

```
run_id = RunCounter + 1
RunCounter ← run_id
```

The counter starts at `0` on `initialize`, so the first run is always `1`. IDs are
contiguous and increase by exactly one per successful `batch_process_payroll` call (and
also per `prepare_payroll_run` call, since each reserving operation increments the
counter).

## Deterministic request identifier (#480)

The sequential `run_id` above is only knowable after the transaction lands. To
let a dashboard or SDK reference a run before submitting it, the contract also
exposes a stable, reproducible 32-byte identifier derived from immutable request
fields:

```
identifier = sha256(
    b"zkpayroll_run_identifier_v1"
    || nonce[32]
    || employee_count (u32, big-endian)
    || draft_hash[32]   // 32 zero bytes when no draft hash was supplied
)
```

| Function | Returns | Notes |
|---|---|---|
| `compute_payroll_run_identifier(nonce, employee_count, draft_hash)` | `BytesN<32>` | Pure; no storage or auth. Usable before submission. |
| `get_payroll_run_identifier(run_id)` | `BytesN<32>` | Resolves from a pending or completed run record; panics when unavailable. |
| `get_run_identifier_checked(run_id)` | `Result<BytesN<32>, PayrollRunIdentifierError>` | Checked variant for clients that prefer typed errors. |

Properties:

- **Reproducible off chain.** The encoding above is canonical, so the SDK can
  compute the same value without an RPC call and later assert it matches
  `get_payroll_run_identifier`.
- **Stable across lifecycle changes.** The hash uses only `nonce`,
  `employee_count`, and `draft_hash`, which are immutable after preparation.
  Finalizing, archiving, or transferring a pending run's admin does not change
  the identifier.
- **Unique per run.** The nonce is already enforced as contract-wide unique by
  the preparation and direct execution paths, so no two runs can share an
  identifier. `employee_count` and `draft_hash` additionally bind the identifier
  to the payload shape and reviewed draft.
- **Privacy-safe.** The identifier hashes no salary amount, employee address, or
  commitment value, and `PayrollRunIdentifierError` codes are unit-only:
  `InvalidRunId` (reserved `u64::MAX`) and `RunNotFound`.
- **Availability.** A prepared run that is cancelled leaves no pending or
  completed record, so its identifier is no longer queryable even though the
  nonce stays consumed. Compute and persist the identifier off chain before
  cancelling if it is needed for reconciliation.

## Uniqueness guarantees

| Property | Detail |
|---|---|
| Monotonically increasing | IDs never repeat or decrease within a single contract deployment. |
| Contiguous within a deployment | Gaps can appear if `prepare_payroll_run` is called and the pending run is later cancelled — a run ID is allocated but no `PayrollRun` record is created. |
| Scoped to one contract instance | Two separate deployments of the payroll contract share no ID space. |
| Not a nonce | The run ID is deterministic and predictable; it is not a security primitive. The caller-supplied `nonce` (stored in `RunNonce`) is the replay-protection mechanism. |

## Secondary uniqueness: the nonce

Every successful `batch_process_payroll` call requires a unique 32-byte caller-supplied
`nonce`. Once consumed, a nonce is stored under `DataKey::RunNonce(nonce)` and can never
be reused. The `PayrollRun` struct stores both `run_id` and `nonce` so any audit can
verify uniqueness from either dimension.

## On-chain events

Two events are emitted around execution:

| Event topic | Data payload | When |
|---|---|---|
| `("payroll", "run_executed")` | `(run_id: u64, total_amount: i128)` | After a successful `batch_process_payroll` |
| `("payroll", "run_prepared")` | `(run_id: u64, total_amount: i128)` | After a successful `prepare_payroll_run` |
| `("payroll", "run_cancelled")` | `(run_id: u64, total_amount: i128)` | After a successful `cancel_payroll_run` |
| `("payroll", "run_archived")` | `run_id: u64` | After a successful `archive_payroll_run` |

Consumers listening for `run_executed` should index by `run_id` and cross-check
`total_amount` against the stored `PayrollRun` record to guard against event spoofing.

## Querying runs

| Function | Returns | Notes |
|---|---|---|
| `get_payroll_run(run_id)` | `PayrollRun` | Panics if not found. The primary lookup path. |
| `get_pending_run(run_id)` | `Option<PendingPayrollRun>` | Returns `None` after cancellation or finalization. |
| `get_archived_run(run_id)` | `PayrollRun` | Panics if the run has not been explicitly archived. |
| `is_run_archived(run_id)` | `bool` | Non-panicking archive check. |

## What consumers should and should not derive from run IDs

### Safe uses

- **Record lookup**: use `run_id` as a key to `get_payroll_run`.
- **Event correlation**: match `run_executed` events to stored records by `run_id`.
- **Sequential ordering**: `run_id_A < run_id_B` implies run A was allocated before run B.
- **Audit cross-reference**: the `run_id` stored inside a `PayrollRun` struct must equal
  the key used to retrieve it; any mismatch signals data corruption.

### Unsafe uses

- **Timestamp inference**: do not derive execution time from a run ID. Use the
  `PayrollRun.executed_at` field (ledger timestamp at execution).
- **Existence checks**: a run ID being low does not mean its record exists. Pending runs
  that are cancelled leave no `PayrollRun` record.
- **Amount inference**: run IDs encode no amount information. Always read
  `PayrollRun.total_amount`.
- **Replay protection**: run IDs are deterministic and predictable. Use the `nonce` field
  for replay-protection logic.

## Invariants for run identifiers (#992)

These rules are enforced on chain and covered by focused tests.

- **I1 (reserved sentinel).** `u64::MAX` can never be a valid run ID. It is reserved so
  callers can use it as an explicit sentinel. `validate_run_id_checked` returns
  `PayrollRunIdError::ReservedRunId` for it; the legacy `validate_run_id` still panics.
- **I2 (monotonic, gap-free allocation).** `derive_run_id` reads `RunCounter`, returns
  `counter + 1`, and persists the new value only on success. IDs are allocated strictly
  in increasing order with no gaps from this path. A transaction that fails after
  allocation rolls the counter back with the rest of its storage writes.
- **I3 (exhaustion is non-mutating).** The last allocatable ID is `u64::MAX - 1`. When the
  counter is at or beyond that value, `next_run_id_checked` returns
  `RunCounterExhausted` and does **not** advance storage, so a rejected allocation has
  no side effects and can never hand out the reserved sentinel.
- **I4 (existence is separate from validity).** A syntactically valid ID does not imply a
  stored run. `get_payroll_run_checked` returns `RunNotFound` when no record exists and
  `UnauthorizedArchivedRun` when an archived record is queried by a non-admin. These are
  distinct from `ReservedRunId`.
- **I5 (stable, privacy-safe errors).** All `PayrollRunIdError` codes are unit-only and
  append-only. No amount, employee address, commitment, or caller-supplied identifier is
  echoed back. Off-chain callers that only need a boolean can use `is_valid_run_id`.

The checked helpers are additive: existing panicking entrypoints keep their behavior, so
no current caller is broken by the new error surface.

## Cross-references

- Issue [#146](https://github.com/zkpayroll/zk-payroll-contracts/issues/146): archived
  run query API (`get_archived_run`, `is_run_archived`, `archive_payroll_run`).
- Issue [#103](https://github.com/zkpayroll/zk-payroll-contracts/issues/103): per-run
  nonce uniqueness.
- Issue [#102](https://github.com/zkpayroll/zk-payroll-contracts/issues/102): draft hash
  binding.
- Issue [#177](https://github.com/zkpayroll/zk-payroll-contracts/issues/177): metadata
  hash binding.
- See [reconciliation-states.md](./reconciliation-states.md) for the lifecycle of a
  `PayrollRun` record after execution.
