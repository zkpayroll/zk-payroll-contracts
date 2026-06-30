# Contract Event Taxonomy — Issue #96

Defines the canonical event taxonomy for all events emitted by ZK Payroll
contracts. Downstream indexers, dashboards, and SDK consumers should treat
this document as the authoritative naming and categorisation reference.

Pair with [event-severity-mappings.md](./event-severity-mappings.md) for
alert routing guidance.

---

## Category Overview

| Category | ID | Contracts | Purpose |
|----------|----|-----------|---------|
| Onboarding | `ONB` | `payroll_registry`, `salary_commitment` | Company and employee registration lifecycle |
| Funding | `FND` | `payroll` | Treasury deposit and balance management |
| Execution | `EXE` | `payroll`, `payment_executor` | Payroll run and individual payment execution |
| Audit | `AUD` | `audit_module` | Compliance verification and report generation |
| Security | `SEC` | `pause_manager`, `payment_executor` | Pause/unpause, replay protection, auth failures |

---

## ONB — Onboarding Events

These events track the lifecycle of companies and employees entering the system.
They are the expected starting point for any indexer building a roster of active
participants.

### `CommitmentUpdated`

Emitted by `salary_commitment` when a new commitment is stored or an existing
one is updated (compensation change).

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"CommitmentUpdated"` |
| topic[1] | `Address` | Employee address |
| data[0] | `BytesN<32>` | New commitment value (Poseidon hash) |

Notes:
- Also emitted as part of `rotate_commitment`; distinguish from a rotation by
  watching for a subsequent `CommitmentRotated` event in the same ledger.
- The commitment value is a Poseidon hash of `(salary, blinding_factor)` — salary
  amount is NOT recoverable from this value alone.

### `CommitmentRotated`

Emitted by `salary_commitment` when an existing commitment is explicitly rotated
(old commitment revoked, new one stored). The old commitment must no longer be
accepted for future payroll proofs.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"CommitmentRotated"` |
| topic[1] | `Address` | Employee address |
| data[0] | `BytesN<32>` | Old (revoked) commitment |
| data[1] | `BytesN<32>` | New active commitment |

Notes:
- Indexers that cache commitment values MUST update their local state on this event.
- A `CommitmentUpdated` event is also emitted in the same call; the rotation event
  is the authoritative signal that the old value is invalidated.

---

## FND — Funding Events

Funding events track treasury deposits. Indexers monitoring treasury health should
subscribe to this category.

### `deposit`

Emitted by `payroll` when funds are transferred into the treasury.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"payroll"` |
| topic[1] | `Symbol` | `"deposit"` |
| data[0] | `Address` | Source address (depositor) |
| data[1] | `i128` | Token amount deposited (raw units — divide by token decimals for display) |

Notes:
- Requires dual authorisation: the `from` address and the `treasury_owner` must both sign.
- Raw `i128` token units; divide by the token contract's decimal precision before display.

---

## EXE — Execution Events

Execution events represent the core payroll activity. They are the highest-volume
category under normal operations and the primary input for reconciliation.

### `payment_executed`

Emitted by `payroll` for each individual payment within a `batch_process_payroll` call.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"payroll"` |
| topic[1] | `Symbol` | `"payment_executed"` |
| data[0] | `Address` | Employee address |
| data[1] | `i128` | Amount transferred (raw token units) |

Notes:
- One event per employee per batch; correlate with `run_executed` using the `run_id`
  returned by the transaction result.
- The corresponding nullifier is recorded in `salary_commitment` storage in the same
  transaction; a `payment_executed` event without a recorded nullifier indicates a bug.

### `run_executed`

Emitted by `payroll` once per `batch_process_payroll` call after all individual
payments succeed.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"payroll"` |
| topic[1] | `Symbol` | `"run_executed"` |
| data[0] | `u64` | Run ID (monotonically increasing, starts at 1) |
| data[1] | `i128` | Total amount transferred in this run |

Notes:
- Run IDs are contiguous and monotonically increasing. A gap in run IDs signals a
  failed or missing batch — investigate immediately.
- The `PayrollRun` record is queryable on-chain via `get_payroll_run(run_id)`.

### `PayrollProcessed`

Emitted by `payment_executor` for each individual payment executed through the
period-aware path.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"PayrollProcessed"` |
| topic[1] | `u64` | Company ID |
| data[0] | `Address` | Employee address |
| data[1] | `i128` | Amount transferred (raw token units) |
| data[2] | `u32` | Period ID |

Notes:
- Distinguishable from `payment_executed` by the presence of a company ID in the
  topic and a period ID in the data.
- Indexers should track per-period totals: sum `data[1]` across all `PayrollProcessed`
  events sharing the same `topic[1]` (company ID) and `data[2]` (period ID).

### `PeriodCreated`

Emitted by `payment_executor` when a new payroll period is opened for a company.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"PeriodCreated"` |
| topic[1] | `u64` | Company ID |
| data[0] | `u32` | Period ID |

### `PeriodClosed`

Emitted by `payment_executor` when a payroll period is closed. No further payments
can be made in this period after this event.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"PeriodClosed"` |
| topic[1] | `u64` | Company ID |
| data[0] | `u32` | Period ID |

Notes:
- Indexers should mark the period as immutable on receipt of this event.
- Payment volume for this period can be finalised after `PeriodClosed`.

---

## AUD — Audit Events

Audit events are generated by the `audit_module` when compliance operations are
performed. They contain only metadata — salary values are never emitted.

### `AuditSuccessful`

Emitted when an auditor's commitment verification passes.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"AuditSuccessful"` |
| topic[1] | `Address` | Auditor address |
| data[0] | `AuditScope` | Scope discriminant (see encoding below) |
| data[1] | `BytesN<32>` | Keyed commitment value (view-key-masked; not the raw salary commitment) |

`AuditScope` encoding (serialised as `u32`):

| Value | Scope |
|-------|-------|
| `0` | `FullCompany` |
| `1` | `TimeRange` |
| `2` | `EmployeeList` |
| `3` | `AggregateOnly` |

### `AggregateAuditGenerated`

Emitted when an aggregate compliance report is generated. No individual salary
data is included.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"AggregateAuditGenerated"` |
| topic[1] | `Address` | Auditor address |
| data[0] | `Symbol` | Company ID (string symbol) |
| data[1] | `u64` | Period start timestamp |
| data[2] | `u64` | Period end timestamp |

---

## SEC — Security Events

Security events represent operational halts and integrity signals. They should
be treated with the highest priority by monitoring systems. See
[event-severity-mappings.md](./event-severity-mappings.md) for alert levels.

### `PauseManager / paused`

Emitted by `pause_manager` when the system is paused.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"PauseManager"` |
| topic[1] | `Symbol` | `"paused"` |
| data | `()` | No data payload |

Notes:
- All payroll execution halts immediately after this event; `batch_process_payroll`
  and `execute_payment` will panic until unpaused.
- Treat as `CRITICAL` — page on-call immediately (see severity mappings).

### `PauseManager / unpaused`

Emitted by `pause_manager` when the system resumes.

| Field | Type | Description |
|-------|------|-------------|
| topic[0] | `Symbol` | `"PauseManager"` |
| topic[1] | `Symbol` | `"unpaused"` |
| data | `()` | No data payload |

Notes:
- Treat as `HIGH` — verify the root cause of the preceding pause was resolved before
  accepting this event as routine.

---

## Naming Inconsistencies (Known)

The following inconsistencies exist between the two payment paths and should be
accounted for in indexer implementations. They will be addressed in a future
normalisation pass.

| Inconsistency | `payroll` contract | `payment_executor` contract |
|---------------|--------------------|-----------------------------|
| Topic format | Two-symbol tuple `("payroll", "payment_executed")` | Single symbol `"PayrollProcessed"` with company ID in topic[1] |
| Company scoping | No company ID in topic | Company ID in topic[1] |
| Period tracking | No period concept in `payroll` batch path | Period ID in data[2] |
| Nullifier recording | Recorded in `salary_commitment` via cross-contract call | Recorded in `payment_executor` own storage (`DataKey::Nullifier`) |

Indexers consuming both paths should normalise to a common schema keyed by
`(company_id, employee, period, amount, ledger_sequence)`.

---

## Indexer Integration Notes

- All Soroban event topics and data fields are XDR-encoded `ScVal` values. Use
  the Stellar SDK's `EventFilter` to subscribe by contract address and topic.
- Subscribe to events by contract address, not just by topic name, to avoid
  collisions with other contracts using similar symbol names.
- `i128` amounts are raw token units. Divide by the token contract's decimal
  precision before storing or displaying.
- Correlate `payment_executed` events with `run_executed` using the transaction
  hash (both events appear in the same transaction's event list).
- For reconciliation, use `get_payroll_run(run_id)` to read the immutable
  `PayrollRun` record on-chain and compare against indexed payment events.

---

## Related Resources

| Reference | Path |
|-----------|------|
| Event severity mappings | [docs/monitoring/event-severity-mappings.md](./event-severity-mappings.md) |
| Payload examples | [docs/payload-examples.md](../payload-examples.md) |
| SLA operational targets | [docs/SLA_OPERATIONAL_TARGETS.md](../SLA_OPERATIONAL_TARGETS.md) |
| `payroll` contract | `contracts/payroll/src/lib.rs` |
| `payment_executor` contract | `contracts/payment_executor/src/lib.rs` |
| `salary_commitment` contract | `contracts/salary_commitment/src/lib.rs` |
| `audit_module` contract | `contracts/audit_module/src/lib.rs` |
| `pause_manager` contract | `contracts/pause_manager/src/lib.rs` |

---

*Closes Issue [#96](https://github.com/zkpayroll/zk-payroll-contracts/issues/96)*
