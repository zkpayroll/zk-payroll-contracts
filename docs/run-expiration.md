# Payroll Run Expiration (#474)

Prepared-but-unfinalized payroll runs can now expire safely, so stale batches
cannot be submitted or settled long after they were prepared, and their locked
treasury funds return to the available balance.

This documents the on-chain behavior in `contracts/payroll/src/lib.rs`, the
`Expired` state added to the canonical run state machine, and the SDK/dashboard
workflow around it.

## Motivation

`prepare_payroll_run` reserves treasury funds (#343) and marks the run as an
active run for the #253 configuration lock. Before this change, such a run
stayed finalizable forever:

- An operator who prepared a run and walked away left funds locked
  indefinitely and blocked admin rotations, asset allowlist changes, and
  company-state changes (#253).
- A stale run could be finalized weeks later, executing payments whose
  preconditions (treasury balance, asset allowlist, employee roster, reviewer
  approvals) had silently drifted.

Expiration makes "prepared" a bounded state instead of an unbounded one.

## Expiry Policy

Expiration is **opt-in** and backward compatible:

| Operation | Who | Effect |
|-----------|-----|--------|
| `set_run_expiration_policy(admin, max_age_seconds)` | Admin | Enables/updates the policy. `0` disables it (only allowed while no runs are pending). |
| `get_run_expiration_policy()` | Anyone | Returns `Option<PendingRunExpiryPolicy>` (`None` = disabled). |
| `is_payroll_run_expired(run_id)` | Anyone | `true` when the run is pending and `now > prepared_at + max_age_seconds`. |

- Without a policy, runs never expire — existing flows are unchanged.
- A run prepared **before** the policy was set is measured from its own
  `prepared_at`; enabling the policy applies to it immediately.
- The policy cannot be disabled while any run is pending, so a stale run
  cannot be un-expired by removing the policy after the fact.

## Lifecycle

```
prepare_payroll_run            (window elapses)        expire_payroll_run
      │                                │                        │
      ▼                                ▼                        ▼
  submitted ──────────► finalized/executed      submitted ────► expired (terminal)
                ▲                                │
                └── finalize rejected once ──────┘
                    the window has elapsed
```

1. **Inside the window** — nothing changes: the run can be finalized normally
   (`finalize_payroll_run`), cancelled (`cancel_payroll_run`), or simply left
   pending.
2. **Past the window** — `finalize_payroll_run` rejects the run with a panic
   naming the recovery path; `expire_payroll_run(run_id)` becomes available.
3. **Expiry** — permissionless: *any* caller may submit it. The contract
   releases the run's funds reservation (#343), removes the pending record,
   stores a redacted `ExpiredRunRecord`, records the terminal `Expired` state,
   decrements the #253 pending-run counter, and emits `run_expired`.

Expiry deliberately executes **no payments** and transfers **no tokens**. The
run nonce remains burned — a new batch requires a fresh nonce.

## What Is Stored and Emitted (Privacy)

Both the record and the event are redacted by design — the same rule as the
cancellation metadata from #404:

```rust
pub struct ExpiredRunRecord {
    pub run_id: u64,
    pub expired_at: u64,
    pub expired_by: Address,
    pub employee_count: u32,   // metadata only
    pub nonce: BytesN<32>,     // burned binding
    pub draft_hash: BytesN<32>,
    pub is_expired: bool,
}
```

Event: `payroll.run_expired` with payload `(u64 run_id, Address expired_by)`.

No amounts, employee addresses, commitments, or proof material appear in the
record, the event, or the panic messages. `get_expired_run_record(run_id)`
returns the record for dashboards.

## Error Reference

| Error | Meaning | Recovery |
|-------|---------|----------|
| `Run has expired: it was not finalized within the configured window; call expire_payroll_run` | `finalize_payroll_run` was called on a run past its expiry window. | Submit `expire_payroll_run` (anyone can), then prepare a fresh run. |
| `Run has not expired: the configured expiry window has not elapsed` | `expire_payroll_run` was called while the run was still inside its window. | Wait until `is_payroll_run_expired(run_id)` is true, or finalize/cancel instead. |
| `Pending run not found` | The run is not pending (unknown, already finalized, cancelled, or expired). | Refresh state via `get_payroll_run_state`; for expired runs read `get_expired_run_record`. |
| `Cannot disable run expiration while payroll runs are pending` | Admin passed `max_age_seconds = 0` while runs are pending. | Resolve (finalize/cancel/expire) the pending runs first. |

## SDK / Dashboard Guidance

- Subscribe to `payroll.run_expired` alongside `run_cancelled`; treat both as
  terminal resolutions that released a funds reservation.
- Before showing a "Finalize" action, check `is_payroll_run_expired(run_id)`
  when `get_run_expiration_policy()` is `Some` and disable the action with a
  "Run expired" badge instead of surfacing a guaranteed failure.
- A third party can expire your stale runs — do not assume only your operator
  key can resolve them.
- Retry after expiry always means preparing a **new** run with a new nonce.

## Testing

- Contract integration tests: `cargo test -p payroll --test run_expiration`
- Canonical-state conformance: `cargo test -p payroll --lib expired_run_state`
- Event schema snapshot: `cargo test -p event_schema_snapshots payroll`
