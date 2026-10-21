# Payout Schedule Collision Detection (#621)

The `settlement_window` contract now rejects a payout schedule whose time
window overlaps a window already reserved for the same company. Two overlapping
windows could otherwise both claim the same interval, leaving it ambiguous which
schedule a payout belonged to and making double-payment or mis-dated execution
possible.

This documents the on-chain behavior in
`contracts/settlement_window/src/lib.rs` and the SDK/operator workflow around it.

## What a payout window is

Each settlement period is configured with four timestamps and is treated as the
half-open payout window **`[open_at, close_at)`**:

| Timestamp | Meaning |
|-----------|---------|
| `open_at` | Earliest moment the period accepts commitments/locks. |
| `execute_at` | Earliest moment batch execution is permitted. |
| `grace_until` | Execution deadline; after this only cancellation/expiry. |
| `close_at` | Hard close of the window. |

Because the window is half-open, a period that **ends exactly when the next one
begins** is adjacent, not colliding. Contiguous monthly schedules therefore keep
working unchanged.

## Collision rule

Two windows collide when their intervals overlap:

```
max(new.open_at, existing.open_at) < min(new.close_at, existing.close_at)
```

Collision detection is **scoped per `company_id`** — the same window may be
scheduled by two different companies.

| Existing period phase | Counts as a collision? |
|-----------------------|------------------------|
| `Pending` / `Open` / `Executing` / `Grace` / `Closed` / `Expired` | **Yes** — the window stays reserved |
| `Cancelled` | **No** — cancellation frees the company's schedule slot |

A closed period still reserves its historical window, so a new schedule cannot
be silently back-dated into an interval already used for a payout. Cancelling a
period releases its window for reuse, consistent with `create_period` allowing a
replacement period after a cancellation.

Zero-length windows (`open_at == close_at`) are empty and never collide.

## Entrypoints

### `create_period` — enforcement

`create_period` validates the timestamp ordering, then checks for a collision
**before writing any state**. A colliding call is a pure no-op: no period is
created and the period sequence is not advanced.

| Result | Meaning |
|--------|---------|
| `Ok(SettlementPeriod)` | The window is clear; the period was created. |
| `Err(SettlementError::InvalidWindowConfig)` | Timestamps are not ordered `open ≤ execute ≤ grace ≤ close`. |
| `Err(SettlementError::PayoutScheduleCollision)` | The window overlaps a reserved schedule for this company. |
| `Err(SettlementError::PeriodAlreadyExists)` | A different, non-overlapping period is still active. |

### `check_schedule_available` — pre-flight

Read-only and permissionless, so schedulers and dashboards can check a window
before submitting `create_period`:

```rust
// Ok(()) when clear, Err(PayoutScheduleCollision) when the window is taken.
settlement.check_schedule_available(&company_id, &open_at, &close_at)?;
```

It reads no private payroll data (windows are timing metadata only) and mutates
no state.

## Error reference

| Contract | Code | Variant | Suggested client message |
|----------|------|---------|--------------------------|
| `settlement_window` | `10` | `PayoutScheduleCollision` | "This payout window overlaps an existing schedule for the company. Pick a non-overlapping window or cancel the conflicting period." |

## Event surface

The schedule lifecycle emits only timing/identifier metadata — no salary values,
employee addresses, or commitments:

| Event | Topics | Data |
|-------|--------|------|
| `SettlementWindowInit` | `(Symbol)` | `(admin,)` |
| `SettlementPeriodCreated` | `(Symbol, company_id, period_id)` | `(open_at, execute_at, grace_until, close_at)` |
| `SettlementPhaseChanged` | `(Symbol, company_id, period_id)` | `(phase,)` |
| `SettlementPeriodCancelled` | `(Symbol, company_id, period_id)` | `(timestamp,)` |
| `SettlementPeriodExpired` | `(Symbol, company_id, period_id)` | `(timestamp,)` |

## QA coverage

`contracts/settlement_window/src/lib.rs` tests:

| Test | Path |
|------|------|
| `test_contiguous_schedule_after_close_succeeds` | success — adjacent windows allowed |
| `test_overlapping_schedule_after_close_rejected` | failure — closed period still reserves its window |
| `test_cancelled_schedule_frees_its_window` | edge — cancellation releases the window |
| `test_collision_is_scoped_per_company` | edge — same window, different companies |
| `test_check_schedule_available_preflight` | success/failure — read-only pre-flight |
| `test_zero_length_window_does_not_collide` | edge — empty window never collides |

```bash
cargo test -p settlement_window
```
