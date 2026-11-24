# Payroll Period Configuration Freeze Guard

Issue #248 introduces a guard that prevents edits to a payroll period's
configuration once downstream approval or settlement assumptions depend on it.

## Why

A payroll period's settlement window determines when batches may be prepared and
executed. Changing that configuration after a run has been submitted — or after
the period has become settlement-ready — could invalidate approvals and
settlement assumptions that were made against the earlier configuration. The
freeze guard rejects such edits.

## Frozen states

A period's configuration is **frozen** when any of the following holds:

| Condition | Trigger |
| --- | --- |
| Explicit freeze | Admin calls `freeze_period_config(admin, period)`. |
| Submitted run | A payroll run is prepared under the period (`prepare_payroll_run`). |
| Settlement-ready | The period's settlement window has reached `Executable`, `Grace`, or `Closed` status. |

A period with no window configured and no submitted run is **editable** — the
default for backward compatibility.

## Contract entry points

| Entry point | Effect |
| --- | --- |
| `freeze_period_config(admin, period)` | Admin-only. Records an explicit freeze for the period. |
| `get_period_config_state(period)` | Returns `PeriodConfigState::Frozen` when an explicit freeze was recorded, otherwise `Editable`. |
| `is_period_config_frozen(period)` | Returns `true` when the period is frozen by any condition above. |

`set_settlement_window` rejects edits with a frozen period. The explicit freeze
is permanent: there is no unfreeze entry point.

## Calendar overlap detection

`set_settlement_window` also rejects a window whose inclusive range
`[open_at, close_at]` intersects another configured payroll period. Periods may
be configured in any order, and a period may replace its own window provided
the new range does not overlap another period. Sharing an endpoint counts as an
overlap; leave at least one second between a period's `close_at` and the next
period's `open_at`. Overlap failures use payment error code `313` and do not
include payroll amounts or employee data.

## Settlement window boundary invariants (#942)

A configured window must satisfy `open_at <= execution_start <= execution_end
<= close_at`. All timestamps are Unix seconds, and the status is derived from
the current ledger timestamp on each query or execution attempt; the contract
does not persist a prior status. A ledger timestamp rollback therefore
reclassifies the window from the current timestamp rather than retaining a
stale `Closed` state.

| Ledger timestamp | Status | Payroll execution |
| --- | --- | --- |
| `now < execution_start` | `PreOpen` | Rejected. |
| `execution_start <= now <= execution_end` | `Executable` | Accepted, including both endpoints. |
| `execution_end < now <= close_at` | `Grace` | New payroll execution is rejected; eligible pending-run cleanup paths may proceed. |
| `now > close_at` | `Closed` | New payroll execution is rejected; pending runs may be expired once the close boundary has passed. |

The execution interval and close boundary are inclusive at their upper ends:
`execution_end` is still executable, and `close_at` is still in grace. The
first second after either boundary transitions to the next status. Period
windows use inclusive calendar ranges `[open_at, close_at]`, so sharing an
endpoint between two periods is an overlap and configuration is rejected.

Settlement-window enforcement is opt-in. If no window is configured for the
current period, the legacy execution behavior remains available. These rules
depend only on period labels and timestamps; they do not expose employee,
salary, commitment, or proof data.

## Test coverage

`contracts/payroll/tests/period_freeze_guard.rs` covers:

- editable periods still accept configuration edits;
- an explicit admin freeze blocks further edits;
- a settlement-ready period is implicitly frozen;
- submitting a run freezes the period it was prepared under; and
- non-admin freeze attempts are rejected.

`contracts/payroll/tests/settlement_window_enforcement.rs` covers the
execution-start and execution-end boundaries, the first second after the end,
the close boundary and first second after close, plus status recalculation after
a ledger timestamp rollback.
