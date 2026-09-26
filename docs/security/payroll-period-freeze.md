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

## Test coverage

`contracts/payroll/tests/period_freeze_guard.rs` covers:

- editable periods still accept configuration edits;
- an explicit admin freeze blocks further edits;
- a settlement-ready period is implicitly frozen;
- submitting a run freezes the period it was prepared under; and
- non-admin freeze attempts are rejected.
