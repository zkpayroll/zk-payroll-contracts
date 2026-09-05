# Admin Configuration Locks During Active Payroll Execution (#253)

Admin configuration changes must not undermine a payroll run that is already
in progress. This document covers two related, complementary gates in
`contracts/payroll/src/lib.rs`:

1. **Configuration lock** — while a payroll run is prepared but not yet
   resolved, specific admin configuration changes are rejected.
2. **Company lifecycle state gate** — the company's admin-set lifecycle
   state (`CompanyState`, issue #147) determines whether *new* payroll runs
   may start at all.

## 1. What counts as "active payroll execution"

A payroll run becomes active the moment `prepare_payroll_run` reserves its
nonce and stores a `PendingPayrollRun` (canonical state `submitted`). It
stays active until it is explicitly resolved via `cancel_payroll_run`
(canonical state `cancelled`). The contract tracks how many runs are
currently active in `DataKey::PendingRunCount`; `has_active_payroll_run()`
exposes this as a boolean for clients and dashboards.

Multiple runs can be active at once. The configuration lock stays engaged
until **every** active run has been cancelled — cancelling one of several
does not release it.

## 2. Locked entrypoints

While `has_active_payroll_run()` is `true`, these calls panic with
`"Configuration is locked: a payroll run is currently in progress. Cancel
all pending runs before changing this setting"`:

| Entrypoint | Why it's unsafe mid-run |
| --- | --- |
| `accept_admin_rotation` | Handing off administration mid-run could let a party the run was not authorised under later act on it. |
| `accept_treasury_rotation` | The treasury owner can request deposits and emergency withdrawals; rotating it mid-run could let a new party move funds while the run is pending. |
| `set_asset_allowed` | Changing the payout asset allowlist mid-run could redirect or invalidate a run already validated against the previous allowlist. |
| `set_company_state` | Changing the company's lifecycle state is a policy-level decision that should not be made while a run's outcome is still pending. |

## 3. Deliberately left unlocked (escape hatches)

| Entrypoint | Why it stays available |
| --- | --- |
| `propose_admin_rotation` / `propose_treasury_rotation` | Proposing is inert — nothing changes until the *accept* step, which is locked. |
| `cancel_admin_rotation` / `cancel_treasury_rotation` | Cancelling a proposal only reverts to the status quo. |
| `set_pause_manager` | Pausing is the system-wide emergency stop and must always remain reachable, including while other config is locked. |
| `cancel_payroll_run` | This is the mechanism that *releases* the lock — it must never be blocked by the lock it clears. It also deliberately bypasses the pause check for the same reason (see its doc comment). |
| `update_reconciliation_status` | Resolving an already-executed run's outcome must remain available regardless of other pending runs. |

## 4. Company lifecycle state gate (issue #147)

`CompanyState` (`Active` / `Paused` / `Archived` / `Incomplete`, default
`Active` when never set) now gates whether a *new* run may start:
`prepare_payroll_run` and `batch_process_payroll` both call
`require_company_active` before any other validation, auth check, balance
read, or transfer. Non-`Active` states panic with a state-specific message,
e.g. `"Company is paused; payroll execution is not permitted"`.

`set_company_state` is itself one of the locked entrypoints above, so an
admin cannot pause/archive the company and simultaneously leave an
in-flight run stranded in an ambiguous state — they must resolve (cancel)
pending runs first, or use the always-available pause manager for an
immediate stop.

## 5. Errors and client guidance

See the [Company Setup and Administration](./errors.md#company-setup-and-administration)
table in `docs/errors.md` for the standard retry/recovery classification.
Both gates fail with plain `panic!` messages (non-retryable until the
underlying condition changes — cancel pending runs, or wait for the company
state to be restored to `Active`); neither includes salary amounts,
employee identities, or other private payroll values, so panic messages and
the `has_active_payroll_run()` / `get_company_state()` read-only views are
safe to surface directly in logs, dashboards, and error toasts.

## 6. Tests

- `tests/admin/` (`admin_config_lock_tests`) — configuration lock coverage:
  each locked entrypoint rejected while a run is pending and accepted once
  resolved, the multi-run "lock persists until all runs resolved" edge
  case, and the escape-hatch entrypoints that remain available.
- `tests/state/` (`company_state_gate_tests`) — company lifecycle state gate
  coverage: default-`Active` backward compatibility, rejection under each
  non-`Active` state, and the pause/resume round trip.

```bash
cargo test -p admin_config_lock_tests
cargo test -p company_state_gate_tests
```
