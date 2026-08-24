# Employee Status Lifecycle

Issue #249 documents the canonical employee status lifecycle that contracts,
SDKs, and dashboards must mirror. The contract source of truth is
`EmployeeStatus` in `contracts/payroll_registry/src/lib.rs`; the machine-readable
mirror is `fixtures/state-machine/employee-status-machine.json`.

## Canonical States

| State | Contract variant | Eligible for payroll | Semantics |
| --- | --- | --- | --- |
| `active` | `Active` (ordinal 0) | Yes | Commitment registered and record complete; included in payroll runs. |
| `inactive` | `Inactive` (ordinal 1) | No | Temporarily ineligible (on leave, suspended, terminated pending off-chain action). |
| `incomplete` | `Incomplete` (ordinal 2) | No | Missing required registration data; never eligible until corrected and marked `active`. |
| *removed* | *(record deleted)* | No | Terminal. The commitment and status entries are erased; reads fall back to `incomplete`. |

New employees added via `add_employee` / `add_employee_by_wallet` start in
`active`. Addresses with no registry entry also read as ineligible.

## Allowed Transitions

All transitions are initiated by the company admin via `set_employee_status`
and require the company admin's authorization. Each accepted transition emits
a lifecycle event carrying `(previous_status, new_status, ledger_sequence, timestamp)`.

| From | To | Event | User-visible meaning |
| --- | --- | --- | --- |
| `active` | `inactive` | `EmployeeDeactivated` | Suspend an employee (leave of absence, suspension). |
| `inactive` | `active` | `EmployeeReactivated` | Reactivate after suspension or return from leave. |
| `active` | `incomplete` | `EmployeeStatusUpdated` | Flag a live record that lost required data. |
| `incomplete` | `active` | `EmployeeStatusUpdated` | Record corrected; employee re-enters payroll. |
| `inactive` | `incomplete` | `EmployeeStatusUpdated` | Escalate a suspension to a data-quality hold. |
| `incomplete` | `inactive` | `EmployeeStatusUpdated` | Downgrade a data-quality hold to a plain suspension. |

Writing the already-current status is an idempotent no-op: storage keeps its
value and **no event is emitted**.

## Blocked Transitions

| Operation | Outcome |
| --- | --- |
| Status change without the company admin's authorization | Rejected (`require_auth` fails). |
| Status change for an unregistered employee | Rejected — panics with `Employee not found`. |
| Status change under an unknown company | Rejected — panics with `Company not found`. |
| Any status change after removal | Rejected — removal is terminal; re-add the employee instead. |

Removal itself (`remove_employee`) hard-deletes both the commitment
(`DataKey::Employee`) and the eligibility entry (`DataKey::EmpStatus`) and
emits `EmployeeRemoved`. A removed address reads back as `Incomplete` and is
permanently ineligible until explicitly re-added, which starts a fresh
`active` lifecycle.

## Payroll Enforcement

`payment_executor::execute_payment` (and therefore `execute_batch_payroll`)
consults `payroll_registry::is_eligible` before verifying proofs or moving
funds:

* **Eligible** — registered and `Active`: payment proceeds.
* **Ineligible** — everything else (`Inactive`, `Incomplete`, removed, or
  never registered): payment aborts with `PaymentError::EmployeeIneligible`
  before any token transfer, so no funds can reach a blocked employee.

For batch execution this means an ineligible entry rejects the run with
`PaymentError::EmployeeIneligible`; entries processed before the rejection
point follow normal per-payment semantics.

## Reference Implementation Tests

The behaviour on this page is pinned by the integration suite in
`tests/employees/`:

| Suite | Coverage |
| --- | --- |
| `status_transitions.rs` | All six allowed transitions, idempotent same-status writes, unauthorized calls, unknown company/employee rejections, removal semantics, lifecycle event payloads. |
| `payroll_eligibility.rs` | Active employees are paid; inactive, incomplete, removed, and unregistered addresses are blocked with no transfer; reactivation and record correction restore payability; batches reject ineligible entries. |

Run them with:

```bash
cargo test -p employee_status_tests
```
