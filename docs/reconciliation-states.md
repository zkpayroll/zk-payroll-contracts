# Reconciliation States

This document explains each reconciliation state of a completed payroll run, the valid
transitions between them, what each state means for treasury accounting and employee
payment status, and what conditions cause a run to enter or exit each state.

## Overview

Every `PayrollRun` record carries a `reconciliation_status: ReconciliationStatus` field.
This field tracks whether the off-chain accounting for the run — matching on-chain
transfers to payroll records, ledger entries, and company books — has been completed.

Reconciliation is an **administrative annotation**. It has no effect on the payments
themselves: all employee transfers happen atomically inside `batch_process_payroll`, and
their outcome does not change based on what reconciliation status is later assigned.

## States

### `Unreconciled` (default)

Set automatically when a run is created by `batch_process_payroll`.

**Meaning**: The payroll batch has been executed and all employee transfers are final, but
the off-chain accounting process has not yet confirmed that every disbursed amount is
properly recorded in the company's financial systems.

**Treasury accounting**: Funds have left the treasury contract and been delivered to
employee addresses. The treasury balance has decreased by `total_amount`. No further
action is taken by the contract.

**Employee payment**: Employees have received their payments. This state is invisible to
employees.

**Typical next step**: The reconciliation workflow reads the `run_executed` events and
`PayrollRun` records, matches them against payroll registers and accounting entries, then
transitions the run to `Reconciled` or `Failed`.

### `Reconciled`

Set by the admin via `update_reconciliation_status(admin, run_id, Reconciled)`.

**Meaning**: Off-chain accounting has confirmed that every transfer in this batch is
correctly recorded in the company's books. The run is considered fully settled from both
an on-chain and an off-chain perspective.

**Treasury accounting**: No additional contract action. The reconciliation confirmation is
an off-chain outcome; it is reflected on-chain solely for auditability.

**Employee payment**: No change. Payments already completed at execution.

### `Failed`

Set by the admin via `update_reconciliation_status(admin, run_id, Failed)`.

**Meaning**: The reconciliation process found a discrepancy — for example, a transfer
amount differs from the expected payroll figure, or an employee address is incorrect in
the company's system. The run needs investigation.

**Treasury accounting**: Funds have already been disbursed. A `Failed` reconciliation
status does not trigger any on-chain reversal; remediation (if required) must be handled
through the emergency withdrawal flow or a corrective payroll run.

**Employee payment**: No change. Payments already completed at execution. A `Failed`
status signals an accounting issue, not a payment reversal.

## State transitions

Any transition is permitted by the contract: the admin can move between any pair of
states freely, including `Reconciled → Failed` (re-opening a settled run) or
`Failed → Reconciled` (clearing an investigation). There is no enforced state machine at
the contract level.

```
                     update_reconciliation_status
                     ↓
  (execution) → Unreconciled ⇆ Reconciled ⇆ Failed
                     ↑______________↑______________↑
                        (any direction, admin only)
```

The practical workflow most teams follow is linear:

```
Unreconciled → Reconciled
     └─── (if discrepancy found) → Failed → (after resolution) → Reconciled
```

## Authorization

Only the `admin` address may call `update_reconciliation_status`. The contract validates
this before accepting the update and emits a `("payroll", "reconciliation_updated")` event
with `(run_id, new_status)` for every accepted transition.

## On-chain event

| Event topic | Data payload |
|---|---|
| `("payroll", "reconciliation_updated")` | `(run_id: u64, status: ReconciliationStatus)` |

Indexers should listen for this event to keep off-chain dashboards up to date without
polling individual run records.

## Open questions and pending decisions

1. **Transition guards**: Future versions may enforce a linear state machine (e.g.,
   prohibit `Reconciled → Unreconciled`) to prevent accidental re-opening of settled runs.
   Contributors should track [issue #134](https://github.com/zkpayroll/zk-payroll-contracts/issues/134)
   for any decision on enforced transitions.

2. **Bulk reconciliation**: The current API reconciles one run at a time. A bulk endpoint
   for batch-reconciling multiple runs is not yet implemented.

3. **Reconciliation deadline**: There is currently no on-chain time limit after which an
   `Unreconciled` run triggers an alert. Monitoring thresholds are managed off-chain via
   the dashboard.

## Cross-references

- Issue [#134](https://github.com/zkpayroll/zk-payroll-contracts/issues/134):
  reconciliation status tracking implementation.
- Issue [#148](https://github.com/zkpayroll/zk-payroll-contracts/issues/148): this
  documentation issue.
- See [payroll-run-identifiers.md](./payroll-run-identifiers.md) for how to look up a
  `PayrollRun` record by `run_id`.
- See [archived-run-queries.md](./archived-run-queries.md) for querying historical runs
  that have been explicitly archived.
