# PR Description

## Title
`feat(payroll): Add payroll run reconciliation status for downstream settlement tracking (#134)`

## Description
This PR introduces reconciliation status tracking for completed payroll runs to support downstream settlement integrations.

### Key Changes
- **Reconciliation States**: Added the `ReconciliationStatus` enum representing the three phases: `Unreconciled` (initial state), `Reconciled` (settlement success), and `Failed` (settlement exception).
- **Payroll Run Linking**: Added the `reconciliation_status` field to the `PayrollRun` struct and initialized new runs as `Unreconciled` at execution time inside `batch_process_payroll`.
- **Admin Reconciliation Updates**: Implemented the `update_reconciliation_status` entry-point, allowing contract administrators to update run status and publishing a `reconciliation_updated` event on success.
- **Client Guidelines Documentation**: Added `docs/interop/reconciliation-status.md` which documents reconciliation states, transitions, event structures, and recommendations for downstream integration.

## How Was This Tested?
- Added unit tests covering the entire reconciliation lifecycle:
  - `test_new_run_is_unreconciled`
  - `test_admin_can_update_reconciliation_status`
  - `test_non_admin_cannot_update_reconciliation_status` (asserts panic on unauthorized updates)
  - `test_update_status_for_invalid_run_panics` (asserts panic when targeting non-existent run IDs)
- Verified all contract tests pass successfully in the local workspace using:
  ```bash
  cargo test -p payroll --release
  ```

## Closes
Closes #134
