# Payroll & Draft State Machine Reference

This document serves as the high-level reference for state machines within `zk-payroll-contracts`.

For detailed specifications, see:
- [Payroll Run State Machine](file:///c:/Users/hp/OneDrive/Desktop/GrantFox/zk-payroll-contracts/docs/payroll-state-machine.md)
- Machine-readable specification: [`fixtures/state-machine/payroll-run-state-machine.json`](file:///c:/Users/hp/OneDrive/Desktop/GrantFox/zk-payroll-contracts/fixtures/state-machine/payroll-run-state-machine.json)

## 1. Payroll Run State Machine (`PayrollRunState`)

Tracks on-chain execution lifecycle:

`Draft` → `Validating` → `ProofPending` → `ReadyToSubmit` → `Submitted` → `Confirming` → `Completed`

- **Terminal States**: `Completed`, `Cancelled`
- **Retryable States**: `Failed`
- **Reviewable States**: `ReconciliationRequired`

## 2. Payroll Draft Lifecycle (`RunDraftState`)

Tracks off-chain preparation and admin draft management prior to processing:

`Pending` (Created / Updated) → `Finalized` / `Submitted` / `Cancelled` / `Expired`

- **Created**: Initial state (`Pending`) via `create_run_draft`.
- **Updated**: Amendments via `amend_run_draft` (only valid for `Pending` drafts).
- **Finalized**: Locked for review via `finalize_run_draft`.
- **Submitted**: Submitted for processing via `submit_run_draft` (terminal).
- **Cancelled**: Stopped before execution via `cancel_run_draft` (terminal).
- **Expired**: Marked stale/expired via `expire_run_draft` (terminal).

## 3. Cancellation & State Cleanup Semantics

- **Pending Run Cancellation**: Calling `cancel_payroll_run_with_reason` purges the transient `PendingRun` record from contract storage, records `PayrollRunState::Cancelled` in `PayrollState`, and keeps the batch nonce permanently consumed for audit trail integrity and replay prevention.
- **Draft Cancellation**: Calling `cancel_run_draft` transitions the draft to terminal `Cancelled`, preserving historical amendment and creation metadata while blocking further modifications.
- **Escape Hatch**: Run cancellation is explicitly allowed during emergency pause to empower admins to recover from invalid or compromised submissions.

## Privacy Compliance

In accordance with system privacy requirements:
- State transitions only record metadata (`draft_id`, `admin`, `total_amount` aggregate, `period_label`, `run_id`, `reason`).
- Individual salary amounts, employee identifiers, and commitment seeds are **never** included in events, state variables, or logs.

