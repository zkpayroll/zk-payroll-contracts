# Admin Approval Audit History (#791)

An on-chain, append-only history of the approvals the contract admin takes
alone in the payroll contract.

## What is recorded

Every successful admin approval appends one `AdminApprovalRecord`:

| Field | Meaning |
|-------|---------|
| `sequence` | 1-based position in the history, in the order approvals happened. |
| `approver` | The admin who approved and authorized the call. |
| `kind` | What was approved (`AdminApprovalKind`). |
| `target_id` | The approved object's id, or `0` when there is none. |
| `approved_at` | Ledger timestamp of the approval. |
| `ledger_sequence` | Ledger sequence of the approval. |

| Entrypoint | `kind` | `target_id` |
|------------|--------|-------------|
| `finalize_payroll_run` | `PayrollRunFinalized` | The run id. |
| `approve_emergency_withdrawal` | `EmergencyWithdrawal` | `0` (at most one request is pending). |

Each record also emits `("payroll", "admin_approval_recorded")` with data
`(sequence, approver, kind as u32, target_id, approved_at)`, before the
entrypoint's existing events (`run_finalized`, `emergency_approved`), which are
unchanged.

A rejected approval (wrong caller, nothing pending, paused, disputed, and so on)
records nothing. Records are never changed or removed by the contract. Only
addresses, ids, and ledger time are stored; no salary amount, employee identity,
or proof material.

## Contract surface

| Entrypoint | Purpose |
|------------|---------|
| `get_admin_approval_count()` | Number of approvals recorded. |
| `get_admin_approval(sequence)` | One record by its 1-based sequence, or `None`. |
| `get_admin_approval_history(after_sequence, limit)` | A page of records, oldest first: those with `sequence > after_sequence`, at most `limit`. Start with `after_sequence = 0`, then pass the last sequence received. A start at or past the end returns an empty page. |

All three are read-only and need no authorization.

## Errors

`get_admin_approval_history` rejects a page size it will not serve instead of
clamping it:

| Code | Error | Cause |
|------|-------|-------|
| 7910 | `AdminApprovalAuditError::PageLimitZero` | `limit` is `0`. |
| 7911 | `AdminApprovalAuditError::PageLimitTooLarge` | `limit` exceeds `MAX_ADMIN_APPROVAL_PAGE` (50). |
