# Draft Payroll Approval Snapshot Locking (#648)

Once a draft's approval tracker (`init_draft_approval` /
`submit_draft_approval`, see
[Approved Payroll Revision Protection](./approved-payroll-revision-protection.md))
reaches quorum, the admin can lock a snapshot of exactly what was approved.

## Lifecycle

1. `lock_draft_approval_snapshot(admin, draft_id)` records a
   `DraftApprovalSnapshot`: the protected content hash, the draft's
   `total_amount`, `employee_count`, `period_label`, `amendment_count`, the
   number of approvals, and who locked it and when. The draft must be
   `Pending` or `Finalized` and its tracker must have reached quorum.
2. While locked, `amend_run_draft`, `amend_draft_with_rollback`, and
   `init_draft_approval` are rejected with
   `"Draft approval snapshot is locked: release it with release_draft_approval_snapshot (which resets approvals) before changing the draft"`.
3. `verify_draft_approval_snapshot(draft_id)` is a read-only check that the
   draft and approval tracker still match the snapshot. Executors should call
   it before acting on an approved draft.
4. `release_draft_approval_snapshot(admin, draft_id)` removes the lock and
   discards every collected approval, so a corrected draft must be approved
   again before it can be re-locked.

## Revision binding

An approval is bound to the draft revision it was collected against. Each
approval records the draft's revision (its `amendment_count` and protected
content hash) at submission time, and any operation that consumes an approval
(for example locking a snapshot or executing an approved draft) re-checks that
binding.

If the draft has been amended since an approval was collected, the approval
references a superseded revision and is rejected with
`DraftSnapshotError::ApprovalReferencesSupersededDraft` (code `6490`). The
error carries no draft content, amounts, or employee data; it only signals that
the approval is stale. Re-run `init_draft_approval` and collect fresh approvals
against the current revision before retrying.

`get_draft_approval_snapshot(draft_id)` and `is_draft_snapshot_locked(draft_id)`
are read-only views.

## Errors (`DraftSnapshotError`)

| Code | Variant | Meaning |
|------|---------|---------|
| 6480 | `NotInitialized` | Payroll is not initialized. |
| 6481 | `Unauthorized` | Caller is not the payroll admin. |
| 6482 | `DraftNotFound` | No draft for this id. |
| 6483 | `DraftNotLockable` | Draft is submitted, cancelled, or expired. |
| 6484 | `ApprovalNotInitialized` | Call `init_draft_approval` first. |
| 6485 | `ApprovalQuorumNotMet` | Collect the remaining approvals first. |
| 6486 | `SnapshotAlreadyLocked` | A snapshot is already locked. |
| 6487 | `SnapshotNotFound` | No snapshot is locked for this draft. |
| 6488 | `DraftChangedSinceSnapshot` | Draft content drifted; do not execute. |
| 6489 | `ApprovalChangedSinceSnapshot` | Approval tracker drifted; re-run approval. |
| 6490 | `ApprovalReferencesSupersededDraft` | Approval was collected against a superseded draft revision; re-run approval. |

## Events

- `("payroll", "draft_snapshot_locked")`: `(draft_id, protected_content_hash, approvals, locked_at)`
- `("payroll", "draft_snapshot_released")`: `(draft_id, released_at)`

Snapshots contain only aggregate draft fields that are already stored
on-chain; no per-employee data is captured.
