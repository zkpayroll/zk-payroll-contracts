# Approval Invalidation Invariants

This document records the invariants that govern payroll approval invalidation. The logic lives in `contracts/payroll/src/lib.rs` and its supporting modules, not in `payroll_registry`. The rules below are enforced on chain and covered by focused tests.

## A1: An approval is bound to one protected revision

`init_draft_approval` binds the tracker to `protected_content_hash`, computed from total amount, employee count, obligation root, and metadata hash. `submit_draft_approval` accepts only that exact hash. A hash from another revision is rejected with the generic panic `Stale approval reused: protected fields changed`. No employee identity or salary value appears in the rejection.

**Enforcement points:** `init_draft_approval`, `submit_draft_approval`.

## A2: Changing a protected field invalidates collected approvals

`amend_draft_with_rollback` replaces the protected hash and resets `current_approvals`, `current_stage`, `is_locked`, and the signer list. Prior approvals never carry over to the new revision, and a signer must approve the new hash explicitly.

**Enforcement points:** `amend_draft_with_rollback`, `signing::MultiStageApproval`.

## A3: A signer approves a revision at most once

The tracker stores signers per revision. A repeated approval from the same signer is rejected while that revision is open. After A2 resets the tracker, the same signer may approve the new revision, but only by supplying the new hash.

**Enforcement points:** `submit_draft_approval`.

## A4: A locked revision cannot accept further approvals

Once `current_approvals` reaches `required_approvals`, the tracker is locked and `submit_draft_approval` rejects further calls. A protected-field change that is allowed to proceed must first reset the tracker through A2.

**Enforcement points:** `submit_draft_approval`, `draft_approval_snapshot::require_snapshot_unlocked`.

## A5: Run-level decisions invalidate the active approval

`reject_payroll_run` and `request_changes_payroll_run` clear all recorded approvals for the run. `withdraw_approval` removes the approving reviewer's counted approval and records a `Withdrawn` decision. `supersede_approval` transfers the counted approval to a different reviewer and refreshes the review timestamp. Each transition keeps an audit record while removing authorization for the prior decision.

**Enforcement points:** `reject_payroll_run`, `request_changes_payroll_run`, `withdraw_approval`, `supersede_approval`.

## A6: Stale approval cleanup is admin-only and privacy-safe

`cleanup_stale_approval` requires the contract admin, a non-sentinel run id, an `Approved` decision, and a timestamp strictly past the expiry window. The emitted event names only the run id, record type, and admin. `check_stale_approval` provides the same staleness assessment without mutating state.

**Enforcement points:** `cleanup_stale_approval`, `check_stale_approval`, `get_stale_approval_status`.

## A7: Checked amendment failures are typed and leave no partial state

`amend_draft_rollback_checked` is the additive, non-panicking counterpart to
`amend_draft_with_rollback`. It validates every precondition in a read-only preflight
helper (`preflight_amend_draft_with_rollback`) before any storage write, then applies the
change with at most one write via `apply_amendment`. A rejection therefore cannot leave a
partially updated approval tracker.

Errors are unit-only, append-only `ApprovalInvalidationError` codes (8401 to 8407). They
name only the failed precondition, never an amount, signer, or content hash. An unchanged
protected revision returns `NoRevisionChange` rather than a misleading success, since
there is nothing to invalidate. The legacy panicking API maps these codes back to its
original messages, so existing callers behave identically.

**Enforcement points:** `preflight_amend_draft_with_rollback`, `apply_amendment`,
`amend_draft_rollback_checked`.

## Test coverage

- `contracts/payroll/tests/approval_rollback.rs`: stale hash, duplicate signer, lock, and amendment rollback.
- `contracts/payroll/tests/approval_invalidation_adversarial.rs`: stale hash after amendment, approvals not carrying over, re-initialization after amendment, and unauthorized cleanup.
- `contracts/payroll/tests/stale_approval_cleanup.rs`: staleness boundaries and authorization.

All events and errors use opaque run or draft identifiers. This document intentionally contains no salary values, employee addresses, or proof material.
