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

Errors are unit-only, append-only `ApprovalInvalidationError` codes (8401 to 8410). They
name only the failed precondition, never an amount, signer, or content hash. An unchanged
protected revision returns `NoRevisionChange` rather than a misleading success, since
there is nothing to invalidate. The legacy panicking API maps these codes back to its
original messages, so existing callers behave identically.

**Enforcement points:** `preflight_amend_draft_with_rollback`, `apply_amendment`,
`amend_draft_rollback_checked`.

## A8: Draft revisions retain verifiable ancestry

Each protected-content revision is recorded under the separate `DraftRevisionKey`
namespace with its revision number, parent revision, parent hash, content hash,
and optional invalidation reason. `amend_draft_from_revision` accepts an expected
parent revision and returns `StaleParentRevision` without writes if another edit
has already advanced the draft. Existing trackers without lineage metadata are
treated as revision 1 and materialized when their first child revision is
written. The `approval_invalidation_recorded` event reports only draft/revision
identifiers and the generic `ProtectedContentChanged` reason.

**Enforcement points:** `current_draft_revision_record`,
`preflight_amend_draft_with_rollback`, `amend_draft_from_revision`.

## A9: An approval cannot reference a superseded draft revision

An approval is bound to both the protected content hash (A1) and the draft revision it
was created against. `submit_draft_approval` rejects any approval whose revision is not
the current `current_draft_revision_record` revision, even when the supplied content hash
matches. A superseded revision is therefore never approvable: once A2 or A8 advances the
draft, approvals for the prior revision are dead. The rejection is the generic
`Stale approval reused: protected fields changed` panic (or the typed
`ApprovalInvalidationError::StaleParentRevision` code from the checked API) and names no
amount, signer, or content hash.

**Enforcement points:** `submit_draft_approval`, `current_draft_revision_record`,
`preflight_amend_draft_with_rollback`.

## A10: Settlement timeout recovery is bounded

Settlement timeout recovery only applies to a run that is in a recoverable settlement
state and whose timeout window has strictly elapsed. Recovery before the window elapses,
on a run that is not awaiting settlement, or on an already-settled run is rejected
without state writes. Recovery never re-opens a completed settlement and never moves
funds based on a stale timeout assessment; the boundary is exclusive at the timeout
timestamp. Rejections are unit-only typed errors that identify the failed precondition
and the opaque run id only.

**Enforcement points:** settlement timeout recovery entry points in
`contracts/payroll/src/`, `contracts/events/src/`.

## A11: Events and errors are privacy-safe

Every event and error emitted by the approval and settlement paths carries only opaque
identifiers (run id, draft id, revision number, record type, actor/admin address) and
generic reason codes. Salary amounts, employee addresses, obligation leaves, and proof
material are never included in event payloads, panic messages, or typed error variants.
Redaction is verified by focused tests that assert the absence of sensitive fields in
serialized events and error output.

**Enforcement points:** `contracts/payroll/src/`, `contracts/events/src/`.

## Test coverage

- `contracts/payroll/tests/approval_rollback.rs`: stale hash, duplicate signer, lock, and amendment rollback.
- `contracts/payroll/tests/approval_invalidation_adversarial.rs`: stale hash after amendment, approvals not carrying over, re-initialization after amendment, and unauthorized cleanup.
- `contracts/payroll/tests/stale_approval_cleanup.rs`: staleness boundaries and authorization.
- `contracts/payroll/tests/approval_superseded_revision.rs`: approval rejected against a superseded draft revision, success on the current revision, and the boundary where the revision advances between init and submit.
- `contracts/payroll/tests/settlement_timeout_recovery.rs`: recovery success after the timeout, rejection before the timeout and on non-settleable runs, and the exact-timeout boundary.
- `contracts/payroll/tests/event_redaction.rs`: serialized approval and settlement events and typed errors contain no salary, employee, obligation, or proof fields.

All events and errors use opaque run or draft identifiers. This document intentionally contains no salary values, employee addresses, or proof material.
