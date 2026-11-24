# Payroll Upgrade Compatibility

This note records the compatibility rules for payroll approval revision lineage
and invalidation reporting (#1094).

## Storage

- `ApprovalKey::DraftApproval` and the stored `MultiStageApproval` shape remain
  unchanged.
- Revision history is stored under the separate `DraftRevisionKey` namespace.
  New records append a revision number, parent revision/hash, content hash,
  optional generic invalidation reason, and optional timestamp.
- A tracker from an older deployment with no revision metadata is read as
  revision 1. Its hash is the existing protected-content hash and its original
  timestamp is unknown. The baseline record is materialized when the first
  child revision is written; upgrades do not require a bulk migration.
- Revision numbers are monotonic and are never reused. Existing approval,
  payment, commitment, and nullifier records are not rewritten.

## Public Interfaces

- Existing amendment entrypoints retain their signatures and behavior.
- `get_draft_revision_head` and `get_draft_revision_record` are additive,
  read-only queries.
- `amend_draft_from_revision` is the preferred checked API for concurrent
  editors. It requires the caller's expected parent revision and rejects a
  stale parent before any storage mutation. Clients should refresh the head and
  present the changed draft for approval rather than blindly retrying stale
  content.
- `ApprovalInvalidationError` is append-only. Codes 8408–8410 report stale
  parent, inconsistent stored ancestry, and revision-counter exhaustion. Errors
  contain no payroll values, employee identities, or hashes.

## Events and Privacy

The legacy `approvals_rolled_back` event keeps its existing topics and data.
The additive `approval_invalidation_recorded` event carries only the draft ID,
parent and child revision numbers, and `ProtectedContentChanged`. It does not
identify which protected field changed or include amounts, employee data,
proofs, or content hashes.

## Upgrade Checks

Before activation, verify that existing `DraftApproval` records remain
readable, a legacy tracker resolves as revision 1, and its first amendment
creates revision 2 with the legacy hash as parent. Confirm old event consumers
still receive the unchanged `approvals_rolled_back` payload; new indexers may
consume the additive invalidation event and revision queries.