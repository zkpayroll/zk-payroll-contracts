# Approved Payroll Revision Protection (#616)

A payroll draft can require multiple reviewer approvals before it is considered
cleared for execution. Each approval is bound to the **protected revision** of
the draft — a digest over the fields that must not change once approved. If a
protected field is revised, the collected approvals roll back, so an approval
can never authorise a revision it never saw.

This documents the on-chain behavior in `contracts/payroll/src/lib.rs` and
`contracts/payroll/src/signing.rs`.

## The protected revision

An approval tracker is initialised with a `protected_content_hash` computed
over the revision's protected fields:

```
SHA-256(
    "zkpayroll_protected_content_v1" ||
    total_amount (i128 LE) ||
    employee_count (u32 LE) ||
    obligation_root (32 bytes) ||
    metadata_hash (32 bytes)
)
```

Any change to one of those fields produces a different hash, which is what
makes the revision distinguishable from the one that was approved. Fields
outside this set (descriptions, labels) can change without disturbing the
approvals.

## Entrypoints

| Entrypoint | Who | Effect |
|------------|-----|--------|
| `init_draft_approval(admin, draft_id, total_amount, employee_count, obligation_root, metadata_hash, required_approvals)` | Admin | Creates the tracker bound to the revision's protected hash. Re-initialising replaces any existing tracker. |
| `submit_draft_approval(signer, draft_id, protected_content_hash)` | Any signer | Records one approval against the revision identified by the supplied hash. Advances the stage; locks once `required_approvals` is reached. |
| `get_draft_approval_state(draft_id)` | Anyone | Read-only: the current `MultiStageApproval`, or `None`. |
| `amend_draft_with_rollback(admin, draft_id, new_total_amount, new_employee_count, new_obligation_root, new_metadata_hash)` | Admin | Re-binds the tracker to the revised protected fields and rolls approvals back when the hash changes. |
| `get_draft_revision_head(draft_id)` / `get_draft_revision_record(draft_id, revision)` | Anyone | Read-only ancestry queries. Existing trackers without lineage metadata appear as revision 1. |
| `amend_draft_from_revision(admin, draft_id, expected_parent_revision, ...)` | Admin | Checked amendment that rejects stale parent revisions with `StaleParentRevision` before any write. |

## Revision protection rules

`submit_draft_approval` rejects (panics) in the following cases, each with an
actionable message:

| Fail condition | Message | Why it matters |
|----------------|---------|----------------|
| Revision already locked | `Draft is locked` | Once the threshold is met the approved revision is frozen; no further approvals are accepted. |
| Supplied hash ≠ current revision | `Stale approval reused: protected fields changed` | An approval gathered before a revision cannot be replayed against the revised draft. |
| Same signer approves twice | `Duplicate approval from same signer` | Prevents one signer from reaching the threshold alone. |

`amend_draft_with_rollback` protects the approved revision by **invalidating**
rather than reusing approvals: when the new protected fields hash differently,
the tracker is re-bound to the new revision and `current_approvals`,
`current_stage`, `is_locked`, and the signer list are reset. A revision that
leaves the protected fields unchanged keeps the existing approvals.
Each protected-content change appends a revision record linked to its parent
revision and hash. The invalidation reason is recorded as the generic
`ProtectedContentChanged` value, without identifying which private payroll
field changed.

## Storage key

Approval state lives under `ApprovalKey::DraftApproval(draft_id)`, deliberately
a **separate enum** from `DataKey`: `DataKey` is already at the Soroban
contract-spec ceiling of 50 union cases, so this feature is keyed on its own
enum to leave every existing storage key — and the
data already persisted by deployed contracts — untouched.
Revision lineage is stored separately under `DraftRevisionKey`. A tracker
created before lineage support is lazily represented as revision 1; its
original timestamp is unknown and remains `None` in the synthesized record.

## Event surface

A rollback emits a privacy-safe marker carrying only the draft identifier — no
salary values or employee data:

```
topics = ( Symbol("payroll"), Symbol("approvals_rolled_back") )
data   = ( draft_id: u64 )
```

The additive `approval_invalidation_recorded` event records the ancestry edge
and generic invalidation reason while preserving the original event shape:

```text
topics = ( Symbol("payroll"), Symbol("approval_invalidation_recorded") )
data   = ( draft_id: u64, parent_revision: u64, revision: u64,
           reason: ApprovalInvalidationReason )
```

The event and typed errors contain no protected values, employee data, or proof
material. See [Payroll Upgrade Compatibility](../contracts/payroll/UPGRADE_COMPATIBILITY.md)
for the storage and API compatibility rules.

## QA coverage

- `contracts/payroll/tests/approval_rollback.rs` (5 tests) — multi-stage flow,
  stale-hash rejection, rollback on protected-field edits, duplicate signer,
  and approval-after-lock.
- `contracts/payroll/tests/approved_revision_protection.rs` — lock at threshold,
  unchanged revision keeps approvals, changed revision invalidates the old hash,
  ancestry links, stale-parent rejection, zero `required_approvals` rejected,
  approving an unknown draft rejected, and non-admin initialisation/amendment
  rejected.

```bash
cargo test -p payroll --test approval_rollback
cargo test -p payroll --test approved_revision_protection
```
