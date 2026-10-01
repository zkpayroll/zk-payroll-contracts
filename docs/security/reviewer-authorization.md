# Security Architecture: Payroll Reviewer Authorization

This document specifies the security architecture, authorization controls, and auditability guarantees for the **Payroll Reviewer Authorization** workflow in the `zk-payroll-contracts` suite.

---

## 1. Overview & Purpose

Reviewer permissions protect the payroll approval workflow from unauthorized actions. Before a prepared payroll run or draft is executed or finalized, designated organization reviewers verify the run metadata, draft commitment hashes, and employee counts off-chain. 

Only explicitly authorized reviewer accounts can submit approval decisions, reject payroll runs, or request changes.

---

## 2. Reviewer Authorization Lifecycle

### 2.1 Role Provisioning & Revocation
- **Granting Reviewer Role (`add_reviewer`)**: 
  - Executed exclusively by the contract `admin`.
  - Rejected once granting it would exceed the configured `MaxReviewers` cap, if any (see §2.2, issue #539). Re-adding an address that is already authorized is always a no-op with respect to the cap.
  - Emits `reviewer_added` event with the newly authorized reviewer `Address`.
- **Revoking Reviewer Role (`remove_reviewer`)**:
  - Executed exclusively by the contract `admin`.
  - Immediately invalidates authorization.
  - Emits `reviewer_removed` event.
- **Authorization Query (`is_reviewer`)**:
  - Public read-only query returning `bool` indicating active reviewer status.

### 2.2 Reviewer Assignment Limits (issue #539)
- **`set_max_reviewers(admin, max_reviewers)`**: employer-configurable, opt-in cap on the number of concurrently authorized reviewers. Admin-only, mirrors `set_capacity_limits`'s opt-in shape: absent a policy, `add_reviewer` remains unlimited, matching this workflow's pre-#539 behavior.
  - Rejects `max_reviewers == 0`.
  - Lowering the cap below the current reviewer count is allowed and never revokes existing reviewers; it only blocks further `add_reviewer` calls until the count drops back under the cap.
  - Emits `max_reviewers_set`.
- **`get_max_reviewers()`**: returns the configured cap, or `None` if unset.
- **`get_reviewer_count()`**: returns the number of currently authorized reviewers, maintained incrementally alongside `AuthorizedReviewer` so the cap can be enforced without an unbounded storage scan.

```
       +--------------+  add_reviewer(admin)  +-------------------+
       | Unauthorized | -------------------> | Authorized        |
       | Address      | <------------------- | Reviewer          |
       +--------------+ remove_reviewer(admin)| Address           |
                                              +-------------------+
                                                        |
                                           Can call review entrypoints:
                                           - approve_payroll_run
                                           - reject_payroll_run
                                           - request_changes_payroll_run
```

### 2.3 Revocation and Approval Thresholds
Removing a reviewer is never blocked by the approval threshold (§2.4), so a compromised reviewer can always be revoked immediately. Their approvals stop counting at once. If revocation leaves fewer reviewers than the threshold, pending runs cannot be finalized until the admin adds a reviewer, or cancels the pending runs and lowers the threshold.

### 2.4 Payroll Approval Threshold
- **`set_approval_threshold(admin, threshold)`**: opt-in requirement that `threshold` distinct reviewers approve a prepared run before `finalize_payroll_run` executes it. Admin-only.
  - Rejects `0` (use `clear_approval_threshold`), values above `MAX_APPROVAL_THRESHOLD` (10), and values above the current reviewer count, since an unreachable threshold would block payroll.
  - Rejected while any payroll run is pending (`Configuration is locked: ...`), so the bar cannot be lowered under an in-flight run.
  - Emits `approval_threshold_set` (`u32` threshold) and a `config_changed` event with key `approval_threshold`.
- **`clear_approval_threshold(admin)`**: removes the requirement. Admin-only, subject to the same pending-run lock. Emits `approval_threshold_set` with `0`.
- **`get_approval_threshold()`**: returns the threshold, or `None` if unset.
- **`get_run_approvals(run_id)`**: every recorded `RunApproval { reviewer, approved_at }` for the run, including approvals that no longer count.
- **`get_approval_progress(run_id)`**: `ApprovalProgress { required, approved, threshold_met }`. `required` is `0` when no threshold is set.

An approval counts toward the threshold only while its reviewer is still authorized and it is no older than `DEFAULT_APPROVAL_EXPIRY_SECONDS` (inclusive boundary, matching §3.1). A reviewer whose approval expired may approve again. At most `MAX_RUN_APPROVALS` (20) live approvals are stored per run.

While a threshold is set, `batch_process_payroll`, `batch_process_payroll_idempotent`, `batch_process_payroll_bounded`, and `batch_process_with_expiry` are unavailable: they assign the run ID at execution time, so approvals could never be collected for them. `dry_run_batch_process_payroll` reports `PayrollFailureReason::ApprovalWorkflowRequired` (23). A bounded batch started before a threshold was set cannot resume until the threshold is cleared.

---

## 3. Review Decisions & Workflows

An authorized reviewer can submit one of three review decisions for a `run_id`:

| Decision | Enum Variant | Semantics & Workflow Action |
| --- | --- | --- |
| **Approve** | `ReviewDecision::Approved` | Confirms the prepared run or draft meets requirements and is cleared for execution/finalization. |
| **Reject** | `ReviewDecision::Rejected` | Flags the run as rejected due to invalid parameters or policy violations, preventing safe progress. |
| **Request Changes** | `ReviewDecision::ChangesRequested` | Flags the run for modification or correction off-chain before re-submission. |

A reviewer may hold only one live approval per run; approving again is rejected with `Duplicate approval: reviewer has already approved this payroll run`. Rejecting or requesting changes clears every recorded approval for the run, so a fresh quorum is needed afterwards.

Approval corrections (#522) keep the threshold consistent without resetting the quorum:
- `withdraw_approval(reviewer, run_id, reason)` records `ReviewDecision::Withdrawn` and removes only that reviewer's approval from the count. A withdrawal is not treated as an objection.
- `supersede_approval(reviewer, run_id)` moves the counted approval from the previous approver to `reviewer`. It is rejected with the duplicate-approval message if `reviewer` already holds a live approval.

### 3.1 Finalization Checks
`finalize_payroll_run` applies these approval checks, in order:

| Condition | Failure message |
| --- | --- |
| Latest approval is older than `DEFAULT_APPROVAL_EXPIRY_SECONDS` | `Payroll approval expired: approval record exceeds maximum allowed age` |
| Threshold set and the latest decision is a rejection or change request | `Payroll run has an outstanding rejection or change request: collect fresh approvals before finalizing` |
| Threshold set and live approvals < threshold | `Insufficient payroll approvals: <approved> of <required> required approvals recorded` |

A failed finalization reverts, leaving the run pending so approvals can still be collected. Failure messages report approval counts only.

### 3.2 Review Record Storage
The latest decision is persisted under `DataKey::RunReview(u64)`, and the approvals counted against the threshold under `DataKey::RunApprovals(u64)`. `prune_payroll_run` removes both; `prune_cancelled_batch` removes the approvals. `RunReview` has this shape:

```rust
pub struct RunReview {
    pub run_id: u64,
    pub reviewer: Address,
    pub decision: ReviewDecision,
    pub reason: Symbol,
    pub reviewed_at: u64,
}
```

---

## 4. Permission Boundary & Security Controls

1. **Explicit Authentication (`require_auth`)**:
   - Every review action (`approve_payroll_run`, `reject_payroll_run`, `request_changes_payroll_run`) mandates Soroban cryptographic signature verification for the `reviewer` address (`reviewer.require_auth()`).
2. **Access Control Check (`is_reviewer`)**:
   - Entrypoints panic with `Unauthorized: caller is not an authorized reviewer` if the caller address is not registered in `DataKey::AuthorizedReviewer`.
3. **Emergency Pause Guard (`require_not_paused`)**:
   - Review operations are halted when the `pause_manager` is in a paused state.

---

## 5. Privacy Preservation Guarantees

In alignment with zero-knowledge design principles across the contract suite:
- **No Private Payroll Data Exposure**: Review events (`run_approved`, `run_rejected`, `changes_requested`) and storage structs contain only public identifiers (`run_id`, `reviewer`, decision, `reason` symbol, timestamp).
- **Salary Redaction**: Employee addresses, individual payment amounts, and Poseidon blinding factors are never included in review logs or public view calls.

---

## 6. Auditability & Event Schema

Review events enable off-chain dashboards, indexers, and compliance auditors to track approval timelines:

```
topics = ( Symbol("payroll"), Symbol("run_approved" | "run_rejected" | "changes_requested") )
data   = ( run_id: u64, reviewer: Address, [reason: Symbol] )
```

---

## 7. Verification & Testing Coverage

Reviewer authorization behavior is verified under `tests/access-control/unauthorized_actions.rs` (Category 5):
- `test_unauthorized_approve_payroll_run_fails`: Confirms non-reviewers cannot approve.
- `test_unauthorized_reject_payroll_run_fails`: Confirms non-reviewers cannot reject.
- `test_unauthorized_request_changes_payroll_run_fails`: Confirms non-reviewers cannot request changes.
- `test_unauthorized_add_reviewer_fails`: Confirms non-admins cannot grant reviewer permissions.
- `test_revoked_reviewer_cannot_approve_fails`: Confirms revoked reviewers are immediately blocked.

Approval threshold behavior is verified in `contracts/payroll/tests/approval_threshold.rs`: finalizing once the threshold is met, the default no-threshold flow, insufficient, duplicate, revoked, and expired approvals, objections that reset the quorum, blocked direct execution, dry-run reporting, and configuration validation, authorization, and the pending-run lock.
