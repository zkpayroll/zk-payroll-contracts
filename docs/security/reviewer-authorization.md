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
  - Emits `reviewer_added` event with the newly authorized reviewer `Address`.
- **Revoking Reviewer Role (`remove_reviewer`)**:
  - Executed exclusively by the contract `admin`.
  - Immediately invalidates authorization.
  - Emits `reviewer_removed` event.
- **Authorization Query (`is_reviewer`)**:
  - Public read-only query returning `bool` indicating active reviewer status.

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

---

## 3. Review Decisions & Workflows

An authorized reviewer can submit one of three review decisions for a `run_id`:

| Decision | Enum Variant | Semantics & Workflow Action |
| --- | --- | --- |
| **Approve** | `ReviewDecision::Approved` | Confirms the prepared run or draft meets requirements and is cleared for execution/finalization. |
| **Reject** | `ReviewDecision::Rejected` | Flags the run as rejected due to invalid parameters or policy violations, preventing safe progress. |
| **Request Changes** | `ReviewDecision::ChangesRequested` | Flags the run for modification or correction off-chain before re-submission. |

### 3.1 Review Record Storage
Review records are persisted in contract storage under `DataKey::RunReview(u64)` as a `RunReview` struct:

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
