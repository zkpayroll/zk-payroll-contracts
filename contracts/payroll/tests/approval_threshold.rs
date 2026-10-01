//! Configurable payroll approval threshold.
//!
//! `set_approval_threshold` requires N distinct, live reviewer approvals
//! before `finalize_payroll_run` executes a prepared run. The policy is
//! opt-in: without it, the review workflow is unchanged.

#![cfg(test)]

mod common;

use payroll::failure_reasons::{DryRunArgs, PayrollFailureReason};
use payroll::{ApprovalProgress, PayrollClient, DEFAULT_APPROVAL_EXPIRY_SECONDS};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

struct Fixture<'a> {
    client: PayrollClient<'a>,
    admin: Address,
    employee: Address,
    reviewers: Vec<Address>,
}

fn setup_with_reviewers(env: &Env, reviewer_count: u32) -> Fixture<'_> {
    let (client, _token, employee) = common::setup(env);
    let admin = client.get_addresses().admin;
    let mut reviewers = Vec::new(env);
    for _ in 0..reviewer_count {
        let reviewer = Address::generate(env);
        client.add_reviewer(&admin, &reviewer);
        reviewers.push_back(reviewer);
    }
    Fixture {
        client,
        admin,
        employee,
        reviewers,
    }
}

fn prepare_run(env: &Env, fx: &Fixture<'_>, nonce_marker: u8) -> u64 {
    let (proofs, amounts, employees) = common::one_payment(env, &fx.employee);
    fx.client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(env, nonce_marker),
        &None,
    )
}

fn reviewer(fx: &Fixture<'_>, index: u32) -> Address {
    fx.reviewers.get(index).unwrap()
}

fn advance_time(env: &Env, seconds: u64) {
    env.ledger().with_mut(|li| li.timestamp += seconds);
}

// ── Default behavior (no threshold) ──────────────────────────────────────────

#[test]
fn finalize_without_threshold_requires_no_approvals() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 0);

    assert_eq!(fx.client.get_approval_threshold(), None);
    let run_id = prepare_run(&env, &fx, 1);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);

    assert!(fx.client.get_pending_run(&run_id).is_none());
}

#[test]
fn progress_without_threshold_reports_zero_required() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);

    assert_eq!(
        fx.client.get_approval_progress(&run_id),
        ApprovalProgress {
            required: 0,
            approved: 1,
            threshold_met: true,
        }
    );
}

// ── Successful path ──────────────────────────────────────────────────────────

#[test]
fn finalize_succeeds_once_threshold_is_met() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 3);
    fx.client.set_approval_threshold(&fx.admin, &2);
    assert_eq!(fx.client.get_approval_threshold(), Some(2));

    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    let progress = fx.client.get_approval_progress(&run_id);
    assert_eq!(progress.approved, 1);
    assert!(!progress.threshold_met);

    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    let progress = fx.client.get_approval_progress(&run_id);
    assert_eq!(progress.required, 2);
    assert_eq!(progress.approved, 2);
    assert!(progress.threshold_met);
    assert_eq!(fx.client.get_run_approvals(&run_id).len(), 2);

    fx.client.finalize_payroll_run(&fx.admin, &run_id);
    assert!(fx.client.get_pending_run(&run_id).is_none());
}

#[test]
fn clearing_threshold_restores_default_workflow() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    fx.client.clear_approval_threshold(&fx.admin);
    assert_eq!(fx.client.get_approval_threshold(), None);

    let run_id = prepare_run(&env, &fx, 1);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
    assert!(fx.client.get_pending_run(&run_id).is_none());
}

// ── Finalization failures ────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Insufficient payroll approvals: 1 of 2 required approvals recorded")]
fn finalize_below_threshold_panics() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
}

#[test]
fn failed_finalize_leaves_run_pending() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    assert!(fx
        .client
        .try_finalize_payroll_run(&fx.admin, &run_id)
        .is_err());
    assert!(fx.client.get_pending_run(&run_id).is_some());

    // The run can still be completed once the quorum is collected.
    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
    assert!(fx.client.get_pending_run(&run_id).is_none());
}

#[test]
#[should_panic(expected = "Duplicate approval: reviewer has already approved this payroll run")]
fn same_reviewer_cannot_approve_twice() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
}

#[test]
fn revoked_reviewer_approval_no_longer_counts() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 3);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client.remove_reviewer(&fx.admin, &reviewer(&fx, 1));

    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 1);
    assert!(fx
        .client
        .try_finalize_payroll_run(&fx.admin, &run_id)
        .is_err());

    // A remaining reviewer can restore the quorum.
    fx.client.approve_payroll_run(&reviewer(&fx, 2), &run_id);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
}

#[test]
fn expired_approvals_do_not_count_and_can_be_renewed() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    advance_time(&env, 100);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);

    // Exactly at the first approval's expiry boundary it still counts.
    advance_time(&env, DEFAULT_APPROVAL_EXPIRY_SECONDS - 100);
    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 2);

    // One second later the first approval has expired.
    advance_time(&env, 1);
    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 1);
    assert!(fx
        .client
        .try_finalize_payroll_run(&fx.admin, &run_id)
        .is_err());

    // The reviewer whose approval expired may approve again.
    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 2);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
}

#[test]
#[should_panic(expected = "Payroll run has an outstanding rejection or change request")]
fn rejection_clears_approvals_and_blocks_finalize() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 3);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client
        .reject_payroll_run(&reviewer(&fx, 2), &run_id, &Symbol::new(&env, "policy"));

    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 0);
    assert!(fx.client.get_run_approvals(&run_id).is_empty());
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
}

#[test]
fn change_request_requires_a_fresh_quorum() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.request_changes_payroll_run(
        &reviewer(&fx, 1),
        &run_id,
        &Symbol::new(&env, "missing_docs"),
    );
    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 0);

    // Both reviewers, including the earlier approver, approve afresh.
    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
}

#[test]
fn withdrawn_approval_stops_counting_without_resetting_quorum() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 3);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client
        .withdraw_approval(&reviewer(&fx, 1), &run_id, &Symbol::new(&env, "recheck"));

    assert_eq!(fx.client.get_approval_progress(&run_id).approved, 1);
    assert!(fx
        .client
        .try_finalize_payroll_run(&fx.admin, &run_id)
        .is_err());

    fx.client.approve_payroll_run(&reviewer(&fx, 2), &run_id);
    fx.client.finalize_payroll_run(&fx.admin, &run_id);
    assert!(fx.client.get_pending_run(&run_id).is_none());
}

#[test]
fn superseded_approval_moves_to_the_new_reviewer() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 3);
    fx.client.set_approval_threshold(&fx.admin, &2);
    let run_id = prepare_run(&env, &fx, 1);

    fx.client.approve_payroll_run(&reviewer(&fx, 0), &run_id);
    fx.client.approve_payroll_run(&reviewer(&fx, 1), &run_id);
    fx.client.supersede_approval(&reviewer(&fx, 2), &run_id);

    let approvers: Vec<Address> = {
        let mut list = Vec::new(&env);
        for approval in fx.client.get_run_approvals(&run_id).iter() {
            list.push_back(approval.reviewer);
        }
        list
    };
    assert_eq!(approvers.len(), 2);
    assert!(approvers.contains(reviewer(&fx, 0)));
    assert!(approvers.contains(reviewer(&fx, 2)));
    assert!(!approvers.contains(reviewer(&fx, 1)));

    fx.client.finalize_payroll_run(&fx.admin, &run_id);
    assert!(fx.client.get_pending_run(&run_id).is_none());
}

// ── Direct execution while a threshold is configured ─────────────────────────

#[test]
#[should_panic(expected = "Approval threshold configured: use prepare_payroll_run")]
fn direct_batch_execution_is_blocked_while_threshold_is_set() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &1);

    let (proofs, amounts, employees) = common::one_payment(&env, &fx.employee);
    fx.client.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 1),
        &None,
        &Address::generate(&env),
    );
}

#[test]
#[should_panic(expected = "Approval threshold configured: use prepare_payroll_run")]
fn bounded_batch_execution_is_blocked_while_threshold_is_set() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &1);

    let (proofs, amounts, employees) = common::one_payment(&env, &fx.employee);
    fx.client.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 1),
        &None,
        &10,
    );
}

#[test]
#[should_panic(expected = "Approval threshold configured: use prepare_payroll_run")]
fn expiry_checked_batch_execution_is_blocked_while_threshold_is_set() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &1);

    let (proofs, amounts, employees) = common::one_payment(&env, &fx.employee);
    let proof_refs = Vec::from_array(&env, [BytesN::from_array(&env, &[7u8; 32])]);
    fx.client.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 1),
        &None,
    );
}

#[test]
fn dry_run_reports_approval_workflow_required() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    let args = DryRunArgs {
        amounts: Vec::from_array(&env, [100_i128]),
        employees: Vec::from_array(&env, [fx.employee.clone()]),
        expected_total_spend: 100,
        nonce: common::nonce(&env, 1),
        draft_hash: None,
        proof_count: 1,
        sequence: None,
        source_address: None,
        contract_period: None,
        expected_contract_period: None,
        contract_period_closed: false,
    };

    let before = fx.client.dry_run_batch_process_payroll(&args);
    assert!(!before
        .blockers
        .contains(PayrollFailureReason::ApprovalWorkflowRequired));

    fx.client.set_approval_threshold(&fx.admin, &1);
    let after = fx.client.dry_run_batch_process_payroll(&args);
    assert!(!after.would_succeed);
    assert!(after
        .blockers
        .contains(PayrollFailureReason::ApprovalWorkflowRequired));
}

// ── Configuration validation and authorization ───────────────────────────────

#[test]
#[should_panic(expected = "Approval threshold must be positive")]
fn threshold_of_zero_is_rejected() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &0);
}

#[test]
#[should_panic(expected = "Approval threshold exceeds the number of authorized reviewers")]
fn unreachable_threshold_is_rejected() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &3);
}

#[test]
#[should_panic(expected = "Approval threshold exceeds the maximum supported value")]
fn threshold_above_maximum_is_rejected() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, payroll::MAX_APPROVAL_THRESHOLD + 1);
    fx.client
        .set_approval_threshold(&fx.admin, &(payroll::MAX_APPROVAL_THRESHOLD + 1));
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn non_admin_cannot_set_threshold() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client
        .set_approval_threshold(&Address::generate(&env), &1);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn non_admin_cannot_clear_threshold() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &1);
    fx.client.clear_approval_threshold(&Address::generate(&env));
}

#[test]
#[should_panic(expected = "Configuration is locked")]
fn threshold_cannot_change_while_a_run_is_pending() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 2);
    fx.client.set_approval_threshold(&fx.admin, &2);
    prepare_run(&env, &fx, 1);

    // Lowering the bar under an in-flight run must be rejected.
    fx.client.set_approval_threshold(&fx.admin, &1);
}

#[test]
#[should_panic(expected = "Configuration is locked")]
fn threshold_cannot_be_cleared_while_a_run_is_pending() {
    let env = Env::default();
    let fx = setup_with_reviewers(&env, 1);
    fx.client.set_approval_threshold(&fx.admin, &1);
    prepare_run(&env, &fx, 1);
    fx.client.clear_approval_threshold(&fx.admin);
}
