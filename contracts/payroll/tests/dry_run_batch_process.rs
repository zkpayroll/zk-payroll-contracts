//! Dry-run preflight for `batch_process_payroll` (issue #521) and the stable
//! `PayrollFailureReason` registry it reports through (issue #509).

#![cfg(test)]

mod common;

use ::token::TokenClient;
use payroll::failure_reasons::{DryRunArgs, PayrollFailureReason};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn args(env: &Env, employee: &Address, amount: i128, nonce_marker: u8) -> DryRunArgs {
    DryRunArgs {
        amounts: Vec::from_array(env, [amount]),
        employees: Vec::from_array(env, [employee.clone()]),
        expected_total_spend: amount,
        nonce: common::nonce(env, nonce_marker),
        draft_hash: None,
        proof_count: 1,
    }
}

/// `common::setup` initializes the payroll with a funded treasury but never
/// allowlists the token, so most tests need this to get past
/// `AssetNotAllowed` and isolate the blocker they actually want to observe.
fn allow_token(client: &payroll::PayrollClient<'_>, token: &Address) {
    client.set_asset_allowed(token, &true);
}

#[test]
fn well_formed_batch_has_no_blockers() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let report = client.dry_run_batch_process_payroll(&args(&env, &employee, 100, 1));
    assert!(report.would_succeed);
    assert!(report.blockers.is_empty());
}

#[test]
fn zero_proofs_is_reported_as_missing_proof() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    allow_token(&client, &token);

    let a = DryRunArgs {
        amounts: Vec::new(&env),
        employees: Vec::new(&env),
        expected_total_spend: 0,
        nonce: common::nonce(&env, 1),
        draft_hash: None,
        proof_count: 0,
    };
    let report = client.dry_run_batch_process_payroll(&a);
    assert!(!report.would_succeed);
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::MissingProof));
}

#[test]
fn non_positive_amount_is_reported() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let report = client.dry_run_batch_process_payroll(&args(&env, &employee, 0, 1));
    assert!(!report.would_succeed);
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::NonPositiveAmount));
}

#[test]
fn expected_spend_mismatch_is_reported() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let mut a = args(&env, &employee, 100, 1);
    a.expected_total_spend = 999;
    let report = client.dry_run_batch_process_payroll(&a);
    assert!(!report.would_succeed);
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::ExpectedSpendMismatch));
}

#[test]
fn duplicate_employee_is_reported() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let a = DryRunArgs {
        amounts: Vec::from_array(&env, [50_i128, 50_i128]),
        employees: Vec::from_array(&env, [employee.clone(), employee.clone()]),
        expected_total_spend: 100,
        nonce: common::nonce(&env, 1),
        draft_hash: None,
        proof_count: 2,
    };
    let report = client.dry_run_batch_process_payroll(&a);
    assert!(!report.would_succeed);
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::DuplicateEmployee));
}

#[test]
fn draft_hash_without_precommit_is_reported() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let mut a = args(&env, &employee, 100, 1);
    a.draft_hash = Some(BytesN::from_array(&env, &[9u8; 32]));
    let report = client.dry_run_batch_process_payroll(&a);
    assert!(!report.would_succeed);
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::DraftNotPreCommitted));
}

#[test]
fn precommitted_draft_hash_is_not_reported_and_is_not_consumed() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);
    let admin = client.get_addresses().admin;

    let draft_hash = BytesN::from_array(&env, &[9u8; 32]);
    client.commit_draft(&admin, &draft_hash);

    let mut a = args(&env, &employee, 100, 1);
    a.draft_hash = Some(draft_hash);
    let report = client.dry_run_batch_process_payroll(&a);
    assert!(!report
        .blockers
        .contains(&PayrollFailureReason::DraftNotPreCommitted));

    // The dry-run must not have consumed the pre-commitment: calling it
    // again with the same args must still see it as pre-committed.
    let report_again = client.dry_run_batch_process_payroll(&a);
    assert!(!report_again
        .blockers
        .contains(&PayrollFailureReason::DraftNotPreCommitted));
}

#[test]
fn dry_run_never_writes_run_nonce_state() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    let a = args(&env, &employee, 100, 3);
    // Run the dry-run twice with the identical nonce: if it had consumed the
    // nonce on the first call, the second call would report
    // DuplicateRunNonce, which it must not.
    let first = client.dry_run_batch_process_payroll(&a);
    let second = client.dry_run_batch_process_payroll(&a);
    assert!(!first
        .blockers
        .contains(&PayrollFailureReason::DuplicateRunNonce));
    assert!(!second
        .blockers
        .contains(&PayrollFailureReason::DuplicateRunNonce));
}

#[test]
fn asset_not_allowed_is_reported_by_default() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    // Deliberately skip allow_token: common::setup never allowlists its
    // token on its own.

    let report = client.dry_run_batch_process_payroll(&args(&env, &employee, 100, 1));
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::AssetNotAllowed));
}

#[test]
fn insufficient_treasury_balance_is_reported() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);

    // common::setup funds the treasury with exactly 1_000_000; request more
    // than that so the balance check is the blocker under test.
    let report = client.dry_run_batch_process_payroll(&args(&env, &employee, 2_000_000, 1));
    assert!(report
        .blockers
        .contains(&PayrollFailureReason::InsufficientTreasuryBalance));
}

#[test]
fn dry_run_never_moves_funds() {
    let env = Env::default();
    let (client, token, employee) = common::setup(&env);
    allow_token(&client, &token);
    let token_client = TokenClient::new(&env, &token);
    let before = token_client.balance(&employee);

    client.dry_run_batch_process_payroll(&args(&env, &employee, 100, 1));

    assert_eq!(
        token_client.balance(&employee),
        before,
        "a dry run must never transfer funds"
    );
}
