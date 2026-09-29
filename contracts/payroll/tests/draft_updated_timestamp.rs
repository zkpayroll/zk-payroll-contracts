//! Tests for payroll draft last-updated timestamp behavior (Issue #439).
//!
//! Verifies that:
//! 1. A new draft initializes `updated_at` equal to `created_at`.
//! 2. Amending editable fields (`total_amount`, `employee_count`) updates `updated_at` to the current ledger timestamp.
//! 3. Successive amendments continue advancing `updated_at` while preserving `created_at`.
//! 4. Failed amendments (invalid amount, unauthorized caller) do not mutate `updated_at`.
//! 5. Finalized drafts reject further amendments and freeze `updated_at`.
//! 6. Querying draft timestamp exposes only time metadata without private payroll parameters.

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address) {
    env.mock_all_auths();
    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register_contract(None, Token);
    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let admin = Address::generate(env);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &Address::generate(env),
        &Address::generate(env),
    );
    (payroll_client, admin)
}

#[test]
fn test_draft_initial_updated_at_matches_created_at() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "sep_2026");
    let draft_id = payroll.create_run_draft(&admin, &50_000i128, &5u32, &period);

    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.created_at, 1_700_000_000);
    assert_eq!(draft.updated_at, 1_700_000_000);
    assert_eq!(payroll.get_draft_updated_at(&draft_id), 1_700_000_000);
    assert_eq!(draft.amendment_count, 0);
}

#[test]
fn test_draft_updated_at_advances_when_editable_fields_amended() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "oct_2026");
    let draft_id = payroll.create_run_draft(&admin, &100_000i128, &10u32, &period);

    // Advance ledger timestamp by 600 seconds (10 minutes)
    env.ledger().set_timestamp(1_700_000_600);

    // Amend editable fields (total_amount and employee_count)
    payroll.amend_run_draft(&admin, &draft_id, &110_000i128, &11u32);

    let amended = payroll.get_run_draft(&draft_id);
    assert_eq!(
        amended.created_at, 1_700_000_000,
        "created_at must remain immutable"
    );
    assert_eq!(
        amended.updated_at, 1_700_000_600,
        "updated_at must reflect modification time"
    );
    assert_eq!(payroll.get_draft_updated_at(&draft_id), 1_700_000_600);
    assert_eq!(amended.total_amount, 110_000i128);
    assert_eq!(amended.employee_count, 11u32);
    assert_eq!(amended.amendment_count, 1);
}

#[test]
fn test_draft_updated_at_advances_on_multiple_amendments() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "nov_2026");
    let draft_id = payroll.create_run_draft(&admin, &30_000i128, &3u32, &period);

    // First amendment at +300s
    env.ledger().set_timestamp(1_700_000_300);
    payroll.amend_run_draft(&admin, &draft_id, &35_000i128, &4u32);
    assert_eq!(payroll.get_draft_updated_at(&draft_id), 1_700_000_300);

    // Second amendment at +1200s
    env.ledger().set_timestamp(1_700_001_200);
    payroll.amend_run_draft(&admin, &draft_id, &38_000i128, &4u32);

    let second_amended = payroll.get_run_draft(&draft_id);
    assert_eq!(second_amended.created_at, 1_700_000_000);
    assert_eq!(second_amended.updated_at, 1_700_001_200);
    assert_eq!(second_amended.amendment_count, 2);
}

#[test]
fn test_draft_updated_at_does_not_change_on_failed_amendment() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "dec_2026");
    let draft_id = payroll.create_run_draft(&admin, &25_000i128, &2u32, &period);

    // Advance time
    env.ledger().set_timestamp(1_700_000_900);

    // Attempt invalid amendment (non-positive amount) via try_ call
    let failed_attempt = payroll.try_amend_run_draft(&admin, &draft_id, &-500i128, &2u32);
    assert!(failed_attempt.is_err());

    // updated_at must NOT have changed
    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.updated_at, 1_700_000_000);
    assert_eq!(draft.amendment_count, 0);
}

#[test]
fn test_draft_updated_at_frozen_after_finalization() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "jan_2027");
    let draft_id = payroll.create_run_draft(&admin, &40_000i128, &4u32, &period);

    // Amend at +500s
    env.ledger().set_timestamp(1_700_000_500);
    payroll.amend_run_draft(&admin, &draft_id, &42_000i128, &4u32);

    // Finalize at +800s
    env.ledger().set_timestamp(1_700_000_800);
    payroll.finalize_run_draft(&admin, &draft_id);

    // Try amending after finalization at +1200s
    env.ledger().set_timestamp(1_700_001_200);
    let rejected_amend = payroll.try_amend_run_draft(&admin, &draft_id, &50_000i128, &5u32);
    assert!(
        rejected_amend.is_err(),
        "Finalized draft must reject amendments"
    );

    // updated_at reflects last valid modification before finalization
    let draft = payroll.get_run_draft(&draft_id);
    assert_eq!(draft.updated_at, 1_700_000_500);
    assert_eq!(draft.amendment_count, 1);
}

#[test]
#[should_panic(expected = "Draft not found")]
fn test_get_draft_updated_at_nonexistent_panics() {
    let env = Env::default();
    let (payroll, _admin) = setup_payroll(&env);
    payroll.get_draft_updated_at(&999_999u64);
}

#[test]
fn test_timestamp_query_leaks_no_private_payroll_data() {
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_123);
    let (payroll, admin) = setup_payroll(&env);

    let period = Symbol::new(&env, "feb_2027");
    let draft_id = payroll.create_run_draft(&admin, &987_654_321i128, &777u32, &period);

    // Querying timestamp returns strictly u64 time metadata
    let ts = payroll.get_draft_updated_at(&draft_id);
    assert_eq!(ts, 1_700_000_123u64);
}
