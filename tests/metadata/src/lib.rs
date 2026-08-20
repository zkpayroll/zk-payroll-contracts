#![cfg(test)]

use audit_module::{AuditModule, AuditModuleClient, AuditScope};
use pause_manager::{PauseManager, PauseManagerClient};
use payroll::{Payroll, PayrollClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::ProofVerifier;
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, String, Symbol, Vec,
};
use token::{Token, TokenClient};

fn setup_system(
    env: &Env,
) -> (
    PayrollClient<'static>,
    PayrollRegistryClient<'static>,
    SalaryCommitmentContractClient<'static>,
    AuditModuleClient<'static>,
    Address, // admin
    Address, // treasury
    Address, // employee
) {
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1000);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let treasury_owner = Address::generate(env);
    let employee = Address::generate(env);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);
    token_client.initialize(
        &admin,
        &7,
        &String::from_str(env, "USD Dollar"),
        &String::from_str(env, "USDC"),
    );
    token_client.mint(&treasury, &1_000_000);

    let pause_manager_id = env.register_contract(None, PauseManager);
    let pause_manager_client = PauseManagerClient::new(env, &pause_manager_id);
    pause_manager_client.initialize(&admin);

    let proof_verifier_id = env.register_contract(None, ProofVerifier);
    let proof_verifier_client = proof_verifier::ProofVerifierClient::new(env, &proof_verifier_id);
    proof_verifier_client.init_verifier_admin(&admin);
    let mock_vk = proof_verifier::VerificationKey {
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
    };
    proof_verifier_client.initialize_verifier(&mock_vk);

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry_client = PayrollRegistryClient::new(env, &registry_id);

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let audit_id = env.register_contract(None, AuditModule);
    let audit_client = AuditModuleClient::new(env, &audit_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &proof_verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    (
        payroll_client,
        registry_client,
        commitment_client,
        audit_client,
        admin,
        treasury,
        employee,
    )
}

fn valid_hash(env: &Env, val: u8) -> BytesN<32> {
    BytesN::from_array(env, &[val; 32])
}

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

// ── 1. Payroll ID Validation Tests ──────────────────────────────────────────

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_get_payroll_run_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, _, _, _) = setup_system(&env);
    payroll.get_payroll_run(&u64::MAX);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_cancel_payroll_run_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    let reason = Symbol::new(&env, "cancel_test");
    payroll.cancel_payroll_run_with_reason(&admin, &u64::MAX, &reason);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_archive_payroll_run_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    payroll.archive_payroll_run(&admin, &u64::MAX);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_get_archived_run_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, _, _, _) = setup_system(&env);
    payroll.get_archived_run(&u64::MAX);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_is_run_archived_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, _, _, _) = setup_system(&env);
    payroll.is_run_archived(&u64::MAX);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_get_metadata_hash_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, _, _, _) = setup_system(&env);
    payroll.get_metadata_hash(&u64::MAX);
}

#[test]
#[should_panic(expected = "Invalid payroll run ID")]
fn test_set_run_metadata_max_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    let hash = valid_hash(&env, 0xaa);
    payroll.commit_metadata_hash(&admin, &hash);
    payroll.set_run_metadata(&admin, &u64::MAX, &hash);
}

#[test]
#[should_panic(expected = "Invalid draft ID: must be non-zero")]
fn test_amend_run_draft_zero_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    payroll.amend_run_draft(&admin, &0u64, &1000i128, &5u32);
}

// ── 2. Reference ID & Period Label Length Validation Tests ────────────────

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_set_employee_reference_id_empty_panics() {
    let env = Env::default();
    let (_, _, commitment, _, _, _, employee) = setup_system(&env);
    let empty_ref = String::from_str(&env, "");
    commitment.set_employee_reference_id(&employee, &empty_ref);
}

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_set_employee_reference_id_over_256_chars_panics() {
    let env = Env::default();
    let (_, _, commitment, _, _, _, employee) = setup_system(&env);
    let long_str = "a".repeat(257);
    let long_ref = String::from_str(&env, &long_str);
    commitment.set_employee_reference_id(&employee, &long_ref);
}

#[test]
fn test_set_employee_reference_id_valid_length_succeeds() {
    let env = Env::default();
    let (_, _, commitment, _, _, _, employee) = setup_system(&env);

    let valid_ref_min = String::from_str(&env, "E1");
    commitment.set_employee_reference_id(&employee, &valid_ref_min);
    assert_eq!(
        commitment.get_employee_reference_id(&employee),
        Some(valid_ref_min.clone())
    );

    let long_str = "EMP-".to_string() + &"9".repeat(240);
    let valid_ref_max = String::from_str(&env, &long_str);
    commitment.set_employee_reference_id(&employee, &valid_ref_max);
    assert_eq!(
        commitment.get_employee_reference_id(&employee),
        Some(valid_ref_max.clone())
    );
}

#[test]
#[should_panic]
fn test_create_run_draft_empty_period_label_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    let empty_label = Symbol::new(&env, "");
    payroll.create_run_draft(&admin, &5000i128, &10u32, &empty_label);
}

// ── 3. Reason Length & Non-Empty Validation Tests ─────────────────────────

#[test]
#[should_panic]
fn test_cancel_payroll_run_empty_reason_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);

    let draft_label = Symbol::new(&env, "Q1_2026");
    let draft_id = payroll.create_run_draft(&admin, &5000i128, &2u32, &draft_label);
    assert!(draft_id > 0);

    let empty_reason = Symbol::new(&env, "");
    payroll.cancel_payroll_run_with_reason(&admin, &1u64, &empty_reason);
}

#[test]
fn test_cancel_payroll_run_valid_reason_succeeds() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, employee) = setup_system(&env);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let mut proofs = Vec::new(&env);
    proofs.push_back(proof);
    let mut amounts = Vec::new(&env);
    amounts.push_back(1000i128);
    let mut employees = Vec::new(&env);
    employees.push_back(employee);

    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &1000i128,
        &valid_hash(&env, 0x11),
        &None,
    );
    assert_eq!(run_id, 1);
    assert!(payroll.get_pending_run(&run_id).is_some());

    let valid_reason = Symbol::new(&env, "budget_update");
    payroll.cancel_payroll_run_with_reason(&admin, &run_id, &valid_reason);
}

// ── 4. Digest / Hash Value Non-Zero Validation Tests ─────────────────────

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_commit_metadata_hash_all_zero_digest_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    payroll.commit_metadata_hash(&admin, &zero_hash(&env));
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_commit_draft_all_zero_digest_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    payroll.commit_draft(&admin, &zero_hash(&env));
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_deposit_all_zero_id_panics() {
    let env = Env::default();
    let (payroll, _, _, _, admin, _, _) = setup_system(&env);
    payroll.deposit(&admin, &1000i128, &zero_hash(&env));
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_batch_process_payroll_all_zero_nonce_panics() {
    let env = Env::default();
    let (payroll, _, _, _, _, _, employee) = setup_system(&env);

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let mut proofs = Vec::new(&env);
    proofs.push_back(proof);
    let mut amounts = Vec::new(&env);
    amounts.push_back(1000i128);
    let mut employees = Vec::new(&env);
    employees.push_back(employee);

    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1000i128,
        &zero_hash(&env),
        &None,
    );
}

#[test]
#[should_panic(expected = "Metadata hash cannot be all-zero digest")]
fn test_audit_verify_payroll_metadata_all_zero_digest_panics() {
    let env = Env::default();
    let (_, _, _, audit, _admin, _, _) = setup_system(&env);

    let auditor = Address::generate(&env);
    let expiration = env.ledger().sequence() + 1_000;
    let _key_bytes = audit.generate_view_key(&auditor, &expiration);

    let _ = audit.verify_payroll_metadata(
        &auditor,
        &zero_hash(&env),
        &valid_hash(&env, 0x55),
        &AuditScope::FullCompany,
    );
}

// ── 5. Privacy & Zero-Knowledge Verification Tests ───────────────────────

#[test]
fn test_metadata_validation_preserves_privacy() {
    let env = Env::default();
    let (payroll, _, commitment, _, admin, _, employee) = setup_system(&env);
    commitment.store_commitment(&employee, &valid_hash(&env, 0x99));

    let proof = BytesN::from_array(&env, &[1u8; 256]);
    let mut proofs = Vec::new(&env);
    proofs.push_back(proof);
    let mut amounts = Vec::new(&env);
    amounts.push_back(50_000i128);
    let mut employees = Vec::new(&env);
    employees.push_back(employee);

    let nonce = valid_hash(&env, 0x77);
    let meta_hash = valid_hash(&env, 0x88);

    payroll.commit_metadata_hash(&admin, &meta_hash);
    let run_id =
        payroll.batch_process_payroll(&proofs, &amounts, &employees, &50_000i128, &nonce, &None);
    payroll.set_run_metadata(&admin, &run_id, &meta_hash);

    let run = payroll.get_payroll_run(&run_id);
    assert_eq!(run.metadata_hash, meta_hash);
    assert_eq!(run.run_id, 1);
    assert_eq!(run.employee_count, 1);
    assert_eq!(run.total_amount, 50_000i128);
}
