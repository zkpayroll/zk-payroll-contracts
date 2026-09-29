//! Tests for payroll period reopening in PaymentExecutor (#484).
//!
//! Acceptance criteria:
//! - Only the authorized company admin can reopen a closed period.
//! - Unauthorized users cannot reopen a closed period.
//! - Reopening an already open period fails with `PeriodAlreadyOpen`.
//! - Reopening when another period is already active fails with `PeriodAlreadyExists`.
//! - Reopening a non-existent period fails with `PeriodNotFound`.
//! - Reopening emits the `PeriodReopened` event with non-sensitive identifiers.
//! - Payments can resume after a period is reopened.

#![cfg(test)]

use ::token::{Token, TokenClient};
use pause_manager::{PauseManager, PauseManagerClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

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
            ],
        ),
    }
}

fn setup_system<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,
    Address,
    Address,
) {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);

    let company_id = registry.register_company(&admin, &treasury);

    token.mint(&treasury, &1_000_000);

    let tax_addr = Address::generate(env);
    executor.set_withholding_config(
        &company_id,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    (
        executor,
        registry,
        commitment_client,
        token,
        company_id,
        admin,
        treasury,
    )
}

#[test]
fn test_authorized_admin_can_reopen_closed_period() {
    let env = Env::default();
    let (executor, registry, commitment_client, _token, company_id, admin, _treasury) =
        setup_system(&env);

    // 1. Create and close period 1
    let p1 = executor.create_period(&company_id);
    assert_eq!(p1.period_id, 1);
    assert!(!p1.closed);

    // Close period 1
    let closed_p1 = executor.close_period(&company_id, &1);
    assert!(closed_p1.closed);
    assert!(closed_p1.end_ledger > 0);

    // 2. Reopen period 1
    let reopened_p1 = executor.reopen_period(&company_id, &1);
    assert!(!reopened_p1.closed);
    assert_eq!(reopened_p1.end_ledger, 0);

    // Verify persisted state reflects reopening
    let fetched = executor.get_period(&company_id, &1).unwrap();
    assert!(!fetched.closed);
    assert_eq!(fetched.end_ledger, 0);

    // 3. Payments can be executed in reopened period
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[1u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    let record = executor.execute_payment(
        &company_id,
        &employee,
        &5_000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );
    assert_eq!(record.period, 1);
    assert!(executor.is_paid(&employee, &1));
}

#[test]
fn test_reopen_already_open_period_fails() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    executor.create_period(&company_id);

    // Period is already open -> reopen must fail with PeriodAlreadyOpen
    let res = executor.try_reopen_period(&company_id, &1);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PeriodAlreadyOpen);
}

#[test]
fn test_reopen_nonexistent_period_fails() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    let res = executor.try_reopen_period(&company_id, &999);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PeriodNotFound);
}

#[test]
fn test_reopen_period_when_another_period_is_active_fails() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    // Period 1 created and closed
    executor.create_period(&company_id);
    executor.close_period(&company_id, &1);

    // Period 2 created (now period 2 is active)
    executor.create_period(&company_id);

    // Reopening period 1 while period 2 is active must fail with PeriodAlreadyExists
    let res = executor.try_reopen_period(&company_id, &1);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().unwrap(), PaymentError::PeriodAlreadyExists);

    // Close period 2
    executor.close_period(&company_id, &2);

    // Now period 1 can be successfully reopened
    let reopened = executor.reopen_period(&company_id, &1);
    assert!(!reopened.closed);
}

#[test]
#[should_panic(expected = "Company admin is revoked")]
fn test_reopen_period_revoked_admin_fails() {
    let env = Env::default();
    let (executor, registry, _commitment_client, _token, company_id, admin, _treasury) =
        setup_system(&env);

    executor.create_period(&company_id);
    executor.close_period(&company_id, &1);

    registry.revoke_company_admin(&company_id, &admin);

    executor.reopen_period(&company_id, &1);
}

#[test]
#[should_panic(expected = "Contract is paused")]
fn test_reopen_period_while_paused_fails() {
    let env = Env::default();
    let (executor, _registry, _commitment_client, _token, company_id, _admin, _treasury) =
        setup_system(&env);

    executor.create_period(&company_id);
    executor.close_period(&company_id, &1);

    let pm_id = env.register_contract(None, PauseManager);
    let pm = PauseManagerClient::new(&env, &pm_id);
    let pm_admin = Address::generate(&env);
    pm.initialize(&pm_admin);
    executor.set_pause_manager(&pm_id);

    pm.pause();
    assert!(pm.is_paused());

    executor.reopen_period(&company_id, &1);
}
