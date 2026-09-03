//! Treasury Withdrawal Guardrails Integration Tests (#343)

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
use token::{Token, TokenClient};

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

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn setup_payroll(
    env: &Env,
) -> (
    PayrollClient<'_>,
    Address,
    Address,
    Address,
    Address,
    Address,
) {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    let verifier_admin = Address::generate(env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);

    token_client.mint(&treasury, &1_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);
    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

    (
        payroll_client,
        admin,
        treasury,
        treasury_owner,
        employee,
        token_id,
    )
}

#[test]
fn test_withdrawal_before_lock_and_after_cancellation() {
    let env = Env::default();
    let (client, admin, treasury, treasury_owner, employee, token_id) = setup_payroll(&env);

    let token_client = TokenClient::new(&env, &token_id);
    let total_balance = token_client.balance(&treasury);

    // Initial state: locked funds = 0, available = total_balance
    assert_eq!(client.get_locked_funds(&token_id), 0);
    assert_eq!(
        client.get_available_treasury_balance(&token_id),
        total_balance
    );

    // Prepare payroll run locking 50,000
    let mut proofs = Vec::new(&env);
    proofs.push_back(mock_proof(&env));
    let mut amounts = Vec::new(&env);
    amounts.push_back(50_000i128);
    let mut employees = Vec::new(&env);
    employees.push_back(employee);

    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &50_000i128,
        &test_nonce(&env, 12),
        &None,
    );

    assert_eq!(client.get_locked_funds(&token_id), 50_000);
    assert_eq!(
        client.get_available_treasury_balance(&token_id),
        total_balance - 50_000
    );

    // Safe surplus withdrawal of 10,000
    let recipient = Address::generate(&env);
    client.request_emergency_withdrawal(&treasury_owner, &10_000i128, &recipient);
    client.approve_emergency_withdrawal(&admin);

    // Cancel payroll run -> locked funds return to 0
    client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "cancelled"));
    assert_eq!(client.get_locked_funds(&token_id), 0);
    assert_eq!(
        client.get_available_treasury_balance(&token_id),
        total_balance - 10_000
    );
}

#[test]
#[should_panic(
    expected = "Insufficient available treasury balance: funds locked for pending payroll"
)]
fn test_withdrawal_attempt_exceeding_surplus_rejected() {
    let env = Env::default();
    let (client, _admin, treasury, treasury_owner, employee, token_id) = setup_payroll(&env);

    let token_client = TokenClient::new(&env, &token_id);
    let total_balance = token_client.balance(&treasury);

    // Lock almost all funds in payroll run
    let mut proofs = Vec::new(&env);
    proofs.push_back(mock_proof(&env));
    let mut amounts = Vec::new(&env);
    amounts.push_back(total_balance - 500);
    let mut employees = Vec::new(&env);
    employees.push_back(employee);

    let _run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &(total_balance - 500),
        &test_nonce(&env, 13),
        &None,
    );

    // Available surplus is 500. Withdrawing 1,000 must panic.
    let recipient = Address::generate(&env);
    client.request_emergency_withdrawal(&treasury_owner, &1_000i128, &recipient);
}
