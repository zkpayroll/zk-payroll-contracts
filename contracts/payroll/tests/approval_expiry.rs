//! Payroll approval expiry validation tests (#403).

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, DEFAULT_APPROVAL_EXPIRY_SECONDS};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Vec};

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
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

    (payroll_client, admin, treasury, treasury_owner, employee)
}

fn single_payment_batch(
    env: &Env,
    employee: &Address,
    amount: i128,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    let mut proofs = Vec::new(env);
    proofs.push_back(mock_proof(env));
    let mut amounts = Vec::new(env);
    amounts.push_back(amount);
    let mut employees = Vec::new(env);
    employees.push_back(employee.clone());
    (proofs, amounts, employees)
}

#[test]
fn test_approval_validity_window() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 30);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &nonce,
        &None,
    );

    payroll.approve_payroll_run(&reviewer, &run_id);
    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 5;
    });

    assert!(payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

#[test]
#[should_panic(expected = "Payroll approval expired: approval record exceeds maximum allowed age")]
fn test_finalize_panics_after_approval_expiry() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 31);
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &nonce,
        &None,
    );

    payroll.approve_payroll_run(&reviewer, &run_id);

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 10;
    });

    payroll.finalize_payroll_run(&admin, &run_id);
}
