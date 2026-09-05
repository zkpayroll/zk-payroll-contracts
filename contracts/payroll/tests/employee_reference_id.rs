//! Tests for employee reference identifiers used in payroll safe lookup flows.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec, String};

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

fn setup_payroll_with_reference(env: &Env) -> (PayrollClient<'_>, SalaryCommitmentContractClient<'_>, Address, Address, Address, String) {
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

    // Set employee reference ID (safe lookup key)
    let ref_id = String::from_str(env, "EMP-ZK-999");
    commitment_client.set_employee_reference_id(&employee, &ref_id);

    (payroll_client, commitment_client, admin, employee, treasury, ref_id)
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
fn test_safe_lookup_and_batch_preparation() {
    let env = Env::default();
    let (payroll, commitment, admin, original_employee, _treasury, ref_id) = setup_payroll_with_reference(&env);

    // 1. External system uses the safe reference ID to fetch the on-chain employee address
    let resolved_employee = commitment.get_employee_by_reference_id(&ref_id).expect("Employee should exist");
    
    // Verify it resolves correctly
    assert_eq!(resolved_employee, original_employee);

    // 2. We use the resolved address to construct a payroll batch
    let (proofs, amounts, employees) = single_payment_batch(&env, &resolved_employee, 10_000);
    let nonce = test_nonce(&env, 42);

    // 3. Prepare the batch. This demonstrates the lookup flow correctly integrating with batch execution
    // without exposing private values tied to the reference ID directly.
    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &10_000,
        &nonce,
        &None,
    );

    assert!(run_id > 0);

    // 4. Finalize the batch
    payroll.finalize_payroll_run(&admin, &run_id);
    
    // Reverse check: Given an employee in a batch, can we get their reference ID safely?
    let retrieved_ref_id = commitment.get_employee_reference_id(&resolved_employee).expect("Should have reference ID");
    assert_eq!(retrieved_ref_id, ref_id);
}
