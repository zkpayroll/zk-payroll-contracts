//! Bounded batch processing tests for Issue #475.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Vec};

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

fn setup_payroll(
    env: &Env,
) -> (
    PayrollClient<'_>,
    SalaryCommitmentContractClient<'_>,
    TokenClient<'_>,
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

    (
        payroll_client,
        commitment_client,
        token_client,
        admin,
        treasury,
        treasury_owner,
    )
}

fn prepare_employees(
    env: &Env,
    commitment_client: &SalaryCommitmentContractClient<'_>,
    count: usize,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    let mut proofs = Vec::new(env);
    let mut amounts = Vec::new(env);
    let mut employees = Vec::new(env);

    for i in 0..count {
        let emp = Address::generate(env);
        let mut seed = [0u8; 32];
        seed[0] = (i + 1) as u8;
        commitment_client.store_commitment(&emp, &BytesN::from_array(env, &seed));

        proofs.push_back(mock_proof(env));
        amounts.push_back(1_000i128);
        employees.push_back(emp);
    }

    (proofs, amounts, employees)
}

#[test]
fn test_bounded_batch_happy_path() {
    let env = Env::default();
    let (payroll, commitment_client, token_client, admin, _treasury, _treasury_owner) =
        setup_payroll(&env);

    let (proofs, amounts, employees) = prepare_employees(&env, &commitment_client, 3);
    let nonce = test_nonce(&env, 1);

    let run_id = payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &3u32,
    );

    assert!(run_id > 0);

    // Confirm all employees received transfers
    for i in 0..3 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(token_client.balance(&emp), 1_000i128);
    }
}

#[test]
fn test_bounded_batch_partial_and_resumption() {
    let env = Env::default();
    let (payroll, commitment_client, token_client, _admin, _treasury, _treasury_owner) =
        setup_payroll(&env);

    let (proofs, amounts, employees) = prepare_employees(&env, &commitment_client, 5);
    let nonce = test_nonce(&env, 2);

    // Step 1: Process batch of 5 with batch_size = 2 (processes employees 0 and 1)
    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(token_client.balance(&employees.get(0).unwrap()), 1_000);
    assert_eq!(token_client.balance(&employees.get(1).unwrap()), 1_000);
    assert_eq!(token_client.balance(&employees.get(2).unwrap()), 0);

    // Step 2: Resume batch processing (processes employees 2 and 3)
    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(token_client.balance(&employees.get(2).unwrap()), 1_000);
    assert_eq!(token_client.balance(&employees.get(3).unwrap()), 1_000);
    assert_eq!(token_client.balance(&employees.get(4).unwrap()), 0);

    // Step 3: Final resumption (processes employee 4)
    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(token_client.balance(&employees.get(4).unwrap()), 1_000);

    // Verify employee 0 was NOT double paid
    assert_eq!(token_client.balance(&employees.get(0).unwrap()), 1_000);
}

#[test]
#[should_panic(expected = "Batch size exceeds maximum limit of 50")]
fn test_bounded_batch_over_cap_rejected() {
    let env = Env::default();
    let (payroll, commitment_client, _token_client, _admin, _treasury, _treasury_owner) =
        setup_payroll(&env);

    let (proofs, amounts, employees) = prepare_employees(&env, &commitment_client, 1);
    let nonce = test_nonce(&env, 3);

    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &nonce,
        &None,
        &51u32,
    );
}

#[test]
#[should_panic(expected = "Empty payroll batch")]
fn test_bounded_batch_empty_batch_rejected() {
    let env = Env::default();
    let (payroll, _commitment_client, _token_client, _admin, _treasury, _treasury_owner) =
        setup_payroll(&env);

    let proofs = Vec::new(&env);
    let amounts = Vec::new(&env);
    let employees = Vec::new(&env);
    let nonce = test_nonce(&env, 4);

    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &0i128,
        &nonce,
        &None,
        &10u32,
    );
}

#[test]
#[should_panic(expected = "Batch size must be greater than zero")]
fn test_bounded_batch_zero_batch_size_rejected() {
    let env = Env::default();
    let (payroll, commitment_client, _token_client, _admin, _treasury, _treasury_owner) =
        setup_payroll(&env);

    let (proofs, amounts, employees) = prepare_employees(&env, &commitment_client, 1);
    let nonce = test_nonce(&env, 5);

    payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &nonce,
        &None,
        &0u32,
    );
}

#[test]
#[should_panic(expected = "authorized")]
fn test_bounded_batch_unauthorized_caller_rejected() {
    let env = Env::default();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    let verifier_admin = Address::generate(&env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    let treasury = Address::generate(&env);
    let admin = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    let emp = Address::generate(&env);
    commitment_client.store_commitment(&emp, &BytesN::from_array(&env, &[1u8; 32]));

    let mut proofs = Vec::new(&env);
    proofs.push_back(mock_proof(&env));
    let mut amounts = Vec::new(&env);
    amounts.push_back(1_000i128);
    let mut employees = Vec::new(&env);
    employees.push_back(emp);
    let nonce = test_nonce(&env, 6);

    let attacker = Address::generate(&env);
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &attacker,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "batch_process_payroll_bounded",
            args: (
                proofs.clone(),
                amounts.clone(),
                employees.clone(),
                1_000i128,
                nonce.clone(),
                Option::<BytesN<32>>::None,
                10u32,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &nonce,
        &None,
        &10u32,
    );
}
