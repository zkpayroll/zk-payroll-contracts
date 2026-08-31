#![allow(dead_code)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0; 64]),
        beta: BytesN::from_array(env, &[0; 128]),
        gamma: BytesN::from_array(env, &[0; 128]),
        delta: BytesN::from_array(env, &[0; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
            ],
        ),
    }
}

pub fn setup(env: &Env) -> (PayrollClient<'_>, Address, Address) {
    env.mock_all_auths();

    let verifier = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token = env.register_contract(None, Token);
    let treasury = Address::generate(env);
    TokenClient::new(env, &token).mint(&treasury, &1_000_000);

    let contract = env.register_contract(None, Payroll);
    let client = PayrollClient::new(env, &contract);
    let admin = Address::generate(env);
    client.initialize(
        &admin,
        &token,
        &verifier,
        &commitment,
        &treasury,
        &Address::generate(env),
    );
    commitment_client.set_payroll_operator(&contract);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0; 32]));
    (client, token, employee)
}

pub fn nonce(env: &Env, marker: u8) -> BytesN<32> {
    let mut bytes = [0; 32];
    bytes[0] = marker;
    BytesN::from_array(env, &bytes)
}

pub fn one_payment(env: &Env, employee: &Address) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    (
        Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]),
        Vec::from_array(env, [100_i128]),
        Vec::from_array(env, [employee.clone()]),
    )
}
