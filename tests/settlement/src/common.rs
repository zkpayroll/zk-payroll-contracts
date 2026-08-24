//! Shared helpers for settlement state transition tests.
//!
//! Mirrors the setup used by the payroll contract's own unit tests so the
//! settlement suite exercises the real, fully wired contract stack.

#![allow(dead_code)]

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};
use token::{Token, TokenClient};

/// Standard single-employee payment batch for preparing a run.
pub fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

/// Unique 32-byte run nonce derived from a seed.
pub fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

/// Mock Groth16 verification key accepted by `ProofVerifier` in tests.
pub fn mock_vk(env: &Env) -> VerificationKey {
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

/// A fully wired payroll environment plus the roles the tests need.
pub struct Setup {
    pub env: Env,
    pub payroll: PayrollClient<'static>,
    pub admin: Address,
    pub treasury: Address,
    pub treasury_owner: Address,
    pub employee: Address,
}

impl Setup {
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

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
        let token_client = TokenClient::new(&env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll = PayrollClient::new(&env, &payroll_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        token_client.mint(&treasury, &1_000_000i128);
        payroll.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(&env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

        // SAFETY: all clients borrow `env`, which lives for the lifetime of
        // `Setup`. The transmute keeps the API ergonomic for test code.
        let payroll = unsafe { extend_client_lifetime(payroll) };

        Self {
            env,
            payroll,
            admin,
            treasury,
            treasury_owner,
            employee,
        }
    }

    /// Single-employee payment batch used to prepare a payroll run.
    pub fn single_payment_batch(&self, amount: i128) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
        let mut proofs = Vec::new(&self.env);
        proofs.push_back(mock_proof(&self.env));
        let mut amounts = Vec::new(&self.env);
        amounts.push_back(amount);
        let mut employees = Vec::new(&self.env);
        employees.push_back(self.employee.clone());
        (proofs, amounts, employees)
    }

    /// Prepare a payroll run; it lands in the `Submitted` (`pending`) state.
    pub fn prepare_run(&self, seed: u8) -> u64 {
        let (proofs, amounts, employees) = self.single_payment_batch(1000);
        self.payroll.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&self.env, seed),
            &None,
        )
    }
}

unsafe fn extend_client_lifetime<'a>(client: PayrollClient<'a>) -> PayrollClient<'static> {
    std::mem::transmute::<PayrollClient<'a>, PayrollClient<'static>>(client)
}
