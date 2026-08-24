//! Shared helpers for employee status transition tests.
//!
//! Wires the full contract stack the way `payment_executor` expects
//! (registry, salary commitment, proof verifier, token) and provides
//! small seeding helpers so each test only describes what it varies.

#![allow(dead_code)]

use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{EmployeeStatus, PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};
use token::{Token, TokenClient};

/// Standard test payroll amount used by the eligibility tests.
pub const PAYMENT_AMOUNT: i128 = 1_000;
/// Treasury mint size that comfortably covers a single test payment.
pub const TREASURY_FUNDING: i128 = 10_000;

/// Deterministic 32-byte commitment derived from a seed byte.
pub fn commitment(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

/// Mock Groth16 verification key accepted by `ProofVerifier`.
///
/// The verifier accepts zeroed keys in test mode, so payments can exercise
/// the full execution path without real circuit artifacts.
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
            ],
        ),
    }
}

/// A fully wired contract environment.
///
/// Clients borrow from [`TestEnv::env`], so tests create them per scope:
/// `PayrollRegistryClient::new(&t.env, &t.addresses.registry)`.
pub struct TestEnv {
    pub env: Env,
    pub addresses: ContractAddresses,
    pub executor_id: Address,
}

impl TestEnv {
    /// Deploy and initialize every contract with mocked authentication.
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);
        let executor_id = env.register_contract(None, PaymentExecutor);

        let verifier = ProofVerifierClient::new(&env, &verifier_id);
        verifier.init_verifier_admin(&Address::generate(&env));
        verifier.initialize_verifier(&mock_vk(&env));

        let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
        commitment.init_commitment_admin(&Address::generate(&env));

        let addresses = ContractAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id,
        };

        PaymentExecutorClient::new(&env, &executor_id).initialize(&addresses);

        Self {
            env,
            addresses,
            executor_id,
        }
    }

    /// Register a company and fund its treasury.
    ///
    /// Returns `(company_id, admin, treasury)`.
    pub fn register_company(&self) -> (u64, Address, Address) {
        let admin = Address::generate(&self.env);
        let treasury = Address::generate(&self.env);

        let company_id = self.registry().register_company(&admin, &treasury);

        self.token().mint(&treasury, &TREASURY_FUNDING);

        (company_id, admin, treasury)
    }

    /// Add an employee whose salary commitment matches their registry entry
    /// and whose status starts as [`EmployeeStatus::Active`].
    pub fn add_active_employee(&self, company_id: u64, seed: u8) -> Address {
        let employee = Address::generate(&self.env);
        let commit = commitment(&self.env, seed);

        self.commitment_store().store_commitment(&employee, &commit);
        self.registry().add_employee(&company_id, &employee, &commit);

        employee
    }

    /// Open payroll period 1 for the company.
    pub fn open_period(&self, company_id: u64) {
        self.executor().create_period(&company_id);
    }

    pub fn registry(&self) -> PayrollRegistryClient<'_> {
        PayrollRegistryClient::new(&self.env, &self.addresses.registry)
    }

    pub fn commitment_store(&self) -> SalaryCommitmentContractClient<'_> {
        SalaryCommitmentContractClient::new(&self.env, &self.addresses.commitment)
    }

    pub fn token(&self) -> TokenClient<'_> {
        TokenClient::new(&self.env, &self.addresses.token)
    }

    pub fn executor(&self) -> PaymentExecutorClient<'_> {
        PaymentExecutorClient::new(&self.env, &self.executor_id)
    }

    /// Set the employee status as the company admin would.
    pub fn set_status(&self, company_id: u64, employee: &Address, status: EmployeeStatus) {
        self.registry()
            .set_employee_status(&company_id, employee, &status);
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}
