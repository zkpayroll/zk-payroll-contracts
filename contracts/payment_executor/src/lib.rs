#![no_std]

use pause_manager::PauseManagerClient;
use payroll_registry::{CompanyInfo, PayrollRegistryClient};
use proof_verifier::{Groth16Proof, ProofVerifierClient};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env,
};

/// Payment record
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentRecord {
    pub company_id: u64,
    pub employee: Address,
    pub proof_hash: BytesN<32>,
    pub timestamp: u64,
    pub period: u32,
}

/// A payroll period definition with scheduling metadata.
///
/// Each payroll run is tied to a unique period per company. Periods are
/// monotonically numbered and carry ledger-based scheduling metadata so
/// that downstream consumers (audit, UI reporting) can map payments to
/// calendar cycles without leaking salary values.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollPeriod {
    pub period_id: u32,
    pub company_id: u64,
    /// Ledger sequence at which the period was opened.
    pub start_ledger: u32,
    /// Ledger sequence at which the period was closed (0 = still open).
    pub end_ledger: u32,
    /// Unix timestamp when the period was created (on-chain time).
    pub created_at: u64,
    /// True when the period has been closed. Payments cannot be made
    /// against a closed period.
    pub closed: bool,
    /// Number of payments executed within this period.
    pub payment_count: u32,
}

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PaymentError {
    ProofAlreadyUsed = 1,
    ArrayLengthMismatch = 2,
    AlreadyPaid = 3,
    /// The payroll period does not exist.
    PeriodNotFound = 4,
    /// The payroll period is closed — no new payments allowed.
    PeriodClosed = 5,
    /// Attempt to create a duplicate period for this company.
    PeriodAlreadyExists = 6,
}

/// Contract addresses for dependencies
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub registry: Address,
    pub commitment: Address,
    pub verifier: Address,
    pub token: Address,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Addresses,
    Payment(Address, u32),
    Nullifier(BytesN<32>),
    TotalPaid(u64),
    ExecutorAdmin,
    PauseManager,
    Period(u64, u32),
    PeriodSequence(u64),
}

#[contract]
pub struct PaymentExecutor;

#[contractimpl]
impl PaymentExecutor {
    fn amount_to_public_input(env: &Env, amount: i128) -> BytesN<32> {
        if amount < 0 {
            panic!("Amount must be non-negative");
        }

        let mut bytes = [0u8; 32];
        let amount_u128 = amount as u128;
        bytes[16..].copy_from_slice(&amount_u128.to_be_bytes());
        BytesN::from_array(env, &bytes)
    }

    /// Initialize with contract addresses
    pub fn initialize(env: Env, addresses: ContractAddresses) {
        let key = DataKey::Addresses;
        if env.storage().persistent().has(&key) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&key, &addresses);
    }

    /// Set the executor-level admin (one-time, protected by auth).
    pub fn set_executor_admin(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::ExecutorAdmin) {
            panic!("Executor admin already set");
        }
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::ExecutorAdmin, &admin);
    }

    /// Set the pause manager contract address (only executor admin).
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set");
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    // -----------------------------------------------------------------------
    // Payroll period lifecycle
    // -----------------------------------------------------------------------

    /// Create a new payroll period for a company.
    ///
    /// Periods are numbered sequentially per company. Only one period can
    /// be open at a time — a new period cannot be created until the previous
    /// one is closed (or no periods exist yet).
    pub fn create_period(env: Env, company_id: u64) -> Result<PayrollPeriod, PaymentError> {
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);
        company.admin.require_auth();

        // Assign sequential period ID
        let seq_key = DataKey::PeriodSequence(company_id);
        let next_id: u32 = env.storage().persistent().get(&seq_key).unwrap_or(1u32);

        let period_key = DataKey::Period(company_id, next_id);
        if env.storage().persistent().has(&period_key) {
            return Err(PaymentError::PeriodAlreadyExists);
        }

        let period = PayrollPeriod {
            period_id: next_id,
            company_id,
            start_ledger: env.ledger().sequence(),
            end_ledger: 0,
            created_at: env.ledger().timestamp(),
            closed: false,
            payment_count: 0,
        };

        env.storage().persistent().set(&period_key, &period);
        env.storage().persistent().set(&seq_key, &(next_id + 1));

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "PeriodCreated"), company_id),
            (next_id,),
        );

        Ok(period)
    }

    /// Close a payroll period so no further payments can be made in it.
    pub fn close_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<PayrollPeriod, PaymentError> {
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);
        company.admin.require_auth();

        let period_key = DataKey::Period(company_id, period_id);
        let mut period: PayrollPeriod = env
            .storage()
            .persistent()
            .get(&period_key)
            .ok_or(PaymentError::PeriodNotFound)?;

        if period.closed {
            return Err(PaymentError::PeriodClosed);
        }

        period.closed = true;
        period.end_ledger = env.ledger().sequence();
        env.storage().persistent().set(&period_key, &period);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "PeriodClosed"), company_id),
            (period_id,),
        );

        Ok(period)
    }

    /// Read a period definition.
    pub fn get_period(env: Env, company_id: u64, period_id: u32) -> Option<PayrollPeriod> {
        let key = DataKey::Period(company_id, period_id);
        env.storage().persistent().get(&key)
    }

    // -----------------------------------------------------------------------
    // Payment execution
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn execute_payment(
        env: Env,
        company_id: u64,
        employee: Address,
        amount: i128,
        proof_a: BytesN<64>,
        proof_b: BytesN<128>,
        proof_c: BytesN<64>,
        nullifier: BytesN<32>,
        period: u32,
    ) -> Result<PaymentRecord, PaymentError> {
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // Check if pause manager is configured and system is paused
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        // Validate the period exists and is open
        let period_key = DataKey::Period(company_id, period);
        let mut period_record: PayrollPeriod = env
            .storage()
            .persistent()
            .get(&period_key)
            .ok_or(PaymentError::PeriodNotFound)?;

        if period_record.closed {
            return Err(PaymentError::PeriodClosed);
        }

        // Check cryptographically if the exact proof was submitted previously
        let nullifier_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(PaymentError::ProofAlreadyUsed);
        }

        // Check payment hasn't been made for this period
        let payment_key = DataKey::Payment(employee.clone(), period);
        if env.storage().persistent().has(&payment_key) {
            return Err(PaymentError::AlreadyPaid);
        }

        // Read on-chain commitment and company metadata from payroll_registry.
        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let on_chain_commitment = registry.get_commitment(&company_id, &employee);
        let company: CompanyInfo = registry.get_company(&company_id);

        // Ensure only HR admin for this company can trigger payroll.
        company.admin.require_auth();

        // Construct public inputs required by issue #20:
        let mut public_inputs = soroban_sdk::Vec::new(&env);
        public_inputs.push_back(on_chain_commitment);
        public_inputs.push_back(Self::amount_to_public_input(&env, amount));

        // Validate Groth16 proof via proof_verifier contract.
        let verifier = ProofVerifierClient::new(&env, &addresses.verifier);
        let proof = Groth16Proof {
            a: proof_a.clone(),
            b: proof_b.clone(),
            c: proof_c.clone(),
        };
        if !verifier.verify(&proof, &public_inputs) {
            panic!("Invalid payment proof");
        }

        // Execute token transfer from company treasury to employee.
        let token_client = token::Client::new(&env, &addresses.token);
        token_client.transfer(&company.treasury, &employee, &amount);

        // Record payment
        let record = PaymentRecord {
            company_id,
            employee: employee.clone(),
            proof_hash: nullifier.clone(),
            timestamp: env.ledger().timestamp(),
            period,
        };

        env.storage().persistent().set(&payment_key, &record);
        env.storage().persistent().set(&nullifier_key, &true);

        // Update total paid
        let total_key = DataKey::TotalPaid(company_id);
        let current_total: i128 = env.storage().persistent().get(&total_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&total_key, &(current_total + amount));

        // Increment payment count in the period record
        period_record.payment_count += 1;
        env.storage()
            .persistent()
            .set(&DataKey::Period(company_id, period), &period_record);

        env.events().publish(
            (
                soroban_sdk::Symbol::new(&env, "PayrollProcessed"),
                company_id,
            ),
            (employee, amount, period),
        );

        let _ = nullifier;

        Ok(record)
    }

    /// Execute batch payroll for multiple employees
    #[allow(clippy::too_many_arguments)]
    pub fn execute_batch_payroll(
        env: Env,
        company_id: u64,
        employees: soroban_sdk::Vec<Address>,
        amounts: soroban_sdk::Vec<i128>,
        proofs_a: soroban_sdk::Vec<BytesN<64>>,
        proofs_b: soroban_sdk::Vec<BytesN<128>>,
        proofs_c: soroban_sdk::Vec<BytesN<64>>,
        nullifiers: soroban_sdk::Vec<BytesN<32>>,
        period: u32,
    ) -> Result<soroban_sdk::Vec<PaymentRecord>, PaymentError> {
        let count = employees.len();

        if amounts.len() != count
            || proofs_a.len() != count
            || proofs_b.len() != count
            || proofs_c.len() != count
            || nullifiers.len() != count
        {
            return Err(PaymentError::ArrayLengthMismatch);
        }

        let mut records = soroban_sdk::Vec::new(&env);

        for i in 0..count {
            let record = Self::execute_payment(
                env.clone(),
                company_id,
                employees.get(i).unwrap(),
                amounts.get(i).unwrap(),
                proofs_a.get(i).unwrap(),
                proofs_b.get(i).unwrap(),
                proofs_c.get(i).unwrap(),
                nullifiers.get(i).unwrap(),
                period,
            )?;
            records.push_back(record);
        }

        Ok(records)
    }

    /// Get payment record
    pub fn get_payment(env: Env, employee: Address, period: u32) -> PaymentRecord {
        let key = DataKey::Payment(employee, period);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Payment not found")
    }

    /// Check if payment was made for a period
    pub fn is_paid(env: Env, employee: Address, period: u32) -> bool {
        let key = DataKey::Payment(employee, period);
        env.storage().persistent().has(&key)
    }

    /// Get total amount paid by company
    pub fn get_total_paid(env: Env, company_id: u64) -> i128 {
        let key = DataKey::TotalPaid(company_id);
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::{Token, TokenClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use payroll_registry::PayrollRegistry;
    use proof_verifier::{ProofVerifier, VerificationKey};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, IntoVal};

    fn setup_addresses(env: &Env) -> ContractAddresses {
        env.mock_all_auths();
        let registry_id = env.register_contract(None, PayrollRegistry);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        ContractAddresses {
            registry: registry_id,
            commitment: Address::generate(env),
            verifier: verifier_id,
            token: token_id,
        }
    }

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[0u8; 128]),
            gamma: BytesN::from_array(env, &[0u8; 128]),
            delta: BytesN::from_array(env, &[0u8; 128]),
            ic: soroban_sdk::Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                ],
            ),
        }
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);
    }

    #[test]
    fn test_is_paid() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let employee = Address::generate(&env);

        assert!(!client.is_paid(&employee, &1));
    }

    #[test]
    fn test_execute_payment_transfers_after_verification() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        // Create payroll period
        let _ = client.create_period(&company_id);

        let valid_proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let valid_proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let valid_proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let valid_nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 9_000);
        assert_eq!(token_client.balance(&employee), 1_000);
    }

    #[test]
    fn test_double_spend_proof_reuse_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[7u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);

        let valid_proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let valid_proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let valid_proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let valid_nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
    }

    #[test]
    fn test_batch_array_length_mismatch_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let company_id = 0u64;

        let employees =
            soroban_sdk::Vec::from_array(&env, [Address::generate(&env), Address::generate(&env)]);
        let amounts: soroban_sdk::Vec<i128> = soroban_sdk::Vec::from_array(&env, [1000]);
        let proofs_a: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let proofs_b: soroban_sdk::Vec<BytesN<128>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 128])]);
        let proofs_c: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let nullifiers: soroban_sdk::Vec<BytesN<32>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 32])]);
        let period = 1;

        let result = client.try_execute_batch_payroll(
            &company_id,
            &employees,
            &amounts,
            &proofs_a,
            &proofs_b,
            &proofs_c,
            &nullifiers,
            &period,
        );

        assert_eq!(
            result.unwrap_err().unwrap(),
            PaymentError::ArrayLengthMismatch
        );
    }

    // -----------------------------------------------------------------------
    // Period tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_period() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&admin, &treasury);

        let period = client.create_period(&company_id);
        let result = period;
        assert_eq!(result.period_id, 1);
        assert_eq!(result.company_id, company_id);
        assert!(!result.closed);
        assert_eq!(result.payment_count, 0);
    }

    #[test]
    fn test_close_period() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&admin, &treasury);

        let _ = client.create_period(&company_id);
        let result = client.close_period(&company_id, &1);

        assert!(result.closed);
        assert_eq!(result.end_ledger, result.start_ledger);
    }

    #[test]
    fn test_payment_in_closed_period_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);
        let _ = client.close_period(&company_id, &1);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::PeriodClosed);
    }

    #[test]
    fn test_payment_in_nonexistent_period_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        // Period 99 doesn't exist
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &99,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::PeriodNotFound);
    }

    /// Acceptance Criteria: Reentrancy
    #[test]
    fn test_reentrancy_cei_pattern() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &2_500,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 7_500);
        assert_eq!(token_client.balance(&employee), 2_500);
        assert!(client.is_paid(&employee, &1));
        assert_eq!(client.get_total_paid(&company_id), 2_500);

        let replay = client.try_execute_payment(
            &company_id,
            &employee,
            &2_500,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(replay.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
        assert_eq!(token_client.balance(&treasury), 7_500);
        assert_eq!(token_client.balance(&employee), 2_500);
        assert_eq!(client.get_total_paid(&company_id), 2_500);
    }

    // ── Pause tests ──────────────────────────────────────────────────────────

    fn setup_executor_with_pause_manager(
        env: &Env,
    ) -> (
        PaymentExecutorClient<'_>,
        PauseManagerClient<'_>,
        u64,
        Address,
        Address,
        Address,
    ) {
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(env, &contract_id);

        let addresses = setup_addresses(env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(env, &addresses.registry);
        let token_client = TokenClient::new(env, &addresses.token);

        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let employee = Address::generate(env);
        let commitment = BytesN::from_array(env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        // Set executor admin
        client.set_executor_admin(&admin);

        // Register and configure pause manager
        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(env, &pm_id);
        let operator = Address::generate(env);
        pm_client.initialize(&operator);

        client.set_pause_manager(&pm_id);

        (client, pm_client, company_id, admin, treasury, employee)
    }

    #[test]
    fn test_paused_executor_rejects_payment() {
        let env = Env::default();
        let (client, pm_client, company_id, _admin, _treasury, employee) =
            setup_executor_with_pause_manager(&env);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        pm_client.pause();

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unpaused_executor_resumes_payment() {
        let env = Env::default();
        let (client, pm_client, company_id, _admin, _treasury, employee) =
            setup_executor_with_pause_manager(&env);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.create_period(&company_id);

        pm_client.pause();

        // Verify paused
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a.clone(),
            &proof_b.clone(),
            &proof_c.clone(),
            &nullifier.clone(),
            &1,
        );
        assert!(result.is_err());

        // Unpause
        pm_client.unpause();

        // Should succeed now
        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert!(client.is_paid(&employee, &1));
    }

    #[test]
    fn test_executor_works_without_pause_manager() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        client.create_period(&company_id);
        token_client.mint(&treasury, &10_000);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 9_000);
        assert_eq!(token_client.balance(&employee), 1_000);
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_set_pause_manager_rejects_unauthorized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        let admin = Address::generate(&env);

        // Only mock auth for admin during initialize
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (addresses.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&addresses);

        // Set executor admin as the legitimate admin
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_executor_admin",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_executor_admin(&admin);

        // Attacker tries to set pause manager
        let pm_id = env.register_contract(None, PauseManager);
        let attacker = Address::generate(&env);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_pause_manager",
                args: (pm_id.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_pause_manager(&pm_id);
    }
}
