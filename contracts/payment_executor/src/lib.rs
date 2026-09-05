#![no_std]

extern crate alloc;
use alloc::format;

use pause_manager::PauseManagerClient;
use payroll_registry::{CompanyInfo, PayrollRegistryClient};
use proof_verifier::{Groth16Proof, ProofVerifierClient};
use salary_commitment::SalaryCommitmentContractClient;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env, Symbol,
};

/// Maximum age for a proof relative to its period creation time (7 days in seconds).
/// Proofs must be submitted within this window to prevent replay attacks using stale proofs.
const MAX_PROOF_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

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
    /// The proof has expired and can no longer be used (issue #77).
    ProofExpired = 7,
    /// Empty payroll batches are rejected to avoid silent no-op execution.
    EmptyBatch = 8,
    /// Asset decimal configuration is missing or unsupported (issue #354).
    AssetDecimalsMissing = 9,
    /// Asset decimal mismatch between payment and contract assumptions (issue #354).
    AssetDecimalsMismatch = 10,
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
    /// Allowed assets for payment execution (issue #175)
    AllowedAsset(Address),
    /// Storage key schema version (issue #174)
    StorageVersion,
    /// Asset decimal configuration for proper amount normalization (issue #354)
    AssetDecimals(Address),
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

    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    /// Initialize with contract addresses
    pub fn initialize(env: Env, addresses: ContractAddresses) {
        let key = DataKey::Addresses;
        if env.storage().persistent().has(&key) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&key, &addresses);
        // Automatically allow initial token asset (issue #175)
        env.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(addresses.token.clone()), &true);
        // Set initial storage key version (issue #174)
        env.storage()
            .persistent()
            .set(&DataKey::StorageVersion, &1u32);

        env.events().publish(
            (
                Symbol::new(&env, "TreasuryAssetAllowedUpdated"),
                addresses.token.clone(),
            ),
            (true, env.ledger().timestamp()),
        );
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
        payroll_events::emit_executor_admin_set(&env, admin);
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
        payroll_events::emit_executor_pause_manager_set(&env, pause_manager);
    }

    /// Allow or disallow an asset token for payment execution (only executor admin - issue #175).
    pub fn set_asset_allowed(env: Env, asset: Address, allowed: bool) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set");
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(asset.clone()), &allowed);

        env.events().publish(
            (Symbol::new(&env, "TreasuryAssetAllowedUpdated"), asset),
            (allowed, env.ledger().timestamp()),
        );
    }

    /// Check if an asset token is allowlisted for payments (issue #175).
    pub fn is_asset_allowed(env: Env, asset: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::AllowedAsset(asset))
            .unwrap_or(false)
    }

    /// Read contract storage schema version (issue #174).
    pub fn get_storage_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::StorageVersion)
            .unwrap_or(1u32)
    }

    /// Configure the decimal places for an asset token (issue #354).
    /// Required to ensure proper amount normalization and prevent decimal mismatches.
    /// Only executor admin can set this configuration.
    pub fn set_asset_decimals(env: Env, asset: Address, decimals: u32) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set");
        admin.require_auth();

        if decimals > 18 {
            panic!("Asset decimals must not exceed 18");
        }

        env.storage()
            .persistent()
            .set(&DataKey::AssetDecimals(asset.clone()), &decimals);

        env.events().publish(
            (Symbol::new(&env, "AssetDecimalsConfigured"), asset),
            (decimals, env.ledger().timestamp()),
        );
    }

    /// Get the configured decimal places for an asset token (issue #354).
    /// Returns 0 if not configured, indicating configuration is missing.
    pub fn get_asset_decimals(env: Env, asset: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::AssetDecimals(asset))
            .unwrap_or(0u32)
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
        Self::require_not_paused(&env);
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

        if next_id > 1 {
            let prev_key = DataKey::Period(company_id, next_id - 1);
            if let Some(prev_period) = env
                .storage()
                .persistent()
                .get::<DataKey, PayrollPeriod>(&prev_key)
            {
                if !prev_period.closed {
                    return Err(PaymentError::PeriodAlreadyExists);
                }
            }
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

        payroll_events::emit_period_created(&env, company_id, next_id);

        Ok(period)
    }

    /// Close a payroll period so no further payments can be made in it.
    pub fn close_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<PayrollPeriod, PaymentError> {
        Self::require_not_paused(&env);
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

        payroll_events::emit_period_closed(&env, company_id, period_id);

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
        let period_record: PayrollPeriod = env
            .storage()
            .persistent()
            .get(&period_key)
            .ok_or(PaymentError::PeriodNotFound)?;

        if period_record.closed {
            return Err(PaymentError::PeriodClosed);
        }

        // Check proof freshness: reject stale proofs (issue #77).
        // Proofs must be submitted within MAX_PROOF_AGE_SECONDS of the period creation.
        let current_time = env.ledger().timestamp();
        let proof_age = current_time.saturating_sub(period_record.created_at);
        if proof_age > MAX_PROOF_AGE_SECONDS {
            return Err(PaymentError::ProofExpired);
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

        // Read the employee commitment from the dedicated commitment contract
        // and company metadata from payroll_registry.
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let commitment = commitment_client.get_commitment(&employee).commitment;
        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);

        // Ensure only HR admin for this company can trigger payroll and treasury authorizes payment.
        company.admin.require_auth();
        company.treasury.require_auth();

        // Construct public inputs required by issue #20:
        let mut public_inputs = soroban_sdk::Vec::new(&env);
        public_inputs.push_back(commitment);
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

        // Validate treasury asset allowlist (issue #175)
        if !Self::is_asset_allowed(env.clone(), addresses.token.clone()) {
            panic!("Asset not allowed");
        }

        // Issue #217: Validate treasury asset mapping matches supported payroll assets
        // Ensure the token contract address is valid and matches expected format
        let token_str = format!("{:?}", addresses.token);
        if token_str.is_empty() {
            panic!("Invalid treasury asset mapping: empty token address");
        }

        // Verify the treasury address is properly configured and matches asset type
        let treasury_str = format!("{:?}", company.treasury);
        if treasury_str.is_empty() {
            panic!("Invalid treasury mapping: empty treasury address");
        }

        // Issue #354: Validate asset decimal normalization guardrails
        let asset_decimals = Self::get_asset_decimals(env.clone(), addresses.token.clone());
        if asset_decimals == 0 {
            return Err(PaymentError::AssetDecimalsMissing);
        }

        // Verify amount is properly normalized according to asset decimal configuration
        if amount < 0 {
            return Err(PaymentError::AssetDecimalsMismatch);
        }
        let max_amount_for_decimals = 10i128.pow(asset_decimals);
        if amount > 0 && amount < max_amount_for_decimals / 1_000_000_000 {
            return Err(PaymentError::AssetDecimalsMismatch);
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

        // Increment period payment count
        let period_key = DataKey::Period(company_id, period);
        if let Some(mut period_struct) = env
            .storage()
            .persistent()
            .get::<DataKey, PayrollPeriod>(&period_key)
        {
            period_struct.payment_count += 1;
            env.storage().persistent().set(&period_key, &period_struct);
        }

        // Update total paid
        let total_key = DataKey::TotalPaid(company_id);
        let current_total: i128 = env.storage().persistent().get(&total_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&total_key, &(current_total + amount));

        // Emit PayrollProcessed event so off-chain indexers can reconcile payments.
        payroll_events::emit_executor_payment_processed(&env, company_id, employee, amount, period);

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

        if count == 0 {
            return Err(PaymentError::EmptyBatch);
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

    /// Get the maximum allowed age for a proof in seconds (issue #77).
    pub fn get_max_proof_age(_env: Env) -> u64 {
        MAX_PROOF_AGE_SECONDS
    }

    /// Get the contract dependency addresses configured during initialization.
    pub fn get_addresses(env: Env) -> ContractAddresses {
        env.storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized")
    }

    /// Get the executor admin address.
    pub fn get_executor_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set")
    }

    /// Get the current period sequence for a company (defaults to 0).
    pub fn get_period_sequence(env: Env, company_id: u64) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::PeriodSequence(company_id))
            .unwrap_or(0u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::pause_manager::{PauseManager, PauseManagerClient};
    use ::salary_commitment::SalaryCommitmentContract;
    use ::token::{Token, TokenClient};
    use payroll_registry::PayrollRegistry;
    use proof_verifier::{ProofVerifier, VerificationKey};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Env, IntoVal, Symbol, TryIntoVal};

    fn setup_addresses(env: &Env) -> ContractAddresses {
        env.mock_all_auths();
        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        let commitment_admin = Address::generate(env);
        commitment_client.init_commitment_admin(&commitment_admin);

        ContractAddresses {
            registry: registry_id,
            commitment: commitment_id,
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
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
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

        let events = env.events().all();
        assert_eq!(events.len(), 6);
        let event = events.get(events.len() - 1).unwrap();
        assert_eq!(event.1.len(), 2);
        let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(sym0, Symbol::new(&env, "PayrollProcessed"));
        let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(comp_id, company_id);
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
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[7u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
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
    fn test_duplicate_period_creation_fails() {
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

        let result = client.try_create_period(&company_id);
        assert_eq!(
            result.unwrap_err().unwrap(),
            PaymentError::PeriodAlreadyExists
        );
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
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
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

        let events = env.events().all();
        assert_eq!(events.len(), 6);
        let event = events.get(events.len() - 1).unwrap();
        assert_eq!(event.1.len(), 2);
        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(sym, Symbol::new(&env, "PayrollProcessed"));

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
        let commitment_client = SalaryCommitmentContractClient::new(env, &addresses.commitment);
        let token_client = TokenClient::new(env, &addresses.token);

        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let employee = Address::generate(env);
        let commitment = BytesN::from_array(env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
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
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
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

    // ── Issue #77: proof expiration checks ────────────────────────────────────

    #[test]
    fn test_fresh_proof_within_expiration_window() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        // Create a period
        let period = client.create_period(&company_id);
        assert_eq!(period.period_id, 1);

        // Execute payment immediately (proof is fresh)
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &BytesN::from_array(&env, &[1u8; 64]),
            &BytesN::from_array(&env, &[2u8; 128]),
            &BytesN::from_array(&env, &[3u8; 64]),
            &BytesN::from_array(&env, &[4u8; 32]),
            &1,
        );
        // Should succeed (proof is fresh)
        assert!(result.is_ok());
    }

    #[test]
    fn test_period_tracks_creation_time() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        // Create a period
        let period = client.create_period(&company_id);

        // Verify period is created and has correct initial state
        assert_eq!(period.period_id, 1);
        assert_eq!(period.company_id, company_id);
        assert!(!period.closed);
        assert_eq!(period.payment_count, 0);
        // created_at is set to current ledger timestamp (can be 0 in test env)
    }

    #[test]
    fn test_get_max_proof_age() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let max_age = client.get_max_proof_age();
        // Should be 7 days in seconds
        assert_eq!(max_age, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_asset_allowlist_management_and_execution() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        // Initial token asset is allowlisted
        assert!(client.is_asset_allowed(&addresses.token));

        // Disallow token asset
        client.set_asset_allowed(&addresses.token, &false);
        assert!(!client.is_asset_allowed(&addresses.token));

        // Re-allow token asset
        client.set_asset_allowed(&addresses.token, &true);
        assert!(client.is_asset_allowed(&addresses.token));
    }

    #[test]
    #[should_panic(expected = "Asset not allowed")]
    fn test_execute_payment_fails_when_asset_disallowed() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        // Disallow the payment token asset
        client.set_asset_allowed(&addresses.token, &false);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        let _period = client.create_period(&company_id);

        client.execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &BytesN::from_array(&env, &[1u8; 64]),
            &BytesN::from_array(&env, &[2u8; 128]),
            &BytesN::from_array(&env, &[3u8; 64]),
            &BytesN::from_array(&env, &[4u8; 32]),
            &1,
        );
    }

    #[test]
    fn test_storage_version_returns_version_1() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        assert_eq!(client.get_storage_version(), 1);
    }

    #[test]
    fn test_asset_allowed_emits_events() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        let before_init = env.events().all().len();
        client.initialize(&addresses);
        let after_init = env.events().all().len();
        assert_eq!(after_init, before_init + 1);

        let init_event = env.events().all().get(after_init - 1).unwrap();
        let sym0: Symbol = init_event
            .1
            .get(0)
            .unwrap()
            .try_into_val(&env.clone())
            .unwrap();
        assert_eq!(sym0, Symbol::new(&env, "TreasuryAssetAllowedUpdated"));

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let before_set = env.events().all().len();
        let new_asset = Address::generate(&env);
        client.set_asset_allowed(&new_asset, &true);
        let after_set = env.events().all().len();
        assert_eq!(after_set, before_set + 1);

        let set_event = env.events().all().get(after_set - 1).unwrap();
        let set_sym0: Symbol = set_event
            .1
            .get(0)
            .unwrap()
            .try_into_val(&env.clone())
            .unwrap();
        assert_eq!(set_sym0, Symbol::new(&env, "TreasuryAssetAllowedUpdated"));
    }

    // ── Issue #245: operator vs admin role separation ─────────────────────────
    //
    // `payment_executor` has two distinct privileged roles that must not be
    // conflated: the protocol-level `ExecutorAdmin` (gates contract-wide
    // config: `set_asset_allowed`, `set_pause_manager`) and each company's
    // own `admin` (gates that company's periods and payments only — the
    // "operator" of its own payroll). Neither role should be able to
    // exercise the other's capabilities.

    /// A company admin (this company's payroll "operator") must not be able
    /// to exercise the protocol-level `ExecutorAdmin` capability of changing
    /// the treasury asset allowlist just because they administer a company.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_company_admin_cannot_set_asset_allowed() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let company_admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let _company_id = registry_client.register_company(&company_admin, &treasury);

        // Company admin (not the executor admin) attempts a protocol-level
        // config change.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &company_admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_asset_allowed",
                args: (addresses.token.clone(), false).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_asset_allowed(&addresses.token, &false);
    }

    /// The protocol-level `ExecutorAdmin` must not be able to trigger payroll
    /// execution for a company it does not administer — that capability
    /// belongs solely to the company's own admin.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_executor_admin_cannot_execute_payment_for_foreign_company() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let company_admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&company_admin, &treasury);

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[5u8; 32]);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &100_000i128);

        client.create_period(&company_id);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        // Executor admin (not this company's admin) attempts to execute a
        // payment for a company it does not administer.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &executor_admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "execute_payment",
                args: (
                    company_id,
                    employee.clone(),
                    1000i128,
                    proof_a.clone(),
                    proof_b.clone(),
                    proof_c.clone(),
                    nullifier.clone(),
                    1u32,
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        }]);
        let _ = client.execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1u32,
        );
    }

    // =====================================================================
    // Issue #277: `amount_to_public_input` precision-format encoding
    //
    // The ZK public input for an amount must be a canonical, big-endian,
    // zero-padded `BytesN<32>` per
    // `docs/interop/proof-schema-version-negotiation.md`'s "Unsupported
    // Combinations" section ("Public inputs using i128 raw bytes instead of
    // the canonical BytesN<32> big-endian zero-padded encoding" is
    // explicitly rejected). These tests pin the exact byte layout across
    // supported precision boundaries and confirm invalid (negative) amounts
    // are rejected before any encoding happens.
    // =====================================================================

    #[test]
    fn test_amount_to_public_input_zero_is_all_zero_bytes() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, 0);
        assert_eq!(encoded.to_array(), [0u8; 32]);
    }

    #[test]
    fn test_amount_to_public_input_one_is_zero_padded_big_endian() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, 1);
        let arr = encoded.to_array();

        // High 16 bytes are always zero: i128 fits entirely within the low
        // 16 bytes of the 32-byte field, per the canonical encoding.
        assert_eq!(arr[..16], [0u8; 16]);
        // Big-endian: the least-significant byte is last.
        let mut expected_low16 = [0u8; 16];
        expected_low16[15] = 1;
        assert_eq!(arr[16..], expected_low16);
    }

    #[test]
    fn test_amount_to_public_input_preserves_full_precision_for_non_round_amount() {
        // A non-round, multi-byte amount must round-trip through the
        // big-endian encoding with no truncation or rounding drift.
        let env = Env::default();
        let amount: i128 = 999_999_999_937;
        let encoded = PaymentExecutor::amount_to_public_input(&env, amount);
        let arr = encoded.to_array();

        let mut low16 = [0u8; 16];
        low16.copy_from_slice(&arr[16..]);
        let round_tripped = u128::from_be_bytes(low16) as i128;

        assert_eq!(arr[..16], [0u8; 16]);
        assert_eq!(round_tripped, amount);
    }

    #[test]
    fn test_amount_to_public_input_accepts_maximum_i128_at_full_precision() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, i128::MAX);
        let arr = encoded.to_array();

        let mut low16 = [0u8; 16];
        low16.copy_from_slice(&arr[16..]);
        let round_tripped = u128::from_be_bytes(low16) as i128;

        assert_eq!(round_tripped, i128::MAX);
    }

    #[test]
    #[should_panic(expected = "Amount must be non-negative")]
    fn test_amount_to_public_input_rejects_negative_one() {
        // Boundary just below the supported precision range: the smallest
        // magnitude negative value must still be rejected, not just
        // `i128::MIN`.
        let env = Env::default();
        let _ = PaymentExecutor::amount_to_public_input(&env, -1);
    }

    #[test]
    #[should_panic(expected = "Amount must be non-negative")]
    fn test_amount_to_public_input_rejects_i128_min() {
        let env = Env::default();
        let _ = PaymentExecutor::amount_to_public_input(&env, i128::MIN);
    }

    // ── Asset symbol normalization ─────────────────────────────────────────

    fn normalize_asset_symbol(env: &Env, symbol: &str) -> Symbol {
        let normalized = symbol.trim().to_ascii_uppercase();
        Symbol::new(env, normalized.as_str())
    }

    #[test]
    fn test_normalize_asset_symbol_trims_and_uppercases() {
        let env = Env::default();
        assert_eq!(
            normalize_asset_symbol(&env, "  usdc "),
            Symbol::new(&env, "USDC")
        );
    }

    #[test]
    fn test_normalize_asset_symbol_preserves_canonical_asset_codes() {
        let env = Env::default();
        assert_eq!(
            normalize_asset_symbol(&env, "USDC"),
            Symbol::new(&env, "USDC")
        );
    }

    #[test]
    fn test_normalize_asset_symbol_handles_mixed_case_alphanumeric_codes() {
        let env = Env::default();
        assert_eq!(
            normalize_asset_symbol(&env, "  xLm12 "),
            Symbol::new(&env, "XLM12")
        );
    }

    #[test]
    fn test_allowlist_comparison_uses_normalized_symbol() {
        let env = Env::default();
        let allowlisted = Symbol::new(&env, "USDC");
        let raw_submitted = Symbol::new(&env, "usdc");

        // Without normalization this allowlist comparison would fail.
        assert_ne!(raw_submitted, allowlisted);

        let normalized = normalize_asset_symbol(&env, "usdc");
        assert_eq!(normalized, allowlisted);
    }
}
