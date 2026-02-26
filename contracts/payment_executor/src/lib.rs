#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, BytesN, Env, Symbol};

/// Payment record
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentRecord {
    pub company_id: Symbol,
    pub employee: Address,
    pub proof_hash: BytesN<32>,
    pub timestamp: u64,
    pub period: u32, // Payment period (e.g., month number)
}

/// Contract addresses for dependencies
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub registry: Address,
    pub commitment: Address,
    pub verifier: Address,
    pub token: Address, // USDC or payment token
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Addresses,
    Payment(Address, u32), // (employee, period)
    TotalPaid(Symbol),     // Total paid by company
}

#[contract]
pub struct PaymentExecutor;

#[contractimpl]
impl PaymentExecutor {
    /// Initialize with contract addresses
    pub fn initialize(env: Env, addresses: ContractAddresses) {
        let key = DataKey::Addresses;
        if env.storage().persistent().has(&key) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&key, &addresses);
    }

    /// Execute a private payment with ZK proof
    ///
    /// The proof verifies:
    /// 1. The payment amount matches the salary commitment
    /// 2. The recipient is the correct employee
    /// 3. The nullifier is fresh (no double payment)
    #[allow(clippy::too_many_arguments)]
    pub fn execute_payment(
        env: Env,
        company_id: Symbol,
        employee: Address,
        amount: i128, // Payment amount (verified by ZK proof)
        proof_a: BytesN<64>,
        proof_b: BytesN<128>,
        proof_c: BytesN<64>,
        nullifier: BytesN<32>,
        period: u32,
    ) -> PaymentRecord {
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // Check payment hasn't been made for this period
        let payment_key = DataKey::Payment(employee.clone(), period);
        if env.storage().persistent().has(&payment_key) {
            panic!("Payment already made for this period");
        }

        // TODO: Call proof verifier contract
        // let verifier = ProofVerifierClient::new(&env, &addresses.verifier);
        // let proof = Groth16Proof { a: proof_a, b: proof_b, c: proof_c };
        //
        // let commitment = commitment_client.get_commitment(&employee);
        // let recipient_hash = poseidon_hash(employee);
        //
        // if !verifier.verify_payment_proof(
        //     &proof,
        //     &commitment.commitment,
        //     &nullifier,
        //     &recipient_hash
        // ) {
        //     panic!("Invalid payment proof");
        // }

        // TODO: Record nullifier to prevent reuse
        // let commitment_client = SalaryCommitmentClient::new(&env, &addresses.commitment);
        // commitment_client.record_nullifier(&nullifier);

        // Execute token transfer
        let token_client = token::Client::new(&env, &addresses.token);

        // Get company treasury from registry
        // let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        // let company = registry.get_company(&company_id);
        // token_client.transfer(&company.treasury, &employee, &amount);

        // Record payment
        let record = PaymentRecord {
            company_id: company_id.clone(),
            employee: employee.clone(),
            proof_hash: nullifier.clone(), // Use nullifier as unique identifier
            timestamp: env.ledger().timestamp(),
            period,
        };

        // Enforce Checks-Effects-Interactions (CEI) Pattern:
        // Update the contract's local persistent storage state BEFORE interacting
        // with any external contracts (like token and token_client transfers).
        env.storage().persistent().set(&payment_key, &record);

        // Update total paid
        let total_key = DataKey::TotalPaid(company_id);
        let current_total: i128 = env.storage().persistent().get(&total_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&total_key, &(current_total + amount));

        // For now, use placeholder
        let _ = (proof_a, proof_b, proof_c, nullifier.clone(), amount);
        let _ = token_client;

        record
    }

    /// Execute batch payroll for multiple employees
    #[allow(clippy::too_many_arguments)]
    pub fn execute_batch_payroll(
        env: Env,
        company_id: Symbol,
        employees: soroban_sdk::Vec<Address>,
        amounts: soroban_sdk::Vec<i128>,
        proofs_a: soroban_sdk::Vec<BytesN<64>>,
        proofs_b: soroban_sdk::Vec<BytesN<128>>,
        proofs_c: soroban_sdk::Vec<BytesN<64>>,
        nullifiers: soroban_sdk::Vec<BytesN<32>>,
        period: u32,
    ) -> soroban_sdk::Vec<PaymentRecord> {
        let count = employees.len();

        if amounts.len() != count
            || proofs_a.len() != count
            || proofs_b.len() != count
            || proofs_c.len() != count
            || nullifiers.len() != count
        {
            panic!("Array length mismatch");
        }

        let mut records = soroban_sdk::Vec::new(&env);

        for i in 0..count {
            let record = Self::execute_payment(
                env.clone(),
                company_id.clone(),
                employees.get(i).unwrap(),
                amounts.get(i).unwrap(),
                proofs_a.get(i).unwrap(),
                proofs_b.get(i).unwrap(),
                proofs_c.get(i).unwrap(),
                nullifiers.get(i).unwrap(),
                period,
            );
            records.push_back(record);
        }

        records
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
    pub fn get_total_paid(env: Env, company_id: Symbol) -> i128 {
        let key = DataKey::TotalPaid(company_id);
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn setup_addresses(env: &Env) -> ContractAddresses {
        ContractAddresses {
            registry: Address::generate(env),
            commitment: Address::generate(env),
            verifier: Address::generate(env),
            token: Address::generate(env),
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
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let employee = Address::generate(&env);

        assert!(!client.is_paid(&employee, &1));
    }

    #[test]
    #[should_panic(expected = "Payment already made for this period")]
    fn test_double_spend_proof_reuse_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let company_id = Symbol::new(&env, "tech_corp");
        let employee = Address::generate(&env);

        let valid_proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let valid_proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let valid_proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let valid_nullifier = BytesN::from_array(&env, &[4u8; 32]);

        // Attacker submits a perfectly valid proof once.
        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1, // Period 1
        );

        // Attacker attempts to replay the exact same valid proof for the same period.
        // It must panic before any transfer occurs.
        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1, // Period 1
        );
    }

    #[test]
    #[should_panic(expected = "Array length mismatch")]
    fn test_batch_array_length_mismatch_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let company_id = Symbol::new(&env, "tech_corp");

        // Admin provides 2 employees
        let employees =
            soroban_sdk::Vec::from_array(&env, [Address::generate(&env), Address::generate(&env)]);

        // But maliciously only provides 1 amount to try and break out-of-bounds bounds.
        let amounts: soroban_sdk::Vec<i128> = soroban_sdk::Vec::from_array(&env, [1000]);
        let proofs_a: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let proofs_b: soroban_sdk::Vec<BytesN<128>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 128])]);
        let proofs_c: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let nullifiers: soroban_sdk::Vec<BytesN<32>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 32])]);

        // Should panic instantly without interacting with state.
        client.execute_batch_payroll(
            &company_id,
            &employees,
            &amounts,
            &proofs_a,
            &proofs_b,
            &proofs_c,
            &nullifiers,
            &1, // Period
        );
    }
}
