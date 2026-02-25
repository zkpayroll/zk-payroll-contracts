#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

/// Commitment data structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct SalaryCommitment {
    pub commitment: [u8; 32], // Poseidon(salary, blinding_factor)
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u32,
}

/// Nullifier to prevent double-spending
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentNullifier {
    pub nullifier: [u8; 32],
    pub used_at: u64,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Commitment(Address),
    Nullifier([u8; 32]),
    CompanyRoot(Symbol),
}

#[contract]
pub struct SalaryCommitmentContract;

#[contractimpl]
impl SalaryCommitmentContract {
    /// Store a new salary commitment for an employee
    pub fn store_commitment(env: Env, employee: Address, commitment: [u8; 32]) -> SalaryCommitment {
        let timestamp = env.ledger().timestamp();

        let salary_commitment = SalaryCommitment {
            commitment,
            created_at: timestamp,
            updated_at: timestamp,
            version: 1,
        };

        let key = DataKey::Commitment(employee);
        env.storage().persistent().set(&key, &salary_commitment);

        salary_commitment
    }

    /// Update an existing salary commitment (for salary changes)
    pub fn update_commitment(
        env: Env,
        employee: Address,
        new_commitment: [u8; 32],
    ) -> SalaryCommitment {
        let key = DataKey::Commitment(employee);
        let mut existing: SalaryCommitment = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found");

        existing.commitment = new_commitment;
        existing.updated_at = env.ledger().timestamp();
        existing.version += 1;

        env.storage().persistent().set(&key, &existing);

        existing
    }

    /// Get commitment for an employee
    pub fn get_commitment(env: Env, employee: Address) -> SalaryCommitment {
        let key = DataKey::Commitment(employee);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found")
    }

    /// Check if a commitment exists
    pub fn has_commitment(env: Env, employee: Address) -> bool {
        let key = DataKey::Commitment(employee);
        env.storage().persistent().has(&key)
    }

    /// Record a payment nullifier (prevents double payment)
    pub fn record_nullifier(env: Env, nullifier: [u8; 32]) {
        let key = DataKey::Nullifier(nullifier);

        if env.storage().persistent().has(&key) {
            panic!("Nullifier already used - double payment attempt");
        }

        let payment_nullifier = PaymentNullifier {
            nullifier,
            used_at: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&key, &payment_nullifier);
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(env: Env, nullifier: [u8; 32]) -> bool {
        let key = DataKey::Nullifier(nullifier);
        env.storage().persistent().has(&key)
    }

    /// Compute Poseidon hash (placeholder - will use host function)
    ///
    /// In production, this will use CAP-0075 Poseidon host functions
    pub fn compute_commitment(_env: Env, _salary: u64, _blinding_factor: [u8; 32]) -> [u8; 32] {
        // TODO: Use Soroban Poseidon host function
        // poseidon_hash([salary_bytes, blinding_factor])

        // Placeholder implementation
        [0u8; 32]
    }

    /// Verify a commitment matches a salary (with proof)
    /// This is used for auditing with view keys
    pub fn verify_commitment(
        env: Env,
        employee: Address,
        claimed_salary: u64,
        blinding_factor: [u8; 32],
    ) -> bool {
        let stored = Self::get_commitment(env.clone(), employee);
        let computed = Self::compute_commitment(env, claimed_salary, blinding_factor);

        stored.commitment == computed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_store_commitment() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let commitment = [42u8; 32];

        let result = client.store_commitment(&employee, &commitment);

        assert_eq!(result.commitment, commitment);
        assert_eq!(result.version, 1);
    }

    #[test]
    fn test_update_commitment() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = [1u8; 32];
        let updated = [2u8; 32];

        client.store_commitment(&employee, &initial);
        let result = client.update_commitment(&employee, &updated);

        assert_eq!(result.commitment, updated);
        assert_eq!(result.version, 2);
    }

    #[test]
    fn test_nullifier() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = [99u8; 32];

        assert!(!client.is_nullifier_used(&nullifier));

        client.record_nullifier(&nullifier);

        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    #[should_panic(expected = "Nullifier already used")]
    fn test_double_nullifier_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = [99u8; 32];

        client.record_nullifier(&nullifier);
        client.record_nullifier(&nullifier); // Should panic
    }
}
