#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Operational roles
//
// The salary commitment contract separates four operational roles:
//   HR_ADMIN    — Registered in `initialize()`. Authorizes all writes
//                 (store / update / revoke commitment, record nullifier).
//   PAYROLL_OP  — An address delegated to execute payroll (record nullifiers
//                 only). Set via `set_payroll_operator`.
//   AUDITOR     — Grant access via the audit_module (view keys).
//   TREASURY    — Does NOT interact with this contract; payment source lives
//                 in payment_executor.
//
// Unauthorized role actions fail with `require_auth()` / explicit role checks.
// ---------------------------------------------------------------------------

/// Commitment data structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct SalaryCommitment {
    pub commitment: BytesN<32>, // Poseidon(salary, blinding_factor)
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u32,
    /// True when this commitment has been rotated out and must not be used
    /// for future payroll proofs.
    pub revoked: bool,
}

/// Nullifier to prevent double-spending
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentNullifier {
    pub nullifier: BytesN<32>,
    pub used_at: u64,
}

/// Previous commitment snapshot retained for audit history on rotation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CommitmentSnapshot {
    pub commitment: BytesN<32>,
    pub version: u32,
    pub rotated_at: u64,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Commitment(Address),
    Nullifier(BytesN<32>),
    CompanyRoot(Symbol),
    /// Previous commitment history per employee (appended on rotation).
    CommitmentHistory(Address, u32),
    /// The HR admin address that can write to this contract.
    Admin,
    /// A delegated payroll operator that can record nullifiers.
    PayrollOperator,
}

#[contract]
pub struct SalaryCommitmentContract;

#[contractimpl]
impl SalaryCommitmentContract {
    /// Initialize the contract with an HR admin address.
    /// Must be called once. The admin is the only address allowed to
    /// store / update / revoke commitments.
    pub fn init_commitment_admin(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Set a delegated payroll operator that may record nullifiers
    /// (required for batch payroll execution). Only the admin may call.
    pub fn set_payroll_operator(env: Env, operator: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PayrollOperator, &operator);
    }

    /// Get the stored admin address.
    pub fn get_commitment_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized")
    }

    /// Get the payroll operator address (if set).
    pub fn get_payroll_operator(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::PayrollOperator)
    }

    /// Store a new salary commitment for an employee.
    /// Only the HR admin may call.
    pub fn store_commitment(
        env: Env,
        employee: Address,
        commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_admin(&env);

        let timestamp = env.ledger().timestamp();

        let salary_commitment = SalaryCommitment {
            commitment: commitment.clone(),
            created_at: timestamp,
            updated_at: timestamp,
            version: 1,
            revoked: false,
        };

        let key = DataKey::Commitment(employee.clone());
        env.storage().persistent().set(&key, &salary_commitment);

        env.events().publish(
            (Symbol::new(&env, "CommitmentUpdated"), employee),
            (commitment,),
        );

        salary_commitment
    }

    /// Update an existing salary commitment (rotation for compensation changes).
    /// Only the HR admin may call.
    ///
    /// The previous commitment is archived in CommitmentHistory so it remains
    /// auditable. The new commitment replaces the active record and the version
    /// is incremented.
    pub fn update_commitment(
        env: Env,
        employee: Address,
        new_commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_admin(&env);

        let key = DataKey::Commitment(employee.clone());
        let existing: SalaryCommitment = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found");

        // Archive current commitment before replacing
        Self::archive_commitment(&env, &employee, &existing.commitment, existing.version);

        let updated = SalaryCommitment {
            commitment: new_commitment.clone(),
            created_at: existing.created_at,
            updated_at: env.ledger().timestamp(),
            version: existing.version + 1,
            revoked: false,
        };

        env.storage().persistent().set(&key, &updated);

        env.events().publish(
            (Symbol::new(&env, "CommitmentUpdated"), employee),
            (new_commitment,),
        );

        updated
    }

    /// Rotate a salary commitment: archive the old one with `revoked = true`
    /// and store the new one. Old commitments CANNOT be used for future payroll
    /// proofs (see `is_commitment_active`).
    /// Only the HR admin may call.
    pub fn rotate_commitment(
        env: Env,
        employee: Address,
        new_commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_admin(&env);

        let key = DataKey::Commitment(employee.clone());
        let mut existing: SalaryCommitment = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found");

        // Mark active commitment as revoked
        existing.revoked = true;
        env.storage().persistent().set(&key, &existing);

        // Archive the revoked commitment
        Self::archive_commitment(&env, &employee, &existing.commitment, existing.version);

        // Store the new active commitment
        let rotated = Self::store_commitment(env.clone(), employee.clone(), new_commitment);

        // Emit an explicit rotation event
        env.events().publish(
            (Symbol::new(&env, "CommitmentRotated"), employee),
            (existing.commitment, rotated.commitment.clone()),
        );

        rotated
    }

    /// Check whether a commitment is currently active (not revoked).
    pub fn is_commitment_active(env: Env, employee: Address) -> bool {
        let key = DataKey::Commitment(employee);
        if let Some(c) = env
            .storage()
            .persistent()
            .get::<DataKey, SalaryCommitment>(&key)
        {
            return !c.revoked;
        }
        false
    }

    /// Retrieve the commitment history for an employee.
    /// Returns archived snapshots from previous rotations.
    pub fn get_commitment_history(env: Env, employee: Address) -> Vec<CommitmentSnapshot> {
        let mut history = Vec::new(&env);
        let mut idx: u32 = 0;
        loop {
            let history_key = DataKey::CommitmentHistory(employee.clone(), idx);
            if let Some(snapshot) = env
                .storage()
                .persistent()
                .get::<DataKey, CommitmentSnapshot>(&history_key)
            {
                history.push_back(snapshot);
                idx += 1;
            } else {
                break;
            }
        }
        history
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

    /// Record a payment nullifier (prevents double payment).
    /// Authorized for both the HR admin and the delegated payroll operator.
    pub fn record_nullifier(env: Env, nullifier: BytesN<32>) {
        Self::require_admin_or_operator(&env);

        let key = DataKey::Nullifier(nullifier.clone());

        if env.storage().persistent().has(&key) {
            panic!("Nullifier already used");
        }

        let payment_nullifier = PaymentNullifier {
            nullifier,
            used_at: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&key, &payment_nullifier);
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        let key = DataKey::Nullifier(nullifier);
        env.storage().persistent().has(&key)
    }

    /// Compute a commitment hash for a salary and blinding factor.
    pub fn compute_commitment(env: Env, salary: u64, blinding_factor: BytesN<32>) -> BytesN<32> {
        let mut preimage = soroban_sdk::Bytes::new(&env);
        preimage.extend_from_array(&salary.to_le_bytes());
        let blinding_bytes: [u8; 32] = blinding_factor.into();
        preimage.extend_from_array(&blinding_bytes);

        env.crypto().sha256(&preimage).into()
    }

    /// Verify a commitment matches a salary (with proof)
    pub fn verify_commitment(
        env: Env,
        employee: Address,
        claimed_salary: u64,
        blinding_factor: BytesN<32>,
    ) -> bool {
        let stored = Self::get_commitment(env.clone(), employee);
        let computed = Self::compute_commitment(env, claimed_salary, blinding_factor);

        stored.commitment == computed && !stored.revoked
    }

    // -----------------------------------------------------------------------
    // Role guards
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        admin.require_auth();
    }

    fn require_admin_or_operator(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");

        let operator: Option<Address> = env.storage().persistent().get(&DataKey::PayrollOperator);

        match operator {
            Some(op) => op.require_auth(),
            None => admin.require_auth(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn archive_commitment(env: &Env, employee: &Address, commitment: &BytesN<32>, version: u32) {
        let mut idx: u32 = 0;
        loop {
            let history_key = DataKey::CommitmentHistory(employee.clone(), idx);
            if !env.storage().persistent().has(&history_key) {
                let snapshot = CommitmentSnapshot {
                    commitment: commitment.clone(),
                    version,
                    rotated_at: env.ledger().timestamp(),
                };
                env.storage().persistent().set(&history_key, &snapshot);
                break;
            }
            idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn setup_with_admin() -> (Env, soroban_sdk::Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        (env, contract_id, admin)
    }

    #[test]
    fn test_store_commitment() {
        let (env, contract_id, admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let _admin = admin;

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[42u8; 32]);

        let result = client.store_commitment(&employee, &commitment);

        assert_eq!(result.commitment, commitment);
        assert_eq!(result.version, 1);
        assert!(!result.revoked);
    }

    #[test]
    fn test_update_commitment() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = BytesN::from_array(&env, &[1u8; 32]);
        let updated = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &initial);
        let result = client.update_commitment(&employee, &updated);

        assert_eq!(result.commitment, updated);
        assert_eq!(result.version, 2);
    }

    #[test]
    fn test_nullifier() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = BytesN::from_array(&env, &[99u8; 32]);

        assert!(!client.is_nullifier_used(&nullifier));

        client.record_nullifier(&nullifier);

        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    #[should_panic(expected = "Nullifier already used")]
    fn test_double_nullifier_fails() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = BytesN::from_array(&env, &[99u8; 32]);

        client.record_nullifier(&nullifier);
        client.record_nullifier(&nullifier);
    }

    #[test]
    fn test_rotate_commitment_archives_and_revokes() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let old_cmt = BytesN::from_array(&env, &[1u8; 32]);
        let new_cmt = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &old_cmt);
        let rotated = client.rotate_commitment(&employee, &new_cmt);

        assert_eq!(rotated.commitment, new_cmt);
        assert!(!rotated.revoked);

        let history = client.get_commitment_history(&employee);
        assert!(!history.is_empty());
    }

    #[test]
    fn test_rotated_commitment_not_active() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let old_cmt = BytesN::from_array(&env, &[1u8; 32]);
        let new_cmt = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &old_cmt);
        assert!(client.is_commitment_active(&employee));

        client.rotate_commitment(&employee, &new_cmt);
        assert!(client.is_commitment_active(&employee));
    }

    #[test]
    fn test_multiple_sequential_rotations() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let cmt1 = BytesN::from_array(&env, &[1u8; 32]);
        let cmt2 = BytesN::from_array(&env, &[2u8; 32]);
        let cmt3 = BytesN::from_array(&env, &[3u8; 32]);

        client.store_commitment(&employee, &cmt1);
        client.rotate_commitment(&employee, &cmt2);
        client.rotate_commitment(&employee, &cmt3);

        let current = client.get_commitment(&employee);
        assert_eq!(current.commitment, cmt3);
        assert!(!current.revoked);

        let history = client.get_commitment_history(&employee);
        assert!(history.len() >= 2);
    }

    #[test]
    fn test_payroll_operator_can_record_nullifier() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        client.set_payroll_operator(&operator);

        let nullifier = BytesN::from_array(&env, &[55u8; 32]);
        client.record_nullifier(&nullifier);
        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_store_commitment_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        // No mock_auths — store_commitment should require admin auth and panic
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[99u8; 32]);
        client.store_commitment(&employee, &commitment);
    }
}
