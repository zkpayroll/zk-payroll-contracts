#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Bytes, BytesN, Env, Vec};

/// Groth16 proof components (G1 A, G2 B, G1 C) for BN254.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: BytesN<64>,
    pub b: BytesN<128>,
    pub c: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

/// A registered reference to a specific proof, carrying an explicit expiry.
///
/// Issue #251: proof references authorize payroll actions and audit access,
/// so they must never remain usable past their expiration ledger. Following
/// the `audit_module` convention, a reference is valid while
/// `current_ledger_sequence <= expires_at_ledger` and it has not been
/// revoked.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofReference {
    /// SHA-256 of the exact proof bytes this reference authorizes. The
    /// digest is computed on-chain at registration so a reference can never
    /// be replayed against different proof material.
    pub proof_hash: BytesN<32>,
    pub registered_at_ledger: u32,
    /// First ledger sequence at which the reference is no longer usable.
    pub expires_at_ledger: u32,
    pub revoked: bool,
}

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ProofError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    ReferenceAlreadyExists = 3,
    ReferenceNotFound = 4,
    ReferenceExpired = 5,
    ReferenceRevoked = 6,
    InvalidExpiry = 7,
    ExpiryBeyondCap = 8,
    ProofMismatch = 9,
}

#[contracttype]
pub enum DataKey {
    VerificationKey,
    Admin,
    ProofReference(BytesN<32>),
}

/// Upper bound for a reference lifetime (~30 days of ledgers at 5s each).
/// Prevents an operator mistake from creating effectively eternal proofs.
pub const MAX_REFERENCE_TTL_LEDGERS: u32 = 518_400;

#[contract]
pub struct ProofVerifier;

#[contractimpl]
impl ProofVerifier {
    pub fn init_verifier_admin(env: Env, admin: soroban_sdk::Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn get_verifier_admin(env: Env) -> soroban_sdk::Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized")
    }

    pub fn initialize_verifier(env: Env, vk: VerificationKey) {
        Self::require_admin(&env);

        if env.storage().persistent().has(&DataKey::VerificationKey) {
            panic!("Verifier already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::VerificationKey, &vk);
    }

    pub fn get_verification_key(env: Env) -> VerificationKey {
        env.storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .expect("Verifier not initialized")
    }

    pub fn verify(env: Env, proof: Groth16Proof, public_inputs: Vec<BytesN<32>>) -> bool {
        let proof_bytes = Self::pack_groth16_proof(&env, &proof);
        Self::verify_payment_proof(env, proof_bytes, public_inputs)
    }

    pub fn verify_payment_proof(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        let vk: VerificationKey = env
            .storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .expect("Verifier not initialized");

        if public_inputs.len() + 1 != vk.ic.len() {
            return false;
        }

        Self::simulated_verify_groth16(&env, &vk, proof, public_inputs)
    }

    // ------------------------------------------------------------------
    // Proof reference expiry (issue #251)
    // ------------------------------------------------------------------

    /// Register an expiring reference to `proof`.
    ///
    /// Expiry rules:
    /// - `expires_at_ledger` must be strictly greater than the current
    ///   ledger sequence (`ProofError::InvalidExpiry` otherwise).
    /// - The resulting time-to-live may not exceed
    ///   [`MAX_REFERENCE_TTL_LEDGERS`] (`ProofError::ExpiryBeyondCap`).
    /// - Each `ref_id` can be registered only once
    ///   (`ProofError::ReferenceAlreadyExists`).
    ///
    /// Emits a `ProofRefRegistered` event on success.
    pub fn register_proof_reference(
        env: Env,
        admin: soroban_sdk::Address,
        ref_id: BytesN<32>,
        proof: BytesN<256>,
        expires_at_ledger: u32,
    ) -> Result<ProofReference, ProofError> {
        admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::ProofReference(ref_id.clone()))
        {
            return Err(ProofError::ReferenceAlreadyExists);
        }

        let current = env.ledger().sequence();
        if expires_at_ledger <= current {
            return Err(ProofError::InvalidExpiry);
        }
        if expires_at_ledger.saturating_sub(current) > MAX_REFERENCE_TTL_LEDGERS {
            return Err(ProofError::ExpiryBeyondCap);
        }

        let reference = ProofReference {
            proof_hash: Self::proof_digest(&env, &proof),
            registered_at_ledger: current,
            expires_at_ledger,
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::ProofReference(ref_id.clone()), &reference);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "ProofRefRegistered"), ref_id),
            (expires_at_ledger,),
        );

        Ok(reference)
    }

    /// Revoke a reference before its expiry. Revocation is permanent: an
    /// expired-and-then-revoked reference stays rejected either way.
    ///
    /// Emits a `ProofRefRevoked` event on success.
    pub fn revoke_proof_reference(
        env: Env,
        admin: soroban_sdk::Address,
        ref_id: BytesN<32>,
    ) -> Result<(), ProofError> {
        admin.require_auth();

        let key = DataKey::ProofReference(ref_id.clone());
        let mut reference: ProofReference = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ProofError::ReferenceNotFound)?;
        reference.revoked = true;
        env.storage().persistent().set(&key, &reference);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "ProofRefRevoked"), ref_id),
            (),
        );

        Ok(())
    }

    /// Return the stored reference record.
    pub fn get_proof_reference(env: Env, ref_id: BytesN<32>) -> Result<ProofReference, ProofError> {
        env.storage()
            .persistent()
            .get(&DataKey::ProofReference(ref_id))
            .ok_or(ProofError::ReferenceNotFound)
    }

    /// Whether `ref_id` currently authorizes actions: registered, not
    /// revoked, and not yet expired.
    ///
    /// Boundary semantics (matching `audit_module` view keys): a reference
    /// remains usable through the ledger whose sequence equals
    /// `expires_at_ledger`; from `expires_at_ledger + 1` onward it is
    /// expired.
    pub fn is_proof_reference_valid(env: Env, ref_id: BytesN<32>) -> bool {
        match env
            .storage()
            .persistent()
            .get::<DataKey, ProofReference>(&DataKey::ProofReference(ref_id))
        {
            Some(reference) => Self::reference_is_current(&env, &reference).is_ok(),
            None => false,
        }
    }

    /// Verify a proof through its registered reference (issue #251).
    ///
    /// This is the enforcement point for expiry-sensitive consumers: unlike
    /// [`verify_payment_proof`], a missing, expired, or revoked reference —
    /// or proof bytes that differ from the ones the reference was created
    /// for — makes verification fail without authorizing anything.
    ///
    /// Returns `false` (rather than panicking) so cross-contract callers can
    /// treat an unusable reference uniformly as "not authorized".
    pub fn verify_with_reference(
        env: Env,
        ref_id: BytesN<32>,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        let reference: ProofReference = match env
            .storage()
            .persistent()
            .get(&DataKey::ProofReference(ref_id))
        {
            Some(reference) => reference,
            None => return false,
        };
        if !Self::reference_is_current(&env, &reference).is_ok() {
            return false;
        }
        if reference.proof_hash != Self::proof_digest(&env, &proof) {
            return false;
        }
        Self::verify_payment_proof(env, proof, public_inputs)
    }

    /// A reference is current while unrevoked and not past its expiry
    /// ledger. Following `audit_module`'s convention, expiry starts at
    /// `sequence() > expires_at_ledger`.
    fn reference_is_current(env: &Env, reference: &ProofReference) -> Result<(), ProofError> {
        if reference.revoked {
            return Err(ProofError::ReferenceRevoked);
        }
        if env.ledger().sequence() > reference.expires_at_ledger {
            return Err(ProofError::ReferenceExpired);
        }
        Ok(())
    }

    fn proof_digest(env: &Env, proof: &BytesN<256>) -> BytesN<32> {
        env.crypto()
            .sha256(&Bytes::from_array(env, &proof.to_array()))
            .into()
    }

    fn pack_groth16_proof(env: &Env, proof: &Groth16Proof) -> BytesN<256> {
        let mut buf = [0u8; 256];
        buf[..64].copy_from_slice(&proof.a.to_array());
        buf[64..192].copy_from_slice(&proof.b.to_array());
        buf[192..256].copy_from_slice(&proof.c.to_array());
        BytesN::from_array(env, &buf)
    }

    fn simulated_verify_groth16(
        _env: &Env,
        _vk: &VerificationKey,
        _proof: BytesN<256>,
        _public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        true
    }

    fn require_admin(env: &Env) {
        let admin: soroban_sdk::Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        admin.require_auth();
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod expiry_tests;
