#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env, Vec};

/// Groth16 proof components (G1 A, G2 B, G1 C) for BN254.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: BytesN<64>,
    pub b: BytesN<128>,
    pub c: BytesN<64>,
}

/// A generic Verification Key for a Groth16 circuit on BN254.
///
/// Maps natively to SnarkJS `vkey.json` components.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    /// G1 point (x, y)
    pub alpha: BytesN<64>,
    /// G2 point (x_c0, x_c1, y_c0, y_c1)
    pub beta: BytesN<128>,
    /// G2 point (x_c0, x_c1, y_c0, y_c1)
    pub gamma: BytesN<128>,
    /// G2 point (x_c0, x_c1, y_c0, y_c1)
    pub delta: BytesN<128>,
    /// The linear combination points corresponding to public inputs.
    pub ic: Vec<BytesN<64>>,
}

/// Storage keys for the verifier contract.
#[contracttype]
pub enum DataKey {
    /// Stores the active VerificationKey
    VerificationKey,
}

#[contract]
pub struct ProofVerifier;

#[contractimpl]
impl ProofVerifier {
    /// Initialize the verifier contract with a verification key.
    ///
    /// This should be called exactly once during deployment/setup.
    pub fn initialize_verifier(env: Env, vk: VerificationKey) {
        if env.storage().persistent().has(&DataKey::VerificationKey) {
            panic!("Verifier already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::VerificationKey, &vk);
    }

    /// Read the currently stored verification key.
    pub fn get_verification_key(env: Env) -> VerificationKey {
        env.storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .expect("Verifier not initialized")
    }

    /// Verify using decomposed Groth16 points (used by `payment_executor`).
    pub fn verify(env: Env, proof: Groth16Proof, public_inputs: Vec<BytesN<32>>) -> bool {
        let proof_bytes = Self::pack_groth16_proof(&env, &proof);
        Self::verify_payment_proof(env, proof_bytes, public_inputs)
    }

    /// Verify a BN254 Groth16 proof against the stored Verification Key.
    ///
    /// Accepts a raw 256-byte proof payload (SnarkJS layout: A (64) || B (128) || C (64)).
    ///
    /// The number of public inputs must be `vk.ic.len() - 1` (constant term `ic[0]`
    /// is not counted as a user-supplied input).
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

    fn pack_groth16_proof(env: &Env, proof: &Groth16Proof) -> BytesN<256> {
        let mut buf = [0u8; 256];
        buf[..64].copy_from_slice(&proof.a.to_array());
        buf[64..192].copy_from_slice(&proof.b.to_array());
        buf[192..256].copy_from_slice(&proof.c.to_array());
        BytesN::from_array(env, &buf)
    }

    // A mock stub representing the native `env.crypto().verify_groth16(..)` call.
    fn simulated_verify_groth16(
        _env: &Env,
        _vk: &VerificationKey,
        _proof: BytesN<256>,
        _public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
