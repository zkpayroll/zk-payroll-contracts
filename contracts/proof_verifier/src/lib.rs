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

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracttype]
pub enum DataKey {
    VerificationKey,
    Admin,
}

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
