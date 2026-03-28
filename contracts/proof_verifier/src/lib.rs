#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    BytesN, Env, Vec,
};

/// Groth16 proof structure — serialized BN254 curve points.
///
/// - `a`: G1 point (64 bytes = two 32-byte big-endian Fp coordinates)
/// - `b`: G2 point (128 bytes = four 32-byte big-endian Fp coordinates)
/// - `c`: G1 point (64 bytes)
#[contracttype]
#[derive(Clone, Debug)]
pub struct Groth16Proof {
    pub a: BytesN<64>,  // G1 point
    pub b: BytesN<128>, // G2 point
    pub c: BytesN<64>,  // G1 point
}

/// Verification key for the payment circuit.
///
/// Maps the exact Verification Key components from snarkjs export:
/// - `alpha`: G1 point (vk_alpha_1)
/// - `beta`:  G2 point (vk_beta_2)
/// - `gamma`: G2 point (vk_gamma_2)
/// - `delta`: G2 point (vk_delta_2)
/// - `ic`:    Vec of G1 points (IC — input commitments; length = num_public_inputs + 1)
#[contracttype]
#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>, // Input commitments
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    VerificationKey,
}

#[contract]
pub struct ProofVerifier;

#[contractimpl]
impl ProofVerifier {
    /// Initialize the verifier with a verification key.
    ///
    /// This should be called once with the VK exported from the trusted setup.
    /// Can be re-deployed with a new VK if the proving key changes,
    /// without migrating payment_executor state.
    pub fn initialize_verifier(env: Env, vk: VerificationKey) {
        let key = DataKey::VerificationKey;
        if env.storage().persistent().has(&key) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&key, &vk);
    }

    /// Verify a Groth16 proof for a payment.
    ///
    /// Public inputs:
    /// - salary_commitment: The Poseidon hash commitment of the salary
    /// - payment_nullifier: Unique identifier to prevent double-spending
    /// - recipient_hash:    Hash of recipient address
    pub fn verify_payment_proof(
        env: Env,
        proof: Groth16Proof,
        salary_commitment: BytesN<32>,
        payment_nullifier: BytesN<32>,
        recipient_hash: BytesN<32>,
    ) -> bool {
        let public_inputs = Vec::from_array(
            &env,
            [salary_commitment, payment_nullifier, recipient_hash],
        );

        Self::verify(env, proof, public_inputs)
    }

    /// Generic verifier entrypoint used by execution wrappers.
    ///
    /// Accepts any number of 32-byte public inputs and verifies the
    /// Groth16 proof against the stored verification key.
    pub fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        let vk: VerificationKey = env
            .storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .expect("Verifier not initialized");

        Self::verify_groth16_pairing(&env, &proof, &vk, &public_inputs)
    }

    /// Verify a range proof (salary within valid range).
    pub fn verify_range_proof(
        env: Env,
        proof: Groth16Proof,
        commitment: BytesN<32>,
        min_value: u64,
        max_value: u64,
    ) -> bool {
        let vk: VerificationKey = env
            .storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .expect("Verifier not initialized");

        let _ = (commitment, min_value, max_value);

        // TODO: Implement range proof verification with dedicated circuit VK
        let empty_inputs = Vec::from_array(
            &env,
            [
                BytesN::from_array(&env, &[0u8; 32]),
                BytesN::from_array(&env, &[0u8; 32]),
                BytesN::from_array(&env, &[0u8; 32]),
            ],
        );
        Self::verify_groth16_pairing(&env, &proof, &vk, &empty_inputs)
    }

    /// Internal: Groth16 pairing verification using BN254 host primitives.
    ///
    /// Implements the standard Groth16 verification equation:
    ///
    ///   e(A, B) == e(α, β) · e(∑(pub_i · IC_{i+1}) + IC_0, γ) · e(C, δ)
    ///
    /// Re-arranged with the negation trick for a single pairing_check call:
    ///
    ///   e(-A, B) · e(α, β) · e(IC_combined, γ) · e(C, δ) == 1
    ///
    /// Where IC_combined = IC[0] + Σ(pub[i] · IC[i+1])
    fn verify_groth16_pairing(
        env: &Env,
        proof: &Groth16Proof,
        vk: &VerificationKey,
        public_inputs: &Vec<BytesN<32>>,
    ) -> bool {
        let bn254 = env.crypto().bn254();

        // --- Validate IC length ---
        // IC must have (num_public_inputs + 1) elements
        let num_inputs = public_inputs.len();
        let ic_len = vk.ic.len();
        if ic_len != num_inputs + 1 {
            panic!("IC length mismatch: expected {} but got {}", num_inputs + 1, ic_len);
        }

        // --- Compute the linear combination of IC with public inputs ---
        // IC_combined = IC[0] + pub[0]·IC[1] + pub[1]·IC[2] + ...
        let mut ic_combined = Bn254G1Affine::from_bytes(vk.ic.get(0).unwrap());

        for i in 0..num_inputs {
            let pub_input = public_inputs.get(i).unwrap();
            let ic_point = Bn254G1Affine::from_bytes(vk.ic.get(i + 1).unwrap());
            let scalar = Fr::from_bytes(pub_input);

            // pub[i] · IC[i+1]
            let scaled = bn254.g1_mul(&ic_point, &scalar);
            // Accumulate
            ic_combined = bn254.g1_add(&ic_combined, &scaled);
        }

        // --- Negate proof.A for the pairing check equation ---
        let neg_a = -Bn254G1Affine::from_bytes(proof.a.clone());

        // --- Construct the 4-pairing check ---
        // e(-A, B) · e(α, β) · e(IC_combined, γ) · e(C, δ) == 1
        let g1_points: Vec<Bn254G1Affine> = Vec::from_array(env, [
            neg_a,
            Bn254G1Affine::from_bytes(vk.alpha.clone()),
            ic_combined,
            Bn254G1Affine::from_bytes(proof.c.clone()),
        ]);

        let g2_points: Vec<Bn254G2Affine> = Vec::from_array(env, [
            Bn254G2Affine::from_bytes(proof.b.clone()),
            Bn254G2Affine::from_bytes(vk.beta.clone()),
            Bn254G2Affine::from_bytes(vk.gamma.clone()),
            Bn254G2Affine::from_bytes(vk.delta.clone()),
        ]);

        bn254.pairing_check(g1_points, g2_points)
    }

    /// Verify batch of proofs (for batch payroll).
    pub fn verify_batch_proofs(
        env: Env,
        proofs: Vec<Groth16Proof>,
        commitments: Vec<BytesN<32>>,
        nullifiers: Vec<BytesN<32>>,
        recipient_hashes: Vec<BytesN<32>>,
    ) -> bool {
        if proofs.len() != commitments.len()
            || proofs.len() != nullifiers.len()
            || proofs.len() != recipient_hashes.len()
        {
            return false;
        }

        for i in 0..proofs.len() {
            let proof = proofs.get(i).unwrap();
            let commitment = commitments.get(i).unwrap();
            let nullifier = nullifiers.get(i).unwrap();
            let recipient = recipient_hashes.get(i).unwrap();

            if !Self::verify_payment_proof(env.clone(), proof, commitment, nullifier, recipient) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn mock_verification_key(env: &Env) -> VerificationKey {
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

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register(ProofVerifier, ());
        let client = ProofVerifierClient::new(&env, &contract_id);

        let vk = mock_verification_key(&env);
        client.initialize_verifier(&vk);
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_double_initialize_panics() {
        let env = Env::default();
        let contract_id = env.register(ProofVerifier, ());
        let client = ProofVerifierClient::new(&env, &contract_id);

        let vk = mock_verification_key(&env);
        client.initialize_verifier(&vk);
        client.initialize_verifier(&vk); // Should panic
    }
}
