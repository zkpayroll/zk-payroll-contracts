//! Off-chain cryptographic primitives for the ZK Payroll CLI.
//!
//! # BN254 scalar field
//! The BN254 (Alt-BN128) curve's scalar field has prime order:
//!   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!
//! Blinding factors MUST be valid elements of this field so that they can be
//! used directly as private inputs to the Circom payment circuit.
//!
//! # Poseidon hash
//! `poseidon_commitment` uses circomlib-compatible Poseidon parameters over
//! BN254 (width-3 sponge, two field-element inputs).  This matches the
//! `payment.circom` circuit and the on-chain verifier once CAP-0075 lands.
//!
//! # Byte encoding convention
//! All 32-byte field-element representations in this module use the canonical
//! **little-endian** encoding produced by `ark_serialize::CanonicalSerialize`.
//! Callers that store or display these bytes as hex will see the LE form;
//! this is consistent with the arkworks / circomlib toolchain.

use anyhow::Context;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate a uniformly random BN254 scalar field element using the OS CSPRNG.
///
/// Reads 64 bytes (512 bits) from [`OsRng`] and reduces modulo the BN254
/// scalar field prime.  The statistical bias from the reduction is at most
/// 2^{-254}, which is cryptographically negligible.
///
/// # Returns
/// 32-byte **little-endian** canonical representation of the field element.
///
/// # Panics
/// Panics only if the operating system cannot supply entropy — an unrecoverable
/// condition.
pub fn gen_blinding_factor() -> [u8; 32] {
    // 64 bytes → 512 bits; reducing 512-bit uniform value mod 254-bit prime
    // gives bias < 2^{-254}.
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);

    let fr = Fr::from_le_bytes_mod_order(&wide);
    fr_to_le_bytes(fr)
}

/// Compute `Poseidon(salary_amount, blinding_factor)` over the BN254 scalar
/// field using circomlib-compatible parameters (width-3 sponge, two inputs).
///
/// # Arguments
/// * `salary` — gross salary amount; interpreted as a field element via
///   `Fr::from(salary)`.
/// * `blinding_le` — 32-byte little-endian BN254 scalar returned by
///   [`gen_blinding_factor`].
///
/// # Returns
/// 32-byte **little-endian** encoding of the Poseidon hash output.
pub fn poseidon_commitment(salary: u64, blinding_le: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let salary_fr = Fr::from(salary);
    // Re-hydrate the field element from its stored LE byte representation.
    let blinding_fr = Fr::from_le_bytes_mod_order(blinding_le);

    // Poseidon with circomlib-compatible parameters for BN254, two inputs.
    let mut hasher =
        Poseidon::<Fr>::new_circom(2).context("Failed to initialise Poseidon hasher")?;

    let hash_fr = hasher
        .hash(&[salary_fr, blinding_fr])
        .context("Poseidon hash computation failed")?;

    Ok(fr_to_le_bytes(hash_fr))
}

/// Serialise an `Fr` field element to its 32-byte little-endian canonical form.
///
/// Uses `ark_serialize::CanonicalSerialize` which is infallible for in-memory
/// `Vec<u8>` writers.
fn fr_to_le_bytes(fr: Fr) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    fr.serialize_uncompressed(&mut buf)
        .expect("Fr serialisation to Vec<u8> is infallible");
    debug_assert_eq!(
        buf.len(),
        32,
        "BN254 field element must be exactly 32 bytes"
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh blinding factor must be exactly 32 bytes and non-zero.
    #[test]
    fn blinding_factor_is_nonzero_32_bytes() {
        let b = gen_blinding_factor();
        assert_eq!(b.len(), 32);
        assert_ne!(b, [0u8; 32], "random blinding factor must not be zero");
    }

    /// Two independently generated blinding factors must differ (collision
    /// probability is negligible for a 254-bit field).
    #[test]
    fn blinding_factors_are_distinct() {
        let b1 = gen_blinding_factor();
        let b2 = gen_blinding_factor();
        assert_ne!(b1, b2, "two random blinding factors must differ");
    }

    /// Poseidon commitment is exactly 32 bytes.
    #[test]
    fn commitment_is_32_bytes() {
        let blinding = gen_blinding_factor();
        let c = poseidon_commitment(5_000_000, &blinding).unwrap();
        assert_eq!(c.len(), 32);
    }

    /// Commitment is deterministic: same inputs yield the same output.
    #[test]
    fn commitment_is_deterministic() {
        let blinding = gen_blinding_factor();
        let c1 = poseidon_commitment(5_000_000, &blinding).unwrap();
        let c2 = poseidon_commitment(5_000_000, &blinding).unwrap();
        assert_eq!(c1, c2, "Poseidon hash must be deterministic");
    }

    /// Different salaries produce different commitments (with the same blinding).
    #[test]
    fn different_salaries_produce_different_commitments() {
        let blinding = gen_blinding_factor();
        let c1 = poseidon_commitment(5_000_000, &blinding).unwrap();
        let c2 = poseidon_commitment(6_000_000, &blinding).unwrap();
        assert_ne!(
            c1, c2,
            "different salaries must yield different commitments"
        );
    }

    /// Different blinding factors produce different commitments (same salary).
    #[test]
    fn different_blindings_produce_different_commitments() {
        let b1 = gen_blinding_factor();
        let b2 = gen_blinding_factor();
        let c1 = poseidon_commitment(5_000_000, &b1).unwrap();
        let c2 = poseidon_commitment(5_000_000, &b2).unwrap();
        assert_ne!(
            c1, c2,
            "different blinding factors must yield different commitments"
        );
    }

    /// Zero salary is a valid field element — commitment must not panic.
    #[test]
    fn zero_salary_is_valid() {
        let blinding = gen_blinding_factor();
        let result = poseidon_commitment(0, &blinding);
        assert!(result.is_ok(), "zero salary must be a valid Poseidon input");
    }
}
