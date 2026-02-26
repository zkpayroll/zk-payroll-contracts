//! Proof generation helper for integration tests.
//!
//! Bridges Circom/SnarkJS proof generation with the Soroban Rust test
//! framework by:
//!
//! 1. Spawning `node circuits/generate_proof.js <salary> <blinding>` as a
//!    subprocess via [`std::process::Command`].
//! 2. Reading the generated `proof_bytes.json` file written to a temp directory.
//! 3. Deserialising the hex-encoded fields into fixed-size Rust arrays that
//!    map directly onto the `Groth16Proof` and `BytesN` types used by Soroban.
//!
//! If Node.js is not installed or the script cannot be located the helper
//! returns `None` and emits a warning to stderr so that CI environments
//! without a Node.js / SnarkJS toolchain gracefully skip the test.
//!
//! # Security
//! The subprocess receives only two `u64` arguments converted to decimal
//! strings by [`u64_to_decimal`].  There is no string interpolation from
//! external sources, so command injection is not possible.

// This module is only compiled in `cfg(test)` mode.
// The parent crate is `#![no_std]`, but the Rust test harness always links
// `std`, so we make it explicitly available here.
#[allow(unused_extern_crates)]
extern crate std;

use std::env;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::String;
use std::vec::Vec;

// ── Public types ──────────────────────────────────────────────────────────────

/// Groth16 proof bytes parsed from `proof_bytes.json`.
///
/// Byte layout matches the `Groth16Proof` struct in `proof_verifier`:
/// * `pi_a`  — 64 bytes: G1 point `x_bytes ‖ y_bytes`
/// * `pi_b`  — 128 bytes: G2 point `x0_bytes ‖ x1_bytes ‖ y0_bytes ‖ y1_bytes`
/// * `pi_c`  — 64 bytes: G1 point `x_bytes ‖ y_bytes`
///
/// Each BN254 field element occupies exactly 32 big-endian bytes (zero-padded).
///
/// Public fields are intentionally all exposed: callers that invoke
/// `verify_payment_proof` directly (rather than through `batch_process_payroll`)
/// will use `payment_nullifier` and `recipient_hash` as public inputs.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GeneratedProof {
    /// G1 point π_A: 64 bytes
    pub pi_a: [u8; 64],
    /// G2 point π_B: 128 bytes
    pub pi_b: [u8; 128],
    /// G1 point π_C: 64 bytes
    pub pi_c: [u8; 64],
    /// Public input 0 — salary commitment: 32 bytes
    pub salary_commitment: [u8; 32],
    /// Public input 1 — payment nullifier: 32 bytes
    pub payment_nullifier: [u8; 32],
    /// Public input 2 — recipient address hash: 32 bytes
    pub recipient_hash: [u8; 32],
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Attempt to generate a Groth16 proof by invoking the Node.js helper script.
///
/// Calls `node circuits/generate_proof.js <salary> <blinding>`, then reads
/// and parses the resulting `proof_bytes.json`.
///
/// Returns `None` (with a stderr warning) when any of the following prevent
/// proof generation:
/// * Node.js is not installed
/// * `circuits/generate_proof.js` is not found
/// * The subprocess exits with a non-zero status
/// * `proof_bytes.json` is missing or unparseable
///
/// This allows CI environments without a Node.js / SnarkJS toolchain to skip
/// proof-generation tests gracefully without failing the build.
pub fn try_generate_proof(salary: u64, blinding: u64) -> Option<GeneratedProof> {
    if !is_node_available() {
        warn(
            "Node.js is not installed; \
             install Node.js to enable dynamic proof generation tests.",
        );
        return None;
    }

    let script_path = match find_script() {
        Some(p) => p,
        None => {
            warn(
                "circuits/generate_proof.js not found; \
                 skipping dynamic proof generation.",
            );
            return None;
        }
    };

    // Write proof artefacts into an isolated temp directory.
    let out_dir = env::temp_dir().join("zk_payroll_proofs");
    if fs::create_dir_all(&out_dir).is_err() {
        warn("Cannot create temp directory; skipping dynamic proof generation.");
        return None;
    }

    // Spawn: node <script_path> <salary> <blinding>
    // Arguments are validated u64 values converted to decimal — no injection.
    let salary_str   = u64_to_decimal(salary);
    let blinding_str = u64_to_decimal(blinding);

    let output = Command::new("node")
        .arg(&script_path)
        .arg(&salary_str)
        .arg(&blinding_str)
        .current_dir(&out_dir)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => {
            warn("Failed to spawn `node`; skipping dynamic proof generation.");
            return None;
        }
    };

    if !output.status.success() {
        warn("generate_proof.js exited with non-zero status; skipping.");
        return None;
    }

    let bytes_path = out_dir.join("proof_bytes.json");
    let bytes_json = match fs::read_to_string(&bytes_path) {
        Ok(s) => s,
        Err(_) => {
            warn("Cannot read proof_bytes.json; skipping.");
            return None;
        }
    };

    match parse_proof_bytes(&bytes_json) {
        Some(p) => Some(p),
        None => {
            warn("Failed to parse proof_bytes.json; skipping.");
            None
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Write a warning to stderr without using the `eprintln!` macro (which
/// requires the std prelude to be in scope).
fn warn(msg: &str) {
    let _ = std::io::stderr().write_all(b"WARNING [proof_helper]: ");
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
}

/// Return `true` if `node --version` exits successfully.
fn is_node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Locate `circuits/generate_proof.js` by navigating upward from
/// `CARGO_MANIFEST_DIR` (i.e. `contracts/integration_tests`) to the
/// workspace root.
fn find_script() -> Option<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    // contracts/integration_tests/ → contracts/ → workspace root
    let workspace_root = Path::new(&manifest_dir).parent()?.parent()?;
    let script = workspace_root.join("circuits").join("generate_proof.js");
    if script.exists() { Some(script) } else { None }
}

/// Convert a `u64` to its decimal ASCII representation without relying on
/// the `ToString` trait or `format!` macro (both of which depend on the std
/// prelude being in scope in a `#![no_std]` crate context).
fn u64_to_decimal(mut n: u64) -> String {
    if n == 0 {
        let mut s = String::new();
        s.push('0');
        return s;
    }
    // Build digits in reverse, then reverse the Vec.
    let mut digits: Vec<u8> = Vec::new();
    while n > 0 {
        digits.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    digits.reverse();
    // SAFETY: digits is all ASCII decimal chars, so UTF-8 is valid.
    String::from_utf8(digits).expect("decimal digits are valid UTF-8")
}

/// Parse `proof_bytes.json` (a flat JSON object with hex-string values)
/// into a [`GeneratedProof`].
///
/// The format is intentionally simple — no nested objects, no escape
/// sequences — so a lightweight hand-rolled parser suffices, avoiding any
/// external JSON library dependency.
fn parse_proof_bytes(json: &str) -> Option<GeneratedProof> {
    let pi_a_hex       = extract_str_field(json, "pi_a")?;
    let pi_b_hex       = extract_str_field(json, "pi_b")?;
    let pi_c_hex       = extract_str_field(json, "pi_c")?;
    let commit_hex     = extract_str_field(json, "salary_commitment")?;
    let nullifier_hex  = extract_str_field(json, "payment_nullifier")?;
    let recipient_hex  = extract_str_field(json, "recipient_hash")?;

    Some(GeneratedProof {
        pi_a:              hex_decode::<64>(pi_a_hex)?,
        pi_b:              hex_decode::<128>(pi_b_hex)?,
        pi_c:              hex_decode::<64>(pi_c_hex)?,
        salary_commitment: hex_decode::<32>(commit_hex)?,
        payment_nullifier: hex_decode::<32>(nullifier_hex)?,
        recipient_hash:    hex_decode::<32>(recipient_hex)?,
    })
}

/// Extract the string value of a top-level JSON key.
///
/// Scans for the exact byte pattern `"<field>": "<value>"` and returns the
/// slice of `json` between the value's enclosing quotes.  Handles flat JSON
/// objects with string values only — sufficient for `proof_bytes.json`.
fn extract_str_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let bytes       = json.as_bytes();
    let field_bytes = field.as_bytes();
    let flen        = field_bytes.len();

    let mut i = 0usize;
    while i + flen + 2 <= bytes.len() {
        // Match the pattern: `"<field>"`
        if bytes[i] == b'"'
            && bytes.get(i + 1..i + 1 + flen) == Some(field_bytes)
            && bytes.get(i + 1 + flen)         == Some(&b'"')
        {
            // Advance past the closing `"` of the key name.
            let after_key = &json[i + 1 + flen + 1..];
            // Expect optional whitespace, then `:`.
            let after_key = after_key.trim_start_matches(|c: char| c.is_ascii_whitespace());
            let after_col = after_key.strip_prefix(':')?;
            // Expect optional whitespace, then the opening `"` of the value.
            let after_col = after_col.trim_start_matches(|c: char| c.is_ascii_whitespace());
            let value     = after_col.strip_prefix('"')?;
            // Value extends to the next `"`.
            let end = value.find('"')?;
            return Some(&value[..end]);
        }
        i += 1;
    }
    None
}

/// Decode a lowercase hex string into exactly `N` bytes.
///
/// * The input must have exactly `N * 2` characters (no `0x` prefix).
/// * Returns `None` on length mismatch or invalid hex digits.
fn hex_decode<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ── Unit tests for the helper itself ─────────────────────────────────────────
#[cfg(test)]
mod inner {
    use super::*;

    #[test]
    fn test_u64_to_decimal_zero() {
        assert_eq!(u64_to_decimal(0), "0");
    }

    #[test]
    fn test_u64_to_decimal_values() {
        assert_eq!(u64_to_decimal(1),        "1");
        assert_eq!(u64_to_decimal(5000),     "5000");
        assert_eq!(u64_to_decimal(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn test_hex_decode_zeros() {
        let zeros = "0".repeat(64);
        let result = hex_decode::<32>(&zeros);
        assert_eq!(result, Some([0u8; 32]));
    }

    #[test]
    fn test_hex_decode_wrong_length() {
        assert!(hex_decode::<32>("aabb").is_none());
    }

    #[test]
    fn test_extract_str_field() {
        let json = r#"{"pi_a": "deadbeef", "pi_b": "cafebabe"}"#;
        assert_eq!(extract_str_field(json, "pi_a"), Some("deadbeef"));
        assert_eq!(extract_str_field(json, "pi_b"), Some("cafebabe"));
        assert_eq!(extract_str_field(json, "pi_c"), None);
    }

    #[test]
    fn test_extract_str_field_no_partial_match() {
        // "pi_a" must not match a field literally named "pi_ax"
        let json = r#"{"pi_ax": "wrongval", "pi_a": "rightval"}"#;
        assert_eq!(extract_str_field(json, "pi_a"), Some("rightval"));
    }
}
