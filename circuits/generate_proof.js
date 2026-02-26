#!/usr/bin/env node
'use strict';

/**
 * ZK Payroll – Proof Generator
 *
 * Usage:
 *   node generate_proof.js <salary> <blinding>
 *
 * Writes three files to the current working directory:
 *   proof.json       – Groth16 proof in standard SnarkJS format
 *   public.json      – Public signals in standard SnarkJS format
 *   proof_bytes.json – Same data as hex strings for direct Rust consumption
 *
 * Behaviour:
 *   1. If `snarkjs` is installed AND the compiled circuit artifacts
 *      (payment_js/payment.wasm + payment_final.zkey) are present beside
 *      this script, a **real** Groth16 proof is generated via SnarkJS.
 *   2. Otherwise a **deterministic mock** proof is generated in the same
 *      JSON formats so that the Rust parsing and deserialization pipeline
 *      can be exercised without requiring a full ZK toolchain.
 *
 * All field elements are drawn from the BN254 scalar field (< BN254_R) so
 * the byte representations always fit in 32 bytes.
 */

const fs   = require('fs');
const path = require('path');

// ── CLI args ──────────────────────────────────────────────────────────────────
const salary   = BigInt(process.argv[2] ?? '5000');
const blinding = BigInt(process.argv[3] ?? '123');

// BN254 scalar field prime r
const BN254_R = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

// ── Circuit artefact paths ────────────────────────────────────────────────────
const CIRCUIT_DIR = __dirname;
const WASM_PATH   = path.join(CIRCUIT_DIR, 'payment_js', 'payment.wasm');
const ZKEY_PATH   = path.join(CIRCUIT_DIR, 'payment_final.zkey');

// ── Entry point ───────────────────────────────────────────────────────────────
(async () => {
  let snarkjs      = null;
  let hasArtifacts = false;

  try {
    snarkjs      = require('snarkjs');
    hasArtifacts = fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH);
  } catch (_) {
    // snarkjs not installed – fall through to mock path
  }

  if (snarkjs && hasArtifacts) {
    await generateRealProof(snarkjs, salary, blinding);
  } else {
    if (!snarkjs) {
      process.stderr.write(
        '[generate_proof.js] snarkjs not found – generating deterministic mock proof.\n'
      );
    } else {
      process.stderr.write(
        '[generate_proof.js] Circuit artefacts not found – generating deterministic mock proof.\n'
      );
    }
    generateMockProof(salary, blinding);
  }
})().catch(err => {
  process.stderr.write(`[generate_proof.js] Fatal: ${err.message}\n`);
  process.exit(1);
});

// ── Real proof (requires snarkjs + compiled circuit) ─────────────────────────
async function generateRealProof(snarkjs, salary, blinding) {
  const input = {
    salary:   salary.toString(),
    blinding: blinding.toString(),
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input, WASM_PATH, ZKEY_PATH
  );

  writeStandardFiles(proof, publicSignals);
  writeProofBytesFile(proof, publicSignals);
  process.stdout.write('[generate_proof.js] Real Groth16 proof written.\n');
}

// ── Mock proof (no toolchain required) ───────────────────────────────────────
function generateMockProof(salary, blinding) {
  const s = salary   % BN254_R;
  const b = blinding % BN254_R;

  // Derive deterministic public signals (placeholder for Poseidon hash)
  const commitment = (s + b * 7n)             % BN254_R;  // salary_commitment
  const nullifier  = (commitment * 13n + 1n)  % BN254_R;  // payment_nullifier
  const recipient  = (b * 31n + 17n)          % BN254_R;  // recipient_hash

  // G1 point π_A: two 32-byte field elements
  const a_x = (s * 3n  + 1n) % BN254_R;
  const a_y = (b * 5n  + 2n) % BN254_R;

  // G2 point π_B: four 32-byte field elements
  const b_x0 = (s * 17n + 5n) % BN254_R;
  const b_x1 = (b * 19n + 6n) % BN254_R;
  const b_y0 = (s * 23n + 7n) % BN254_R;
  const b_y1 = (b * 29n + 8n) % BN254_R;

  // G1 point π_C: two 32-byte field elements
  const c_x = (commitment * 7n  + 3n) % BN254_R;
  const c_y = (nullifier  * 11n + 4n) % BN254_R;

  const proof = {
    pi_a:     [a_x.toString(),  a_y.toString(),  '1'],
    pi_b:     [
      [b_x0.toString(), b_x1.toString()],
      [b_y0.toString(), b_y1.toString()],
      ['1', '0'],
    ],
    pi_c:     [c_x.toString(), c_y.toString(), '1'],
    protocol: 'groth16',
    curve:    'bn128',
  };

  const publicSignals = [
    commitment.toString(),
    nullifier.toString(),
    recipient.toString(),
  ];

  writeStandardFiles(proof, publicSignals);
  writeProofBytesFile(proof, publicSignals);
  process.stdout.write('[generate_proof.js] Mock proof written.\n');
}

// ── File writers ──────────────────────────────────────────────────────────────

/** Write the standard SnarkJS proof.json and public.json. */
function writeStandardFiles(proof, publicSignals) {
  fs.writeFileSync('proof.json',  JSON.stringify(proof,         null, 2));
  fs.writeFileSync('public.json', JSON.stringify(publicSignals, null, 2));
}

/**
 * Derive hex-encoded byte arrays from proof and public signals and write
 * proof_bytes.json.  This flat key→hex-string format is trivial to parse
 * in Rust without an external JSON library.
 *
 * Field-element encoding:
 *   Each BN254 field element (≤ 254 bits) is encoded as a 32-byte
 *   big-endian unsigned integer, represented as exactly 64 lowercase
 *   hex characters (zero-padded on the left).
 *
 * Point encoding:
 *   G1 point (x, y)          → 64 bytes  = x_bytes ‖ y_bytes
 *   G2 point (x0,x1, y0,y1) → 128 bytes = x0_bytes ‖ x1_bytes ‖ y0_bytes ‖ y1_bytes
 */
function writeProofBytesFile(proof, publicSignals) {
  const fe = s => fieldElemToHex32(BigInt(s)); // field element → 64 hex chars

  // π_A: G1 = x ‖ y  (128 hex chars = 64 bytes)
  const pi_a = fe(proof.pi_a[0]) + fe(proof.pi_a[1]);

  // π_B: G2 = x0 ‖ x1 ‖ y0 ‖ y1  (256 hex chars = 128 bytes)
  const pi_b =
    fe(proof.pi_b[0][0]) + fe(proof.pi_b[0][1]) +
    fe(proof.pi_b[1][0]) + fe(proof.pi_b[1][1]);

  // π_C: G1 = x ‖ y  (128 hex chars = 64 bytes)
  const pi_c = fe(proof.pi_c[0]) + fe(proof.pi_c[1]);

  const salary_commitment = fe(publicSignals[0]);
  const payment_nullifier = fe(publicSignals[1]);
  const recipient_hash    = fe(publicSignals[2]);

  const proofBytes = {
    pi_a,
    pi_b,
    pi_c,
    salary_commitment,
    payment_nullifier,
    recipient_hash,
  };

  fs.writeFileSync('proof_bytes.json', JSON.stringify(proofBytes, null, 2));
}

/**
 * Convert a BigInt field element to exactly 64 lowercase hex characters
 * (32 bytes, big-endian, zero-padded).
 *
 * Panics if the value does not fit in 32 bytes (value >= 2^256).
 */
function fieldElemToHex32(n) {
  if (n < 0n) {
    throw new Error(`Negative field element: ${n}`);
  }
  const hex = n.toString(16);
  if (hex.length > 64) {
    throw new Error(`Field element too large for 32 bytes: ${n}`);
  }
  return hex.padStart(64, '0');
}
