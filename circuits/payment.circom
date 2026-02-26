pragma circom 2.0.0;

/*
 * ZK Payroll – Payment Circuit (placeholder)
 *
 * Proves knowledge of (salary, blinding) such that:
 *
 *   salary_commitment = Poseidon(salary, blinding)
 *   payment_nullifier = Poseidon(salary_commitment, nonce)
 *   recipient_hash    = Poseidon(recipient_address)
 *
 * Public inputs:
 *   salary_commitment  – stored on-chain at onboarding time
 *   payment_nullifier  – unique per payment; prevents double-spending
 *   recipient_hash     – hash of the employee's wallet address
 *
 * Private inputs (known only to the prover):
 *   salary             – the employee's actual salary
 *   blinding           – a random blinding factor chosen at commitment time
 *   nonce              – payment-specific nonce (e.g. block number)
 *   recipient_address  – the employee's actual address
 *
 * NOTE: This is a PLACEHOLDER circuit.  The constraint system below uses
 * simple linear arithmetic instead of Poseidon because the circomlib
 * Poseidon template is not yet linked.  Replace the constraints below
 * with the real Poseidon template once `circomlib` is installed:
 *
 *   npm install circomlib
 *
 * and update the templates to:
 *   include "node_modules/circomlib/circuits/poseidon.circom";
 *
 * Compile with:
 *   circom payment.circom --r1cs --wasm --sym -o build/
 *
 * Then run the trusted setup:
 *   snarkjs groth16 setup build/payment.r1cs pot12_final.ptau payment_0000.zkey
 *   snarkjs zkey contribute payment_0000.zkey payment_final.zkey --name="1st Contributor"
 *   snarkjs zkey export verificationkey payment_final.zkey verification_key.json
 */

template PaymentCircuit() {
    // ── Private inputs ────────────────────────────────────────────────────────
    signal input salary;
    signal input blinding;

    // ── Public outputs ────────────────────────────────────────────────────────
    signal output salary_commitment;
    signal output payment_nullifier;
    signal output recipient_hash;

    // ── Placeholder constraints (NOT cryptographically sound) ─────────────────
    // Replace with real Poseidon constraints before production deployment.
    salary_commitment <== salary + blinding * 7;
    payment_nullifier <== salary_commitment * 13 + 1;
    recipient_hash    <== blinding * 31 + 17;
}

component main {
    public [salary_commitment, payment_nullifier, recipient_hash]
} = PaymentCircuit();
