# ZK Payroll Glossary

A shared reference for key terms across contract, proof, and payroll concepts. This glossary aligns terminology with the SDK interface and dashboard implementations.

---

## Contract Terms

### Commitment (Salary Commitment)
A zero-knowledge commitment (Poseidon hash) that represents a private salary amount. The commitment binds a salary value to a blinding factor, making it impossible to recover the salary from the commitment alone. Commitments are stored on-chain and serve as the basis for all salary-based proofs.

**Related**: Blinding factor, Poseidon hash, Proof

### Payroll Registry
A contract that maintains the roster of companies and their employees. The registry stores company metadata (admin, treasury) and employee-commitment mappings, acting as the authoritative source for payroll participant data.

**Related**: Company ID, Employee, Treasury

### Payment Executor
A contract that executes individual employee payments after proof verification. It enforces payment safety rules (no double-spend via nullifiers, no payment to unregistered employees) and maintains period-based isolation to prevent replay attacks across payroll cycles.

**Related**: Nullifier, Period, Proof verification, Replay protection

### Company ID
A unique 64-bit unsigned integer assigned sequentially by `payroll_registry` when a company registers. Company IDs are globally unique and immutable.

**Related**: Payroll registry, Treasury

### Employee
An individual receiving payroll. Identified by their Soroban `Address` (Ed25519 public key). Each employee is associated with exactly one commitment per company.

**Related**: Address, Commitment, Salary

### Period
A time-bounded payroll cycle. Each company can create multiple periods (e.g., weekly, bi-weekly, monthly). Period IDs are scoped within a company: `(company_id, period_id)` forms a unique composite key.

**Related**: Company ID, Period-based isolation, Payment executor

### Treasury
The Soroban address that holds company funds for payroll disbursement. The treasury receives deposits and authorizes payment transfers to employees.

**Related**: Company ID, Payment executor

---

## Proof & Cryptographic Terms

### Proof (Groth16 Proof)
A succinct zero-knowledge proof that validates a payment without revealing the underlying salary amount. Groth16 proofs consist of three components: proof_a, proof_b, and proof_c (each a BN254 elliptic curve point). The proof verifies that a claimed payment is consistent with a stored commitment and satisfies all circuit constraints.

**Related**: Groth16, BN254, Proof verification, Nullifier

### Proof Verification
The on-chain process of checking that a Groth16 proof is valid with respect to the verification key and public inputs. The `proof_verifier` contract performs this using BN254 elliptic curve arithmetic. Verification succeeds only if the proof satisfies all circuit constraints.

**Related**: Groth16, BN254, Proof verifier, Verification key

### Proof Verifier
A contract that implements Groth16 proof verification over BN254. It stores the verification key and validates incoming proofs against it. The verifier is the security boundary: an invalid proof is rejected before payment execution proceeds.

**Related**: Groth16, BN254, Verification key

### Verification Key
The public parameters used to verify Groth16 proofs. The verification key includes curve points (alpha, beta, gamma, delta) and the initial commitments (IC). It is generated during the trusted setup and must be kept immutable.

**Related**: Groth16, Trusted setup, Proof verification

### BN254
A 254-bit elliptic curve over a finite field. Used as the basis for Groth16 proof construction and verification in this system. Stellar Protocol X-Ray (Protocol 25) provides BN254 arithmetic primitives for Soroban contracts.

**Related**: Groth16, Proof, Stellar Protocol X-Ray

### Poseidon Hash
A hash function designed for zero-knowledge systems. Used to compute salary commitments: `commitment = Poseidon(salary_amount, blinding_factor)`. Poseidon is more proof-friendly than SHA256 and reduces circuit constraints.

**Related**: Commitment, Blinding factor

### Blinding Factor
A random secret value paired with a salary amount to create a commitment. The blinding factor ensures that two identical salaries produce different commitments (hiding salary from statistical analysis). Blinding factors are never stored on-chain.

**Related**: Commitment, Salary, Poseidon hash

### Nullifier
A unique identifier derived from proof and salary data that prevents proof replay (double-spend). After a proof is executed, its nullifier is recorded in `payment_executor` storage. Subsequent attempts to use the same proof fail because its nullifier is already marked as consumed.

**Related**: Replay protection, Proof, Double-spend

### Replay Protection
A mechanism preventing the same proof from being executed more than once. Implemented via nullifiers: each executed proof's nullifier is stored, and new submissions with duplicate nullifiers are rejected with `ProofAlreadyUsed`.

**Related**: Nullifier, Double-spend, Security

### Trusted Setup
A ceremony that generates the proving key and verification key for Groth16. The output artifacts (zkey, ptau) must be kept secure; compromise of these files breaks the security of the entire system.

**Related**: Groth16, Verification key, Proof

---

## Audit & Compliance Terms

### Audit Module
A contract enabling selective disclosure of salary data to authorized auditors. Auditors generate view keys to decrypt specific commitments for compliance verification. View keys are scoped by company, time range, and optional employee list.

**Related**: View key, Selective disclosure, Auditor

### View Key
A time-bounded credential issued by the audit module to an auditor, enabling decryption of commitments within a specified scope (company, time range, employees). View keys expire at a defined ledger sequence and cannot be reused after expiration.

**Related**: Audit module, Selective disclosure, Auditor

### Selective Disclosure
The ability to prove facts about salary data to an auditor without exposing salary amounts to the public ledger. Auditors use view keys to decrypt commitments and verify that payments were made according to policy.

**Related**: Audit module, View key, Compliance

### Auditor
An authorized party granted temporary access to salary data via a view key. Auditors can verify commitments and reconstruct payment amounts, but cannot extend view key scope or revoke access from other auditors.

**Related**: Audit module, View key, Selective disclosure

### Audit Access Revocation
The process of revoking an auditor's active view key before its natural expiration. Only authorized actors (typically company admin or designated compliance officer) can revoke access. Revocation is recorded in an event for audit trail purposes.

**Related**: View key, Auditor, Compliance

---

## Operational Terms

### Pause Manager
A contract that can halt all payroll activity in an emergency. When paused, `payment_executor` rejects all new payments. Only authorized operators can pause or unpause the system.

**Related**: Payment executor, Emergency, Security

### Period-Based Isolation
A design pattern preventing payment replay across multiple payroll cycles. Each period forms an independent namespace; a proof valid in period 1 cannot be reused in period 2, even with the same nullifier, because the verification inputs include the period ID.

**Related**: Period, Nullifier, Replay protection

### Double-Spend
An attack where the same proof is submitted multiple times to extract multiple payments for a single salary commitment. Double-spend is prevented via nullifier replay protection.

**Related**: Nullifier, Replay protection, Proof

### Circuit Constraint
A mathematical requirement enforced by the zero-knowledge circuit. Constraints verify properties like: (1) the proof is signed by the employee, (2) the amount matches the commitment, (3) the payment recipient is authorized. Constraints are evaluated during proof verification.

**Related**: Groth16, Proof, Proof verification

---

## Process Terms

### Payroll Run
A single invocation of `batch_process_payroll` that executes multiple payments in a single transaction. Each run is assigned a unique run ID for tracking and reconciliation. Run IDs are contiguous; a gap signals a failed batch.

**Related**: Payment executor, Batch processing

### Batch Processing
The execution of multiple employee payments in a single transaction. Batch processing reduces gas costs and simplifies reconciliation compared to per-employee transactions.

**Related**: Payroll run, Payment executor

### Interrupted Execution
A partial payroll run where some payments succeed before the transaction fails (e.g., out-of-gas, unregistered employee mid-batch). Idempotent retry logic ensures subsequent attempts complete without duplicating successful payments.

**Related**: Payroll run, Batch processing, Retry safety

### Retry Safety
The property that retrying a partially completed operation (e.g., payroll) produces the same result as a fresh execution. Implemented via idempotent payment logic: already-paid employees are skipped, nullifiers prevent double-spend, and period closure prevents payment to old periods.

**Related**: Interrupted execution, Nullifier, Idempotency

---

## SDK & Integration Terms

### SDK (Software Development Kit)
Client libraries enabling applications to interact with ZK Payroll contracts. The SDK abstracts proof generation, commitment management, and contract invocation, providing a simpler interface than raw XDR.

**Related**: Contract, Proof, Entrypoint

### Entrypoint
A public function exposed by a contract. Examples: `register_company`, `add_employee`, `execute_payment`. Entrypoints are the contract's API boundary.

**Related**: Contract, SDK

### Stellar Protocol X-Ray (Protocol 25)
A Stellar update introducing ZK primitives (BN254, Poseidon) to Soroban. This system leverages these primitives for efficient proof verification on-chain.

**Related**: BN254, Poseidon hash, Soroban

### Soroban
Stellar's smart contract platform. Contracts are written in Rust, compiled to WebAssembly (WASM), and run on the Stellar ledger.

**Related**: Contract, Rust, WASM

---

## Cross-Reference Index

| Term | See Also |
|------|----------|
| Commitment | Blinding factor, Poseidon hash, Proof |
| Proof | BN254, Groth16, Nullifier, Verification key |
| Payroll run | Batch processing, Interrupted execution, Retry safety |
| Audit module | View key, Selective disclosure, Auditor |
| Period | Company ID, Payment executor, Replay protection |
| Nullifier | Double-spend, Replay protection, Proof |

