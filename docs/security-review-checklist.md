# Security Review Checklist — Issue #84

This checklist **must be completed** before any mainnet-style deployment of ZK Payroll contracts. It provides a focused security gate addressing authentication, replay protection, treasury safety, and proof validation.

> **Enforcement:** All items must be checked off before mainnet release. Mandatory items (🔴) are blockers. Optional hardening items (🟡) are recommended but non-blocking.

---

## 1. Authentication & Authorization (🔴 Mandatory)

- [ ] **All state-mutating entry-points require auth** — Every function modifying contract state calls `env.require_auth()` at the entry point. No exceptions.
  - *Test:* `cargo test` passes all `test_unauthorized_*` tests in each contract.
  - *Files:* `contracts/payroll_registry/src/lib.rs`, `contracts/payment_executor/src/lib.rs`, `contracts/audit_module/src/lib.rs`

- [ ] **Admin addresses validated at initialization** — `init_*_admin()` entry-points reject invalid (zero) addresses.
  - *Test:* Run `cargo test -- test_invalid_admin_address`
  - *Expected:* All admin init tests pass with proper error handling.

- [ ] **Company admin == registry admin** — Only the company admin registered in `register_company()` can modify that company's state.
  - *Test:* `test_unauthorized_employee_registration` in `payroll_registry/src/tests.rs`
  - *Expected:* Non-admin addresses are rejected with `Unauthorized` error.

- [ ] **Proof operator authorization** — Only authorized accounts can call `process_payment()` / `execute_batch()` on payment executor.
  - *Test:* Grep for `require_auth` in `contracts/payment_executor/src/lib.rs`
  - *Expected:* Payment entry-points call `env.require_auth()` before state writes.

---

## 2. Replay Protection (🔴 Mandatory)

- [ ] **Proof nullifiers prevent double-spend** — Each valid proof records a nullifier; re-submission of the same proof is rejected.
  - *Test:* `test_double_payment_rejected` in `contracts/integration_tests/src/lib.rs`
  - *Expected:* Second proof submission with same nullifier returns `ProofAlreadyVerified` error.

- [ ] **Nonce / sequence numbers in replay-sensitive operations** — Batch payroll operations use a monotonic sequence or nonce.
  - *Test:* `test_replay_protection` (if exists, or add to security_tests.rs)
  - *Expected:* Out-of-order or duplicate batches are rejected.

- [ ] **Signature validation on off-chain messages** — Any message signed off-chain (e.g., JSON payloads) includes a unique nonce.
  - *Check:* Review `docs/sdk-interface-spec.md` for signature requirements.
  - *Expected:* Clients include `nonce` in payloads; contracts validate it is fresh.

- [ ] **Commitment storage prevents re-use** — Once a salary commitment is locked (e.g., for a payment), it cannot be re-used in a different employee record.
  - *Test:* `test_commitment_immutability` in `salary_commitment/src/tests.rs`
  - *Expected:* Attempt to assign same commitment to two employees is rejected.

---

## 3. Treasury Safety (🔴 Mandatory)

- [ ] **Treasury address cannot be the same as any user address** — No single user controls both treasury and an employee account.
  - *Check:* Review company registration logic.
  - *Test:* Add test: `test_treasury_address_distinct_from_admin()`
  - *Files:* `contracts/payroll_registry/src/lib.rs`

- [ ] **Payment amounts match commitment amounts** — On-chain verification ensures the amount in the proof matches the salary commitment.
  - *Test:* `test_payment_amount_mismatch_rejected` in `contracts/integration_tests/src/lib.rs`
  - *Expected:* Proof for amount 5000 but commitment for 4000 is rejected.

- [ ] **No negative or overflow on treasury balance** — Treasury balance cannot go below 0 or overflow u64.
  - *Test:* `test_treasury_underflow_rejected` and `test_treasury_overflow_rejected`
  - *Expected:* Insufficient treasury funds cause transaction to revert.

- [ ] **Payment access control — only registered treasury can withdraw** — Only the registered treasury `Address` can initiate payment transfers.
  - *Test:* Unauthorized address cannot call `transfer_from_treasury()`
  - *Files:* `contracts/payment_executor/src/lib.rs`

- [ ] **SEP-41 token interaction safety** — All calls to the token contract are wrapped in error handling; failed transfers do not corrupt state.
  - *Test:* `test_token_transfer_failure_handling` (if token mock fails)
  - *Files:* `contracts/payment_executor/src/lib.rs` and `contracts/payroll/src/lib.rs`

---

## 4. Proof Validation (🔴 Mandatory)

- [ ] **Groth16 verifier is called for every proof** — No code path bypasses proof verification.
  - *Test:* Run `grep -r "verify" contracts/payment_executor/src/` and confirm all payment paths call verifier.
  - *Expected:* Every `process_payment()` call goes through `proof_verifier.verify_payment_proof()`.

- [ ] **Verification key is immutable post-initialization** — Once set, the VK cannot be changed without a new contract deployment.
  - *Check:* `proof_verifier::initialize_verifier()` is called only once.
  - *Test:* `test_vk_immutability` — second init call panics.
  - *Files:* `contracts/proof_verifier/src/lib.rs`

- [ ] **Public input count validation** — The verifier checks `public_inputs.len() + 1 == vk.ic.len()`.
  - *Test:* `test_invalid_public_inputs_rejected` in `proof_verifier/src/tests.rs`
  - *Expected:* Proof with wrong input count is rejected without panic.

- [ ] **Proof byte layout is enforced** — Proofs must be exactly 256 bytes: `pi_a[64] || pi_b[128] || pi_c[64]`.
  - *Test:* `test_proof_wrong_size_rejected`
  - *Expected:* 255-byte or 257-byte proof is rejected.

- [ ] **Zero-knowledge property is maintained** — Commitments do not leak salary amounts.
  - *Check:* Audit `salary_commitment/src/lib.rs` to confirm salary is never stored unencrypted.
  - *Expected:* Only the hash (Poseidon or SHA-256) is stored; plaintext salary is never logged or state-written.

---

## 5. State Consistency & Data Integrity (🔴 Mandatory)

- [ ] **Salary commitments are immutable** — Once registered, a commitment cannot be overwritten.
  - *Test:* `test_commitment_overwrite_rejected` in `salary_commitment/src/tests.rs`
  - *Expected:* Second `set_commitment()` call for same employee returns error.

- [ ] **Company registration is idempotent** — Registering the same company twice does not break state.
  - *Test:* `test_register_company_twice()` in `payroll_registry/src/tests.rs`
  - *Expected:* Second registration either returns same company ID or an error, never corrupt state.

- [ ] **Nullifier mapping is consistent** — Each proof's nullifier maps to exactly one verified payment.
  - *Check:* Review `payment_executor::process_payment()` nullifier insertion logic.
  - *Test:* `test_nullifier_uniqueness()` — verify no two proofs map to same nullifier.

- [ ] **Event logging includes required context** — All critical operations emit events with company ID, employee address, amount, and timestamp.
  - *Test:* `test_events_emitted_on_payment()` in `contracts/integration_tests/src/lib.rs`
  - *Expected:* Payment events include all required fields for audit logs.

---

## 6. Configuration & Setup Safety (🔴 Mandatory)

- [ ] **Contract addresses are validated on setup** — `initialize()` calls reject zero-address dependencies.
  - *Test:* `test_initialize_with_invalid_verifier()`, etc.
  - *Files:* `contracts/payment_executor/src/lib.rs`, `contracts/payroll/src/lib.rs`

- [ ] **Pause manager is properly initialized** — Before any payroll execution, the pause manager must be set and not paused.
  - *Test:* `test_payments_fail_when_paused()` in `contracts/payment_executor/tests/security_tests.rs`
  - *Expected:* If pause manager is paused, all payments are rejected.

- [ ] **Cross-contract dependencies are documented** — Clear mapping of which contract talks to which.
  - *Check:* Read `docs/sdk-interface-spec.md` for dependency diagram.
  - *Files:* `docs/architecture/commitment-state-storage-layout-13.md`

---

## 7. Denial of Service (DoS) Resistance (🟡 Recommended)

- [ ] **Unbounded loops are bounded** — No loops iterate over unbounded user-supplied collections.
  - *Check:* Review `execute_batch()` in `contracts/payment_executor/src/lib.rs` — batch size is capped.
  - *Test:* `test_batch_size_limit()` — submitting a batch > limit is rejected.

- [ ] **Storage rent is accounted for** — All state writes account for Soroban's storage rent / archival fees.
  - *Check:* Each contract's storage assumptions are documented.
  - *Files:* `docs/ops/rollback-checklist.md`

- [ ] **Gas limits are reasonable** — Payment processing should never require unreasonable gas.
  - *Benchmark:* Run `stellar contract invoke` and record gas used for a single payment.
  - *Expected:* < 100k stroops per payment (adjust if testnet realities differ).

---

## 8. Cryptographic Soundness (🟡 Recommended)

- [ ] **Poseidon parameters match Protocol 25 spec** — The Poseidon hash function uses the correct BN254 curve parameters.
  - *Check:* Review `salary_commitment/src/lib.rs` and confirm Poseidon constant usage.
  - *Reference:* [Stellar CAP-0075](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0075.md)

- [ ] **Blinding factor entropy is sufficient** — Blinding factors in fixtures are deterministic for testing but docs note that production use must use cryptographically random values.
  - *Check:* Read `docs/fixtures-guide.md` and `README.md` for blinding factor guidance.
  - *Expected:* Production code does NOT use fixture blinding factors.

- [ ] **No hardcoded secrets** — No private keys, blinding factors, or ceremony artifacts are committed to the repository.
  - *Test:* `git grep -E 'PRIVATE|SECRET|ptau' -- '*.rs' '*.circom'` returns zero results.

---

## 9. Testing & Coverage (🔴 Mandatory)

- [ ] **Unit test coverage >= 80%** — All contracts have comprehensive unit test coverage.
  - *Test:* Run coverage tool (e.g., `cargo tarpaulin`).
  - *Expected:* All public functions have at least one unit test.

- [ ] **End-to-end integration test passes** — Full happy-path from company registration → employee onboarding → payment execution.
  - *Test:* `cargo test -- test_happy_path` in `contracts/integration_tests/`
  - *Expected:* Test completes without panics or errors.

- [ ] **Negative tests for all critical paths** — Every auth/validation check has a corresponding test.
  - *Checklist:*
    - [ ] Unauthorized user cannot register company
    - [ ] Invalid proof is rejected
    - [ ] Double-spend is prevented
    - [ ] Treasury underflow is prevented
    - [ ] Non-admin cannot register employee

- [ ] **Security-specific tests exist** — `contracts/payment_executor/tests/security_tests.rs` covers re-entrancy, pause manager, and payment flow.
  - *Test:* `cargo test -p payment_executor --test security_tests`
  - *Expected:* All security tests pass.

---

## 10. Documentation & Deployment Readiness (🔴 Mandatory)

- [ ] **Security assumptions are documented** — A README or security section explains the threat model.
  - *File:* Check `README.md` "Security" section and `docs/security-review-checklist.md`.
  - *Expected:* Clear statement of what the contract does and does NOT protect against.

- [ ] **Deployment checklist is complete** — Use `docs/ops/preflight-deployment-checklist.md` before any release.
  - *Action:* Print the checklist and ensure all items are ticked before mainnet proposal.

- [ ] **Incident response playbook is current** — `docs/incident-response-playbook.md` describes what to do if a critical issue is discovered.
  - *Check:* Pause manager can stop all payments within 5 minutes.
  - *Expected:* Runbook is accessible and reviewed by on-call team.

- [ ] **Audit report (if applicable)** — If an external audit has been conducted, link to the final report and remediation status.
  - *Link:* (Update when audit is available)

---

## 11. Mainnet-Specific Checks (🔴 Before Production)

- [ ] **Network configuration validated** — Correct RPC endpoint, network passphrase, and protocol version.
  - *Check:* `stellar network ls` confirms active network.
  - *Test:* Ping RPC endpoint and confirm health.

- [ ] **Admin keys are secure** — Deployment and contract admin keys are stored in hardware wallets or HSM.
  - *Check:* No private key material in env, config files, or shell history.

- [ ] **Treasury is funded** — Treasury account has sufficient XLM for payroll runs.
  - *Action:* Run `stellar account balance --source <TREASURY>` and confirm >= (total_payroll + 1 XLM for fees).

- [ ] **Pause manager is deployed and tested** — Can be called from on-call operator key within 5 minutes of detection of a critical issue.
  - *Test:* Practice pause + unpause on testnet; measure time to execute.

---

## Review Sign-Off

| Role | Name | Signature | Date | Notes |
|------|------|-----------|------|-------|
| Security Lead | | | | |
| Contract Admin | | | | |
| On-Call Operator | | | | |

**All mandatory (🔴) items above must be signed off before proceeding to mainnet deployment.**

---

## Related Resources

- [Preflight Deployment Checklist](docs/ops/preflight-deployment-checklist.md) — Operational readiness.
- [Incident Response Playbook](docs/incident-response-playbook.md) — What to do if something goes wrong.
- [SDK Interface Spec](docs/sdk-interface-spec.md) — Client-facing API and assumptions.
- [Architecture Documentation](docs/architecture/) — System design and threat model.
