# Incident Response Playbook: Audit Failures & Disclosure Mistakes

This playbook defines how the team responds when audit workflows fail or when compliance-sensitive information is handled incorrectly. The goal is fast, coordinated containment — not post-mortem blame.

---

## Incident Categories

| ID | Category | Example |
|----|----------|---------|
| IR-1 | Audit module malfunction | `audit_module` fails to generate or validate a view key |
| IR-2 | Nullifier bypass or replay | A payment proof is accepted more than once |
| IR-3 | Commitment disclosure leak | A salary amount or blinding factor is exposed on-chain or in logs |
| IR-4 | Disclosure workflow error | A view key is issued to the wrong auditor or with the wrong scope |
| IR-5 | Trusted setup compromise | A zkey or ptau artifact is found to be tainted or leaked |
| IR-6 | Unauthorized state mutation | A state-mutating entry-point is called without proper auth |
| IR-7 | Circuit constraint failure | A proof is verified on-chain despite invalid inputs |

---

## Roles

| Role | Responsibility |
|------|----------------|
| **Incident Lead** | Coordinates response, owns the timeline, communicates externally |
| **Contract Owner** | Investigates on-chain state; has authority to trigger `pause_manager` |
| **ZK Engineer** | Reviews circuit constraints, proof parameters, and zkey integrity |
| **Comms Lead** | Drafts disclosures to auditors, affected employers, and the Stellar community |

For small teams, one person can hold multiple roles. The Incident Lead role must always be filled first.

---

## IR-1: Audit Module Malfunction

**Indicators:**
- View key generation returns an error or produces an invalid key.
- `audit_module.verify_with_view_key` rejects a legitimately issued key.
- CI tests in `contracts/audit_module/src/tests.rs` start failing unexpectedly.

**Immediate containment:**
1. Pause new view key issuance via `pause_manager` if the malfunction risks exposing unintended data.
2. Do not attempt on-chain state fixes until the root cause is identified.
3. Capture the failed transaction hash and XDR for reproduction.

**Investigation:**
- Review `contracts/audit_module/src/lib.rs` for recent changes.
- Reproduce the failure in a local test: `cargo test -p audit_module`.
- Check that view key scope parameters (time range, company ID) are being serialized/deserialized correctly.

**Resolution:**
- Deploy a patched contract version after internal review.
- Reissue any view keys that were generated during the malfunction window.
- Document the root cause in a follow-up issue.

---

## IR-2: Nullifier Bypass or Replay

**Indicators:**
- The same proof is accepted by `payment_executor` more than once.
- Duplicate payment events appear on-chain for the same nullifier hash.
- Fuzz targets in `fuzz/fuzz_targets/fuzz_proof_validation.rs` surface a replay path.

**Immediate containment:**
1. **Pause the contract immediately** using `pause_manager`. This is a critical financial integrity issue.
2. Record affected company IDs, employee addresses, and transaction hashes.
3. Do not restore operations until a fix is verified on testnet.

**Investigation:**
- Verify nullifier storage logic in `contracts/payment_executor/src/lib.rs`.
- Confirm that the nullifier key is written to persistent storage *before* the payment is executed.
- Check `contracts/payment_executor/tests/security_tests.rs` for replay test coverage gaps.
- Review the `DataKey::Nullifier` path in storage — confirm it uses `Persistent` storage, not `Temporary`.

**Resolution:**
- Fix the nullifier write ordering or storage type.
- Add or extend replay tests in `security_tests.rs`.
- After testnet verification, redeploy and unpause.
- Notify affected parties of any duplicate payments and initiate remediation.

---

## IR-3: Commitment Disclosure Leak

**Indicators:**
- A salary amount or blinding factor appears in transaction metadata, logs, or a public repository.
- An employee reports their private salary data was visible.
- A CI log or test fixture contains real salary values.

**Immediate containment:**
1. If the leak is in a git commit or CI log: rotate the exposed blinding factor immediately and issue a new commitment for the affected employee.
2. If the leak is in a public repository: use GitHub's secret scanning / commit history tools to redact if possible, then treat the data as permanently exposed and rotate.
3. Do not log salary values or blinding factors in any diagnostic output.

**Investigation:**
- Identify the source: contract event emission, CLI debug output (`cli/src/`), or test fixtures.
- Search the codebase for accidental logging:
  ```bash
  # Look for debug prints that may include sensitive values
  grep -r "println!\|dbg!\|log::" contracts/ cli/
  ```

**Resolution:**
- Remove or redact the disclosure source.
- Update all affected commitments on-chain.
- Notify the affected employer and employee per applicable privacy obligations.
- Document in a post-incident review.

---

## IR-4: Disclosure Workflow Error

**Indicators:**
- A view key was issued to the wrong auditor address.
- A view key covers a broader time range or company scope than intended.
- An auditor reports access to records they should not have.

**Immediate containment:**
1. Revoke the incorrectly scoped view key if revocation is supported; otherwise, treat it as expired and document the exposure window.
2. Contact the unintended recipient immediately to request non-use of the key.

**Investigation:**
- Review the parameters passed to `audit_module.generate_view_key` in the originating transaction.
- Check whether the CLI command in `cli/src/` correctly mapped user input to contract arguments.

**Resolution:**
- Reissue a correctly scoped view key to the intended auditor.
- If the incorrect key was used to access data, document the scope of exposure.
- Add a validation test that checks view key scope boundaries.

---

## IR-5: Trusted Setup Compromise

**Indicators:**
- A zkey or ptau artifact is found in a public location it was not intended for.
- A contributor reports that a private contribution secret was exposed.
- The `payment_final.zkey` hash does not match the published checksum.

**Immediate containment:**
1. **Pause the `proof_verifier` contract.** All proofs generated with the compromised zkey must be treated as untrustworthy.
2. Do not accept any new proof submissions until a fresh trusted setup is complete.

**Investigation:**
- Verify the `payment_final.zkey` against its published B2 checksum.
- Review git history and CI logs to determine if the artifact was exposed in a build artifact or log.

**Resolution:**
- Run a new Phase 2 trusted setup following the [ZK Trusted Setup](../CONTRIBUTING.md#zk-trusted-setup-ptau) procedure.
- Regenerate `verification_key.json` and redeploy `proof_verifier`.
- Invalidate all proofs generated under the compromised setup; require re-submission.
- Publish a transparency notice if the project is in public use.

---

## IR-6: Unauthorized State Mutation

**Indicators:**
- A state-mutating entry-point (e.g., `add_employee`, `update_commitment`) is invoked by an unexpected address.
- `env.require_auth()` was missing or bypassed in a deployed contract version.
- Security tests in `contracts/payment_executor/tests/security_tests.rs` flag an auth gap.

**Immediate containment:**
1. Pause the affected contract.
2. Record all unauthorized transactions and the addresses involved.

**Investigation:**
- Audit the affected entry-point for correct `env.require_auth()` placement.
- Check that the authorized address is validated against a stored admin/company key, not just checked for transaction signing.

**Resolution:**
- Deploy a corrected contract with the auth check in place.
- Review all entry-points across all contracts for similar gaps before unpausing.
- Add or extend auth tests in the relevant test modules.

---

## IR-7: Circuit Constraint Failure

**Indicators:**
- An on-chain proof is accepted despite being generated with inputs that should have been rejected.
- A new circuit change introduced a constraint regression.
- Fuzzing surfaces an accepting proof for out-of-range values.

**Immediate containment:**
1. Pause `proof_verifier` and `payment_executor`.
2. Do not accept any new proof submissions.

**Investigation:**
- Reproduce the invalid proof acceptance locally using `snarkjs groth16 verify`.
- Review recent changes to `circuits/payment.circom` and `circuits/range_proof.circom`.
- Run `snarkjs r1cs info` to inspect the constraint count before and after the change.

**Resolution:**
- Fix the circuit constraint gap and run a new trusted setup (Phase 2).
- Redeploy `proof_verifier` with the updated verification key.
- All proofs submitted between the regression and the fix must be re-evaluated.

---

## Communication Templates

### Internal alert (Slack / Discord)
```
[INCIDENT] <IR-X> declared — <one-line description>
Lead: <name>
Status: Investigating / Contained / Resolved
Next update: <time>
Affected: <contract names / company IDs>
```

### External disclosure (for public incidents)
```
We identified an issue affecting <contract/workflow> on <date>.
Scope: <what was affected and what was not>
Immediate action taken: <pause / rotation / etc.>
User impact: <what affected users should do>
Resolution: <current status>
We will share a full post-incident report at <link/date>.
```

---

## Post-Incident Review

For any IR-2, IR-3, IR-5, or IR-7 incident, a written post-incident review is required within 7 days of resolution. The review should cover:

1. Timeline of detection, containment, and resolution
2. Root cause
3. Affected scope (contracts, companies, employees)
4. Corrective action taken
5. Preventive measures added (tests, checks, process changes)

Store reviews in `docs/post-incident/` using the filename format `YYYY-MM-DD-IR-<category>-<short-slug>.md`.

---

## Related Issues and Systems

| Reference | Link |
|-----------|------|
| Audit module tests | `contracts/audit_module/src/tests.rs` |
| Payment security tests | `contracts/payment_executor/tests/security_tests.rs` |
| Pause manager | `contracts/pause_manager/src/lib.rs` |
| Proof verifier tests | `contracts/proof_verifier/src/tests.rs` |
| Fuzz targets | `fuzz/fuzz_targets/fuzz_proof_validation.rs` |
| ZK trusted setup procedure | [CONTRIBUTING.md — ZK Trusted Setup](../CONTRIBUTING.md#zk-trusted-setup-ptau) |
| v0 readiness checklist | [docs/v0-readiness-checklist.md](./v0-readiness-checklist.md) |
| Soroban build troubleshooting | [docs/troubleshooting-soroban-build.md](./troubleshooting-soroban-build.md) |

---

*Last updated: Issue [#116](https://github.com/zkpayroll/zk-payroll-contracts/issues/116)*
