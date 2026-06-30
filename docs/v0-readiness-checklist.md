# v0 Readiness Checklist

This document tracks the minimum requirements, blockers, and optional improvements needed before the `v0` release of the ZK Payroll Contracts can be considered ready. It serves as a coordination hub for contributors.

## 🛑 Blockers (Must Have for v0)

### 1. Security
- [ ] **Internal Security Audit**: Complete internal review of the Groth16 verification logic. (Issue #XX)
- [ ] **Payment Security**: Resolve all critical/high findings and ensure payment security tests pass. (See related PRs/Issues like #41)
- [ ] **Poseidon Parameters**: Verify that the salary commitment hashes are using the correct Protocol 25 Poseidon parameters. (Issue #XX)

### 2. Testing
- [ ] **Verifier Coverage**: Achieve 100% unit test coverage for the `proof_verifier` contract. (Issue #XX)
- [ ] **E2E Integration**: Implement end-to-end testing for the `payment_executor` simulating a full payroll run. (Issue #XX)
- [ ] **Security Acceptance Criteria**: Finalize and pass all tests defined in the security acceptance criteria suite. (Issue #XX)

### 3. Documentation
- [ ] **API Documentation**: Ensure all public interfaces across the 5 core contracts have proper Rustdocs. (Issue #XX)
- [ ] **Deployment Guide**: Write a step-by-step testnet deployment guide for the WASM contracts. (Issue #XX)
- [ ] **Audit Module Guide**: Document the view key generation and selective disclosure workflow. (Issue #XX)

### 4. Deployment
- [ ] **Reproducible Builds**: Set up a CI pipeline that guarantees reproducible WASM builds. (Issue #XX)
- [ ] **Testnet Release**: Deploy the `v0.1.0-rc.1` candidate to the Stellar Testnet. (Issue #XX)

---

## 🚧 Optional Improvements (Nice-to-Have / Post-v0)

- [ ] **Batch Payment Optimization**: Implement bulk salary commitment processing to reduce gas. (See `feat/salary-commitment-batch`)
- [ ] **Multi-currency Support**: Allow payroll in different Stellar assets (e.g., USDC, XLM). (Issue #XX)
- [ ] **Indexer Reconciliation**: Support off-chain indexer state reconciliation. (Issue #11)
