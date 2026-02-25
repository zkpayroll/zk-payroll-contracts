## Summary

<!-- Provide a concise description of what this PR does and why.
     Link the related issue(s) below. -->

Closes #<!-- issue number -->

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behaviour)
- [ ] ZK circuit change (requires new trusted setup / ptau ceremony)
- [ ] Refactor (no functional changes)
- [ ] Documentation / comments only
- [ ] CI/CD or tooling change

## Description of Changes

<!-- List the key changes made in this PR. For contract changes, describe
     the affected entry-points and storage slots. For circuit changes,
     describe which signals / constraints were modified. -->

-
-
-

---

## Checklist

### General

- [ ] My code follows the project's Rust style guidelines (`cargo fmt --check` passes)
- [ ] I have performed a self-review of my own code
- [ ] I have added comments for any non-obvious logic
- [ ] I have updated relevant documentation (`README.md`, `CONTRIBUTING.md`, inline docs)
- [ ] My changes do not introduce new compiler warnings (`cargo clippy` passes)
- [ ] I have added tests that cover my changes
- [ ] All existing tests pass locally (`cargo test`)

### Smart Contracts (if applicable)

- [ ] I have measured and documented gas / resource usage for new or changed entry-points
  - CPU instructions (before / after):
  - Memory bytes (before / after):
  - Ledger entries read/written (before / after):
  - Estimated XLM fee (before / after):
- [ ] I have verified there are no storage layout regressions (state rent impact assessed)
- [ ] I have checked for integer overflow / underflow and used checked arithmetic
- [ ] Authorization checks (`require_auth`, `require_auth_for_args`) are correct and tested
- [ ] No sensitive data (salaries, blinding factors, private keys) is emitted in events or exposed in storage

### ZK Circuits (if applicable)

- [ ] Circuit compiles without errors: `circom <circuit>.circom --r1cs --wasm --sym`
- [ ] Witness generation succeeds for test inputs
- [ ] Proof generation and verification pass end-to-end
- [ ] New trusted setup (phase 2 ptau) is required: **Yes / No**
  - If yes, link to the ceremony artifacts:
- [ ] Constraint count change documented:
  - Before: <!-- n constraints -->
  - After:  <!-- n constraints -->
- [ ] Verifier Solidity/Rust contract regenerated (if verifying key changed)

### Security

- [ ] I have considered potential attack vectors relevant to this change
  - [ ] Re-entrancy (not applicable on Soroban, but noted for audit completeness)
  - [ ] Front-running / MEV risks
  - [ ] Proof malleability (for ZK changes)
  - [ ] Commitment binding / hiding properties preserved (for commitment changes)
- [ ] No hardcoded secrets, keys, or sensitive configuration values in code
- [ ] Dependencies added/updated have been reviewed for known vulnerabilities (`cargo audit`)

---

## Testing Evidence

<!-- Paste relevant test output or describe manual testing steps performed. -->

```
cargo test output:
```

## Additional Notes

<!-- Any other context reviewers should know: deployment steps, migration
     scripts, known limitations, follow-up issues, etc. -->
