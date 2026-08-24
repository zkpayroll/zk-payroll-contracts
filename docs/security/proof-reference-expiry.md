# Proof Reference Expiry (Issue #251)

## Summary

Proof references are on-chain records in the `proof_verifier` contract that
bind a specific Groth16 proof to an explicit expiration. They exist so that
expiry-sensitive consumers — payroll execution paths and audit access
workflows — can gate authorization on a reference instead of treating every
submitted proof as eternally valid.

**Core rule: an expired, revoked, or missing proof reference never authorizes
a payroll action or audit action.**

## Contract surface

All of the following live in `contracts/proof_verifier/src/lib.rs`.

| Function | Purpose |
| --- | --- |
| `register_proof_reference(admin, ref_id, proof, expires_at_ledger)` | Admin-only. Registers `ref_id` for the exact `proof` bytes (SHA-256 digest is computed on-chain) with an explicit expiry ledger. |
| `revoke_proof_reference(admin, ref_id)` | Admin-only. Permanently revokes before or after expiry; revocation is irreversible. |
| `get_proof_reference(ref_id)` | Returns the stored record (`proof_hash`, `registered_at_ledger`, `expires_at_ledger`, `revoked`). |
| `is_proof_reference_valid(ref_id)` | Read-only check used by tooling: registered ∧ not revoked ∧ not expired. |
| `verify_with_reference(ref_id, proof, public_inputs)` | Enforcement point: verifies the proof **only through** its reference. Missing / expired / revoked / mismatched proofs return `false` instead of authorizing. |

## Expiry rules

1. **Registration validation**
   - `expires_at_ledger` must be strictly greater than the current ledger
     sequence (`ProofError::InvalidExpiry` otherwise). References cannot be
     created already expired.
   - Time-to-live is capped at `MAX_REFERENCE_TTL_LEDGERS` = 518,400 ledgers
     (~30 days at 5 s ledgers). Anything longer fails with
     `ProofError::ExpiryBeyondCap`, preventing operator mistakes from minting
     effectively eternal proofs.
   - Each `ref_id` can only be registered once
     (`ProofError::ReferenceAlreadyExists`).
   - Only the verifier admin may register or revoke.

2. **Validity boundary** (matches the `audit_module` view-key convention)
   - A reference is usable while `ledger.sequence() <= expires_at_ledger`.
   - From `expires_at_ledger + 1` onward it is expired
     (`ProofError::ReferenceExpired`) and `verify_with_reference` returns
     `false`.

3. **Revocation**
   - `revoke_proof_reference` flips `revoked` permanently. Revoked references
     fail validity immediately regardless of expiry
     (`ProofError::ReferenceRevoked`).

4. **Binding to proof material**
   - Registration stores `sha256(proof)`. `verify_with_reference` recomputes
     the digest at verification time and rejects any other proof bytes
     (`ProofError::ProofMismatch` path → `false`), so a valid reference can
     never be replayed against different proof material.

5. **Missing references**
   - Verification through an unregistered `ref_id` returns `false`
     (`ProofError::ReferenceNotFound` from getters). Silence is treated as
     "not authorized".

## Failure semantics

`verify_with_reference` deliberately returns `false` rather than panicking:
cross-contract callers (payroll batches, audit tooling) should treat any
`false` as "this proof does not authorize the action" and skip/reject the
record. This keeps expiry failures uniform with cryptographic verification
failures.

Existing direct verification (`verify_payment_proof`, `verify`) is unchanged;
references are opt-in for consumers that need expiry guarantees.

## Test coverage

See `contracts/proof_verifier/src/expiry_tests.rs`:

- Valid reference authorizes verification.
- Missing, expired, and revoked references are rejected.
- Boundary timing: usable at `expires_at_ledger - 1` **and** at
  `expires_at_ledger`; rejected from `expires_at_ledger + 1` onward.
- Registration rejects past/present expiry, TTL beyond cap, duplicate ids,
  and non-admin callers.
- A reference does not authorize different proof bytes.
- Direct verification without references continues to work.
