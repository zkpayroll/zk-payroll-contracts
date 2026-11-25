# Proof Input Validation Invariants

This document formalizes the invariants enforced by the proof verifier module to ensure correctness, operational clarity, and privacy preservation.

## Invariant #1: Public Input Count Must Match Verification Key

**Rule:** `public_inputs.len() + 1 == vk.ic.len()`

- Public inputs must exactly match the size expected by the active verification key
- Violations return `false` (format rejection, not cryptographic failure)
- Prevents out-of-bounds access and misaligned verification

**Enforced in:**
- `verify()` / `verify_payment_proof()`: input length validation
- `verify_with_reference()`: input length validated before proof check

**Test coverage:**
- `invariant_input_count_match_success()` — accepts correct counts
- `invariant_input_count_match_boundary_zero()` — edge case: zero inputs with ic.len() == 1
- `invariant_input_count_mismatch_returns_false()` — mismatch returns false, not panic
- `test_validator_reports_input_count_mismatch()` — validator returns the exact safe error code
- `test_verify_with_empty_verification_key_is_rejected()` — an empty IC vector rejects every input count

**Typed enforcement:** `validate_proof_inputs()` returns `ProofError::InvalidPublicInputCount` for this violation and `ProofError::VerifierNotInitialized` when no key is registered. Both codes are stable integers. The `verify*` entry points call the same validation path and return `false` on rejection, so no private data is exposed through either surface.

---

## Invariant #2: Proof Digest Binding (Reference Mode Only)

**Rule:** `sha256(proof) == reference.proof_hash`

- A reference authorizes only the exact proof material it was registered with
- Violations return `false` (silent rejection)
- Prevents replay attacks and proof tampering

**Enforced in:**
- `register_proof_reference()`: proof digest computed at registration
- `verify_with_reference()`: digest verified before verification proceeds

**Test coverage:**
- `invariant_proof_digest_binding_exact_match()` — same proof accepts
- `invariant_proof_digest_binding_rejects_mutation()` — different proof rejects
- `invariant_proof_digest_binding_single_byte_tamper()` — single-byte change caught

---

## Invariant #3: Reference Expiry Window

**Rule:** Reference remains valid through `expires_at_ledger` (inclusive); expired from `expires_at_ledger + 1` onward

- Boundary: `ledger.sequence() <= reference.expires_at_ledger` for validity
- Enforces mandatory lifetime cap: `MAX_REFERENCE_TTL_LEDGERS` (~30 days)
- Prevents indefinite authorization of proof material

**Enforced in:**
- `register_proof_reference()`: TTL checked against MAX_REFERENCE_TTL_LEDGERS
- `reference_is_current()`: expiry checked on every verification

**Test coverage:**
- `invariant_expiry_window_valid_at_registration()` — valid immediately after registration
- `invariant_expiry_window_valid_at_exact_ledger()` — valid AT expires_at ledger
- `invariant_expiry_window_invalid_after_ledger()` — invalid from expires_at + 1

---

## Invariant #4: Reference Revocation

**Rule:** `reference.revoked == false` required for any authorization

- Revocation is permanent and immediate
- Overrides expiry: revoked references never authorize, even if not yet expired
- Enables cancellation of compromised or mistaken authorizations

**Enforced in:**
- `revoke_proof_reference()`: sets revoked flag
- `reference_is_current()`: checks revoked before expiry

**Test coverage:**
- `invariant_revocation_before_expiry()` — revocation invalidates valid reference
- `invariant_revocation_is_permanent()` — revoked stays rejected even past expiry

---

## Invariant #5: No Private Data Exposure

**Rule:** Error messages and rejection codes must not leak employee identities, salary amounts, or proof material

- All rejections return `false` or generic error codes (e.g., `ReferenceExpired`, `ProofMismatch`)
- No diagnostic details in contract errors
- Operators correlate events internally via audit logs; public signals remain opaque

**Enforced in:**
- All public entry points: rejections return `false` or named error enum variants
- No proof bytes, digests, or input data serialized in errors

**Test coverage:**
- `invariant_error_messages_do_not_leak_proof_bytes()` — proof mismatch returns false silently
- `invariant_expired_reference_error_generic()` — expiry returns false, not panic with details

---

## Summary Table

| Invariant | Trigger | Result | Rationale |
|-----------|---------|--------|-----------|
| #1: Input count match | Mismatch between public inputs and vk.ic | Return `false` | Groth16 positional alignment |
| #2: Proof digest binding | Proof bytes differ from reference digest | Return `false` | Replay/mutation prevention |
| #3: Expiry window | Ledger sequence > expires_at_ledger | Return `false` | Lifetime cap enforcement |
| #4: Revocation | reference.revoked == true | Return `false` | Immediate authorization revocation |
| #5: Privacy preservation | Any rejection | Generic error code or false | Payroll data confidentiality |

---

## Implementation Status

All five invariants are:
1. **Documented** in module docstring (`lib.rs`)
2. **Implemented** in contract code with enforcement checks
3. **Tested** with focused success, failure, and boundary tests in `tests.rs` and `expiry_tests.rs`

Structural checks are also available through `validate_proof_inputs()`, which reports `VerifierNotInitialized` (11) and `InvalidPublicInputCount` (10) without exposing any proof or payroll data.

### Test Breakdown
- **Invariant #1 (Input Count):** 5 tests
- **Invariant #2 (Proof Digest):** 3 tests
- **Invariant #3 (Expiry):** 3 tests
- **Invariant #4 (Revocation):** 2 tests
- **Invariant #5 (Privacy):** 2 tests
- **Total invariant-focused tests:** 15 new tests + existing 30+ tests in `tests.rs` and `expiry_tests.rs`

All tests follow the naming convention `invariant_<invariant_name>_<scenario>()` for clarity and traceability.
