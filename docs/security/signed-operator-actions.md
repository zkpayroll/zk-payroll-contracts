# Signed, Expiring Operator Authorizations (Issue #519)

## Summary

Prior to this feature, no off-chain signature verification scheme existed
anywhere in this contract suite — every privileged action was gated purely
by `Address::require_auth()` against a stored admin/reviewer/operator
address. This module adds a **separate, opt-in** path: the admin registers
an ed25519 "operator key" once, and can then authorize specific privileged
actions off-chain by signing a payload that MUST carry an expiration ledger,
submitted on-chain later by anyone — the operator key's signature IS the
authorization; the submitter needs no role of their own.

This is useful for an operator workflow where the signing key is
offline/air-gapped from the infrastructure that submits transactions.

**Core rule: a signed operator authorization never authorizes anything past
its expiration ledger, and can never be replayed once consumed.**

`require_auth()`-gated entrypoints (`add_reviewer` itself, etc.) are
**unchanged** by this feature — it is an additional, parallel authorization
mechanism, not a replacement.

## Scope of this reference implementation

Issue #519 asks for the *mechanism* ("require privileged off-chain
authorizations to include and enforce an expiration time"), not a survey of
every privileged action in this contract suite. This implementation
introduces the full signing/verification/expiry/replay-protection plumbing
and applies it to exactly one action — granting reviewer authorization
(`signed_add_reviewer`, an alternative path to `add_reviewer`) — as the
reference wiring. Extending `SignedOperatorAction` with additional variants
to cover other privileged actions is straightforward future work; the
signing, expiry, and replay-protection plumbing (`require_not_expired`,
`consumed_key`, `MAX_AUTHORIZATION_TTL_LEDGERS`) is written to be reused as-is.

## Contract surface

All of the following live in `contracts/payroll/src/lib.rs` and
`contracts/payroll/src/signed_operator_actions.rs`.

| Function | Purpose |
| --- | --- |
| `register_operator_key(admin, operator_key)` | Admin-only. Registers (or replaces) the ed25519 public key that signs operator authorizations. At most one key at a time. |
| `revoke_operator_key(admin)` | Admin-only. Removes the registered key; `signed_add_reviewer` becomes unusable until a new key is registered. |
| `get_operator_key()` | Returns the currently registered public key, if any. |
| `signed_add_reviewer(reviewer, payload, signature)` | Callable by anyone holding a validly signed `payload`. Grants reviewer authorization to `reviewer` exactly like `add_reviewer`, including the `MaxReviewers` cap (issue #539). |

## The signed payload

```rust
pub struct SignedOperatorPayload {
    pub action: SignedOperatorAction,   // e.g. AddReviewer(reviewer_address)
    pub expires_at_ledger: u32,         // mandatory — no unexpiring variant exists
    pub nonce: BytesN<32>,              // caller-chosen, lets the SAME action be re-signed later
}
```

The message an operator key signs is the raw XDR encoding
(`payload.clone().to_xdr(env)`) of this struct. Replay protection separately
hashes that same encoding with SHA-256 to derive the consumed-authorization
storage key — the same XDR-then-hash convention `config_audit::value_ref`
already uses elsewhere in this crate for audit-event references, reused here
for consistency rather than inventing a second encoding scheme.

## Expiry and replay rules

1. **Expiry is mandatory and enforced on every call.**
   `expires_at_ledger` must be strictly greater than the current ledger
   sequence at verification time, or the call panics with error code
   `ReplayError::AuthorizationExpired` (605) — a code already reserved in
   `shared_errors` but never wired to a producer before this feature.
2. **TTL is capped**, mirroring `proof_verifier::MAX_REFERENCE_TTL_LEDGERS`:
   `MAX_AUTHORIZATION_TTL_LEDGERS` = 518,400 ledgers (~30 days at 5s ledgers).
   A payload whose lifetime at verification time exceeds this cap is
   rejected, preventing an operator mistake (or a compromised signing key)
   from producing an effectively eternal authorization.
3. **Signature verification** uses `env.crypto().ed25519_verify` against the
   currently registered operator key. Revoking or replacing the key
   immediately invalidates the ability to submit NEW authorizations signed
   by the old key (already-consumed ones remain consumed either way).
4. **Replay protection**: each payload's hashed XDR encoding is recorded as
   consumed (`DataKey::ConsumedOperatorAuth`) the first time it is
   successfully used. Submitting the identical payload + signature again is
   rejected — the same category of protection `RunNonce` and
   `DraftCommitment` give elsewhere in this contract against replaying a
   prior authorization.
5. **Action binding**: `payload.action` must match the entrypoint's own
   arguments (e.g. `signed_add_reviewer`'s `reviewer` parameter must equal
   the `AddReviewer` payload's wrapped address) — a payload signed to
   authorize one target can never be submitted against a different one.

## What this does NOT change

- `add_reviewer` (the existing `require_auth()`-gated path) is untouched and
  remains the primary way an admin grants reviewer authorization directly.
- No existing entrypoint's authorization model changed. This is additive.
- The `MaxReviewers` cap (issue #539) applies identically to both paths —
  `signed_add_reviewer` calls the same internal `grant_reviewer_internal`
  helper `add_reviewer` does.

## Verification & testing coverage

Covered in `contracts/payroll/tests/signed_operator_actions.rs`:
- A validly signed, unexpired authorization grants reviewer access.
- An authorization at or past its own `expires_at_ledger` is rejected.
- An authorization whose requested lifetime exceeds the TTL cap is rejected.
- A signature from a key other than the registered operator key is rejected.
- Replaying the identical payload + signature a second time is rejected.
- A payload whose `action` does not match the call's own arguments is
  rejected.
- Calling with no operator key registered is rejected.
- Calling after the operator key has been revoked is rejected.
- The `MaxReviewers` cap (#539) is enforced identically through this path.
