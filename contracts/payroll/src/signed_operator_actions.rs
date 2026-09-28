//! Signed, expiring operator authorizations (issue #519).
//!
//! No off-chain signature verification scheme exists anywhere in this
//! contract suite prior to this module — every privileged action is gated
//! purely by `Address::require_auth()` against a stored admin/reviewer
//! address. This module adds a SEPARATE, opt-in path: the admin registers an
//! ed25519 "operator key" once (`register_operator_key`), and can then
//! authorize specific privileged actions off-chain by signing a payload that
//! MUST carry an expiration ledger, submitted on-chain later by anyone
//! (the operator key's signature is the authorization; the submitter does
//! not need to be the admin or hold any role). This is useful for an
//! operator workflow where the signing key is offline/air-gapped from the
//! submitting infrastructure.
//!
//! `require_auth()`-gated entrypoints (`add_reviewer` itself, etc.) are
//! UNCHANGED — this is an additional, parallel authorization mechanism, not
//! a replacement.
//!
//! Follows the ledger-based expiry pattern already established by
//! `proof_verifier::ProofReference` (`expires_at_ledger`, capped by
//! `MAX_AUTHORIZATION_TTL_LEDGERS`) and reports failure via the
//! already-reserved-but-previously-unwired
//! `shared_errors::ReplayError::AuthorizationExpired` code.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env};

use shared_errors::ReplayError;

/// Upper bound on how far in the future a signed action's expiration may be
/// set, mirroring `proof_verifier::MAX_REFERENCE_TTL_LEDGERS` (~30 days of
/// ledgers at 5s each). Prevents an operator mistake (or a compromised
/// signing key) from producing an effectively eternal authorization.
pub const MAX_AUTHORIZATION_TTL_LEDGERS: u32 = 518_400;

/// The specific privileged action a signed operator authorization grants.
/// Deliberately narrow at introduction (issue #519's reference
/// implementation covers `add_reviewer`); extend this enum, not the
/// signing/verification plumbing, when a second action needs this path.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedOperatorAction {
    /// Authorizes `add_reviewer(reviewer)` — the wrapped `Address` is the
    /// reviewer being granted authorization.
    AddReviewer(Address),
}

/// The payload an operator key signs off-chain. XDR-encoded and SHA-256'd
/// to produce the ed25519 message, exactly the way `config_audit::value_ref`
/// hashes a value for the audit-event reference scheme (same crate
/// convention, different use).
#[contracttype]
#[derive(Clone, Debug)]
pub struct SignedOperatorPayload {
    pub action: SignedOperatorAction,
    /// First ledger sequence at which this authorization is no longer
    /// usable. Mandatory: there is no unexpiring variant of this action.
    pub expires_at_ledger: u32,
    /// Caller-chosen nonce so the SAME action (e.g. re-adding the same
    /// reviewer later) can be signed and submitted again without colliding
    /// with a prior, already-consumed authorization for identical content.
    pub nonce: BytesN<32>,
}

pub(crate) fn signed_payload_message(e: &Env, payload: &SignedOperatorPayload) -> Bytes {
    payload.clone().to_xdr(e)
}

pub(crate) fn consumed_key(e: &Env, payload: &SignedOperatorPayload) -> BytesN<32> {
    e.crypto()
        .sha256(&signed_payload_message(e, payload))
        .into()
}

/// Validate a signed operator payload's expiry and TTL cap. Returns the
/// message bytes to verify the signature against on success.
///
/// # Panics
/// - `expires_at_ledger` is already at or before the current ledger
///   (`ReplayError::AuthorizationExpired`).
/// - The requested lifetime exceeds `MAX_AUTHORIZATION_TTL_LEDGERS`.
pub(crate) fn require_not_expired(e: &Env, payload: &SignedOperatorPayload) -> Bytes {
    let current = e.ledger().sequence();
    if payload.expires_at_ledger <= current {
        panic!(
            "Signed operator action expired (error code {})",
            ReplayError::AuthorizationExpired as u32
        );
    }
    if payload.expires_at_ledger - current > MAX_AUTHORIZATION_TTL_LEDGERS {
        panic!("Signed operator action expiry exceeds the maximum allowed lifetime");
    }
    signed_payload_message(e, payload)
}
