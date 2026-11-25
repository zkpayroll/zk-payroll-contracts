//! Adversarial approval invalidation tests (issues #987 and #988).
//!
//! These tests pin the invariants documented in
//! `contracts/payroll/APPROVAL_INVALIDATION_INVARIANTS.md`: a stale protected
//! hash never authorizes a new revision, collected approvals do not carry
//! over after a protected-field change, re-initialization binds the new
//! revision, and stale-approval cleanup stays admin-only.

#![cfg(test)]

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};
use token::Token;

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

struct Ctx {
    env: Env,
    admin: Address,
    payroll_id: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let verifier_id = env.register(ProofVerifier, ());
    let verifier = ProofVerifierClient::new(&env, &verifier_id);
    verifier.init_verifier_admin(&admin);
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register(SalaryCommitmentContract, ());
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register(Token, ());
    let payroll_id = env.register(Payroll, ());
    let payroll = PayrollClient::new(&env, &payroll_id);
    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &Address::generate(&env),
        &Address::generate(&env),
    );

    Ctx {
        env,
        admin,
        payroll_id,
    }
}

fn root(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
#[should_panic(expected = "Stale approval reused: protected fields changed")]
fn test_stale_hash_after_amendment_is_rejected() {
    let ctx = setup();
    let draft_id = 200u64;

    let original = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &original.protected_content_hash);

    ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
    );

    // The old hash must not authorize an approval on the amended revision.
    let attacker = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&attacker, &draft_id, &original.protected_content_hash);
}

#[test]
fn test_approval_does_not_carry_over_after_amendment() {
    let ctx = setup();
    let draft_id = 201u64;

    let original = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &original.protected_content_hash);
    assert_eq!(
        ctx.payroll()
            .get_draft_approval_state(&draft_id)
            .unwrap()
            .current_approvals,
        1
    );

    let amended = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
    );
    assert_eq!(amended.current_approvals, 0);
    assert!(!amended.is_locked);
    assert_eq!(
        ctx.payroll()
            .get_draft_approval_state(&draft_id)
            .unwrap()
            .signers
            .len(),
        0
    );

    // The same signer may approve the new revision, but only with its hash.
    let refreshed =
        ctx.payroll()
            .submit_draft_approval(&signer, &draft_id, &amended.protected_content_hash);
    assert_eq!(refreshed.current_approvals, 1);
}

#[test]
fn test_reinitialize_after_amendment_binds_new_revision() {
    let ctx = setup();
    let draft_id = 202u64;

    let original = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &original.protected_content_hash);

    let amended = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
    );

    let reinitialized = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
        &2u32,
    );
    assert_eq!(
        reinitialized.protected_content_hash,
        amended.protected_content_hash
    );
    assert_eq!(reinitialized.current_approvals, 0);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_non_admin_cannot_cleanup_stale_approval() {
    let ctx = setup();
    let attacker = Address::generate(&ctx.env);

    ctx.payroll()
        .cleanup_stale_approval(&attacker, &1u64, &1u64);
}

// ---------------------------------------------------------------------------
// Issue #876: approvals must bind to the current draft revision.
// ---------------------------------------------------------------------------

/// Sanitized rejection message for an approval that references a superseded
/// draft revision. It must never embed salary, employee or proof material.
const SUPERSEDED_REVISION_ERROR: &str = "Stale approval reused: protected fields changed";

/// Asserts that a panic message is the sanitized superseded-revision error and
/// does not leak any private payroll data.
fn assert_sanitized_superseded_error(msg: &str) {
    assert!(
        msg.contains(SUPERSEDED_REVISION_ERROR),
        "expected sanitized superseded-revision error, got: {msg}"
    );
    let lowered = msg.to_ascii_lowercase();
    for needle in [
        "salary",
        "amount",
        "employee",
        "proof",
        "commitment",
        "10000",
        "12000",
    ] {
        assert!(
            !lowered.contains(needle),
            "error message leaked private payroll data ({needle}): {msg}"
        );
    }
}

#[test]
fn test_approval_against_current_revision_succeeds() {
    let ctx = setup();
    let draft_id = 300u64;

    let draft = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let signer = Address::generate(&ctx.env);
    let state = ctx
        .payroll()
        .submit_draft_approval(&signer, &draft_id, &draft.protected_content_hash);

    assert_eq!(state.current_approvals, 1);
    assert_eq!(state.signers.len(), 1);
    assert_eq!(state.protected_content_hash, draft.protected_content_hash);
}

#[test]
fn test_approval_against_superseded_revision_is_rejected() {
    let ctx = setup();
    let draft_id = 301u64;

    let original = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let amended = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
    );
    assert_ne!(
        original.protected_content_hash,
        amended.protected_content_hash
    );

    let attacker = Address::generate(&ctx.env);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.payroll()
            .submit_draft_approval(&attacker, &draft_id, &original.protected_content_hash);
    }));

    let err = result.expect_err("superseded revision approval must be rejected");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert_sanitized_superseded_error(&msg);

    // The rejected attempt must not have mutated approval state.
    let state = ctx.payroll().get_draft_approval_state(&draft_id).unwrap();
    assert_eq!(state.current_approvals, 0);
    assert_eq!(state.signers.len(), 0);
    assert_eq!(state.protected_content_hash, amended.protected_content_hash);
}

#[test]
fn test_approval_boundary_revision_matches_after_update() {
    let ctx = setup();
    let draft_id = 302u64;

    let original = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &root(&ctx.env, 0x11),
        &root(&ctx.env, 0x22),
        &2u32,
    );
    let amended = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &12_000i128,
        &3u32,
        &root(&ctx.env, 0x33),
        &root(&ctx.env, 0x44),
    );

    // Boundary: the hash of the current revision is accepted even though the
    // draft was amended, while the immediately preceding revision is not.
    let signer = Address::generate(&ctx.env);
    let state =
        ctx.payroll()
            .submit_draft_approval(&signer, &draft_id, &amended.protected_content_hash);
    assert_eq!(state.current_approvals, 1);
    assert_eq!(state.protected_content_hash, amended.protected_content_hash);

    let stale = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx.payroll()
            .submit_draft_approval(&signer, &draft_id, &original.protected_content_hash);
    }));
    let err = stale.expect_err("previous revision must stay rejected");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert_sanitized_superseded_error(&msg);

    // Approval count is unchanged by the rejected stale attempt.
    assert_eq!(
        ctx.payroll()
            .get_draft_approval_state(&draft_id)
            .unwrap()
            .current_approvals,
        1
    );
}
