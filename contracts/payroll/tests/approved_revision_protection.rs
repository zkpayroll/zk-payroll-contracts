//! Approved payroll revision protection tests (#616).
//!
//! A draft revision's multi-stage approval tracker is bound to the revision's
//! protected content hash. These tests cover the core paths:
//!
//! | Test | Scenario |
//! |------|----------|
//! | `test_approvals_lock_the_protected_revision` | Sequential approvals advance the stage and lock at the threshold |
//! | `test_unchanged_revision_keeps_approvals` | A revision with identical protected fields preserves approvals |
//! | `test_revision_change_invalidates_old_approval_hash` | A changed revision rolls back approvals and rejects the stale hash |
//! | `test_init_rejects_zero_required_approvals` | Invalid config is rejected |
//! | `test_submit_without_tracker_rejected` | Approving an unknown draft is rejected |
//! | `test_non_admin_cannot_init_or_amend` | Only the admin may initialise or revise a tracker |

use payroll::{Payroll, PayrollClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

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
    let payroll_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(&env, &payroll_id);
    client.initialize(
        &admin,
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
        &Address::generate(&env),
    );

    Ctx {
        env,
        admin,
        payroll_id,
    }
}

fn digest(ctx: &Ctx, byte: u8) -> BytesN<32> {
    BytesN::from_array(&ctx.env, &[byte; 32])
}

// ── Success ──────────────────────────────────────────────────────────────────

#[test]
fn test_approvals_lock_the_protected_revision() {
    let ctx = setup();
    let draft_id = 1u64;

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &50_000i128,
        &10u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
        &2u32,
    );
    assert_eq!(approval.current_approvals, 0);
    assert_eq!(approval.current_stage, 0);
    assert!(!approval.is_locked);

    let hash = approval.protected_content_hash;

    let signer1 = Address::generate(&ctx.env);
    let stage1 = ctx
        .payroll()
        .submit_draft_approval(&signer1, &draft_id, &hash);
    assert_eq!(stage1.current_approvals, 1);
    assert_eq!(stage1.current_stage, 1);
    assert!(!stage1.is_locked);

    let signer2 = Address::generate(&ctx.env);
    let stage2 = ctx
        .payroll()
        .submit_draft_approval(&signer2, &draft_id, &hash);
    assert_eq!(stage2.current_approvals, 2);
    assert_eq!(stage2.current_stage, 2);
    assert!(stage2.is_locked);

    // The locked revision is what is persisted.
    let persisted = ctx.payroll().get_draft_approval_state(&draft_id).unwrap();
    assert!(persisted.is_locked);
    assert_eq!(persisted.protected_content_hash, hash);
}

// ── Edge cases ───────────────────────────────────────────────────────────────

#[test]
fn test_unchanged_revision_keeps_approvals() {
    let ctx = setup();
    let draft_id = 2u64;
    let obligation_root = digest(&ctx, 0x11);
    let metadata_hash = digest(&ctx, 0x22);

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &3u32,
        &obligation_root,
        &metadata_hash,
        &2u32,
    );

    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &draft_id, &approval.protected_content_hash);

    // Revising with identical protected fields leaves the revision (and the
    // collected approvals) untouched.
    let state = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &3u32,
        &obligation_root,
        &metadata_hash,
    );
    assert_eq!(state.current_approvals, 1);
    assert_eq!(state.current_stage, 1);
    assert_eq!(
        state.protected_content_hash,
        approval.protected_content_hash
    );
}

#[test]
fn test_revision_change_invalidates_old_approval_hash() {
    let ctx = setup();
    let draft_id = 3u64;

    let approval = ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &10_000i128,
        &2u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
        &2u32,
    );
    let old_hash = approval.protected_content_hash;

    let signer1 = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer1, &draft_id, &old_hash);

    // A protected field changes: the revisions differ, so the tracker is
    // re-bound and approvals roll back.
    let rolled_back = ctx.payroll().amend_draft_with_rollback(
        &ctx.admin,
        &draft_id,
        &20_000i128,
        &2u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
    );
    assert_eq!(rolled_back.current_approvals, 0);
    assert_eq!(rolled_back.current_stage, 0);
    assert!(!rolled_back.is_locked);
    assert_ne!(rolled_back.protected_content_hash, old_hash);

    // An approval bound to the old revision cannot be replayed.
    let signer2 = Address::generate(&ctx.env);
    let stale = ctx
        .payroll()
        .try_submit_draft_approval(&signer2, &draft_id, &old_hash);
    assert!(stale.is_err());

    // The revised revision is still approvable with its new hash.
    let fresh = ctx.payroll().submit_draft_approval(
        &signer2,
        &draft_id,
        &rolled_back.protected_content_hash,
    );
    assert_eq!(fresh.current_approvals, 1);
}

// ── Failure paths ────────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "required_approvals must be positive")]
fn test_init_rejects_zero_required_approvals() {
    let ctx = setup();
    ctx.payroll().init_draft_approval(
        &ctx.admin,
        &4u64,
        &1_000i128,
        &1u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
        &0u32,
    );
}

#[test]
#[should_panic(expected = "Draft approval not initialized")]
fn test_submit_without_tracker_rejected() {
    let ctx = setup();
    let signer = Address::generate(&ctx.env);
    ctx.payroll()
        .submit_draft_approval(&signer, &99u64, &digest(&ctx, 0xAA));
}

#[test]
fn test_non_admin_cannot_init_or_amend() {
    let ctx = setup();
    let outsider = Address::generate(&ctx.env);
    let draft_id = 5u64;

    // A non-admin cannot initialise a tracker.
    let init = ctx.payroll().try_init_draft_approval(
        &outsider,
        &draft_id,
        &1_000i128,
        &1u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
        &1u32,
    );
    assert!(init.is_err());

    // A non-admin cannot revise an existing tracker either.
    ctx.payroll().init_draft_approval(
        &ctx.admin,
        &draft_id,
        &1_000i128,
        &1u32,
        &digest(&ctx, 0x11),
        &digest(&ctx, 0x22),
        &1u32,
    );
    let amend = ctx.payroll().try_amend_draft_with_rollback(
        &outsider,
        &draft_id,
        &2_000i128,
        &1u32,
        &digest(&ctx, 0x33),
        &digest(&ctx, 0x44),
    );
    assert!(amend.is_err());
}
