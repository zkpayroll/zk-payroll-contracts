//! Contract draft payroll approval snapshot locking (#648).

#![cfg(test)]

mod common;

use payroll::{DataKey, DraftSnapshotError, PayrollClient, PayrollRunDraft};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol};

const TOTAL: i128 = 1_000;
const EMPLOYEES: u32 = 3;

struct Ctx<'a> {
    env: &'a Env,
    client: PayrollClient<'a>,
    admin: Address,
    draft_id: u64,
}

fn digest(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

fn setup(env: &Env) -> Ctx<'_> {
    let (client, _token, _employee) = common::setup(env);
    let admin = client.get_addresses().admin;
    let draft_id = client.create_run_draft(&admin, &TOTAL, &EMPLOYEES, &Symbol::new(env, "P1"));
    Ctx {
        env,
        client,
        admin,
        draft_id,
    }
}

/// Initialize a two-signer approval tracker and optionally reach quorum.
fn approve(ctx: &Ctx, signers: u32) -> BytesN<32> {
    let approval = ctx.client.init_draft_approval(
        &ctx.admin,
        &ctx.draft_id,
        &TOTAL,
        &EMPLOYEES,
        &digest(ctx.env, 0x11),
        &digest(ctx.env, 0x22),
        &2,
    );
    for _ in 0..signers {
        ctx.client.submit_draft_approval(
            &Address::generate(ctx.env),
            &ctx.draft_id,
            &approval.protected_content_hash,
        );
    }
    approval.protected_content_hash
}

#[test]
fn approved_draft_snapshot_locks_and_verifies() {
    let env = Env::default();
    let ctx = setup(&env);
    let hash = approve(&ctx, 2);

    let snapshot = ctx
        .client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);
    assert_eq!(snapshot.draft_id, ctx.draft_id);
    assert_eq!(snapshot.protected_content_hash, hash);
    assert_eq!(snapshot.total_amount, TOTAL);
    assert_eq!(snapshot.employee_count, EMPLOYEES);
    assert_eq!(snapshot.amendment_count, 0);
    assert_eq!(snapshot.approvals, 2);
    assert_eq!(snapshot.locked_by, ctx.admin);

    assert!(ctx.client.is_draft_snapshot_locked(&ctx.draft_id));
    assert_eq!(
        ctx.client.get_draft_approval_snapshot(&ctx.draft_id),
        Some(snapshot.clone())
    );
    assert_eq!(
        ctx.client.verify_draft_approval_snapshot(&ctx.draft_id),
        snapshot
    );
}

#[test]
fn locked_snapshot_blocks_every_content_changing_path() {
    let env = Env::default();
    let ctx = setup(&env);
    approve(&ctx, 2);
    ctx.client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);

    assert!(ctx
        .client
        .try_amend_run_draft(&ctx.admin, &ctx.draft_id, &2_000, &EMPLOYEES)
        .is_err());
    assert!(ctx
        .client
        .try_amend_draft_with_rollback(
            &ctx.admin,
            &ctx.draft_id,
            &2_000,
            &EMPLOYEES,
            &digest(&env, 0x11),
            &digest(&env, 0x22),
        )
        .is_err());
    assert!(ctx
        .client
        .try_init_draft_approval(
            &ctx.admin,
            &ctx.draft_id,
            &TOTAL,
            &EMPLOYEES,
            &digest(&env, 0x11),
            &digest(&env, 0x22),
            &1,
        )
        .is_err());

    // Nothing changed, so the snapshot still verifies.
    assert_eq!(ctx.client.get_run_draft(&ctx.draft_id).total_amount, TOTAL);
    assert!(ctx
        .client
        .try_verify_draft_approval_snapshot(&ctx.draft_id)
        .is_ok());
}

#[test]
fn releasing_resets_approvals_and_reopens_amendments() {
    let env = Env::default();
    let ctx = setup(&env);
    approve(&ctx, 2);
    ctx.client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);

    ctx.client
        .release_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);
    assert!(!ctx.client.is_draft_snapshot_locked(&ctx.draft_id));
    assert_eq!(ctx.client.get_draft_approval_snapshot(&ctx.draft_id), None);

    let approval = ctx
        .client
        .get_draft_approval_state(&ctx.draft_id)
        .expect("tracker kept");
    assert_eq!(approval.current_approvals, 0);
    assert!(!approval.is_locked);
    assert_eq!(approval.signers.len(), 0);

    ctx.client
        .amend_run_draft(&ctx.admin, &ctx.draft_id, &1_100, &EMPLOYEES);
    assert_eq!(ctx.client.get_run_draft(&ctx.draft_id).total_amount, 1_100);

    // Without fresh approvals the draft cannot be re-locked.
    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::ApprovalQuorumNotMet))
    );
}

#[test]
fn lock_requires_tracker_quorum_and_single_lock() {
    let env = Env::default();
    let ctx = setup(&env);

    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::ApprovalNotInitialized))
    );

    approve(&ctx, 1);
    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::ApprovalQuorumNotMet))
    );
    assert!(!ctx.client.is_draft_snapshot_locked(&ctx.draft_id));
}

#[test]
fn lock_is_rejected_twice_and_for_non_admins() {
    let env = Env::default();
    let ctx = setup(&env);
    approve(&ctx, 2);

    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&Address::generate(&env), &ctx.draft_id),
        Err(Ok(DraftSnapshotError::Unauthorized))
    );
    ctx.client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);
    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::SnapshotAlreadyLocked))
    );
}

#[test]
fn missing_and_terminal_drafts_cannot_be_locked() {
    let env = Env::default();
    let ctx = setup(&env);

    assert_eq!(
        ctx.client.try_lock_draft_approval_snapshot(&ctx.admin, &99),
        Err(Ok(DraftSnapshotError::DraftNotFound))
    );

    approve(&ctx, 2);
    ctx.client.cancel_run_draft(&ctx.admin, &ctx.draft_id);
    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::DraftNotLockable))
    );
    assert_eq!(
        ctx.client
            .try_release_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::DraftNotLockable))
    );
}

#[test]
fn verify_and_release_require_a_locked_snapshot() {
    let env = Env::default();
    let ctx = setup(&env);

    assert_eq!(
        ctx.client.try_verify_draft_approval_snapshot(&ctx.draft_id),
        Err(Ok(DraftSnapshotError::SnapshotNotFound))
    );
    assert_eq!(
        ctx.client
            .try_release_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::SnapshotNotFound))
    );
}

#[test]
fn approval_on_superseded_revision_is_rejected() {
    let env = Env::default();
    let ctx = setup(&env);

    // Approve the draft at its current revision, then supersede it via amendment.
    let approval = ctx.client.init_draft_approval(
        &ctx.admin,
        &ctx.draft_id,
        &TOTAL,
        &EMPLOYEES,
        &digest(&env, 0x11),
        &digest(&env, 0x22),
        &2,
    );
    let stale_hash = approval.protected_content_hash;
    ctx.client
        .amend_run_draft(&ctx.admin, &ctx.draft_id, &1_100, &EMPLOYEES);

    // Approvals referencing the superseded revision must not count toward quorum.
    let signer = Address::generate(&env);
    assert!(ctx
        .client
        .try_submit_draft_approval(&signer, &ctx.draft_id, &stale_hash)
        .is_err());
    assert_eq!(
        ctx.client
            .try_lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id),
        Err(Ok(DraftSnapshotError::ApprovalQuorumNotMet))
    );
    assert!(!ctx.client.is_draft_snapshot_locked(&ctx.draft_id));
}

#[test]
fn approval_on_current_revision_succeeds() {
    let env = Env::default();
    let ctx = setup(&env);

    ctx.client
        .amend_run_draft(&ctx.admin, &ctx.draft_id, &1_100, &EMPLOYEES);

    // Fresh approvals bound to the current revision reach quorum and lock.
    let hash = approve(&ctx, 2);
    let snapshot = ctx
        .client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);
    assert_eq!(snapshot.protected_content_hash, hash);
    assert_eq!(snapshot.total_amount, 1_100);
    assert!(ctx.client.is_draft_snapshot_locked(&ctx.draft_id));
}

#[test]
fn approval_at_exact_revision_boundary_is_accepted() {
    let env = Env::default();
    let ctx = setup(&env);

    // Approve at the current revision without any intervening amendment.
    let approval = ctx.client.init_draft_approval(
        &ctx.admin,
        &ctx.draft_id,
        &TOTAL,
        &EMPLOYEES,
        &digest(&env, 0x11),
        &digest(&env, 0x22),
        &2,
    );
    let current_hash = approval.protected_content_hash;
    let signer = Address::generate(&env);
    ctx.client
        .submit_draft_approval(&signer, &ctx.draft_id, &current_hash);

    // The boundary revision (no supersession) still counts toward quorum.
    let state = ctx
        .client
        .get_draft_approval_state(&ctx.draft_id)
        .expect("tracker kept");
    assert_eq!(state.current_approvals, 1);
    assert!(!state.is_locked);
}

#[test]
fn verify_detects_draft_drift_written_outside_the_guarded_paths() {
    let env = Env::default();
    let ctx = setup(&env);
    approve(&ctx, 2);
    ctx.client
        .lock_draft_approval_snapshot(&ctx.admin, &ctx.draft_id);

    // Simulate a write path that bypasses the snapshot guard.
    env.as_contract(&ctx.client.address, || {
        let key = DataKey::RunDraft(ctx.draft_id);
        let mut draft: PayrollRunDraft = env.storage().persistent().get(&key).unwrap();
        draft.total_amount += 1;
        env.storage().persistent().set(&key, &draft);
    });

    assert_eq!(
        ctx.client.try_verify_draft_approval_snapshot(&ctx.draft_id),
        Err(Ok(DraftSnapshotError::DraftChangedSinceSnapshot))
    );
}
