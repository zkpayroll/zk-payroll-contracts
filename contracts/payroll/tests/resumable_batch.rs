//! Resumable payroll batch handling tests (issue #611).

#![cfg(test)]

use payroll::{BatchCheckpointState, BatchResumeStatus, PayrollClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

fn setup(env: &Env) -> (Address, PayrollClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register_contract(None, payroll::Payroll {});
    let client = PayrollClient::new(env, &contract_id);

    client.initialize(
        &admin,
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
    );

    (admin, client)
}

fn checkpoint_identity(env: &Env) -> (Address, BytesN<32>, Address, BytesN<32>) {
    (
        Address::generate(env),
        BytesN::from_array(env, &[0x55; 32]),
        Address::generate(env),
        BytesN::from_array(env, &[0x66; 32]),
    )
}

// ── Success paths ────────────────────────────────────────────────────────────

#[test]
fn failed_batch_reports_failed_retryable_and_resumes() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
        &BatchCheckpointState::Failed,
    );

    let plan = client.get_batch_resume_plan(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5, // 5 payments in the original batch, 2 processed before failure
    );

    assert_eq!(plan.status, BatchResumeStatus::FailedRetryable);
    assert_eq!(plan.processed_count, 2);
    assert_eq!(plan.expected_total, 5);
    assert!(plan.cursor_consistent);
    assert_eq!(plan.remaining_count, 3);
    assert!(plan.can_resume);
}

#[test]
fn admin_can_resume_failed_batch_and_plan_clears() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
        &BatchCheckpointState::Failed,
    );

    // Non-admin callers are rejected before any state change.
    let outsider = Address::generate(&env);
    assert!(client
        .try_resume_payroll_batch(
            &outsider,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &5,
        )
        .is_err());
    assert!(client.get_batch_resume_plan(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5
    )
    .can_resume);

    client.resume_payroll_batch(&admin, &employer, &batch_root, &asset, &execution_nonce, &5);

    let checkpoint =
        client.get_batch_execution_checkpoint(&employer, &batch_root, &asset, &execution_nonce);
    assert_eq!(checkpoint.state, BatchCheckpointState::Resumed);
    assert!(!checkpoint.failed);
    assert_eq!(checkpoint.last_checkpoint_index, 2);

    // After the explicit resume the plan reports a plain resumable batch.
    let plan = client.get_batch_resume_plan(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5,
    );
    assert_eq!(plan.status, BatchResumeStatus::Resumable);
    assert!(!plan.can_resume, "already resumed; submit the bounded batch");
    assert_eq!(plan.remaining_count, 3);
}

// ── Invalid paths ────────────────────────────────────────────────────────────

#[test]
fn resume_rejects_wrong_payment_count() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
        &BatchCheckpointState::Failed,
    );

    // Cursor (2) covers the whole batch when only 2 payments are expected.
    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &2,
        )
        .is_err());

    // Zero and over-cap counts are rejected as well.
    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &0,
        )
        .is_err());
    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &51,
        )
        .is_err());

    // The checkpoint must still be failed and resumable with the right count.
    let checkpoint =
        client.get_batch_execution_checkpoint(&employer, &batch_root, &asset, &execution_nonce);
    assert!(checkpoint.failed);
    assert!(client.get_batch_resume_plan(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5
    )
    .can_resume);
}

#[test]
fn resume_rejects_unknown_checkpoint() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &3,
        )
        .is_err());
}

#[test]
fn resume_rejects_completed_batch() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &3,
        &BatchCheckpointState::Completed,
    );

    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &3,
        )
        .is_err());
}

#[test]
fn resume_rejects_mid_execution_checkpoint() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
        &BatchCheckpointState::PartiallyCheckpointed,
    );

    // A batch that is mid-execution (not failed) resumes by resubmitting the
    // bounded batch itself, not through the failure-recovery entrypoint.
    assert!(client
        .try_resume_payroll_batch(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &5,
        )
        .is_err());
}

// ── Plan edge cases ──────────────────────────────────────────────────────────

#[test]
fn plan_without_checkpoint_reports_not_found() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    let plan =
        client.get_batch_resume_plan(&employer, &batch_root, &asset, &execution_nonce, &4);
    assert_eq!(plan.status, BatchResumeStatus::NotFound);
    assert_eq!(plan.processed_count, 0);
    assert_eq!(plan.remaining_count, 0);
    assert!(!plan.cursor_consistent);
    assert!(!plan.can_resume);
}

#[test]
fn plan_rejects_invalid_expected_totals() {
    let env = Env::default();
    let (_admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    for bad in [0u32, 51u32] {
        let plan =
            client.get_batch_resume_plan(&employer, &batch_root, &asset, &execution_nonce, &bad);
        assert_eq!(plan.status, BatchResumeStatus::NotFound);
        assert!(!plan.can_resume);
    }
}

#[test]
fn plan_reports_completed_batch() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &3,
        &BatchCheckpointState::Completed,
    );

    let plan =
        client.get_batch_resume_plan(&employer, &batch_root, &asset, &execution_nonce, &3);
    assert_eq!(plan.status, BatchResumeStatus::Completed);
    assert_eq!(plan.processed_count, 3);
    assert_eq!(plan.remaining_count, 0);
    assert!(!plan.can_resume);
}

#[test]
fn plan_flags_inconsistent_cursor() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &4,
        &BatchCheckpointState::Failed,
    );

    // Caller believes the batch has only 2 payments: the persisted cursor (4)
    // is beyond it, so the plan flags the mismatch instead of exposing a
    // negative or wrapped remaining count.
    let plan =
        client.get_batch_resume_plan(&employer, &batch_root, &asset, &execution_nonce, &2);
    assert!(!plan.cursor_consistent);
    assert_eq!(plan.remaining_count, 0);
    assert!(!plan.can_resume);
}

#[test]
fn plan_reports_mid_execution_progress() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );
    client.record_batch_checkpoint_progress(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &3,
        &BatchCheckpointState::PartiallyCheckpointed,
    );

    let plan =
        client.get_batch_resume_plan(&employer, &batch_root, &asset, &execution_nonce, &5);
    assert_eq!(plan.status, BatchResumeStatus::Resumable);
    assert_eq!(plan.processed_count, 3);
    assert_eq!(plan.remaining_count, 2);
    assert!(plan.cursor_consistent);
    assert!(!plan.can_resume, "mid-execution batches resubmit directly");
}
