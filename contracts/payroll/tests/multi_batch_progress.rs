//! Multi-batch execution progress tracking (issue #643).
//!
//! Covers: opening a tracker with validated totals, incremental monotonic
//! progress with auto-completion, explicit failure marking, read-only polling,
//! authorization and duplicate guards, over-total / regression / no-op
//! rejection, terminal-state immutability, unknown-identifier handling, and
//! boundary edge cases (single-batch execution, exact-total completion,
//! max-cap plan).

#![cfg(test)]

use payroll::{MultiBatchStatus, Payroll, PayrollClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};
use token::Token;

fn setup(env: &Env) -> (Address, PayrollClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let token_id = env.register_contract(None, Token);
    let contract_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(env, &contract_id);

    client.initialize(
        &admin,
        &token_id,
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
    );

    (admin, client)
}

fn execution_id(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    // Avoid the all-zero digest so the non-zero guard passes.
    if seed == 0 {
        arr[1] = 1;
    }
    BytesN::from_array(env, &arr)
}

fn zero_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

// ── Success paths ──────────────────────────────────────────────────────────

#[test]
fn begin_opens_tracker_at_zero_progress() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 1);

    let progress = client.begin_multi_batch_execution(&admin, &id, &4, &100);

    assert_eq!(progress.execution_id, id);
    assert_eq!(progress.total_batches, 4);
    assert_eq!(progress.completed_batches, 0);
    assert_eq!(progress.total_payments, 100);
    assert_eq!(progress.processed_payments, 0);
    assert_eq!(progress.status, MultiBatchStatus::InProgress);
    assert_eq!(progress.updated_by, admin);
    assert!(!client.is_multi_batch_complete(&id));

    // Read path returns the same aggregate view.
    let fetched = client.get_multi_batch_progress(&id);
    assert_eq!(fetched, progress);
}

#[test]
fn incremental_progress_advances_and_auto_completes() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 2);

    client.begin_multi_batch_execution(&admin, &id, &4, &100);

    // Partial progress stays InProgress and is not complete.
    let mid = client.record_multi_batch_progress(&admin, &id, &1, &25);
    assert_eq!(mid.completed_batches, 1);
    assert_eq!(mid.processed_payments, 25);
    assert_eq!(mid.status, MultiBatchStatus::InProgress);
    assert!(!client.is_multi_batch_complete(&id));

    // Advancing only one cursor still counts as forward progress.
    let mid2 = client.record_multi_batch_progress(&admin, &id, &2, &25);
    assert_eq!(mid2.completed_batches, 2);
    assert_eq!(mid2.processed_payments, 25);

    // Reaching both totals flips to Completed automatically.
    let done = client.record_multi_batch_progress(&admin, &id, &4, &100);
    assert_eq!(done.status, MultiBatchStatus::Completed);
    assert!(client.is_multi_batch_complete(&id));

    let fetched = client.get_multi_batch_progress(&id);
    assert_eq!(fetched.status, MultiBatchStatus::Completed);
    assert_eq!(fetched.completed_batches, 4);
    assert_eq!(fetched.processed_payments, 100);
}

#[test]
fn mark_failed_preserves_cursors_and_blocks_completion() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 3);

    client.begin_multi_batch_execution(&admin, &id, &4, &100);
    client.record_multi_batch_progress(&admin, &id, &1, &25);

    let failed = client.mark_multi_batch_failed(&admin, &id);
    assert_eq!(failed.status, MultiBatchStatus::Failed);
    // Cursors are preserved so operators see how far it got.
    assert_eq!(failed.completed_batches, 1);
    assert_eq!(failed.processed_payments, 25);
    assert!(!client.is_multi_batch_complete(&id));
}

// ── Failure paths ──────────────────────────────────────────────────────────

#[test]
fn non_admin_cannot_open_record_or_fail() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let outsider = Address::generate(&env);
    let id = execution_id(&env, 4);

    assert!(client
        .try_begin_multi_batch_execution(&outsider, &id, &2, &20)
        .is_err());
    // Failed open wrote nothing.
    assert!(client.try_get_multi_batch_progress(&id).is_err());

    client.begin_multi_batch_execution(&admin, &id, &2, &20);
    assert!(client
        .try_record_multi_batch_progress(&outsider, &id, &1, &10)
        .is_err());
    assert!(client.try_mark_multi_batch_failed(&outsider, &id).is_err());

    // Cursors untouched by the unauthorized attempts.
    let progress = client.get_multi_batch_progress(&id);
    assert_eq!(progress.completed_batches, 0);
    assert_eq!(progress.processed_payments, 0);
}

#[test]
fn duplicate_begin_is_rejected() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 5);

    client.begin_multi_batch_execution(&admin, &id, &2, &20);
    assert!(client
        .try_begin_multi_batch_execution(&admin, &id, &2, &20)
        .is_err());

    let progress = client.get_multi_batch_progress(&id);
    assert_eq!(progress.total_batches, 2);
    assert_eq!(progress.total_payments, 20);
}

#[test]
fn begin_validates_totals_with_actionable_errors() {
    let env = Env::default();
    let (admin, client) = setup(&env);

    // Zero totals.
    assert!(client
        .try_begin_multi_batch_execution(&admin, &execution_id(&env, 11), &0, &10)
        .is_err());
    assert!(client
        .try_begin_multi_batch_execution(&admin, &execution_id(&env, 12), &2, &0)
        .is_err());
    // Over-cap totals.
    assert!(client
        .try_begin_multi_batch_execution(&admin, &execution_id(&env, 13), &51, &51)
        .is_err());
    assert!(client
        .try_begin_multi_batch_execution(&admin, &execution_id(&env, 14), &2, &2501)
        .is_err());
    // Fewer payments than batches (each batch holds >= 1 payment).
    assert!(client
        .try_begin_multi_batch_execution(&admin, &execution_id(&env, 15), &4, &3)
        .is_err());
    // Zero execution identifier.
    assert!(client
        .try_begin_multi_batch_execution(&admin, &zero_id(&env), &2, &20)
        .is_err());
}

#[test]
fn record_rejects_over_total_regression_and_no_op() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 6);

    client.begin_multi_batch_execution(&admin, &id, &2, &20);
    client.record_multi_batch_progress(&admin, &id, &1, &10);

    // Over-total cursors.
    assert!(client
        .try_record_multi_batch_progress(&admin, &id, &3, &10)
        .is_err());
    assert!(client
        .try_record_multi_batch_progress(&admin, &id, &1, &21)
        .is_err());
    // Backward cursors.
    assert!(client
        .try_record_multi_batch_progress(&admin, &id, &0, &10)
        .is_err());
    assert!(client
        .try_record_multi_batch_progress(&admin, &id, &1, &9)
        .is_err());
    // Identical resubmission is not forward progress.
    assert!(client
        .try_record_multi_batch_progress(&admin, &id, &1, &10)
        .is_err());

    // Stored cursor unchanged after the rejected records.
    let progress = client.get_multi_batch_progress(&id);
    assert_eq!(progress.completed_batches, 1);
    assert_eq!(progress.processed_payments, 10);
    assert_eq!(progress.status, MultiBatchStatus::InProgress);
}

#[test]
fn terminal_executions_reject_further_writes() {
    let env = Env::default();
    let (admin, client) = setup(&env);

    // Completed terminal.
    let done_id = execution_id(&env, 21);
    client.begin_multi_batch_execution(&admin, &done_id, &1, &10);
    client.record_multi_batch_progress(&admin, &done_id, &1, &10);
    assert!(client
        .try_record_multi_batch_progress(&admin, &done_id, &1, &10)
        .is_err());
    assert!(client
        .try_mark_multi_batch_failed(&admin, &done_id)
        .is_err());

    // Failed terminal.
    let failed_id = execution_id(&env, 22);
    client.begin_multi_batch_execution(&admin, &failed_id, &2, &20);
    client.mark_multi_batch_failed(&admin, &failed_id);
    assert!(client
        .try_record_multi_batch_progress(&admin, &failed_id, &1, &10)
        .is_err());
    assert!(client
        .try_mark_multi_batch_failed(&admin, &failed_id)
        .is_err());
}

#[test]
fn unknown_execution_id_has_actionable_errors() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let missing = execution_id(&env, 99);

    assert!(client.try_get_multi_batch_progress(&missing).is_err());
    assert!(client
        .try_record_multi_batch_progress(&admin, &missing, &1, &10)
        .is_err());
    assert!(client
        .try_mark_multi_batch_failed(&admin, &missing)
        .is_err());
    // Polling helper reports false rather than trapping for dashboards.
    assert!(!client.is_multi_batch_complete(&missing));
}

// ── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn single_batch_execution_completes_in_one_record() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 31);

    client.begin_multi_batch_execution(&admin, &id, &1, &1);
    let done = client.record_multi_batch_progress(&admin, &id, &1, &1);
    assert_eq!(done.status, MultiBatchStatus::Completed);
    assert!(client.is_multi_batch_complete(&id));
}

#[test]
fn max_cap_plan_is_accepted_and_exact_total_completes() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = execution_id(&env, 32);

    // Largest plan the contract accepts: 50 batches x 50 payments.
    let opened = client.begin_multi_batch_execution(&admin, &id, &50, &2500);
    assert_eq!(opened.total_batches, 50);
    assert_eq!(opened.total_payments, 2500);

    // Exact-total boundary completes; one over would have been rejected.
    let done = client.record_multi_batch_progress(&admin, &id, &50, &2500);
    assert_eq!(done.status, MultiBatchStatus::Completed);
    assert!(client.is_multi_batch_complete(&id));
}

#[test]
fn payments_may_complete_before_batches_and_vice_versa() {
    let env = Env::default();
    let (admin, client) = setup(&env);

    // All payments processed but one batch still open: stays InProgress.
    let a = execution_id(&env, 41);
    client.begin_multi_batch_execution(&admin, &a, &4, &4);
    let partial = client.record_multi_batch_progress(&admin, &a, &3, &4);
    assert_eq!(partial.status, MultiBatchStatus::InProgress);
    assert!(!client.is_multi_batch_complete(&a));

    // All batches closed but one payment still outstanding: stays InProgress.
    let b = execution_id(&env, 42);
    client.begin_multi_batch_execution(&admin, &b, &4, &100);
    let partial_b = client.record_multi_batch_progress(&admin, &b, &4, &99);
    assert_eq!(partial_b.status, MultiBatchStatus::InProgress);
    assert!(!client.is_multi_batch_complete(&b));

    // Finishing the lagging cursor completes.
    let done = client.record_multi_batch_progress(&admin, &b, &4, &100);
    assert_eq!(done.status, MultiBatchStatus::Completed);
}
