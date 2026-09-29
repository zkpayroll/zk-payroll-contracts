#![cfg(test)]

use payroll::{BatchCheckpointState, PayrollClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

fn setup(env: &Env) -> (Address, PayrollClient<'_>) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(payroll::Payroll {}, ());
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
        BytesN::from_array(env, &[0x33; 32]),
        Address::generate(env),
        BytesN::from_array(env, &[0x44; 32]),
    )
}

#[test]
fn test_interrupted_run_is_recoverable_and_resumes_safely() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    // Initialize checkpoint with 5 total payments, 2 processed before interruption
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

    // Checkpoint should be recognized as recoverable
    assert!(client.is_interrupted_run_recoverable(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5,
    ));

    // Admin recovers the interrupted run
    let recovered = client.recover_interrupted_payroll_run(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5,
    );

    assert_eq!(recovered.state, BatchCheckpointState::Resumed);
    assert_eq!(recovered.last_checkpoint_index, 2);
    assert!(!recovered.completed);
    assert!(!recovered.failed);

    // Verify storage reflects the resumed state
    let stored =
        client.get_batch_execution_checkpoint(&employer, &batch_root, &asset, &execution_nonce);
    assert_eq!(stored.state, BatchCheckpointState::Resumed);
    assert_eq!(stored.last_checkpoint_index, 2);
}

#[test]
fn test_failed_interrupted_run_is_recoverable() {
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
        &1,
        &BatchCheckpointState::Failed,
    );

    assert!(client.is_interrupted_run_recoverable(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &4,
    ));

    let recovered = client.recover_interrupted_payroll_run(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &4,
    );

    assert_eq!(recovered.state, BatchCheckpointState::Resumed);
    assert_eq!(recovered.last_checkpoint_index, 1);
    assert!(!recovered.failed);
}

#[test]
fn test_completed_run_is_not_recoverable() {
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

    assert!(!client.is_interrupted_run_recoverable(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &3,
    ));
}

#[test]
#[should_panic(expected = "Cannot recover a fully completed payroll run")]
fn test_recover_completed_run_panics() {
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

    client.recover_interrupted_payroll_run(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &3,
    );
}

#[test]
#[should_panic(expected = "Interrupted payroll run checkpoint not found")]
fn test_recover_nonexistent_checkpoint_panics() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let (employer, batch_root, asset, execution_nonce) = checkpoint_identity(&env);

    client.recover_interrupted_payroll_run(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &5,
    );
}
