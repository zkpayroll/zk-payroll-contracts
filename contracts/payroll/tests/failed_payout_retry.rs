#![cfg(test)]

use payroll::{BatchCheckpointState, PayrollClient};
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
        BytesN::from_array(env, &[0x11; 32]),
        Address::generate(env),
        BytesN::from_array(env, &[0x22; 32]),
    )
}

#[test]
fn failed_incomplete_payout_checkpoint_can_be_explicitly_resumed() {
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
        &0,
        &BatchCheckpointState::Failed,
    );

    assert!(client.is_failed_payout_retry_eligible(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
    ));
    assert!(client.resume_failed_payout_retry(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
        &0,
    ));

    let resumed =
        client.get_batch_execution_checkpoint(&employer, &batch_root, &asset, &execution_nonce);
    assert_eq!(resumed.state, BatchCheckpointState::Resumed);
    assert!(!resumed.failed);
    assert!(!client.is_failed_payout_retry_eligible(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
    ));
}

#[test]
fn failed_checkpoint_at_end_of_batch_is_not_retry_eligible() {
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

    assert!(!client.is_failed_payout_retry_eligible(
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &2,
    ));
    assert!(client
        .try_resume_failed_payout_retry(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &2,
            &2,
        )
        .is_err());

    let checkpoint =
        client.get_batch_execution_checkpoint(&employer, &batch_root, &asset, &execution_nonce);
    assert!(checkpoint.failed);
}
