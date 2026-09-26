#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};
use payroll::{
    BatchCheckpointState, ContractAddresses, PayrollClient,
};

fn setup(e: &Env) -> (Address, PayrollClient<'static>) {
    e.mock_all_auths();
    let admin = Address::generate(e);
    let token = Address::generate(e);
    let verifier = Address::generate(e);
    let commitment = Address::generate(e);
    let treasury = Address::generate(e);
    let treasury_owner = Address::generate(e);

    let contract_id = e.register_contract(None, payroll::Payroll {});
    let client = PayrollClient::new(e, &contract_id);
    client.initialize(
        &admin,
        &token,
        &verifier,
        &commitment,
        &treasury,
        &treasury_owner,
    );

    (admin, client)
}

#[test]
fn test_cleanup_completed_batch() {
    let e = Env::default();
    let (admin, client) = setup(&e);

    let employer = Address::generate(&e);
    let batch_root = BytesN::from_array(&e, &[1; 32]);
    let asset = Address::generate(&e);
    let execution_nonce = BytesN::from_array(&e, &[2; 32]);

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
        &BatchCheckpointState::Completed,
    );

    client.cleanup_batch_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
    );
}

#[test]
#[should_panic(expected = "Cannot cleanup active batch checkpoint")]
fn test_cleanup_active_batch_fails() {
    let e = Env::default();
    let (admin, client) = setup(&e);

    let employer = Address::generate(&e);
    let batch_root = BytesN::from_array(&e, &[1; 32]);
    let asset = Address::generate(&e);
    let execution_nonce = BytesN::from_array(&e, &[2; 32]);

    client.begin_batch_execution_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
        &0,
    );

    client.cleanup_batch_checkpoint(
        &admin,
        &employer,
        &batch_root,
        &asset,
        &execution_nonce,
    );
}
