#![cfg(test)]

use payroll::{PayrollClient, PayrollUploadStatus};
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

fn upload_id(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

#[test]
fn upload_checkpoint_advances_idempotently_and_completes() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = upload_id(&env, 1);
    let root = upload_id(&env, 2);

    client.begin_payroll_upload_checkpoint(&admin, &id, &root, &2);

    let first = client.record_payroll_upload_progress(&admin, &id, &1);
    assert_eq!(first.uploaded_chunks, 1);
    assert_eq!(first.status, PayrollUploadStatus::InProgress);

    let retry = client.record_payroll_upload_progress(&admin, &id, &1);
    assert_eq!(retry.uploaded_chunks, 1);

    let completed = client.record_payroll_upload_progress(&admin, &id, &2);
    assert_eq!(completed.uploaded_chunks, 2);
    assert_eq!(completed.status, PayrollUploadStatus::Completed);
    assert_eq!(
        client.record_payroll_upload_progress(&admin, &id, &2),
        completed
    );
    assert_eq!(
        client.get_payroll_upload_checkpoint(&id),
        completed
    );
}

#[test]
fn failed_upload_resumes_from_the_saved_cursor() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = upload_id(&env, 3);
    let root = upload_id(&env, 4);

    client.begin_payroll_upload_checkpoint(&admin, &id, &root, &3);
    client.record_payroll_upload_progress(&admin, &id, &1);
    let failed = client.mark_payroll_upload_failed(&admin, &id);
    assert_eq!(failed.status, PayrollUploadStatus::Failed);
    assert_eq!(failed.uploaded_chunks, 1);

    let resumed = client.resume_payroll_upload(&admin, &id);
    assert_eq!(resumed.status, PayrollUploadStatus::InProgress);
    assert_eq!(resumed.uploaded_chunks, 1);

    let progress = client.record_payroll_upload_progress(&admin, &id, &2);
    assert_eq!(progress.status, PayrollUploadStatus::InProgress);
    assert_eq!(progress.uploaded_chunks, 2);
    let completed = client.record_payroll_upload_progress(&admin, &id, &3);
    assert_eq!(completed.status, PayrollUploadStatus::Completed);
    assert_eq!(completed.uploaded_chunks, 3);
}

#[test]
fn upload_checkpoint_rejects_skipped_chunks_without_mutating_progress() {
    let env = Env::default();
    let (admin, client) = setup(&env);
    let id = upload_id(&env, 5);
    let root = upload_id(&env, 6);

    client.begin_payroll_upload_checkpoint(&admin, &id, &root, &3);
    assert!(client
        .try_record_payroll_upload_progress(&admin, &id, &2)
        .is_err());

    let stored = client.get_payroll_upload_checkpoint(&id);
    assert_eq!(stored.uploaded_chunks, 0);
    assert_eq!(stored.status, PayrollUploadStatus::InProgress);
}
