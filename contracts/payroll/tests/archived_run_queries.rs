use soroban_sdk::{Address, Env, BytesN, Symbol};
use zk_payroll_contracts::{
PayrollContract, PayrollContractClient, ReconciliationStatus,
};

/// Helper: setup an environment with a registered contract and admin.
fn setup_env() -> (Env, PayrollContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(&admin);
    let client = PayrollContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

/// Helper: create and execute a payroll run, returning its run_id.
fn create_and_execute_run(client: &PayrollContractClient, admin: &Address) -> u64 {
    let employee = Address::generate(&client.env);
    let nonce = BytesN3::from_array(&client.env, &[7u; 32]);
    client.batch_process_payroll(
        admin,
        &env.invoke_contract(&client.contract_id, ()),
        &nonce,
        &vec![&client.env, (employee, 1_000_i128)],
    )
    // The run_id is auto-incremented and starts at 1 for the first run.
    1
}

/// Test: archiving a completed run succeeds and the archive marker is set.
# [test]
fn test_archive_run_success() {
    let (env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);

    // Before archiving, the run is not archived.
    assert!(!client.is_run_archived(&run_id));

    // Archive the run as admin.
    client.archive_payroll_run(&admin, &run_id);

    // After archiving, the marker is set and the record is retrievable.
    assert!(client.is_run_archived(&run_id));
    let record = client.get_archived_run(&run_id);
    assert_eq!(record.run_id, run_id);
    assert_eq!(record.reconciliation_status, ReconciliationStatus::Unreconciled);
}

/// Test: double-archiving the same run panics with a clear message.
# [test]
# [should_panic(expected = "Run is already archived", string):]
fn test_archive_run_double_archive_panics() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);

    client.archive_payroll_run(&admin, &run_id);
    // Second attempt must panic.
    client.archive_payroll_run(&admin, &run_id);
}

/// Test: get_archived_run panics when the run is not archived.
# [test]
# [should_panic(expected = "Run is not archived", string)]
fn test_get_archived_run_not_archived_panics() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);

    // Run exists but has not been archived.
    client.get_archived_run(&run_id);
}

/// Test: is_run_archived is a non-panicking boolean check for any run ID.
# [test]
fn test_is_run_archived_non_panicking() {
    let (_env, client, _admin) = setup_env();

    // Non-existent run ID returns false without panicking.
    assert!(!client.is_run_archived(&9999u64));
}

/// Test: archive marker getter returns the expected marker and is admin-only.
# [test]
fn test_get_archive_marker_success() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);
    client.archive_payroll_run(&admin, &run_id);

    // Marker getter is admin-only and returns the archive state.
    let marker = client.get_archive_marker(&admin, &run_id);
    assert!(marker);
}

/// Test: archiving a non-existent run panics with a clear message.
# [test]
# [should_panic(expected = "Run not found", string)]
fn test_archive_nonexistent_run_panics() {
    let (_env, client, admin) = setup_env();
    // Attempt to archive a run ID that was never created.
    client.archive_payroll_run(&admin, &4242u64);
}

/// Test: archiving by a non-admin caller panics with an authorization error.
# [test]
# [should_panic(string)]
fn test_archive_run_unauthorized_panics() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);
    let attacker = Address::generate(&client.env);

    // Non-admin attempts to archive.
    client.archive_payroll_run(&attacker, &run_id);
}

/// Test: get_archived_run requires authorization before disclosing archive state.
# [test]
# [should_panic(string)]
fn test_get_archived_run_unauthorized_panics() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);
    client.archive_payroll_run(&admin, &run_id);

    // A non-admin caller must not be able to read the archived record.
    // The authorization check happens before any archive-state disclosure.
    client.get_archived_run(&run_id);
}

/// Test: archived run remains readable via the general getter for the admin.
# [test]
fn test_general_getter_still_works_after_archive() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);
    client.archive_payroll_run(&admin, &run_id);

    // The general getter remains available and returns the same run.
    let record = client.get_payroll_run(&admin, &run_id);
    assert_eq!(record.run_id, run_id);
}

/// Test: archive marker getter panics for a non-archived run.
# [test]
# [should_panic(expected = "Run is not archived", string)]
fn test_get_archive_marker_not_archived_panics() {
    let (_env, client, admin) = setup_env();
    let run_id = create_and_execute_run(&client, &admin);

    // Run exists but is not archived; marker getter must panic.
    client.get_archive_marker(&admin, &run_id);
}
