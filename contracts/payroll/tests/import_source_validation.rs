mod common;

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};

#[test]
fn authorized_source_accepts_batch() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let source = Address::generate(&env);

    // Register the source
    payroll.register_import_source(&source, &0);

    // Submit batch from authorized source
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let result = payroll.try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 1),
        &None,
        &source,
    );

    assert!(result.is_ok());
}

#[test]
#[should_panic(expected = "Import source is not authorized for payroll operations")]
fn unauthorized_source_rejects_batch() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let unauthorized_source = Address::generate(&env);

    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 2),
        &None,
        &unauthorized_source,
    );
}

#[test]
#[should_panic(expected = "Import source is not authorized for payroll operations")]
fn deactivated_source_rejects_batch() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let source = Address::generate(&env);

    // Register and then deactivate
    payroll.register_import_source(&source, &0);
    payroll.deactivate_import_source(&source);

    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 3),
        &None,
        &source,
    );
}

#[test]
fn is_import_source_authorized_check() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let source = Address::generate(&env);

    // Unregistered source should not be authorized
    assert!(!payroll.is_import_source_authorized(&source));

    // Register source
    payroll.register_import_source(&source, &1);
    assert!(payroll.is_import_source_authorized(&source));

    // Deactivate source
    payroll.deactivate_import_source(&source);
    assert!(!payroll.is_import_source_authorized(&source));
}

#[test]
fn dry_run_reports_unauthorized_source() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let source = Address::generate(&env);

    let (_, amounts, employees) = common::one_payment(&env, &employee);
    let args = payroll::DryRunArgs {
        amounts: amounts.clone(),
        employees: employees.clone(),
        expected_total_spend: 100,
        nonce: common::nonce(&env, 4),
        draft_hash: None,
        proof_count: 1,
        sequence: None,
        source_address: Some(source),
    };

    let report = payroll.dry_run_batch_process_payroll(&args);
    assert!(!report.would_succeed);
    assert!(report.blockers.len() > 0);
}
