#![cfg(test)]

use payroll::{Payroll, PayrollClient, PendingPayrollRun, ContractAddresses};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

mod common;

#[test]
fn test_transfer_pending_run_admin_success() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);

    // Prepare a payroll run to get a pending run
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let expected_total_spend = amounts.get(0).unwrap();
    let nonce = common::nonce(&env, 1);
    
    // Note: Since prepare_payroll_run does not require admin auth, we just call it.
    // However, it creates a PendingPayrollRun with admin = addrs.admin
    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &expected_total_spend,
        &nonce,
        &None,
    );

    let new_admin = Address::generate(&env);

    let pending_run = client.get_pending_run(&run_id).unwrap();
    let admin = pending_run.admin.clone();

    // Transfer the admin
    client.transfer_pending_run_admin(&admin, &run_id, &new_admin);

    // Verify the new admin is set
    let pending_run_after = client.get_pending_run(&run_id).unwrap();
    assert_eq!(pending_run_after.admin, new_admin);
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the pending run admin")]
fn test_transfer_pending_run_admin_unauthorized() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);

    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let expected_total_spend = amounts.get(0).unwrap();
    let nonce = common::nonce(&env, 1);
    
    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &expected_total_spend,
        &nonce,
        &None,
    );

    let wrong_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Attempt to transfer with wrong admin
    client.transfer_pending_run_admin(&wrong_admin, &run_id, &new_admin);
}

#[test]
#[should_panic(expected = "Invalid transfer: new admin is the same as current admin")]
fn test_transfer_pending_run_admin_same_admin() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);

    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let expected_total_spend = amounts.get(0).unwrap();
    let nonce = common::nonce(&env, 1);
    
    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &expected_total_spend,
        &nonce,
        &None,
    );
    
    let pending_run = client.get_pending_run(&run_id).unwrap();
    let admin = pending_run.admin.clone();

    // Attempt to transfer to the same admin
    client.transfer_pending_run_admin(&admin, &run_id, &admin);
}
