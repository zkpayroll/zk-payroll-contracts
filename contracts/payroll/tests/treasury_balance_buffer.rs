#![cfg(test)]

mod common;

use payroll::PayrollClient;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn prepare(env: &Env, client: &PayrollClient, amount: i128, marker: u8) -> u64 {
    let employee = Address::generate(env);
    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]);
    let amounts = Vec::from_array(env, [amount]);
    let employees = Vec::from_array(env, [employee]);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &amount,
        &common::nonce(env, marker),
        &None,
    )
}

#[test]
fn zero_buffer_preserves_existing_treasury_capacity() {
    let env = Env::default();
    let (client, token, _) = common::setup(&env);

    assert_eq!(client.get_treasury_balance_buffer(), 0);
    assert_eq!(client.get_available_treasury_balance(&token), 1_000_000);

    prepare(&env, &client, 1_000_000, 1);
    assert_eq!(client.get_locked_funds(&token), 1_000_000);
}

#[test]
fn reservations_and_readiness_retain_the_configured_buffer() {
    let env = Env::default();
    let (client, token, _) = common::setup(&env);
    let admin = client.get_addresses().admin;

    client.set_treasury_balance_buffer(&admin, &100_000);

    assert_eq!(client.get_treasury_balance_buffer(), 100_000);
    assert_eq!(client.get_available_treasury_balance(&token), 900_000);
    assert_eq!(
        client.get_safe_treasury_summary(&token).available_balance,
        900_000
    );
    assert!(client.check_funding_source_readiness(&900_000).ready);
    assert!(!client.check_funding_source_readiness(&900_001).ready);

    prepare(&env, &client, 900_000, 1);
    assert_eq!(client.get_locked_funds(&token), 900_000);
    assert_eq!(client.get_available_treasury_balance(&token), 0);
}

#[test]
fn failed_reservation_can_be_retried_at_the_buffer_boundary() {
    let env = Env::default();
    let (client, token, _) = common::setup(&env);
    let admin = client.get_addresses().admin;
    client.set_treasury_balance_buffer(&admin, &100_000);

    let proofs = Vec::from_array(&env, [BytesN::from_array(&env, &[1; 256])]);
    let amounts = Vec::from_array(&env, [900_001_i128]);
    let employees = Vec::from_array(&env, [Address::generate(&env)]);
    let nonce = common::nonce(&env, 2);
    assert!(client
        .try_prepare_payroll_run(&proofs, &amounts, &employees, &900_001, &nonce, &None)
        .is_err());
    assert_eq!(client.get_locked_funds(&token), 0);

    let smaller_amounts = Vec::from_array(&env, [900_000_i128]);
    client.prepare_payroll_run(
        &proofs,
        &smaller_amounts,
        &employees,
        &900_000,
        &nonce,
        &None,
    );
    assert_eq!(client.get_locked_funds(&token), 900_000);
}

#[test]
#[should_panic(expected = "Treasury balance buffer would be breached")]
fn direct_payout_cannot_spend_the_retained_buffer() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    let admin = client.get_addresses().admin;
    client.set_treasury_balance_buffer(&admin, &1);
    let source = common::authorized_source(&env, &client);
    let proofs = Vec::from_array(&env, [BytesN::from_array(&env, &[1; 256])]);
    let amounts = Vec::from_array(&env, [1_000_000_i128]);
    let employees = Vec::from_array(&env, [employee]);

    client.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &1_000_000,
        &common::nonce(&env, 3),
        &None,
        &source,
    );
}

#[test]
#[should_panic(
    expected = "Insufficient available treasury balance: funds are locked for pending payroll or reserved by the treasury buffer"
)]
fn emergency_withdrawal_cannot_spend_the_retained_buffer() {
    let env = Env::default();
    let (client, _, _) = common::setup(&env);
    let addresses = client.get_addresses();
    client.set_treasury_balance_buffer(&addresses.admin, &100_000);

    client.request_emergency_withdrawal(
        &addresses.treasury_owner,
        &900_001,
        &Address::generate(&env),
    );
}

#[test]
#[should_panic(expected = "Treasury balance buffer cannot be negative")]
fn negative_buffer_configuration_is_rejected() {
    let env = Env::default();
    let (client, _, _) = common::setup(&env);
    let admin = client.get_addresses().admin;

    client.set_treasury_balance_buffer(&admin, &-1);
}
