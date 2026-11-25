//! Typed errors for retention policy updates (issue #976).
//!
//! `set_retention_override` used to answer a paused contract or a missing admin with a bare
//! panic. Both are now `RetentionError`s, so a client can tell them apart from each other and from
//! a refused shortening, and none of them carries a company id, record id or timestamp.
extern crate std;

use super::*;
use pause_manager::{PauseManager, PauseManagerClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::Env;
use std::format;

const COMPANY: u64 = 41;
const KIND: RecordType = RecordType::FinalizedBatch;

fn setup() -> (Env, Address, RetentionManagerContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_000_000);
    let contract_id = env.register(RetentionManagerContract, ());
    let admin = Address::generate(&env);
    let client = RetentionManagerContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    (env, admin, client)
}

fn pause(
    env: &Env,
    admin: &Address,
    client: &RetentionManagerContractClient,
) -> PauseManagerClient<'static> {
    let pm_id = env.register(PauseManager, ());
    let pm = PauseManagerClient::new(env, &pm_id);
    pm.initialize(admin);
    client.set_pause_manager(&pm_id);
    pm.pause();
    pm
}

/// The window a record registered right now would get.
fn window_now(env: &Env, client: &RetentionManagerContractClient, id: u64) -> u64 {
    let record = client.register_record(&COMPANY, &id, &KIND);
    let _ = env;
    record.eligible_after - record.registered_at
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(RetentionError::RetentionWindowShortened as u32, 7);
    assert_eq!(RetentionError::Paused as u32, 10);
    assert_eq!(RetentionError::NotInitialized as u32, 11);
}

#[test]
fn a_paused_contract_answers_a_policy_update_with_paused() {
    let (env, admin, client) = setup();
    let _pm = pause(&env, &admin, &client);

    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &(FINALIZED_RETENTION_SECS + 1)),
        Err(Ok(RetentionError::Paused))
    );
}

#[test]
fn clearing_an_override_while_paused_is_paused_too() {
    let (env, admin, client) = setup();
    let _pm = pause(&env, &admin, &client);

    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &0u64),
        Err(Ok(RetentionError::Paused))
    );
}

#[test]
fn paused_is_reported_before_a_shortening_is() {
    let (env, admin, client) = setup();
    let _pm = pause(&env, &admin, &client);

    // 1 second would shorten the window, but the contract is not accepting changes at all.
    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &1u64),
        Err(Ok(RetentionError::Paused))
    );
}

#[test]
fn the_same_update_is_accepted_once_the_contract_is_unpaused() {
    let (env, admin, client) = setup();
    let pm = pause(&env, &admin, &client);
    let wanted = FINALIZED_RETENTION_SECS + 1;
    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &wanted),
        Err(Ok(RetentionError::Paused))
    );

    pm.unpause();

    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &wanted),
        Ok(Ok(()))
    );
    assert_eq!(window_now(&env, &client, 1), wanted);
}

#[test]
fn a_contract_with_no_admin_answers_with_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(RetentionManagerContract, ());
    let client = RetentionManagerContractClient::new(&env, &contract_id);

    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &(FINALIZED_RETENTION_SECS + 1)),
        Err(Ok(RetentionError::NotInitialized))
    );
}

#[test]
fn every_refusal_leaves_the_policy_as_it_was() {
    let (env, admin, client) = setup();
    let extended = FINALIZED_RETENTION_SECS + 1_000;
    client.set_retention_override(&COMPANY, &KIND, &extended);

    // Restating, shortening and clearing are refused as RetentionWindowShortened.
    for window in [extended, extended - 1, 1u64, 0u64] {
        assert_eq!(
            client.try_set_retention_override(&COMPANY, &KIND, &window),
            Err(Ok(RetentionError::RetentionWindowShortened)),
            "window {window}"
        );
    }
    // A paused contract refuses everything, including a valid extension.
    let pm = pause(&env, &admin, &client);
    assert_eq!(
        client.try_set_retention_override(&COMPANY, &KIND, &(extended + 1)),
        Err(Ok(RetentionError::Paused))
    );
    pm.unpause();

    assert_eq!(window_now(&env, &client, 1), extended);
}

#[test]
fn a_refused_update_for_one_company_does_not_touch_another() {
    let (env, _admin, client) = setup();
    let other = COMPANY + 1;
    let extended = FINALIZED_RETENTION_SECS + 7;
    client.set_retention_override(&other, &KIND, &extended);

    let _ = client.try_set_retention_override(&COMPANY, &KIND, &1u64);

    let record = client.register_record(&other, &1u64, &KIND);
    assert_eq!(record.eligible_after - record.registered_at, extended);
    assert_eq!(window_now(&env, &client, 1), FINALIZED_RETENTION_SECS);
}

#[test]
fn errors_name_neither_the_company_nor_the_record_type() {
    let (env, admin, client) = setup();
    client.set_retention_override(&COMPANY, &KIND, &(FINALIZED_RETENTION_SECS + 1));

    let shortened = client.try_set_retention_override(&COMPANY, &KIND, &1u64);
    assert_eq!(
        format!("{:?}", shortened),
        "Err(Ok(RetentionWindowShortened))"
    );

    let _pm = pause(&env, &admin, &client);
    let paused = client.try_set_retention_override(&COMPANY, &KIND, &u64::MAX);
    assert_eq!(format!("{:?}", paused), "Err(Ok(Paused))");
    assert!(!format!("{:?}", paused).contains("41"));
}

#[test]
fn a_caller_who_is_not_the_admin_is_refused_by_the_host_not_by_a_retention_error() {
    let (env, _admin, client) = setup();
    // No authorisation is mocked from now on, so the admin's own check cannot pass.
    env.set_auths(&[]);

    let result =
        client.try_set_retention_override(&COMPANY, &KIND, &(FINALIZED_RETENTION_SECS + 1));

    assert!(matches!(result, Err(Err(_))));
    env.mock_all_auths();
    assert_eq!(window_now(&env, &client, 1), FINALIZED_RETENTION_SECS);
}
