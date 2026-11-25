//! Adversarial tests for administrative pause state (issue #998).
//!
//! Focus: an attacker who can sign their own transactions must never be able
//! to pause, unpause, or take over the operator role. Every check uses an
//! explicit single-signer auth mock so a stray `mock_all_auths()` cannot hide
//! an authorization gap.

mod common;

use common::{initialized, mock_signer, no_args, uninitialized};
use pause_manager::{PauseCategory, PauseManagerClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, IntoVal};

#[test]
fn test_attacker_cannot_pause_or_unpause_globally() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let attacker = Address::generate(&env);

    mock_signer(&env, &id, &attacker, "pause", no_args(&env));
    assert!(client.try_pause().is_err());
    assert!(!client.is_paused());

    // Let the real operator pause so the attacker's unpause has a target.
    env.mock_all_auths();
    client.pause();
    assert!(client.is_paused());

    mock_signer(&env, &id, &attacker, "unpause", no_args(&env));
    assert!(client.try_unpause().is_err());
    assert!(client.is_paused());
}

#[test]
fn test_attacker_cannot_pause_or_unpause_any_category() {
    for category in [
        PauseCategory::Payroll,
        PauseCategory::Treasury,
        PauseCategory::Audit,
        PauseCategory::Admin,
    ] {
        let (env, id, _operator) = initialized();
        let client = PauseManagerClient::new(&env, &id);
        let attacker = Address::generate(&env);

        mock_signer(
            &env,
            &id,
            &attacker,
            "pause_category",
            (category,).into_val(&env),
        );
        assert!(client.try_pause_category(&category).is_err());
        assert!(!client.is_category_paused(&category));

        env.mock_all_auths();
        client.pause_category(&category);

        mock_signer(
            &env,
            &id,
            &attacker,
            "unpause_category",
            (category,).into_val(&env),
        );
        assert!(client.try_unpause_category(&category).is_err());
        assert!(client.is_category_paused(&category));
    }
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the current operator")]
fn test_attacker_cannot_propose_operator_rotation() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let attacker = Address::generate(&env);
    let new_operator = Address::generate(&env);

    mock_signer(
        &env,
        &id,
        &attacker,
        "propose_operator_rotation",
        (attacker.clone(), new_operator).into_val(&env),
    );
    client.propose_operator_rotation(&attacker, &Address::generate(&env));
}

#[test]
#[should_panic(expected = "Unauthorized: caller is not the proposed operator")]
fn test_attacker_cannot_accept_a_rotation_meant_for_someone_else() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = Address::generate(&env);
    let attacker = Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);

    mock_signer(
        &env,
        &id,
        &attacker,
        "accept_operator_rotation",
        (attacker.clone(),).into_val(&env),
    );
    client.accept_operator_rotation(&attacker);
}

#[test]
#[should_panic(expected = "authorized")]
fn test_proposed_operator_signatures_are_still_required_to_accept() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = Address::generate(&env);
    let attacker = Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);

    // The argument names the correct proposed operator, but the signature
    // comes from an attacker; require_auth must still reject it.
    mock_signer(
        &env,
        &id,
        &attacker,
        "accept_operator_rotation",
        (new_operator.clone(),).into_val(&env),
    );
    client.accept_operator_rotation(&new_operator);
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_attacker_cannot_cancel_a_pending_rotation() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = Address::generate(&env);
    let attacker = Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);

    mock_signer(
        &env,
        &id,
        &attacker,
        "cancel_operator_rotation",
        (attacker.clone(),).into_val(&env),
    );
    client.cancel_operator_rotation(&attacker);
}

#[test]
fn test_reinitialization_cannot_reset_or_rotate_the_operator() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let attacker = Address::generate(&env);

    mock_signer(
        &env,
        &id,
        &attacker,
        "initialize",
        (attacker.clone(),).into_val(&env),
    );
    assert!(client.try_initialize(&attacker).is_err());
    assert_eq!(client.get_operator(), operator);
}

#[test]
fn test_accepting_a_cancelled_rotation_is_rejected() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);
    client.cancel_operator_rotation(&operator);

    assert!(client.try_accept_operator_rotation(&new_operator).is_err());
    assert_eq!(client.get_operator(), operator);
    assert!(client.get_pending_operator_rotation().is_none());
}

#[test]
fn test_old_operator_cannot_act_after_rotation_despite_existing_pause_state() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = Address::generate(&env);

    client.pause_category(&PauseCategory::Payroll);
    client.propose_operator_rotation(&operator, &new_operator);
    client.accept_operator_rotation(&new_operator);

    mock_signer(&env, &id, &operator, "pause", no_args(&env));
    assert!(client.try_pause().is_err());
    assert!(client.is_category_paused(&PauseCategory::Payroll));
    assert_eq!(client.get_operator(), new_operator);
}

#[test]
fn test_uninitialized_mutating_calls_fail_without_creating_state() {
    let (env, id) = uninitialized();
    let client = PauseManagerClient::new(&env, &id);
    let attacker = Address::generate(&env);

    mock_signer(&env, &id, &attacker, "pause", no_args(&env));
    assert!(client.try_pause().is_err());
    // The failed call did not leave a half-configured operator behind.
    assert!(!client.is_paused());
    assert!(client
        .try_check_pause_action(&pause_manager::PauseAction::Pause)
        .is_err());
}
