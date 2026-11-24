//! Safe, actionable errors for administrative pause state (issue #996).
//!
//! The preflight query returns stable typed errors instead of panic strings,
//! so clients can explain failures without revealing payroll data.

mod common;

use common::{initialized, uninitialized};
use pause_manager::{PauseAction, PauseCategory, PauseError, PauseManagerClient};
use soroban_sdk::testutils::Address as _;

/// The generated `try_` client returns a nested result: the outer layer is a
/// host/invoke failure and the inner layer is the contract error.
fn preflight(client: &PauseManagerClient<'_>, action: &PauseAction) -> Result<(), PauseError> {
    match client.try_check_pause_action(action) {
        Ok(Ok(())) => Ok(()),
        Err(Ok(error)) => Err(error),
        _ => panic!("unexpected host-level preflight failure"),
    }
}

#[test]
fn test_safe_messages_are_actionable_and_contain_no_payroll_data() {
    for error in [
        PauseError::NotInitialized,
        PauseError::AlreadyInitialized,
        PauseError::UnauthorizedOperator,
        PauseError::PendingRotationExists,
        PauseError::NoPendingRotation,
        PauseError::InvalidRotationTarget,
    ] {
        let message = error.message();
        assert!(!message.is_empty());
        assert!(!message.to_lowercase().contains("salary"));
        assert!(!message.to_lowercase().contains("employee"));
        assert!(!message.to_lowercase().contains("commitment"));
    }

    assert_eq!(PauseError::NotInitialized as u32, 1);
    assert_eq!(PauseError::InvalidRotationTarget as u32, 6);
}

#[test]
fn test_actions_before_initialization_report_not_initialized() {
    let (env, id) = uninitialized();
    let client = PauseManagerClient::new(&env, &id);
    let address = soroban_sdk::Address::generate(&env);

    for action in [
        PauseAction::Initialize,
        PauseAction::Pause,
        PauseAction::Unpause,
        PauseAction::PauseCategory(PauseCategory::Payroll),
        PauseAction::UnpauseCategory(PauseCategory::Audit),
        PauseAction::ProposeOperatorRotation(address.clone(), address.clone()),
        PauseAction::AcceptOperatorRotation(address.clone()),
        PauseAction::CancelOperatorRotation(address),
    ] {
        assert_eq!(preflight(&client, &action), Err(PauseError::NotInitialized));
    }
}

#[test]
fn test_pause_and_category_actions_are_allowed_once_initialized() {
    let (env, id, _operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    assert_eq!(preflight(&client, &PauseAction::Pause), Ok(()));
    assert_eq!(preflight(&client, &PauseAction::Unpause), Ok(()));
    for category in [
        PauseCategory::Payroll,
        PauseCategory::Treasury,
        PauseCategory::Audit,
        PauseCategory::Admin,
    ] {
        assert_eq!(preflight(&client, &PauseAction::PauseCategory(category)), Ok(()));
        assert_eq!(preflight(&client, &PauseAction::UnpauseCategory(category)), Ok(()));
    }
    assert_eq!(
        preflight(&client, &PauseAction::Initialize),
        Err(PauseError::AlreadyInitialized),
    );
}

#[test]
fn test_propose_rotation_reports_unauthorized_wrong_caller() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let attacker = soroban_sdk::Address::generate(&env);
    let new_operator = soroban_sdk::Address::generate(&env);

    assert_eq!(
        preflight(
            &client,
            &PauseAction::ProposeOperatorRotation(attacker, new_operator),
        ),
        Err(PauseError::UnauthorizedOperator),
    );
    assert_eq!(client.get_operator(), operator);
}

#[test]
fn test_propose_rotation_rejects_current_operator_as_target() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);

    assert_eq!(
        preflight(
            &client,
            &PauseAction::ProposeOperatorRotation(operator.clone(), operator),
        ),
        Err(PauseError::InvalidRotationTarget),
    );
    assert!(client.get_pending_operator_rotation().is_none());
}

#[test]
fn test_duplicate_pending_rotation_reports_pending_rotation_exists() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);
    let another = soroban_sdk::Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);
    assert_eq!(
        preflight(
            &client,
            &PauseAction::ProposeOperatorRotation(operator, another),
        ),
        Err(PauseError::PendingRotationExists),
    );
}

#[test]
fn test_accept_rotation_reports_specific_errors() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);
    let stranger = soroban_sdk::Address::generate(&env);

    assert_eq!(
        preflight(&client, &PauseAction::AcceptOperatorRotation(new_operator.clone())),
        Err(PauseError::NoPendingRotation),
    );

    client.propose_operator_rotation(&operator, &new_operator);
    assert_eq!(
        preflight(&client, &PauseAction::AcceptOperatorRotation(new_operator)),
        Ok(()),
    );
    assert_eq!(
        preflight(&client, &PauseAction::AcceptOperatorRotation(stranger)),
        Err(PauseError::UnauthorizedOperator),
    );
}

#[test]
fn test_cancel_rotation_reports_specific_errors() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);
    let attacker = soroban_sdk::Address::generate(&env);

    assert_eq!(
        preflight(&client, &PauseAction::CancelOperatorRotation(operator.clone())),
        Err(PauseError::NoPendingRotation),
    );

    client.propose_operator_rotation(&operator, &new_operator);
    assert_eq!(
        preflight(&client, &PauseAction::CancelOperatorRotation(operator)),
        Ok(()),
    );
    assert_eq!(
        preflight(&client, &PauseAction::CancelOperatorRotation(attacker)),
        Err(PauseError::UnauthorizedOperator),
    );
}

#[test]
fn test_preflight_does_not_mutate_pause_or_rotation_state() {
    let (env, id, operator) = initialized();
    let client = PauseManagerClient::new(&env, &id);
    let new_operator = soroban_sdk::Address::generate(&env);

    client.propose_operator_rotation(&operator, &new_operator);
    let before_status = client.get_pause_status();

    let _ = preflight(&client, &PauseAction::Pause);
    let _ = preflight(&client, &PauseAction::AcceptOperatorRotation(new_operator.clone()));

    let after_status = client.get_pause_status();
    assert_eq!(after_status.payroll_paused, before_status.payroll_paused);
    assert_eq!(after_status.admin_paused, before_status.admin_paused);
    let proposal = client
        .get_pending_operator_rotation()
        .expect("rotation must remain pending");
    assert_eq!(proposal.new_operator, new_operator);
    assert_eq!(proposal.proposed_by, operator);
    assert!(!client.is_paused());
}
