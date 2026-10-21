//! Focused coverage for contract execution initiator authorization (#620).
//!
//! The payroll contract exposes a single notion of "who may initiate a contract
//! execution": the registered payroll admin. These tests cover the read-only
//! preflight helpers, the auth-enforcing `validate_execution_initiator`
//! entrypoint, and the enforcement wired into the execution/preparation
//! entrypoints themselves. They also cover execution reference collision
//! prevention: a reference may only be consumed once, and a rejected execution
//! must not burn its reference.

mod common;

use payroll::execution_authorization::ExecutionInitiatorRole;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

// ── Read-only preflight ─────────────────────────────────────────────────────

#[test]
fn initialized_contract_recognizes_the_registered_admin_as_initiator() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let admin = payroll.get_addresses().admin;

    assert_eq!(payroll.get_execution_initiator(), Some(admin.clone()));

    let status = payroll.check_execution_initiator(&admin);
    assert!(status.authorized);
    assert!(status.initialized);
    assert_eq!(status.initiator, admin);
    assert_eq!(status.role, ExecutionInitiatorRole::Authorized);
    assert!(payroll.is_exec_initiator_authorized(&admin));
}

#[test]
fn a_non_admin_address_is_not_authorized() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let outsider = Address::generate(&env);

    let status = payroll.check_execution_initiator(&outsider);
    assert!(!status.authorized);
    assert!(status.initialized);
    assert_eq!(status.role, ExecutionInitiatorRole::Unauthorized);
    assert!(!payroll.is_exec_initiator_authorized(&outsider));
}

#[test]
fn uninitialized_contract_reports_not_initialized() {
    let env = Env::default();
    let payroll_id = env.register_contract(None, payroll::Payroll);
    let client = payroll::PayrollClient::new(&env, &payroll_id);
    let anyone = Address::generate(&env);

    assert_eq!(client.get_execution_initiator(), None);

    let status = client.check_execution_initiator(&anyone);
    assert!(!status.authorized);
    assert!(!status.initialized);
    assert!(!client.is_exec_initiator_authorized(&anyone));
}

#[test]
fn preflight_needs_no_authorization() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let admin = payroll.get_addresses().admin;

    // A dashboard can ask the question without holding any signature.
    env.mock_auths(&[]);
    assert!(payroll.is_exec_initiator_authorized(&admin));
    assert_eq!(payroll.get_execution_initiator(), Some(admin));
}

// ── Auth-enforcing validation entrypoint ────────────────────────────────────

#[test]
fn validate_execution_initiator_accepts_the_admin() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let admin = payroll.get_addresses().admin;

    assert!(payroll.try_validate_execution_initiator(&admin).is_ok());
}

#[test]
#[should_panic(expected = "Unauthorized contract execution initiator")]
fn validate_execution_initiator_rejects_a_non_admin() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let outsider = Address::generate(&env);

    payroll.validate_execution_initiator(&outsider);
}

#[test]
#[should_panic(expected = "Contract not initialized")]
fn validate_execution_initiator_requires_initialization() {
    let env = Env::default();
    let payroll_id = env.register_contract(None, payroll::Payroll);
    let client = payroll::PayrollClient::new(&env, &payroll_id);
    let anyone = Address::generate(&env);

    client.validate_execution_initiator(&anyone);
}

// ── Enforcement at the execution boundary ───────────────────────────────────

#[test]
fn execution_without_initiator_authorization_is_rejected() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let source = common::authorized_source(&env, &payroll);

    // No execution initiator has authorized this call.
    env.mock_auths(&[]);
    let result = payroll.try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 21),
        &None,
        &source,
    );

    assert!(result.is_err(), "an execution must be rejected when its initiator is not authorized");
}

#[test]
fn preparation_without_initiator_authorization_is_rejected() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    env.mock_auths(&[]);
    let result = payroll.try_prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 22),
        &None,
    );

    assert!(
        result.is_err(),
        "preparing a run must be rejected when its initiator is not authorized"
    );
}

#[test]
fn bounded_execution_without_initiator_authorization_is_rejected() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    env.mock_auths(&[]);
    let result = payroll.try_batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 23),
        &None,
        &1u32,
    );

    assert!(
        result.is_err(),
        "a bounded execution must be rejected when its initiator is not authorized"
    );
}

// ── Edge case: rotating the admin moves initiator authority ─────────────────

#[test]
fn admin_rotation_moves_execution_initiator_authority() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let previous_admin = payroll.get_addresses().admin;
    let new_admin = Address::generate(&env);

    payroll.propose_admin_rotation(&previous_admin, &new_admin);
    payroll.accept_admin_rotation(&new_admin);

    assert_eq!(payroll.get_execution_initiator(), Some(new_admin.clone()));
    assert!(payroll.is_exec_initiator_authorized(&new_admin));
    assert!(
        !payroll.is_exec_initiator_authorized(&previous_admin),
        "the previous admin must lose initiator authority after rotation"
    );
}

// ── Execution reference collision prevention ────────────────────────────────

#[test]
fn execution_reference_is_consumed_on_success() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let source = common::authorized_source(&env, &payroll);
    let reference = common::nonce(&env, 31);

    assert!(!payroll.is_execution_reference_used(&reference));

    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &reference,
        &None,
        &source,
    );

    assert!(
        payroll.is_execution_reference_used(&reference),
        "a successful execution must consume its reference"
    );
}

#[test]
#[should_panic(expected = "Execution reference already used")]
fn execution_reference_collision_is_rejected() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let source = common::authorized_source(&env, &payroll);
    let reference = common::nonce(&env, 32);

    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &reference,
        &None,
        &source,
    );

    // Reusing the same reference must be rejected, even with valid auth.
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &reference,
        &None,
        &source,
    );
}

#[test]
fn rejected_execution_does_not_consume_its_reference() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let source = common::authorized_source(&env, &payroll);
    let reference = common::nonce(&env, 33);

    // Unauthorized initiator: the call is rejected before the reference is
    // consumed, so the same reference remains usable afterwards.
    env.mock_auths(&[]);
    let rejected = payroll.try_batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &reference,
        &None,
        &source,
    );
    assert!(rejected.is_err());
    assert!(
        !payroll.is_execution_reference_used(&reference),
        "a rejected execution must not burn its reference"
    );

    // The reference is still available for a properly authorized execution.
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100,
        &reference,
        &None,
        &source,
    );
    assert!(payroll.is_execution_reference_used(&reference));
}
