//! Regression coverage for employer role changes (#949).
//!
//! These tests pin the observable behaviour of the two-step handoff,
//! revocation and read helpers after a role change. They complement the
//! hostile cases in `employer_role_adversarial.rs` by asserting the exact
//! post-transition state, timestamps and cross-company isolation that SDK
//! clients rely on.
//!
//! No salary, employee, commitment or payment data appears in this file.

use access_control::{
    accept_employer_role_transfer, cancel_employer_role_transfer, get_employer_role,
    get_pending_transfer, is_active_employer, propose_employer_role_transfer, register_employer,
    require_active_employer, revoke_employer_role, EmployerRoleError,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

fn setup() -> (Env, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let employer = Address::generate(&env);
    let company_id = 1u64;
    register_employer(&env, company_id, &employer);
    (env, company_id, employer)
}

fn advance(env: &Env, timestamp: u64) {
    env.ledger().with_mut(|ledger| ledger.timestamp = timestamp);
}

#[test]
fn registered_role_starts_active_and_records_the_timestamp() {
    let env = Env::default();
    env.mock_all_auths();
    advance(&env, 100);
    let employer = Address::generate(&env);
    register_employer(&env, 7, &employer);

    let record = get_employer_role(&env, 7);
    assert_eq!(record.employer, employer);
    assert!(!record.revoked);
    assert_eq!(record.last_changed_at, 100);
    assert!(is_active_employer(&env, 7, &employer));
    require_active_employer(&env, 7, &employer);
}

#[test]
fn proposal_keeps_its_target_and_timestamp_until_accepted() {
    let (env, company_id, employer) = setup();
    advance(&env, 200);
    let incoming = Address::generate(&env);

    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    let proposal = get_pending_transfer(&env, company_id).expect("proposal must be stored");
    assert_eq!(proposal.incoming, incoming);
    assert_eq!(proposal.initiated_by, employer);
    assert_eq!(proposal.proposed_at, 200);

    // The base role is unchanged while the handoff is in flight.
    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, employer);
    assert_eq!(record.last_changed_at, 0);
    assert!(!record.revoked);
}

#[test]
fn acceptance_is_atomic_and_updates_the_change_timestamp() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    advance(&env, 300);

    accept_employer_role_transfer(&env, company_id, &incoming);

    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, incoming);
    assert!(!record.revoked);
    assert_eq!(record.last_changed_at, 300);
    assert!(get_pending_transfer(&env, company_id).is_none());
    assert!(!is_active_employer(&env, company_id, &employer));
    assert!(is_active_employer(&env, company_id, &incoming));
}

#[test]
fn an_accepted_transfer_cannot_be_replayed() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    accept_employer_role_transfer(&env, company_id, &incoming);

    let result = std::panic::catch_unwind(|| {
        accept_employer_role_transfer(&env, company_id, &incoming);
    });
    assert!(result.is_err(), "acceptance must not be replayable");
    assert_eq!(get_employer_role(&env, company_id).employer, incoming);
}

#[test]
fn cancellation_clears_only_the_pending_transfer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);

    cancel_employer_role_transfer(&env, company_id, &employer);

    assert!(get_pending_transfer(&env, company_id).is_none());
    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, employer);
    assert!(!record.revoked);
    assert!(is_active_employer(&env, company_id, &employer));

    let replay = std::panic::catch_unwind(|| {
        cancel_employer_role_transfer(&env, company_id, &employer);
    });
    assert!(replay.is_err(), "cancellation must not be replayable");
}

#[test]
fn revocation_preserves_the_employer_record_and_blocks_authorization() {
    let (env, company_id, employer) = setup();
    advance(&env, 400);

    revoke_employer_role(&env, company_id, &employer);

    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, employer);
    assert!(record.revoked);
    assert_eq!(record.last_changed_at, 400);
    assert!(!is_active_employer(&env, company_id, &employer));

    let result = std::panic::catch_unwind(|| {
        require_active_employer(&env, company_id, &employer);
    });
    assert!(result.is_err(), "revoked employer must not be authorized");
}

#[test]
fn role_changes_are_isolated_between_companies() {
    let env = Env::default();
    env.mock_all_auths();
    let employer_a = Address::generate(&env);
    let employer_b = Address::generate(&env);
    let incoming = Address::generate(&env);

    register_employer(&env, 1, &employer_a);
    register_employer(&env, 2, &employer_b);

    propose_employer_role_transfer(&env, 1, &employer_a, &incoming);
    assert!(get_pending_transfer(&env, 2).is_none());
    assert_eq!(get_employer_role(&env, 2).employer, employer_b);

    accept_employer_role_transfer(&env, 1, &incoming);
    assert_eq!(get_employer_role(&env, 1).employer, incoming);
    assert_eq!(get_employer_role(&env, 2).employer, employer_b);
    assert!(is_active_employer(&env, 2, &employer_b));
    assert!(!is_active_employer(&env, 2, &incoming));
}

#[test]
fn error_contract_is_stable_for_sdk_consumers() {
    let cases = [
        (EmployerRoleError::CompanyNotFound, 800u32),
        (EmployerRoleError::UnauthorizedEmployer, 801),
        (EmployerRoleError::PendingTransferExists, 802),
        (EmployerRoleError::NoPendingTransfer, 803),
        (EmployerRoleError::InvalidTransferTarget, 804),
        (EmployerRoleError::EmployerRevoked, 805),
        (EmployerRoleError::SelfTransferNotAllowed, 806),
        (EmployerRoleError::AlreadyActive, 807),
    ];

    for (error, code) in cases {
        assert_eq!(error as u32, code);
        assert!(!error.message().is_empty());
    }
}
