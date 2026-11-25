//! Adversarial tests for employer role changes (issue #953).
//!
//! Every test targets a distinct attack or mis-use vector documented in
//! `EMPLOYER_ROLE_INVARIANTS.md`.  The suite is intentionally hostile: it
//! attempts every plausible unauthorized operation before confirming that the
//! underlying state is unmodified.
//!
//! # Design constraints
//! * No salary, employee, commitment, or payment data appears anywhere in
//!   this file — not in variable names, not in assertions, and not in panic
//!   messages.  Violations would breach the privacy contract (INV-PRI-1).
//! * Each test configures its own `Env` so tests are fully independent.
//! * `env.mock_all_auths()` is used only where the test is explicitly
//!   verifying non-authorization behavior.  For authorization rejection tests
//!   we let the host deny the auth naturally or use `try_*` returns.

use access_control::{
    accept_employer_role_transfer, cancel_employer_role_transfer, get_employer_role,
    get_pending_transfer, is_active_employer, propose_employer_role_transfer,
    register_employer, require_active_employer, revoke_employer_role, EmployerRoleError,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────���──────────────────────────────────────────────────────────────────────

/// Set up a fresh environment with one registered employer and return
/// `(env, company_id, employer_address)`.
fn setup() -> (Env, u64, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let employer = Address::generate(&env);
    let company_id: u64 = 1;
    register_employer(&env, company_id, &employer);
    (env, company_id, employer)
}

// ─────────────────────────────────────────────────────────────────────────────
// § 1  Error messages are actionable and carry no private payroll data
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_error_messages_are_actionable_and_contain_no_private_data() {
    let private_terms = ["salary", "employee", "commitment", "amount", "hash"];

    for variant in [
        EmployerRoleError::CompanyNotFound,
        EmployerRoleError::UnauthorizedEmployer,
        EmployerRoleError::PendingTransferExists,
        EmployerRoleError::NoPendingTransfer,
        EmployerRoleError::InvalidTransferTarget,
        EmployerRoleError::EmployerRevoked,
        EmployerRoleError::SelfTransferNotAllowed,
        EmployerRoleError::AlreadyActive,
    ] {
        let msg = variant.message();
        assert!(!msg.is_empty(), "error message must not be empty: {variant:?}");
        for term in &private_terms {
            assert!(
                !msg.to_lowercase().contains(term),
                "error message for {variant:?} leaks private term '{term}': {msg}"
            );
        }
    }

    // Stable numeric codes (INV: codes must not shift)
    assert_eq!(EmployerRoleError::CompanyNotFound as u32, 800);
    assert_eq!(EmployerRoleError::UnauthorizedEmployer as u32, 801);
    assert_eq!(EmployerRoleError::PendingTransferExists as u32, 802);
    assert_eq!(EmployerRoleError::NoPendingTransfer as u32, 803);
    assert_eq!(EmployerRoleError::InvalidTransferTarget as u32, 804);
    assert_eq!(EmployerRoleError::EmployerRevoked as u32, 805);
    assert_eq!(EmployerRoleError::SelfTransferNotAllowed as u32, 806);
    assert_eq!(EmployerRoleError::AlreadyActive as u32, 807);
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2  Registration adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_double_registration_is_rejected() {
    let (env, company_id, employer) = setup();
    // A second registration for the same company must fail.
    register_employer(&env, company_id, &employer);
}

#[test]
fn test_absent_role_record_is_not_active() {
    let env = Env::default();
    env.mock_all_auths();
    let address = Address::generate(&env);
    // Company 99 was never registered.
    assert!(!is_active_employer(&env, 99, &address));
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3  require_active_employer: unauthorized callers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_third_party_cannot_pass_require_active_employer() {
    let (env, company_id, _employer) = setup();
    let attacker = Address::generate(&env);
    require_active_employer(&env, company_id, &attacker);
}

#[test]
#[should_panic]
fn test_revoked_employer_cannot_pass_require_active_employer() {
    let (env, company_id, employer) = setup();
    revoke_employer_role(&env, company_id, &employer);
    // Should panic with EmployerRevoked even though address matches.
    require_active_employer(&env, company_id, &employer);
}

#[test]
#[should_panic]
fn test_nonexistent_company_panics_in_require_active_employer() {
    let env = Env::default();
    env.mock_all_auths();
    let address = Address::generate(&env);
    require_active_employer(&env, 42, &address);
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4  Transfer proposal: adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_attacker_cannot_propose_transfer() {
    let (env, company_id, _employer) = setup();
    let attacker = Address::generate(&env);
    let new_employer = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &attacker, &new_employer);
}

#[test]
#[should_panic]
fn test_self_transfer_is_rejected() {
    let (env, company_id, employer) = setup();
    // Proposing a transfer to oneself must fail with SelfTransferNotAllowed.
    propose_employer_role_transfer(&env, company_id, &employer, &employer);
}

#[test]
#[should_panic]
fn test_duplicate_proposal_is_rejected() {
    let (env, company_id, employer) = setup();
    let incoming_a = Address::generate(&env);
    let incoming_b = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming_a);
    // A second proposal while the first is pending must fail.
    propose_employer_role_transfer(&env, company_id, &employer, &incoming_b);
}

#[test]
#[should_panic]
fn test_revoked_employer_cannot_propose_transfer() {
    let (env, company_id, employer) = setup();
    revoke_employer_role(&env, company_id, &employer);
    let new_employer = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &new_employer);
}

#[test]
fn test_failed_proposal_does_not_create_pending_record() {
    let (env, company_id, _employer) = setup();
    let attacker = Address::generate(&env);
    let new_employer = Address::generate(&env);

    let result = std::panic::catch_unwind(|| {
        propose_employer_role_transfer(&env, company_id, &attacker, &new_employer);
    });
    assert!(result.is_err(), "attacker proposal should panic");
    assert!(
        get_pending_transfer(&env, company_id).is_none(),
        "failed proposal must not create a pending transfer record"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5  Transfer acceptance: adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_acceptance_without_pending_transfer_panics() {
    let (env, company_id, _employer) = setup();
    let stranger = Address::generate(&env);
    accept_employer_role_transfer(&env, company_id, &stranger);
}

#[test]
#[should_panic]
fn test_wrong_address_cannot_accept_transfer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    let attacker = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    // Attacker uses their own address; must be rejected with InvalidTransferTarget.
    accept_employer_role_transfer(&env, company_id, &attacker);
}

#[test]
#[should_panic]
fn test_original_employer_cannot_accept_their_own_transfer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    // The proposing employer tries to accept in place of the named incoming.
    accept_employer_role_transfer(&env, company_id, &employer);
}

#[test]
fn test_failed_acceptance_leaves_state_unchanged() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    let attacker = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);

    let _ = std::panic::catch_unwind(|| {
        accept_employer_role_transfer(&env, company_id, &attacker);
    });

    // Role record must still point at the original employer.
    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, employer, "employer must not change after a failed acceptance");
    // Pending transfer must still exist.
    assert!(
        get_pending_transfer(&env, company_id).is_some(),
        "pending transfer must remain after a failed acceptance"
    );
}

#[test]
#[should_panic]
fn test_acceptance_blocked_when_role_is_revoked_after_proposal() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    // Role is revoked while the transfer is in-flight.
    revoke_employer_role(&env, company_id, &employer);
    // Acceptance must now fail.
    accept_employer_role_transfer(&env, company_id, &incoming);
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6  Transfer cancellation: adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_cancellation_without_pending_transfer_panics() {
    let (env, company_id, employer) = setup();
    cancel_employer_role_transfer(&env, company_id, &employer);
}

#[test]
#[should_panic]
fn test_incoming_cannot_cancel_pending_transfer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    // The named incoming tries to cancel before accepting.
    cancel_employer_role_transfer(&env, company_id, &incoming);
}

#[test]
#[should_panic]
fn test_third_party_cannot_cancel_pending_transfer() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    let attacker = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    cancel_employer_role_transfer(&env, company_id, &attacker);
}

#[test]
fn test_cancelled_transfer_cannot_be_accepted_afterwards() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &incoming);
    cancel_employer_role_transfer(&env, company_id, &employer);

    // Pending record must be gone.
    assert!(get_pending_transfer(&env, company_id).is_none());

    // Acceptance attempt must fail.
    let result = std::panic::catch_unwind(|| {
        accept_employer_role_transfer(&env, company_id, &incoming);
    });
    assert!(result.is_err(), "acceptance of a cancelled transfer must panic");
    // Role unchanged.
    assert_eq!(get_employer_role(&env, company_id).employer, employer);
}

// ─────────────────────────────────────────────────────────────────────────────
// § 7  Revocation: adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[should_panic]
fn test_third_party_cannot_revoke_employer() {
    let (env, company_id, _employer) = setup();
    let attacker = Address::generate(&env);
    revoke_employer_role(&env, company_id, &attacker);
}

#[test]
#[should_panic]
fn test_double_revocation_is_rejected() {
    let (env, company_id, employer) = setup();
    revoke_employer_role(&env, company_id, &employer);
    // Second revocation must panic, not silently succeed.
    revoke_employer_role(&env, company_id, &employer);
}

#[test]
fn test_revoked_employer_is_blocked_from_all_state_mutations() {
    let (env, company_id, employer) = setup();
    revoke_employer_role(&env, company_id, &employer);

    let new_employer = Address::generate(&env);

    // propose transfer
    let result = std::panic::catch_unwind(|| {
        propose_employer_role_transfer(&env, company_id, &employer, &new_employer);
    });
    assert!(result.is_err(), "revoked employer must not propose a transfer");

    // cancel transfer (none exists, but the revocation check comes first)
    let result = std::panic::catch_unwind(|| {
        cancel_employer_role_transfer(&env, company_id, &employer);
    });
    assert!(result.is_err(), "revoked employer must not cancel a transfer");

    // require_active_employer
    let result = std::panic::catch_unwind(|| {
        require_active_employer(&env, company_id, &employer);
    });
    assert!(result.is_err(), "revoked employer must not pass require_active_employer");

    // is_active_employer must return false
    assert!(!is_active_employer(&env, company_id, &employer));
}

#[test]
fn test_revocation_does_not_alter_history_or_delete_record() {
    let (env, company_id, employer) = setup();
    revoke_employer_role(&env, company_id, &employer);

    let record = get_employer_role(&env, company_id);
    // The employer address is preserved in the record.
    assert_eq!(record.employer, employer);
    // The revoked flag is set.
    assert!(record.revoked);
    // last_changed_at is non-zero (updated at revocation time).
    assert!(record.last_changed_at > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// § 8  Happy path: full transfer lifecycle (regression guard)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_full_transfer_lifecycle_succeeds() {
    let (env, company_id, employer) = setup();
    let incoming = Address::generate(&env);

    propose_employer_role_transfer(&env, company_id, &employer, &incoming);

    let proposal = get_pending_transfer(&env, company_id)
        .expect("pending transfer must exist after proposal");
    assert_eq!(proposal.incoming, incoming);
    assert_eq!(proposal.initiated_by, employer);

    accept_employer_role_transfer(&env, company_id, &incoming);

    // After acceptance the role belongs to `incoming`.
    let record = get_employer_role(&env, company_id);
    assert_eq!(record.employer, incoming);
    assert!(!record.revoked);

    // Pending record is cleared.
    assert!(get_pending_transfer(&env, company_id).is_none());

    // Old employer is no longer active.
    assert!(!is_active_employer(&env, company_id, &employer));
    // New employer is active.
    assert!(is_active_employer(&env, company_id, &incoming));
}

#[test]
fn test_new_employer_can_act_after_accepted_transfer() {
    let (env, company_id, employer) = setup();
    let new_employer = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &new_employer);
    accept_employer_role_transfer(&env, company_id, &new_employer);

    // The new employer should pass require_active_employer without panicking.
    require_active_employer(&env, company_id, &new_employer);
}

#[test]
fn test_old_employer_cannot_act_after_accepted_transfer() {
    let (env, company_id, employer) = setup();
    let new_employer = Address::generate(&env);
    propose_employer_role_transfer(&env, company_id, &employer, &new_employer);
    accept_employer_role_transfer(&env, company_id, &new_employer);

    let result = std::panic::catch_unwind(|| {
        require_active_employer(&env, company_id, &employer);
    });
    assert!(result.is_err(), "old employer must be rejected after transfer completes");
}

// ─────────────────────────────────────────────────────────────────────────────
// § 9  Chained transfers (new employer can re-transfer)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_new_employer_can_propose_a_further_transfer() {
    let (env, company_id, employer_a) = setup();
    let employer_b = Address::generate(&env);
    let employer_c = Address::generate(&env);

    propose_employer_role_transfer(&env, company_id, &employer_a, &employer_b);
    accept_employer_role_transfer(&env, company_id, &employer_b);

    // employer_b now owns the role and can transfer it onward.
    propose_employer_role_transfer(&env, company_id, &employer_b, &employer_c);
    accept_employer_role_transfer(&env, company_id, &employer_c);

    assert!(is_active_employer(&env, company_id, &employer_c));
    assert!(!is_active_employer(&env, company_id, &employer_b));
    assert!(!is_active_employer(&env, company_id, &employer_a));
}
