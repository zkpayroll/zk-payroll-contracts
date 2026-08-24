//! Employee status transition matrix tests (issue #249).
//!
//! The registry models three registration states — [`Active`],
//! [`Inactive`], and [`Incomplete`] — plus hard removal. These tests pin
//! down every allowed transition, prove invalid operations are rejected,
//! and document the events emitted along the way.
//!
//! Allowed transitions (all initiated by the company admin via
//! `set_employee_status`):
//!
//! | From        | To          | Event                  |
//! | ----------- | ----------- | ---------------------- |
//! | Active      | Inactive    | `EmployeeDeactivated`  |
//! | Inactive    | Active      | `EmployeeReactivated`  |
//! | Active      | Incomplete  | `EmployeeStatusUpdated`|
//! | Incomplete  | Active      | `EmployeeStatusUpdated`|
//! | Inactive    | Incomplete  | `EmployeeStatusUpdated`|
//! | Incomplete  | Inactive    | `EmployeeStatusUpdated`|
//!
//! Blocked / rejected operations:
//!
//! * any status change for an unregistered employee (`Employee not found`)
//! * any status change under an unknown company (`Company not found`)
//! * same-status writes are silently ignored (no event, no storage churn)
//! * calls that do not carry the company admin's authorization
//! * status changes after removal (the record is gone)
//!
//! [`Active`]: payroll_registry::EmployeeStatus::Active
//! [`Inactive`]: payroll_registry::EmployeeStatus::Inactive
//! [`Incomplete`]: payroll_registry::EmployeeStatus::Incomplete

use crate::common::{commitment, TestEnv};
use payroll_registry::EmployeeStatus;
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, IntoVal, Symbol, TryIntoVal};

// ---------------------------------------------------------------------------
// Allowed transitions
// ---------------------------------------------------------------------------

/// Active → Inactive suspends payroll eligibility while keeping the
/// commitment registered.
#[test]
fn active_to_inactive_suspends_eligibility() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 1);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Inactive
    );
    assert!(!t.registry().is_eligible(&company_id, &employee));
}

/// Inactive → Active reactivates a suspended employee and restores full
/// payroll eligibility without re-registering them.
#[test]
fn inactive_to_active_restores_eligibility() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 2);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    t.set_status(company_id, &employee, EmployeeStatus::Active);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
    assert!(t.registry().is_eligible(&company_id, &employee));
}

/// Active → Incomplete flags a record that lost required data; the employee
/// must stop being eligible immediately.
#[test]
fn active_to_incomplete_blocks_eligibility() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 3);
    assert!(t.registry().is_eligible(&company_id, &employee));

    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Incomplete
    );
    assert!(!t.registry().is_eligible(&company_id, &employee));
}

/// Incomplete → Active is the "record corrected" path back into payroll.
#[test]
fn incomplete_to_active_after_record_correction_is_allowed() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 4);

    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);
    assert!(!t.registry().is_eligible(&company_id, &employee));

    t.set_status(company_id, &employee, EmployeeStatus::Active);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
    assert!(t.registry().is_eligible(&company_id, &employee));
}

/// Inactive → Incomplete lets an admin escalate a suspended record to an
/// explicit data-quality hold; the employee stays ineligible.
#[test]
fn inactive_to_incomplete_stays_ineligible() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 5);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Incomplete
    );
    assert!(!t.registry().is_eligible(&company_id, &employee));
}

/// Incomplete → Inactive downgrades a data-quality hold to a plain
/// suspension; the employee remains ineligible either way.
#[test]
fn incomplete_to_inactive_stays_ineligible() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 6);

    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);
    t.set_status(company_id, &employee, EmployeeStatus::Inactive);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Inactive
    );
    assert!(!t.registry().is_eligible(&company_id, &employee));
}

/// Status changes never disturb the stored salary commitment.
#[test]
fn transitions_preserve_commitment() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 7);
    let expected = commitment(&t.env, 7);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);

    assert_eq!(
        t.registry().get_commitment(&company_id, &employee),
        expected
    );
}

// ---------------------------------------------------------------------------
// Rejected operations
// ---------------------------------------------------------------------------

/// Setting a status for an address that was never added is rejected.
#[test]
fn set_status_for_unregistered_employee_panics() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let stranger = Address::generate(&t.env);

    let result = t
        .registry()
        .try_set_employee_status(&company_id, &stranger, &EmployeeStatus::Inactive);

    assert!(result.is_err(), "unregistered employees have no status to change");
}

/// Status updates under a company id that does not exist are rejected.
#[test]
fn set_status_under_unknown_company_panics() {
    let t = TestEnv::new();
    let (_id, _admin, _treasury) = t.register_company();
    let employee = Address::generate(&t.env);

    let result = t
        .registry()
        .try_set_employee_status(&999u64, &employee, &EmployeeStatus::Inactive);

    assert!(result.is_err());
}

/// Writing the already-current status is a silent no-op: storage keeps its
/// value and no lifecycle event is emitted.
#[test]
fn same_status_write_is_an_idempotent_no_op() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 8);

    let before = t.env.events().all().len();

    t.set_status(company_id, &employee, EmployeeStatus::Active);

    assert_eq!(
        t.env.events().all().len(),
        before,
        "no-op transitions must not emit lifecycle events"
    );
    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
}

/// A non-admin authorization is rejected by the company admin check.
///
/// The mock auth signs the call as `attacker`, so the contract's
/// `require_auth` against the real admin must fail.
#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn set_status_requires_the_company_admin_signature() {
    use soroban_sdk::testutils::MockAuth;
    use soroban_sdk::testutils::MockAuthInvoke;

    let env = soroban_sdk::Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, payroll_registry::PayrollRegistry);
    let registry = payroll_registry::PayrollRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let employee = Address::generate(&env);
    registry.add_employee(&company_id, &employee, &commitment(&env, 9));

    let attacker = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "set_employee_status",
            args: (
                company_id,
                employee.clone(),
                EmployeeStatus::Inactive,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.set_employee_status(&company_id, &employee, &EmployeeStatus::Inactive);
}

// ---------------------------------------------------------------------------
// Removal behaviour
// ---------------------------------------------------------------------------

/// Removing an employee hard-deletes both the commitment and the eligibility
/// status; the employee reads back as `Incomplete` and is never eligible.
#[test]
fn removal_clears_record_and_status() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 10);

    // Deactivate first so a stale `Inactive` value would be observable if
    // removal failed to clear it.
    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    t.registry().remove_employee(&company_id, &employee);

    assert!(!t.registry().is_eligible(&company_id, &employee));
    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Incomplete,
        "removed employees must read back as Incomplete, not keep stale state"
    );

    let result = t.registry().try_get_commitment(&company_id, &employee);
    assert!(result.is_err(), "commitment must be gone after removal");
}

/// Any status change after removal is rejected: removed is terminal.
#[test]
fn set_status_after_removal_panics() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 11);

    t.registry().remove_employee(&company_id, &employee);

    let result = t
        .registry()
        .try_set_employee_status(&company_id, &employee, &EmployeeStatus::Active);

    assert!(result.is_err(), "removed employees cannot be reactivated in place");
}

/// Re-adding a previously removed employee starts a clean lifecycle:
/// fresh `Active` status and restored eligibility.
#[test]
fn readdition_after_removal_starts_fresh_as_active() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 12);

    t.registry().remove_employee(&company_id, &employee);
    assert!(!t.registry().is_eligible(&company_id, &employee));

    let new_commitment = commitment(&t.env, 99);
    t.commitment_store().store_commitment(&employee, &new_commitment);
    t.registry()
        .add_employee(&company_id, &employee, &new_commitment);

    assert_eq!(
        t.registry().get_employee_status(&company_id, &employee),
        EmployeeStatus::Active
    );
    assert!(t.registry().is_eligible(&company_id, &employee));
}

/// Removal emits the `EmployeeRemoved` audit event.
#[test]
fn removal_emits_employee_removed_event() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 13);

    let before = t.env.events().all().len();
    t.registry().remove_employee(&company_id, &employee);
    let after = t.env.events().all().len();
    assert_eq!(after, before + 1);

    let event = t.env.events().all().get(after - 1).unwrap();
    let sym: Symbol = event.1.get(0).unwrap().try_into_val(&t.env).unwrap();
    assert_eq!(sym, Symbol::new(&t.env, "EmployeeRemoved"));
}

// ---------------------------------------------------------------------------
// Lifecycle event payloads
// ---------------------------------------------------------------------------

/// Deactivation emits `EmployeeDeactivated` carrying the previous and new
/// status plus ledger metadata.
#[test]
fn deactivation_event_reports_previous_and_new_status() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 14);

    let before = t.env.events().all().len();
    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    let event = t.env.events().all().get(before).unwrap();

    let sym: Symbol = event.1.get(0).unwrap().try_into_val(&t.env).unwrap();
    assert_eq!(sym, Symbol::new(&t.env, "EmployeeDeactivated"));

    let data_tuple: (EmployeeStatus, EmployeeStatus, u32, u64) =
        event.2.try_into_val(&t.env).unwrap();
    assert_eq!(data_tuple.0, EmployeeStatus::Active);
    assert_eq!(data_tuple.1, EmployeeStatus::Inactive);
}

/// Reactivation emits `EmployeeReactivated` carrying the previous and new
/// status.
#[test]
fn reactivation_event_reports_previous_and_new_status() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 15);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);

    let before = t.env.events().all().len();
    t.set_status(company_id, &employee, EmployeeStatus::Active);
    let event = t.env.events().all().get(before).unwrap();

    let sym: Symbol = event.1.get(0).unwrap().try_into_val(&t.env).unwrap();
    assert_eq!(sym, Symbol::new(&t.env, "EmployeeReactivated"));

    let data_tuple: (EmployeeStatus, EmployeeStatus, u32, u64) =
        event.2.try_into_val(&t.env).unwrap();
    assert_eq!(data_tuple.0, EmployeeStatus::Inactive);
    assert_eq!(data_tuple.1, EmployeeStatus::Active);
}

/// Transitions into or out of `Incomplete` emit the generic
/// `EmployeeStatusUpdated` event.
#[test]
fn incomplete_transition_emits_generic_status_updated_event() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 16);

    let before = t.env.events().all().len();
    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);
    let event = t.env.events().all().get(before).unwrap();

    let sym: Symbol = event.1.get(0).unwrap().try_into_val(&t.env).unwrap();
    assert_eq!(sym, Symbol::new(&t.env, "EmployeeStatusUpdated"));
}
