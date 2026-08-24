//! End-to-end checks that payroll execution respects employee status
//! transitions (issue #249).
//!
//! `payment_executor::execute_payment` must consult the registry before
//! moving funds: only registered employees whose status is `Active` are
//! payable. Suspended (`Inactive`), flagged (`Incomplete`), removed, and
//! never-registered employees are rejected with
//! [`PaymentError::EmployeeIneligible`] and no token transfer takes place.
//!
//! [`PaymentError::EmployeeIneligible`]: payment_executor::PaymentError::EmployeeIneligible

use crate::common::{commitment, TestEnv, PAYMENT_AMOUNT};
use payment_executor::PaymentError;
use payroll_registry::EmployeeStatus;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN};

/// Distinct Groth16 placeholder proofs; the mock verifier accepts them all.
struct Proofs {
    a: BytesN<64>,
    b: BytesN<128>,
    c: BytesN<64>,
    nullifier: BytesN<32>,
}

fn proofs(env: &soroban_sdk::Env, seed: u8) -> Proofs {
    Proofs {
        a: BytesN::from_array(env, &[seed; 64]),
        b: BytesN::from_array(env, &[seed; 128]),
        c: BytesN::from_array(env, &[seed.wrapping_add(1); 64]),
        nullifier: BytesN::from_array(env, &[seed.wrapping_add(2); 32]),
    }
}

/// Pay `employee` through the executor as the company admin.
fn pay(t: &TestEnv, company_id: u64, employee: &Address, seed: u8) {
    let p = proofs(&t.env, seed);
    t.executor()
        .execute_payment(
            &company_id,
            employee,
            &PAYMENT_AMOUNT,
            &p.a,
            &p.b,
            &p.c,
            &p.nullifier,
            &1u32,
        );
}

/// Expect [`PaymentError::EmployeeIneligible`] from a payment attempt.
fn expect_ineligible(t: &TestEnv, company_id: u64, employee: &Address, seed: u8) {
    let p = proofs(&t.env, seed);
    let result = t.executor().try_execute_payment(
        &company_id,
        employee,
        &PAYMENT_AMOUNT,
        &p.a,
        &p.b,
        &p.c,
        &p.nullifier,
        &1u32,
    );

    assert_eq!(
        result.unwrap_err().unwrap(),
        PaymentError::EmployeeIneligible,
        "ineligible employees must be blocked from payroll"
    );
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

/// An Active employee is paid normally: funds move treasury → employee and
/// the payment is recorded for the period.
#[test]
fn active_employee_is_paid() {
    let t = TestEnv::new();
    let (company_id, _admin, treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 20);
    t.open_period(company_id);

    pay(&t, company_id, &employee, 100);

    assert_eq!(t.token().balance(&employee), PAYMENT_AMOUNT);
    assert_eq!(
        t.token().balance(&treasury),
        crate::common::TREASURY_FUNDING - PAYMENT_AMOUNT
    );
    assert!(t.executor().is_paid(&employee, &1));
}

// ---------------------------------------------------------------------------
// Blocked employees
// ---------------------------------------------------------------------------

/// Deactivating an employee blocks their payment: nothing transfers and the
/// period shows no payment for them.
#[test]
fn inactive_employee_is_not_paid() {
    let t = TestEnv::new();
    let (company_id, _admin, treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 21);
    t.open_period(company_id);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);

    expect_ineligible(&t, company_id, &employee, 101);

    assert_eq!(t.token().balance(&employee), 0);
    assert_eq!(t.token().balance(&treasury), crate::common::TREASURY_FUNDING);
    assert!(!t.executor().is_paid(&employee, &1));
    assert_eq!(t.executor().get_total_paid(&company_id), 0);
}

/// Employees flagged `Incomplete` are blocked from payroll until their
/// record is corrected.
#[test]
fn incomplete_employee_is_not_paid() {
    let t = TestEnv::new();
    let (company_id, _admin, treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 22);
    t.open_period(company_id);

    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);

    expect_ineligible(&t, company_id, &employee, 102);

    assert_eq!(t.token().balance(&employee), 0);
    assert_eq!(t.token().balance(&treasury), crate::common::TREASURY_FUNDING);
}

/// Removed employees can never be paid, even though their salary
/// commitment may have been re-registered by an indexer replay.
#[test]
fn removed_employee_is_not_paid() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 23);
    t.open_period(company_id);

    t.registry().remove_employee(&company_id, &employee);

    expect_ineligible(&t, company_id, &employee, 103);
    assert_eq!(t.token().balance(&employee), 0);
}

/// An address holding a stored commitment but absent from the registry has
/// no eligibility either — registry membership gates payroll.
#[test]
fn unregistered_address_is_not_paid() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let outsider = Address::generate(&t.env);

    // Commitment exists, but the registry has no record of this employee.
    t.commitment_store()
        .store_commitment(&outsider, &commitment(&t.env, 24));
    t.open_period(company_id);

    expect_ineligible(&t, company_id, &outsider, 104);
    assert_eq!(t.token().balance(&outsider), 0);
}

// ---------------------------------------------------------------------------
// Reactivation restores payroll access
// ---------------------------------------------------------------------------

/// Suspend → attempt payment → reactivate → payment succeeds. A status
/// round-trip fully restores payroll participation.
#[test]
fn reactivated_employee_is_paid_again() {
    let t = TestEnv::new();
    let (company_id, _admin, treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 25);
    t.open_period(company_id);

    t.set_status(company_id, &employee, EmployeeStatus::Inactive);
    expect_ineligible(&t, company_id, &employee, 105);
    assert_eq!(t.token().balance(&employee), 0);

    t.set_status(company_id, &employee, EmployeeStatus::Active);
    pay(&t, company_id, &employee, 106);

    assert_eq!(t.token().balance(&employee), PAYMENT_AMOUNT);
    assert_eq!(t.token().balance(&treasury), crate::common::TREASURY_FUNDING - PAYMENT_AMOUNT);
    assert!(t.executor().is_paid(&employee, &1));
}

/// Correcting an `Incomplete` record back to `Active` also re-enables
/// payment.
#[test]
fn corrected_incomplete_record_is_payable_again() {
    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let employee = t.add_active_employee(company_id, 26);
    t.open_period(company_id);

    t.set_status(company_id, &employee, EmployeeStatus::Incomplete);
    expect_ineligible(&t, company_id, &employee, 107);

    t.set_status(company_id, &employee, EmployeeStatus::Active);
    pay(&t, company_id, &employee, 108);

    assert_eq!(t.token().balance(&employee), PAYMENT_AMOUNT);
}

// ---------------------------------------------------------------------------
// Batch execution
// ---------------------------------------------------------------------------

/// A batch containing an ineligible employee is rejected outright when the
/// ineligible entry comes first: no employee in the batch is paid.
#[test]
fn batch_containing_inactive_employee_is_rejected() {
    use soroban_sdk::Vec;

    let t = TestEnv::new();
    let (company_id, _admin, _treasury) = t.register_company();
    let inactive_employee = t.add_active_employee(company_id, 27);
    let active_employee = t.add_active_employee(company_id, 28);
    t.open_period(company_id);

    t.set_status(company_id, &inactive_employee, EmployeeStatus::Inactive);

    let employees = Vec::from_array(
        &t.env,
        [inactive_employee.clone(), active_employee.clone()],
    );
    let amounts = Vec::from_array(&t.env, [PAYMENT_AMOUNT, PAYMENT_AMOUNT]);
    let p0 = proofs(&t.env, 109);
    let p1 = proofs(&t.env, 110);
    let proofs_a = Vec::from_array(&t.env, [p0.a, p1.a]);
    let proofs_b = Vec::from_array(&t.env, [p0.b, p1.b]);
    let proofs_c = Vec::from_array(&t.env, [p0.c, p1.c]);
    let nullifiers = Vec::from_array(&t.env, [p0.nullifier, p1.nullifier]);

    let result = t.executor().try_execute_batch_payroll(
        &company_id,
        &employees,
        &amounts,
        &proofs_a,
        &proofs_b,
        &proofs_c,
        &nullifiers,
        &1u32,
    );

    assert_eq!(result.unwrap_err().unwrap(), PaymentError::EmployeeIneligible);

    // Nobody in the batch received funds.
    assert_eq!(t.token().balance(&inactive_employee), 0);
    assert_eq!(t.token().balance(&active_employee), 0);
    assert!(!t.executor().is_paid(&active_employee, &1));
    assert_eq!(t.executor().get_total_paid(&company_id), 0);
}
