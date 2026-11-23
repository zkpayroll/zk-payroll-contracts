//! Enforcement and typed errors for reference-id changes (issues #959, #960, #961).
//!
//! A reference id is the HR-system handle of a payee. Once the employee's commitment is locked by
//! an approved or settled payroll run, moving the employee to another id would re-attribute that
//! run after the fact, so the move is refused until the lock is lifted. Every refusal is a typed
//! `BeneficiaryError` that names neither the id nor the employee.
extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::String as SorobanString;
use std::format;

fn setup() -> (Env, SalaryCommitmentContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SalaryCommitmentContract, ());
    let client = SalaryCommitmentContractClient::new(&env, &contract_id);
    client.init_commitment_admin(&Address::generate(&env));
    (env, client)
}

fn id(env: &Env, text: &str) -> SorobanString {
    SorobanString::from_str(env, text)
}

fn with_commitment(env: &Env, client: &SalaryCommitmentContractClient<'static>, n: u8) -> Address {
    let employee = Address::generate(env);
    client.store_commitment(&employee, &BytesN::from_array(env, &[n; 32]));
    employee
}

// ── Error codes ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn error_codes_are_stable() {
    assert_eq!(BeneficiaryError::ReferenceIdTaken as u32, 1);
    assert_eq!(BeneficiaryError::ReferenceIdLocked as u32, 2);
}

// ── Locked employees keep their reference id ────────────────────────────────────────────────────

#[test]
fn locked_employee_cannot_move_to_another_reference_id() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&employee);

    assert_eq!(
        client.try_set_employee_reference_id(&employee, &id(&env, "EMP-2")),
        Err(Ok(BeneficiaryError::ReferenceIdLocked))
    );
}

#[test]
fn a_refused_move_changes_nothing() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&employee);

    let _ = client.try_set_employee_reference_id(&employee, &id(&env, "EMP-2"));

    assert_eq!(
        client.get_employee_reference_id(&employee),
        Some(id(&env, "EMP-1"))
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-1")),
        Some(employee.clone())
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-2")),
        None
    );
}

#[test]
fn the_id_the_refused_move_wanted_stays_free_for_someone_else() {
    let (env, client) = setup();
    let locked = with_commitment(&env, &client, 1);
    let other = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&locked, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&locked);
    let _ = client.try_set_employee_reference_id(&locked, &id(&env, "EMP-2"));

    client.set_employee_reference_id(&other, &id(&env, "EMP-2"));

    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-2")),
        Some(other)
    );
}

#[test]
fn locked_employee_can_restate_the_same_id_in_any_spelling() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&employee);

    assert_eq!(
        client.try_set_employee_reference_id(&employee, &id(&env, "EMP-1")),
        Ok(Ok(()))
    );
    assert_eq!(
        client.try_set_employee_reference_id(&employee, &id(&env, "  emp-1 ")),
        Ok(Ok(()))
    );
    assert_eq!(
        client.get_employee_reference_id(&employee),
        Some(id(&env, "EMP-1"))
    );
}

#[test]
fn locked_employee_without_an_id_can_be_given_a_first_one() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.lock_commitment_updates(&employee);

    assert_eq!(
        client.try_set_employee_reference_id(&employee, &id(&env, "EMP-1")),
        Ok(Ok(()))
    );
}

#[test]
fn unlocking_allows_the_move_and_frees_the_old_id() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&employee);
    client.unlock_commitment_updates(&employee);

    client.set_employee_reference_id(&employee, &id(&env, "EMP-2"));

    assert_eq!(
        client.get_employee_reference_id(&employee),
        Some(id(&env, "EMP-2"))
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-1")),
        None
    );
}

#[test]
fn locking_again_re_arms_the_refusal() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));
    client.lock_commitment_updates(&employee);
    client.unlock_commitment_updates(&employee);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-2"));
    client.lock_commitment_updates(&employee);

    assert_eq!(
        client.try_set_employee_reference_id(&employee, &id(&env, "EMP-3")),
        Err(Ok(BeneficiaryError::ReferenceIdLocked))
    );
}

#[test]
fn one_employees_lock_does_not_pin_another_employee() {
    let (env, client) = setup();
    let locked = with_commitment(&env, &client, 1);
    let free = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&locked, &id(&env, "EMP-1"));
    client.set_employee_reference_id(&free, &id(&env, "EMP-2"));
    client.lock_commitment_updates(&locked);

    client.set_employee_reference_id(&free, &id(&env, "EMP-3"));

    assert_eq!(
        client.get_employee_reference_id(&free),
        Some(id(&env, "EMP-3"))
    );
}

#[test]
fn an_unlocked_employee_still_moves_freely() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));

    client.set_employee_reference_id(&employee, &id(&env, "EMP-2"));

    assert_eq!(
        client.get_employee_reference_id(&employee),
        Some(id(&env, "EMP-2"))
    );
}

// ── Typed errors ────────────────────────────────────────────────────────────────────────────────

#[test]
fn claiming_a_held_id_is_a_typed_error() {
    let (env, client) = setup();
    let holder = with_commitment(&env, &client, 1);
    let other = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&holder, &id(&env, "EMP-1"));

    assert_eq!(
        client.try_set_employee_reference_id(&other, &id(&env, "EMP-1")),
        Err(Ok(BeneficiaryError::ReferenceIdTaken))
    );
}

#[test]
fn a_held_id_is_taken_whatever_its_spelling() {
    let (env, client) = setup();
    let holder = with_commitment(&env, &client, 1);
    let other = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&holder, &id(&env, "EMP-1"));

    assert_eq!(
        client.try_set_employee_reference_id(&other, &id(&env, " emp-1\t")),
        Err(Ok(BeneficiaryError::ReferenceIdTaken))
    );
}

#[test]
fn a_refused_claim_leaves_the_holder_and_the_claimant_untouched() {
    let (env, client) = setup();
    let holder = with_commitment(&env, &client, 1);
    let other = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&holder, &id(&env, "EMP-1"));
    client.set_employee_reference_id(&other, &id(&env, "EMP-9"));

    let _ = client.try_set_employee_reference_id(&other, &id(&env, "EMP-1"));

    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-1")),
        Some(holder)
    );
    assert_eq!(
        client.get_employee_reference_id(&other),
        Some(id(&env, "EMP-9"))
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP-9")),
        Some(other)
    );
}

#[test]
fn a_locked_employee_asking_for_a_held_id_is_told_it_is_taken() {
    let (env, client) = setup();
    let locked = with_commitment(&env, &client, 1);
    let holder = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&locked, &id(&env, "EMP-1"));
    client.set_employee_reference_id(&holder, &id(&env, "EMP-2"));
    client.lock_commitment_updates(&locked);

    assert_eq!(
        client.try_set_employee_reference_id(&locked, &id(&env, "EMP-2")),
        Err(Ok(BeneficiaryError::ReferenceIdTaken))
    );
}

#[test]
fn errors_do_not_echo_the_id_or_the_employee() {
    let (env, client) = setup();
    let holder = with_commitment(&env, &client, 1);
    let other = with_commitment(&env, &client, 2);
    client.set_employee_reference_id(&holder, &id(&env, "SECRET-HR-7731"));

    let taken = client.try_set_employee_reference_id(&other, &id(&env, "SECRET-HR-7731"));
    let text = format!("{:?}", taken);

    assert!(!text.contains("SECRET-HR-7731"));
    assert!(!text.contains("HR-7731"));
    assert_eq!(text, "Err(Ok(ReferenceIdTaken))");

    client.lock_commitment_updates(&holder);
    let locked = client.try_set_employee_reference_id(&holder, &id(&env, "OTHER-ID"));
    assert_eq!(format!("{:?}", locked), "Err(Ok(ReferenceIdLocked))");
}

#[test]
fn a_malformed_id_is_still_refused_before_any_binding_changes() {
    let (env, client) = setup();
    let employee = with_commitment(&env, &client, 1);
    client.set_employee_reference_id(&employee, &id(&env, "EMP-1"));

    assert!(client
        .try_set_employee_reference_id(&employee, &id(&env, "   "))
        .is_err());

    assert_eq!(
        client.get_employee_reference_id(&employee),
        Some(id(&env, "EMP-1"))
    );
}
