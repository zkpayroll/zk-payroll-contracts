//! Tests for payroll run amendment validation (#635).

#![cfg(test)]

use soroban_sdk::{
    symbol_short, testutils::Address as _, Address, BytesN, Env, String, Symbol,
};

use payroll::{
    amendment_validation::{
        can_amend_run, get_amendment_history, seal_run, validate_run_amendment,
    },
    ContractAddresses, DataKey,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn setup_contract(e: &Env, admin: &Address) {
    let fake_addr = Address::generate(e);
    e.storage().persistent().set(
        &DataKey::Addresses,
        &ContractAddresses {
            admin: admin.clone(),
            token: fake_addr.clone(),
            verifier: fake_addr.clone(),
            commitment: fake_addr.clone(),
            treasury: fake_addr.clone(),
            treasury_owner: fake_addr.clone(),
        },
    );
}

fn make_run_id(e: &Env) -> BytesN<32> {
    BytesN::from_array(e, &[1u8; 32])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_amendment_validation_success() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    setup_contract(&e, &admin);

    let run_id = make_run_id(&e);

    e.ledger().set_timestamp(5_000);
    validate_run_amendment(
        &e,
        admin.clone(),
        run_id.clone(),
        String::from_str(&e, "Correcting employee count"),
        Symbol::new(&e, "employee_count"),
    );

    let history = get_amendment_history(&e, &run_id);
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(0).unwrap().amendor, admin);
    assert_eq!(history.get(0).unwrap().amended_at, 5_000);
}

#[test]
#[should_panic(expected = "Run cannot be amended")]
fn test_amendment_finalized_run_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    setup_contract(&e, &admin);

    let run_id = make_run_id(&e);

    // Seal the run to simulate finalization
    seal_run(&e, &run_id);

    validate_run_amendment(
        &e,
        admin.clone(),
        run_id.clone(),
        String::from_str(&e, "Too late"),
        Symbol::new(&e, "some_field"),
    );
}

#[test]
#[should_panic(expected = "Amendment reason must not be empty")]
fn test_amendment_empty_reason_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    setup_contract(&e, &admin);

    let run_id = make_run_id(&e);

    validate_run_amendment(
        &e,
        admin.clone(),
        run_id.clone(),
        String::from_str(&e, ""),
        Symbol::new(&e, "some_field"),
    );
}

#[test]
fn test_get_amendment_history() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    setup_contract(&e, &admin);

    let run_id = make_run_id(&e);

    e.ledger().set_timestamp(1_000);
    validate_run_amendment(
        &e,
        admin.clone(),
        run_id.clone(),
        String::from_str(&e, "First amendment"),
        Symbol::new(&e, "field_a"),
    );

    e.ledger().set_timestamp(2_000);
    validate_run_amendment(
        &e,
        admin.clone(),
        run_id.clone(),
        String::from_str(&e, "Second amendment"),
        Symbol::new(&e, "field_b"),
    );

    let history = get_amendment_history(&e, &run_id);
    assert_eq!(history.len(), 2);
    assert_eq!(history.get(0).unwrap().amended_at, 1_000);
    assert_eq!(history.get(1).unwrap().amended_at, 2_000);
}

#[test]
fn test_can_amend_run_true_before_seal() {
    let e = Env::default();
    let run_id = make_run_id(&e);
    assert!(can_amend_run(&e, &run_id));
}

#[test]
fn test_can_amend_run_false_after_seal() {
    let e = Env::default();
    let run_id = make_run_id(&e);
    seal_run(&e, &run_id);
    assert!(!can_amend_run(&e, &run_id));
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_non_admin_amendment_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let other = Address::generate(&e);
    setup_contract(&e, &admin);

    let run_id = make_run_id(&e);

    validate_run_amendment(
        &e,
        other, // not the admin
        run_id,
        String::from_str(&e, "Unauthorized attempt"),
        Symbol::new(&e, "some_field"),
    );
}
