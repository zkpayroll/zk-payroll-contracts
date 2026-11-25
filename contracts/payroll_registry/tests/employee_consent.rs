//! Tests for employee consent commitment lifecycle (#350).

#![cfg(test)]

use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env,
};

use payroll_registry::consent::{
    get_consent, has_active_consent, record_consent, require_active_consent, revoke_consent,
    ConsentState,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn commitment(e: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(e, &[seed; 32])
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_record_consent_success() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.ledger().set_timestamp(1_000);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 1))
    });

    let rec = e
        .as_contract(&__cid, || get_consent(&e, &employer, &employee))
        .expect("consent should exist");
    assert_eq!(rec.state, ConsentState::Active);
    assert_eq!(rec.employee, employee);
    assert_eq!(rec.employer, employer);
    assert!(e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));
}

#[test]
fn test_revoke_consent() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.ledger().set_timestamp(1_000);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 2))
    });
    assert!(e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));

    e.ledger().set_timestamp(2_000);
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    });

    let rec = e
        .as_contract(&__cid, || get_consent(&e, &employer, &employee))
        .unwrap();
    assert_eq!(rec.state, ConsentState::Revoked);
    assert!(!e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));
}

#[test]
#[should_panic(expected = "Employee consent required")]
fn test_no_consent_blocks_enrollment() {
    let e = Env::default();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    // No consent recorded — require_active_consent must panic
    e.as_contract(&__cid, || require_active_consent(&e, &employer, &employee));
}

#[test]
fn test_consent_replacement() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.ledger().set_timestamp(500);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 10))
    });
    let first = e
        .as_contract(&__cid, || get_consent(&e, &employer, &employee))
        .unwrap();
    assert_eq!(first.commitment_hash, commitment(&e, 10));
    assert_eq!(first.created_at, 500);

    // Replace the consent with a new commitment
    e.ledger().set_timestamp(1_500);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 20))
    });

    let second = e
        .as_contract(&__cid, || get_consent(&e, &employer, &employee))
        .unwrap();
    assert_eq!(second.commitment_hash, commitment(&e, 20));
    assert_eq!(second.state, ConsentState::Active);
    // created_at is preserved from the original recording
    assert_eq!(second.created_at, 500);
    assert_eq!(second.updated_at, 1_500);
}

#[test]
fn test_revoked_consent_blocks_require() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 5))
    });
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    });

    // After revocation, has_active_consent is false
    assert!(!e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));
}

#[test]
#[should_panic(expected = "Employee consent required")]
fn test_require_active_consent_fails_after_revocation() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 7))
    });
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    });

    // Must panic after revocation
    e.as_contract(&__cid, || require_active_consent(&e, &employer, &employee));
}

#[test]
#[should_panic(expected = "already revoked")]
fn test_double_revoke_fails() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 8))
    });
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    });
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    }); // must panic
}

#[test]
#[should_panic(expected = "zero hash")]
fn test_zero_commitment_hash_rejected() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    // Zero hash should be rejected
    e.as_contract(&__cid, || {
        record_consent(&e, employer, employee, BytesN::from_array(&e, &[0u8; 32]))
    });
}

#[test]
fn test_reconsentment_after_revocation() {
    let e = Env::default();
    e.mock_all_auths();

    let employer = Address::generate(&e);
    let employee = Address::generate(&e);
    let __cid = e.register(payroll_registry::PayrollRegistry, ());

    e.ledger().set_timestamp(100);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 1))
    });
    e.as_contract(&__cid, || {
        revoke_consent(&e, employer.clone(), employee.clone())
    });
    assert!(!e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));

    // Re-consent after revocation should succeed
    e.ledger().set_timestamp(200);
    e.as_contract(&__cid, || {
        record_consent(&e, employer.clone(), employee.clone(), commitment(&e, 2))
    });
    assert!(e.as_contract(&__cid, || has_active_consent(&e, &employer, &employee)));
}
