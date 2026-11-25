//! Privacy-safe event redaction tests.
//!
//! These tests assert that serialized payroll events and error messages never
//! leak sensitive payroll data such as salary amounts, employee identifiers,
//! or proof bytes. They cover:
//!
//! * Success: emitted events are redacted before serialization.
//! * Failure: error paths produce redacted messages.
//! * Boundary: empty / optional sensitive fields remain redacted.

use payroll::events::{PayrollEvent, PayrollEventKind};
use payroll::error::PayrollError;

/// A representative salary amount that must never appear in serialized output.
const SENSITIVE_SALARY: u64 = 987_654_321;

/// A representative employee identifier that must never appear in serialized output.
const SENSITIVE_EMPLOYEE_ID: &str = "employee-secret-id-42";

/// Representative proof bytes that must never appear in serialized output.
const SENSITIVE_PROOF: &[u8] = b"super-secret-proof-bytes";

/// Assert that a serialized string does not contain any sensitive markers.
fn assert_no_sensitive_data(serialized: &str) {
    assert!(
        !serialized.contains(&SENSITIVE_SALARY.to_string()),
        "serialized output leaked salary amount: {serialized}"
    );
    assert!(
        !serialized.contains(SENSITIVE_EMPLOYEE_ID),
        "serialized output leaked employee identifier: {serialized}"
    );
    assert!(
        !serialized.contains(&String::from_utf8_lossy(SENSITIVE_PROOF).to_string()),
        "serialized output leaked proof bytes: {serialized}"
    );
}

#[test]
fn success_event_is_redacted() {
    let event = PayrollEvent::new(PayrollEventKind::SalaryPaid {
        employee_id: SENSITIVE_EMPLOYEE_ID.to_string(),
        amount: SENSITIVE_SALARY,
        proof: SENSITIVE_PROOF.to_vec(),
    });

    let serialized = event.to_redacted_string();
    assert_no_sensitive_data(&serialized);
    // The redacted event should still be well-formed and identify its kind.
    assert!(serialized.contains("SalaryPaid"));
}

#[test]
fn success_event_redacted_json_roundtrip() {
    let event = PayrollEvent::new(PayrollEventKind::SalaryPaid {
        employee_id: SENSITIVE_EMPLOYEE_ID.to_string(),
        amount: SENSITIVE_SALARY,
        proof: SENSITIVE_PROOF.to_vec(),
    });

    let serialized = event.to_redacted_json();
    assert_no_sensitive_data(&serialized);
}

#[test]
fn failure_error_is_redacted() {
    let err = PayrollError::InvalidPayment {
        employee_id: SENSITIVE_EMPLOYEE_ID.to_string(),
        amount: SENSITIVE_SALARY,
        reason: "insufficient funds".to_string(),
    };

    let message = err.to_redacted_string();
    assert_no_sensitive_data(&message);
    // The error should still convey the failure category.
    assert!(message.contains("InvalidPayment"));
}

#[test]
fn failure_error_display_is_redacted() {
    let err = PayrollError::InvalidPayment {
        employee_id: SENSITIVE_EMPLOYEE_ID.to_string(),
        amount: SENSITIVE_SALARY,
        reason: "insufficient funds".to_string(),
    };

    let message = format!("{err}");
    assert_no_sensitive_data(&message);
}

#[test]
fn boundary_empty_optional_fields_are_redacted() {
    let event = PayrollEvent::new(PayrollEventKind::SalaryPaid {
        employee_id: String::new(),
        amount: 0,
        proof: Vec::new(),
    });

    let serialized = event.to_redacted_string();
    assert_no_sensitive_data(&serialized);
    assert!(serialized.contains("SalaryPaid"));
}

#[test]
fn boundary_empty_optional_fields_redacted_json() {
    let event = PayrollEvent::new(PayrollEventKind::SalaryPaid {
        employee_id: String::new(),
        amount: 0,
        proof: Vec::new(),
    });

    let serialized = event.to_redacted_json();
    assert_no_sensitive_data(&serialized);
}

#[test]
fn boundary_error_with_empty_fields_is_redacted() {
    let err = PayrollError::InvalidPayment {
        employee_id: String::new(),
        amount: 0,
        reason: String::new(),
    };

    let message = err.to_redacted_string();
    assert_no_sensitive_data(&message);
    assert!(message.contains("InvalidPayment"));
}