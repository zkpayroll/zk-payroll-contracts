//! Adversarial treasury reservation coverage (#948).
//!
//! The suite attacks the reservation decision with negative and extreme
//! figures, multiple competing reservations, buffer changes and asset
//! confusion. It also pins the payload-safe error taxonomy introduced for
//! #946 and checks that a rejected preflight leaves no state behind.
//!
//! No salary, employee, commitment or proof data appears in this file.

#![cfg(test)]

mod common;

use payroll::{
    check_reservation_with_buffer, checked_reservation, ReservationIssue,
    TreasuryReservationError,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Env;

// ─────────────────────────────────────────────────────────────────────────────
// Safe error taxonomy (#946)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn error_codes_are_permanent_and_messages_carry_no_private_data() {
    let private_terms = ["salary", "employee", "commitment", "proof", "blinding"];
    let errors = [
        TreasuryReservationError::NotInitialized,
        TreasuryReservationError::AssetNotAllowed,
        TreasuryReservationError::NonPositiveAmount,
        TreasuryReservationError::InsufficientUnreserved,
        TreasuryReservationError::TreasuryUnavailable,
        TreasuryReservationError::ReservationNotFound,
        TreasuryReservationError::InvalidReservationState,
        TreasuryReservationError::UnauthorizedReservationChange,
        TreasuryReservationError::CrossAssetMismatch,
    ];

    let expected_codes = [8600u32, 8601, 8602, 8603, 8604, 8605, 8606, 8607, 8608];
    for (error, expected_code) in errors.into_iter().zip(expected_codes) {
        assert_eq!(error as u32, expected_code);
        let message = error.message().to_lowercase();
        assert!(!message.is_empty(), "message must be actionable");
        assert!(!error.as_str().is_empty());
        for term in private_terms {
            assert!(
                !message.contains(term),
                "error {error:?} leaks private term '{term}'"
            );
        }
    }
}

#[test]
fn an_aggregate_issue_is_reduced_to_a_payload_free_error() {
    // The detailed figure is useful internally but must not reach clients.
    let issue = ReservationIssue::InsufficientUnreserved { available: 42 };
    assert_eq!(
        issue.safe_error(),
        TreasuryReservationError::InsufficientUnreserved
    );
    assert_eq!(
        checked_reservation(100, 0, 0, 101),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Arithmetic attacks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_negative_lock_cannot_inflate_the_available_balance() {
    assert_eq!(
        checked_reservation(100, -100, 0, 101),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
    assert_eq!(
        checked_reservation(100, i128::MIN, 0, 101),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
    // The pure legacy decision clamp remains identical to the safe one.
    assert_eq!(
        check_reservation_with_buffer(100, i128::MIN, 0, 100),
        Ok(payroll::ReservationOutcome {
            available_before: 100,
            reserved_after: 200,
            available_after: 0,
        })
    );
}

#[test]
fn a_negative_buffer_cannot_be_used_to_over_reserve() {
    assert_eq!(
        checked_reservation(1_000, 0, -1_000, 1_001),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
    assert_eq!(
        checked_reservation(1_000, 0, -1_000, 1_000)
            .unwrap()
            .available_after,
        0
    );
}

#[test]
fn extreme_values_do_not_wrap_into_a_successful_reservation() {
    assert_eq!(
        checked_reservation(i128::MAX, 0, i128::MAX, 1),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
    assert_eq!(
        checked_reservation(i128::MIN, 0, 0, 1),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
    assert_eq!(
        checked_reservation(10, 11, 0, 1),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );

    let outcome = checked_reservation(i128::MAX, i128::MAX - 1, 0, 1).unwrap();
    assert_eq!(outcome.reserved_after, i128::MAX);
    assert_eq!(outcome.available_after, 0);
}

#[test]
fn non_positive_amounts_fail_even_when_the_treasury_is_empty_or_uninitialized() {
    for amount in [0, -1, i128::MIN] {
        assert_eq!(
            checked_reservation(0, 0, 0, amount),
            Err(TreasuryReservationError::NonPositiveAmount)
        );
    }
}

#[test]
fn competing_reservations_stop_exactly_at_the_total_balance() {
    let first = checked_reservation(1_000, 0, 0, 600).unwrap();
    assert_eq!(first.available_after, 400);

    let second = checked_reservation(1_000, first.reserved_after, 0, 400).unwrap();
    assert_eq!(second.reserved_after, 1_000);
    assert_eq!(second.available_after, 0);

    assert_eq!(
        checked_reservation(1_000, first.reserved_after, 0, 401),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
}

#[test]
fn a_buffer_change_without_a_deposit_rejects_the_same_amount() {
    let before = checked_reservation(1_000, 0, 0, 1_000).unwrap();
    assert_eq!(before.available_after, 0);
    assert_eq!(
        checked_reservation(1_000, 0, 1, 1_000),
        Err(TreasuryReservationError::InsufficientUnreserved)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Contract-level adversarial cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn preflight_reports_typed_errors_and_never_writes_state() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    client.try_validate_treasury_reservation(&token, &1_000_000).unwrap().unwrap();

    client.add_locked_funds(&token, &600_000);
    let locked_before = client.get_locked_funds(&token);
    let available_before = client.get_available_treasury_balance(&token);

    assert_eq!(
        client
            .try_validate_treasury_reservation(&token, &400_001)
            .unwrap_err()
            .unwrap(),
        TreasuryReservationError::InsufficientUnreserved
    );
    assert_eq!(client.get_locked_funds(&token), locked_before);
    assert_eq!(
        client.get_available_treasury_balance(&token),
        available_before
    );

    client.try_validate_treasury_reservation(&token, &400_000).unwrap().unwrap();
}

#[test]
fn a_foreign_asset_is_rejected_before_any_balance_is_read() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let foreign_asset = soroban_sdk::Address::generate(&env);

    assert_eq!(
        client
            .try_validate_treasury_reservation(&foreign_asset, &1)
            .unwrap_err()
            .unwrap(),
        TreasuryReservationError::CrossAssetMismatch
    );
    assert_eq!(client.get_locked_funds(&token), 0);
}

#[test]
fn a_buffer_raised_after_a_reservation_blocks_the_same_amount() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    client.try_validate_treasury_reservation(&token, &1_000_000).unwrap().unwrap();

    client.set_treasury_balance_buffer(&admin, &1);
    assert_eq!(
        client
            .try_validate_treasury_reservation(&token, &1_000_000)
            .unwrap_err()
            .unwrap(),
        TreasuryReservationError::InsufficientUnreserved
    );
    client.try_validate_treasury_reservation(&token, &999_999).unwrap().unwrap();
}

#[test]
fn non_positive_preflight_amounts_use_the_safe_error() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    assert_eq!(
        client
            .try_validate_treasury_reservation(&token, &0)
            .unwrap_err()
            .unwrap(),
        TreasuryReservationError::NonPositiveAmount
    );
    assert_eq!(
        client
            .try_validate_treasury_reservation(&token, &i128::MIN)
            .unwrap_err()
            .unwrap(),
        TreasuryReservationError::NonPositiveAmount
    );
}
