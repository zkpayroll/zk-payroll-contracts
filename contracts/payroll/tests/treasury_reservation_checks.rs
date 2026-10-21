//! Treasury balance reservation checks (#699).
//!
//! `prepare_payroll_run` locks the run's total so withdrawals cannot spend it.
//! These tests pin that it refuses to lock more than the treasury holds
//! unreserved, that the refusal is actionable and leaves no trace, and that
//! runs which fit are unaffected.

#![cfg(test)]

mod common;

use ::token::TokenClient;
use payroll::{
    check_reservation, unreserved_balance, FundingSourceBlocker, PayrollClient, ReservationIssue,
    ReservationOutcome,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

/// The treasury balance `common::setup` mints.
const TREASURY_BALANCE: i128 = 1_000_000;

/// A one-payment batch of `amount`, paid to a fresh employee.
fn run_of(env: &Env, amount: i128) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    (
        Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]),
        Vec::from_array(env, [amount]),
        Vec::from_array(env, [Address::generate(env)]),
    )
}

fn prepare(env: &Env, client: &PayrollClient, amount: i128, marker: u8) -> u64 {
    let (proofs, amounts, employees) = run_of(env, amount);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &amount,
        &common::nonce(env, marker),
        &None,
    )
}

fn try_prepare(env: &Env, client: &PayrollClient, amount: i128, marker: u8) -> bool {
    let (proofs, amounts, employees) = run_of(env, amount);
    client
        .try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &amount,
            &common::nonce(env, marker),
            &None,
        )
        .is_ok()
}

#[test]
fn a_run_within_the_treasury_balance_reserves_its_total() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    let run_id = prepare(&env, &client, 400_000, 1);

    assert!(client.get_pending_run(&run_id).is_some());
    assert_eq!(client.get_locked_funds(&token), 400_000);
    assert_eq!(client.get_available_treasury_balance(&token), 600_000);
}

#[test]
fn reserving_exactly_the_unreserved_balance_is_allowed() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    prepare(&env, &client, TREASURY_BALANCE, 1);

    assert_eq!(client.get_locked_funds(&token), TREASURY_BALANCE);
    assert_eq!(client.get_available_treasury_balance(&token), 0);
}

#[test]
#[should_panic(
    expected = "Insufficient available treasury balance: run needs 1000001 but only 1000000 is reservable after the 0 buffer (0 of 1000000 is locked for pending payroll)"
)]
fn one_unit_over_the_unreserved_balance_is_rejected_with_the_numbers() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    prepare(&env, &client, TREASURY_BALANCE + 1, 1);
}

#[test]
#[should_panic(expected = "fund the treasury, reduce the buffer, or cancel a pending run")]
fn the_rejection_says_how_to_recover() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    prepare(&env, &client, TREASURY_BALANCE + 1, 1);
}

#[test]
fn reservations_accumulate_across_pending_runs() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    prepare(&env, &client, 600_000, 1);

    // Only 400_000 is left unreserved, so 400_001 does not fit and 400_000 does.
    assert!(!try_prepare(&env, &client, 400_001, 2));
    assert_eq!(client.get_locked_funds(&token), 600_000);

    prepare(&env, &client, 400_000, 2);
    assert_eq!(client.get_locked_funds(&token), TREASURY_BALANCE);
    assert_eq!(client.get_available_treasury_balance(&token), 0);

    // Nothing is left for a third run, however small.
    assert!(!try_prepare(&env, &client, 1, 3));
}

#[test]
#[should_panic(
    expected = "run needs 400001 but only 400000 is reservable after the 0 buffer (600000 of 1000000 is locked for pending payroll)"
)]
fn the_rejection_names_the_funds_other_runs_already_lock() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    prepare(&env, &client, 600_000, 1);
    prepare(&env, &client, 400_001, 2);
}

#[test]
fn cancelling_a_run_frees_its_reservation_for_the_next_one() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;

    let first = prepare(&env, &client, TREASURY_BALANCE, 1);
    assert!(!try_prepare(&env, &client, 1, 2));

    client.cancel_payroll_run(&admin, &first, &Symbol::new(&env, "replan"));
    assert_eq!(client.get_locked_funds(&token), 0);

    prepare(&env, &client, 700_000, 2);
    assert_eq!(client.get_locked_funds(&token), 700_000);
}

#[test]
fn finalizing_a_run_does_not_leave_its_reservation_blocking_later_runs() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;
    let treasury = client.get_addresses().treasury;

    let first = prepare(&env, &client, 300_000, 1);
    client.finalize_payroll_run(&admin, &first);
    assert_eq!(client.get_locked_funds(&token), 0);

    // Whatever finalizing did to the treasury balance, the run's lock is gone:
    // the next run is measured against the balance alone.
    let balance = TokenClient::new(&env, &token).balance(&treasury);
    prepare(&env, &client, balance, 2);
    assert!(!try_prepare(&env, &client, 1, 3));
}

#[test]
fn a_treasury_drawn_below_its_locked_funds_has_nothing_to_reserve() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let treasury = client.get_addresses().treasury;

    prepare(&env, &client, 500_000, 1);

    // The treasury is an ordinary account: something outside payroll moves
    // money out and leaves it holding 300_000 against 500_000 locked.
    TokenClient::new(&env, &token).transfer(&treasury, &Address::generate(&env), &700_000);

    assert!(!try_prepare(&env, &client, 1, 2));
    assert_eq!(client.get_locked_funds(&token), 500_000);
}

#[test]
#[should_panic(
    expected = "run needs 1 but only 0 is reservable after the 0 buffer (500000 of 300000 is locked for pending payroll)"
)]
fn the_rejection_reports_zero_available_never_a_negative_figure() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);
    let treasury = client.get_addresses().treasury;

    prepare(&env, &client, 500_000, 1);
    TokenClient::new(&env, &token).transfer(&treasury, &Address::generate(&env), &700_000);

    prepare(&env, &client, 1, 2);
}

#[test]
fn a_rejected_run_leaves_no_trace() {
    let env = Env::default();
    let (client, token, _employee) = common::setup(&env);

    prepare(&env, &client, 600_000, 1);
    let locked_before = client.get_locked_funds(&token);

    assert!(!try_prepare(&env, &client, 500_000, 2));

    assert_eq!(client.get_locked_funds(&token), locked_before);
    // The nonce was not consumed, so the same nonce is still usable once the
    // run is resized to fit.
    prepare(&env, &client, 400_000, 2);
    assert_eq!(client.get_locked_funds(&token), TREASURY_BALANCE);
}

#[test]
fn a_successful_prepare_agrees_with_the_funding_source_readiness_check() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    prepare(&env, &client, 250_000, 1);

    // What the readiness check calls ready is exactly what prepare accepts.
    let fits = client.check_funding_source_readiness(&750_000);
    assert!(fits.ready);
    assert!(try_prepare(&env, &client, 750_000, 2));

    let overshoot = client.check_funding_source_readiness(&1);
    assert!(!overshoot.ready);
    assert_eq!(overshoot.blocker, FundingSourceBlocker::InsufficientFunds);
    assert!(!try_prepare(&env, &client, 1, 3));
}

#[test]
fn a_run_that_fits_is_unaffected_by_the_check() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 1),
        &None,
    );

    let pending = client.get_pending_run(&run_id).unwrap();
    assert_eq!(pending.total_amount, 100);
    assert_eq!(pending.employee_count, 1);
}

// ---------------------------------------------------------------------------
// The pure decision behind the check.
// ---------------------------------------------------------------------------
mod decision {
    use super::*;

    #[test]
    fn reserves_when_the_treasury_covers_the_amount() {
        let outcome = check_reservation(1_000, 0, 400).unwrap();
        assert_eq!(
            outcome,
            ReservationOutcome {
                available_before: 1_000,
                reserved_after: 400,
                available_after: 600,
            }
        );
    }

    #[test]
    fn other_pending_runs_reduce_what_can_be_reserved() {
        let outcome = check_reservation(1_000, 700, 300).unwrap();
        assert_eq!(outcome.available_before, 300);
        assert_eq!(outcome.reserved_after, 1_000);
        assert_eq!(outcome.available_after, 0);

        assert_eq!(
            check_reservation(1_000, 700, 301),
            Err(ReservationIssue::InsufficientUnreserved { available: 300 })
        );
    }

    #[test]
    fn reserving_exactly_the_unreserved_balance_is_allowed() {
        let outcome = check_reservation(500, 0, 500).unwrap();
        assert_eq!(outcome.available_after, 0);
        assert_eq!(outcome.reserved_after, 500);
    }

    #[test]
    fn one_unit_over_the_unreserved_balance_is_rejected() {
        assert_eq!(
            check_reservation(500, 0, 501),
            Err(ReservationIssue::InsufficientUnreserved { available: 500 })
        );
    }

    #[test]
    fn a_treasury_below_its_locked_funds_has_nothing_available() {
        // The treasury was drawn down outside payroll after funds were locked.
        assert_eq!(unreserved_balance(300, 500), 0);
        assert_eq!(
            check_reservation(300, 500, 1),
            Err(ReservationIssue::InsufficientUnreserved { available: 0 })
        );
    }

    #[test]
    fn an_empty_treasury_cannot_reserve() {
        assert_eq!(
            check_reservation(0, 0, 1),
            Err(ReservationIssue::InsufficientUnreserved { available: 0 })
        );
    }

    #[test]
    fn non_positive_amounts_are_rejected_before_the_balance_is_considered() {
        for amount in [0, -1, i128::MIN] {
            assert_eq!(
                check_reservation(1_000, 0, amount),
                Err(ReservationIssue::NonPositiveAmount)
            );
        }
        // Even an empty treasury reports the amount problem first.
        assert_eq!(
            check_reservation(0, 0, 0),
            Err(ReservationIssue::NonPositiveAmount)
        );
    }

    #[test]
    fn extreme_balances_do_not_overflow() {
        let outcome = check_reservation(i128::MAX, 0, i128::MAX).unwrap();
        assert_eq!(outcome.available_after, 0);
        assert_eq!(outcome.reserved_after, i128::MAX);

        let outcome = check_reservation(i128::MAX, i128::MAX - 1, 1).unwrap();
        assert_eq!(outcome.reserved_after, i128::MAX);
        assert_eq!(outcome.available_after, 0);
    }

    #[test]
    fn a_negative_locked_figure_never_inflates_the_available_balance() {
        assert_eq!(unreserved_balance(100, -50), 100);
        assert_eq!(unreserved_balance(100, i128::MIN), 100);
        assert_eq!(
            check_reservation(100, i128::MIN, 101),
            Err(ReservationIssue::InsufficientUnreserved { available: 100 })
        );
    }

    #[test]
    fn issues_have_stable_codes() {
        assert_eq!(
            ReservationIssue::NonPositiveAmount.as_str(),
            "non_positive_amount"
        );
        assert_eq!(
            ReservationIssue::InsufficientUnreserved { available: 7 }.as_str(),
            "insufficient_unreserved"
        );
    }
}
