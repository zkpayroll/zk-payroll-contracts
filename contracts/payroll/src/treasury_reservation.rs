//! Treasury balance reservation checks (#699).
//!
//! `prepare_payroll_run` reserves the run's total in the contract's locked
//! funds so that a withdrawal cannot spend money a pending run is counting on.
//! Before this check, the reservation was recorded without asking whether the
//! treasury could cover it: two runs prepared back to back could together
//! lock more than the treasury holds, and the shortfall only surfaced later,
//! when `finalize_payroll_run` tried to transfer the money.
//!
//! This module is the pure decision behind the check. It is given the
//! treasury's token balance, the funds already locked for other pending runs,
//! and the amount a new run wants to lock, and says whether the reservation
//! may proceed. Reading the balance, storage, and the panic messages live in
//! [`crate::Payroll`]; everything here is side-effect free so it can be
//! tested without a Soroban host.
//!
//! The rule is the same one [`crate::Payroll::check_funding_source_readiness`]
//! applies to a hypothetical spend: the amount must fit in the balance after
//! existing locks and the configured buffer. Reserving uses that rule too, so
//! readiness and `prepare_payroll_run` cannot disagree.
//!
//! Privacy: only aggregate token amounts are read. No employee identity,
//! salary row, or proof material is involved.

/// Why a reservation may not proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationIssue {
    /// The amount to reserve is zero or negative.
    NonPositiveAmount,
    /// The balance available after existing locks and the buffer is smaller
    /// than the amount.
    ///
    /// `available` is what could still be reserved, never negative.
    InsufficientUnreserved { available: i128 },
}

impl ReservationIssue {
    /// Stable code for logs, dashboards, and tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReservationIssue::NonPositiveAmount => "non_positive_amount",
            ReservationIssue::InsufficientUnreserved { .. } => "insufficient_unreserved",
        }
    }
}

/// What the treasury looks like once a reservation is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationOutcome {
    /// Balance available to reserve after existing locks and the buffer.
    pub available_before: i128,
    /// Total locked funds after this reservation.
    pub reserved_after: i128,
    /// Reservable balance left after this reservation.
    pub available_after: i128,
}

/// Balance that is not locked for a pending run. Never negative: a treasury
/// that holds less than is locked has nothing available, not a negative sum.
/// A negative locked figure is not something the contract stores; if one ever
/// appeared it is treated as zero rather than inflating the available balance.
pub fn unreserved_balance(total_balance: i128, reserved: i128) -> i128 {
    total_balance.saturating_sub(reserved.max(0)).max(0)
}

/// Decide whether `amount` may be reserved against a treasury holding
/// `total_balance` of which `reserved` is already locked.
///
/// The boundary is inclusive: reserving exactly the unreserved balance is
/// allowed and leaves nothing available.
pub fn check_reservation(
    total_balance: i128,
    reserved: i128,
    amount: i128,
) -> Result<ReservationOutcome, ReservationIssue> {
    check_reservation_with_buffer(total_balance, reserved, 0, amount)
}

/// Balance available for a new reservation after locks and a retained buffer.
/// Negative values are treated as zero so an invalid input cannot increase
/// available funds.
pub fn reservable_balance(total_balance: i128, reserved: i128, buffer: i128) -> i128 {
    total_balance
        .saturating_sub(reserved.max(0))
        .saturating_sub(buffer.max(0))
        .max(0)
}

/// Decide whether `amount` may be reserved while keeping `buffer` in the
/// treasury after accounting for existing reservations.
pub fn check_reservation_with_buffer(
    total_balance: i128,
    reserved: i128,
    buffer: i128,
    amount: i128,
) -> Result<ReservationOutcome, ReservationIssue> {
    if amount <= 0 {
        return Err(ReservationIssue::NonPositiveAmount);
    }

    let available_before = reservable_balance(total_balance, reserved, buffer);
    if available_before < amount {
        return Err(ReservationIssue::InsufficientUnreserved {
            available: available_before,
        });
    }

    // `amount <= available_before <= total_balance - reserved - buffer`, so
    // this sum is at most `total_balance` and cannot overflow.
    let reserved_after = reserved.max(0) + amount;

    Ok(ReservationOutcome {
        available_before,
        reserved_after,
        available_after: available_before - amount,
    })
}
