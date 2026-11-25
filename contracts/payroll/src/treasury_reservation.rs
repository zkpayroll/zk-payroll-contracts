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

use soroban_sdk::contracterror;

/// Stable, payload-free errors for treasury reservation failures (#946).
///
/// Codes are append-only and permanently assigned in the 8600–8699 range;
/// they must never be reused or renumbered. Every variant is unit-only so a
/// client receives a code that maps to one fixed, actionable message. No
/// variant carries an amount, address, employee identifier, commitment, or
/// other private payroll data, making these errors safe to log verbatim.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TreasuryReservationError {
    /// The contract has not been initialized.
    NotInitialized = 8600,
    /// The canonical treasury asset is not on the allowlist.
    AssetNotAllowed = 8601,
    /// The amount to reserve is zero or negative.
    NonPositiveAmount = 8602,
    /// The treasury cannot cover the amount after locks and the buffer.
    InsufficientUnreserved = 8603,
    /// The token contract did not answer the treasury balance query.
    TreasuryUnavailable = 8604,
    /// No reservation exists for the asset being changed.
    ReservationNotFound = 8605,
    /// Stored reservation state is invalid (for example, a negative lock).
    InvalidReservationState = 8606,
    /// The caller is not authorized to change a reservation.
    UnauthorizedReservationChange = 8607,
    /// The asset being reserved differs from the canonical treasury asset.
    CrossAssetMismatch = 8608,
}

impl TreasuryReservationError {
    /// Fixed message for SDKs and dashboards. Never includes payroll data.
    pub fn message(self) -> &'static str {
        match self {
            Self::NotInitialized => {
                "Treasury contract is not initialized. Initialize it before reserving funds."
            }
            Self::AssetNotAllowed => {
                "Asset is not on the treasury allowlist. Use an admin-approved asset."
            }
            Self::NonPositiveAmount => {
                "Reservation amount must be positive. Retry with a positive amount."
            }
            Self::InsufficientUnreserved => {
                "Treasury cannot cover this reservation after pending locks and the retained buffer. Fund the treasury, reduce the buffer, or cancel a pending run."
            }
            Self::TreasuryUnavailable => {
                "Treasury token balance is unavailable. Retry or check the configured token contract."
            }
            Self::ReservationNotFound => {
                "No reservation exists for this asset. Check the asset and run identifier."
            }
            Self::InvalidReservationState => {
                "Stored reservation state is invalid. Reconcile pending runs before reserving."
            }
            Self::UnauthorizedReservationChange => {
                "Only an authorized treasury operator may change reservations. Use the authorized caller."
            }
            Self::CrossAssetMismatch => {
                "Reservation asset differs from the configured treasury asset. Use the canonical asset."
            }
        }
    }

    /// Stable short code for logs and dashboards.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::AssetNotAllowed => "asset_not_allowed",
            Self::NonPositiveAmount => "non_positive_amount",
            Self::InsufficientUnreserved => "insufficient_unreserved",
            Self::TreasuryUnavailable => "treasury_unavailable",
            Self::ReservationNotFound => "reservation_not_found",
            Self::InvalidReservationState => "invalid_reservation_state",
            Self::UnauthorizedReservationChange => "unauthorized_reservation_change",
            Self::CrossAssetMismatch => "cross_asset_mismatch",
        }
    }
}

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

impl From<ReservationIssue> for TreasuryReservationError {
    fn from(issue: ReservationIssue) -> Self {
        match issue {
            ReservationIssue::NonPositiveAmount => Self::NonPositiveAmount,
            ReservationIssue::InsufficientUnreserved { .. } => Self::InsufficientUnreserved,
        }
    }
}

impl ReservationIssue {
    /// The payload-free contract error that corresponds to this issue.
    ///
    /// The detailed `ReservationIssue` is kept for internal diagnostics; the
    /// mapped error is what clients and dashboards receive.
    pub fn safe_error(self) -> TreasuryReservationError {
        self.into()
    }
}

/// Same decision as [`check_reservation_with_buffer`], reported through the
/// stable, payload-free error taxonomy (#946).
pub fn checked_reservation(
    total_balance: i128,
    reserved: i128,
    buffer: i128,
    amount: i128,
) -> Result<ReservationOutcome, TreasuryReservationError> {
    check_reservation_with_buffer(total_balance, reserved, buffer, amount).map_err(Into::into)
}

#[cfg(test)]
mod safe_error_tests {
    use super::*;

    #[test]
    fn error_codes_are_stable_and_append_only() {
        assert_eq!(TreasuryReservationError::NotInitialized as u32, 8600);
        assert_eq!(TreasuryReservationError::AssetNotAllowed as u32, 8601);
        assert_eq!(TreasuryReservationError::NonPositiveAmount as u32, 8602);
        assert_eq!(TreasuryReservationError::InsufficientUnreserved as u32, 8603);
        assert_eq!(TreasuryReservationError::TreasuryUnavailable as u32, 8604);
        assert_eq!(TreasuryReservationError::ReservationNotFound as u32, 8605);
        assert_eq!(TreasuryReservationError::InvalidReservationState as u32, 8606);
        assert_eq!(
            TreasuryReservationError::UnauthorizedReservationChange as u32,
            8607
        );
        assert_eq!(TreasuryReservationError::CrossAssetMismatch as u32, 8608);
    }

    #[test]
    fn messages_are_actionable_and_free_of_payroll_data() {
        let private_terms = ["salary", "employee", "commitment", "proof", "amount is"];
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

        for error in errors {
            let message = error.message().to_lowercase();
            assert!(!message.is_empty());
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
    fn decision_issues_map_to_safe_errors() {
        assert_eq!(
            ReservationIssue::NonPositiveAmount.safe_error(),
            TreasuryReservationError::NonPositiveAmount
        );
        assert_eq!(
            ReservationIssue::InsufficientUnreserved { available: 7 }.safe_error(),
            TreasuryReservationError::InsufficientUnreserved
        );
        assert_eq!(
            checked_reservation(100, 0, 0, 0),
            Err(TreasuryReservationError::NonPositiveAmount)
        );
        assert_eq!(
            checked_reservation(100, 0, 10, 101),
            Err(TreasuryReservationError::InsufficientUnreserved)
        );
    }
}
