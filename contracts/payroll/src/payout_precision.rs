//! Payout amount precision and rounding validation (#1085).
//!
//! Payroll amounts are `i128` integer token base units. Two failure modes can
//! silently change how much an employee receives:
//!
//! 1. Aggregating a batch with unchecked arithmetic can wrap the running total,
//!    so the authorised spend no longer matches the amounts that are paid.
//! 2. Deriving a payout from a pro-rata share (`gross * numerator / denominator`)
//!    truncates integer division. Without an explicit rounding mode and a
//!    tolerance, the rounding loss is invisible to callers.
//!
//! This module makes both checks explicit. Errors are typed and carry no
//! amounts, employee addresses, or proof material, so they are safe to surface
//! to clients and to include in diagnostics. The public entrypoints are
//! read-only preflights; the batch total helper is used by the execution path.

use soroban_sdk::{contracterror, contractimpl, contracttype, Env, Vec};

use crate::{Payroll, PayrollArgs, PayrollClient};

/// Highest decimal precision accepted for a payout (#646, #1085).
pub const MAX_PAYOUT_DECIMALS: u32 = 18;
/// Basis-point scale used to express rounding drift.
pub const PAYOUT_BPS_SCALE: i128 = 10_000;

/// Typed failures for payout precision validation (#1085).
///
/// Codes are stable and intentionally do not embed amounts or identities.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PayoutPrecisionError {
    /// A payout amount or gross amount was zero or negative.
    NonPositiveAmount = 8700,
    /// The declared asset precision is above [`MAX_PAYOUT_DECIMALS`].
    InvalidDecimals = 8701,
    /// The share is invalid: numerator is negative, denominator is zero, or
    /// numerator exceeds denominator.
    InvalidShare = 8702,
    /// Tolerance is above 10,000 basis points (100%).
    InvalidTolerance = 8703,
    /// Scaling, rounding, or aggregation would overflow `i128`.
    ArithmeticOverflow = 8704,
    /// Rounding drift exceeds the caller's configured tolerance.
    RoundingDriftExceedsTolerance = 8705,
    /// The checked batch total differs from the authorised spend.
    ExpectedSpendMismatch = 8706,
}

/// How a fractional pro-rata payout is resolved to whole base units.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PayoutRoundingMode {
    /// Truncate towards zero. The contract never pays more than the share.
    Floor = 0,
    /// Round to the nearest base unit; exact halves round up.
    HalfUp = 1,
}

/// Privacy-safe result of a pro-rata payout precision check.
///
/// `rounding_delta` is `rounded_amount * denominator - gross * numerator`: a
/// negative value means the payout was rounded down, a positive value means it
/// was rounded up. It lets callers reconcile the exact share without leaking
/// salary values through errors or logs.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutPrecisionAssessment {
    pub rounded_amount: i128,
    pub rounding_delta: i128,
    pub drift_bps: u32,
    pub decimals: u32,
    pub tolerance_bps: u32,
    pub rounding_mode: PayoutRoundingMode,
}

/// Privacy-safe result of a batch precision check.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutBatchAssessment {
    pub payment_count: u32,
    pub total: i128,
    pub expected_total: i128,
}

/// Validate a pro-rata payout derived from `gross * numerator / denominator`.
///
/// Uses checked arithmetic throughout, applies the requested rounding mode
/// explicitly, and rejects a rounding loss larger than `tolerance_bps`. The
/// base-unit precision must be at most [`MAX_PAYOUT_DECIMALS`].
pub fn validate_pro_rata_payout(
    gross_amount: i128,
    numerator: i128,
    denominator: i128,
    decimals: u32,
    tolerance_bps: u32,
    rounding_mode: PayoutRoundingMode,
) -> Result<PayoutPrecisionAssessment, PayoutPrecisionError> {
    if gross_amount <= 0 {
        return Err(PayoutPrecisionError::NonPositiveAmount);
    }
    if decimals > MAX_PAYOUT_DECIMALS {
        return Err(PayoutPrecisionError::InvalidDecimals);
    }
    if numerator < 0 || denominator <= 0 || numerator > denominator {
        return Err(PayoutPrecisionError::InvalidShare);
    }
    if tolerance_bps > PAYOUT_BPS_SCALE as u32 {
        return Err(PayoutPrecisionError::InvalidTolerance);
    }

    let exact_scaled = gross_amount
        .checked_mul(numerator)
        .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;

    let quotient = exact_scaled / denominator;
    let remainder = exact_scaled % denominator;
    let rounded_amount = match rounding_mode {
        PayoutRoundingMode::Floor => quotient,
        PayoutRoundingMode::HalfUp => {
            let doubled = remainder
                .checked_mul(2)
                .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;
            if doubled >= denominator {
                quotient
                    .checked_add(1)
                    .ok_or(PayoutPrecisionError::ArithmeticOverflow)?
            } else {
                quotient
            }
        }
    };

    // Signed difference from the exact share, in scaled base units. Recomputed
    // from the rounded result so both rounding modes reconcile identically.
    let rounding_delta = rounded_amount
        .checked_mul(denominator)
        .and_then(|scaled| scaled.checked_sub(exact_scaled))
        .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;

    let drift_bps = if rounding_delta == 0 {
        0
    } else {
        let magnitude = rounding_delta
            .checked_abs()
            .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;
        let bps = magnitude
            .checked_mul(PAYOUT_BPS_SCALE)
            .and_then(|scaled| scaled.checked_div(denominator))
            .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;
        // A non-zero remainder is always smaller than the denominator, so the
        // drift fits in u32; clamp anyway rather than truncating the cast.
        if bps > u32::MAX as i128 {
            u32::MAX
        } else {
            bps as u32
        }
    };

    if drift_bps > tolerance_bps {
        return Err(PayoutPrecisionError::RoundingDriftExceedsTolerance);
    }

    Ok(PayoutPrecisionAssessment {
        rounded_amount,
        rounding_delta,
        drift_bps,
        decimals,
        tolerance_bps,
        rounding_mode,
    })
}

/// Sum payout amounts without truncation or wrapping.
///
/// Every amount must be positive; a running total that cannot be represented
/// as `i128` is rejected instead of silently losing precision.
pub fn sum_payout_amounts(amounts: &Vec<i128>) -> Result<i128, PayoutPrecisionError> {
    let mut total = 0i128;
    for index in 0..amounts.len() {
        let amount = amounts
            .get(index)
            .ok_or(PayoutPrecisionError::NonPositiveAmount)?;
        if amount <= 0 {
            return Err(PayoutPrecisionError::NonPositiveAmount);
        }
        total = total
            .checked_add(amount)
            .ok_or(PayoutPrecisionError::ArithmeticOverflow)?;
    }
    Ok(total)
}

/// Execution-path guard: validate payouts before any run state is written.
///
/// Panic messages are static. They never include the amounts that caused the
/// failure, so a rejected payroll batch cannot leak salary data into logs.
pub(crate) fn require_precise_batch_total(
    e: &Env,
    amounts: &Vec<i128>,
    expected_total: i128,
) -> i128 {
    let _ = e;
    let total = match sum_payout_amounts(amounts) {
        Ok(total) => total,
        Err(PayoutPrecisionError::ArithmeticOverflow) => {
            panic!("Payout batch total overflow: amounts cannot be represented in i128")
        }
        Err(_) => panic!("Amount must be positive"),
    };
    if total != expected_total {
        // Keep the historical prefix for compatibility with existing clients
        // and docs, without echoing the values themselves.
        panic!("Expected spend mismatch: the authorised total differs from the batch total");
    }
    total
}

#[contractimpl]
impl Payroll {
    /// Read-only preflight for a pro-rata payout (#1085).
    ///
    /// Returns the rounded amount, its exact rounding delta, and the drift in
    /// basis points. No state is read or written and no sensitive values are
    /// logged.
    pub fn check_payout_precision(
        e: Env,
        gross_amount: i128,
        numerator: i128,
        denominator: i128,
        decimals: u32,
        tolerance_bps: u32,
        rounding_mode: PayoutRoundingMode,
    ) -> Result<PayoutPrecisionAssessment, PayoutPrecisionError> {
        let _ = e;
        validate_pro_rata_payout(
            gross_amount,
            numerator,
            denominator,
            decimals,
            tolerance_bps,
            rounding_mode,
        )
    }

    /// Read-only preflight for an exact payout batch total (#1085).
    ///
    /// Confirms that every amount is positive, the sum is representable, and
    /// the sum matches the authorised spend, without moving funds.
    pub fn validate_payout_batch(
        e: Env,
        amounts: Vec<i128>,
        expected_total_spend: i128,
    ) -> Result<PayoutBatchAssessment, PayoutPrecisionError> {
        let _ = e;
        let total = sum_payout_amounts(&amounts)?;
        if total != expected_total_spend {
            return Err(PayoutPrecisionError::ExpectedSpendMismatch);
        }
        Ok(PayoutBatchAssessment {
            payment_count: amounts.len(),
            total,
            expected_total: expected_total_spend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::vec;

    #[test]
    fn exact_pro_rata_payout_has_no_rounding_delta() {
        let result =
            validate_pro_rata_payout(1_000_000, 1, 4, 7, 0, PayoutRoundingMode::Floor).unwrap();
        assert_eq!(result.rounded_amount, 250_000);
        assert_eq!(result.rounding_delta, 0);
        assert_eq!(result.drift_bps, 0);
        // Conservation: rounded * denominator - delta == gross * numerator.
        assert_eq!(result.rounded_amount * 4 - result.rounding_delta, 1_000_000);
    }

    #[test]
    fn floor_rounding_reports_downward_delta_and_bounded_drift() {
        let result =
            validate_pro_rata_payout(1_000_003, 1, 4, 7, 7_500, PayoutRoundingMode::Floor).unwrap();
        assert_eq!(result.rounded_amount, 250_000);
        assert_eq!(result.rounding_delta, -3);
        assert_eq!(result.drift_bps, 7_500);
        assert_eq!(result.rounded_amount * 4 - result.rounding_delta, 1_000_003);
    }

    #[test]
    fn half_up_rounds_nearest_and_can_report_upward_delta() {
        let result =
            validate_pro_rata_payout(1_001, 1, 2, 7, 5_000, PayoutRoundingMode::HalfUp).unwrap();
        assert_eq!(result.rounded_amount, 501);
        assert_eq!(result.rounding_delta, 1);
        assert_eq!(result.drift_bps, 5_000);
    }

    #[test]
    fn rounding_drift_above_tolerance_is_rejected() {
        assert_eq!(
            validate_pro_rata_payout(1_000_003, 1, 4, 7, 100, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::RoundingDriftExceedsTolerance)
        );
        assert_eq!(
            validate_pro_rata_payout(1_001, 1, 2, 7, 4_999, PayoutRoundingMode::HalfUp),
            Err(PayoutPrecisionError::RoundingDriftExceedsTolerance)
        );
    }

    #[test]
    fn invalid_precision_inputs_have_stable_typed_errors() {
        assert_eq!(
            validate_pro_rata_payout(0, 1, 2, 7, 0, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::NonPositiveAmount)
        );
        assert_eq!(
            validate_pro_rata_payout(100, 1, 2, 19, 0, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::InvalidDecimals)
        );
        assert_eq!(
            validate_pro_rata_payout(100, 2, 1, 7, 0, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::InvalidShare)
        );
        assert_eq!(
            validate_pro_rata_payout(100, 1, 0, 7, 0, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::InvalidShare)
        );
        assert_eq!(
            validate_pro_rata_payout(100, 1, 2, 7, 10_001, PayoutRoundingMode::Floor),
            Err(PayoutPrecisionError::InvalidTolerance)
        );
        assert_eq!(
            validate_pro_rata_payout(
                i128::MAX,
                i128::MAX,
                i128::MAX,
                7,
                0,
                PayoutRoundingMode::Floor
            ),
            Err(PayoutPrecisionError::ArithmeticOverflow)
        );
    }

    #[test]
    fn maximum_precision_boundary_is_accepted() {
        let result = validate_pro_rata_payout(
            18,
            1,
            2,
            MAX_PAYOUT_DECIMALS,
            10_000,
            PayoutRoundingMode::HalfUp,
        )
        .unwrap();
        assert_eq!(result.rounded_amount, 9);
        assert_eq!(result.decimals, MAX_PAYOUT_DECIMALS);
    }

    #[test]
    fn batch_sum_preserves_non_round_amounts() {
        let env = Env::default();
        let amounts = vec![&env, 1_i128, 333_333_333, 999_999_937];
        assert_eq!(sum_payout_amounts(&amounts), Ok(1_333_333_271));
    }

    #[test]
    fn batch_sum_rejects_non_positive_and_overflow() {
        let env = Env::default();
        assert_eq!(
            sum_payout_amounts(&vec![&env, 10_i128, 0]),
            Err(PayoutPrecisionError::NonPositiveAmount)
        );
        assert_eq!(
            sum_payout_amounts(&vec![&env, i128::MAX, 1]),
            Err(PayoutPrecisionError::ArithmeticOverflow)
        );
    }
}
