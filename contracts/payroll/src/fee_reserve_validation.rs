//! Fee reserve validation (#255).
//!
//! Before a payroll run executes, the treasury must hold enough funds not only
//! to cover the payroll amounts but also a fee reserve to handle on-chain
//! transaction costs. This module provides pure validation logic so execution
//! fails early with a clear error instead of partway through payment.
//!
//! Privacy: only aggregate token amounts are checked; no employee identity,
//! salary row, or commitment is involved.

/// Why fee reserve validation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeReserveError {
    /// Treasury does not hold enough above the payroll total for fees.
    ///
    /// `required` is the fee reserve that must remain and `available` is how
    /// much is actually left after payroll — never negative.
    InsufficientFeeReserve { required: i128, available: i128 },
    /// Fee reserve config is invalid (negative reserve required).
    InvalidFeeConfig,
    /// Payroll total must be positive.
    NonPositivePayrollTotal,
}

impl FeeReserveError {
    /// Stable string codes for logs, dashboards, and tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            FeeReserveError::InsufficientFeeReserve { .. } => "insufficient_fee_reserve",
            FeeReserveError::InvalidFeeConfig => "invalid_fee_config",
            FeeReserveError::NonPositivePayrollTotal => "non_positive_payroll_total",
        }
    }
}

/// Policy governing how much of the treasury must remain after payroll as a
/// fee reserve.
///
/// - `required_fee_reserve`: the flat minimum that must remain free in the
///   treasury after the payroll total is deducted.  Zero is allowed (no flat
///   minimum).
/// - `max_fee_reserve_bps`: an optional cap expressed in basis points of the
///   payroll total.  When non-zero the effective reserve is the larger of the
///   flat minimum and `payroll_total * max_fee_reserve_bps / 10_000`.  Zero
///   means "no BPS cap" — only the flat minimum applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeReserveConfig {
    /// Minimum fee reserve to keep in treasury after payroll (absolute amount).
    pub required_fee_reserve: i128,
    /// Maximum fee reserve as basis points of payroll total (0 = no BPS cap).
    pub max_fee_reserve_bps: u32,
}

/// Summary of a fee-reserve validation check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeReserveValidation {
    /// Payroll total that was validated.
    pub payroll_total: i128,
    /// Treasury balance at validation time.
    pub treasury_balance: i128,
    /// Funds already locked by other pending runs.
    pub reserved: i128,
    /// Fee reserve that must remain after payroll (computed from config).
    pub fee_reserve_required: i128,
    /// Balance available after deducting existing reservations and the payroll
    /// total.  Never negative.
    pub available_after_payroll: i128,
    /// `true` iff `available_after_payroll >= fee_reserve_required`.
    pub is_valid: bool,
}

/// Returns the larger of the flat `required_fee_reserve` and the BPS-derived
/// amount for `payroll_total`.  When `max_fee_reserve_bps` is 0 only the flat
/// minimum is returned.
pub fn compute_effective_fee_reserve(payroll_total: i128, config: &FeeReserveConfig) -> i128 {
    if config.max_fee_reserve_bps == 0 {
        return config.required_fee_reserve;
    }
    let bps_amount = payroll_total
        .saturating_mul(config.max_fee_reserve_bps as i128)
        / 10_000;
    config.required_fee_reserve.max(bps_amount)
}

/// Validate that the treasury holds enough to cover both the payroll total and
/// the required fee reserve.
///
/// Returns `InvalidFeeConfig` if `config.required_fee_reserve < 0`.
/// Returns `NonPositivePayrollTotal` if `payroll_total <= 0`.
/// Returns `InsufficientFeeReserve` when the balance remaining after
/// `already_reserved + payroll_total` is below the required fee reserve.
/// Returns `Ok(FeeReserveValidation { … })` on success.
pub fn validate_fee_reserve(
    treasury_balance: i128,
    already_reserved: i128,
    payroll_total: i128,
    config: &FeeReserveConfig,
) -> Result<FeeReserveValidation, FeeReserveError> {
    if config.required_fee_reserve < 0 {
        return Err(FeeReserveError::InvalidFeeConfig);
    }

    if payroll_total <= 0 {
        return Err(FeeReserveError::NonPositivePayrollTotal);
    }

    let fee_reserve_required = compute_effective_fee_reserve(payroll_total, config);

    // How much remains in the treasury after existing locks and this payroll.
    // Clamp to 0 so we never report a negative available balance.
    let available_after_payroll = treasury_balance
        .saturating_sub(already_reserved.max(0))
        .saturating_sub(payroll_total)
        .max(0);

    if available_after_payroll < fee_reserve_required {
        return Err(FeeReserveError::InsufficientFeeReserve {
            required: fee_reserve_required,
            available: available_after_payroll,
        });
    }

    Ok(FeeReserveValidation {
        payroll_total,
        treasury_balance,
        reserved: already_reserved,
        fee_reserve_required,
        available_after_payroll,
        is_valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(required: i128, bps: u32) -> FeeReserveConfig {
        FeeReserveConfig {
            required_fee_reserve: required,
            max_fee_reserve_bps: bps,
        }
    }

    #[test]
    fn test_valid_fee_reserve_passes() {
        // treasury=1000, reserved=0, payroll=500, fee_reserve=100 → available=500 ≥ 100
        let result = validate_fee_reserve(1_000, 0, 500, &config(100, 0));
        let v = result.expect("should pass");
        assert!(v.is_valid);
        assert_eq!(v.payroll_total, 500);
        assert_eq!(v.treasury_balance, 1_000);
        assert_eq!(v.reserved, 0);
        assert_eq!(v.fee_reserve_required, 100);
        assert_eq!(v.available_after_payroll, 500);
    }

    #[test]
    fn test_insufficient_fee_reserve_fails() {
        // treasury=600, reserved=0, payroll=500, fee_reserve=200 → available=100 < 200
        let result = validate_fee_reserve(600, 0, 500, &config(200, 0));
        assert_eq!(
            result,
            Err(FeeReserveError::InsufficientFeeReserve {
                required: 200,
                available: 100
            })
        );
    }

    #[test]
    fn test_zero_fee_reserve_config_passes() {
        // required=0 — any payroll that fits in the treasury is fine
        let result = validate_fee_reserve(500, 0, 500, &config(0, 0));
        let v = result.expect("should pass with zero reserve");
        assert!(v.is_valid);
        assert_eq!(v.fee_reserve_required, 0);
        assert_eq!(v.available_after_payroll, 0);
    }

    #[test]
    fn test_negative_fee_config_is_invalid() {
        let result = validate_fee_reserve(1_000_000, 0, 500, &config(-1, 0));
        assert_eq!(result, Err(FeeReserveError::InvalidFeeConfig));
        assert_eq!(
            FeeReserveError::InvalidFeeConfig.as_str(),
            "invalid_fee_config"
        );
    }

    #[test]
    fn test_non_positive_payroll_total_fails() {
        // zero total
        assert_eq!(
            validate_fee_reserve(1_000, 0, 0, &config(50, 0)),
            Err(FeeReserveError::NonPositivePayrollTotal)
        );
        // negative total
        assert_eq!(
            validate_fee_reserve(1_000, 0, -100, &config(50, 0)),
            Err(FeeReserveError::NonPositivePayrollTotal)
        );
        assert_eq!(
            FeeReserveError::NonPositivePayrollTotal.as_str(),
            "non_positive_payroll_total"
        );
    }

    #[test]
    fn test_bps_cap_is_applied() {
        // payroll=1000, bps=200 (2%) → bps_amount=20; flat=10 → effective=20
        // treasury=1100, reserved=0 → available_after_payroll=100 ≥ 20 → passes
        let cfg = config(10, 200);
        let result = validate_fee_reserve(1_100, 0, 1_000, &cfg);
        let v = result.expect("should pass");
        assert_eq!(v.fee_reserve_required, 20); // BPS amount wins over flat 10
        assert_eq!(v.available_after_payroll, 100);

        // Now make the treasury just barely insufficient:
        // treasury=1010, reserved=0, payroll=1000 → available=10 < 20
        let result2 = validate_fee_reserve(1_010, 0, 1_000, &cfg);
        assert_eq!(
            result2,
            Err(FeeReserveError::InsufficientFeeReserve {
                required: 20,
                available: 10
            })
        );
    }

    #[test]
    fn test_compute_effective_fee_reserve_returns_larger() {
        // flat=100, bps=0 → 100
        assert_eq!(
            compute_effective_fee_reserve(50_000, &config(100, 0)),
            100
        );

        // flat=100, bps=100 (1%), payroll=50_000 → bps_amount=500 > 100 → 500
        assert_eq!(
            compute_effective_fee_reserve(50_000, &config(100, 100)),
            500
        );

        // flat=1000, bps=100 (1%), payroll=50_000 → bps_amount=500 < 1000 → 1000
        assert_eq!(
            compute_effective_fee_reserve(50_000, &config(1_000, 100)),
            1_000
        );

        // flat=0, bps=50 (0.5%), payroll=10_000 → bps_amount=50 > 0 → 50
        assert_eq!(
            compute_effective_fee_reserve(10_000, &config(0, 50)),
            50
        );
    }
}
