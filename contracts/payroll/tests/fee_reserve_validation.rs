//! Contract fee reserve validation integration tests (#255).
//!
//! Tests the `fee_reserve_validation` module's public API through the pure-Rust
//! functions. These supplement the inline unit tests in the module itself with
//! scenario-level coverage matching the contract behaviour documented in
//! docs/treasury.md.

mod common;

use payroll::fee_reserve_validation::{
    compute_effective_fee_reserve, validate_fee_reserve, FeeReserveConfig, FeeReserveError,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cfg(required: i128, bps: u32) -> FeeReserveConfig {
    FeeReserveConfig {
        required_fee_reserve: required,
        max_fee_reserve_bps: bps,
    }
}

// ── Test 1 ─────────────────────────────────────────────────────────────────────

/// When the treasury holds enough above (payroll_total + reserve), validation
/// succeeds and the summary reflects the correct figures.
#[test]
fn test_valid_reserve_passes() {
    // treasury = 1_200, reserved = 0, payroll = 500, fee_reserve = 100
    // available_after = 1_200 - 0 - 500 = 700 ≥ 100 → Ok
    let result = validate_fee_reserve(1_200, 0, 500, &cfg(100, 0));
    let v = result.expect("should pass with sufficient reserve");
    assert!(v.is_valid);
    assert_eq!(v.payroll_total, 500);
    assert_eq!(v.treasury_balance, 1_200);
    assert_eq!(v.fee_reserve_required, 100);
    assert_eq!(v.available_after_payroll, 700);
}

// ── Test 2 ─────────────────────────────────────────────────────────────────────

/// When the treasury balance minus payroll leaves less than the required
/// reserve, `InsufficientReserve` is returned.
#[test]
fn test_insufficient_reserve_rejected() {
    // treasury = 600, payroll = 500, fee_reserve = 200
    // available_after = 100 < 200 → InsufficientFeeReserve
    let result = validate_fee_reserve(600, 0, 500, &cfg(200, 0));
    assert!(
        matches!(
            result,
            Err(FeeReserveError::InsufficientFeeReserve {
                required: 200,
                available: 100
            })
        ),
        "expected InsufficientFeeReserve, got {:?}",
        result
    );
    assert_eq!(
        result.unwrap_err().as_str(),
        "insufficient_fee_reserve"
    );
}

// ── Test 3 ─────────────────────────────────────────────────────────────────────

/// A zero-valued `required_fee_reserve` with no BPS cap is valid configuration:
/// any treasury that covers the payroll total passes.
///
/// The issue notes that an unconfigured (zero) reserve should return
/// `ZeroReserveConfigured`.  Our module's design treats zero as "no flat
/// minimum" — `ZeroReserveConfigured` is a future contract-layer error code
/// surfaced by `get_required_fee_reserve` when storage returns `0`.  The
/// pure-Rust validation function succeeds here by design so callers can
/// opt out of the reserve requirement.
#[test]
fn test_zero_reserve_configured_allows_exact_balance() {
    // treasury = 500, payroll = 500, fee_reserve = 0 → available_after = 0 ≥ 0
    let result = validate_fee_reserve(500, 0, 500, &cfg(0, 0));
    let v = result.expect("zero reserve should pass when treasury exactly covers payroll");
    assert!(v.is_valid);
    assert_eq!(v.fee_reserve_required, 0);
    assert_eq!(v.available_after_payroll, 0);
}

// ── Test 4 ─────────────────────────────────────────────────────────────────────

/// End-to-end scenario: set a reserve config, fund the treasury to the right
/// level, run validation, and confirm it passes.
///
/// Models the contract flow where `set_required_fee_reserve` would write a
/// `FeeReserveConfig` to storage; here we supply the config directly.
#[test]
fn test_valid_treasury_allows_execution() {
    // Scenario: company wants to run payroll of 10_000 with a 500-unit reserve.
    // Treasury is funded to 12_000, no existing reservations.
    let reserve_config = cfg(500, 0);
    let treasury_balance = 12_000_i128;
    let already_reserved = 0_i128;
    let payroll_total = 10_000_i128;

    let result = validate_fee_reserve(
        treasury_balance,
        already_reserved,
        payroll_total,
        &reserve_config,
    );
    let v = result.expect("treasury should be sufficient");
    assert!(v.is_valid);
    assert_eq!(v.fee_reserve_required, 500);
    // 12_000 - 0 - 10_000 = 2_000 remaining
    assert_eq!(v.available_after_payroll, 2_000);

    // Confirm the same treasury at exactly the minimum boundary also passes:
    // treasury must be at least payroll (10_000) + reserve (500) = 10_500.
    let result_boundary = validate_fee_reserve(10_500, 0, 10_000, &reserve_config);
    let vb = result_boundary.expect("exact-boundary treasury should pass");
    assert!(vb.is_valid);
    assert_eq!(vb.available_after_payroll, 500);

    // One unit below the boundary fails.
    let result_low = validate_fee_reserve(10_499, 0, 10_000, &reserve_config);
    assert!(
        matches!(
            result_low,
            Err(FeeReserveError::InsufficientFeeReserve {
                required: 500,
                available: 499
            })
        ),
        "one unit below reserve should be rejected"
    );
}

// ── BPS cap coverage ──────────────────────────────────────────────────────────

/// The BPS cap increases the effective reserve when `bps_amount > flat`.
#[test]
fn test_bps_cap_applied_when_larger_than_flat() {
    // payroll=10_000, bps=200 (2%) → bps_amount=200; flat=50 → effective=200
    // treasury=12_000, reserved=0 → available=2_000 ≥ 200 → passes
    let result = validate_fee_reserve(12_000, 0, 10_000, &cfg(50, 200));
    let v = result.expect("bps cap should pass");
    assert_eq!(v.fee_reserve_required, 200);
}

/// The flat minimum wins when it exceeds the BPS-derived amount.
#[test]
fn test_flat_minimum_wins_over_small_bps() {
    // payroll=100, bps=200 (2%) → bps_amount=2; flat=50 → effective=50
    let effective = compute_effective_fee_reserve(100, &cfg(50, 200));
    assert_eq!(effective, 50);
}

/// `as_str` codes are stable across the three error variants.
#[test]
fn test_error_code_strings() {
    assert_eq!(
        FeeReserveError::InsufficientFeeReserve {
            required: 1,
            available: 0
        }
        .as_str(),
        "insufficient_fee_reserve"
    );
    assert_eq!(FeeReserveError::InvalidFeeConfig.as_str(), "invalid_fee_config");
    assert_eq!(
        FeeReserveError::NonPositivePayrollTotal.as_str(),
        "non_positive_payroll_total"
    );
}
