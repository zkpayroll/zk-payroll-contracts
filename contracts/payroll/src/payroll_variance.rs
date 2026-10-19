//! Payroll variance threshold validation (#644).
//!
//! A *variance* is the relative move between a payroll baseline total and a
//! proposed total, expressed in basis points (1 bp = 0.01%). An employer may
//! configure a ceiling such as 1000 bps (10%) so that an accidental extra zero
//! or a truncated batch is rejected at write time with an actionable error
//! instead of silently flowing into finalization.
//!
//! The policy is opt-in. While no threshold is stored,
//! [`Payroll::amend_run_draft`](crate::Payroll::amend_run_draft) behaves exactly
//! as it did before this feature existed: no check runs and no storage is
//! touched. Once an admin calls
//! [`Payroll::set_payroll_variance_threshold`](crate::Payroll::set_payroll_variance_threshold),
//! every draft amendment is checked against the ceiling before any state is
//! written, and a rejected amendment consumes no correction budget and mutates
//! no draft state.
//!
//! A threshold of `0` is meaningful (only exact matches are accepted) and is
//! distinct from "not configured". The maximum is [`MAX_VARIANCE_BPS`] (100%).
//!
//! Everything here is privacy-safe: only aggregate totals and basis-point
//! magnitudes are inspected. No salary amount breakdown, employee identity, or
//! proof material is stored, surfaced, or emitted.

use soroban_sdk::contracttype;

/// Basis points in 100%: the largest configurable variance threshold.
pub const MAX_VARIANCE_BPS: u32 = 10_000;

/// Basis-point scale factor: 1 bp = 0.01%.
const BPS_SCALE: u128 = 10_000;

/// Employer-configured payroll variance ceiling (#644).
///
/// Stored under [`crate::VarianceKey::PayrollVarianceThreshold`]. Absent
/// storage means "not configured" (unrestricted); a stored `0` means only
/// exact matches are accepted.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayrollVarianceConfig {
    /// Maximum allowed relative move in basis points (`0..=10_000`).
    pub max_variance_bps: u32,
}

/// Privacy-safe snapshot of a variance pre-flight check (#644).
///
/// Carries only aggregate totals and basis-point magnitudes, never employee
/// identities or salary breakdowns, so it is safe to surface to dashboards and
/// integrators.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayrollVarianceCheck {
    /// Baseline total the proposed total was compared against.
    pub baseline_total: i128,
    /// Proposed total that was evaluated.
    pub proposed_total: i128,
    /// Configured ceiling in basis points (`0` when unconfigured).
    pub max_variance_bps: u32,
    /// Measured relative move in basis points (`u32::MAX` saturates).
    pub variance_bps: u32,
    /// `true` when the proposed total satisfies the configured ceiling
    /// (always `true` when no threshold is configured).
    pub within_threshold: bool,
    /// `true` when a threshold is configured (even `0`).
    pub threshold_configured: bool,
}

/// Reason a payroll variance validation failed (#644).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayrollVarianceIssue {
    /// No threshold is configured; any total is acceptable.
    NoThresholdConfigured,
    /// The configured ceiling exceeds [`MAX_VARIANCE_BPS`].
    InvalidThreshold,
    /// The baseline total is not positive, so no relative move can be computed.
    InvalidBaseline,
    /// The proposed total is not positive.
    InvalidProposed,
    /// The measured variance exceeds the configured ceiling.
    ExceedsThreshold,
}

impl PayrollVarianceIssue {
    /// Stable, integration-friendly code for this issue.
    pub fn as_str(&self) -> &'static str {
        match self {
            PayrollVarianceIssue::NoThresholdConfigured => "no_threshold_configured",
            PayrollVarianceIssue::InvalidThreshold => "invalid_threshold",
            PayrollVarianceIssue::InvalidBaseline => "invalid_baseline",
            PayrollVarianceIssue::InvalidProposed => "invalid_proposed",
            PayrollVarianceIssue::ExceedsThreshold => "variance_exceeds_threshold",
        }
    }
}

/// Measure the relative move from `baseline` to `proposed` in basis points.
///
/// Returns `0` when both totals are equal (including `0 == 0`) and
/// `u32::MAX` when the move is undefined or overflows: a zero baseline with a
/// non-zero proposal, or a delta so large that `delta * 10_000` does not fit
/// in a `u128`. Saturating keeps a pathological input from wrapping into a
/// small, passing value.
pub fn variance_bps(baseline: i128, proposed: i128) -> u32 {
    if baseline == proposed {
        return 0;
    }
    if baseline <= 0 {
        return u32::MAX;
    }
    let delta: u128 = if proposed >= baseline {
        (proposed - baseline) as u128
    } else {
        (baseline - proposed) as u128
    };
    let baseline_u: u128 = baseline as u128;
    // Guard the multiply before it can wrap: anything this large already
    // exceeds every configurable ceiling.
    if delta > u128::MAX / BPS_SCALE {
        return u32::MAX;
    }
    let scaled = delta.saturating_mul(BPS_SCALE);
    let bps = scaled / baseline_u;
    if bps > u32::MAX as u128 {
        u32::MAX
    } else {
        bps as u32
    }
}

/// Build a [`PayrollVarianceCheck`] snapshot without mutating any state.
///
/// `max_bps` is `None` when no threshold is configured, in which case the
/// check always reports `within_threshold = true`.
pub fn check_payroll_variance(
    baseline: i128,
    proposed: i128,
    max_bps: Option<u32>,
) -> PayrollVarianceCheck {
    let Some(max) = max_bps else {
        return PayrollVarianceCheck {
            baseline_total: baseline,
            proposed_total: proposed,
            max_variance_bps: 0,
            variance_bps: variance_bps(baseline, proposed),
            within_threshold: true,
            threshold_configured: false,
        };
    };
    let measured = variance_bps(baseline, proposed);
    // An invalid ceiling can never be satisfied; the write path rejects such
    // a ceiling outright, so reaching this branch means stored data predates
    // validation or the caller supplied it directly.
    let within = max <= MAX_VARIANCE_BPS && baseline > 0 && proposed > 0 && measured <= max;
    PayrollVarianceCheck {
        baseline_total: baseline,
        proposed_total: proposed,
        max_variance_bps: max,
        variance_bps: measured,
        within_threshold: within,
        threshold_configured: true,
    }
}

/// Validate a proposed total against a baseline and an optional ceiling.
///
/// Returns `Ok(())` when no threshold is configured or the move fits inside
/// it. Otherwise returns the first applicable [`PayrollVarianceIssue`]:
/// invalid ceiling, non-positive baseline, non-positive proposal, then
/// threshold breach.
pub fn validate_payroll_variance(
    baseline: i128,
    proposed: i128,
    max_bps: Option<u32>,
) -> Result<(), PayrollVarianceIssue> {
    let Some(max) = max_bps else {
        return Ok(());
    };
    if max > MAX_VARIANCE_BPS {
        return Err(PayrollVarianceIssue::InvalidThreshold);
    }
    if baseline <= 0 {
        return Err(PayrollVarianceIssue::InvalidBaseline);
    }
    if proposed <= 0 {
        return Err(PayrollVarianceIssue::InvalidProposed);
    }
    if variance_bps(baseline, proposed) > max {
        return Err(PayrollVarianceIssue::ExceedsThreshold);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_totals_have_zero_variance() {
        assert_eq!(variance_bps(1_000, 1_000), 0);
        assert_eq!(variance_bps(0, 0), 0);
    }

    #[test]
    fn ten_percent_move_is_1000_bps() {
        assert_eq!(variance_bps(1_000, 1_100), 1_000);
        assert_eq!(variance_bps(1_000, 900), 1_000);
    }

    #[test]
    fn boundary_rounds_down_like_integer_division() {
        // 1 / 10_000 = 1bp exactly.
        assert_eq!(variance_bps(10_000, 10_001), 1);
        // 1 / 20_000 = 0.5bp truncates to 0.
        assert_eq!(variance_bps(20_000, 20_001), 0);
    }

    #[test]
    fn zero_baseline_with_nonzero_proposal_saturates() {
        assert_eq!(variance_bps(0, 1_000), u32::MAX);
    }

    #[test]
    fn unconfigured_threshold_always_passes() {
        assert!(validate_payroll_variance(1_000, 99_000_000, None).is_ok());
        let check = check_payroll_variance(1_000, 2_000, None);
        assert!(check.within_threshold);
        assert!(!check.threshold_configured);
        assert_eq!(check.variance_bps, 10_000);
    }

    #[test]
    fn exact_threshold_boundary_passes() {
        assert!(validate_payroll_variance(1_000, 1_100, Some(1_000)).is_ok());
        let check = check_payroll_variance(1_000, 1_100, Some(1_000));
        assert!(check.within_threshold);
        assert_eq!(check.variance_bps, 1_000);
    }

    #[test]
    fn one_bp_over_threshold_fails() {
        assert_eq!(
            validate_payroll_variance(10_000, 11_001, Some(1_000)),
            Err(PayrollVarianceIssue::ExceedsThreshold)
        );
    }

    #[test]
    fn zero_threshold_requires_exact_match() {
        assert!(validate_payroll_variance(5_000, 5_000, Some(0)).is_ok());
        assert_eq!(
            validate_payroll_variance(5_000, 5_001, Some(0)),
            Err(PayrollVarianceIssue::ExceedsThreshold)
        );
    }

    #[test]
    fn full_range_threshold_accepts_doubling() {
        // Doubling is exactly a 100% move.
        assert!(validate_payroll_variance(1_000, 2_000, Some(10_000)).is_ok());
        assert_eq!(
            validate_payroll_variance(1_000, 2_001, Some(10_000)),
            Err(PayrollVarianceIssue::ExceedsThreshold)
        );
    }

    #[test]
    fn invalid_inputs_are_reported_first() {
        assert_eq!(
            validate_payroll_variance(1_000, 1_100, Some(10_001)),
            Err(PayrollVarianceIssue::InvalidThreshold)
        );
        assert_eq!(
            validate_payroll_variance(0, 1_100, Some(1_000)),
            Err(PayrollVarianceIssue::InvalidBaseline)
        );
        assert_eq!(
            validate_payroll_variance(1_000, 0, Some(1_000)),
            Err(PayrollVarianceIssue::InvalidProposed)
        );
    }

    #[test]
    fn issue_codes_are_stable() {
        assert_eq!(
            PayrollVarianceIssue::ExceedsThreshold.as_str(),
            "variance_exceeds_threshold"
        );
        assert_eq!(
            PayrollVarianceIssue::NoThresholdConfigured.as_str(),
            "no_threshold_configured"
        );
    }
}
