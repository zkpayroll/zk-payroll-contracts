//! Employer-configured authorization limits for payroll corrections (issue #577).
//!
//! A *correction* is an amendment to a pending payroll run draft, applied
//! through `amend_run_draft`. Before this module the amendment flow accepted
//! any number of amendments of any size, so an employer had no on-chain way to
//! bound how much a correction could move or how many employees it could touch.
//!
//! An employer opts in by calling `set_correction_limits`. Until
//! they do, no limits are stored and the amendment flow behaves exactly as it
//! always has — this is deliberately backward compatible. Once limits are
//! configured, every correction to a payroll period is measured against three
//! counters accumulated for that period:
//!
//! * the number of corrections applied,
//! * the cumulative absolute amount moved by those corrections,
//! * the number of employees covered by those corrections.
//!
//! Everything here is privacy-safe: it stores and reports only aggregate
//! counters and totals. It never reads, emits, or returns salary amounts,
//! per-employee values, or employee identities, and the rejection messages
//! name the limit that was hit without disclosing any payroll value.

use soroban_sdk::{contracttype, Env, Symbol};

use crate::DataKey;

/// Employer-configured authorization limits for payroll corrections.
///
/// Corrections are opt-in limited: when this policy is absent from storage the
/// amendment flow performs no correction checks at all. A zero on an individual
/// field means "that dimension is not capped", so an all-zero policy is
/// equivalent to leaving the feature disabled.
///
/// Privacy-safe: contains only counts and thresholds, never salary values or
/// employee identities.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionAuthorizationLimits {
    /// Maximum number of corrections allowed per payroll period.
    pub max_corrections_per_period: u32,
    /// Maximum cumulative absolute value delta allowed per payroll period.
    pub max_total_delta: i128,
    /// Maximum number of employees whose entries may be corrected per period.
    pub max_employees_corrected: u32,
}

/// Accumulated correction usage counters for a single payroll period, tracked
/// against the employer's configured [`CorrectionAuthorizationLimits`].
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionUsage {
    /// Corrections successfully applied so far in this period.
    pub correction_count: u32,
    /// Cumulative absolute amount moved by those corrections.
    pub total_delta: i128,
    /// Employees covered by those corrections.
    pub employees_corrected: u32,
}

impl CorrectionUsage {
    /// The counters reported for a period that has seen no corrections.
    pub(crate) fn zeroed() -> Self {
        Self {
            correction_count: 0,
            total_delta: 0,
            employees_corrected: 0,
        }
    }
}

/// The configured correction policy, or `None` when the feature is disabled.
pub(crate) fn configured_limits(e: &Env) -> Option<CorrectionAuthorizationLimits> {
    e.storage()
        .persistent()
        .get(&DataKey::CorrectionAuthorizationLimits)
}

/// Accumulated correction usage for `period_label`.
///
/// Returns zeroed counters when nothing has been recorded for the period, so
/// callers never have to special-case a missing record.
pub(crate) fn usage_for(e: &Env, period_label: &Symbol) -> CorrectionUsage {
    e.storage()
        .persistent()
        .get(&DataKey::CorrectionUsage(period_label.clone()))
        .unwrap_or_else(CorrectionUsage::zeroed)
}

/// Store a new correction policy.
pub(crate) fn write_limits(e: &Env, limits: &CorrectionAuthorizationLimits) {
    e.storage()
        .persistent()
        .set(&DataKey::CorrectionAuthorizationLimits, limits);
}

/// Reject a correction that would exceed any configured limit.
///
/// Call this *before* applying a correction so a rejected attempt leaves no
/// partial state behind. When no policy is configured the check is a no-op,
/// which is what keeps the feature backward compatible.
///
/// # Panics
/// * `delta` is negative.
/// * The period has already used its allowance of corrections, employees, or
///   total delta.
pub(crate) fn require_within_limits(
    e: &Env,
    period_label: &Symbol,
    delta: i128,
    employees_touched: u32,
) {
    if delta < 0 {
        panic!("Correction delta cannot be negative");
    }

    let Some(limits) = configured_limits(e) else {
        return;
    };
    let usage = usage_for(e, period_label);

    if limits.max_corrections_per_period > 0
        && usage.correction_count >= limits.max_corrections_per_period
    {
        panic!("Correction authorization limit exceeded: maximum corrections per period reached");
    }
    if limits.max_employees_corrected > 0
        && usage.employees_corrected.saturating_add(employees_touched)
            > limits.max_employees_corrected
    {
        panic!(
            "Correction authorization limit exceeded: maximum employees corrected per period reached"
        );
    }
    if limits.max_total_delta > 0
        && usage.total_delta.saturating_add(delta) > limits.max_total_delta
    {
        panic!("Correction authorization limit exceeded: maximum total delta per period reached");
    }
}

/// Record a correction that has been applied.
///
/// Call this only after the correction has been written, so the counters never
/// advance for an attempt that reverted. When no policy is configured this is a
/// no-op and writes no storage, so contracts that never opt in pay nothing for
/// the feature.
pub(crate) fn record(e: &Env, period_label: &Symbol, delta: i128, employees_touched: u32) {
    if !e
        .storage()
        .persistent()
        .has(&DataKey::CorrectionAuthorizationLimits)
    {
        return;
    }

    let mut usage = usage_for(e, period_label);
    usage.correction_count = usage.correction_count.saturating_add(1);
    usage.total_delta = usage.total_delta.saturating_add(delta);
    usage.employees_corrected = usage.employees_corrected.saturating_add(employees_touched);
    e.storage()
        .persistent()
        .set(&DataKey::CorrectionUsage(period_label.clone()), &usage);
}
