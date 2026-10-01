//! Employer-configured authorization limits for payroll corrections (#577).
//!
//! A *correction* is an amendment to a pending payroll draft, applied through
//! [`crate::Payroll::amend_run_draft`]. Corrections move money, so an employer
//! may want a ceiling on how much correction activity a single payroll period
//! can absorb before the policy is deliberately revisited.
//!
//! Limits are opt-in. While no policy is configured
//! ([`crate::Payroll::get_correction_auth_limits`] returns `None`),
//! `amend_run_draft` behaves exactly as it did before this module existed: no
//! counter is read, no storage is written, and no correction is rejected. Once
//! an admin calls [`crate::Payroll::set_correction_auth_limits`], every
//! amendment in that period is checked against the configured ceilings and
//! recorded against the period's usage counters.
//!
//! Three independent ceilings are supported, each disabled by `0`:
//!
//! * [`CorrectionAuthorizationLimits::max_corrections_per_period`] — how many
//!   amendments a period accepts.
//! * [`CorrectionAuthorizationLimits::max_total_delta`] — cumulative absolute
//!   change in draft total amount.
//! * [`CorrectionAuthorizationLimits::max_employees_corrected`] — cumulative
//!   employee count carried by corrected drafts.
//!
//! Everything here is privacy-safe: counters are aggregate numbers only. No
//! salary amount, employee identity, or proof material is stored or surfaced,
//! and a rejection names the ceiling that was hit rather than any value.

use soroban_sdk::contracttype;

/// Employer-configured correction authorization ceilings for a payroll period.
///
/// A ceiling of `0` disables that particular check, so an all-zero policy is
/// equivalent to leaving the limits unset. Limits are enforced per payroll
/// period.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionAuthorizationLimits {
    /// Maximum number of corrections accepted per payroll period (`0` = no cap).
    pub max_corrections_per_period: u32,
    /// Maximum cumulative absolute change in draft total amount per period
    /// (`0` = no cap).
    pub max_total_delta: i128,
    /// Maximum cumulative employee count carried by corrected drafts per period
    /// (`0` = no cap).
    pub max_employees_corrected: u32,
}

/// Accumulated correction usage counters for a single payroll period.
///
/// Absent storage means "no corrections recorded yet"; [`CorrectionUsage::ZERO`]
/// is returned in that case. The struct intentionally carries no salary or
/// employee identifiers.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionUsage {
    /// Corrections applied to drafts in this period.
    pub correction_count: u32,
    /// Cumulative absolute change in draft total amount across those corrections.
    pub total_delta: i128,
    /// Cumulative employee count carried by those corrected drafts.
    pub employees_corrected: u32,
}

/// Which configured ceiling rejected a correction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrectionLimitBreach {
    /// `max_corrections_per_period` would be exceeded.
    CorrectionsPerPeriod,
    /// `max_total_delta` would be exceeded.
    TotalDelta,
    /// `max_employees_corrected` would be exceeded.
    EmployeesCorrected,
}

impl CorrectionUsage {
    /// Counters for a period with no recorded corrections.
    pub const ZERO: CorrectionUsage = CorrectionUsage {
        correction_count: 0,
        total_delta: 0,
        employees_corrected: 0,
    };

    /// Counters after applying one correction whose total amount moved by
    /// `delta` and which carries `employees_touched` employees. Uses
    /// saturating arithmetic so a pathological input can never wrap a counter.
    pub fn plus(&self, delta: i128, employees_touched: u32) -> CorrectionUsage {
        CorrectionUsage {
            correction_count: self.correction_count.saturating_add(1),
            total_delta: self.total_delta.saturating_add(delta),
            employees_corrected: self.employees_corrected.saturating_add(employees_touched),
        }
    }
}

impl CorrectionAuthorizationLimits {
    /// An all-zero policy constrains nothing and is treated as "not configured".
    pub fn is_effective(&self) -> bool {
        self.max_corrections_per_period > 0
            || self.max_total_delta > 0
            || self.max_employees_corrected > 0
    }

    /// Whether applying one correction of `delta` magnitude carrying
    /// `employees_touched` employees would stay within every configured ceiling,
    /// evaluated against the period's existing `usage`.
    ///
    /// `delta` is an absolute magnitude, so raising and lowering a draft total
    /// both consume the same budget. A zero ceiling disables that check.
    pub fn check(
        &self,
        usage: &CorrectionUsage,
        delta: i128,
        employees_touched: u32,
    ) -> Result<(), CorrectionLimitBreach> {
        if self.max_corrections_per_period > 0
            && usage.correction_count >= self.max_corrections_per_period
        {
            return Err(CorrectionLimitBreach::CorrectionsPerPeriod);
        }
        if self.max_employees_corrected > 0
            && usage.employees_corrected.saturating_add(employees_touched)
                > self.max_employees_corrected
        {
            return Err(CorrectionLimitBreach::EmployeesCorrected);
        }
        if self.max_total_delta > 0
            && usage.total_delta.saturating_add(delta) > self.max_total_delta
        {
            return Err(CorrectionLimitBreach::TotalDelta);
        }
        Ok(())
    }
}
