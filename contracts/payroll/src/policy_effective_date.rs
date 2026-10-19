//! Payroll policy effective-date guardrails (#703)
//!
//! Validates that payroll policies have valid effective dates and that
//! policy changes are applied at the correct time.

#![no_std]

use soroban_sdk::{contracttype, Env};

/// Error codes for policy effective-date validation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyDateError {
    /// The effective date is in the past.
    EffectiveDateInPast = 1,
    /// The effective date is too far in the future.
    EffectiveDateTooFarFuture = 2,
    /// The end date is before the start date.
    EndDateBeforeStartDate = 3,
    /// The policy is not yet effective.
    PolicyNotYetEffective = 4,
    /// The policy has already expired.
    PolicyExpired = 5,
    /// Overlapping policy periods.
    OverlappingPeriods = 6,
}

/// A payroll policy with effective-date bounds.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEffectivePeriod {
    /// Unix timestamp when the policy becomes effective.
    pub effective_from: u64,
    /// Unix timestamp when the policy expires (0 = never).
    pub effective_until: u64,
    /// Whether the policy is currently active.
    pub is_active: bool,
}

/// Maximum future horizon for policy effective dates (365 days in seconds).
pub const MAX_FUTURE_HORIZON: u64 = 365 * 24 * 60 * 60;

/// Validate that a policy effective date is within acceptable bounds.
pub fn validate_effective_date(
    env: &Env,
    effective_from: u64,
    effective_until: u64,
) -> Result<PolicyEffectivePeriod, PolicyDateError> {
    let now = env.ledger().timestamp();

    // Effective date cannot be in the past
    if effective_from < now {
        return Err(PolicyDateError::EffectiveDateInPast);
    }

    // Effective date cannot be too far in the future
    if effective_from > now + MAX_FUTURE_HORIZON {
        return Err(PolicyDateError::EffectiveDateTooFarFuture);
    }

    // If there's an end date, it must be after the start date
    if effective_until > 0 && effective_until <= effective_from {
        return Err(PolicyDateError::EndDateBeforeStartDate);
    }

    Ok(PolicyEffectivePeriod {
        effective_from,
        effective_until,
        is_active: effective_from <= now && (effective_until == 0 || effective_until > now),
    })
}

/// Check if a policy is currently effective.
pub fn is_policy_effective(env: &Env, period: &PolicyEffectivePeriod) -> bool {
    let now = env.ledger().timestamp();
    period.effective_from <= now && (period.effective_until == 0 || period.effective_until > now)
}

/// Check if a policy is not yet effective.
pub fn is_policy_pending(env: &Env, period: &PolicyEffectivePeriod) -> bool {
    let now = env.ledger().timestamp();
    period.effective_from > now
}

/// Check if a policy has expired.
pub fn is_policy_expired(env: &Env, period: &PolicyEffectivePeriod) -> bool {
    let now = env.ledger().timestamp();
    period.effective_until > 0 && period.effective_until <= now
}

/// Validate that two policy periods don't overlap.
pub fn validate_no_overlap(
    existing: &PolicyEffectivePeriod,
    new: &PolicyEffectivePeriod,
) -> Result<(), PolicyDateError> {
    // If existing policy never expires, any new policy overlaps
    if existing.effective_until == 0 {
        return Err(PolicyDateError::OverlappingPeriods);
    }

    // Check for overlap: new starts before existing ends AND new ends after existing starts
    let new_end = if new.effective_until == 0 { u64::MAX } else { new.effective_until };
    if new.effective_from < existing.effective_until && new_end > existing.effective_from {
        return Err(PolicyDateError::OverlappingPeriods);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Ledger;
    use soroban_sdk::Env;

    #[test]
    fn test_valid_effective_date() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let result = validate_effective_date(&env, 2000, 3000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_effective_date_in_past() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let result = validate_effective_date(&env, 500, 2000);
        assert_eq!(result, Err(PolicyDateError::EffectiveDateInPast));
    }

    #[test]
    fn test_end_date_before_start_date() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let result = validate_effective_date(&env, 2000, 1500);
        assert_eq!(result, Err(PolicyDateError::EndDateBeforeStartDate));
    }

    #[test]
    fn test_policy_effective() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1500);

        let period = PolicyEffectivePeriod {
            effective_from: 1000,
            effective_until: 2000,
            is_active: true,
        };
        assert!(is_policy_effective(&env, &period));
    }

    #[test]
    fn test_policy_pending() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1500);

        let period = PolicyEffectivePeriod {
            effective_from: 2000,
            effective_until: 3000,
            is_active: false,
        };
        assert!(is_policy_pending(&env, &period));
    }

    #[test]
    fn test_no_overlap() {
        let existing = PolicyEffectivePeriod {
            effective_from: 1000,
            effective_until: 2000,
            is_active: true,
        };
        let new = PolicyEffectivePeriod {
            effective_from: 2000,
            effective_until: 3000,
            is_active: true,
        };
        assert!(validate_no_overlap(&existing, &new).is_ok());
    }

    #[test]
    fn test_overlap_detected() {
        let existing = PolicyEffectivePeriod {
            effective_from: 1000,
            effective_until: 2000,
            is_active: true,
        };
        let new = PolicyEffectivePeriod {
            effective_from: 1500,
            effective_until: 2500,
            is_active: true,
        };
        assert_eq!(
            validate_no_overlap(&existing, &new),
            Err(PolicyDateError::OverlappingPeriods)
        );
    }
}
