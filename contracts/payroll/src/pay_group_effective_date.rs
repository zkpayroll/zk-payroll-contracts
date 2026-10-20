//! Pay-group date preflight checks (#783). All intervals are [start, end).

use soroban_sdk::{contracterror, contracttype, BytesN, Env, Vec};

/// Match the existing payroll-policy scheduling horizon (365 days).
pub const MAX_PAY_GROUP_FUTURE_SECONDS: u64 = 365 * 24 * 60 * 60;
/// Bound the amount of history inspected by one validation call.
pub const MAX_PAY_GROUP_PERIODS: u32 = 50;

/// A pay group's opaque identifier and effective-date interval.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayGroupEffectivePeriod {
    pub group_ref: BytesN<32>,
    pub effective_from: u64,
    /// Zero means no end date; otherwise the end is exclusive.
    pub effective_until: u64,
}

/// Stable errors for pay-group date checks; codes are scoped to issue #783.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayGroupDateError {
    InvalidGroupReference = 7830,
    InvalidInterval = 7831,
    StartInPast = 7832,
    StartTooFarFuture = 7833,
    OverlappingPeriod = 7834,
    TooManyPeriods = 7835,
    NotYetEffective = 7836,
    Expired = 7837,
}

/// Read-only contract interface for pay-group date validation.
pub trait PayGroupValidation {
    /// Validate a proposed interval against caller-supplied authoritative history.
    fn validate_pay_group_dates(
        env: Env,
        proposed: PayGroupEffectivePeriod,
        existing: Vec<PayGroupEffectivePeriod>,
    ) -> Result<(), PayGroupDateError>;
    /// Check whether an interval is effective at the ledger timestamp.
    fn check_pay_group_effective(
        env: Env,
        period: PayGroupEffectivePeriod,
    ) -> Result<(), PayGroupDateError>;
}

fn validate_interval(period: &PayGroupEffectivePeriod) -> Result<(), PayGroupDateError> {
    if period.group_ref.to_array() == [0; 32] {
        return Err(PayGroupDateError::InvalidGroupReference);
    }
    if period.effective_until != 0 && period.effective_until <= period.effective_from {
        return Err(PayGroupDateError::InvalidInterval);
    }
    Ok(())
}

/// Validate a new interval against existing intervals for the same group.
/// Read-only: history must come from the integrator's authoritative group store.
pub fn validate_pay_group_dates(
    env: &Env,
    proposed: &PayGroupEffectivePeriod,
    existing: &Vec<PayGroupEffectivePeriod>,
) -> Result<(), PayGroupDateError> {
    validate_interval(proposed)?;
    if existing.len() > MAX_PAY_GROUP_PERIODS {
        return Err(PayGroupDateError::TooManyPeriods);
    }
    let now = env.ledger().timestamp();
    if proposed.effective_from < now {
        return Err(PayGroupDateError::StartInPast);
    }
    // Subtraction after the past-date check avoids overflowing now + horizon.
    if proposed.effective_from - now > MAX_PAY_GROUP_FUTURE_SECONDS {
        return Err(PayGroupDateError::StartTooFarFuture);
    }
    for period in existing.iter() {
        validate_interval(&period)?;
        if period.group_ref == proposed.group_ref
            && (period.effective_until == 0 || proposed.effective_from < period.effective_until)
            && (proposed.effective_until == 0 || period.effective_from < proposed.effective_until)
        {
            return Err(PayGroupDateError::OverlappingPeriod);
        }
    }
    Ok(())
}

/// Require the interval to cover the current ledger timestamp, including start.
pub fn check_pay_group_effective(
    env: &Env,
    period: &PayGroupEffectivePeriod,
) -> Result<(), PayGroupDateError> {
    validate_interval(period)?;
    let now = env.ledger().timestamp();
    if now < period.effective_from {
        return Err(PayGroupDateError::NotYetEffective);
    }
    if period.effective_until != 0 && now >= period.effective_until {
        return Err(PayGroupDateError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Ledger, vec};

    fn period(env: &Env, start: u64, end: u64) -> PayGroupEffectivePeriod {
        PayGroupEffectivePeriod {
            group_ref: BytesN::from_array(env, &[1; 32]),
            effective_from: start,
            effective_until: end,
        }
    }

    #[test]
    fn accepts_adjacent_intervals_and_distinct_groups() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let proposed = period(&env, 100, 200);
        let mut other = period(&env, 100, 0);
        other.group_ref = BytesN::from_array(&env, &[2; 32]);
        assert_eq!(
            validate_pay_group_dates(&env, &proposed, &vec![&env, period(&env, 1, 100), other]),
            Ok(())
        );
    }

    #[test]
    fn rejects_invalid_reference_interval_past_and_horizon() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let empty = Vec::new(&env);
        let mut invalid = period(&env, 100, 200);
        invalid.group_ref = BytesN::from_array(&env, &[0; 32]);
        assert_eq!(
            validate_pay_group_dates(&env, &invalid, &empty),
            Err(PayGroupDateError::InvalidGroupReference)
        );
        for end in [99, 100] {
            assert_eq!(
                validate_pay_group_dates(&env, &period(&env, 100, end), &empty),
                Err(PayGroupDateError::InvalidInterval)
            );
        }
        assert_eq!(
            validate_pay_group_dates(&env, &period(&env, 99, 200), &empty),
            Err(PayGroupDateError::StartInPast)
        );
        let boundary = 100 + MAX_PAY_GROUP_FUTURE_SECONDS;
        assert_eq!(
            validate_pay_group_dates(&env, &period(&env, boundary, 0), &empty),
            Ok(())
        );
        assert_eq!(
            validate_pay_group_dates(&env, &period(&env, boundary + 1, 0), &empty),
            Err(PayGroupDateError::StartTooFarFuture)
        );
    }

    #[test]
    fn rejects_overlap_in_both_directions_and_open_ended_intervals() {
        let env = Env::default();
        for (old, new) in [
            (period(&env, 100, 200), period(&env, 150, 250)),
            (period(&env, 200, 300), period(&env, 100, 250)),
            (period(&env, 100, 0), period(&env, 200, 0)),
        ] {
            assert_eq!(
                validate_pay_group_dates(&env, &new, &vec![&env, old]),
                Err(PayGroupDateError::OverlappingPeriod)
            );
        }
        assert_eq!(
            validate_pay_group_dates(
                &env,
                &period(&env, 100, 200),
                &vec![&env, period(&env, 200, 0)]
            ),
            Ok(())
        );
    }

    #[test]
    fn bounds_history_and_validates_existing_intervals() {
        let env = Env::default();
        assert_eq!(
            validate_pay_group_dates(
                &env,
                &period(&env, 100, 200),
                &vec![&env, period(&env, 20, 10)]
            ),
            Err(PayGroupDateError::InvalidInterval)
        );
        let mut history = Vec::new(&env);
        for _ in 0..=MAX_PAY_GROUP_PERIODS {
            history.push_back(period(&env, 1, 2));
        }
        assert_eq!(
            validate_pay_group_dates(&env, &period(&env, 100, 200), &history),
            Err(PayGroupDateError::TooManyPeriods)
        );
    }

    #[test]
    fn active_check_uses_inclusive_start_and_exclusive_end() {
        let env = Env::default();
        let record = period(&env, 100, 200);
        env.ledger().with_mut(|li| li.timestamp = 99);
        assert_eq!(
            check_pay_group_effective(&env, &record),
            Err(PayGroupDateError::NotYetEffective)
        );
        env.ledger().with_mut(|li| li.timestamp = 100);
        assert_eq!(check_pay_group_effective(&env, &record), Ok(()));
        env.ledger().with_mut(|li| li.timestamp = 200);
        assert_eq!(
            check_pay_group_effective(&env, &record),
            Err(PayGroupDateError::Expired)
        );
        assert_eq!(
            check_pay_group_effective(&env, &period(&env, 100, 0)),
            Ok(())
        );
    }

    #[test]
    fn timestamp_near_u64_max_does_not_overflow() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = u64::MAX - 1);
        assert_eq!(
            validate_pay_group_dates(&env, &period(&env, u64::MAX, 0), &Vec::new(&env)),
            Ok(())
        );
    }
}
