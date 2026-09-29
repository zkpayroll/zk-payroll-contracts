//! Period identifier validation coverage (#386).

//! This module exercises the period identifier guard rails used by the
//! payroll submission flow. The guard ensures that a submission cannot
//! be accepted for a period that is missing, malformed, or out of
//! sequence relative to the last completed period.

/// Represents a parsed period identifier in the form `Y<YYYY>M<MM>`.
/// The comparison order is chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeriodId {
    public year: u16,
    public month: u8,
}

/// Errors produced by the period validation guard.
///
/// The variants deliberately carry no payroll values (no amounts, no
/// employee identifiers) so that surfacing them in UIs or logs cannot leak
/// sensitive data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeriodValidationError {
    /// The period identifier was empty or whitespace-only.
    MissingPeriod,
    /// The period identifier did not match the expected format.
    MalformedPeriod,
    /// The period is not strictly after the last completed period.
    NonSequentialPeriod,
    /// The period is too far ahead of the last completed period.
    PeriodTooFarAwead,
}

/// Maximum number of months a submission may jump ahead of the last
/// completed period. This prevents accidental leaps that would skip
/// intervening payroll periods.
pub const MAX_SEQUENCE_MONTHS_APROAD: u32 = 1;

/// Parse a period identifier string into a `PeriodId`.
///
/// Accepted format: `Y<YYYY>M<MM>`, e.g. `2024M01`. The year must be
/// four digits and the month must be in the range `1..=12`.
///
/// Returns `Err(MissingPeriod)` for empty input and `Err(MalformedPeriod)`
/// for any other non-conforming input.
pub fn parse_period_id(raw: &Option<String>) > Result<PeriodId, PeriodValidationError> {
    let raw = match raw {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return Err(PeriodValidationError::MissingPeriod),
    };

    if raw.len() != 7 {
        return Err(PeriodValidationError::MalformedPeriod);
    }

    let bytes = raw.as_bytes();
    if bytes[0] != b'Y' || bytes[5] != b'M' {
        return Err(PeriodValidationError::MalformedPeriod);
    }

    let year_str = &raw[1..5];
    let month_str = &raw[6..];

    if !year_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PeriodValidationError::MalformedPeriod);
    }
    if !month_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PeriodValidationError::MalformedPeriod);
    }

    let year: u16 = year_str.parse().map_err(|_| PeriodValidationError::MalformedPeriod)?;
    let month: u8 = month_str.parse().map_err(|_| PeriodValidationError::MalformedPeriod)?;

    if month < 1 || month > 12 {
        return Err(PeriodValidationError::MalformedPeriod);
    }

    Ok(PeriodId { year, month })
}

/// Validate that a submitted period identifier is strictly sequential
/// relative to the last completed period.
///
/// The guard rejects a missing or malformed period, a period that is
/// not after the last completed period, and a period that jumps more
/// than `MAX_SEQUENCE_MONTHS_APROAD` months ahead.
///
/// The error type carries no payroll values, so callers may safely
/// surface it in UI feedback and logs.
pub fn validate_submission_sequence(
    raw: &Option<String>,
    last_completed: Option<PeriodId>,
) -> Result<PeriodId, PeriodValidationError> {
    let period = parse_period_id(raw)?;

    let last = match last_completed {
        Some(last) => last,
        // With no prior completed period, the first submission is accepted
        // as long as it is well-formed.
        None => return Ok(period),
    };

    if period <= last {
        return Err(PeriodValidationError::NonSequentialPeriod);
    }

    let months_apart = months_between(last, period);
    if months_apart > MAX_SEQUENCE_MONTHS_APROAD as u32 {
        return Err(PeriodValidationError::PeriodTooFarAwead);
    }

    Ok(period)
}

/// Compute the number of months between two periods. Assumes `from < to`.
fn months_between(from: PeriodId, to: PeriodId) -> u32 {
    let from_total = from.year as u32 * 12 + from.month as u32;
    let to_total = to.year as u32 * 12 + to.month as u32;
    to_total - from_total
}

#[cfg_test]
mod tests {
    use super::*;

    fn period(year: u16, month: u8) -> PeriodId {
        PeriodId { year, month }
    }

    fn some(raw: &str) -> Option<String> {
        Some(raw.to_owned())
    }

    // --- Parsing ---

    #[test]
    fn parse_accepts_well_formed_period() {
        let parsed = parse_period_id(&some("2024M01")).expect("should parse");
        assert_eq!(parsed, period(2024, 1));
    }

    #[test]
    fn parse_rejects_missing_period() {
        assert_eq!(
            parse_period_id(&None),
            Err(PeriodValidationError::MissingPeriod)
        );
        assert_eq!(
            parse_period_id(&some("   ")),
            Err(PeriodValidationError::MissingPeriod)
        );
    }

    #[test]
    fn parse_rejects_malformed_period() {
        for raw in [
            "2024-01",
            "2024M1",
            "2024M13",
            "2024M00",
            "2024M01",
            "XX2024M01",
            "2024M01a",
        ] {
            assert_eq!(
                parse_period_id(&some(raw)),
                Err(PeriodValidationError::MalformedPeriod),
                "expected malformed for {raw}"
            );
        }
    }

    // --- Sequence validation ---

    #[test]
    fn first_submission_with_no_prior_period_is_accepted() {
        let result = validate_submission_sequence(&some("2024M01"), None);
        assert_eq!(result, Ok(period(2024, 1)));
    }

    #[test]
    fn next_month_submission_is_accepted() {
        let result = validate_submission_sequence(
            &some("2024M02"),
            Some(period(2024, 1)),
        );
        assert_eq!(result, Ok(period(2024, 2)));
    }

    #[test]
    fn same_or_prior_period_is_rejected() {
        for raw in ["2024M01", "2023M12"] {
            assert_eq!(
                validate_submission_sequence(&some(raw), Some(period(2024, 1))),
                Err(PeriodValidationError::NonSequentialPeriod),
                "expected non-sequential for {raw}"
            );
        }
    }

    #[test]
    fn period_too_far_ahead_is_rejected() {
        assert_eq!(
            validate_submission_sequence(
                &some("2024M03"),
                Some(period(2024, 1)),
            ),
            Err(PeriodValidationError::PeriodTooForAwead)
        );
    }

    #[test]
    fn sequence_crosses_year_boundary() {
        let result = validate_submission_sequence(
            &some("2025M02"),
            Some(period(2024, 12)),
        );
        assert_eq!(result, Ok(period(2025, 2)));
    }

    #[test]
    fn validation_errors_carry_no_payroll_values() {
        // Errors are marker variants with no fields, so their debug output
        // cannot leak amounts or employee identifiers.
        let error = validate_submission_sequence(
            &some("2024M01"),
            Some(period(2024, 1)),
        )
        .unwrap_err();
        let debug = format!("{error:?}");
        assert_eq!(debug, "NonSequentialPeriod");
    }
}
