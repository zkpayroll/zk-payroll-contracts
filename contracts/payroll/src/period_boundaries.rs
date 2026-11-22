//! Privacy-safe settlement window boundary primitives (#939, #940, #941).
//!
//! The window phase is derived from the current ledger timestamp on every
//! call. No employee, salary, commitment, or caller-supplied payload is used
//! to produce an error, and no phase is persisted.

use soroban_sdk::contracterror;

/// Stable, payload-free errors for payroll period boundary failures.
///
/// Codes are append-only. Every variant is unit-only: clients receive a code
/// that maps to a fixed message, never a timestamp, amount, employee address,
/// or commitment from the rejected invocation.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PayrollPeriodBoundaryError {
    /// `open_at <= execution_start <= execution_end <= close_at` was violated.
    InvalidWindowOrder = 8501,
    /// Two configured periods share an inclusive calendar endpoint or range.
    WindowOverlap = 8502,
    /// Execution was attempted before `execution_start`.
    ExecutionNotYetOpen = 8503,
    /// Execution was attempted after `execution_end`, including grace and closed.
    ExecutionClosed = 8504,
    /// Pending-run expiry was attempted before `close_at`.
    CloseBoundaryNotReached = 8505,
    /// The period's settlement window can no longer be reconfigured.
    PeriodConfigFrozen = 8506,
}

/// Phase of a settlement window at a ledger timestamp.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PeriodBoundaryPhase {
    PreOpen,
    Executable,
    Grace,
    Closed,
}

/// Validate the ordering of a proposed settlement window.
pub fn validate_window_order(
    open_at: u64,
    execution_start: u64,
    execution_end: u64,
    close_at: u64,
) -> Result<(), PayrollPeriodBoundaryError> {
    if open_at <= execution_start && execution_start <= execution_end && execution_end <= close_at {
        Ok(())
    } else {
        Err(PayrollPeriodBoundaryError::InvalidWindowOrder)
    }
}

/// Whether two inclusive calendar ranges intersect.
pub fn ranges_overlap(
    first_open: u64,
    first_close: u64,
    second_open: u64,
    second_close: u64,
) -> bool {
    first_open <= second_close && second_open <= first_close
}

/// Classify a window at `now`. Execution is closed at both the upper end of
/// the execution interval and the upper end of the grace interval.
pub fn classify_window(
    execution_start: u64,
    execution_end: u64,
    close_at: u64,
    now: u64,
) -> PeriodBoundaryPhase {
    if now < execution_start {
        PeriodBoundaryPhase::PreOpen
    } else if now <= execution_end {
        PeriodBoundaryPhase::Executable
    } else if now <= close_at {
        PeriodBoundaryPhase::Grace
    } else {
        PeriodBoundaryPhase::Closed
    }
}

/// Return the error that blocks execution in `phase`, if any.
pub fn execution_error(phase: PeriodBoundaryPhase) -> Option<PayrollPeriodBoundaryError> {
    match phase {
        PeriodBoundaryPhase::PreOpen => Some(PayrollPeriodBoundaryError::ExecutionNotYetOpen),
        PeriodBoundaryPhase::Executable => None,
        PeriodBoundaryPhase::Grace | PeriodBoundaryPhase::Closed => {
            Some(PayrollPeriodBoundaryError::ExecutionClosed)
        }
    }
}

/// Whether the close boundary has been reached. The boundary is inclusive:
/// a pending run may be expired at `close_at` and at any later timestamp.
pub fn close_boundary_reached(close_at: u64, now: u64) -> bool {
    now >= close_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_inclusive_window_ordering() {
        assert_eq!(validate_window_order(100, 200, 200, 300), Ok(()));
        assert_eq!(validate_window_order(100, 100, 100, 100), Ok(()));
        assert_eq!(
            validate_window_order(201, 200, 250, 300),
            Err(PayrollPeriodBoundaryError::InvalidWindowOrder)
        );
        assert_eq!(
            validate_window_order(100, 200, 199, 300),
            Err(PayrollPeriodBoundaryError::InvalidWindowOrder)
        );
        assert_eq!(
            validate_window_order(100, 200, 300, 299),
            Err(PayrollPeriodBoundaryError::InvalidWindowOrder)
        );
    }

    #[test]
    fn treats_shared_calendar_endpoints_as_overlaps() {
        assert!(ranges_overlap(100, 400, 400, 500));
        assert!(ranges_overlap(100, 500, 150, 200));
        assert!(!ranges_overlap(100, 400, 401, 500));
    }

    #[test]
    fn classifies_both_sides_of_each_boundary() {
        let cases = [
            (199, PeriodBoundaryPhase::PreOpen),
            (200, PeriodBoundaryPhase::Executable),
            (300, PeriodBoundaryPhase::Executable),
            (301, PeriodBoundaryPhase::Grace),
            (400, PeriodBoundaryPhase::Grace),
            (401, PeriodBoundaryPhase::Closed),
        ];

        for (now, expected) in cases {
            assert_eq!(classify_window(200, 300, 400, now), expected);
        }
    }

    #[test]
    fn execution_errors_are_payload_free() {
        assert_eq!(
            execution_error(PeriodBoundaryPhase::PreOpen),
            Some(PayrollPeriodBoundaryError::ExecutionNotYetOpen)
        );
        assert_eq!(execution_error(PeriodBoundaryPhase::Executable), None);
        assert_eq!(
            execution_error(PeriodBoundaryPhase::Grace),
            Some(PayrollPeriodBoundaryError::ExecutionClosed)
        );
        assert_eq!(
            execution_error(PeriodBoundaryPhase::Closed),
            Some(PayrollPeriodBoundaryError::ExecutionClosed)
        );
    }

    #[test]
    fn close_boundary_is_inclusive() {
        assert!(!close_boundary_reached(400, 399));
        assert!(close_boundary_reached(400, 400));
        assert!(close_boundary_reached(400, 401));
    }
}
