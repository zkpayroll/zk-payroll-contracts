use soroban_sdk::{Env, Address};
use crate::PayrollRunRecord;

/// Archival Eligibility Check
/// 
/// Determines if a payroll run meets the criteria for safe archival:
/// - Run is fully executed (not pending or draft)
/// - Run has final reconciliation status (not unreconciled)
/// - No active disputes are linked to this run
/// - Sufficient time has elapsed since execution (per retention policy)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchivalEligibility {
    /// Run is eligible for archival immediately
    Eligible,
    /// Run cannot be archived due to pending execution
    RunStillPending,
    /// Run cannot be archived due to unresolved reconciliation
    UnreconciledRun,
    /// Run cannot be archived due to active or recent disputes
    ActiveDisputes,
    /// Run cannot be archived due to insufficient retention period
    RetentionPeriodNotMet,
}

/// Default minimum retention period after execution: 90 days in seconds.
pub const MIN_RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Validates whether a payroll run meets archival prerequisites.
/// 
/// Returns an `ArchivalEligibility` describing whether the run can be safely archived.
/// Error messages are privacy-safe and never expose salary amounts or employee details.
pub fn is_run_archival_eligible(
    env: &Env,
    run: &PayrollRunRecord,
    current_timestamp: u64,
) -> ArchivalEligibility {
    use crate::ReconciliationStatus;

    // Check 1: Run must be executed (not pending or draft)
    if !run.is_executed {
        return ArchivalEligibility::RunStillPending;
    }

    // Check 2: Run must have final reconciliation status
    // Only Reconciled or Failed runs can be archived
    match run.reconciliation_status {
        ReconciliationStatus::Unreconciled => {
            return ArchivalEligibility::UnreconciledRun;
        }
        ReconciliationStatus::Reconciled | ReconciliationStatus::Failed => {
            // Proceed to next checks
        }
    }

    // Check 3: No active disputes (if dispute tracking is enabled)
    // This check is deferred to the payroll contract layer since
    // dispute state is maintained separately and requires contract access.
    
    // Check 4: Retention period check
    // An executed run must carry an execution timestamp; otherwise we cannot
    // prove the retention window has elapsed, so archival is unsafe.
    let executed_at = match run.executed_at {
        Some(ts) => ts,
        None => return ArchivalEligibility::RetentionPeriodNotMet,
    };

    let elapsed = current_timestamp.saturating_sub(executed_at);
    if elapsed < MIN_RETENTION_SECONDS {
        return ArchivalEligibility::RetentionPeriodNotMet;
    }

    ArchivalEligibility::Eligible
}

/// Validates archival eligibility and panics with a safe error message if ineligible.
/// 
/// Used as a guard in archival entry-points to fail fast with clear operational feedback.
pub fn require_archival_eligible(
    env: &Env,
    run: &PayrollRunRecord,
    current_timestamp: u64,
) {
    let eligibility = is_run_archival_eligible(env, run, current_timestamp);
    
    match eligibility {
        ArchivalEligibility::Eligible => {
            // No-op: eligible, proceed
        }
        ArchivalEligibility::RunStillPending => {
            panic!("Payroll run cannot be archived: execution still in progress");
        }
        ArchivalEligibility::UnreconciledRun => {
            panic!("Payroll run cannot be archived: reconciliation status is unresolved");
        }
        ArchivalEligibility::ActiveDisputes => {
            panic!("Payroll run cannot be archived: disputes are still active");
        }
        ArchivalEligibility::RetentionPeriodNotMet => {
            panic!("Payroll run cannot be archived: minimum retention period not met");
        }
    }
}

/// Returns `true` if the run can be safely archived, `false` otherwise.
///
/// Convenience wrapper around [`is_run_archival_eligible`] for callers that only
/// need a boolean decision. Never exposes salary amounts or employee details.
pub fn can_archive_run(
    env: &Env,
    run: &PayrollRunRecord,
    current_timestamp: u64,
) -> bool {
    is_run_archival_eligible(env, run, current_timestamp) == ArchivalEligibility::Eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archival_eligibility_executed_reconciled() {
        // Mock executed and reconciled run should be eligible after retention period
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 1u64,
            is_executed: true,
            executed_at: Some(1000u64),
            reconciliation_status: crate::ReconciliationStatus::Reconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };
        
        // Current time is well past retention window
        let current_timestamp = 1000u64 + (91 * 24 * 60 * 60); // 91 days later
        
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::Eligible
        );
    }

    #[test]
    fn test_archival_eligibility_pending_run() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 1u64,
            is_executed: false, // Still pending
            executed_at: None,
            reconciliation_status: crate::ReconciliationStatus::Unreconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };
        
        let current_timestamp = 10_000u64;
        
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::RunStillPending
        );
    }

    #[test]
    fn test_archival_eligibility_unreconciled() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 1u64,
            is_executed: true,
            executed_at: Some(1000u64),
            reconciliation_status: crate::ReconciliationStatus::Unreconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };
        
        let current_timestamp = 1000u64 + (91 * 24 * 60 * 60);
        
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::UnreconciledRun
        );
    }

    #[test]
    fn test_archival_eligibility_retention_not_met() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 1u64,
            is_executed: true,
            executed_at: Some(1000u64),
            reconciliation_status: crate::ReconciliationStatus::Reconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };
        
        // Current time is only 30 days after execution (less than 90 day minimum)
        let current_timestamp = 1000u64 + (30 * 24 * 60 * 60);
        
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::RetentionPeriodNotMet
        );
    }

    #[test]
    fn test_archival_eligibility_failed_run_eligible() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 2u64,
            is_executed: true,
            executed_at: Some(1000u64),
            reconciliation_status: crate::ReconciliationStatus::Failed,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };

        let current_timestamp = 1000u64 + MIN_RETENTION_SECONDS;

        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::Eligible
        );
        assert!(can_archive_run(&env, &run, current_timestamp));
    }

    #[test]
    fn test_archival_eligibility_missing_executed_at() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 3u64,
            is_executed: true,
            executed_at: None,
            reconciliation_status: crate::ReconciliationStatus::Reconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };

        let current_timestamp = 1000u64 + MIN_RETENTION_SECONDS;

        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::RetentionPeriodNotMet
        );
        assert!(!can_archive_run(&env, &run, current_timestamp));
    }

    #[test]
    fn test_archival_eligibility_exact_retention_boundary() {
        let env = Env::default();
        let run = PayrollRunRecord {
            run_id: 4u64,
            is_executed: true,
            executed_at: Some(1000u64),
            reconciliation_status: crate::ReconciliationStatus::Reconciled,
            total_amount: 1_000_000i128,
            draft_hash: Default::default(),
            metadata_hash: Default::default(),
        };

        // Exactly at the retention boundary should be eligible.
        let current_timestamp = 1000u64 + MIN_RETENTION_SECONDS;
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::Eligible
        );

        // One second before the boundary should not be eligible.
        let current_timestamp = 1000u64 + MIN_RETENTION_SECONDS - 1;
        assert_eq!(
            is_run_archival_eligible(&env, &run, current_timestamp),
            ArchivalEligibility::RetentionPeriodNotMet
        );
    }
}
