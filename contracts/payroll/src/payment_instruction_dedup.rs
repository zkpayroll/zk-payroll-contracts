//! Duplicate detection for payment instructions (#653).
//!
//! A *payment instruction* is an authoritative record that directs the
//! contract to transfer a specific amount to a specific employee within a
//! payroll period.  Without duplicate detection, submitting the same
//! instruction twice — whether through a client retry, a race between two
//! operator sessions, or a crafted replay — would pay an employee twice for
//! the same period without any on-chain signal.
//!
//! This module provides a lightweight dedup layer that tracks every
//! (`period_id`, `instruction_id`) pair seen within a period.  The first
//! submission for a pair succeeds and is recorded; a subsequent submission
//! of the same pair is rejected with `PaymentError::EmployeeAlreadyPaid`
//! before any transfer is attempted.
//!
//! Only the pair key is stored — no salary amount, employee identity, or
//! proof material is retained by this module.  Dedup records are written
//! to persistent storage so they survive ledger eviction windows and cannot
//! be cleared by a contract upgrade.

use soroban_sdk::{contracttype, Env};

use shared_errors::PaymentError;

/// Storage key for a single dedup entry.
///
/// Stored as a boolean flag under this key; the mere presence of the entry
/// is sufficient — the value carries no additional information.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentInstructionDedupKey {
    /// The payroll period this instruction belongs to.
    pub period_id: u64,
    /// The unique identifier of the payment instruction within the period.
    pub instruction_id: u64,
}

/// Record a payment instruction as seen, or reject it if it was already seen.
///
/// Reads persistent storage to check whether (`period_id`, `instruction_id`)
/// has been recorded.  On a new pair, writes the entry and returns `Ok(())`.
/// On a duplicate, returns `Err(PaymentError::EmployeeAlreadyPaid)` without
/// modifying storage.
///
/// # Privacy
/// Only the composite key is written; no amount, address, or proof is stored
/// or surfaced.
pub fn record_or_reject_duplicate(
    env: &Env,
    period_id: u64,
    instruction_id: u64,
) -> Result<(), PaymentError> {
    let key = PaymentInstructionDedupKey { period_id, instruction_id };

    if env
        .storage()
        .persistent()
        .get::<_, bool>(&key)
        .unwrap_or(false)
    {
        return Err(PaymentError::EmployeeAlreadyPaid);
    }

    env.storage().persistent().set(&key, &true);
    Ok(())
}

/// Returns `true` if (`period_id`, `instruction_id`) has already been
/// recorded, without modifying storage.
///
/// Intended for read-only preflight checks by dashboards and SDKs.
pub fn is_duplicate(env: &Env, period_id: u64, instruction_id: u64) -> bool {
    let key = PaymentInstructionDedupKey { period_id, instruction_id };
    env.storage()
        .persistent()
        .get::<_, bool>(&key)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn first_submission_succeeds_and_is_recorded() {
        let env = Env::default();
        assert!(record_or_reject_duplicate(&env, 1, 100).is_ok());
        assert!(is_duplicate(&env, 1, 100));
    }

    #[test]
    fn second_submission_of_same_pair_is_rejected() {
        let env = Env::default();
        record_or_reject_duplicate(&env, 1, 100).unwrap();
        let result = record_or_reject_duplicate(&env, 1, 100);
        assert_eq!(result, Err(PaymentError::EmployeeAlreadyPaid));
    }

    #[test]
    fn same_instruction_id_in_different_period_is_accepted() {
        let env = Env::default();
        record_or_reject_duplicate(&env, 1, 100).unwrap();
        // Period 2, same instruction_id 100 — different pair, must succeed.
        assert!(record_or_reject_duplicate(&env, 2, 100).is_ok());
    }

    #[test]
    fn different_instruction_id_in_same_period_is_accepted() {
        let env = Env::default();
        record_or_reject_duplicate(&env, 1, 100).unwrap();
        assert!(record_or_reject_duplicate(&env, 1, 101).is_ok());
    }

    #[test]
    fn is_duplicate_returns_false_before_first_submission() {
        let env = Env::default();
        assert!(!is_duplicate(&env, 99, 999));
    }

    #[test]
    fn is_duplicate_does_not_modify_storage() {
        let env = Env::default();
        // Calling is_duplicate twice should not flip the flag.
        assert!(!is_duplicate(&env, 5, 50));
        assert!(!is_duplicate(&env, 5, 50));
        // First real submission should still succeed.
        assert!(record_or_reject_duplicate(&env, 5, 50).is_ok());
    }
}
