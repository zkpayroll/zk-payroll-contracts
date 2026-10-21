//! Expiry policy for payroll adjustment approvals (#654).
//!
//! A *payroll adjustment* is an amendment to employee pay amounts or deduction
//! lines after an initial draft has been prepared.  Each adjustment must be
//! approved by an authorised reviewer before it can be incorporated into the
//! payroll run.  An approval that goes untouched — neither consumed by a
//! finalization nor revoked — should not remain valid indefinitely: a stale
//! approval may have been granted against data the reviewer has since
//! reconsidered, and retaining it silently undermines the review guarantee.
//!
//! This module adds an *opt-in* expiry window measured from the timestamp at
//! which the approval was recorded.  While no policy is configured, existing
//! approval-based flows are unchanged.  Once a policy is stored, any approval
//! older than `max_age_seconds` is treated as withdrawn and must be re-issued.
//!
//! Privacy guarantees mirror those of [`crate::correction_request_expiry`]:
//! the policy stores only timing metadata and the configuring address.
//! No salary amount, employee identity, or proof material is read or emitted
//! by the expiry check.

use soroban_sdk::{contracttype, Address};

/// Expiry policy for adjustment approvals stored on a payroll contract (#654).
///
/// Written to persistent storage under `DataKey::AdjustmentApprovalExpiryPolicy`
/// when an admin enables the feature.  Absent means the feature is off.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentApprovalExpiryPolicy {
    /// Maximum age (in seconds) an approval may reach before it lapses.
    /// Always non-zero when stored — passing `0` to the setter clears the
    /// policy instead, re-establishing the no-expiry default.
    pub max_age_seconds: u64,
    /// Ledger timestamp at which this policy was last written.
    pub set_at: u64,
    /// Admin address that configured the policy; retained for audit trails.
    pub set_by: Address,
}

impl AdjustmentApprovalExpiryPolicy {
    /// Returns `true` when an approval recorded at `approved_at` has lapsed
    /// as of ledger timestamp `now`.
    ///
    /// The boundary is half-open: an approval expires only once the window has
    /// *strictly* elapsed (`now > approved_at + max_age_seconds`), so an
    /// approval sitting exactly on the boundary is still valid.  Saturating
    /// arithmetic prevents a pathological timestamp from wrapping the comparison.
    pub fn is_expired(&self, now: u64, approved_at: u64) -> bool {
        now > approved_at.saturating_add(self.max_age_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn policy(env: &Env, max_age_seconds: u64) -> AdjustmentApprovalExpiryPolicy {
        AdjustmentApprovalExpiryPolicy {
            max_age_seconds,
            set_at: 0,
            set_by: Address::generate(env),
        }
    }

    #[test]
    fn approval_within_window_is_not_expired() {
        let env = Env::default();
        let p = policy(&env, 3600);
        // approved 1 800 s ago, window is 3 600 s — still valid
        assert!(!p.is_expired(1_800, 0));
    }

    #[test]
    fn approval_exactly_at_boundary_is_not_expired() {
        let env = Env::default();
        let p = policy(&env, 3600);
        // now == approved_at + max_age_seconds — still valid (half-open)
        assert!(!p.is_expired(3_600, 0));
    }

    #[test]
    fn approval_one_second_past_boundary_is_expired() {
        let env = Env::default();
        let p = policy(&env, 3600);
        assert!(p.is_expired(3_601, 0));
    }

    #[test]
    fn approval_long_in_the_past_is_expired() {
        let env = Env::default();
        let p = policy(&env, 86_400); // 24 h
        // approved 3 days ago
        assert!(p.is_expired(1_000_259_200, 1_000_000_000));
    }

    #[test]
    fn saturating_arithmetic_prevents_overflow_on_pathological_timestamp() {
        let env = Env::default();
        let p = policy(&env, u64::MAX);
        // approved_at + u64::MAX saturates to u64::MAX; now <= u64::MAX so never expired
        assert!(!p.is_expired(u64::MAX, 1));
    }
}
