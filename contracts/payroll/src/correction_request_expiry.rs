//! Expiry handling for payroll correction requests (#622).
//!
//! A *correction request* is a pending payroll run draft that its creator can
//! still amend (correct) through [`crate::Payroll::amend_run_draft`]. An
//! employer may want open correction requests to lapse: an untouched draft
//! should not stay correctable forever, because a stale draft holds the
//! period's single pending-draft slot (#398) and can silently drift away from
//! the payroll data it was prepared against.
//!
//! Enforcement is opt-in. Until an admin configures a policy
//! ([`crate::Payroll::get_correction_request_expiry`] returns `None`),
//! `amend_run_draft` behaves exactly as it did before this module existed: no
//! policy is read, no clock is consulted, and every amendment is accepted.
//!
//! The configured [`CorrectionRequestExpiryPolicy::max_age_seconds`] is an
//! *inactivity* window measured from the draft's `updated_at` timestamp, which
//! every accepted amendment refreshes. A request that is being actively
//! corrected therefore never lapses; only one left untouched for longer than
//! the window does. A lapsed request can no longer be corrected and may be
//! retired by anyone via [`crate::Payroll::expire_correction_request`], which
//! frees the period for a fresh draft.
//!
//! Everything here is privacy-safe: the policy carries only an age bound, who
//! configured it, and when. The expiry check reads timestamps and the draft
//! state only, so no salary amount, employee identity, or proof material is
//! stored or surfaced, and a rejection names the recovery path rather than any
//! payroll value.

use soroban_sdk::{contracttype, Address};

/// Correction-request expiry policy for a payroll contract (#622).
///
/// Stored under `DataKey::CorrectionRequestExpiryPolicy` when the admin enables
/// expiry. While present, a `Pending` payroll run draft whose `updated_at` is
/// older than `max_age_seconds` can no longer be amended and may be expired by
/// anyone. Absent storage means expiry is disabled.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionRequestExpiryPolicy {
    /// Maximum idle age (in seconds) a pending correction request may reach
    /// before it lapses. Always non-zero; `0` clears the policy instead.
    pub max_age_seconds: u64,
    /// Ledger timestamp when the policy was written.
    pub set_at: u64,
    /// Address that configured the policy (the contract admin).
    pub set_by: Address,
}

impl CorrectionRequestExpiryPolicy {
    /// Whether an open correction request last touched at `updated_at` has
    /// lapsed as of `now`.
    ///
    /// The window is half-open: a request expires only once the window has
    /// strictly elapsed (`now > updated_at + max_age_seconds`), so a request
    /// sitting exactly on the boundary is still correctable. Uses saturating
    /// arithmetic so a pathological timestamp can never wrap the comparison.
    pub fn is_expired(&self, now: u64, updated_at: u64) -> bool {
        now > updated_at.saturating_add(self.max_age_seconds)
    }
}
