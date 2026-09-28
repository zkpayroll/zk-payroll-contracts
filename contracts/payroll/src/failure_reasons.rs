//! Stable payroll failure reason codes (issue #509) and dry-run preflight
//! validation for payroll execution (issue #521).
//!
//! `batch_process_payroll`'s preconditions are enforced as bare `panic!`
//! calls with free-text messages (see `contracts/payroll/src/lib.rs`), which
//! abort the whole transaction with no structured, stable-for-off-chain-use
//! identifier and stop at the first failure. This module adds a stable,
//! numbered reason-code registry — mirroring the existing
//! `audit_module::challenge::ChallengeReasonCode` pattern already used
//! elsewhere in this contract suite — and a read-only dry-run entrypoint
//! that runs the same precondition checks `batch_process_payroll` does
//! (everything except the token transfer, proof verification, and any
//! storage write) and reports every blocker it finds in one call, instead of
//! panicking on the first one.
//!
//! This is deliberately additive: `batch_process_payroll` itself is
//! unchanged, so its existing behavior and every existing test against it
//! keep working exactly as before. The reason codes here are surfaced ONLY
//! through the new dry-run report.

use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};

use crate::CapacityLimitKind;

/// Stable, numbered reason a payroll batch would be rejected by
/// `batch_process_payroll`. Values are append-only: once shipped, a
/// variant's discriminant never changes and is never reused for a different
/// meaning, so off-chain consumers can safely persist and pattern-match on
/// it across contract upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayrollFailureReason {
    /// The company's lifecycle state is not `Active` (paused, archived, or
    /// setup incomplete).
    CompanyNotActive = 0,
    /// No proofs were supplied (`proofs.len() == 0`).
    MissingProof = 1,
    /// `amounts`/`employees`/`proofs` lengths do not all match.
    ArrayLengthMismatch = 2,
    /// The batch exceeds `MAX_BATCH`.
    BatchTooLarge = 3,
    /// `nonce` has already been consumed by a previous run.
    DuplicateRunNonce = 4,
    /// A `draft_hash` was supplied but has no matching `commit_draft`
    /// pre-commitment.
    DraftNotPreCommitted = 5,
    /// Two or more entries in `employees` are the same address.
    DuplicateEmployee = 6,
    /// One or more `amounts` entries is not strictly positive.
    NonPositiveAmount = 7,
    /// The sum of `amounts` does not equal the caller-declared
    /// `expected_total_spend`.
    ExpectedSpendMismatch = 8,
    /// `nonce` is not strictly greater than the employer's last accepted
    /// nonce (replay or out-of-order submission).
    NonceNotMonotonic = 9,
    /// The treasury's configured payout asset is not on the allowlist.
    AssetNotAllowed = 10,
    /// The pause manager (if configured) reports the system as paused.
    SystemPaused = 11,
    /// Executing this batch would exceed the employer's configured
    /// per-period `CapacityLimits` (batch count, employee count, or total
    /// value — see the report's `capacity_details` for which).
    CapacityLimitExceeded = 12,
    /// The current period's settlement window (if configured) is not open
    /// for execution right now.
    SettlementWindowNotOpen = 13,
    /// The treasury's token balance is less than `expected_total_spend`.
    InsufficientTreasuryBalance = 14,
}

/// Result of a dry-run preflight check for `batch_process_payroll`.
///
/// Privacy-safe by construction: it carries only which stable reason codes
/// blocked the batch (plus, for capacity, which dimension), never salary
/// amounts, employee addresses, or proof material — safe to hand to an
/// off-chain dashboard or agent the same way
/// `payment_executor::check_upgrade_compatibility`'s report is documented to
/// be.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollDryRunReport {
    /// `true` if and only if `blockers` is empty — the batch would be
    /// accepted by `batch_process_payroll` as far as this preflight can
    /// determine. Proof verification itself is NOT checked here (see the
    /// struct-level caveat below), so `would_succeed` is a necessary, not
    /// sufficient, condition for the real call to succeed.
    pub would_succeed: bool,
    /// Every blocking reason found, in the same order
    /// `batch_process_payroll` would encounter them. Empty when
    /// `would_succeed` is `true`.
    pub blockers: Vec<PayrollFailureReason>,
    /// Set when `blockers` contains `CapacityLimitExceeded`, identifying
    /// which dimension(s) were exceeded. Empty otherwise.
    pub capacity_details: Vec<CapacityLimitKind>,
}

impl PayrollDryRunReport {
    pub(crate) fn empty(e: &Env) -> Self {
        Self {
            would_succeed: true,
            blockers: Vec::new(e),
            capacity_details: Vec::new(e),
        }
    }

    pub(crate) fn push(&mut self, reason: PayrollFailureReason) {
        self.blockers.push_back(reason);
        self.would_succeed = false;
    }

    pub(crate) fn push_capacity(&mut self, detail: CapacityLimitKind) {
        self.push(PayrollFailureReason::CapacityLimitExceeded);
        self.capacity_details.push_back(detail);
    }
}

/// Arguments for a dry-run check, mirroring `batch_process_payroll`'s
/// signature minus the proofs (proof verification is out of scope for this
/// preflight — see the module doc comment).
#[contracttype]
#[derive(Clone, Debug)]
pub struct DryRunArgs {
    pub amounts: Vec<i128>,
    pub employees: Vec<Address>,
    pub expected_total_spend: i128,
    pub nonce: BytesN<32>,
    pub draft_hash: Option<BytesN<32>>,
    pub proof_count: u32,
}
