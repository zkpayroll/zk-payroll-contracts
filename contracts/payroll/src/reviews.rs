/// Overpayment review subsystem — issue #357.
///
/// # Design rationale
///
/// Overpayment handling requires accountability *without* giving any single
/// actor a hidden reversal switch.  This module achieves that by:
///
/// 1. **Flagging, not reversing.**  Opening a review attaches a sentinel to
///    the completed `PayrollRun`; it never touches token balances.  Settled
///    payments remain settled throughout the review lifecycle.
///
/// 2. **Blocking cleanup, not execution.**  A run under review cannot have its
///    reconciliation status changed to `Reconciled` (archival-equivalent) until
///    the review is explicitly closed.  Active payment execution is unaffected.
///
/// 3. **Authorized resolution with mandatory reason.**  Closing a review
///    requires the contract admin and a non-empty reason symbol.  The reason is
///    stored on-chain so the audit trail is self-contained.
///
/// 4. **Privacy-safe events.**  All emitted events follow the privacy rules in
///    `events.rs`; they never surface amounts, employee addresses, or proof data.
///
/// # Entrypoints exposed via `Payroll` contract impl (see `lib.rs`)
///
/// | Function                     | Auth      | Description                              |
/// |------------------------------|-----------|------------------------------------------|
/// | `open_overpayment_review`    | admin     | Flag a run; blocks reconciliation.       |
/// | `resolve_overpayment_review` | admin     | Close with mandatory reason; unblocks.   |
/// | `get_overpayment_review`     | none      | Read current review for a run.           |
/// | `has_open_review`            | none      | Guard helper — true if review is open.   |
use soroban_sdk::{contracttype, symbol_short, Address, Env, Symbol};

// ── Data types ────────────────────────────────────────────────────────────────

/// Lifecycle state of an overpayment review.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ReviewStatus {
    /// Review is active.  Reconciliation operations on the associated run are
    /// blocked until this transitions to `Resolved`.
    Open = 0,
    /// Review has been closed by an authorized admin with an explicit reason.
    /// No further state transitions are possible on this record.
    Resolved = 1,
}

/// An overpayment review record linked to a specific payroll run.
///
/// Privacy note: `flagged_amount` is intentionally absent.  The reviewing
/// party records disputed amounts off-chain using the `run_id` as the
/// correlation key.
#[contracttype]
#[derive(Clone, Debug)]
pub struct OverpaymentReview {
    /// Auto-incremented review identifier.
    pub review_id: u64,
    /// The completed payroll run this review is attached to.
    pub run_id: u64,
    /// Ledger timestamp when the review was opened.
    pub flagged_at: u64,
    /// Admin address that opened the review.
    pub flagged_by: Address,
    /// Current lifecycle state.
    pub status: ReviewStatus,
    /// Ledger timestamp when the review was resolved (0 = unresolved).
    pub resolved_at: u64,
    /// Admin address that resolved the review (`None` while open).
    pub resolved_by: Option<Address>,
    /// Mandatory human-readable reason supplied at resolution time
    /// (empty symbol while open).
    pub resolution_reason: Symbol,
}

// ── Storage key extension ─────────────────────────────────────────────────────
//
// These keys are appended to the existing `DataKey` enum in `lib.rs`.
// They are reproduced here as a local enum so `reviews.rs` can be compiled
// and tested independently; `lib.rs` re-exports the variants into the
// canonical `DataKey` namespace (see the `DataKey` extension below).

/// Internal storage keys used exclusively by the reviews subsystem.
///
/// Do **not** add these to the main `DataKey` enum variants that are already
/// in use; they live here to keep review storage isolated and append-only.
#[contracttype]
pub enum ReviewDataKey {
    /// Auto-increment counter for review IDs.
    ReviewCounter,
    /// Overpayment review record keyed by `run_id`.
    ///
    /// At most one review may exist per run at any time.  Opening a second
    /// review on the same run is rejected unless the first is `Resolved`.
    OverpaymentReview(u64),
}

// ── Review logic ──────────────────────────────────────────────────────────────

/// Open a new overpayment review for the given payroll run.
///
/// # Panics
///
/// * `"Not initialized"` — contract storage has no `Addresses` entry.
/// * `"Unauthorized"` — `admin` is not the stored contract admin.
/// * `"Run not found"` — no `PayrollRun` exists for `run_id`.
/// * `"Review already open"` — a `ReviewStatus::Open` review already exists
///   for this run.  Close it first.
///
/// # Events
///
/// Emits `("payroll", "review_opened")` with `(review_id, run_id, flagged_at)`.
/// No salary amounts or employee addresses are included.
pub fn open_overpayment_review(env: &Env, admin: &Address, run_id: u64) -> u64 {
    let addrs: crate::ContractAddresses = env
        .storage()
        .persistent()
        .get(&crate::DataKey::Addresses)
        .expect("Not initialized");
    if *admin != addrs.admin {
        panic!("Unauthorized");
    }
    admin.require_auth();

    if !env
        .storage()
        .persistent()
        .has(&crate::DataKey::PayrollRun(run_id))
    {
        panic!("Run not found");
    }

    // Guard: an open review must not already exist for this run.
    if let Some(existing) = env
        .storage()
        .persistent()
        .get::<ReviewDataKey, OverpaymentReview>(&ReviewDataKey::OverpaymentReview(run_id))
    {
        if existing.status == ReviewStatus::Open {
            panic!("Review already open for this run");
        }
    }

    // Derive a new monotonic review ID.
    let counter: u64 = env
        .storage()
        .persistent()
        .get(&ReviewDataKey::ReviewCounter)
        .unwrap_or(0u64);
    let review_id = counter + 1;
    env.storage()
        .persistent()
        .set(&ReviewDataKey::ReviewCounter, &review_id);

    let flagged_at = env.ledger().timestamp();

    let review = OverpaymentReview {
        review_id,
        run_id,
        flagged_at,
        flagged_by: admin.clone(),
        status: ReviewStatus::Open,
        resolved_at: 0,
        resolved_by: None,
        resolution_reason: Symbol::new(env, ""),
    };

    env.storage()
        .persistent()
        .set(&ReviewDataKey::OverpaymentReview(run_id), &review);

    env.events().publish(
        (symbol_short!("payroll"), Symbol::new(env, "review_opened")),
        (review_id, run_id, flagged_at),
    );
    // topics : ("payroll", "review_opened")
    // data   : (review_id, run_id, flagged_at)

    review_id
}

/// Resolve an open overpayment review with a mandatory reason.
///
/// Resolving the review removes the archival block and transitions the record
/// to `ReviewStatus::Resolved`.  **Settled payments are never touched.**
///
/// # Panics
///
/// * `"Unauthorized"` — `admin` is not the stored contract admin.
/// * `"Review not found"` — no review record exists for `run_id`.
/// * `"Review already resolved"` — the review is already in `Resolved` state.
/// * `"Resolution reason must not be empty"` — `reason` is an empty symbol
///   (`Symbol::new(&env, "")`).
///
/// # Events
///
/// Emits `("payroll", "review_resolved")` with `(review_id, run_id, resolved_at)`.
pub fn resolve_overpayment_review(env: &Env, admin: &Address, run_id: u64, reason: Symbol) {
    let addrs: crate::ContractAddresses = env
        .storage()
        .persistent()
        .get(&crate::DataKey::Addresses)
        .expect("Not initialized");
    if *admin != addrs.admin {
        panic!("Unauthorized");
    }
    admin.require_auth();
    // Enforce non-empty reason.
    {
        // Soroban symbols do not implement `is_empty()` on `no_std`.
        // We round-trip through `to_string()` which is unavailable in `no_std`,
        // so we compare against a known empty symbol instead.
        let empty = Symbol::new(env, "");
        if reason == empty {
            panic!("Resolution reason must not be empty");
        }
    }

    let key = ReviewDataKey::OverpaymentReview(run_id);
    let mut review: OverpaymentReview = env
        .storage()
        .persistent()
        .get(&key)
        .expect("Review not found");

    if review.status == ReviewStatus::Resolved {
        panic!("Review already resolved");
    }

    let resolved_at = env.ledger().timestamp();

    review.status = ReviewStatus::Resolved;
    review.resolved_at = resolved_at;
    review.resolved_by = Some(admin.clone());
    review.resolution_reason = reason;

    env.storage().persistent().set(&key, &review);

    env.events().publish(
        (
            symbol_short!("payroll"),
            Symbol::new(env, "review_resolved"),
        ),
        (review.review_id, run_id, resolved_at),
    );
    // topics : ("payroll", "review_resolved")
    // data   : (review_id, run_id, resolved_at)
}

/// Return the overpayment review record for a run, if one exists.
pub fn get_overpayment_review(env: &Env, run_id: u64) -> Option<OverpaymentReview> {
    env.storage()
        .persistent()
        .get(&ReviewDataKey::OverpaymentReview(run_id))
}

/// Return `true` if there is a currently `Open` review for the given run.
///
/// Called by the archival block guard in `lib.rs` before allowing a
/// reconciliation status update to `Reconciled`.
pub fn has_open_review(env: &Env, run_id: u64) -> bool {
    match env
        .storage()
        .persistent()
        .get::<ReviewDataKey, OverpaymentReview>(&ReviewDataKey::OverpaymentReview(run_id))
    {
        Some(r) => r.status == ReviewStatus::Open,
        None => false,
    }
}

/// Emit the `archival_blocked` guard event.
///
/// Called from `lib.rs` when a reconciliation update is rejected because an
/// open review exists.  Separated here so callers can trigger the emit before
/// they panic, giving off-chain indexers a richer audit trail.
pub fn emit_archival_blocked(env: &Env, run_id: u64, review_id: u64) {
    env.events().publish(
        (
            symbol_short!("payroll"),
            Symbol::new(env, "archival_blocked"),
        ),
        (run_id, review_id),
    );
    // topics : ("payroll", "archival_blocked")
    // data   : (run_id, review_id)
}
