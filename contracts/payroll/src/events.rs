/// Privacy-safe event helpers for the overpayment review and contract period subsystems.
///
/// # Privacy design
///
/// Overpayment reviews must not expose salary values or per-employee payment
/// details on-chain.  Every event defined here carries only the minimum
/// identifiers needed for off-chain indexers and auditors to correlate events
/// with their own permissioned records:
///
///   * `run_id`   — the opaque u64 payroll-run identifier.
///   * `review_id` — the opaque u64 review identifier.
///   * `flagged_at` / `resolved_at` — on-chain ledger timestamps.
///   * `resolver`  — the authorized address that closed the review.
///
/// **Deliberately omitted:** amounts, employee addresses, commitment hashes,
/// proof data, and any field that would allow a passive observer to reconstruct
/// salary information.
///
/// # Event catalogue
///
/// | Symbol constant          | Topics payload                    | Data payload                          |
/// |--------------------------|-----------------------------------|---------------------------------------|
/// | `REVIEW_OPENED`          | `("payroll", "review_opened")`    | `(review_id, run_id, flagged_at)`     |
/// | `REVIEW_RESOLVED`        | `("payroll", "review_resolved")`  | `(review_id, run_id, resolved_at)`    |
/// | `ARCHIVAL_BLOCKED`       | `("payroll", "archival_blocked")` | `(run_id, review_id)`                 |
/// | `PERIOD_TRANSITION`      | `("payroll", "period_transition")`| `(run_id, from_period, to_period)`    |

// ── Symbol string constants ───────────────────────────────────────────────────
//
// Soroban symbols are ≤ 32 characters.  These are defined as `&str` so callers
// can pass them directly to `Symbol::new(&env, REVIEW_OPENED)` without import
// boilerplate.

/// Topics name for the "review opened" event.
pub const REVIEW_OPENED: &str = "review_opened";

/// Topics name for the "review resolved" event.
pub const REVIEW_RESOLVED: &str = "review_resolved";

/// Topics name for the "archival blocked" guard event.
pub const ARCHIVAL_BLOCKED: &str = "archival_blocked";

/// Top-level contract namespace used in all event topics.
pub const PAYROLL_NS: &str = "payroll";

/// Topics name for the "period transition" event.
///
/// Emitted whenever a payroll run advances from one contract period to the
/// next.  The payload intentionally carries only opaque period identifiers so
/// that off-chain indexers can follow the transition without learning any
/// salary or contributor details.
pub const PERIOD_TRANSITION: &str = "period_transition";

/// Topics name for the "period transition rejected" guard event.
///
/// Emitted when a caller attempts an invalid period transition (e.g. a
/// non-monotonic or skipped period).  Carries the same opaque identifiers as
/// the success event so auditors can correlate the rejection with the run.
pub const PERIOD_TRANSITION_REJECTED: &str = "period_transition_rejected";
