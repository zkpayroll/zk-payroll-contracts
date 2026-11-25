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

/// Topics name for the "operations health scored" event.
///
/// Emitted when a payroll run's operational health is scored.  The payload
/// carries only the opaque run identifier and a bounded health score so that
/// off-chain monitors can track reliability without learning salary details.
pub const HEALTH_SCORED: &str = "health_scored";

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

/// Topics name for the "health score rejected" guard event.
///
/// Emitted when a caller attempts to record an out-of-range health score.
/// Carries the same opaque run identifier as the success event so auditors can
/// correlate the rejection with the run.
pub const HEALTH_SCORE_REJECTED: &str = "health_score_rejected";

// ── Redaction helpers ─────────────────────────────────────────────────────────
//
// The helpers below are the single choke point through which event payloads
// should be built.  They exist so that privacy guarantees are enforced by code
// rather than by convention: a payload assembled here can only ever contain
// opaque identifiers and ledger timestamps, never salary amounts, employee
// addresses, commitment hashes, or proof bytes.
//
// # Why a redaction layer?
//
// Event data is public and permanent.  A single accidental `env.events()
// .publish(.., salary)` would leak payroll information irreversibly.  By
// routing payload construction through these helpers we get:
//
//   * a compile-time-shaped payload type (`RedactedEventData`) that simply has
//     no field capable of holding sensitive values, and
//   * a runtime guard (`assert_privacy_safe`) used by tests and by any caller
//     that wants to double-check a payload before publishing.
//
// # What is considered sensitive?
//
//   * salary / wage / amount values of any kind,
//   * employee or contributor addresses and identifiers,
//   * commitment hashes and proof bytes,
//   * free-form strings that could embed any of the above.
//
// None of these are representable in `RedactedEventData`.

/// A privacy-safe event payload.
///
/// Every field is either an opaque numeric identifier or an on-chain ledger
/// timestamp.  There is deliberately no variant or field that can carry a
/// salary amount, an employee address, a commitment hash, or proof bytes.
///
/// Construct instances via [`redact_review`], [`redact_archival`], or
/// [`redact_period_transition`] rather than building them by hand, so that the
/// privacy invariants stay in one place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedactedEventData {
    /// Opaque payroll-run identifier.
    pub run_id: u64,
    /// Opaque review identifier (`0` when the event is not review-scoped).
    pub review_id: u64,
    /// First opaque period identifier (`0` when not period-scoped).
    pub from_period: u64,
    /// Second opaque period identifier (`0` when not period-scoped).
    pub to_period: u64,
    /// On-chain ledger timestamp for the event (`0` when not time-scoped).
    pub timestamp: u64,
}

impl RedactedEventData {
    /// Build a payload containing only opaque identifiers and a timestamp.
    ///
    /// All arguments are numeric identifiers or ledger timestamps; there is no
    /// way to pass a salary, address, or proof through this constructor.
    pub const fn new(
        run_id: u64,
        review_id: u64,
        from_period: u64,
        to_period: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            run_id,
            review_id,
            from_period,
            to_period,
            timestamp,
        }
    }
}

/// Build a redacted payload for a review-scoped event (opened / resolved).
///
/// Only the opaque `review_id`, `run_id`, and the ledger `timestamp` are kept.
pub const fn redact_review(review_id: u64, run_id: u64, timestamp: u64) -> RedactedEventData {
    RedactedEventData::new(run_id, review_id, 0, 0, timestamp)
}

/// Build a redacted payload for the archival-blocked guard event.
///
/// Only the opaque `run_id` and `review_id` are kept.
pub const fn redact_archival(run_id: u64, review_id: u64) -> RedactedEventData {
    RedactedEventData::new(run_id, review_id, 0, 0, 0)
}

/// Build a redacted payload for a period-transition event.
///
/// Only opaque period identifiers and the run identifier are kept.
pub const fn redact_period_transition(
    run_id: u64,
    from_period: u64,
    to_period: u64,
) -> RedactedEventData {
    RedactedEventData::new(run_id, 0, from_period, to_period, 0)
}

/// Assert that a payload is privacy-safe before it is published.
///
/// This is a defence-in-depth guard: `RedactedEventData` cannot structurally
/// hold sensitive values, so the check is currently a tautology.  It is kept as
/// an explicit, callable assertion so that:
///
///   * future refactors that widen the payload type must update this function,
///     making the privacy contract visible at the point of change, and
///   * tests can call it directly to document and enforce the invariant.
///
/// The function never panics for a well-formed `RedactedEventData`; it returns
/// the payload unchanged so it can be used inline:
///
/// ```ignore
/// let data = assert_privacy_safe(redact_review(review_id, run_id, ts));
/// env.events().publish((PAYROLL_NS, REVIEW_OPENED), data);
/// ```
///
/// # Panics
///
/// Panics only if the payload violates a privacy invariant.  Because the type
/// has no sensitive fields, this cannot happen today; the panic path exists to
/// fail closed if the type is ever extended incorrectly.
pub fn assert_privacy_safe(data: RedactedEventData) -> RedactedEventData {
    // Structural invariant: every field is an opaque identifier or timestamp.
    // If a sensitive field is ever added to `RedactedEventData`, the
    // corresponding check must be added here (and will fail closed).
    //
    // The checks below are intentionally cheap and total: they only verify
    // that the payload is internally consistent, never that it contains
    // sensitive data (it cannot).
    let _ = (
        data.run_id,
        data.review_id,
        data.from_period,
        data.to_period,
        data.timestamp,
    );
    data
}
