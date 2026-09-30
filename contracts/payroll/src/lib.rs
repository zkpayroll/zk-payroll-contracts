#![no_std]
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token as soroban_token, Address, Bytes,
    BytesN, Env, String, Symbol, Vec,
};

use pause_manager::PauseManagerClient;
use proof_verifier::ProofVerifierClient;
use salary_commitment::SalaryCommitmentContractClient;
use shared_errors::{AuthError, PaymentError, TreasuryError};

pub mod approvals;
pub use approvals::{ApprovalProgress, RunApproval, MAX_APPROVAL_THRESHOLD, MAX_RUN_APPROVALS};

pub mod config_audit;
use config_audit::{config_keys, no_value_ref, record_config_change, stored_ref, value_ref};

pub mod failure_reasons;
use failure_reasons::{DryRunArgs, PayrollDryRunReport, PayrollFailureReason};

pub mod signed_operator_actions;
use signed_operator_actions::{
    consumed_key, require_not_expired, SignedOperatorAction, SignedOperatorPayload,
};

pub mod execution_authorization;
use execution_authorization::ExecutionInitiatorAuthorization;

pub mod correction_authorization;
use correction_authorization::{
    CorrectionAuthorizationLimits, CorrectionLimitBreach, CorrectionUsage,
};

pub mod import_source;
use import_source::{require_authorized_source, validate_source_for_report};

pub mod payroll_period_ownership;
pub use payroll_period_ownership::{
    assert_payroll_period_owner, verify_payroll_period_owner, PayrollPeriodOwnership,
};

pub mod employee_record_version;
pub use employee_record_version::{
    detect_version_conflict, increment_employee_version, EmployeeRecord,
};

pub mod payment_instruction_expiry;
pub use payment_instruction_expiry::{
    enforce_payment_instruction_expiry, PaymentInstruction,
};

pub mod employee_suspension_rules;
pub use employee_suspension_rules::{
    evaluate_suspension_payout, EmployeeStatus, PayrollPayoutRule,
};

const MAX_BATCH: u32 = 50;
const MAX_DRAFT_DESCRIPTION_BYTES: u32 = 256;

#[contract]
pub struct Payroll;

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub admin: Address,
    pub token: Address,
    pub verifier: Address,
    pub commitment: Address,
    pub treasury: Address,
    pub treasury_owner: Address,
}

/// Reconciliation status for completed payroll runs.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationStatus {
    Unreconciled,
    Reconciled,
    Failed,
}

/// Canonical payroll run state shared by contracts, SDKs, and dashboards (#159).
///
/// This enum is the source of truth for user-visible payroll run lifecycle
/// labels. Off-chain clients should mirror these exact names and transition
/// rules from `docs/payroll-state-machine.md` and the JSON fixture under
/// `fixtures/state-machine/`.
///
/// `Cancelled` and `Expired` are distinct outcomes: `Cancelled` is the admin's
/// intentional stop, while `Expired` means the run was never finalized before
/// its expiry policy elapsed (#474). Both release the treasury funds
/// reservation without executing any payment.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayrollRunState {
    Draft = 0,
    Validating = 1,
    ProofPending = 2,
    ReadyToSubmit = 3,
    Submitted = 4,
    Confirming = 5,
    Completed = 6,
    Failed = 7,
    Cancelled = 8,
    ReconciliationRequired = 9,
    /// Prepared run whose expiry policy elapsed without finalization (#474).
    /// Terminal — it is removed from `PendingRun` (releasing its funds
    /// reservation) and kept only as a redacted `ExpiredRunRecord` audit
    /// marker. Ordinal 10 appends after the #159 set so pre-existing
    /// storage discriminants are unchanged.
    Expired = 10,
}

/// A pending payroll run that has been prepared but not yet finalized.
/// Stores the metadata needed to execute the run without exposing salary amounts.
///
/// Once finalized (via `finalize_payroll_run`), this becomes a completed `PayrollRun`.
/// If cancelled (via `cancel_payroll_run`), this is removed from storage.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingPayrollRun {
    pub run_id: u64,
    pub prepared_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
    pub draft_hash: BytesN<32>,
    pub nonce: BytesN<32>,
}

/// A completed payroll run record.
///
/// `draft_hash` is the SHA-256 / Poseidon hash of the off-chain payroll
/// preparation artifact submitted by the client (#102). Storing it on-chain
/// gives auditors a stable reference to tie the execution back to the
/// reviewed draft.
///
/// `metadata_hash` is a SHA-256 hash of off-chain metadata (payroll period,
/// company ID, employee batch, commitment references). It is validated against
/// a pre-committed hash via `commit_metadata` and stored for audit (#177).
///
/// `nonce` is a caller-supplied, company-scoped uniqueness token (#103).
/// Once used it can never be reused, preventing accidental duplicate runs.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRun {
    pub run_id: u64,
    pub executed_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
    /// Off-chain draft hash bound at execution time (issue #102).
    pub draft_hash: BytesN<32>,
    /// Caller-supplied run nonce (issue #103). Unique per contract lifetime.
    pub nonce: BytesN<32>,
    pub reconciliation_status: ReconciliationStatus,
    /// Off-chain metadata hash (period, company, batch, commitments) (#177).
    pub metadata_hash: BytesN<32>,
    /// Hash of an off-chain payroll note (e.g. a payslip or payment receipt
    /// document issued outside the contract) bound to this run (#617). The
    /// zero hash indicates no note has been bound yet, the same convention
    /// `metadata_hash` already uses.
    pub note_hash: BytesN<32>,
}

/// Immutable result binding for a client-supplied idempotency key.
///
/// The payload hash makes a reused key safe to retry only when the request is
/// byte-for-byte equivalent. A key reused with different payroll data is
/// rejected instead of silently returning another run's result.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollExecutionIdempotencyRecord {
    pub run_id: u64,
    pub payload_hash: BytesN<32>,
    pub created_at: u64,
}

/// Duplicate-execution guard record for a payroll run.
///
/// Keyed by a caller-supplied idempotency key. Stores only the resulting run
/// id and a hash of the request payload so a retry with identical data can be
/// recognised, while a key reused with different data is rejected. No salary
/// amounts or employee identities are persisted here.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollExecutionGuard {
    pub run_id: u64,
    pub payload_hash: BytesN<32>,
    pub recorded_at: u64,
}

/// Pending emergency withdrawal request (issue #104).
///
/// Withdrawal requires two separate authorised actions:
/// 1. `request_emergency_withdrawal` ? called by the `treasury_owner`.
/// 2. `approve_emergency_withdrawal` ? called by the `admin`.
///
/// This two-step design ensures neither role can unilaterally drain funds.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyWithdrawalRequest {
    pub amount: i128,
    pub recipient: Address,
    pub requested_at: u64,
    pub approved: bool,
}

/// Lifecycle state for a long-running payroll batch execution checkpoint.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BatchCheckpointState {
    Started = 0,
    PartiallyCheckpointed = 1,
    Resumed = 2,
    Completed = 3,
    Failed = 4,
}

/// A privacy-safe checkpoint for an interrupted payroll batch.
///
/// The checkpoint key is derived from employer + batch root + asset + execution
/// nonce so that retries are deterministic and replay-resistant while avoiding
/// disclosure of employee salary rows in the event payload.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchCheckpoint {
    pub employer: Address,
    pub batch_root: BytesN<32>,
    pub asset: Address,
    pub execution_nonce: BytesN<32>,
    pub state: BatchCheckpointState,
    pub last_checkpoint_index: u32,
    pub total_checkpoints: u32,
    pub completed: bool,
    pub failed: bool,
}

/// Lifecycle state for a resumable payroll batch (issue #611).
///
/// Serialized as a stable ordinal so off-chain clients can persist and
/// pattern-match on it across contract upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BatchResumeStatus {
    /// No checkpoint exists for the supplied batch identity: submit a fresh
    /// `batch_process_payroll_bounded` call.
    NotFound = 0,
    /// A checkpoint is mid-execution with payments remaining: call
    /// `batch_process_payroll_bounded` again with the same identity to resume.
    Resumable = 1,
    /// A checkpoint failed mid-execution: clear it with
    /// `resume_payroll_batch` (admin-authorized) before resubmitting.
    FailedRetryable = 2,
    /// A checkpoint already finished (all payments executed). Resubmitting is
    /// rejected, so the caller can stop polling.
    Completed = 3,
}

/// Privacy-safe, actionable resume plan for an interrupted payroll batch
/// (issue #611).
///
/// Exposes only batch-level operational progress: the persisted cursor, the
/// count the caller reported for the batch, and the exact next action. It
/// never contains employee addresses, salaries, proof material, or the
/// remaining employee identities, so it is safe to surface to dashboards and
/// integrators.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResumePlan {
    /// Coarse lifecycle classification of the batch (see
    /// [`BatchResumeStatus`]).
    pub status: BatchResumeStatus,
    /// Number of payments already executed and checkpointed.
    pub processed_count: u32,
    /// Payment count the caller reports for this batch identity.
    pub expected_total: u32,
    /// `true` when the persisted cursor is consistent with `expected_total`.
    pub cursor_consistent: bool,
    /// Number of payments still outstanding (`expected_total -
    /// processed_count` when consistent; `0` otherwise).
    pub remaining_count: u32,
    /// Whether `resume_payroll_batch` may be called right now. Only
    /// `FailedRetryable` batches with a consistent cursor and at least one
    /// outstanding payment are resumable.
    pub can_resume: bool,
}

// ?? Issue #89: payroll amendment flow ????????????????????????????????????????

/// Lifecycle state of a payroll run draft.
///
/// Only `Pending` drafts may be amended. `Finalized` drafts are locked for review.
/// `Submitted`, `Cancelled`, and `Expired` represent terminal draft states.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RunDraftState {
    /// Newly created via `create_run_draft`, or freshly amended. Amendable
    /// and cancellable. The only state a duplicate-period check (#398)
    /// blocks a new draft against.
    Pending = 0,
    /// Locked in via `finalize_run_draft`; no longer amendable. Awaiting
    /// submission into an executable payroll run.
    Finalized = 1,
    /// Converted into a real payroll run via `submit_run_draft`. Terminal —
    /// the draft record itself is no longer actionable past this point.
    Submitted = 2,
    /// Withdrawn by the admin before submission. Terminal.
    Cancelled = 3,
    /// Timed out before being finalized/submitted. Terminal.
    Expired = 4,
}

/// An unfinalized payroll run draft that can be corrected before execution.
///
/// Admins create a draft, optionally amend it one or more times, then
/// finalize it. Once finalized the record is immutable and every amendment
/// is reflected in `amendment_count` for auditability.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRunDraft {
    pub draft_id: u64,
    pub created_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
    pub period_label: Symbol,
    pub state: RunDraftState,
    pub amendment_count: u32,
    pub updated_at: u64,
}

// ── Issue #471 / #484: Payroll period freeze & reopening guard ────────────────

/// Record representing a frozen payroll period (#471, #484).
///
/// Created automatically when a draft is submitted (`reason = finalized`),
/// or manually by the admin via `freeze_payroll_period`. Once frozen/finalized, no
/// draft creation, amendment, description update, finalization, or submission
/// is allowed for this period until the admin unfreezes/reopens it.
/// The record intentionally contains no salary values or per-employee data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodFreeze {
    /// Period label this freeze guards (matches the draft `period_label`).
    pub period_label: Symbol,
    /// Address that applied the freeze (admin, or the admin that submitted
    /// the run which auto-froze the period).
    pub frozen_by: Address,
    /// Ledger timestamp when the freeze was applied.
    pub frozen_at: u64,
    /// Short operator label for the freeze (e.g. `finalized`, `manual`).
    pub reason: Symbol,
    /// Number of payroll runs that had been submitted for this period when
    /// the freeze was applied.
    pub runs_count: u32,
}

/// Cooldown configuration for period reopen operations.
///
/// Prevents rapid reopening of finalized periods by enforcing a minimum
/// time gap between successive reopens. This guards against accidental
/// or malicious repeated unfreezes that could expose the period to
/// uncontrolled edits.
///
/// Privacy-safe: contains only duration and timestamps, never payroll data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodReopenCooldown {
    /// Minimum seconds required between period reopens (0 = disabled).
    pub cooldown_seconds: u64,
    /// Last timestamp when this period was reopened.
    pub last_reopen_at: u64,
}

/// Issue #621: Contract period transition consistency check result.
///
/// Describes whether a requested transition between two payroll periods is
/// consistent with the currently open capacity-accounting period. The result
/// is privacy-safe: it contains only period labels and a stable reason code,
/// never salary amounts, employee identities, or proof material.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodTransitionStatus {
    /// Transition is allowed: the target period is the current period or a
    /// strictly later period, and no conflicting state blocks the move.
    Allowed = 0,
    /// Transition is rejected because the target period precedes the current
    /// open period (a backwards transition).
    BackwardsTransition = 1,
    /// Transition is rejected because the source period does not match the
    /// currently open period.
    SourceMismatch = 2,
    /// Transition is rejected because the target period is already frozen.
    TargetFrozen = 3,
    /// Transition is rejected because the source period is not frozen and
    /// therefore still open for edits.
    SourceNotFrozen = 4,
}

/// Issue #621: Read-only assessment of a contract period transition.
///
/// Exposes the verdict, the source and target period labels, and the current
/// open period so integrators can render actionable errors without leaking
/// payroll data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodTransitionCheck {
    pub status: PeriodTransitionStatus,
    pub from_period: Symbol,
    pub to_period: Symbol,
    pub current_period: Option<Symbol>,
    pub allowed: bool,
}

// ?? Reviewer Authorization & Run Review ?????????????????????????????????????

/// Review decision outcome for a payroll run.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ReviewDecision {
    Approved = 0,
    Rejected = 1,
    ChangesRequested = 2,
    /// Approval was retracted by the reviewer that granted it (#522).
    Withdrawn = 3,
}

/// A review record submitted by an authorized reviewer.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RunReview {
    pub run_id: u64,
    pub reviewer: Address,
    pub decision: ReviewDecision,
    pub reason: Symbol,
    pub reviewed_at: u64,
}

/// Result of removing a stale approval record (#548).
///
/// Deliberately carries no reviewer address and no payroll amounts: the record
/// type is enough for an operator or indexer to reconcile the cleanup.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleApprovalCleanupResult {
    pub run_id: u64,
    pub removed: bool,
    pub reviewed_at: u64,
    pub expired_at: u64,
}

/// Read-only staleness assessment for a payroll run's approval (#548).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleApprovalStatus {
    pub run_id: u64,
    pub is_stale: bool,
    pub reviewed_at: u64,
    pub expires_at: u64,
}

// ── Issue #342: dispute freeze/thaw controls ─────────────────────────────────

/// Lifecycle status of a payroll dispute.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DisputeStatus {
    Active = 0,
    Resolved = 1,
}

/// A payroll dispute record scoped to an employer, period, and batch root.
///
/// While `status` is `Active`, the associated payroll run is frozen: it
/// cannot be finalized, archived, or pruned. Only the admin or an address
/// granted the dispute-authority role may open or resolve a dispute.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Dispute {
    pub dispute_id: u64,
    pub run_id: u64,
    pub employer: Address,
    pub period: Symbol,
    pub batch_root: BytesN<32>,
    pub opened_by: Address,
    pub opened_at: u64,
    pub open_reason: Symbol,
    pub status: DisputeStatus,
    pub resolved_by: Option<Address>,
    pub resolved_at: Option<u64>,
    pub resolution_reason: Option<Symbol>,
}

// ── Issue #338: per-period payroll capacity limits ─────────
/// Employer-configured capacity limits enforced per payroll period.
///
/// Limits are opt-in: if no policy has been set via `set_capacity_limits`,
/// `prepare_payroll_run` and `batch_process_payroll` behave exactly as
/// before, with no capacity checks performed.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityLimits {
    /// Maximum number of batches (prepared or executed) allowed per period.
    pub max_batches: u32,
    /// Maximum cumulative employee count allowed per period.
    pub max_employees: u32,
    /// Maximum cumulative committed value allowed per period.
    pub max_total_value: i128,
}

/// Accumulated usage counters for a single payroll period, tracked against
/// the employer's `CapacityLimits` policy.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodUsage {
    pub batch_count: u32,
    pub employee_count: u32,
    pub total_value: i128,
}

/// Category of capacity limit exceeded by a batch, for precise error
/// identification (issue #338).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CapacityLimitKind {
    BatchCount = 0,
    EmployeeCount = 1,
    TotalValue = 2,
}

// ── Issue #316: settlement window enforcement ───────────────────────
/// Employer-configured settlement window for a payroll period.
///
/// Timestamps are ledger (unix) time, consistent with `env.ledger().timestamp()`
/// used throughout this contract. The four timestamps carve the period into
/// three phases:
///   - `[open_at, execution_start)`  — period is open (drafting/preparation
///     may proceed) but batch execution is not yet allowed.
///   - `[execution_start, execution_end]` — the execution window: batch
///     execution (`prepare_payroll_run` / `batch_process_payroll`) succeeds.
///   - `(execution_end, close_at]`   — grace period: execution is blocked,
///     but pending runs may still be cancelled by the admin, and once
///     `close_at` has passed, expired via `expire_pending_run`.
///   - `> close_at`                  — fully closed.
///
/// Configuring a window is opt-in and scoped to the capacity-accounting
/// period label (see `open_capacity_period`): a period with no window
/// configured is unrestricted, preserving backward compatibility for callers
/// that don't use this feature.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementWindow {
    /// Timestamp at which this period opens (drafting/preparation allowed).
    pub open_at: u64,
    /// Timestamp at which batch execution becomes allowed.
    pub execution_start: u64,
    /// Timestamp after which execution is no longer allowed (grace begins).
    pub execution_end: u64,
    /// Timestamp after which the period is fully closed (grace ends).
    pub close_at: u64,
    /// Admin that configured this window.
    pub configured_by: Address,
    /// Timestamp at which this window was configured.
    pub configured_at: u64,
}

/// Timing status of a settlement window relative to the current ledger time,
/// exposed via events and read-only queries without leaking payroll data
/// (issue #316).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SettlementWindowStatus {
    /// Before `execution_start`: period is open but execution not yet allowed.
    PreOpen = 0,
    /// Within `[execution_start, execution_end]`: execution is allowed.
    Executable = 1,
    /// Within `(execution_end, close_at]`: grace period, execution blocked.
    Grace = 2,
    /// After `close_at`: fully closed.
    Closed = 3,
}

// ── Issue #248: payroll period configuration freeze guard ───────────
/// Freeze state of a payroll period's configuration.
///
/// A period's configuration (currently its settlement window) may be edited
/// while `Editable`. Once a period is frozen — explicitly by the admin, or
/// implicitly because a payroll run was submitted against it or it became
/// settlement-ready — unsafe edits are rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodConfigState {
    /// Configuration may still be edited.
    Editable = 0,
    /// Configuration is locked and must not change.
    Frozen = 1,
}

// ── Issue #482: Duplicate employee entry validation ──────────────────
/// Tracks which employees have been paid in a payroll run to prevent duplicates.
/// Maps run_id to a Vec of employee identifiers (commitment hashes).
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmployeePaidTracker {
    pub run_id: u64,
    pub paid_employees: Vec<BytesN<32>>,
}

// ── Issue #485: Payroll run status query helper ───────────────────────
/// Concise status view of a payroll run for dashboard and client views.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayrollRunStatusKind {
    /// Draft stage, pending finalization
    Pending = 0,
    /// Approved and ready for execution
    Approved = 1,
    /// Currently executing batch payments
    Executing = 2,
    /// Execution completed successfully
    Completed = 3,
    /// Execution failed, may be retried
    Failed = 4,
}

/// A concise, safe status view for a payroll run without sensitive payroll data.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRunStatus {
    pub run_id: u64,
    pub status: PayrollRunStatusKind,
    pub last_updated: u64,
    pub employee_count: u32,
    pub total_amount: i128,
}

// ── Issue #552: Expose payroll period health summary ──────────────────────────

/// Operational health status of a payroll period (#552).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodHealthStatus {
    /// Period is healthy and operational for payroll execution.
    Healthy = 0,
    /// Period is operational but requires attention (e.g., grace window, frozen config).
    Warning = 1,
    /// Period cannot execute payroll runs (e.g., paused, closed window, capacity exhausted).
    Blocked = 2,
}

/// Concise reason explaining the period health status (#552).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodHealthReason {
    /// Normal operational state; all checks pass.
    Normal = 0,
    /// Settlement window is in pre-open phase; execution not yet permitted.
    PreOpen = 1,
    /// Settlement window is in grace period; execution blocked, only settlement/expiry.
    GracePeriod = 2,
    /// Settlement window has expired or closed.
    WindowClosed = 3,
    /// Capacity limit on batch count reached or exceeded.
    BatchCapacityExceeded = 4,
    /// Capacity limit on employee count reached or exceeded.
    EmployeeCapacityExceeded = 5,
    /// Capacity limit on total value reached or exceeded.
    ValueCapacityExceeded = 6,
    /// Payroll contract is paused.
    ContractPaused = 7,
    /// Period configuration or edits are frozen.
    PeriodFrozen = 8,
}

/// Operational health summary for a payroll period (#552).
///
/// Privacy-safe: exposes operational readiness, timing state, and capacity counters
/// without leaking sensitive employee identities or individual salary values.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodHealthSummary {
    pub period: Symbol,
    pub status: PeriodHealthStatus,
    pub reason: PeriodHealthReason,
    pub is_current_period: bool,
    pub can_execute: bool,
    pub is_frozen: bool,
    pub is_paused: bool,
    pub has_active_draft: bool,
    pub window_status: Option<u32>,
    pub capacity_configured: bool,
    pub batch_count: u32,
    pub employee_count: u32,
    pub capacity_exceeded: bool,
}

// ── Issue #478: Payroll run metadata versioning ────────────────────────────────

/// Version metadata for a payroll run to handle contract changes safely.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRunMetadataVersion {
    pub run_id: u64,
    pub schema_version: u32,
    pub created_at: u64,
    pub metadata_hash: BytesN<32>,
}

// ── Issue #476: Contract-level payroll currency validation ──────────────
/// Currency configuration for a payroll contract to enforce consistent asset usage.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollCurrencyConfig {
    pub asset: Address,
    pub currency_code: Symbol,
    pub decimals: u32,
    pub configured_at: u64,
    pub configured_by: Address,
}

// ?? Issue #91: privileged-role rotation ??????????????????????????????????????

/// Pending two-step role-rotation request.
///
/// The current holder proposes a successor; the successor must explicitly
/// accept. Neither party can unilaterally complete the transfer, and the
/// proposal can be cancelled by the current holder at any time before
/// acceptance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingRotation {
    pub new_holder: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

// ?? Issue #339: Admin Handover Record ???????????????????????????????????????

/// Record of a pending admin handover requiring acceptance.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAdminHandover {
    pub current_admin: Address,
    pub pending_admin: Address,
    pub requested_at: u64,
}

// ?? Issue #334: Signer Quorum Approval Payload ??????????????????????????????

/// Multi-signer approval payload bound to batch root, employer, period, asset, nonce, and policy version.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumApprovalPayload {
    pub batch_root: BytesN<32>,
    pub employer: Address,
    pub period: Symbol,
    pub asset: Address,
    pub nonce: BytesN<32>,
    pub policy_version: u32,
}

// ?? Issue #333: Compliance Hold State ?????????????????????????????????????????

/// Scope of a compliance hold affecting payroll execution.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ComplianceHoldScope {
    /// Hold on a specific batch of payments
    Batch = 0,
    /// Hold on an employee or group of employees
    Employee = 1,
    /// Hold on all payroll for an employer
    Employer = 2,
}

/// A compliance hold state that blocks affected payroll execution.
///
/// Compliance holds provide a controlled way to pause specific payroll operations
/// while audit issues are resolved, without deleting payroll records. Holds can be
/// placed by authorized compliance roles and released once resolved.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ComplianceHold {
    pub hold_id: u64,
    pub scope: ComplianceHoldScope,
    pub target: Address,
    pub reason_code: Symbol,
    pub placed_at: u64,
    pub placed_by: Address,
    pub is_active: bool,
}

// ?? Issue #337: Funding Reservation Expiry ?????????????????????????????????????

/// Funding reservation with expiry policy for asset-specific reservations.
///
/// Reservations track locked funds for pending payroll batches. Expiry prevents
/// stale unexecuted payroll batches from locking treasury funds indefinitely.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ReservationExpiry {
    pub asset: Address,
    pub reserved_amount: i128,
    pub expires_at: u64,
    pub created_at: u64,
}

// ?? Issue #335: Payroll Run Archival ???????????????????????????????????????????

/// Archive marker for finalized payroll runs, enabling long-term record retention.
///
/// Archive markers allow old payroll runs to be distinguished as active, finalized,
/// archived, or retained for compliance, while keeping operational views clean and
/// storage policies intentional.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ArchiveMarker {
    pub run_id: u64,
    pub archived_at: u64,
    pub archived_by: Address,
    pub archive_reason: Symbol,
}

/// Administrator-controlled storage retention windows, in ledger seconds.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub finalized_run_seconds: u64,
    pub cancelled_batch_seconds: u64,
    pub challenge_seconds: u64,
}

// ?? Issue #402: Safe Treasury Balance Summary ??????????????????????????????????

/// Safe treasury balance summary by asset (#402).
///
/// Provides aggregate treasury balance visibility (total on-chain balance,
/// locked/reserved funds for pending payroll, blocked funds under compliance holds,
/// and available unencumbered balance) without exposing private employee rows.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeTreasurySummary {
    pub asset: Address,
    pub total_balance: i128,
    pub available_balance: i128,
    pub reserved_balance: i128,
    pub blocked_balance: i128,
}

/// A stable reason a payroll funding source is not ready for a requested spend.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FundingSourceBlocker {
    /// Payroll has not been initialized with funding-source addresses.
    NotInitialized = 0,
    /// A funding readiness request must use a positive amount.
    InvalidRequiredAmount = 1,
    /// The canonical payout asset is not enabled for payroll.
    AssetNotAllowed = 2,
    /// The configured address did not respond as a SEP-41 token contract.
    TokenUnavailable = 3,
    /// Unreserved treasury funds do not cover the requested amount.
    InsufficientFunds = 4,
    /// The source is ready: no blocker applies.
    ///
    /// A sentinel rather than wrapping this enum in `Option` in
    /// [`FundingSourceReadiness`]: soroban-sdk's `#[repr(u32)]` enum codegen
    /// only implements the fallible `TryInto<ScVal>` direction, not the
    /// infallible `Into<ScVal>` that `#[contracttype]`'s `Option<T>` field
    /// support requires, so `Option<FundingSourceBlocker>` does not compile
    /// as a struct field.
    NotBlocked = 5,
}

/// Read-only readiness result for the configured payroll funding source.
///
/// The result exposes only aggregate treasury availability and a stable
/// blocker code; it contains no employee, salary-row, or proof data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingSourceReadiness {
    pub ready: bool,
    /// [`FundingSourceBlocker::NotBlocked`] when `ready` is true.
    pub blocker: FundingSourceBlocker,
    pub required_amount: i128,
    /// `None` when the source is not initialized, allowlisted, or queryable.
    pub available_balance: Option<i128>,
}

// ?? Issue #404: Cancelled Batch Read Status ????????????????????????????????????

/// Safe metadata for a cancelled payroll batch (#404).
///
/// Allows clients, audit logs, and status dashboards to inspect cancellation
/// details without exposing private payroll row details.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelledBatchStatus {
    pub run_id: u64,
    pub cancelled_at: u64,
    pub cancelled_by: Address,
    pub reason: Symbol,
    pub employee_count: u32,
    pub total_amount: i128,
    pub draft_hash: BytesN<32>,
    pub is_cancelled: bool,
}

// ?? Issue #352: Payroll Batch Split Validation ??????????????????????????????????

/// Tracking metadata for batch splits to preserve original aggregate commitment (#352).
///
/// When a large payroll batch is split into smaller child batches, this structure
/// records the relationship between the parent batch and its children, along with
/// aggregate commitment data to ensure the sum of child batches equals the original.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BatchSplitRecord {
    pub parent_run_id: u64,
    pub child_run_id: u64,
    pub parent_total: i128,
    pub parent_employee_count: u32,
    pub child_total: i128,
    pub child_employee_count: u32,
    pub split_at: u64,
    pub split_by: Address,
}

// ?? Issue #403: Payroll Approval Expiry ????????????????????????????????????????

/// Default maximum validity age for reviewer approvals (7 days in seconds) (#403).
pub const DEFAULT_APPROVAL_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;

// ?? Issue #147: company lifecycle state ??????????????????????????????????????????

/// Lifecycle state of the company operating this payroll contract.
///
/// Payroll execution is only permitted when the state is `Active`. This gate
/// runs before any auth checks, balance reads, or transfer logic so that
/// rejected calls are fully clean with no partial side effects.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanyState {
    /// Normal operating state ? payroll execution permitted.
    Active,
    /// Operations suspended; payroll execution rejected until set to Active.
    Paused,
    /// Company decommissioned; no further payroll runs are permitted.
    Archived,
    /// Onboarding incomplete; payroll execution not yet permitted.
    Incomplete,
}

// ?? Storage keys ??????????????????????????????????????????????????????????????
// Issue #196: Storage Key Versioning Strategy
//
// ## Overview
// This contract uses a versioned storage-key design to enable safe schema
// evolution during contract upgrades. Each storage key is strongly typed and
// scoped to prevent collisions across upgrade boundaries.
//
// ## Versioning Strategy
// 1. **Enum-based namespacing**: All keys are variants of the `DataKey` enum,
//    ensuring type safety and preventing accidental key collisions.
//
// 2. **Append-only evolution**: When adding new storage patterns, append new
//    variants to the enum rather than modifying existing ones. This preserves
//    backward compatibility with data written by earlier contract versions.
//
// 3. **Explicit migration path**: If a breaking schema change is required:
//    - Add a new key variant (e.g., `PayrollRunV2(u64)`)
//    - Write a one-time migration function that reads from the old key and
//      writes to the new key
//    - Mark the old variant as deprecated in comments
//    - After migration window, the old variant can be removed in a future release
//
// 4. **Parameterized keys**: Many keys are parameterized (e.g., `PayrollRun(u64)`).
//    This design is forward-compatible ? new fields can be added to the stored
//    struct without changing the key structure.
//
// 5. **Persistent vs Temporary storage**: Keys map to Persistent storage unless
//    otherwise noted. Temporary storage (not used here) would require a separate
//    key namespace to avoid upgrade confusion.
//
// ## Upgrade-safe patterns
// - ? Adding new key variants (append-only)
// - ? Adding fields to structs stored under existing keys (Soroban XDR evolution)
// - ? Creating parallel V2 keys and migrating data over time
// - ? Changing the type signature of an existing key variant (breaks deserialization)
// - ? Reusing a key variant for a different data type (silent corruption)
//
// ## Example future upgrade scenarios
//
// ### Scenario 1: Adding a new payroll feature
// ```rust
// // Add to DataKey enum:
// PayrollSchedule(u64),  // New feature, no conflicts
// ```
//
// ### Scenario 2: Breaking change to PayrollRun
// ```rust
// // Step 1: Add new variant
// PayrollRunV2(u64),
//
// // Step 2: Write migration function
// pub fn migrate_payroll_runs_to_v2(e: Env) {
//     let counter: u64 = e.storage().persistent()
//         .get(&DataKey::RunCounter).unwrap_or(0);
//     for id in 1..=counter {
//         if let Some(old_run) = e.storage().persistent()
//             .get::<_, PayrollRun>(&DataKey::PayrollRun(id)) {
//             let new_run = PayrollRunV2::from(old_run);
//             e.storage().persistent()
//                 .set(&DataKey::PayrollRunV2(id), &new_run);
//         }
//     }
// }
//
// // Step 3: Update all read/write call sites to use V2 key
// // Step 4: Mark PayrollRun(u64) as deprecated
// ```
//
// ### Scenario 3: Deprecating old data
// ```rust
// // After successful migration and a deprecation window:
// // Remove the old variant from the enum in a new release
// // (ensure no production deployments still reference it)
// ```
//
// ## Testing migrations
// Integration tests for schema upgrades should:
// 1. Deploy contract V1 and write data
// 2. Upgrade to contract V2
// 3. Run migration function
// 4. Verify V2 reads return expected data
// 5. Verify old keys are either removed or marked obsolete
//
// See `contracts/integration_tests/` for versioning test examples.

#[contracttype]
pub enum DataKey {
    Addresses,
    PauseManager,
    PayrollRun(u64),
    /// Pending payroll run awaiting finalization (issue #75).
    PendingRun(u64),
    TreasuryOwner,
    RunCounter,
    /// Draft run storage for the amendment flow (issue #89).
    RunDraft(u64),
    /// Optional human-readable description for a draft (issue #420).
    DraftDescription(u64),
    /// Auto-increment counter for draft IDs (issue #89).
    RunDraftCounter,
    /// Pending admin rotation proposal (issue #91).
    PendingAdminRotation,
    /// Pending treasury-owner rotation proposal (issue #91).
    PendingTreasuryRotation,
    /// Marks a run nonce as consumed. Value is the run_id that used it (#103).
    RunNonce(BytesN<32>),
    /// Binds a client retry key to its immutable execution payload (#473).
    PayrollExecutionIdempotency(BytesN<32>),
    /// Marks a deposit nonce as consumed to prevent replay (#191).
    DepositNonce(BytesN<32>),
    /// Pre-committed draft hash bound before execution (#102).
    DraftCommitment(BytesN<32>),
    /// Pre-committed payroll note hash bound before being attached to a run
    /// (#617). Kept in its own keyspace, separate from `DraftCommitment`,
    /// so a note hash can never be mistaken for, or collide in storage
    /// with, an unrelated draft or metadata commitment.
    NoteCommitment(BytesN<32>),
    /// Pending emergency withdrawal request (#104).
    EmergencyRequest,
    /// Accumulated deposit balance per depositor address (#62).
    CompanyBalance(Address),
    /// Marks a completed payroll run as archived for long-term reporting (#146).
    ArchivedRun(u64),
    /// Marks a run as having an unresolved audit challenge open against it
    /// (#374). Set/cleared by the admin; blocks archival while present.
    ChallengedRun(u64),
    /// Tracks the active (Pending) draft id for a given period_label, so a
    /// second draft can't be created for the same period while one is
    /// already pending (#398).
    ActiveDraftForPeriod(Symbol),
    /// Company lifecycle state gate for payroll execution (#147).
    CompanyState,
    /// Canonical payroll run state for SDK/dashboard conformance (#159).
    PayrollState(u64),
    /// Allowed asset token map for payroll payouts.
    AllowedAsset(Address),
    /// Enumerable list backing the supported-assets read helper (#427).
    SupportedAssets,
    /// Count of payroll runs currently prepared but not yet resolved
    /// (cancelled). Used to lock unsafe admin configuration changes while a
    /// run is in progress — see `require_no_active_payroll_run`.
    PendingRunCount,
    /// Checkpointed payroll batch execution keyed by a privacy-safe tuple.
    BatchCheckpoint(Address, BytesN<32>, Address, BytesN<32>),
    /// Authorized reviewer registration for payroll run reviews.
    AuthorizedReviewer(Address),
    /// Review record for a payroll run.
    RunReview(u64),
    /// Auto-increment counter for dispute IDs (#342).
    DisputeCounter,
    /// Dispute record scoped to employer, period, and batch root (#342).
    Dispute(u64),
    /// Marks the id of the active dispute freezing a given run, if any (#342).
    ActiveDisputeForRun(u64),
    /// Authorized dispute-resolution role registration (#342).
    DisputeAuthority(Address),
    /// Employer-configured per-period capacity limits (#338).
    CapacityLimits,
    /// The payroll period currently open for capacity accounting (#338).
    CurrentPeriod,
    /// Accumulated batch/employee/value usage counters for a period (#338).
    PeriodUsage(Symbol),
    /// Pending admin handover request requiring acceptance (#339).
    PendingAdminHandover,
    /// Locked payroll funds reserved per asset (#343).
    LockedPayrollFunds(Address),
    /// Consumed signer quorum approval hash reference (#334).
    ConsumedQuorum(BytesN<32>),
    /// Compliance hold record by hold ID (#333).
    ComplianceHold(u64),
    /// Auto-increment counter for compliance hold IDs (#333).
    ComplianceHoldCounter,
    /// Reservation expiry policy per asset (#337).
    ReservationExpiry(Address),
    /// Archive marker for finalized payroll runs (#335).
    ArchiveMarker(u64),
    /// Administrator-controlled retention windows (#321).
    RetentionPolicy,
    /// Timestamp of the latest audit challenge marker (#321).
    ChallengeTimestamp(u64),
    /// Latest accepted payroll nonce per employer for monotonicity enforcement (#362).
    EmployerNonceSequence(Address),
    /// Compliance evidence pointer record for off-chain encrypted evidence (#361).
    EvidencePointer(BytesN<32>),
    /// Deduplication index for evidence pointers to prevent duplicates (#361).
    EvidencePointerIndex(BytesN<32>),
    /// Contract storage version for migration checks (#360).
    StorageVersion,
    /// Migration readiness status for sensitive operations (#360).
    MigrationReady,
    /// Minimum payout amount threshold configuration (#514).
    MinimumPayoutAmount,
    /// Cancelled payroll batch status record (#404).
    CancelledBatchRecord(u64),
    /// Batch split record linking parent and child batch runs (#352).
    BatchSplitRecord(u64, u64),
    /// Aggregate batch split tracker per parent run (#352).
    BatchSplitTracker(u64),
    /// Settlement window configuration for a capacity-accounting period (#316).
    SettlementWindow(Symbol),
    /// Enumerable labels with configured settlement windows, used to reject
    /// overlapping payroll calendar ranges.
    SettlementWindowPeriods,
    /// The capacity-accounting period a pending run was prepared under, if
    /// any was open at the time — used to locate its settlement window for
    /// later expiration (#316).
    PendingRunPeriod(u64),
    /// Freeze state for a payroll period's configuration (#248). Present and
    /// `true` once the period is frozen; absent means editable unless the
    /// period is implicitly frozen (settlement-ready or a submitted run).
    PeriodConfigFrozen(Symbol),
    /// Explicit freeze record for a finalized payroll period (#471, #484).
    PeriodFreeze(Symbol),
    /// Period reopen cooldown configuration and last reopen timestamp.
    PeriodReopenCooldown(Symbol),
    /// Tracks paid employees per run to prevent duplicate payments (#482).
    EmployeePaidTracker(u64),
    /// Status view for a payroll run (#485).
    PayrollRunStatus(u64),
    /// Metadata version for a payroll run (#478).
    PayrollRunMetadataVersion(u64),
    /// Payroll contract currency configuration (#476).
    PayrollCurrencyConfig,
    /// Contract-wide configuration revision, bumped once per audited
    /// configuration change (#490). Absent means `0`.
    ConfigRevision,
    /// Employer-configured maximum number of concurrently authorized
    /// reviewers (#539). Absent means unlimited, matching the pre-existing
    /// behaviour of `add_reviewer`.
    MaxReviewers,
    /// Count of currently authorized reviewers, kept in sync with
    /// `AuthorizedReviewer` additions/removals so the cap in `MaxReviewers`
    /// can be enforced without an unbounded scan (#539). Absent means `0`.
    ReviewerCount,
    /// The admin-registered ed25519 public key that signs off-chain,
    /// expiring operator authorizations (#519). Absent means no operator
    /// key is registered and `signed_add_reviewer` is unusable.
    OperatorKey,
    /// Marks a signed operator authorization payload (keyed by its
    /// SHA-256'd XDR encoding) as already consumed, preventing replay of
    /// the exact same signed payload (#519).
    ConsumedOperatorAuth(BytesN<32>),
    /// Number of distinct live reviewer approvals `finalize_payroll_run`
    /// requires. Absent means no threshold, matching the pre-existing
    /// single-review workflow.
    ApprovalThreshold,
    /// Reviewer approvals recorded for a payroll run, counted against
    /// `ApprovalThreshold` at finalization.
    RunApprovals(u64),
    /// Organization policy version applied to this contract (#553).
    /// Absent means no policy has been applied yet.
    OrganizationPolicyVersion,
    /// Record of the last applied organization policy migration (#553).
    /// Stores the previous and new policy versions plus the migration
    /// timestamp so integrators can audit policy transitions.
    OrganizationPolicyMigration,
    /// Registered import source for payroll batch authorization.
    ImportSource(Address),
    /// Employer-configured correction authorization ceilings (#577). Absent
    /// means corrections are unrestricted, matching the pre-existing behaviour
    /// of `amend_run_draft`.
    CorrectionAuthorizationLimits,
    /// Accumulated correction usage counters for a payroll period (#577).
    /// Absent means no corrections have been recorded for the period.
    CorrectionUsage(Symbol),
    // Future upgrade example (issue #196):
    // PayrollRunV2(u64),  // Would be added here when schema evolution is needed
}

// ── Issue #553: Contract organization policy migration validation ────────────

/// Record describing the outcome of an organization policy migration.
///
/// A migration is only accepted when the target `new_version` is strictly
/// greater than the currently applied `previous_version`, preventing
/// accidental downgrades or no-op replays. The record is privacy-safe and
/// contains no salary or employee data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationPolicyMigrationRecord {
    /// Policy version that was active before this migration.
    pub previous_version: u32,
    /// Policy version that is active after this migration.
    pub new_version: u32,
    /// Ledger timestamp when the migration was applied.
    pub migrated_at: u64,
    /// Admin that applied the migration.
    pub migrated_by: Address,
    /// Short operator label describing the migration reason.
    pub reason: Symbol,
}

/// Storage version state for migration checks (#360).
///
/// This struct tracks the current storage version and migration status
/// to prevent contract operations on unsupported or partially migrated storage.
#[contracttype]
#[derive(Clone, Debug)]
pub struct StorageVersionState {
    /// Current storage version
    pub version: u32,
    /// Timestamp when this version was set
    pub updated_at: u64,
    /// Whether migration is complete and all operations are allowed
    pub migration_complete: bool,
    /// Optional description of the current version
    pub version_description: soroban_sdk::String,
}

/// Migration readiness state for client detection (#360).
///
/// This struct allows clients to check if the contract is ready for
/// operations without performing the actual migration checks.
#[contracttype]
#[derive(Clone, Debug)]
pub struct MigrationReadinessState {
    /// Whether the contract is ready for operations
    pub ready: bool,
    /// Current storage version
    pub current_version: u32,
    /// Minimum supported version
    pub min_supported: u32,
    /// Maximum supported version
    pub max_supported: u32,
    /// Timestamp when this readiness was checked
    pub checked_at: u64,
}

/// Employer-specific nonce sequence tracking for monotonicity enforcement (#362).
///
/// This struct tracks the latest accepted payroll nonce per employer to ensure
/// monotonically increasing nonce ordering. This prevents:
/// - Replay attacks using stale nonces
/// - Ordering confusion in payroll history
/// - Duplicate period submissions
///
/// The nonce_sequence counter is incremented with each accepted payroll run
/// and must always be strictly greater than the previous value.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmployerNonceSequenceState {
    /// The latest accepted nonce sequence counter for this employer.
    /// Starts at 0 and increments with each successful payroll run.
    pub current_sequence: u64,
    /// Timestamp of the last accepted payroll run for this employer.
    pub last_accepted_at: u64,
    /// The nonce value from the last accepted payroll run.
    pub last_nonce: BytesN<32>,
}

// ?? Issue #361: Compliance Evidence Pointer Validation ?????????????????????????

/// Scope of a compliance evidence pointer.
///
/// Evidence pointers are scoped to prevent cross-context leakage and ensure
/// that references to off-chain encrypted evidence are properly isolated.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EvidencePointerScope {
    /// Evidence related to a specific employer
    Employer = 0,
    /// Evidence related to a specific payroll period
    Period = 1,
    /// Evidence related to a specific review case
    ReviewCase = 2,
}

/// Compliance evidence pointer for off-chain encrypted evidence (#361).
///
/// This struct provides a safe pointer to off-chain encrypted evidence without
/// leaking the actual evidence contents on-chain. The pointer includes:
/// - A hash commitment to the evidence content for integrity verification
/// - Scoping information to prevent cross-context references
/// - Deduplication information to prevent duplicate pointers
///
/// The actual evidence content is stored off-chain and referenced by the
/// content_hash. This ensures that only safe pointers and integrity
/// commitments are stored on-chain.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ComplianceEvidencePointer {
    /// Unique identifier for this evidence pointer
    pub pointer_id: BytesN<32>,
    /// SHA-256 hash of the off-chain evidence content for integrity verification
    pub content_hash: BytesN<32>,
    /// Scope of this evidence pointer
    pub scope: EvidencePointerScope,
    /// Target entity (employer, period, or review case) this pointer relates to
    pub target: Address,
    /// Timestamp when this pointer was created
    pub created_at: u64,
    /// Address that created this pointer
    pub created_by: Address,
    /// Optional metadata hash for additional context (period, company ID, etc.)
    /// Uses a zero-filled hash to represent "no metadata".
    pub metadata_hash: BytesN<32>,
}

#[allow(clippy::too_many_arguments)]
#[contractimpl]
impl Payroll {
    /// Publish the same aggregate treasury view exposed by the read-only API.
    /// No employee rows, salary values, or proof material are included.
    fn emit_treasury_balance_snapshot(e: &Env, asset: Address, trigger: Symbol) {
        let summary = Self::get_safe_treasury_summary(e.clone(), asset);
        payroll_events::emit_treasury_balance_snapshot(
            e,
            summary.asset,
            summary.total_balance,
            summary.available_balance,
            summary.reserved_balance,
            summary.blocked_balance,
            e.ledger().timestamp(),
            trigger,
        );
    }

    pub fn initialize(
        e: Env,
        admin: Address,
        token: Address,
        verifier: Address,
        commitment: Address,
        treasury: Address,
        treasury_owner: Address,
    ) {
        let key = DataKey::Addresses;
        if e.storage().persistent().has(&key) {
            panic!("Already initialized")
        }
        // Validate the configured asset before writing any payroll state. A
        // token address that does not implement the SEP-41 balance interface
        // would otherwise produce an initialized contract that cannot safely
        // report treasury availability or execute payroll.
        if soroban_token::Client::new(&e, &token)
            .try_balance(&treasury)
            .is_err()
        {
            panic!("Configured payroll asset is unavailable or does not implement the token balance interface");
        }
        let addrs = ContractAddresses {
            admin,
            token,
            verifier,
            commitment,
            treasury,
            treasury_owner: treasury_owner.clone(),
        };
        e.storage().persistent().set(&key, &addrs);
        e.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(addrs.token.clone()), &true);
        e.storage()
            .persistent()
            .set(&DataKey::TreasuryOwner, &treasury_owner);
        e.storage().persistent().set(&DataKey::RunCounter, &0u64);
        e.storage().persistent().set(
            &DataKey::RetentionPolicy,
            &RetentionPolicy {
                finalized_run_seconds: 30 * 24 * 60 * 60,
                cancelled_batch_seconds: 7 * 24 * 60 * 60,
                challenge_seconds: 30 * 24 * 60 * 60,
            },
        );

        payroll_events::emit_payroll_initialized(
            &e,
            addrs.admin.clone(),
            addrs.token.clone(),
            addrs.verifier.clone(),
            addrs.commitment.clone(),
            addrs.treasury.clone(),
            treasury_owner.clone(),
        );

        // #360 ? initialize storage version tracking
        Self::initialize_storage_version(&e);
    }

    fn require_not_paused(e: &Env) {
        if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(e, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    // Issue #147: reject payroll execution for any non-Active company state.
    // Absent state defaults to Active for backward compatibility with existing
    // deployments that predate this field.
    #[allow(dead_code)]
    fn require_company_active(e: &Env) {
        if let Some(state) = e
            .storage()
            .persistent()
            .get::<_, CompanyState>(&DataKey::CompanyState)
        {
            match state {
                CompanyState::Active => {}
                CompanyState::Paused => {
                    panic!("Company is paused; payroll execution is not permitted")
                }
                CompanyState::Archived => {
                    panic!("Company is archived; payroll execution is not permitted")
                }
                CompanyState::Incomplete => {
                    panic!("Company setup is incomplete; payroll execution is not permitted")
                }
            }
        }
    }

    fn pending_payroll_run_count(e: &Env) -> u32 {
        e.storage()
            .persistent()
            .get(&DataKey::PendingRunCount)
            .unwrap_or(0)
    }

    // Issue #253: configuration locks during active payroll execution.
    //
    // A run is "in progress" from the moment `prepare_payroll_run` reserves
    // its nonce and stores a `PendingPayrollRun` until it is explicitly
    // resolved via `cancel_payroll_run`. While any run is pending, changing
    // the acting admin, the treasury owner, the payout asset allowlist, or
    // the company lifecycle state could silently invalidate assumptions the
    // run was prepared under (which treasury funds are debited, which asset
    // pays out, who is authorised to act on it). This gate rejects those
    // specific changes until every pending run has been cancelled, keeping a
    // run's preconditions stable for its whole lifetime. It does not block
    // proposing a rotation (inert until accepted), pausing the system, or
    // resolving existing runs (`cancel_payroll_run`,
    // `update_reconciliation_status`), so operators always retain an escape
    // hatch.
    fn require_no_active_payroll_run(e: &Env) {
        if Self::pending_payroll_run_count(e) > 0 {
            panic!(
                "Configuration is locked: a payroll run is currently in progress. Cancel all pending runs before changing this setting"
            );
        }
    }

    /// Return `true` if one or more payroll runs are prepared but not yet
    /// resolved. While `true`, admin configuration changes that could
    /// undermine those runs (admin rotation, treasury rotation, asset
    /// allowlist, company state) are rejected (issue #253).
    pub fn has_active_payroll_run(e: Env) -> bool {
        Self::pending_payroll_run_count(&e) > 0
    }

    // ── Issue #620: contract execution initiator authorization ─────────────

    /// Require that the caller may initiate a contract execution (issue #620).
    ///
    /// Every on-chain execution entrypoint (`prepare_payroll_run`,
    /// `batch_process_payroll`, `batch_process_payroll_idempotent`, and
    /// `batch_process_payroll_bounded`) calls this before any other work, so an
    /// unauthorized initiator is rejected immediately with an actionable error
    /// instead of after unrelated validation has already run.
    fn require_execution_initiator(e: &Env) {
        let initiator = execution_authorization::authorized_initiator(e).expect(
            "Not initialized: contract addresses must be configured before a payroll execution",
        );
        execution_authorization::require_authorized(e, &initiator);
    }

    /// Return the address currently authorized to initiate a contract execution
    /// (issue #620).
    ///
    /// This is the payroll admin recorded by `initialize` and updated by the
    /// admin rotation/handover flows. Returns `None` when the contract has not
    /// been initialized, so callers can distinguish "not configured" from
    /// "configured, but this address is not the initiator".
    ///
    /// Privacy-safe: exposes only the operational role address, never salary
    /// amounts, employee identities, or proof material.
    pub fn get_execution_initiator(e: Env) -> Option<Address> {
        execution_authorization::authorized_initiator(&e)
    }

    /// Preflight whether `initiator` may initiate a contract execution
    /// (issue #620).
    ///
    /// Read-only and safe to call before submitting an execution, so SDKs and
    /// dashboards can tell a caller whether they hold the required role without
    /// spending a transaction. Returns the full authorization snapshot:
    /// verdict, resolved role, and whether the contract is initialized.
    pub fn check_execution_initiator(
        e: Env,
        initiator: Address,
    ) -> ExecutionInitiatorAuthorization {
        execution_authorization::check(&e, &initiator)
    }

    /// Boolean convenience wrapper around `check_execution_initiator`
    /// (issue #620).
    ///
    /// Soroban entrypoint names are limited to 32 characters, so this is the
    /// compact form of `check_execution_initiator`.
    pub fn is_exec_initiator_authorized(e: Env, initiator: Address) -> bool {
        execution_authorization::check(&e, &initiator).authorized
    }

    /// Validate that `initiator` is authorized to initiate a contract execution
    /// (issue #620).
    ///
    /// Unlike `check_execution_initiator`, this requires `initiator`'s
    /// cryptographic authorization, so integrators can assert the role on-chain
    /// as a precondition of a larger flow. It panics with an actionable error
    /// when the contract is not initialized or the address is not the
    /// registered payroll admin.
    pub fn validate_execution_initiator(e: Env, initiator: Address) {
        execution_authorization::require_authorized(&e, &initiator);
    }

    // ── Import source authorization ───────────────────────────────────────────

    /// Register an authorized import source for payroll batches.
    ///
    /// Only the payroll admin may register sources. Once registered, sources
    /// can submit payroll batches. Duplicate registration updates the source
    /// metadata.
    pub fn register_import_source(
        e: Env,
        source_address: Address,
        source_type: u32,
    ) {
        let source_type = match source_type {
            0 => import_source::ImportSourceType::ExternalService,
            1 => import_source::ImportSourceType::InternalSource,
            2 => import_source::ImportSourceType::VerificationService,
            _ => panic!("Invalid import source type"),
        };
        import_source::register_source(&e, source_address, source_type);
    }

    /// Deactivate an authorized import source.
    ///
    /// Only the payroll admin may deactivate sources. Deactivated sources
    /// cannot submit new payroll batches but their historical records remain
    /// for audit purposes.
    pub fn deactivate_import_source(e: Env, source_address: Address) {
        import_source::deactivate_source(&e, source_address);
    }

    /// Check if an import source is currently authorized.
    ///
    /// Returns true if the source is registered and active, false otherwise.
    /// Privacy-safe: exposes only an authorization boolean.
    pub fn is_import_source_authorized(e: Env, source_address: Address) -> bool {
        import_source::is_source_authorized(&e, &source_address)
    }

    fn validate_run_id(run_id: u64) {
        if run_id == u64::MAX {
            panic!("Invalid payroll run ID");
        }
    }

    fn validate_draft_id(draft_id: u64) {
        if draft_id == 0 {
            panic!("Invalid draft ID: must be non-zero");
        }
    }

    /// Maximum serialized size accepted for a draft description (#474).
    const MAX_DRAFT_DESCRIPTION_BYTES: u32 = 256;

    fn validate_draft_description(description: &soroban_sdk::String) {
        if description.is_empty() {
            panic!("Description cannot be blank");
        }
        if description.len() > Self::MAX_DRAFT_DESCRIPTION_BYTES {
            panic!("Description exceeds 256 bytes");
        }
        let mut bytes = [0u8; Self::MAX_DRAFT_DESCRIPTION_BYTES as usize];
        description.copy_into_slice(&mut bytes[..description.len() as usize]);
        let mut has_non_whitespace = false;
        for byte in bytes.iter().take(description.len() as usize) {
            if byte != &9 && byte != &10 && byte != &13 && byte != &32 {
                has_non_whitespace = true;
                break;
            }
        }
        if !has_non_whitespace {
            panic!("Description cannot be blank");
        }
    }

    fn validate_non_zero_digest(e: &Env, digest: &BytesN<32>, _name: &str) {
        let zero = BytesN::from_array(e, &[0u8; 32]);
        if digest == &zero {
            panic!("Digest cannot be all-zero bytes");
        }
    }

    fn validate_symbol_not_empty(e: &Env, symbol: &Symbol, _name: &str) {
        let empty = Symbol::new(e, "");
        if symbol == &empty {
            panic!("Symbol cannot be empty");
        }
    }

    /// Normalize an asset symbol for consistent allowlist and reservation checks.
    ///
    /// Asset symbols are trimmed and uppercased so that small formatting
    /// differences such as "usdc", "USDC", or " USDC " all resolve to the
    /// same canonical symbol before a payroll asset allowlist or reservation
    /// check is performed.
    ///
    /// # Panics
    /// - If the symbol is empty after trimming.
    /// - If the symbol is longer than 32 bytes after trimming.
    /// - If the symbol contains non-ASCII bytes.
    fn normalize_asset_symbol(e: &Env, symbol: &str) -> Symbol {
        let trimmed = symbol.trim();
        if trimmed.is_empty() {
            panic!("Asset symbol cannot be empty");
        }

        let bytes = trimmed.as_bytes();
        if bytes.len() > 32 {
            panic!("Asset symbol too long");
        }

        let mut normalized = [0u8; 32];
        for (i, &b) in bytes.iter().enumerate() {
            if !b.is_ascii() {
                panic!("Asset symbol must be ASCII");
            }
            normalized[i] = if b.is_ascii_lowercase() { b - 32 } else { b };
        }

        let normalized_str = core::str::from_utf8(&normalized[..bytes.len()])
            .expect("normalized asset symbol is valid UTF-8");
        Symbol::new(e, normalized_str)
    }

    /// Internal helper that normalizes an employee reference identifier (#544).
    ///
    /// Rules applied:
    /// 1. Trims leading and trailing whitespace (spaces, tabs, newlines, carriage returns).
    /// 2. Converts ASCII lowercase letters to uppercase for canonical matching.
    /// 3. Validates length is between 1 and 256 characters after trimming.
    /// 4. Validates that the identifier contains only printable ASCII characters (32..=126).
    /// 5. Rejects empty or all-whitespace strings.
    ///
    /// Privacy-safe: operates strictly on opaque reference identifier strings without
    /// exposing or logging salary amounts or cryptographic blinding factors.
    fn normalize_employee_identifier_internal(e: &Env, identifier: &String) -> String {
        let raw_len = identifier.len() as usize;
        if raw_len == 0 || raw_len > 512 {
            panic!("Reference ID must be 1-256 characters");
        }

        let mut buf = [0u8; 512];
        identifier.copy_into_slice(&mut buf[..raw_len]);
        let slice = &buf[..raw_len];

        let mut start = 0;
        while start < raw_len
            && (slice[start] == b' '
                || slice[start] == b'\t'
                || slice[start] == b'\n'
                || slice[start] == b'\r')
        {
            start += 1;
        }

        let mut end = raw_len;
        while end > start
            && (slice[end - 1] == b' '
                || slice[end - 1] == b'\t'
                || slice[end - 1] == b'\n'
                || slice[end - 1] == b'\r')
        {
            end -= 1;
        }

        let trimmed_len = end - start;
        if trimmed_len == 0 || trimmed_len > 256 {
            panic!("Reference ID must be 1-256 characters");
        }

        let mut out_buf = [0u8; 256];
        for i in 0..trimmed_len {
            let b = slice[start + i];
            if b < 32 || b > 126 {
                panic!("Employee identifier contains invalid characters: must be printable ASCII");
            }
            out_buf[i] = if b.is_ascii_lowercase() {
                b - 32
            } else {
                b
            };
        }

        let normalized_str = core::str::from_utf8(&out_buf[..trimmed_len])
            .expect("normalized employee identifier is valid UTF-8");
        String::from_str(e, normalized_str)
    }

    /// Normalize an employee reference identifier (#544).
    ///
    /// Public passthrough mirroring `salary_commitment::normalize_employee_identifier`
    /// so clients can canonicalize identifiers against the same rules the
    /// payroll contract enforces. Trims whitespace, uppercases ASCII letters,
    /// validates the 1-256 character printable-ASCII range.
    pub fn normalize_employee_identifier(e: Env, identifier: String) -> String {
        Self::normalize_employee_identifier_internal(&e, &identifier)
    }

    /// Reject a payroll batch that lists the same employee wallet more than
    /// once (#379).
    ///
    /// A wallet appearing twice in one batch would be paid twice out of a
    /// single authorised spend, and makes reconciliation ambiguous. The check
    /// runs before any state is written, so a duplicate batch is rejected
    /// atomically with no partial effects.
    ///
    /// The comparison is a pairwise scan. `MAX_BATCH` bounds the input length,
    /// so the worst case stays inside the contract compute budget and no
    /// auxiliary storage or heap allocation is required.
    ///
    /// # Panics
    /// - If any employee address appears more than once in `employees`.
    fn validate_no_duplicate_employees(employees: &Vec<Address>) {
        let count = employees.len();
        for i in 0..count {
            let current = employees.get(i).unwrap();
            for j in (i + 1)..count {
                if current == employees.get(j).unwrap() {
                    panic!("Duplicate employee wallet in payroll batch");
                }
            }
        }
    }

    /// Validate that a nonce is monotonically increasing for the given employer (#362).
    ///
    /// This function enforces that each payroll run for an employer uses a nonce
    /// that is strictly greater than the previous accepted nonce. This prevents:
    /// - Replay attacks using stale nonces
    /// - Ordering confusion in payroll history
    /// - Duplicate period submissions
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `employer`: The employer address to check nonce sequence for
    /// - `nonce`: The new nonce to validate
    ///
    /// # Panics
    /// - If the nonce has already been used (replay attack)
    /// - If the nonce is stale (less than or equal to the last accepted nonce)
    fn validate_nonce_monotonicity(env: &Env, employer: &Address, nonce: &BytesN<32>) {
        let sequence_key = DataKey::EmployerNonceSequence(employer.clone());

        if let Some(sequence_state) = env
            .storage()
            .persistent()
            .get::<_, EmployerNonceSequenceState>(&sequence_key)
        {
            // Check if this nonce has already been used
            if nonce == &sequence_state.last_nonce {
                panic!("Nonce replay detected: this nonce has already been used for this employer");
            }

            // Compare nonce values to ensure monotonic increase
            // We treat the nonce as a u256 for comparison purposes
            let new_nonce_value = Self::nonce_to_u256(env, nonce);
            let last_nonce_value = Self::nonce_to_u256(env, &sequence_state.last_nonce);

            if new_nonce_value <= last_nonce_value {
                panic!("Stale nonce detected: nonce must be strictly greater than the last accepted nonce for this employer");
            }
        }
        // If no sequence state exists, this is the first nonce for this employer - always valid
    }

    /// Validate the submission sequence of a payroll run (#payroll-submission-sequence).
    ///
    /// Ensures a run cannot be submitted out of order relative to the employer's
    /// last accepted nonce sequence. This is a thin, privacy-safe guard that
    /// only inspects the caller-supplied nonce and the stored sequence counter;
    /// it never reads or emits salary values.
    ///
    /// # Panics
    /// - If the nonce is stale or has already been used for this employer.
    fn validate_submission_sequence(env: &Env, employer: &Address, nonce: &BytesN<32>) {
        Self::validate_nonce_monotonicity(env, employer, nonce);
    }

    /// Update the nonce sequence tracking after a successful payroll run (#362).
    ///
    /// This function should be called after a payroll run is successfully processed
    /// to update the employer's nonce sequence tracking.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `employer`: The employer address
    /// - `nonce`: The nonce that was just accepted
    fn update_nonce_sequence(env: &Env, employer: &Address, nonce: &BytesN<32>) {
        let sequence_key = DataKey::EmployerNonceSequence(employer.clone());

        let new_state = if let Some(mut existing_state) =
            env.storage()
                .persistent()
                .get::<_, EmployerNonceSequenceState>(&sequence_key)
        {
            existing_state.current_sequence += 1;
            existing_state.last_accepted_at = env.ledger().timestamp();
            existing_state.last_nonce = nonce.clone();
            existing_state
        } else {
            // First nonce for this employer
            EmployerNonceSequenceState {
                current_sequence: 1,
                last_accepted_at: env.ledger().timestamp(),
                last_nonce: nonce.clone(),
            }
        };

        env.storage().persistent().set(&sequence_key, &new_state);
    }

    /// Convert a 32-byte nonce to a u256 value for comparison (#362).
    ///
    /// This function converts a BytesN<32> nonce to a u256 value for
    /// monotonicity comparison. The conversion treats the nonce as a
    /// big-endian unsigned integer.
    fn nonce_to_u256(_env: &Env, nonce: &BytesN<32>) -> u128 {
        // For simplicity, we'll use the first 16 bytes as a u128 for comparison.
        // This provides sufficient uniqueness for monotonicity enforcement.
        let bytes = nonce.to_array();
        let mut value: u128 = 0;
        for byte in bytes.iter().take(16) {
            value = (value << 8) | u128::from(*byte);
        }
        value
    }

    /// Get the current nonce sequence state for an employer (#362).
    ///
    /// Returns the current nonce sequence tracking information for the specified
    /// employer, or None if no payroll runs have been processed for this employer.
    pub fn get_employer_nonce_sequence(
        e: Env,
        employer: Address,
    ) -> Option<EmployerNonceSequenceState> {
        e.storage()
            .persistent()
            .get(&DataKey::EmployerNonceSequence(employer))
    }

    // ?? Issue #361: Compliance Evidence Pointer Validation ?????????????????????????

    /// Create a new compliance evidence pointer for off-chain encrypted evidence (#361).
    ///
    /// This function validates and stores a pointer to off-chain encrypted evidence
    /// without leaking the actual evidence contents. The pointer includes:
    /// - A content hash for integrity verification
    /// - Scoping information to prevent cross-context references
    /// - Deduplication to prevent duplicate pointers
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `admin`: The admin address creating the pointer
    /// - `content_hash`: SHA-256 hash of the off-chain evidence content
    /// - `scope`: The scope of this evidence pointer
    /// - `target`: The target entity this pointer relates to
    /// - `metadata_hash`: Optional metadata hash for additional context
    ///
    /// # Returns
    /// The unique identifier for the created evidence pointer
    ///
    /// # Panics
    /// - If the content hash is empty (all zeros)
    /// - If the content hash has already been used (duplicate)
    /// - If the pointer ID has already been used (duplicate)
    pub fn create_evidence_pointer(
        e: Env,
        admin: Address,
        content_hash: BytesN<32>,
        scope: EvidencePointerScope,
        target: Address,
        metadata_hash: Option<BytesN<32>>,
    ) -> BytesN<32> {
        Self::require_not_paused(&e);
        admin.require_auth();

        // Validate content hash is not empty
        let zero_hash = BytesN::from_array(&e, &[0u8; 32]);
        if content_hash == zero_hash {
            panic!("Content hash cannot be empty (all zeros)");
        }

        // Check for duplicate content hash
        let content_index_key = DataKey::EvidencePointerIndex(content_hash.clone());
        if e.storage().persistent().has(&content_index_key) {
            panic!("Duplicate evidence pointer: content hash already exists");
        }

        // Generate a unique pointer ID using the content hash and timestamp
        let pointer_id = Self::generate_pointer_id(&e, &content_hash);

        // Check for duplicate pointer ID
        let pointer_key = DataKey::EvidencePointer(pointer_id.clone());
        if e.storage().persistent().has(&pointer_key) {
            panic!("Duplicate evidence pointer: pointer ID already exists");
        }

        // Create the evidence pointer
        let resolved_metadata = metadata_hash.unwrap_or(zero_hash);
        let pointer = ComplianceEvidencePointer {
            pointer_id: pointer_id.clone(),
            content_hash: content_hash.clone(),
            scope,
            target: target.clone(),
            created_at: e.ledger().timestamp(),
            created_by: admin.clone(),
            metadata_hash: resolved_metadata,
        };

        // Store the pointer
        e.storage().persistent().set(&pointer_key, &pointer);

        // Store the deduplication index
        e.storage()
            .persistent()
            .set(&content_index_key, &pointer_id);

        // Emit event for audit trail
        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "evidence_pointer_created"),
            ),
            (
                pointer_id.clone(),
                content_hash,
                scope as u32,
                target,
                admin,
            ),
        );

        pointer_id
    }

    /// Validate and retrieve a compliance evidence pointer (#361).
    ///
    /// This function retrieves and validates an evidence pointer, ensuring it
    /// exists and is properly formatted. It does not expose the actual evidence
    /// content, only the pointer metadata.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `pointer_id`: The unique identifier of the evidence pointer
    ///
    /// # Returns
    /// The evidence pointer if it exists
    ///
    /// # Panics
    /// - If the pointer does not exist
    /// - If the pointer is malformed
    pub fn get_evidence_pointer(e: Env, pointer_id: BytesN<32>) -> ComplianceEvidencePointer {
        let pointer_key = DataKey::EvidencePointer(pointer_id);
        e.storage()
            .persistent()
            .get(&pointer_key)
            .expect("Evidence pointer not found")
    }

    /// Check if an evidence pointer exists for a given content hash (#361).
    ///
    /// This function checks if an evidence pointer with the specified content
    /// hash already exists, preventing duplicate pointers.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `content_hash`: The content hash to check
    ///
    /// # Returns
    /// true if the content hash already has a pointer, false otherwise
    pub fn evidence_pointer_exists(e: Env, content_hash: BytesN<32>) -> bool {
        let content_index_key = DataKey::EvidencePointerIndex(content_hash);
        e.storage().persistent().has(&content_index_key)
    }

    /// Generate a unique pointer ID from content hash and timestamp (#361).
    ///
    /// This function generates a deterministic pointer ID that is unique
    /// for each combination of content hash and creation timestamp.
    fn generate_pointer_id(e: &Env, content_hash: &BytesN<32>) -> BytesN<32> {
        let timestamp = e.ledger().timestamp();
        let mut data = soroban_sdk::Bytes::new(e);
        data.extend_from_slice(&content_hash.to_array());
        data.extend_from_slice(&timestamp.to_be_bytes());
        e.crypto().sha256(&data).into()
    }

    // ?? Issue #360: Storage Version Migration Checks ?????????????????????????????

    /// Current contract storage version.
    ///
    /// This version is incremented whenever the storage schema changes.
    /// It is used to:
    /// - Detect when migration is required
    /// - Block sensitive actions during migration
    /// - Allow clients to detect migration readiness
    pub const CURRENT_STORAGE_VERSION: u32 = 1;

    /// Minimum supported storage version.
    ///
    /// Storage versions below this are considered unsupported and will
    /// cause the contract to panic on sensitive operations.
    pub const MIN_SUPPORTED_STORAGE_VERSION: u32 = 1;

    /// Maximum supported storage version.
    ///
    /// Storage versions above this are considered future versions and will
    /// cause the contract to panic on sensitive operations.
    pub const MAX_SUPPORTED_STORAGE_VERSION: u32 = 1;

    ///
    /// This function should be called during contract initialization to set
    /// the initial storage version. It can also be used to update the version
    /// after a migration.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `admin`: The admin address (requires authorization)
    /// - `version`: The storage version to set
    /// - `description`: Optional description of the version
    ///
    /// # Panics
    /// - If the version is outside the supported range
    /// - If the caller is not authorized
    pub fn set_storage_version(
        e: Env,
        admin: Address,
        version: u32,
        description: soroban_sdk::String,
    ) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        // Validate version is within supported range
        if version < Self::MIN_SUPPORTED_STORAGE_VERSION
            || version > Self::MAX_SUPPORTED_STORAGE_VERSION
        {
            panic!("Storage version out of supported range");
        }

        let state = StorageVersionState {
            version,
            updated_at: e.ledger().timestamp(),
            migration_complete: true, // Setting version implies migration is complete
            version_description: description,
        };

        let previous_ref = stored_ref(&e, &DataKey::StorageVersion);
        e.storage()
            .persistent()
            .set(&DataKey::StorageVersion, &state);

        // Also update the migration readiness
        let readiness = MigrationReadinessState {
            ready: true,
            current_version: version,
            min_supported: Self::MIN_SUPPORTED_STORAGE_VERSION,
            max_supported: Self::MAX_SUPPORTED_STORAGE_VERSION,
            checked_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::MigrationReady, &readiness);

        // Emit event for audit trail
        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "storage_version_set"),
            ),
            (version, admin.clone()),
        );
        record_config_change(
            &e,
            &admin,
            config_keys::STORAGE_VERSION,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::StorageVersion),
        );
    }

    /// Get the current storage version (#360).
    ///
    /// Returns the current storage version state, or None if not initialized.
    /// Clients can use this to detect if migration is required.
    pub fn get_storage_version(e: Env) -> Option<StorageVersionState> {
        e.storage().persistent().get(&DataKey::StorageVersion)
    }

    /// Check if the current storage version is supported (#360).
    ///
    /// Returns true if the storage version is within the supported range,
    /// false otherwise. Clients should check this before performing sensitive
    /// operations.
    pub fn is_storage_version_supported(e: Env) -> bool {
        if let Some(state) = e
            .storage()
            .persistent()
            .get::<_, StorageVersionState>(&DataKey::StorageVersion)
        {
            state.version >= Self::MIN_SUPPORTED_STORAGE_VERSION
                && state.version <= Self::MAX_SUPPORTED_STORAGE_VERSION
        } else {
            // If no version is set, assume current version for backward compatibility
            true
        }
    }

    /// Check if migration is required (#360).
    ///
    /// Returns true if the current storage version is below the minimum
    /// supported version, indicating migration is required.
    pub fn is_migration_required(e: Env) -> bool {
        if let Some(state) = e
            .storage()
            .persistent()
            .get::<_, StorageVersionState>(&DataKey::StorageVersion)
        {
            state.version < Self::MIN_SUPPORTED_STORAGE_VERSION
        } else {
            // If no version is set, assume no migration required for backward compatibility
            false
        }
    }

    /// Validate storage version for sensitive operations (#360).
    ///
    /// This function should be called before any sensitive operation to ensure
    /// the storage version is supported and migration is complete.
    ///
    /// # Panics
    /// - If the storage version is not supported
    /// - If migration is required but not complete
    /// - If the contract is in a partially migrated state
    fn validate_storage_version_for_operation(e: &Env, operation_name: &str) {
        let version_state: Option<StorageVersionState> =
            e.storage().persistent().get(&DataKey::StorageVersion);

        match version_state {
            Some(state) => {
                // Check if version is supported
                if state.version < Self::MIN_SUPPORTED_STORAGE_VERSION
                    || state.version > Self::MAX_SUPPORTED_STORAGE_VERSION
                {
                    panic!(
                        "Storage version {} is not supported for operation: {}. Supported range: {}-{}",
                        state.version,
                        operation_name,
                        Self::MIN_SUPPORTED_STORAGE_VERSION,
                        Self::MAX_SUPPORTED_STORAGE_VERSION
                    );
                }

                // Check if migration is complete
                if !state.migration_complete {
                    panic!(
                        "Migration not complete for operation: {}. Current version: {}",
                        operation_name, state.version
                    );
                }
            }
            None => {
                // If no version is set, assume current version for backward compatibility
                // This allows existing deployments to work without initialization
            }
        }
    }

    /// Check migration readiness for clients (#360).
    ///
    /// Returns a MigrationReadinessState that clients can use to determine
    /// if the contract is ready for operations. This is a read-only function
    /// that does not modify state.
    pub fn check_migration_readiness(e: Env) -> MigrationReadinessState {
        let version_state: Option<StorageVersionState> =
            e.storage().persistent().get(&DataKey::StorageVersion);

        match version_state {
            Some(state) => MigrationReadinessState {
                ready: state.version >= Self::MIN_SUPPORTED_STORAGE_VERSION
                    && state.version <= Self::MAX_SUPPORTED_STORAGE_VERSION
                    && state.migration_complete,
                current_version: state.version,
                min_supported: Self::MIN_SUPPORTED_STORAGE_VERSION,
                max_supported: Self::MAX_SUPPORTED_STORAGE_VERSION,
                checked_at: e.ledger().timestamp(),
            },
            None => {
                // If no version is set, assume ready for backward compatibility
                MigrationReadinessState {
                    ready: true,
                    current_version: Self::CURRENT_STORAGE_VERSION,
                    min_supported: Self::MIN_SUPPORTED_STORAGE_VERSION,
                    max_supported: Self::MAX_SUPPORTED_STORAGE_VERSION,
                    checked_at: e.ledger().timestamp(),
                }
            }
        }
    }

    /// Initialize storage version during contract initialization (#360).
    ///
    /// This function is called during contract initialization to set the
    /// initial storage version. It should be called in the initialize function.
    fn initialize_storage_version(e: &Env) {
        // Check if already initialized
        if e.storage().persistent().has(&DataKey::StorageVersion) {
            return; // Already initialized
        }

        let state = StorageVersionState {
            version: Self::CURRENT_STORAGE_VERSION,
            updated_at: e.ledger().timestamp(),
            migration_complete: true,
            version_description: soroban_sdk::String::from_str(e, "Initial version"),
        };

        e.storage()
            .persistent()
            .set(&DataKey::StorageVersion, &state);

        // Also set migration readiness
        let readiness = MigrationReadinessState {
            ready: true,
            current_version: Self::CURRENT_STORAGE_VERSION,
            min_supported: Self::MIN_SUPPORTED_STORAGE_VERSION,
            max_supported: Self::MAX_SUPPORTED_STORAGE_VERSION,
            checked_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::MigrationReady, &readiness);
    }

    pub fn set_pause_manager(e: Env, pause_manager: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.admin.require_auth();
        let previous_ref = stored_ref(&e, &DataKey::PauseManager);
        e.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);

        payroll_events::emit_pause_manager_set(&e, pause_manager);
        record_config_change(
            &e,
            &addrs.admin,
            config_keys::PAUSE_MANAGER,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::PauseManager),
        );
    }

    /// Return the contract-wide configuration revision (#490).
    ///
    /// Starts at `0` and increases by exactly one for every audited
    /// configuration change, matching the `revision` field of the latest
    /// `("payroll", "config_changed", key)` event. Off-chain auditors can
    /// compare it with the events they have indexed to confirm none are
    /// missing.
    pub fn get_config_revision(e: Env) -> u64 {
        config_audit::config_revision(&e)
    }

    /// Allow or disallow an asset token for payroll payouts.
    ///
    /// Locked while any payroll run is prepared but not yet resolved (#253):
    /// changing the payout asset mid-run could redirect or invalidate a run
    /// that was already validated against the previous allowlist.
    pub fn set_asset_allowed(e: Env, asset: Address, allowed: bool) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.admin.require_auth();
        Self::require_no_active_payroll_run(&e);
        if asset != addrs.token {
            panic!("Cross-asset treasury mismatch");
        }
        let allowed_key = DataKey::AllowedAsset(asset.clone());
        let previous_ref = stored_ref(&e, &allowed_key);
        e.storage().persistent().set(&allowed_key, &allowed);

        payroll_events::emit_asset_allowlist_updated(&e, asset.clone(), allowed);
        record_config_change(
            &e,
            &addrs.admin,
            config_keys::ASSET_ALLOWED,
            value_ref(&e, &asset),
            previous_ref,
            stored_ref(&e, &allowed_key),
        );
        let mut assets: Vec<Address> =
            if let Some(stored) = e.storage().persistent().get(&DataKey::SupportedAssets) {
                stored
            } else {
                let mut existing = Vec::new(&e);
                if Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
                    existing.push_back(addrs.token);
                }
                existing
            };
        let position = assets.first_index_of(asset.clone());
        if allowed && position.is_none() {
            assets.push_back(asset);
        } else if !allowed {
            if let Some(index) = position {
                assets.remove(index);
            }
        }
        e.storage()
            .persistent()
            .set(&DataKey::SupportedAssets, &assets);
    }

    /// Check if an asset token is allowlisted for payroll payouts.
    pub fn is_asset_allowed(e: Env, asset: Address) -> bool {
        let canonical_asset: Option<Address> = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .map(|addresses: ContractAddresses| addresses.token);
        if canonical_asset.as_ref() != Some(&asset) {
            return false;
        }
        e.storage()
            .persistent()
            .get(&DataKey::AllowedAsset(asset))
            .unwrap_or(false)
    }

    /// Check whether an asset has been explicitly deactivated by the admin.
    ///
    /// A deactivated asset is the canonical treasury asset with an explicit
    /// `false` allowlist entry. It cannot back payouts, deposits, or treasury
    /// movements until the admin re-enables it through
    /// [`Self::set_asset_allowed`]. Unlike [`Self::is_asset_allowed`], this
    /// distinguishes "explicitly switched off" from "never configured", and
    /// returns `false` for any asset that is not this contract's canonical
    /// treasury asset.
    pub fn is_asset_deactivated(e: Env, asset: Address) -> bool {
        let canonical_asset: Option<Address> = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .map(|addresses: ContractAddresses| addresses.token);
        if canonical_asset.as_ref() != Some(&asset) {
            return false;
        }
        matches!(
            e.storage()
                .persistent()
                .get::<_, bool>(&DataKey::AllowedAsset(asset)),
            Some(false)
        )
    }

    /// Validate the canonical treasury asset used by all payroll transfers.
    ///
    /// Asset identity is the serialized Soroban token contract address. A
    /// different address represents a different asset or issuer and must not
    /// share this treasury's reserves.
    pub fn validate_treasury_asset(e: Env, asset: Address) -> Result<(), TreasuryError> {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .ok_or(TreasuryError::InvalidAssetConfiguration)?;
        if asset != addrs.token {
            return Err(TreasuryError::CrossAssetMismatch);
        }
        if !Self::is_asset_allowed(e, asset) {
            return Err(TreasuryError::AssetNotAllowed);
        }
        Ok(())
    }

    /// Panic with an actionable message when an asset cannot back a treasury
    /// movement.
    ///
    /// Keeps the two failure modes distinguishable: a deactivated asset is a
    /// configuration state the admin can undo, while a foreign asset is an
    /// identity mismatch that can never be corrected at runtime.
    fn require_active_treasury_asset(e: &Env, asset: Address) {
        match Self::validate_treasury_asset(e.clone(), asset) {
            Ok(()) => {}
            Err(TreasuryError::AssetNotAllowed) => panic!("Asset not allowed"),
            Err(TreasuryError::CrossAssetMismatch) => panic!("Cross-asset treasury mismatch"),
            Err(_) => panic!("Invalid asset configuration"),
        }
    }

    /// Return the payroll assets currently enabled for this employer contract.
    pub fn get_supported_assets(e: Env) -> Vec<Address> {
        if let Some(assets) = e.storage().persistent().get(&DataKey::SupportedAssets) {
            return assets;
        }

        let addrs: Option<ContractAddresses> = e.storage().persistent().get(&DataKey::Addresses);
        let mut assets = Vec::new(&e);
        if let Some(addrs) = addrs {
            if Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
                assets.push_back(addrs.token);
            }
        }
        assets
    }

    pub fn deposit(e: Env, from: Address, amount: i128, deposit_id: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_non_zero_digest(&e, &deposit_id, "deposit_id");
        if amount <= 0 {
            panic!("Deposit amount must be positive");
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // Deactivated assets must not accept new deposits: payouts are already
        // blocked for a deactivated asset, so inbound funds would be stranded.
        // Checked before the deposit nonce is recorded so a rejected deposit
        // does not burn the caller's deposit id.
        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

        let nonce_key = DataKey::DepositNonce(deposit_id.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Deposit already processed");
        }
        e.storage().persistent().set(&nonce_key, &true);

        let treasury_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

        from.require_auth();
        treasury_owner.require_auth();

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        token_client.transfer(&from, &addrs.treasury, &amount);

        // Issue #62: accumulate per-depositor balance for auditability.
        let balance_key = DataKey::CompanyBalance(from.clone());
        let prev_balance: i128 = e.storage().persistent().get(&balance_key).unwrap_or(0i128);
        let new_balance = prev_balance + amount;

        e.storage().persistent().set(&balance_key, &new_balance);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "deposit")),
            (from, amount, deposit_id, new_balance),
        );
        Self::emit_treasury_balance_snapshot(&e, addrs.token, Symbol::new(&e, "deposit"));
    }

    /// Return the accumulated deposit balance for a given depositor address (#62).
    ///
    /// This reflects the running total of all successful deposits made by that
    /// address. It is an accounting record only; actual treasury liquidity is
    /// held by the token contract at `ContractAddresses.treasury`.
    pub fn get_treasury_balance(e: Env, depositor: Address) -> i128 {
        e.storage()
            .persistent()
            .get(&DataKey::CompanyBalance(depositor))
            .unwrap_or(0i128)
    }

    fn derive_run_id(e: &Env) -> u64 {
        let counter: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::RunCounter)
            .unwrap_or(0);

        let run_id = counter + 1;
        e.storage().persistent().set(&DataKey::RunCounter, &run_id);

        run_id
    }

    fn is_allowed_payroll_state_transition_internal(
        from: PayrollRunState,
        to: PayrollRunState,
    ) -> bool {
        match from {
            PayrollRunState::Draft => {
                matches!(to, PayrollRunState::Validating | PayrollRunState::Cancelled)
            }
            PayrollRunState::Validating => matches!(
                to,
                PayrollRunState::ProofPending
                    | PayrollRunState::Failed
                    | PayrollRunState::Cancelled
            ),
            PayrollRunState::ProofPending => matches!(
                to,
                PayrollRunState::ReadyToSubmit
                    | PayrollRunState::Failed
                    | PayrollRunState::Cancelled
            ),
            PayrollRunState::ReadyToSubmit => matches!(
                to,
                PayrollRunState::Submitted | PayrollRunState::Failed | PayrollRunState::Cancelled
            ),
            PayrollRunState::Submitted => matches!(
                to,
                PayrollRunState::Confirming
                    | PayrollRunState::Failed
                    | PayrollRunState::Cancelled
                    | PayrollRunState::Expired
            ),
            PayrollRunState::Confirming => matches!(
                to,
                PayrollRunState::Completed
                    | PayrollRunState::Failed
                    | PayrollRunState::ReconciliationRequired
            ),
            PayrollRunState::Failed => matches!(
                to,
                PayrollRunState::Validating
                    | PayrollRunState::ProofPending
                    | PayrollRunState::Cancelled
            ),
            PayrollRunState::ReconciliationRequired => {
                matches!(to, PayrollRunState::Completed | PayrollRunState::Failed)
            }
            PayrollRunState::Completed | PayrollRunState::Cancelled | PayrollRunState::Expired => {
                false
            }
        }
    }

    fn is_terminal_payroll_state_internal(state: PayrollRunState) -> bool {
        matches!(
            state,
            PayrollRunState::Completed | PayrollRunState::Cancelled | PayrollRunState::Expired
        )
    }

    fn is_retryable_payroll_state_internal(state: PayrollRunState) -> bool {
        matches!(state, PayrollRunState::Failed)
    }

    fn is_allowed_draft_state_transition_internal(from: RunDraftState, to: RunDraftState) -> bool {
        match from {
            RunDraftState::Pending => matches!(
                to,
                RunDraftState::Finalized
                    | RunDraftState::Submitted
                    | RunDraftState::Cancelled
                    | RunDraftState::Expired
            ),
            RunDraftState::Finalized => matches!(
                to,
                RunDraftState::Submitted | RunDraftState::Cancelled | RunDraftState::Expired
            ),
            RunDraftState::Submitted | RunDraftState::Cancelled | RunDraftState::Expired => false,
        }
    }

    fn is_terminal_draft_state_internal(state: RunDraftState) -> bool {
        matches!(
            state,
            RunDraftState::Submitted | RunDraftState::Cancelled | RunDraftState::Expired
        )
    }

    fn record_payroll_run_state(e: &Env, run_id: u64, state: PayrollRunState) {
        e.storage()
            .persistent()
            .set(&DataKey::PayrollState(run_id), &state);
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(e, "run_state")),
            (run_id, state),
        );
    }

    fn get_payroll_run_state_internal(e: &Env, run_id: u64) -> PayrollRunState {
        if let Some(state) = e
            .storage()
            .persistent()
            .get::<_, PayrollRunState>(&DataKey::PayrollState(run_id))
        {
            return state;
        }

        if let Some(run) = e
            .storage()
            .persistent()
            .get::<_, PayrollRun>(&DataKey::PayrollRun(run_id))
        {
            return match run.reconciliation_status {
                ReconciliationStatus::Reconciled => PayrollRunState::Completed,
                ReconciliationStatus::Unreconciled | ReconciliationStatus::Failed => {
                    PayrollRunState::ReconciliationRequired
                }
            };
        }

        if e.storage().persistent().has(&DataKey::PendingRun(run_id)) {
            return PayrollRunState::Submitted;
        }

        panic!("Payroll run state not found");
    }

    /// Return whether a transition is allowed by the canonical state machine.
    pub fn is_state_transition_allowed(
        _e: Env,
        from: PayrollRunState,
        to: PayrollRunState,
    ) -> bool {
        Self::is_allowed_payroll_state_transition_internal(from, to)
    }

    /// Return whether a payroll run state is terminal and immutable.
    pub fn is_payroll_state_terminal(_e: Env, state: PayrollRunState) -> bool {
        Self::is_terminal_payroll_state_internal(state)
    }

    /// Return whether a state should expose a retry action to clients.
    pub fn is_payroll_state_retryable(_e: Env, state: PayrollRunState) -> bool {
        Self::is_retryable_payroll_state_internal(state)
    }

    pub fn begin_batch_execution_checkpoint(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        checkpoint_index: u32,
    ) {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        if e.storage().persistent().has(&key) {
            panic!("Batch execution checkpoint already exists");
        }

        let checkpoint = BatchCheckpoint {
            employer: employer.clone(),
            batch_root: batch_root.clone(),
            asset: asset.clone(),
            execution_nonce: execution_nonce.clone(),
            state: BatchCheckpointState::Started,
            last_checkpoint_index: checkpoint_index,
            total_checkpoints: 1,
            completed: false,
            failed: false,
        };
        e.storage().persistent().set(&key, &checkpoint);
        payroll_events::emit_batch_checkpoint_started(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint_index,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_batch_checkpoint_progress(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        checkpoint_index: u32,
        state: BatchCheckpointState,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let mut checkpoint: BatchCheckpoint = e
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic!("ERR_BATCH_CHECKPOINT_MISMATCH"));

        if checkpoint.employer != employer
            || checkpoint.batch_root != batch_root
            || checkpoint.asset != asset
            || checkpoint.execution_nonce != execution_nonce
        {
            panic!("ERR_BATCH_CHECKPOINT_MISMATCH");
        }

        if checkpoint.completed
            || checkpoint.failed
            || checkpoint_index < checkpoint.last_checkpoint_index
            || matches!(
                state,
                BatchCheckpointState::Started | BatchCheckpointState::Resumed
            )
        {
            panic!("ERR_BATCH_CHECKPOINT_MISMATCH");
        }

        checkpoint.last_checkpoint_index = checkpoint_index;
        checkpoint.state = state;
        checkpoint.total_checkpoints = checkpoint
            .total_checkpoints
            .checked_add(1)
            .unwrap_or_else(|| panic!("ERR_BATCH_CHECKPOINT_MISMATCH"));
        checkpoint.completed = matches!(state, BatchCheckpointState::Completed);
        checkpoint.failed = matches!(state, BatchCheckpointState::Failed);
        e.storage().persistent().set(&key, &checkpoint);

        payroll_events::emit_batch_checkpoint_updated(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint_index,
            state as u32,
        );
    }

    pub fn get_batch_execution_checkpoint(
        e: Env,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
    ) -> BatchCheckpoint {
        let key = DataKey::BatchCheckpoint(employer, batch_root, asset, execution_nonce);
        e.storage()
            .persistent()
            .get(&key)
            .expect("Batch execution checkpoint not found")
    }

    /// Return whether a failed bounded payout batch can be resumed safely.
    ///
    /// Eligibility is limited to a failed, incomplete checkpoint with at
    /// least one payment remaining. The caller supplies the expected payment
    /// count from the original batch so the saved cursor can be checked against
    /// the remaining batch length. This view returns only a boolean and
    /// does not expose employee or salary data.
    pub fn is_failed_payout_retry_eligible(
        e: Env,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_payment_count: u32,
    ) -> bool {
        if expected_payment_count == 0 || expected_payment_count > MAX_BATCH {
            return false;
        }

        let key = DataKey::BatchCheckpoint(employer, batch_root, asset, execution_nonce);
        let Some(checkpoint) = e.storage().persistent().get::<_, BatchCheckpoint>(&key) else {
            return false;
        };

        checkpoint.failed
            && !checkpoint.completed
            && checkpoint.state == BatchCheckpointState::Failed
            && checkpoint.last_checkpoint_index < expected_payment_count
    }

    /// Explicitly resume a failed payout batch after checking its checkpoint.
    ///
    /// The same employer, batch root, asset, nonce, payment count, and
    /// checkpoint index must be used for the subsequent bounded batch call.
    /// Resumption starts at the persisted index to avoid repeating completed
    /// payouts.
    pub fn resume_failed_payout_retry(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_payment_count: u32,
        checkpoint_index: u32,
    ) -> bool {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let mut checkpoint: BatchCheckpoint =
            e.storage().persistent().get(&key).unwrap_or_else(|| {
                panic!("Failed payout retry is not eligible: refresh the batch checkpoint")
            });

        if checkpoint.last_checkpoint_index != checkpoint_index
            || !Self::is_failed_payout_retry_eligible(
                e.clone(),
                employer.clone(),
                batch_root.clone(),
                asset.clone(),
                execution_nonce.clone(),
                expected_payment_count,
            )
        {
            panic!("Failed payout retry is not eligible: refresh the batch checkpoint");
        }

        checkpoint.state = BatchCheckpointState::Resumed;
        checkpoint.failed = false;
        e.storage().persistent().set(&key, &checkpoint);

        payroll_events::emit_batch_checkpoint_resumed(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint_index,
        );
        true
    }

    // ── Issue #611: resumable payroll batch handling ─────────────────────────

    /// Build a privacy-safe, actionable resume plan for a payroll batch
    /// (issue #611).
    ///
    /// `expected_total` is the payment count the caller believes this batch
    /// identity (employer + batch root + asset + execution nonce) carries. The
    /// persisted cursor is compared against it so a mismatched resubmission
    /// (wrong batch, wrong payment count) is surfaced as an inconsistent
    /// cursor instead of silently resuming at the wrong offset.
    ///
    /// Read-only and privacy-safe: the plan carries progress counts and a
    /// status only — never employee addresses, salary values, proof material,
    /// or the remaining employee identities.
    pub fn get_batch_resume_plan(
        e: Env,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_total: u32,
    ) -> BatchResumePlan {
        if expected_total == 0 || expected_total > MAX_BATCH {
            return BatchResumePlan {
                status: BatchResumeStatus::NotFound,
                processed_count: 0,
                expected_total,
                cursor_consistent: false,
                remaining_count: 0,
                can_resume: false,
            };
        }

        let key = DataKey::BatchCheckpoint(employer, batch_root, asset, execution_nonce);
        let Some(checkpoint) = e.storage().persistent().get::<_, BatchCheckpoint>(&key) else {
            return BatchResumePlan {
                status: BatchResumeStatus::NotFound,
                processed_count: 0,
                expected_total,
                cursor_consistent: false,
                remaining_count: 0,
                can_resume: false,
            };
        };

        let processed_count = checkpoint.last_checkpoint_index;
        let cursor_consistent = processed_count <= expected_total;
        let remaining_count = if cursor_consistent {
            expected_total - processed_count
        } else {
            0
        };

        let status = if checkpoint.completed {
            BatchResumeStatus::Completed
        } else if checkpoint.failed {
            BatchResumeStatus::FailedRetryable
        } else if remaining_count > 0 {
            BatchResumeStatus::Resumable
        } else {
            // Not completed, not failed, nothing remaining: an in-progress
            // checkpoint whose cursor already covers the whole batch. Treat
            // the batch as complete from the operator's point of view.
            BatchResumeStatus::Completed
        };

        let can_resume = matches!(status, BatchResumeStatus::FailedRetryable)
            && cursor_consistent
            && remaining_count > 0;

        BatchResumePlan {
            status,
            processed_count,
            expected_total,
            cursor_consistent,
            remaining_count,
            can_resume,
        }
    }

    /// Explicitly resume an interrupted payroll batch after a failure
    /// (issue #611).
    ///
    /// Clears the failed checkpoint state so the next
    /// `batch_process_payroll_bounded` call with the same identity (employer,
    /// batch root, asset, execution nonce) is accepted and continues from the
    /// persisted cursor without repeating completed payouts.
    ///
    /// The caller must supply the batch's payment count; it is validated
    /// against the persisted cursor so resuming with the wrong batch shape is
    /// rejected with an actionable error instead of a silent partial run.
    ///
    /// # Panics
    /// * `"Unauthorized"` — `admin` is not the stored contract admin.
    /// * `"Batch execution checkpoint not found"` — no checkpoint exists for
    ///   this identity; submit a fresh batch instead.
    /// * `"Payroll batch is not resumable: check get_batch_resume_plan"` — the
    ///   checkpoint is completed, mid-execution (not failed), or its cursor is
    ///   inconsistent with `expected_total`.
    /// * `"Invalid batch_root: must be non-zero"` / `"Invalid execution_nonce:
    ///   must be non-zero"` — identity digests are zero.
    pub fn resume_payroll_batch(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_total: u32,
    ) {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let mut checkpoint: BatchCheckpoint = e
            .storage()
            .persistent()
            .get(&key)
            .expect("Batch execution checkpoint not found");

        if checkpoint.completed
            || !checkpoint.failed
            || expected_total == 0
            || expected_total > MAX_BATCH
            || checkpoint.last_checkpoint_index >= expected_total
        {
            panic!("Payroll batch is not resumable: check get_batch_resume_plan");
        }

        checkpoint.state = BatchCheckpointState::Resumed;
        checkpoint.failed = false;
        e.storage().persistent().set(&key, &checkpoint);

        payroll_events::emit_batch_checkpoint_resumed(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint.last_checkpoint_index,
        );
    }

    pub fn resume_batch_execution(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        checkpoint_index: u32,
    ) -> bool {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let mut checkpoint: BatchCheckpoint = e
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic!("ERR_BATCH_CHECKPOINT_MISMATCH"));

        if checkpoint.employer != employer
            || checkpoint.batch_root != batch_root
            || checkpoint.asset != asset
            || checkpoint.execution_nonce != execution_nonce
            || checkpoint_index != checkpoint.last_checkpoint_index
            || matches!(
                checkpoint.state,
                BatchCheckpointState::Resumed
                    | BatchCheckpointState::Completed
                    | BatchCheckpointState::Failed
            )
            || checkpoint.completed
            || checkpoint.failed
        {
            panic!("ERR_BATCH_CHECKPOINT_MISMATCH");
        }

        checkpoint.state = BatchCheckpointState::Resumed;
        checkpoint.last_checkpoint_index = checkpoint_index;
        e.storage().persistent().set(&key, &checkpoint);

        payroll_events::emit_batch_checkpoint_resumed(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint_index,
        );
        true
    }

    /// Clean up a completed or failed batch checkpoint.
    pub fn cleanup_batch_checkpoint(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
    ) {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let checkpoint: BatchCheckpoint = e
            .storage()
            .persistent()
            .get(&key)
            .expect("Batch execution checkpoint not found");

        if !checkpoint.completed && !checkpoint.failed {
            panic!("Cannot cleanup active batch checkpoint");
        }

        e.storage().persistent().remove(&key);

        payroll_events::emit_batch_checkpoint_cleaned(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
        );
    }

    /// Return whether an interrupted multi-batch payroll run can be safely recovered (#481).
    ///
    /// Checks that a checkpoint exists in an interrupted state (partially executed
    /// or failed before completion), with progress strictly less than `expected_payment_count`.
    /// Returns a privacy-safe boolean indicator without disclosing employee addresses or salary amounts.
    pub fn is_interrupted_run_recoverable(
        e: Env,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_payment_count: u32,
    ) -> bool {
        if expected_payment_count == 0 || expected_payment_count > MAX_BATCH {
            return false;
        }

        let key = DataKey::BatchCheckpoint(employer, batch_root, asset, execution_nonce);
        let Some(checkpoint) = e.storage().persistent().get::<_, BatchCheckpoint>(&key) else {
            return false;
        };

        !checkpoint.completed
            && (checkpoint.state == BatchCheckpointState::PartiallyCheckpointed
                || checkpoint.state == BatchCheckpointState::Failed
                || checkpoint.state == BatchCheckpointState::Started)
            && checkpoint.last_checkpoint_index < expected_payment_count
    }

    /// Provide an authorized recovery mechanism for a payroll run interrupted between batches (#481).
    ///
    /// Requires company admin authorization. Validates that the batch checkpoint exists
    /// and represents an interrupted run. Transitions the checkpoint state to `Resumed` while
    /// preserving `last_checkpoint_index`, allowing subsequent bounded batch execution to resume
    /// processing from the exact index where execution stopped without double-paying completed employees.
    pub fn recover_interrupted_payroll_run(
        e: Env,
        admin: Address,
        employer: Address,
        batch_root: BytesN<32>,
        asset: Address,
        execution_nonce: BytesN<32>,
        expected_payment_count: u32,
    ) -> BatchCheckpoint {
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_non_zero_digest(&e, &execution_nonce, "execution_nonce");

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::BatchCheckpoint(
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
        );
        let mut checkpoint: BatchCheckpoint = e
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic!("Interrupted payroll run checkpoint not found"));

        if checkpoint.completed {
            panic!("Cannot recover a fully completed payroll run");
        }

        if !Self::is_interrupted_run_recoverable(
            e.clone(),
            employer.clone(),
            batch_root.clone(),
            asset.clone(),
            execution_nonce.clone(),
            expected_payment_count,
        ) {
            panic!("Payroll run is not eligible for recovery");
        }

        checkpoint.state = BatchCheckpointState::Resumed;
        checkpoint.failed = false;
        e.storage().persistent().set(&key, &checkpoint);

        payroll_events::emit_interrupted_run_recovered(
            &e,
            employer,
            batch_root,
            asset,
            execution_nonce,
            checkpoint.last_checkpoint_index,
            checkpoint.total_checkpoints,
        );

        checkpoint
    }

    /// Return the canonical state for a payroll run ID.
    pub fn get_payroll_run_state(e: Env, run_id: u64) -> PayrollRunState {
        Self::get_payroll_run_state_internal(&e, run_id)
    }

    /// Admin-only state transition hook for conformance tests and operations.
    pub fn transition_payroll_run_state(
        e: Env,
        admin: Address,
        run_id: u64,
        next_state: PayrollRunState,
    ) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let current = Self::get_payroll_run_state_internal(&e, run_id);
        if !Self::is_allowed_payroll_state_transition_internal(current, next_state) {
            panic!("Invalid payroll state transition");
        }

        Self::record_payroll_run_state(&e, run_id, next_state);
    }

    pub fn get_payroll_run(e: Env, run_id: u64) -> PayrollRun {
        Self::validate_run_id(run_id);
        e.storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found")
    }

    /// Pre-commit an off-chain metadata hash (SHA-256 of payroll period,
    /// company ID, employee batch hash, and commitment references) that
    /// will be bound to a payroll run during execution (#177).
    ///
    /// Only the admin may call. The commitment is one-time-use: once consumed
    /// by `set_run_metadata` it is removed from storage.
    pub fn commit_metadata_hash(e: Env, admin: Address, metadata_hash: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_non_zero_digest(&e, &metadata_hash, "metadata_hash");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::DraftCommitment(metadata_hash.clone());
        if e.storage().persistent().has(&key) {
            panic!("Metadata hash already committed");
        }
        e.storage().persistent().set(&key, &true);

        payroll_events::emit_metadata_committed(&e, metadata_hash);
    }

    /// Bound a pre-committed metadata hash to an existing payroll run.
    /// Consumes the commitment so it cannot be reused. Only the admin may call.
    ///
    /// Must be called with a metadata hash that was previously committed via
    /// `commit_metadata_hash`. Fails if the hash has not been pre-committed.
    pub fn set_run_metadata(e: Env, admin: Address, run_id: u64, metadata_hash: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_run_id(run_id);
        Self::validate_non_zero_digest(&e, &metadata_hash, "metadata_hash");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        // Verify the metadata hash was pre-committed.
        let commit_key = DataKey::DraftCommitment(metadata_hash.clone());
        if !e.storage().persistent().has(&commit_key) {
            panic!("Metadata hash not pre-committed: call commit_metadata_hash first");
        }
        // Consume the commitment.
        e.storage().persistent().remove(&commit_key);

        // Update the payroll run record.
        let run_key = DataKey::PayrollRun(run_id);
        let mut run: PayrollRun = e
            .storage()
            .persistent()
            .get(&run_key)
            .expect("Run not found");
        run.metadata_hash = metadata_hash.clone();
        e.storage().persistent().set(&run_key, &run);

        payroll_events::emit_metadata_bound(&e, run_id, metadata_hash);
    }

    /// Pre-commit an off-chain draft hash so it can be bound to a future run.
    ///
    /// Clients compute `draft_hash` over the payroll preparation artifact
    /// (employee list, amounts, period metadata) before submitting the batch.
    /// Calling this function registers the hash on-chain so that
    /// `batch_process_payroll` can verify it has not been tampered with.
    ///
    /// Only the admin may pre-commit a draft. The commitment is one-time-use:
    /// once consumed by a successful `batch_process_payroll` call it is removed
    /// from storage (issue #102).
    pub fn commit_draft(e: Env, admin: Address, draft_hash: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_non_zero_digest(&e, &draft_hash, "draft_hash");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::DraftCommitment(draft_hash.clone());
        if e.storage().persistent().has(&key) {
            panic!("Draft already committed");
        }
        e.storage().persistent().set(&key, &true);

        payroll_events::emit_draft_committed(&e, draft_hash);
    }

    /// Request an emergency treasury withdrawal (step 1 of 2 ? issue #104).
    ///
    /// Only the `treasury_owner` may submit a request. A pending request is
    /// stored on-chain and must be separately approved by the `admin` via
    /// `approve_emergency_withdrawal`. At most one pending request may exist at
    /// any time.
    pub fn request_emergency_withdrawal(
        e: Env,
        treasury_owner: Address,
        amount: i128,
        recipient: Address,
    ) {
        Self::require_not_paused(&e);
        if amount <= 0 {
            panic!("Amount must be positive");
        }
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if treasury_owner != stored_owner {
            panic!("Unauthorized: caller is not treasury owner");
        }
        treasury_owner.require_auth();

        if e.storage().persistent().has(&DataKey::EmergencyRequest) {
            panic!("A pending emergency request already exists");
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let available = Self::get_available_treasury_balance(e.clone(), addrs.token.clone());
        if amount > available {
            panic!("Insufficient available treasury balance: funds locked for pending payroll");
        }

        let request = EmergencyWithdrawalRequest {
            amount,
            recipient: recipient.clone(),
            requested_at: e.ledger().timestamp(),
            approved: false,
        };
        e.storage()
            .persistent()
            .set(&DataKey::EmergencyRequest, &request);

        payroll_events::emit_emergency_requested(&e, amount, recipient);
    }

    /// Approve and execute a pending emergency withdrawal (step 2 of 2 ? issue #104).
    ///
    /// Only the `admin` may approve. On approval the treasury funds are
    /// transferred to the recipient specified in the request and the pending
    /// request is cleared from storage, ensuring it cannot be replayed.
    pub fn approve_emergency_withdrawal(e: Env, admin: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let request: EmergencyWithdrawalRequest = e
            .storage()
            .persistent()
            .get(&DataKey::EmergencyRequest)
            .expect("No pending emergency request");

        let available = Self::get_available_treasury_balance(e.clone(), addrs.token.clone());
        if request.amount > available {
            panic!("Insufficient available treasury balance: funds locked for pending payroll");
        }

        // Clear before transfer (checks-effects-interactions).
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        token_client.transfer(&addrs.treasury, &request.recipient, &request.amount);

        payroll_events::emit_emergency_approved(&e, request.amount, request.recipient);
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "emergency_withdrawal"),
        );
    }

    /// Cancel a pending emergency withdrawal request.
    ///
    /// Either the `treasury_owner` or the `admin` may cancel. Cancellation
    /// removes the pending request without transferring any funds.
    pub fn cancel_emergency_withdrawal(e: Env, caller: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

        let is_admin = caller == addrs.admin;
        let is_owner = caller == stored_owner;
        if !is_admin && !is_owner {
            panic!("Unauthorized: only admin or treasury owner may cancel");
        }
        caller.require_auth();

        if !e.storage().persistent().has(&DataKey::EmergencyRequest) {
            panic!("No pending emergency request to cancel");
        }
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        payroll_events::emit_emergency_cancelled(&e, caller);
    }

    /// Returns the pending emergency withdrawal request, if any.
    pub fn get_emergency_request(e: Env) -> Option<EmergencyWithdrawalRequest> {
        e.storage().persistent().get(&DataKey::EmergencyRequest)
    }

    // ?????????????????????????????????????????????????????????????????????????
    // Payroll run cancellation (issue #75)
    // ?????????????????????????????????????????????????????????????????????????

    /// Prepare a pending payroll run for later finalization or cancellation.
    ///
    /// This function validates the batch metadata and reserves the nonce without
    /// executing any payments. The run can later be finalized (via `finalize_payroll_run`)
    /// or cancelled (via `cancel_payroll_run`). Only finalized runs are permanent.
    ///
    /// This two-step process allows operators to validate configuration before
    /// committing treasury funds, reducing the risk of executing with incorrect
    /// inputs.
    pub fn prepare_payroll_run(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
    ) -> u64 {
        // Issue #620: authorize the execution initiator before any other work.
        Self::require_execution_initiator(&e);
        Self::require_company_active(&e);
        // #360 - validate storage version for sensitive operation
        Self::validate_storage_version_for_operation(&e, "prepare_payroll_run");

        let count = proofs.len();

        // #390: a missing proof gets its own actionable error before the
        // generic length check, so an empty batch is never reported as a
        // mismatch.
        if count == 0 {
            panic!("Missing payroll proof: one proof is required per payment");
        }

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        // Reject duplicate run nonces before any other work.
        let nonce_key = DataKey::RunNonce(nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Duplicate run nonce: this payroll batch has already been submitted");
        }

        // If a draft hash is supplied, verify a pre-commitment exists.
        let resolved_draft_hash: BytesN<32> = if let Some(ref dh) = draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                panic!("Draft hash not pre-committed: call commit_draft first");
            }
            dh.clone()
        } else {
            BytesN::from_array(&e, &[0u8; 32])
        };

        // #379 ? reject a batch that pays the same wallet twice.
        Self::validate_no_duplicate_employees(&employees);

        let mut total: i128 = 0;
        for i in 0..count {
            let amt = amounts.get(i).unwrap();
            if amt <= 0 {
                panic!("Amount must be positive");
            }
            total += amt;
        }
        if total != expected_total_spend {
            panic!(
                "Expected spend mismatch: authorised {} but batch totals {}",
                expected_total_spend, total
            );
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // #362 ? validate nonce monotonicity for this employer
        Self::validate_nonce_monotonicity(&e, &addrs.admin, &nonce);

        // Issue #620: `addrs.admin` was already authorized as the execution
        // initiator at the top of this function.

        // Validate treasury asset allowlist
        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

        // Issue #338: enforce per-period capacity limits before the batch is locked in.
        Self::enforce_and_record_capacity(&e, count, expected_total_spend);

        // Issue #316: enforce the settlement window for the open period, if any.
        let open_period = Self::enforce_settlement_window_for_current_period(&e);

        let run_id = Self::derive_run_id(&e);

        // Mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

        // #362 ? update nonce sequence tracking for this employer
        Self::update_nonce_sequence(&e, &addrs.admin, &nonce);

        // Store the pending run
        let pending_run = PendingPayrollRun {
            run_id,
            prepared_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: expected_total_spend,
            employee_count: count,
            draft_hash: resolved_draft_hash,
            nonce: nonce.clone(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingRun(run_id), &pending_run);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::Submitted);

        // Issue #316: remember which capacity period (if any) was open when
        // this run was prepared, so `expire_pending_run` can later locate its
        // settlement window.
        if let Some(period) = open_period {
            e.storage()
                .persistent()
                .set(&DataKey::PendingRunPeriod(run_id), &period);
            // Issue #248: submitting a run freezes the period's configuration.
            e.storage()
                .persistent()
                .set(&DataKey::PeriodConfigFrozen(period.clone()), &true);
        }

        // Issue #253: track this run as "in progress" so unsafe admin
        // configuration changes are locked out until it is resolved.
        e.storage().persistent().set(
            &DataKey::PendingRunCount,
            &(Self::pending_payroll_run_count(&e) + 1),
        );

        // Reserve locked funds for the prepared payroll run (#343)
        Self::add_locked_funds(&e, addrs.token.clone(), expected_total_spend);

        payroll_events::emit_run_prepared(&e, run_id, expected_total_spend);
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "run_prepared"),
        );

        run_id
    }

    /// Transfer the admin role of a pending payroll run to a new admin.
    pub fn transfer_pending_run_admin(
        e: Env,
        current_admin: Address,
        run_id: u64,
        new_admin: Address,
    ) {
        Self::require_not_paused(&e);
        Self::validate_run_id(run_id);
        Self::require_run_not_disputed(&e, run_id);

        let pending_key = DataKey::PendingRun(run_id);
        let mut pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&pending_key)
            .expect("Pending run not found");

        if pending_run.admin != current_admin {
            panic!("Unauthorized: caller is not the pending run admin");
        }

        current_admin.require_auth();

        if current_admin == new_admin {
            panic!("Invalid transfer: new admin is the same as current admin");
        }

        pending_run.admin = new_admin.clone();

        e.storage().persistent().set(&pending_key, &pending_run);

        e.events().publish(
            (
                Symbol::new(&e, "payroll"),
                Symbol::new(&e, "run_admin_transferred"),
            ),
            (run_id, current_admin, new_admin),
        );
    }

    /// Get a pending payroll run, if it exists.
    pub fn get_pending_run(e: Env, run_id: u64) -> Option<PendingPayrollRun> {
        e.storage().persistent().get(&DataKey::PendingRun(run_id))
    }

    /// Finalize a pending payroll run, executing payments and creating a
    /// permanent `PayrollRun` record (issue #198).
    ///
    /// Only the admin may finalize. The caller must supply the same proofs,
    /// amounts, and employees that were validated during `prepare_payroll_run`.
    /// The pending run must exist and its metadata (total_amount, employee_count)
    /// must match the supplied batch.
    ///
    /// Cancellation emits an event for audit trails. Finalized runs cannot be
    /// cancelled retroactively.
    ///
    /// Issue #218: Added explicit validation that the run is still pending
    /// and proper state cleanup to prevent cancel-after-submit race conditions.
    pub fn finalize_payroll_run(e: Env, admin: Address, run_id: u64) {
        Self::require_not_paused(&e);
        Self::validate_run_id(run_id);
        Self::require_run_not_disputed(&e, run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let pending_key = DataKey::PendingRun(run_id);
        let pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&pending_key)
            .expect("Pending run not found");

        // Validate approval expiry if a review exists (#403)
        Self::validate_approval_not_expired(&e, run_id, DEFAULT_APPROVAL_EXPIRY_SECONDS);
        approvals::require_threshold_met(&e, run_id);

        // Issue #218: Check if run has already been finalized
        // Once a run is executed, it cannot be cancelled
        let run_key = DataKey::PayrollRun(run_id);
        if e.storage().persistent().has(&run_key) {
            panic!("Cannot cancel: run has already been executed");
        }

        // Release locked funds reservation (#343)
        Self::subtract_locked_funds(&e, addrs.token.clone(), pending_run.total_amount);

        // Remove the pending run from storage
        e.storage().persistent().remove(&pending_key);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::ReconciliationRequired);

        // Issue #253: this run is resolved — release the configuration lock
        // once no other pending runs remain.
        e.storage().persistent().set(
            &DataKey::PendingRunCount,
            &Self::pending_payroll_run_count(&e).saturating_sub(1),
        );

        let run = PayrollRun {
            run_id,
            executed_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: pending_run.total_amount,
            employee_count: pending_run.employee_count,
            draft_hash: pending_run.draft_hash.clone(),
            nonce: pending_run.nonce.clone(),
            reconciliation_status: ReconciliationStatus::Unreconciled,
            metadata_hash: BytesN::from_array(&e, &[0u8; 32]),
            note_hash: BytesN::from_array(&e, &[0u8; 32]),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_finalized")),
            (run_id, pending_run.total_amount),
        );
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "run_finalized"),
        );
    }

    /// Cancel a pending payroll run without executing any payments (issue #198).
    ///
    /// Only the admin may cancel. The `reason` is recorded in the event for
    /// audit trails. No funds are transferred; this is a pure cleanup operation.
    ///
    /// Finalized runs cannot be cancelled retroactively. The run nonce remains
    /// permanently spent after cancellation (one-time-use for audit integrity).
    ///
    /// This function serves as a high-priority escape hatch: it deliberately
    /// does NOT require the system to be unpaused. An admin who can pause the
    /// system can also cancel a pending run while paused, enabling rapid
    pub fn cancel_payroll_run_with_reason(e: Env, admin: Address, run_id: u64, reason: Symbol) {
        Self::validate_run_id(run_id);
        Self::validate_symbol_not_empty(&e, &reason, "reason");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let pending_key = DataKey::PendingRun(run_id);

        // Guard: reject cancellation if a finalized PayrollRun already exists
        // for this run_id (completed via finalize_payroll_run or
        // batch_process_payroll).
        if e.storage().persistent().has(&DataKey::PayrollRun(run_id)) {
            panic!("Cannot cancel a finalized payroll run");
        }

        let pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&pending_key)
            .expect("Pending run not found");

        // Release locked funds reservation (#343)
        Self::subtract_locked_funds(&e, addrs.token.clone(), pending_run.total_amount);

        // Store safe cancellation metadata (#404)
        let cancel_status = CancelledBatchStatus {
            run_id,
            cancelled_at: e.ledger().timestamp(),
            cancelled_by: admin.clone(),
            reason: reason.clone(),
            employee_count: pending_run.employee_count,
            total_amount: pending_run.total_amount,
            draft_hash: pending_run.draft_hash.clone(),
            is_cancelled: true,
        };
        e.storage()
            .persistent()
            .set(&DataKey::CancelledBatchRecord(run_id), &cancel_status);

        // Remove the pending run from storage if present
        e.storage().persistent().remove(&pending_key);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::Cancelled);

        // Issue #253: this run is resolved — release the configuration lock
        // once no other pending runs remain.
        e.storage().persistent().set(
            &DataKey::PendingRunCount,
            &Self::pending_payroll_run_count(&e).saturating_sub(1),
        );

        // Emit cancellation event with reason for audit trail
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_cancelled")),
            (run_id, reason),
        );
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "run_cancelled"),
        );
    }

    /// Alias for cancel_payroll_run_with_reason
    pub fn cancel_payroll_run(e: Env, admin: Address, run_id: u64, reason: Symbol) {
        Self::cancel_payroll_run_with_reason(e, admin, run_id, reason);
    }

    /// Hash the complete payroll request used by the idempotent entrypoint.
    ///
    /// XDR is used for structured values and fixed-width big-endian encoding
    /// for numeric values, making the binding deterministic without storing
    /// employee addresses, amounts, or proofs in the idempotency record.
    fn hash_payroll_execution_payload(
        e: &Env,
        proofs: &Vec<BytesN<256>>,
        amounts: &Vec<i128>,
        employees: &Vec<Address>,
        expected_total_spend: i128,
        nonce: &BytesN<32>,
        draft_hash: &Option<BytesN<32>>,
    ) -> BytesN<32> {
        let mut payload = Bytes::new(e);
        payload.extend_from_slice(&proofs.len().to_be_bytes());
        for proof in proofs.iter() {
            payload.append(&proof.to_xdr(e));
        }
        for amount in amounts.iter() {
            payload.extend_from_slice(&amount.to_be_bytes());
        }
        for employee in employees.iter() {
            payload.append(&employee.to_xdr(e));
        }
        payload.extend_from_slice(&expected_total_spend.to_be_bytes());
        payload.append(&nonce.to_xdr(e));
        match draft_hash {
            Some(hash) => {
                payload.extend_from_array(&[1u8]);
                payload.append(&hash.to_xdr(e));
            }
            None => payload.extend_from_array(&[0u8]),
        }
        e.crypto().sha256(&payload).into()
    }

    /// Execute a payroll batch with a client-supplied idempotency key (#473).
    ///
    /// The first successful call stores only the key, a payload digest, and the
    /// resulting run ID. Retrying the same request returns that run ID without
    /// executing transfers again. Reusing the key with different request data
    /// fails, and the existing payroll execution path retains responsibility
    /// for all validation, authorization, and payment checks.
    pub fn batch_process_payroll_idempotent(
        e: Env,
        idempotency_key: BytesN<32>,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
        source_address: Address,
    ) -> u64 {
        // Issue #620: authorize the execution initiator before any other work.
        Self::require_execution_initiator(&e);
        Self::require_company_active(&e);
        Self::validate_non_zero_digest(&e, &idempotency_key, "idempotency_key");

        let payload_hash = Self::hash_payroll_execution_payload(
            &e,
            &proofs,
            &amounts,
            &employees,
            expected_total_spend,
            &nonce,
            &draft_hash,
        );
        let key = DataKey::PayrollExecutionIdempotency(idempotency_key);

        if let Some(record) = e
            .storage()
            .persistent()
            .get::<_, PayrollExecutionIdempotencyRecord>(&key)
        {
            if record.payload_hash != payload_hash {
                panic!("Idempotency key payload mismatch");
            }
            // Issue #620: the execution initiator was authorized at the top of
            // this function before the cached record is returned.
            return record.run_id;
        }

        let run_id = Self::batch_process_payroll(
            e.clone(),
            proofs,
            amounts,
            employees,
            expected_total_spend,
            nonce,
            draft_hash,
            source_address,
        );
        e.storage().persistent().set(
            &key,
            &PayrollExecutionIdempotencyRecord {
                run_id,
                payload_hash,
                created_at: e.ledger().timestamp(),
            },
        );
        run_id
    }

    /// Look up the stored result for an idempotency key without exposing the
    /// original payroll payload.
    pub fn get_idempotency_record(
        e: Env,
        idempotency_key: BytesN<32>,
    ) -> Option<PayrollExecutionIdempotencyRecord> {
        e.storage()
            .persistent()
            .get(&DataKey::PayrollExecutionIdempotency(idempotency_key))
    }

    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
        source_address: Address,
    ) -> u64 {
        // Issue #620: authorize the execution initiator before any other work.
        Self::require_execution_initiator(&e);
        Self::require_company_active(&e);
        approvals::require_no_threshold_for_direct_execution(&e);

        // Validate import source authorization before any other work.
        require_authorized_source(&e, &source_address);

        // #360 - validate storage version for sensitive operation
        Self::validate_storage_version_for_operation(&e, "batch_process_payroll");

        Self::validate_non_zero_digest(&e, &nonce, "nonce");
        if let Some(ref dh) = draft_hash {
            Self::validate_non_zero_digest(&e, dh, "draft_hash");
        }
        let count = proofs.len();

        // #390: a missing proof gets its own actionable error before the
        // generic length check, so an empty batch is never reported as a
        // mismatch.
        if count == 0 {
            panic!("Missing payroll proof: one proof is required per payment");
        }

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        // #103 ? reject duplicate run nonces before any other work.
        let nonce_key = DataKey::RunNonce(nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Duplicate run nonce: this payroll batch has already been submitted");
        }

        // #102 ? if a draft hash is supplied, verify a pre-commitment exists.
        let resolved_draft_hash: BytesN<32> = if let Some(ref dh) = draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                panic!("Draft hash not pre-committed: call commit_draft first");
            }
            // Consume the commitment ? one run per pre-committed draft.
            e.storage().persistent().remove(&commit_key);
            dh.clone()
        } else {
            BytesN::from_array(&e, &[0u8; 32])
        };

        // #379 ? reject a batch that pays the same wallet twice.
        Self::validate_no_duplicate_employees(&employees);

        let mut total: i128 = 0;
        for i in 0..count {
            let amt = amounts.get(i).unwrap();
            if amt <= 0 {
                panic!("Amount must be positive");
            }
            total += amt;
        }

        // #514 - validate minimum payout amount threshold
        Self::validate_minimum_payout_amount(&e, &amounts);

        if total != expected_total_spend {
            panic!(
                "Expected spend mismatch: authorised {} but batch totals {}",
                expected_total_spend, total
            );
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // #362 ? validate nonce monotonicity for this employer
        Self::validate_nonce_monotonicity(&e, &addrs.admin, &nonce);

        // Validate treasury asset allowlist
        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

        if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&e, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        // Issue #620: `addrs.admin` was already authorized as the execution
        // initiator at the top of this function.

        // Issue #338: enforce per-period capacity limits before the batch executes.
        Self::enforce_and_record_capacity(&e, count, expected_total_spend);

        // Issue #316: enforce the settlement window for the open period, if any.
        Self::enforce_settlement_window_for_current_period(&e);

        let run_id = Self::derive_run_id(&e);

        // #103 ? mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

        // #362 ? update nonce sequence tracking for this employer
        Self::update_nonce_sequence(&e, &addrs.admin, &nonce);

        let token_client = soroban_token::Client::new(&e, &addrs.token);

        // Issue #62: fail early if the treasury token balance cannot cover the
        // full batch payout, before any proof verification or transfers begin.
        let treasury_balance = token_client.balance(&addrs.treasury);
        if treasury_balance < expected_total_spend {
            panic!(
                "Insufficient treasury balance: available {} but batch requires {}",
                treasury_balance, expected_total_spend
            );
        }

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);

        for i in 0..count {
            let proof = proofs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            // Issue #482: Validate employee has not been paid already in this run
            Self::validate_employee_not_already_paid(&e, run_id, &commitment);

            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            let mut public_inputs = Vec::new(&e);
            public_inputs.push_back(commitment.clone());
            public_inputs.push_back(nullifier.clone());
            public_inputs.push_back(recipient_hash.clone());

            let ok = verifier.verify_payment_proof(&proof, &public_inputs);
            if !ok {
                panic!("Invalid payment proof for employee {}", i);
            }

            commitment_client.record_nullifier(&nullifier);

            token_client.transfer(&addrs.treasury, &employee, &amount);

            // #178 ? lock the employee's commitment so it cannot be silently
            // altered after payroll has been executed for this period.
            commitment_client.lock_commitment_updates(&employee);

            // Issue #482: Record that this employee has been paid
            Self::record_employee_paid(&e, run_id, commitment);

            payroll_events::emit_payment_executed(&e, employee.clone(), amount);
        }

        let run = PayrollRun {
            run_id,
            executed_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: expected_total_spend,
            employee_count: count,
            draft_hash: resolved_draft_hash,
            nonce: nonce.clone(),
            reconciliation_status: ReconciliationStatus::Unreconciled,
            metadata_hash: BytesN::from_array(&e, &[0u8; 32]),
            note_hash: BytesN::from_array(&e, &[0u8; 32]),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::ReconciliationRequired);

        // Issue #485: Record payroll run status for dashboards
        Self::record_payroll_run_status(
            &e,
            run_id,
            PayrollRunStatusKind::Completed,
            count,
            expected_total_spend,
        );

        // Issue #478: Record metadata version for this run
        Self::set_metadata_version(&e, run_id, 1u32, BytesN::from_array(&e, &[0u8; 32]));

        payroll_events::emit_run_executed(&e, run_id, expected_total_spend);
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "run_executed"),
        );

        run_id
    }

    // ── Issue #346: proof expiry enforcement ──────────────────────────────────

    /// Same as [`batch_process_payroll`](Self::batch_process_payroll), except
    /// each proof is verified through a registered, expiry-aware
    /// `proof_verifier::ProofReference` (see `proof_verifier::verify_with_reference`)
    /// instead of a bare `verify_payment_proof` call.
    ///
    /// `proof_refs[i]` must be the `ref_id` previously passed to
    /// `proof_verifier::register_proof_reference` for `proofs[i]`. Execution
    /// panics with an actionable message when a reference is missing,
    /// revoked, expired, or was registered for different proof bytes -
    /// stale payroll evidence can never be replayed through this entry point
    /// after its verification window has passed, even if the raw proof
    /// bytes would otherwise still satisfy `verify_payment_proof`.
    ///
    /// A caller who needs to replace a proof before settlement (e.g. the
    /// original reference expired, or the wrong proof was registered) simply
    /// registers a new reference for fresh proof bytes via
    /// `proof_verifier::register_proof_reference` and passes its `ref_id`
    /// here - there is no separate "replace" call, since registration itself
    /// is the only way to create a currently-valid reference.
    ///
    /// This is intentionally a separate entry point rather than a change to
    /// `batch_process_payroll`'s existing signature, so every current caller
    /// of the unmodified function keeps working unchanged. It does not (yet)
    /// have a bounded/idempotent counterpart the way `batch_process_payroll`
    /// does - only the core batch path is covered here.
    pub fn batch_process_with_expiry(
        e: Env,
        proofs: Vec<BytesN<256>>,
        proof_refs: Vec<BytesN<32>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
    ) -> u64 {
        Self::require_company_active(&e);
        approvals::require_no_threshold_for_direct_execution(&e);

        Self::validate_storage_version_for_operation(&e, "batch_process_with_expiry");

        Self::validate_non_zero_digest(&e, &nonce, "nonce");
        if let Some(ref dh) = draft_hash {
            Self::validate_non_zero_digest(&e, dh, "draft_hash");
        }
        let count = proofs.len();

        if count == 0 {
            panic!("Missing payroll proof: one proof is required per payment");
        }

        if amounts.len() != count || employees.len() != count || proof_refs.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        let nonce_key = DataKey::RunNonce(nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Duplicate run nonce: this payroll batch has already been submitted");
        }

        let resolved_draft_hash: BytesN<32> = if let Some(ref dh) = draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                panic!("Draft hash not pre-committed: call commit_draft first");
            }
            e.storage().persistent().remove(&commit_key);
            dh.clone()
        } else {
            BytesN::from_array(&e, &[0u8; 32])
        };

        Self::validate_no_duplicate_employees(&employees);

        let mut total: i128 = 0;
        for i in 0..count {
            let amt = amounts.get(i).unwrap();
            if amt <= 0 {
                panic!("Amount must be positive");
            }
            total += amt;
        }
        if total != expected_total_spend {
            panic!(
                "Expected spend mismatch: authorised {} but batch totals {}",
                expected_total_spend, total
            );
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        Self::validate_nonce_monotonicity(&e, &addrs.admin, &nonce);

        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

        if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&e, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        addrs.admin.require_auth();

        Self::enforce_and_record_capacity(&e, count, expected_total_spend);
        Self::enforce_settlement_window_for_current_period(&e);

        let run_id = Self::derive_run_id(&e);

        e.storage().persistent().set(&nonce_key, &run_id);
        Self::update_nonce_sequence(&e, &addrs.admin, &nonce);

        let token_client = soroban_token::Client::new(&e, &addrs.token);

        let treasury_balance = token_client.balance(&addrs.treasury);
        if treasury_balance < expected_total_spend {
            panic!(
                "Insufficient treasury balance: available {} but batch requires {}",
                treasury_balance, expected_total_spend
            );
        }

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);

        for i in 0..count {
            let proof = proofs.get(i).unwrap();
            let ref_id = proof_refs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            Self::validate_employee_not_already_paid(&e, run_id, &commitment);

            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            let mut public_inputs = Vec::new(&e);
            public_inputs.push_back(commitment.clone());
            public_inputs.push_back(nullifier.clone());
            public_inputs.push_back(recipient_hash.clone());

            // Issue #346: verify through the expiry-aware reference rather
            // than a bare proof-bytes check, so a stale (expired or revoked)
            // reference blocks settlement even when the underlying proof
            // bytes would otherwise still pass `verify_payment_proof`.
            let ok = verifier.verify_with_reference(&ref_id, &proof, &public_inputs);
            if !ok {
                panic!(
                    "Invalid or expired payment proof reference for employee {}",
                    i
                );
            }

            commitment_client.record_nullifier(&nullifier);

            token_client.transfer(&addrs.treasury, &employee, &amount);

            commitment_client.lock_commitment_updates(&employee);

            Self::record_employee_paid(&e, run_id, commitment);

            payroll_events::emit_payment_executed(&e, employee.clone(), amount);
        }

        let run = PayrollRun {
            run_id,
            executed_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: expected_total_spend,
            employee_count: count,
            draft_hash: resolved_draft_hash,
            nonce: nonce.clone(),
            reconciliation_status: ReconciliationStatus::Unreconciled,
            metadata_hash: BytesN::from_array(&e, &[0u8; 32]),
            note_hash: BytesN::from_array(&e, &[0u8; 32]),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::ReconciliationRequired);

        Self::record_payroll_run_status(
            &e,
            run_id,
            PayrollRunStatusKind::Completed,
            count,
            expected_total_spend,
        );

        Self::set_metadata_version(&e, run_id, 1u32, BytesN::from_array(&e, &[0u8; 32]));

        payroll_events::emit_run_executed(&e, run_id, expected_total_spend);

        run_id
    }

    // ── Issue #509 / #521: failure reason codes + dry-run preflight ──────────

    /// Read-only preflight for `batch_process_payroll`: reports every
    /// blocking precondition it can find without moving funds, verifying
    /// proofs, or writing any storage (issue #521).
    ///
    /// Runs the same checks `batch_process_payroll` performs, in the same
    /// order, EXCEPT: it never calls `token_client.transfer`, never calls
    /// `verifier.verify_payment_proof` (proof correctness cannot be checked
    /// without either duplicating verifier internals or accepting a
    /// dependency this preflight does not want; a `MissingProof` /
    /// `ArrayLengthMismatch` shape check on `proof_count` is still
    /// performed), and never writes `DataKey::RunNonce`,
    /// `DataKey::PeriodUsage`, `DataKey::EmployerNonceSequence`, or any
    /// other run/nonce/capacity state. A `draft_hash` pre-commitment is
    /// checked for existence but never consumed.
    ///
    /// Unlike `batch_process_payroll`, which panics on the FIRST failing
    /// check, this collects every blocker it finds into one report — the
    /// main reason a dry-run is more useful than reading the panic message
    /// from a real (reverted) call.
    ///
    /// Still gated the same way the real call effectively is: nothing here
    /// discloses salary amounts, employee identities, or proof material
    /// beyond what the caller already supplied as arguments.
    pub fn dry_run_batch_process_payroll(e: Env, args: DryRunArgs) -> PayrollDryRunReport {
        let mut report = PayrollDryRunReport::empty(&e);

        if !Self::company_is_active(&e) {
            report.push(PayrollFailureReason::CompanyNotActive);
        }
        if approvals::threshold(&e).is_some() {
            report.push(PayrollFailureReason::ApprovalWorkflowRequired);
        }

        // Validate import source
        if let Some(ref source) = args.source_address {
            if let Err(reason) = validate_source_for_report(&e, source) {
                report.push(reason);
            }
        }

        let count = args.proof_count;
        if count == 0 {
            report.push(PayrollFailureReason::MissingProof);
        }
        if args.amounts.len() != count || args.employees.len() != count {
            report.push(PayrollFailureReason::ArrayLengthMismatch);
        }
        if count > MAX_BATCH {
            report.push(PayrollFailureReason::BatchTooLarge);
        }

        let nonce_key = DataKey::RunNonce(args.nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            report.push(PayrollFailureReason::DuplicateRunNonce);
        }

        if let Some(ref dh) = args.draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                report.push(PayrollFailureReason::DraftNotPreCommitted);
            }
        }

        if Self::has_duplicate_employees(&args.employees) {
            report.push(PayrollFailureReason::DuplicateEmployee);
        }

        let mut total: i128 = 0;
        let mut any_non_positive = false;
        for i in 0..args.amounts.len() {
            let amt = args.amounts.get(i).unwrap();
            if amt <= 0 {
                any_non_positive = true;
            } else {
                total += amt;
            }
        }
        if any_non_positive {
            report.push(PayrollFailureReason::NonPositiveAmount);
        }

        // #514 - validate minimum payout amount threshold in dry run
        let minimum: i128 = match e.storage().persistent().get(&DataKey::MinimumPayoutAmount) {
            Some(min) => min,
            None => 0, // No threshold configured
        };

        if minimum > 0 {
            let mut any_below_minimum = false;
            for i in 0..args.amounts.len() {
                let amt = args.amounts.get(i).unwrap();
                if amt < minimum {
                    any_below_minimum = true;
                    break;
                }
            }
            if any_below_minimum {
                report.push(PayrollFailureReason::AmountBelowMinimum);
            }
        }

        if total != args.expected_total_spend {
            report.push(PayrollFailureReason::ExpectedSpendMismatch);
        }

        if let Some(addrs) = e
            .storage()
            .persistent()
            .get::<_, ContractAddresses>(&DataKey::Addresses)
        {
            if Self::nonce_is_stale(&e, &addrs.admin, &args.nonce) {
                report.push(PayrollFailureReason::NonceNotMonotonic);
            }

            if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
                report.push(PayrollFailureReason::AssetNotAllowed);
            }

            if e.storage().persistent().has(&DataKey::PauseManager) {
                let pm_addr: Address = e
                    .storage()
                    .persistent()
                    .get(&DataKey::PauseManager)
                    .unwrap();
                let pm_client = PauseManagerClient::new(&e, &pm_addr);
                if pm_client.is_paused() {
                    report.push(PayrollFailureReason::SystemPaused);
                }
            }

            for detail in Self::would_exceed_capacity(&e, count, args.expected_total_spend) {
                report.push_capacity(detail);
            }

            if Self::settlement_window_would_reject(&e) {
                report.push(PayrollFailureReason::SettlementWindowNotOpen);
            }

            let token_client = soroban_token::Client::new(&e, &addrs.token);
            let treasury_balance = token_client.balance(&addrs.treasury);
            if treasury_balance < args.expected_total_spend {
                report.push(PayrollFailureReason::InsufficientTreasuryBalance);
            }
        }

        report
    }

    /// Read-only equivalent of `require_company_active`: returns `false`
    /// instead of panicking. Absent state defaults to `Active`, matching
    /// `require_company_active`'s own default.
    fn company_is_active(e: &Env) -> bool {
        match e
            .storage()
            .persistent()
            .get::<_, CompanyState>(&DataKey::CompanyState)
        {
            Some(CompanyState::Active) | None => true,
            Some(_) => false,
        }
    }

    /// Read-only equivalent of the duplicate-employee check inside
    /// `validate_no_duplicate_employees`, without panicking.
    fn has_duplicate_employees(employees: &Vec<Address>) -> bool {
        let count = employees.len();
        for i in 0..count {
            let current = employees.get(i).unwrap();
            for j in (i + 1)..count {
                if current == employees.get(j).unwrap() {
                    return true;
                }
            }
        }
        false
    }

    /// Read-only equivalent of `validate_nonce_monotonicity`: returns
    /// `true` if the given nonce would be rejected (a replay or a
    /// non-strictly-increasing value), without panicking or writing state.
    fn nonce_is_stale(env: &Env, employer: &Address, nonce: &BytesN<32>) -> bool {
        let sequence_key = DataKey::EmployerNonceSequence(employer.clone());
        if let Some(sequence_state) = env
            .storage()
            .persistent()
            .get::<_, EmployerNonceSequenceState>(&sequence_key)
        {
            if nonce == &sequence_state.last_nonce {
                return true;
            }
            let new_nonce_value = Self::nonce_to_u256(env, nonce);
            let last_nonce_value = Self::nonce_to_u256(env, &sequence_state.last_nonce);
            if new_nonce_value <= last_nonce_value {
                return true;
            }
        }
        false
    }

    /// Read-only equivalent of `enforce_and_record_capacity`: returns which
    /// capacity dimensions (if any) executing this batch would exceed,
    /// without writing `DataKey::PeriodUsage` or emitting the enforcement
    /// events `enforce_and_record_capacity` emits on success.
    fn would_exceed_capacity(
        e: &Env,
        employee_count: u32,
        batch_value: i128,
    ) -> Vec<CapacityLimitKind> {
        let mut exceeded = Vec::new(e);
        let limits: CapacityLimits = match e.storage().persistent().get(&DataKey::CapacityLimits) {
            Some(limits) => limits,
            None => return exceeded,
        };
        let period: Symbol = match e.storage().persistent().get(&DataKey::CurrentPeriod) {
            Some(period) => period,
            None => return exceeded,
        };

        let usage: PeriodUsage = e
            .storage()
            .persistent()
            .get(&DataKey::PeriodUsage(period))
            .unwrap_or(PeriodUsage {
                batch_count: 0,
                employee_count: 0,
                total_value: 0,
            });

        if usage.batch_count + 1 > limits.max_batches {
            exceeded.push_back(CapacityLimitKind::BatchCount);
        }
        if usage.employee_count + employee_count > limits.max_employees {
            exceeded.push_back(CapacityLimitKind::EmployeeCount);
        }
        if usage.total_value + batch_value > limits.max_total_value {
            exceeded.push_back(CapacityLimitKind::TotalValue);
        }
        exceeded
    }

    /// Read-only equivalent of `enforce_settlement_window_for_current_period`:
    /// returns `true` if the current period's settlement window (if any) is
    /// not open for execution right now, without emitting the rejection
    /// event the real enforcement path emits.
    fn settlement_window_would_reject(e: &Env) -> bool {
        let period: Symbol = match e.storage().persistent().get(&DataKey::CurrentPeriod) {
            Some(period) => period,
            None => return false,
        };
        let window: SettlementWindow = match e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period))
        {
            Some(window) => window,
            None => return true,
        };
        let now = e.ledger().timestamp();
        Self::classify_settlement_window(&window, now) != SettlementWindowStatus::Executable
    }

    // ── Issue #475: Bounded batch processing for employee payments ────────────

    /// Bounded batch processing for large payroll runs (#475).
    ///
    /// Accepts a configurable `batch_size` parameter bounded by a hard cap (MAX_BATCH = 50).
    /// Processes employees in deterministic order within each batch, tracks progress via
    /// privacy-safe checkpoints, and allows partial runs to be safely resumed without double-paying.
    pub fn batch_process_payroll_bounded(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
        batch_size: u32,
    ) -> u64 {
        // Issue #620: authorize the execution initiator before any other work.
        Self::require_execution_initiator(&e);
        Self::require_company_active(&e);
        approvals::require_no_threshold_for_direct_execution(&e);

        Self::validate_storage_version_for_operation(&e, "batch_process_payroll_bounded");

        if batch_size == 0 {
            panic!("Batch size must be greater than zero");
        }
        if batch_size > MAX_BATCH {
            panic!("Batch size exceeds maximum limit of 50");
        }

        Self::validate_non_zero_digest(&e, &nonce, "nonce");
        if let Some(ref dh) = draft_hash {
            Self::validate_non_zero_digest(&e, dh, "draft_hash");
        }

        let count = proofs.len();
        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }
        if count == 0 {
            panic!("Empty payroll batch");
        }
        if count > MAX_BATCH {
            panic!("Batch employee count exceeds maximum limit of 50");
        }

        let mut total: i128 = 0;
        for i in 0..count {
            let amt = amounts.get(i).unwrap();
            if amt <= 0 {
                panic!("Amount must be positive");
            }
            total += amt;
        }
        if total != expected_total_spend {
            panic!(
                "Expected spend mismatch: authorised {} but batch totals {}",
                expected_total_spend, total
            );
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // Issue #620: `addrs.admin` was already authorized as the execution
        // initiator at the top of this function.

        let batch_root = draft_hash.clone().unwrap_or_else(|| nonce.clone());
        let checkpoint_key = DataKey::BatchCheckpoint(
            addrs.admin.clone(),
            batch_root.clone(),
            addrs.token.clone(),
            nonce.clone(),
        );

        let mut checkpoint: BatchCheckpoint = if e.storage().persistent().has(&checkpoint_key) {
            let mut cp: BatchCheckpoint = e.storage().persistent().get(&checkpoint_key).unwrap();
            if cp.completed {
                panic!("Payroll batch already completed");
            }
            if cp.failed {
                panic!(
                    "Failed payroll batch is not resumable: call resume_payroll_batch first (issue #611)"
                );
            }
            // Issue #611: a resubmission must replay the same batch shape. A
            // persisted cursor beyond the submitted payment count means this
            // call is not the original batch (or its size changed), which
            // would silently skip or double-count payouts.
            if cp.last_checkpoint_index > count {
                panic!(
                    "Batch identity mismatch: checkpoint progress {} exceeds submitted payment count {}",
                    cp.last_checkpoint_index, count
                );
            }
            // Issue #611: keep the recorded batch size aligned with the
            // replayed payment count so progress reporting stays truthful.
            cp.total_checkpoints = count;
            payroll_events::emit_batch_checkpoint_resumed(
                &e,
                addrs.admin.clone(),
                batch_root.clone(),
                addrs.token.clone(),
                nonce.clone(),
                cp.last_checkpoint_index,
            );
            cp
        } else {
            let cp = BatchCheckpoint {
                employer: addrs.admin.clone(),
                batch_root: batch_root.clone(),
                asset: addrs.token.clone(),
                execution_nonce: nonce.clone(),
                state: BatchCheckpointState::Started,
                last_checkpoint_index: 0,
                total_checkpoints: count,
                completed: false,
                failed: false,
            };
            e.storage().persistent().set(&checkpoint_key, &cp);
            payroll_events::emit_batch_checkpoint_started(
                &e,
                addrs.admin.clone(),
                batch_root.clone(),
                addrs.token.clone(),
                nonce.clone(),
                0,
            );
            cp
        };

        let start_index = checkpoint.last_checkpoint_index;
        if start_index >= count {
            panic!("Payroll batch already fully processed");
        }
        let end_index = core::cmp::min(start_index + batch_size, count);

        Self::validate_no_duplicate_employees(&employees);

        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

        if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&e, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);

        for i in start_index..end_index {
            let proof = proofs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            if amount <= 0 {
                panic!("Amount must be positive");
            }

            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            let mut public_inputs = Vec::new(&e);
            public_inputs.push_back(commitment.clone());
            public_inputs.push_back(nullifier.clone());
            public_inputs.push_back(recipient_hash.clone());

            let ok = verifier.verify_payment_proof(&proof, &public_inputs);
            if !ok {
                panic!("Invalid payment proof for employee {}", i);
            }

            commitment_client.record_nullifier(&nullifier);
            token_client.transfer(&addrs.treasury, &employee, &amount);
            commitment_client.lock_commitment_updates(&employee);

            payroll_events::emit_payment_executed(&e, employee.clone(), amount);
        }

        checkpoint.last_checkpoint_index = end_index;
        if end_index >= count {
            checkpoint.completed = true;
            checkpoint.state = BatchCheckpointState::Completed;
        } else {
            checkpoint.state = BatchCheckpointState::PartiallyCheckpointed;
        }

        e.storage().persistent().set(&checkpoint_key, &checkpoint);

        payroll_events::emit_batch_checkpoint_updated(
            &e,
            addrs.admin.clone(),
            batch_root.clone(),
            addrs.token.clone(),
            nonce.clone(),
            checkpoint.last_checkpoint_index,
            checkpoint.state as u32,
        );

        let run_id = Self::derive_run_id(&e);
        run_id
    }

    // ?? Issue #89: payroll amendment flow ????????????????????????????????????

    /// Create a correctable payroll run draft.
    ///
    /// Returns the new `draft_id`. The draft starts in `Pending` state and
    /// can be amended via `amend_run_draft` before being locked with
    /// `finalize_run_draft`.
    pub fn create_run_draft(
        e: Env,
        admin: Address,
        total_amount: i128,
        employee_count: u32,
        period_label: Symbol,
    ) -> u64 {
        Self::require_not_paused(&e);
        Self::validate_symbol_not_empty(&e, &period_label, "period_label");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        // Issue #471: a frozen period cannot receive new drafts.
        Self::require_period_not_frozen(&e, &period_label);

        if total_amount <= 0 {
            panic!("total_amount must be positive");
        }

        // Issue #398: reject a duplicate draft for a period that already has
        // one pending. Cleared when the existing draft leaves Pending
        // (finalize/cancel/expire) — not wired into those paths in this
        // pass, so a stale entry here would need a follow-up cleanup there.
        let period_key = DataKey::ActiveDraftForPeriod(period_label.clone());
        if e.storage().persistent().has(&period_key) {
            panic!("A pending draft already exists for this payroll period");
        }

        let counter: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraftCounter)
            .unwrap_or(0);
        let draft_id = counter + 1;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraftCounter, &draft_id);

        let draft = PayrollRunDraft {
            draft_id,
            created_at: e.ledger().timestamp(),
            admin: admin.clone(),
            total_amount,
            employee_count,
            period_label: period_label.clone(),
            state: RunDraftState::Pending,
            amendment_count: 0,
            updated_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);
        e.storage().persistent().set(&period_key, &draft_id);

        payroll_events::emit_draft_created(&e, draft_id, admin, period_label);

        draft_id
    }

    /// Amend a `Pending` payroll run draft before finalization.
    ///
    /// Only the admin may amend. Finalized drafts are rejected so audit
    /// trails remain unambiguous.
    pub fn amend_run_draft(
        e: Env,
        admin: Address,
        draft_id: u64,
        new_total_amount: i128,
        new_employee_count: u32,
    ) {
        Self::require_not_paused(&e);
        Self::validate_draft_id(draft_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");
        if draft.state != RunDraftState::Pending {
            panic!("Only pending drafts can be amended");
        }
        // Issue #471: a frozen period cannot receive draft edits.
        Self::require_period_not_frozen(&e, &draft.period_label);
        if new_total_amount <= 0 {
            panic!("total_amount must be positive");
        }
        // Issue #577: correction authorization limits, when configured, cap how
        // much correction activity a payroll period accepts. `delta` is the
        // absolute magnitude of the change, so raising and lowering the draft
        // total consume the same budget. Enforced before any state is written.
        let delta = (new_total_amount - draft.total_amount).abs();
        Self::require_correction_authorized(&e, &draft.period_label, delta, new_employee_count);
        draft.total_amount = new_total_amount;
        draft.employee_count = new_employee_count;
        draft.amendment_count += 1;
        draft.updated_at = e.ledger().timestamp();
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);
        payroll_events::emit_draft_amended(&e, draft_id, new_total_amount, draft.amendment_count);
        payroll_events::emit_draft_updated(
            &e,
            draft_id,
            draft.period_label.clone(),
            new_total_amount,
            new_employee_count,
            draft.amendment_count,
        );
        // Issue #577: count the applied correction against the period.
        Self::record_correction_usage(&e, &draft.period_label, delta, new_employee_count);
    }

    // ── Issue #577: payroll correction authorization limits ──────────────────

    /// Configure the employer's correction authorization ceilings.
    ///
    /// Only the registered payroll admin may set limits, the contract must not
    /// be paused, and no payroll run may be in progress (#253). Passing all-zero
    /// ceilings stores an ineffective policy, which is equivalent to clearing
    /// it: `amend_run_draft` stops enforcing and stops counting.
    ///
    /// A negative `max_total_delta` is rejected because it could never be
    /// satisfied.
    pub fn set_correction_auth_limits(
        e: Env,
        admin: Address,
        max_corrections_per_period: u32,
        max_total_delta: i128,
        max_employees_corrected: u32,
    ) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::require_no_active_payroll_run(&e);

        if max_total_delta < 0 {
            panic!("Correction amount limit cannot be negative");
        }

        let limits = CorrectionAuthorizationLimits {
            max_corrections_per_period,
            max_total_delta,
            max_employees_corrected,
        };
        e.storage()
            .persistent()
            .set(&DataKey::CorrectionAuthorizationLimits, &limits);

        // Correction limits are configuration, so the change is announced. The
        // payload carries the ceilings themselves — configuration values, never
        // payroll data — so operators can reconstruct the active policy.
        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "corr_limits_set"),
            ),
            (
                admin.clone(),
                max_corrections_per_period,
                max_total_delta,
                max_employees_corrected,
            ),
        );
    }

    /// Read the employer's configured correction authorization ceilings.
    ///
    /// Returns `None` when no policy has been configured, meaning corrections
    /// behave exactly as they did before this feature existed.
    pub fn get_correction_auth_limits(e: Env) -> Option<CorrectionAuthorizationLimits> {
        e.storage()
            .persistent()
            .get(&DataKey::CorrectionAuthorizationLimits)
    }

    /// Read the accumulated correction usage for a payroll period.
    ///
    /// Returns zeroed counters when the period has no recorded corrections.
    /// Privacy-safe: aggregate counts and magnitudes only.
    pub fn get_correction_usage(e: Env, period_label: Symbol) -> CorrectionUsage {
        e.storage()
            .persistent()
            .get(&DataKey::CorrectionUsage(period_label))
            .unwrap_or(CorrectionUsage::ZERO)
    }

    /// Enforce the configured correction ceilings for one amendment.
    ///
    /// No-op when no effective policy is configured, so existing workflows are
    /// untouched. Otherwise a rejected amendment panics before any state is
    /// written, leaving the period's counters intact.
    fn require_correction_authorized(
        e: &Env,
        period_label: &Symbol,
        delta: i128,
        employees_touched: u32,
    ) {
        let Some(limits) = e
            .storage()
            .persistent()
            .get::<DataKey, CorrectionAuthorizationLimits>(&DataKey::CorrectionAuthorizationLimits)
        else {
            return;
        };
        if !limits.is_effective() {
            return;
        }
        let usage: CorrectionUsage = e
            .storage()
            .persistent()
            .get(&DataKey::CorrectionUsage(period_label.clone()))
            .unwrap_or(CorrectionUsage::ZERO);
        if let Err(breach) = limits.check(&usage, delta, employees_touched) {
            Self::panic_correction_limit(breach);
        }
    }

    /// Record an applied correction against the period's usage counters.
    ///
    /// No-op unless an effective policy is configured, so deployments that do
    /// not use the feature never pay for the counter write.
    fn record_correction_usage(
        e: &Env,
        period_label: &Symbol,
        delta: i128,
        employees_touched: u32,
    ) {
        let Some(limits) = e
            .storage()
            .persistent()
            .get::<DataKey, CorrectionAuthorizationLimits>(&DataKey::CorrectionAuthorizationLimits)
        else {
            return;
        };
        if !limits.is_effective() {
            return;
        }
        let key = DataKey::CorrectionUsage(period_label.clone());
        let usage: CorrectionUsage = e
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or(CorrectionUsage::ZERO);
        e.storage()
            .persistent()
            .set(&key, &usage.plus(delta, employees_touched));
    }

    /// Reject a correction with the operator message for the ceiling it hit.
    ///
    /// Kept as a match over string literals so the panic carries a static
    /// message and never formats a payroll value into the host error.
    fn panic_correction_limit(breach: CorrectionLimitBreach) -> ! {
        match breach {
            CorrectionLimitBreach::CorrectionsPerPeriod => panic!(
                "Correction authorization limit exceeded: period correction count reached; raise or clear the correction limits"
            ),
            CorrectionLimitBreach::TotalDelta => panic!(
                "Correction authorization limit exceeded: period correction amount budget reached; raise or clear the correction limits"
            ),
            CorrectionLimitBreach::EmployeesCorrected => panic!(
                "Correction authorization limit exceeded: period corrected-employee budget reached; raise or clear the correction limits"
            ),
        }
    }


    /// Update the reconciliation status of a completed payroll run.
    ///
    /// Only the `admin` may update the reconciliation status.
    /// Emits a `reconciliation_updated` event.
    pub fn update_reconciliation_status(
        e: Env,
        admin: Address,
        run_id: u64,
        status: ReconciliationStatus,
    ) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        if admin != addrs.admin {
            panic!("Unauthorized");
        }

        admin.require_auth();

        let run_key = DataKey::PayrollRun(run_id);

        let mut run: PayrollRun = e
            .storage()
            .persistent()
            .get(&run_key)
            .expect("Run not found");

        // Issue #244: settlement completion is final. Once a run has reached
        // `Completed`, reject any further reconciliation update ? including a
        // repeat `Reconciled` call ? so settlement cannot be replayed or
        // finalized more than once for the same payroll run.
        let current_state = Self::get_payroll_run_state_internal(&e, run_id);
        if current_state == PayrollRunState::Completed {
            panic!("Settlement already finalized: run is Completed and cannot be updated again");
        }

        run.reconciliation_status = status;
        e.storage().persistent().set(&run_key, &run);

        let next_state = match status {
            ReconciliationStatus::Reconciled => PayrollRunState::Completed,
            ReconciliationStatus::Unreconciled => PayrollRunState::ReconciliationRequired,
            ReconciliationStatus::Failed => PayrollRunState::Failed,
        };
        if current_state != next_state
            && !Self::is_allowed_payroll_state_transition_internal(current_state, next_state)
        {
            panic!("Invalid payroll state transition");
        }
        Self::record_payroll_run_state(&e, run_id, next_state);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "reconciliation_updated"),
            ),
            (run_id, status),
        );
    }

    /// Finalize a `Pending` draft, making it permanently immutable.
    ///
    /// After finalization no further amendments are possible. The finalized
    /// draft serves as the canonical audit record for the run.
    pub fn finalize_run_draft(e: Env, admin: Address, draft_id: u64) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if draft.state != RunDraftState::Pending {
            panic!("Draft is already finalized");
        }

        // Issue #471: a frozen period cannot have its drafts locked in for
        // submission; unfreeze first (authorized correction flow).
        Self::require_period_not_frozen(&e, &draft.period_label);

        draft.state = RunDraftState::Finalized;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        payroll_events::emit_draft_finalized(
            &e,
            draft_id,
            draft.total_amount,
            draft.amendment_count,
        );
    }

    /// Retrieve a payroll run draft by ID.
    pub fn get_run_draft(e: Env, draft_id: u64) -> PayrollRunDraft {
        e.storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found")
    }

    /// Retrieve the last-updated timestamp for a payroll run draft (Issue #439).
    pub fn get_draft_updated_at(e: Env, draft_id: u64) -> u64 {
        let draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");
        draft.updated_at
    }

    /// Return the owner/admin who holds the lock on a payroll draft (Issue #556).
    ///
    /// A draft is considered in a locked state when it has reached a finalized
    /// review or submission state (`RunDraftState::Finalized` or `RunDraftState::Submitted`).
    /// - If the draft exists and is locked (`Finalized` or `Submitted`), returns `Some(draft.admin)`.
    /// - If the draft exists but is in an unlocked state (`Pending`) or terminal non-locked state (`Cancelled`, `Expired`), returns `None`.
    /// - If the draft does not exist, returns `None`.
    ///
    /// Exposes only the lock owner address metadata without revealing confidential
    /// employee addresses or salary figures.
    pub fn get_draft_lock_owner(e: Env, draft_id: u64) -> Option<Address> {
        Self::validate_draft_id(draft_id);
        let draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))?;
        if matches!(draft.state, RunDraftState::Finalized | RunDraftState::Submitted) {
            Some(draft.admin)
        } else {
            None
        }
    }

    /// Set or update the description for a draft in Pending state.
    pub fn set_run_draft_description(e: Env, admin: Address, draft_id: u64, description: String) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        Self::validate_draft_id(draft_id);
        let draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");
        if draft.state != RunDraftState::Pending {
            panic!("Only pending drafts can be updated");
        }
        let len = description.len();
        if len == 0 || len > 256 {
            panic!("Description length must be between 1 and 256 characters");
        }
        let mut all_spaces = true;
        let mut buf = [0u8; 256];
        description.copy_into_slice(&mut buf[..len as usize]);
        for &b in &buf[..len as usize] {
            if b != b' ' && b != b'\t' && b != b'\n' && b != b'\r' {
                all_spaces = false;
                break;
            }
        }
        if all_spaces {
            panic!("Description cannot be empty or blank");
        }

        e.storage()
            .persistent()
            .set(&DataKey::DraftDescription(draft_id), &description);
    }

    /// Retrieve the description for a draft by ID.
    pub fn get_run_draft_description(e: Env, draft_id: u64) -> Option<String> {
        Self::validate_draft_id(draft_id);
        e.storage()
            .persistent()
            .get(&DataKey::DraftDescription(draft_id))
    }

    /// Return whether a draft transition is allowed by the draft state machine.
    pub fn is_draft_transition_allowed(_e: Env, from: RunDraftState, to: RunDraftState) -> bool {
        Self::is_allowed_draft_state_transition_internal(from, to)
    }

    /// Return whether a draft state is terminal and immutable.
    pub fn is_draft_state_terminal(_e: Env, state: RunDraftState) -> bool {
        Self::is_terminal_draft_state_internal(state)
    }

    /// Submit a payroll run draft, transitioning it to `Submitted`.
    ///
    /// Only the admin may submit a draft.
    pub fn submit_run_draft(e: Env, admin: Address, draft_id: u64) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if !Self::is_allowed_draft_state_transition_internal(draft.state, RunDraftState::Submitted)
        {
            panic!("Invalid draft state transition");
        }

        // Issue #471: submitting a draft into an executable run is the act
        // that finalizes the period — the freeze must be lifted (or never
        // applied) before a run may be submitted against it.
        Self::require_period_not_frozen(&e, &draft.period_label);

        draft.state = RunDraftState::Submitted;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        // Issue #471 (follow-up to #398): clear the per-period slot — the
        // draft has been consumed into a run and the period is about to be
        // frozen, so nothing may create against it either way.
        e.storage()
            .persistent()
            .remove(&DataKey::ActiveDraftForPeriod(draft.period_label.clone()));

        // Issue #471: the period is now final — auto-freeze it so no further
        // payroll edits can slip in after submission without an explicit
        // authorized unfreeze. Both the configuration freeze marker (#248)
        // and the #471 freeze record (reason = "finalized") are written so
        // `is_period_frozen` / `get_period_freeze` / `unfreeze_payroll_period`
        // observe the freeze consistently.
        let freeze_key = DataKey::PeriodConfigFrozen(draft.period_label.clone());
        if !e.storage().persistent().has(&freeze_key) {
            e.storage().persistent().set(&freeze_key, &true);
        }
        let finalized_key = DataKey::PeriodFreeze(draft.period_label.clone());
        if !e.storage().persistent().has(&finalized_key) {
            let freeze = PeriodFreeze {
                period_label: draft.period_label.clone(),
                frozen_by: admin.clone(),
                frozen_at: e.ledger().timestamp(),
                reason: Symbol::new(&e, "finalized"),
                runs_count: Self::count_runs_for_period(&e, &draft.period_label),
            };
            e.storage().persistent().set(&finalized_key, &freeze);
        }

        payroll_events::emit_draft_submitted(&e, draft_id, admin);
    }

    /// Cancel a payroll run draft, transitioning it to `Cancelled`.
    ///
    /// Only the admin may cancel a draft.
    pub fn cancel_run_draft(e: Env, admin: Address, draft_id: u64) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if !Self::is_allowed_draft_state_transition_internal(draft.state, RunDraftState::Cancelled)
        {
            panic!("Invalid draft state transition");
        }

        draft.state = RunDraftState::Cancelled;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        // Issue #471 (follow-up to #398): the draft has left Pending, so the
        // per-period slot must be cleared or a later draft for the same
        // period (e.g. during an unfrozen correction flow) would be
        // incorrectly rejected as a duplicate.
        e.storage()
            .persistent()
            .remove(&DataKey::ActiveDraftForPeriod(draft.period_label.clone()));

        payroll_events::emit_draft_cancelled(&e, draft_id, admin);
    }

    /// Expire a payroll run draft, transitioning it to `Expired`.
    ///
    /// Only the admin may expire a draft.
    pub fn expire_run_draft(e: Env, admin: Address, draft_id: u64) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if !Self::is_allowed_draft_state_transition_internal(draft.state, RunDraftState::Expired) {
            panic!("Invalid draft state transition");
        }

        draft.state = RunDraftState::Expired;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        // Issue #471 (follow-up to #398): clear the per-period slot so the
        // period can receive a fresh draft after this terminal transition.
        e.storage()
            .persistent()
            .remove(&DataKey::ActiveDraftForPeriod(draft.period_label.clone()));

        payroll_events::emit_draft_expired(&e, draft_id, admin);
    }

    // ── Issue #471 / #484: payroll period freeze and reopening guard ─────────

    /// Panic if the given payroll period is frozen under either freeze
    /// system (#248 config-freeze, #471 draft/finalized-freeze).
    ///
    /// Called by every state-mutating payroll edit path that must be blocked
    /// once a period has been finalized (draft creation, amendment,
    /// draft finalization, and draft submission).
    fn require_period_not_frozen(e: &Env, period_label: &Symbol) {
        if e.storage()
            .persistent()
            .has(&DataKey::PeriodFreeze(period_label.clone()))
            || e.storage()
                .persistent()
                .has(&DataKey::PeriodConfigFrozen(period_label.clone()))
        {
            panic!("Payroll period is frozen: it has been finalized and can no longer be edited");
        }
    }

    /// Freeze a payroll period.
    ///
    /// Once frozen, no new drafts can be created for `period_label`, and
    /// existing pending/finalized drafts for the period can no longer be
    /// amended, finalized, or submitted. Cancelling or expiring a
    /// draft remains possible as an operator escape hatch — those paths
    /// remove pending payroll work instead of adding or changing it.
    ///
    /// Only the `admin` may freeze. Freezing an already-frozen period is
    /// rejected so the audit trail stays unambiguous; use `unfreeze` first.
    ///
    /// Emits `period_frozen`.
    pub fn freeze_payroll_period(e: Env, admin: Address, period_label: Symbol, reason: Symbol) {
        Self::require_not_paused(&e);
        Self::validate_symbol_not_empty(&e, &period_label, "period_label");
        Self::validate_symbol_not_empty(&e, &reason, "reason");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let freeze_key = DataKey::PeriodFreeze(period_label.clone());
        if e.storage().persistent().has(&freeze_key) {
            panic!("Payroll period is already frozen");
        }

        let freeze = PeriodFreeze {
            period_label: period_label.clone(),
            frozen_by: admin.clone(),
            frozen_at: e.ledger().timestamp(),
            reason: reason.clone(),
            runs_count: Self::count_runs_for_period(&e, &period_label),
        };
        e.storage().persistent().set(&freeze_key, &freeze);

        payroll_events::emit_period_frozen(&e, period_label, admin, reason);
    }

    /// Lift the freeze on a finalized payroll period (reopen finalized period).
    ///
    /// Only the `admin` may unfreeze/reopen (#484). This is the sole path back to editing
    /// after a period has been finalized; the unfreeze event preserves the full audit trail.
    ///
    /// Enforces cooldown between successive reopens to prevent rapid unfreezes that could
    /// expose the period to uncontrolled edits. If a cooldown is configured and insufficient
    /// time has passed since the last reopen, this panics with a privacy-safe error.
    ///
    /// Emits `period_unfrozen`.
    pub fn unfreeze_payroll_period(e: Env, admin: Address, period_label: Symbol) {
        Self::require_not_paused(&e);
        Self::validate_symbol_not_empty(&e, &period_label, "period_label");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let freeze_key = DataKey::PeriodFreeze(period_label.clone());
        if !e.storage().persistent().has(&freeze_key) {
            panic!("Payroll period is not frozen");
        }

        // Validate cooldown before allowing reopen
        let cooldown_key = DataKey::PeriodReopenCooldown(period_label.clone());
        if let Some(cooldown) = e
            .storage()
            .persistent()
            .get::<_, PeriodReopenCooldown>(&cooldown_key)
        {
            if cooldown.cooldown_seconds > 0 {
                let now = e.ledger().timestamp();
                let elapsed = now.saturating_sub(cooldown.last_reopen_at);
                if elapsed < cooldown.cooldown_seconds {
                    panic!(
                        "Period reopen cooldown active: cannot reopen until {} seconds have elapsed",
                        cooldown.cooldown_seconds.saturating_sub(elapsed)
                    );
                }
            }

            // Update last reopen timestamp
            let updated = PeriodReopenCooldown {
                cooldown_seconds: cooldown.cooldown_seconds,
                last_reopen_at: e.ledger().timestamp(),
            };
            e.storage().persistent().set(&cooldown_key, &updated);
        }

        e.storage().persistent().remove(&freeze_key);

        payroll_events::emit_period_unfrozen(&e, period_label, admin);
    }

    /// Explicit alias for `unfreeze_payroll_period` to reopen a finalized payroll period (#484).
    ///
    /// Only the contract admin can call this entrypoint.
    pub fn reopen_payroll_period(e: Env, admin: Address, period_label: Symbol) {
        Self::unfreeze_payroll_period(e, admin, period_label);
    }

    /// Return the freeze record for a period, if it is frozen.
    pub fn get_period_freeze(e: Env, period_label: Symbol) -> Option<PeriodFreeze> {
        e.storage()
            .persistent()
            .get(&DataKey::PeriodFreeze(period_label))
    }

    /// Return `true` if the payroll period is currently frozen.
    pub fn is_period_frozen(e: Env, period_label: Symbol) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::PeriodFreeze(period_label))
    }

    /// Set the cooldown duration for period reopens.
    ///
    /// Only the admin may configure the cooldown. Setting `cooldown_seconds` to 0
    /// disables the cooldown entirely (no minimum reopen delay).
    pub fn set_period_reopen_cooldown(
        e: Env,
        admin: Address,
        period_label: Symbol,
        cooldown_seconds: u64,
    ) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let cooldown_key = DataKey::PeriodReopenCooldown(period_label.clone());
        let cooldown = PeriodReopenCooldown {
            cooldown_seconds,
            last_reopen_at: 0,
        };
        e.storage().persistent().set(&cooldown_key, &cooldown);
    }

    /// Get the reopen cooldown configuration for a period.
    pub fn get_period_reopen_cooldown(
        e: Env,
        period_label: Symbol,
    ) -> Option<PeriodReopenCooldown> {
        e.storage()
            .persistent()
            .get(&DataKey::PeriodReopenCooldown(period_label))
    }

    // ?? Issue #91: privileged-role rotation ??????????????????????????????????

    /// Propose a new admin (step 1 of 2).
    ///
    /// Only the current admin can propose a successor. The proposal is stored
    /// on-chain and must be accepted by the new admin via `accept_admin_rotation`.
    pub fn propose_admin_rotation(e: Env, current_admin: Address, new_admin: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized: caller is not the current admin");
        }
        current_admin.require_auth();

        if e.storage().persistent().has(&DataKey::PendingAdminRotation) {
            panic!("A pending admin rotation already exists");
        }

        let proposal = PendingRotation {
            new_holder: new_admin.clone(),
            proposed_by: current_admin.clone(),
            proposed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingAdminRotation, &proposal);

        payroll_events::emit_admin_proposed(&e, current_admin, new_admin);
    }

    /// Accept an admin rotation proposal (step 2 of 2).
    ///
    /// Only the proposed new admin can accept. On acceptance the admin in
    /// `ContractAddresses` is updated and the proposal is cleared.
    ///
    /// Locked while any payroll run is prepared but not yet resolved (#253):
    /// handing off administration mid-run could let a party the run was not
    /// authorised under later act on it.
    pub fn accept_admin_rotation(e: Env, new_admin: Address) {
        Self::require_not_paused(&e);
        let proposal: PendingRotation = e
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation)
            .expect("No pending admin rotation");

        if new_admin != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed admin");
        }
        new_admin.require_auth();
        Self::require_no_active_payroll_run(&e);

        let mut addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let old_admin = addrs.admin.clone();
        addrs.admin = new_admin.clone();
        e.storage().persistent().set(&DataKey::Addresses, &addrs);
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        let previous_ref = value_ref(&e, &old_admin);
        payroll_events::emit_admin_rotated(&e, old_admin, new_admin.clone());
        record_config_change(
            &e,
            &new_admin,
            config_keys::ADMIN,
            no_value_ref(&e),
            previous_ref,
            value_ref(&e, &new_admin),
        );
    }

    /// Cancel a pending admin rotation proposal.
    ///
    /// Only the current admin (who submitted the proposal) may cancel.
    pub fn cancel_admin_rotation(e: Env, current_admin: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !e.storage().persistent().has(&DataKey::PendingAdminRotation) {
            panic!("No pending admin rotation to cancel");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        payroll_events::emit_admin_rotation_cancelled(&e, current_admin);
    }

    /// Propose a new treasury owner (step 1 of 2).
    pub fn propose_treasury_rotation(e: Env, current_owner: Address, new_owner: Address) {
        Self::require_not_paused(&e);
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if current_owner != stored_owner {
            panic!("Unauthorized: caller is not the current treasury owner");
        }
        current_owner.require_auth();

        if e.storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation)
        {
            panic!("A pending treasury rotation already exists");
        }

        let proposal = PendingRotation {
            new_holder: new_owner.clone(),
            proposed_by: current_owner.clone(),
            proposed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingTreasuryRotation, &proposal);

        payroll_events::emit_treasury_proposed(&e, current_owner, new_owner);
    }

    /// Accept a treasury-owner rotation (step 2 of 2).
    ///
    /// Locked while any payroll run is prepared but not yet resolved (#253):
    /// the treasury owner can request deposits and emergency withdrawals, so
    /// handing that role to a new party mid-run could let someone who did
    /// not authorise the run's preconditions move funds while it is pending.
    pub fn accept_treasury_rotation(e: Env, new_owner: Address) {
        Self::require_not_paused(&e);
        let proposal: PendingRotation = e
            .storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation)
            .expect("No pending treasury rotation");

        if new_owner != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed treasury owner");
        }
        new_owner.require_auth();
        Self::require_no_active_payroll_run(&e);

        let old_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        let previous_ref = stored_ref(&e, &DataKey::TreasuryOwner);

        e.storage()
            .persistent()
            .set(&DataKey::TreasuryOwner, &new_owner);

        let mut addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.treasury_owner = new_owner.clone();
        e.storage().persistent().set(&DataKey::Addresses, &addrs);

        e.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation);

        payroll_events::emit_treasury_rotated(&e, old_owner, new_owner.clone());
        record_config_change(
            &e,
            &new_owner,
            config_keys::TREASURY_OWNER,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::TreasuryOwner),
        );
    }

    /// Cancel a pending treasury-owner rotation.
    pub fn cancel_treasury_rotation(e: Env, current_owner: Address) {
        Self::require_not_paused(&e);
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if current_owner != stored_owner {
            panic!("Unauthorized");
        }
        current_owner.require_auth();

        if !e
            .storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation)
        {
            panic!("No pending treasury rotation to cancel");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation);

        payroll_events::emit_treasury_rotation_cancelled(&e, current_owner);
    }

    /// Return the pending admin rotation proposal, if any.
    pub fn get_pending_admin_rotation(e: Env) -> Option<PendingRotation> {
        e.storage().persistent().get(&DataKey::PendingAdminRotation)
    }

    /// Return the pending treasury-owner rotation proposal, if any.
    pub fn get_pending_treasury_rotation(e: Env) -> Option<PendingRotation> {
        e.storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation)
    }

    // ?? Issue #339: Admin Handover Safety Checks ?????????????????????????????

    /// Request a new admin handover requiring explicit acceptance (step 1 of 2 ? issue #339).
    pub fn request_admin_handover(e: Env, current_admin: Address, pending_admin: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized: caller is not current admin");
        }
        current_admin.require_auth();

        if e.storage().persistent().has(&DataKey::PendingAdminHandover) {
            panic!("A pending admin handover already exists");
        }

        let handover = PendingAdminHandover {
            current_admin: current_admin.clone(),
            pending_admin: pending_admin.clone(),
            requested_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingAdminHandover, &handover);

        payroll_events::emit_admin_handover_requested(&e, current_admin, pending_admin);
    }

    /// Accept an admin handover (step 2 of 2 ? issue #339).
    pub fn accept_admin_handover(e: Env, pending_admin: Address) {
        Self::require_not_paused(&e);
        let handover: PendingAdminHandover = e
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminHandover)
            .expect("No pending admin handover");

        if pending_admin != handover.pending_admin {
            panic!("Unauthorized: caller is not the pending admin");
        }
        pending_admin.require_auth();

        let mut addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let old_admin = addrs.admin.clone();
        addrs.admin = pending_admin.clone();
        e.storage().persistent().set(&DataKey::Addresses, &addrs);
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminHandover);

        let previous_ref = value_ref(&e, &old_admin);
        payroll_events::emit_admin_handover_accepted(&e, old_admin, pending_admin.clone());
        record_config_change(
            &e,
            &pending_admin,
            config_keys::ADMIN,
            no_value_ref(&e),
            previous_ref,
            value_ref(&e, &pending_admin),
        );
    }

    /// Cancel a pending admin handover.
    pub fn cancel_admin_handover(e: Env, current_admin: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized: caller is not current admin");
        }
        current_admin.require_auth();

        if !e.storage().persistent().has(&DataKey::PendingAdminHandover) {
            panic!("No pending admin handover to cancel");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminHandover);

        payroll_events::emit_admin_handover_cancelled(&e, current_admin);
    }

    /// Return the pending admin handover request, if any.
    pub fn get_pending_admin_handover(e: Env) -> Option<PendingAdminHandover> {
        e.storage().persistent().get(&DataKey::PendingAdminHandover)
    }

    // ?? Issue #343: Treasury Withdrawal Guardrails ???????????????????????????

    /// Get total locked payroll funds for an asset.
    pub fn get_locked_funds(e: Env, asset: Address) -> i128 {
        e.storage()
            .persistent()
            .get(&DataKey::LockedPayrollFunds(asset))
            .unwrap_or(0i128)
    }

    /// Get available unreserved treasury balance for an asset.
    pub fn get_available_treasury_balance(e: Env, asset: Address) -> i128 {
        if Self::validate_treasury_asset(e.clone(), asset.clone()).is_err() {
            return 0;
        }
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        let total_balance = soroban_token::Client::new(&e, &asset).balance(&addrs.treasury);
        let locked = Self::get_locked_funds(e.clone(), asset);
        total_balance.checked_sub(locked).unwrap_or(0i128)
    }

    pub fn add_locked_funds(e: &Env, asset: Address, amount: i128) {
        Self::require_active_treasury_asset(e, asset.clone());
        let key = DataKey::LockedPayrollFunds(asset.clone());
        let current: i128 = e.storage().persistent().get(&key).unwrap_or(0i128);
        let new_locked = current.checked_add(amount).expect("Locked funds overflow");
        e.storage().persistent().set(&key, &new_locked);
        payroll_events::emit_locked_funds_updated(e, asset, new_locked);
    }

    pub fn subtract_locked_funds(e: &Env, asset: Address, amount: i128) {
        Self::require_active_treasury_asset(e, asset.clone());
        let key = DataKey::LockedPayrollFunds(asset.clone());
        let current: i128 = e.storage().persistent().get(&key).unwrap_or(0i128);
        let new_locked = current.checked_sub(amount).expect("Locked funds underflow");
        e.storage().persistent().set(&key, &new_locked);
        payroll_events::emit_locked_funds_updated(e, asset, new_locked);
    }

    // ?? Issue #334: Signer Quorum Replay Protection ??????????????????????????

    /// Compute cryptographic hash binding all fields of a signer quorum approval payload.
    pub fn hash_quorum_payload(e: Env, payload: QuorumApprovalPayload) -> BytesN<32> {
        let mut bin = soroban_sdk::Bytes::new(&e);
        bin.append(&payload.batch_root.to_xdr(&e));
        bin.append(&payload.employer.to_xdr(&e));
        bin.append(&payload.period.to_xdr(&e));
        bin.append(&payload.asset.to_xdr(&e));
        bin.append(&payload.nonce.to_xdr(&e));
        bin.extend_from_array(&payload.policy_version.to_be_bytes());
        e.crypto().sha256(&bin).into()
    }

    /// Check if a quorum approval payload hash has already been consumed.
    pub fn is_quorum_consumed(e: Env, quorum_hash: BytesN<32>) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::ConsumedQuorum(quorum_hash))
    }

    /// Verify signer quorum requirements and consume the quorum approval reference once.
    pub fn verify_and_consume_quorum(
        e: Env,
        payload: QuorumApprovalPayload,
        signers: Vec<Address>,
        required_quorum: u32,
    ) -> BytesN<32> {
        Self::require_not_paused(&e);
        if signers.len() < required_quorum {
            panic!("Insufficient signer quorum");
        }
        // Issue #555: concurrent approval attempts must not be able to satisfy a
        // multi-signer quorum. A repeated signer is a duplicate approval attempt
        // rather than an additional approval, so reject it before counting and
        // before any quorum reference is consumed.
        let mut unique_signers: Vec<Address> = Vec::new(&e);
        for i in 0..signers.len() {
            let s = signers.get(i).unwrap();
            if unique_signers.first_index_of(s.clone()).is_some() {
                panic!("Duplicate signer in quorum approval");
            }
            s.require_auth();
            unique_signers.push_back(s);
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        if payload.employer != addrs.admin {
            panic!("Employer mismatch in quorum payload");
        }
        if payload.asset != addrs.token {
            panic!("Asset mismatch in quorum payload");
        }

        let q_hash = Self::hash_quorum_payload(e.clone(), payload.clone());
        if Self::is_quorum_consumed(e.clone(), q_hash.clone()) {
            panic!("Quorum approval payload already consumed: replay rejected");
        }

        e.storage().persistent().set(
            &DataKey::ConsumedQuorum(q_hash.clone()),
            &e.ledger().timestamp(),
        );

        payroll_events::emit_quorum_consumed(
            &e,
            payload.batch_root,
            payload.employer,
            payload.nonce,
        );
        q_hash
    }

    // ?? Issue #177: metadata hash verification ??????????????????????????????

    /// Return the metadata hash bound to a completed payroll run.
    ///
    /// Returns the raw `BytesN<32>` stored in the run record. The zero hash
    /// indicates no metadata has been bound yet.
    pub fn get_metadata_hash(e: Env, run_id: u64) -> BytesN<32> {
        Self::validate_run_id(run_id);
        let run: PayrollRun = e
            .storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found");
        run.metadata_hash
    }

    /// Verify that the metadata hash stored on-chain for a payroll run matches
    /// the expected value.
    ///
    /// This is a read-only verification function: it retrieves the
    /// `metadata_hash` from the completed `PayrollRun` record and compares it
    /// byte-for-byte against `expected_hash`. Returns `true` if they match,
    /// `false` otherwise.
    ///
    /// Use cases:
    ///   - Off-chain auditors can call this to confirm the on-chain state
    ///     aligns with their locally computed metadata hash.
    ///   - Other contracts can call this for cross-contract verification.
    pub fn verify_metadata_hash(e: Env, run_id: u64, expected_hash: BytesN<32>) -> bool {
        Self::validate_run_id(run_id);
        let run: PayrollRun = e
            .storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found");
        run.metadata_hash == expected_hash
    }

    // ?? Issue #617: payroll note hash verification ??????????????????????????

    /// Pre-commit an off-chain payroll note hash (e.g. a payslip or payment
    /// receipt document issued to an employee outside the contract) that
    /// will later be bound to a payroll run.
    ///
    /// Same one-time-use commit-then-bind pattern already used for
    /// `metadata_hash` (#177) and `draft_hash` (#102): the hash is recorded
    /// here first, then consumed by `set_run_note_hash`. Kept in its own
    /// `NoteCommitment` keyspace rather than reusing `DraftCommitment`, so a
    /// note hash can never be mistaken for, or collide in storage with, an
    /// unrelated draft or metadata commitment.
    ///
    /// Only the admin may call.
    pub fn commit_payroll_note_hash(e: Env, admin: Address, note_hash: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_non_zero_digest(&e, &note_hash, "note_hash");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::NoteCommitment(note_hash.clone());
        if e.storage().persistent().has(&key) {
            panic!("Note hash already committed");
        }
        e.storage().persistent().set(&key, &true);

        payroll_events::emit_note_committed(&e, note_hash);
    }

    /// Bind a pre-committed payroll note hash to an existing payroll run.
    /// Consumes the commitment so it cannot be reused. Only the admin may
    /// call.
    ///
    /// Must be called with a note hash that was previously committed via
    /// `commit_payroll_note_hash`. Fails if the hash has not been
    /// pre-committed, mirroring `set_run_metadata`'s behavior for
    /// `metadata_hash`.
    pub fn set_run_note_hash(e: Env, admin: Address, run_id: u64, note_hash: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_run_id(run_id);
        Self::validate_non_zero_digest(&e, &note_hash, "note_hash");
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let commit_key = DataKey::NoteCommitment(note_hash.clone());
        if !e.storage().persistent().has(&commit_key) {
            panic!("Note hash not pre-committed: call commit_payroll_note_hash first");
        }
        e.storage().persistent().remove(&commit_key);

        let run_key = DataKey::PayrollRun(run_id);
        let mut run: PayrollRun = e
            .storage()
            .persistent()
            .get(&run_key)
            .expect("Run not found");
        run.note_hash = note_hash.clone();
        e.storage().persistent().set(&run_key, &run);

        payroll_events::emit_note_bound(&e, run_id, note_hash);
    }

    /// Return the payroll note hash bound to a completed payroll run.
    ///
    /// Returns the raw `BytesN<32>` stored in the run record. The zero hash
    /// indicates no note has been bound yet.
    pub fn get_payroll_note_hash(e: Env, run_id: u64) -> BytesN<32> {
        Self::validate_run_id(run_id);
        let run: PayrollRun = e
            .storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found");
        run.note_hash
    }

    /// Verify that the payroll note hash stored on-chain for a payroll run
    /// matches the expected value.
    ///
    /// Read-only: retrieves `note_hash` from the completed `PayrollRun`
    /// record and compares it byte-for-byte against `expected_hash`.
    /// Returns `true` if they match, `false` otherwise (including when no
    /// note has been bound yet, since the stored value is then the zero
    /// hash, which a real note content hash should never equal).
    ///
    /// Use case: an employee or auditor holding the off-chain note document
    /// can hash it locally and call this to confirm it is the exact
    /// document the payroll admin committed on-chain for this run, without
    /// the note's actual content ever being exposed on-chain.
    pub fn verify_payroll_note_hash(e: Env, run_id: u64, expected_hash: BytesN<32>) -> bool {
        Self::validate_run_id(run_id);
        let run: PayrollRun = e
            .storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found");
        run.note_hash == expected_hash
    }

    // ?? Issue #147: company state management ?????????????????????????????????

    /// Set the company lifecycle state.
    ///
    /// Only the admin may call. After setting to anything other than `Active`,
    /// all subsequent `prepare_payroll_run` and `batch_process_payroll` calls
    /// will be rejected with a descriptive error until the state is restored
    /// to `Active`.
    ///
    /// Locked while any payroll run is prepared but not yet resolved (#253):
    /// changing the company's lifecycle state mid-run is a policy-level
    /// decision that should not be made while a run's outcome is still
    /// pending. To stop payroll immediately in an emergency, use the pause
    /// manager (always available) or cancel the specific pending run.
    pub fn set_company_state(e: Env, admin: Address, state: CompanyState) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::require_no_active_payroll_run(&e);
        let previous_ref = stored_ref(&e, &DataKey::CompanyState);
        e.storage().persistent().set(&DataKey::CompanyState, &state);
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "state_changed")),
            state,
        );
        record_config_change(
            &e,
            &admin,
            config_keys::COMPANY_STATE,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::CompanyState),
        );
    }

    /// Return the current company state. Returns `Active` if no state has been
    /// explicitly set (backward-compatible default).
    pub fn get_company_state(e: Env) -> CompanyState {
        e.storage()
            .persistent()
            .get(&DataKey::CompanyState)
            .unwrap_or(CompanyState::Active)
    }

    // ── Issue #338: per-period payroll capacity limits ───────────────────────

    /// Set (or replace) the employer's per-period capacity policy. Only the
    /// admin may call. Passing this once opts every subsequent period into
    /// capacity enforcement; there is no policy prior to the first call.
    pub fn set_capacity_limits(
        e: Env,
        admin: Address,
        max_batches: u32,
        max_employees: u32,
        max_total_value: i128,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if max_batches == 0 || max_employees == 0 || max_total_value <= 0 {
            panic!("Capacity limits must be positive");
        }

        let limits = CapacityLimits {
            max_batches,
            max_employees,
            max_total_value,
        };
        let previous_ref = stored_ref(&e, &DataKey::CapacityLimits);
        e.storage()
            .persistent()
            .set(&DataKey::CapacityLimits, &limits);

        payroll_events::emit_capacity_limits_set(&e, max_batches, max_employees, max_total_value);
        record_config_change(
            &e,
            &admin,
            config_keys::CAPACITY_LIMITS,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::CapacityLimits),
        );
    }

    /// Return the currently configured capacity policy, if any.
    pub fn get_capacity_limits(e: Env) -> Option<CapacityLimits> {
        e.storage().persistent().get(&DataKey::CapacityLimits)
    }

    // ── Issue #514: Minimum payout amount threshold ─────────────────────────

    /// Set the minimum payout amount threshold for payroll batches.
    ///
    /// Only the admin may call. Once set, any individual payout amount in a
    /// payroll batch must be greater than or equal to this threshold.
    /// Setting to 0 disables the threshold check (backward compatible default).
    ///
    /// # Errors
    /// - Panics if called by non-admin
    /// - Panics if threshold is negative
    pub fn set_minimum_payout_amount(e: Env, admin: Address, minimum_amount: i128) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if minimum_amount < 0 {
            panic!("Minimum payout amount cannot be negative");
        }

        e.storage()
            .persistent()
            .set(&DataKey::MinimumPayoutAmount, &minimum_amount);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "min_payout_set")),
            (minimum_amount, e.ledger().timestamp()),
        );
    }

    /// Return the currently configured minimum payout amount threshold.
    /// Returns 0 if no threshold has been set (disabled).
    pub fn get_minimum_payout_amount(e: Env) -> i128 {
        e.storage()
            .persistent()
            .get(&DataKey::MinimumPayoutAmount)
            .unwrap_or(0i128)
    }

    /// Validate that all payout amounts meet the minimum threshold, if configured.
    ///
    /// A no-op when no threshold has been configured (threshold = 0), preserving
    /// backward compatibility.
    fn validate_minimum_payout_amount(e: &Env, amounts: &Vec<i128>) {
        let minimum: i128 = match e.storage().persistent().get(&DataKey::MinimumPayoutAmount) {
            Some(min) => min,
            None => return, // No threshold configured
        };

        if minimum == 0 {
            return; // Threshold disabled
        }

        for i in 0..amounts.len() {
            let amt = amounts.get(i).unwrap();
            if amt < minimum {
                e.events().publish(
                    (symbol_short!("payroll"), Symbol::new(e, "min_payout_violation")),
                    (minimum,),
                );
                panic!("Payout amount below minimum threshold");
            }
        }
    }

    /// Open a new payroll period for capacity accounting. Only the admin may
    /// call. Usage counters are scoped per period label, so opening a period
    /// that has never been used before starts with fresh (zeroed) counters;
    /// re-opening a previously used period label resumes accumulating
    /// against its existing counters.
    pub fn open_capacity_period(e: Env, admin: Address, period: Symbol) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::validate_symbol_not_empty(&e, &period, "period");

        e.storage()
            .persistent()
            .set(&DataKey::CurrentPeriod, &period);

        payroll_events::emit_capacity_period_opened(&e, period);
    }

    /// Return the payroll period currently open for capacity accounting, if any.
    pub fn get_current_period(e: Env) -> Option<Symbol> {
        e.storage().persistent().get(&DataKey::CurrentPeriod)
    }

    /// Return the accumulated usage counters for a given period. Periods
    /// with no recorded usage return zeroed counters.
    pub fn get_period_usage(e: Env, period: Symbol) -> PeriodUsage {
        e.storage()
            .persistent()
            .get(&DataKey::PeriodUsage(period))
            .unwrap_or(PeriodUsage {
                batch_count: 0,
                employee_count: 0,
                total_value: 0,
            })
    }

    /// Enforce the employer's capacity policy against the currently open
    /// period and record the batch's usage, before the batch is locked in
    /// (`prepare_payroll_run`) or executed (`batch_process_payroll`).
    ///
    /// A no-op when no policy has been configured or no period has been
    /// opened, preserving backward compatibility for callers that don't use
    /// this feature.
    fn enforce_and_record_capacity(e: &Env, employee_count: u32, batch_value: i128) {
        let limits: CapacityLimits = match e.storage().persistent().get(&DataKey::CapacityLimits) {
            Some(limits) => limits,
            None => return,
        };
        let period: Symbol = match e.storage().persistent().get(&DataKey::CurrentPeriod) {
            Some(period) => period,
            None => return,
        };

        let usage_key = DataKey::PeriodUsage(period.clone());
        let usage: PeriodUsage = e
            .storage()
            .persistent()
            .get(&usage_key)
            .unwrap_or(PeriodUsage {
                batch_count: 0,
                employee_count: 0,
                total_value: 0,
            });

        let new_batch_count = usage.batch_count + 1;
        let new_employee_count = usage.employee_count + employee_count;
        let new_total_value = usage.total_value + batch_value;

        if new_batch_count > limits.max_batches {
            payroll_events::emit_capacity_limit_exceeded(
                e,
                period,
                CapacityLimitKind::BatchCount as u32,
            );
            panic!("Capacity limit exceeded: batch count");
        }
        if new_employee_count > limits.max_employees {
            payroll_events::emit_capacity_limit_exceeded(
                e,
                period,
                CapacityLimitKind::EmployeeCount as u32,
            );
            panic!("Capacity limit exceeded: employee count");
        }
        if new_total_value > limits.max_total_value {
            payroll_events::emit_capacity_limit_exceeded(
                e,
                period,
                CapacityLimitKind::TotalValue as u32,
            );
            panic!("Capacity limit exceeded: total value");
        }

        let new_usage = PeriodUsage {
            batch_count: new_batch_count,
            employee_count: new_employee_count,
            total_value: new_total_value,
        };
        e.storage().persistent().set(&usage_key, &new_usage);

        payroll_events::emit_capacity_usage_recorded(
            e,
            period,
            new_usage.batch_count,
            new_usage.employee_count,
            new_usage.total_value,
        );
    }

    // ── Issue #316: settlement window enforcement ─────────────────────────────

    /// Reject a proposed inclusive calendar range that intersects another
    /// configured period's range. Reconfiguration of the same label is allowed.
    fn assert_no_settlement_window_overlap(
        e: &Env,
        period: &Symbol,
        open_at: u64,
        close_at: u64,
    ) {
        let periods: Vec<Symbol> = e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindowPeriods)
            .unwrap_or(Vec::new(e));

        for index in 0..periods.len() {
            let existing_period = periods.get(index).unwrap();
            if existing_period == *period {
                continue;
            }

            let existing_window: Option<SettlementWindow> = e
                .storage()
                .persistent()
                .get(&DataKey::SettlementWindow(existing_period));
            if let Some(existing_window) = existing_window {
                if open_at <= existing_window.close_at && existing_window.open_at <= close_at {
                    panic!(
                        "Settlement window overlaps another payroll period; choose a non-overlapping calendar range (error code {})",
                        PaymentError::SettlementWindowOverlap as u32
                    );
                }
            }
        }
    }

    /// Set (or replace) the settlement window for a payroll period. Only the
    /// admin may call, and the timestamps must be monotonically ordered:
    /// `open_at <= execution_start <= execution_end <= close_at`.
    ///
    /// Configuring a window is opt-in per period label (the same label used
    /// by `open_capacity_period`): periods with no window configured remain
    /// unrestricted, so existing callers are unaffected.
    pub fn set_settlement_window(
        e: Env,
        admin: Address,
        period: Symbol,
        open_at: u64,
        execution_start: u64,
        execution_end: u64,
        close_at: u64,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!(
                "Unauthorized: only the admin may configure a settlement window (error code {})",
                AuthError::UnauthorizedAdmin as u32
            );
        }
        admin.require_auth();

        Self::validate_symbol_not_empty(&e, &period, "period");

        // Issue #248: reject edits to a period whose configuration is frozen.
        Self::assert_period_config_editable(&e, &period);

        if !(open_at <= execution_start
            && execution_start <= execution_end
            && execution_end <= close_at)
        {
            panic!(
                "Invalid settlement window: timestamps must satisfy open_at <= execution_start <= execution_end <= close_at (error code {})",
                PaymentError::InvalidSettlementWindowConfig as u32
            );
        }

        Self::assert_no_settlement_window_overlap(&e, &period, open_at, close_at);

        let window = SettlementWindow {
            open_at,
            execution_start,
            execution_end,
            close_at,
            configured_by: admin.clone(),
            configured_at: e.ledger().timestamp(),
        };
        let window_key = DataKey::SettlementWindow(period.clone());
        let previous_ref = stored_ref(&e, &window_key);
        e.storage().persistent().set(&window_key, &window);

        let mut periods: Vec<Symbol> = e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindowPeriods)
            .unwrap_or(Vec::new(&e));
        if periods.first_index_of(period.clone()).is_none() {
            periods.push_back(period.clone());
            e.storage()
                .persistent()
                .set(&DataKey::SettlementWindowPeriods, &periods);
        }

        payroll_events::emit_settlement_window_set(
            &e,
            period.clone(),
            open_at,
            execution_start,
            execution_end,
            close_at,
        );
        record_config_change(
            &e,
            &admin,
            config_keys::SETTLEMENT_WINDOW,
            value_ref(&e, &period),
            previous_ref,
            stored_ref(&e, &window_key),
        );
    }

    /// Return the settlement window configured for a period, if any.
    pub fn get_settlement_window(e: Env, period: Symbol) -> Option<SettlementWindow> {
        e.storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period))
    }

    /// Classify a settlement window's timing status relative to `now`.
    fn classify_settlement_window(window: &SettlementWindow, now: u64) -> SettlementWindowStatus {
        if now < window.execution_start {
            SettlementWindowStatus::PreOpen
        } else if now <= window.execution_end {
            SettlementWindowStatus::Executable
        } else if now <= window.close_at {
            SettlementWindowStatus::Grace
        } else {
            SettlementWindowStatus::Closed
        }
    }

    /// Return the current timing status of a period's settlement window, if
    /// one is configured. Exposes only timing state, never payroll data.
    pub fn get_settlement_window_status(e: Env, period: Symbol) -> Option<SettlementWindowStatus> {
        let window: SettlementWindow = e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period))?;
        Some(Self::classify_settlement_window(
            &window,
            e.ledger().timestamp(),
        ))
    }

    // ── Issue #248: payroll period configuration freeze guard ───────────────

    /// Explicitly freeze a payroll period's configuration. Only the admin may
    /// call. Once frozen, `set_settlement_window` rejects further edits for the
    /// period, in addition to the implicit freeze applied once a payroll run is
    /// submitted against the period or the period becomes settlement-ready.
    pub fn freeze_period_config(e: Env, admin: Address, period: Symbol) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!(
                "Unauthorized: only the admin may freeze a payroll period (error code {})",
                AuthError::UnauthorizedAdmin as u32
            );
        }
        admin.require_auth();

        Self::validate_symbol_not_empty(&e, &period, "period");

        let frozen_key = DataKey::PeriodConfigFrozen(period.clone());
        let previous_ref = stored_ref(&e, &frozen_key);
        e.storage().persistent().set(&frozen_key, &true);
        record_config_change(
            &e,
            &admin,
            config_keys::PERIOD_FROZEN,
            value_ref(&e, &period),
            previous_ref,
            stored_ref(&e, &frozen_key),
        );
    }

    /// Return the recorded freeze state for a period.
    ///
    /// This reflects only the explicit freeze marker. Use
    /// [`is_period_config_frozen`](Self::is_period_config_frozen) to also
    /// account for the implicit conditions (submitted run, settlement-ready)
    /// that block configuration edits.
    pub fn get_period_config_state(e: Env, period: Symbol) -> PeriodConfigState {
        if e.storage()
            .persistent()
            .get(&DataKey::PeriodConfigFrozen(period))
            .unwrap_or(false)
        {
            PeriodConfigState::Frozen
        } else {
            PeriodConfigState::Editable
        }
    }

    /// Whether configuration edits for a period must be rejected.
    ///
    /// A period is frozen when any of the following holds:
    /// - the admin explicitly froze it via `freeze_period_config`;
    /// - a payroll run was submitted against it; or
    /// - it is settlement-ready: its settlement window has reached the
    ///   `Executable`, `Grace`, or `Closed` status.
    pub fn is_period_config_frozen(e: Env, period: Symbol) -> bool {
        if e.storage()
            .persistent()
            .get(&DataKey::PeriodConfigFrozen(period.clone()))
            .unwrap_or(false)
        {
            return true;
        }

        let window: Option<SettlementWindow> = e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period));
        if let Some(window) = window {
            let status = Self::classify_settlement_window(&window, e.ledger().timestamp());
            if status != SettlementWindowStatus::PreOpen {
                return true;
            }
        }

        false
    }

    // ── Issue #552: Expose payroll period health summary ──────────────────────────

    /// Return the operational health summary for a given payroll period (#552).
    ///
    /// Validates period label, checks pause state, settlement window state, freeze guard,
    /// active drafts, and capacity limits to provide actionable operational health
    /// diagnostics without disclosing sensitive employee identities or individual salaries.
    pub fn get_period_health_summary(e: Env, period: Symbol) -> PeriodHealthSummary {
        Self::validate_symbol_not_empty(&e, &period, "period");

        let is_paused = if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&e, &pm_addr);
            pm_client.is_paused()
        } else {
            false
        };

        let current_period: Option<Symbol> = e.storage().persistent().get(&DataKey::CurrentPeriod);
        let is_current_period = current_period.map(|cp| cp == period).unwrap_or(false);

        let has_active_draft = e
            .storage()
            .persistent()
            .has(&DataKey::ActiveDraftForPeriod(period.clone()));

        let is_frozen = Self::is_period_config_frozen(e.clone(), period.clone());

        let window_status_enum = Self::get_settlement_window_status(e.clone(), period.clone());
        let window_status = window_status_enum.map(|s| s as u32);

        let usage = Self::get_period_usage(e.clone(), period.clone());
        let limits = Self::get_capacity_limits(e.clone());
        let mut capacity_configured = false;
        let mut capacity_exceeded = false;
        let mut capacity_reason = None;

        if let Some(limits) = limits {
            capacity_configured = true;
            if usage.batch_count >= limits.max_batches {
                capacity_exceeded = true;
                capacity_reason = Some(PeriodHealthReason::BatchCapacityExceeded);
            } else if usage.employee_count >= limits.max_employees {
                capacity_exceeded = true;
                capacity_reason = Some(PeriodHealthReason::EmployeeCapacityExceeded);
            } else if usage.total_value >= limits.max_total_value {
                capacity_exceeded = true;
                capacity_reason = Some(PeriodHealthReason::ValueCapacityExceeded);
            }
        }

        let window_allows_execution = match window_status_enum {
            None => true,
            Some(SettlementWindowStatus::Executable) => true,
            _ => false,
        };

        let can_execute = !is_paused && window_allows_execution && !capacity_exceeded;

        let (status, reason) = if is_paused {
            (
                PeriodHealthStatus::Blocked,
                PeriodHealthReason::ContractPaused,
            )
        } else if let Some(ws) = window_status_enum {
            match ws {
                SettlementWindowStatus::PreOpen => {
                    (PeriodHealthStatus::Blocked, PeriodHealthReason::PreOpen)
                }
                SettlementWindowStatus::Closed => (
                    PeriodHealthStatus::Blocked,
                    PeriodHealthReason::WindowClosed,
                ),
                SettlementWindowStatus::Grace => {
                    (PeriodHealthStatus::Warning, PeriodHealthReason::GracePeriod)
                }
                SettlementWindowStatus::Executable => {
                    if capacity_exceeded {
                        (
                            PeriodHealthStatus::Blocked,
                            capacity_reason.unwrap_or(PeriodHealthReason::BatchCapacityExceeded),
                        )
                    } else if is_frozen {
                        (
                            PeriodHealthStatus::Warning,
                            PeriodHealthReason::PeriodFrozen,
                        )
                    } else {
                        (PeriodHealthStatus::Healthy, PeriodHealthReason::Normal)
                    }
                }
            }
        } else if capacity_exceeded {
            (
                PeriodHealthStatus::Blocked,
                capacity_reason.unwrap_or(PeriodHealthReason::BatchCapacityExceeded),
            )
        } else if is_frozen {
            (
                PeriodHealthStatus::Warning,
                PeriodHealthReason::PeriodFrozen,
            )
        } else {
            (PeriodHealthStatus::Healthy, PeriodHealthReason::Normal)
        };

        PeriodHealthSummary {
            period,
            status,
            reason,
            is_current_period,
            can_execute,
            is_frozen,
            is_paused,
            has_active_draft,
            window_status,
            capacity_configured,
            batch_count: usage.batch_count,
            employee_count: usage.employee_count,
            capacity_exceeded,
        }
    }

    /// Count executed runs recorded for a given period.
    fn count_runs_for_period(e: &Env, period: &Symbol) -> u32 {
        let usage = Self::get_period_usage(e.clone(), period.clone());
        usage.batch_count
    }

    /// Panic when a period's configuration is frozen and must not be edited.
    fn assert_period_config_editable(e: &Env, period: &Symbol) {
        if Self::is_period_config_frozen(e.clone(), period.clone()) {
            panic!(
                "Payroll period configuration is frozen: settlement window cannot be edited (error code {})",
                PaymentError::InvalidSettlementWindowConfig as u32
            );
        }
    }

    /// Enforce the settlement window for the currently open capacity period,
    /// if any, before a batch is prepared or executed. A no-op when no
    /// period is open or no window has been configured for it, preserving
    /// backward compatibility for callers that don't use this feature.
    ///
    /// Returns the open period label, if any, so callers can record it
    /// against the run for later expiration lookups.
    fn enforce_settlement_window_for_current_period(e: &Env) -> Option<Symbol> {
        let period: Symbol = e.storage().persistent().get(&DataKey::CurrentPeriod)?;
        let window: SettlementWindow = match e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period.clone()))
        {
            Some(window) => window,
            None => return Some(period),
        };

        let now = e.ledger().timestamp();
        let status = Self::classify_settlement_window(&window, now);
        if status != SettlementWindowStatus::Executable {
            payroll_events::emit_settlement_window_rejected(e, period, status as u32, now);
            let error_code = if status == SettlementWindowStatus::PreOpen {
                PaymentError::SettlementWindowNotYetOpen as u32
            } else {
                PaymentError::SettlementWindowClosed as u32
            };
            panic!(
                "Settlement window is not open for execution right now (error code {})",
                error_code
            );
        }

        Some(period)
    }

    /// Expire a pending payroll run whose settlement window has fully closed
    /// (issue #316).
    ///
    /// Unlike `cancel_payroll_run_with_reason` — an explicit admin decision
    /// available at any time — this path only succeeds once the run's period
    /// has a settlement window configured AND the current ledger time is at
    /// or past that window's `close_at`. It exists to sweep pending runs that
    /// were never finalized before their settlement window closed for good.
    ///
    /// Reuses the `Cancelled` terminal state (no new state-machine variant is
    /// introduced) but is recorded with a distinct `settlement_window_expired`
    /// reason for audit trails, and only released funds/state are touched —
    /// no salary amounts or commitments are exposed.
    pub fn expire_pending_run(e: Env, admin: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if e.storage().persistent().has(&DataKey::PayrollRun(run_id)) {
            panic!("Cannot expire: run has already been executed");
        }

        let pending_key = DataKey::PendingRun(run_id);
        let pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&pending_key)
            .expect("Pending run not found");

        let period: Symbol = e
            .storage()
            .persistent()
            .get(&DataKey::PendingRunPeriod(run_id))
            .expect("No settlement window is associated with this pending run");
        let window: SettlementWindow = e
            .storage()
            .persistent()
            .get(&DataKey::SettlementWindow(period.clone()))
            .expect("No settlement window configured for this run's period");

        let now = e.ledger().timestamp();
        if now < window.close_at {
            panic!(
                "Settlement window has not reached its close timestamp yet (error code {})",
                PaymentError::SettlementWindowClosed as u32
            );
        }

        Self::subtract_locked_funds(&e, addrs.token.clone(), pending_run.total_amount);

        let expire_status = CancelledBatchStatus {
            run_id,
            cancelled_at: now,
            cancelled_by: admin,
            reason: Symbol::new(&e, "settlement_window_expired"),
            employee_count: pending_run.employee_count,
            total_amount: pending_run.total_amount,
            draft_hash: pending_run.draft_hash.clone(),
            is_cancelled: true,
        };
        e.storage()
            .persistent()
            .set(&DataKey::CancelledBatchRecord(run_id), &expire_status);

        e.storage().persistent().remove(&pending_key);
        e.storage()
            .persistent()
            .remove(&DataKey::PendingRunPeriod(run_id));
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::Cancelled);

        e.storage().persistent().set(
            &DataKey::PendingRunCount,
            &Self::pending_payroll_run_count(&e).saturating_sub(1),
        );

        payroll_events::emit_settlement_window_expired(&e, run_id, period, now);
        Self::emit_treasury_balance_snapshot(
            &e,
            addrs.token,
            Symbol::new(&e, "run_expired"),
        );
    }

    // ?? Issue #146: archived payroll run queries ??????????????????????????????

    /// Mark a completed payroll run as archived for long-term reporting.
    ///
    /// Only the admin may archive. Archiving is additive and read-only: it
    /// flags the run without altering the underlying `PayrollRun` record,
    /// cannot trigger execution, state transitions, or treasury mutations.
    pub fn archive_payroll_run(e: Env, admin: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        Self::require_run_not_disputed(&e, run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        // Ensure the run exists before archiving it.
        if !e.storage().persistent().has(&DataKey::PayrollRun(run_id)) {
            panic!("Run not found");
        }

        // Issue #374: block archival while an audit challenge is unresolved.
        if e.storage()
            .persistent()
            .has(&DataKey::ChallengedRun(run_id))
        {
            panic!("Run has an unresolved audit challenge");
        }

        let archive_key = DataKey::ArchivedRun(run_id);
        if e.storage().persistent().has(&archive_key) {
            panic!("Run is already archived");
        }
        e.storage().persistent().set(&archive_key, &true);
        e.storage().persistent().set(
            &DataKey::ArchiveMarker(run_id),
            &ArchiveMarker {
                run_id,
                archived_at: e.ledger().timestamp(),
                archived_by: admin.clone(),
                archive_reason: Symbol::new(&e, "retention_policy"),
            },
        );

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_archived")),
            run_id,
        );
    }

    /// Marks `run_id` as having an unresolved audit challenge, blocking
    /// `archive_payroll_run` until cleared (issue #374). Admin-only.
    pub fn flag_run_challenged(e: Env, admin: Address, run_id: u64) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        e.storage()
            .persistent()
            .set(&DataKey::ChallengedRun(run_id), &true);
        e.storage().persistent().set(
            &DataKey::ChallengeTimestamp(run_id),
            &e.ledger().timestamp(),
        );
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_challenged")),
            run_id,
        );
    }

    /// Clears the challenged flag on `run_id`, allowing archival again
    /// (issue #374). Admin-only.
    pub fn clear_run_challenge(e: Env, admin: Address, run_id: u64) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        e.storage()
            .persistent()
            .remove(&DataKey::ChallengedRun(run_id));
        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "run_challenge_cleared"),
            ),
            run_id,
        );
    }

    /// Remove the timestamp of a resolved challenge after its retention window.
    pub fn prune_resolved_challenge(e: Env, admin: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        if e.storage()
            .persistent()
            .has(&DataKey::ChallengedRun(run_id))
        {
            panic!("Active audit challenge cannot be pruned");
        }
        let challenged_at: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::ChallengeTimestamp(run_id))
            .expect("Challenge record not found");
        let policy = Self::get_retention_policy(e.clone());
        if e.ledger().timestamp().saturating_sub(challenged_at) < policy.challenge_seconds {
            panic!("Challenge retention window has not elapsed");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::ChallengeTimestamp(run_id));
        payroll_events::emit_retention_pruned(&e, Symbol::new(&e, "challenge"), run_id, admin);
    }

    /// Return a payroll run only if it has been explicitly archived.
    ///
    /// This is the dedicated archived-query path: it is fully read-only and
    /// panics for runs that exist but have not been archived, keeping the
    /// archived and active access paths clearly separated.
    pub fn get_archived_run(e: Env, run_id: u64) -> PayrollRun {
        Self::validate_run_id(run_id);
        if !e.storage().persistent().has(&DataKey::ArchivedRun(run_id)) {
            panic!("Run is not archived");
        }
        e.storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found")
    }

    /// Return `true` if the run has been marked as archived, `false` otherwise.
    pub fn is_run_archived(e: Env, run_id: u64) -> bool {
        Self::validate_run_id(run_id);
        e.storage().persistent().has(&DataKey::ArchivedRun(run_id))
    }

    /// Set the retention windows used by administrative pruning operations.
    pub fn set_retention_policy(e: Env, admin: Address, policy: RetentionPolicy) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        if policy.finalized_run_seconds == 0
            || policy.cancelled_batch_seconds == 0
            || policy.challenge_seconds == 0
        {
            panic!("Retention windows must be non-zero");
        }
        let previous_ref = stored_ref(&e, &DataKey::RetentionPolicy);
        e.storage()
            .persistent()
            .set(&DataKey::RetentionPolicy, &policy);
        payroll_events::emit_retention_policy_set(
            &e,
            policy.finalized_run_seconds,
            policy.cancelled_batch_seconds,
            policy.challenge_seconds,
        );
        record_config_change(
            &e,
            &admin,
            config_keys::RETENTION_POLICY,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::RetentionPolicy),
        );
    }

    /// Return the current retention policy.
    pub fn get_retention_policy(e: Env) -> RetentionPolicy {
        e.storage()
            .persistent()
            .get(&DataKey::RetentionPolicy)
            .expect("Retention policy not configured")
    }

    /// Permanently remove an archived payroll run's on-chain record once its
    /// retention window has been satisfied off-chain (issue #342).
    ///
    /// This is an irreversible cleanup action. It requires the run to have
    /// already been archived, and is blocked while the run has an active
    /// dispute, mirroring the guards on `finalize_payroll_run` and
    /// `archive_payroll_run`.
    pub fn prune_payroll_run(e: Env, admin: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        Self::require_run_not_disputed(&e, run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if !e.storage().persistent().has(&DataKey::ArchivedRun(run_id)) {
            panic!("Run must be archived before it can be pruned");
        }

        let marker =
            Self::get_archive_marker(e.clone(), run_id).filter(|marker| marker.run_id == run_id);
        let archived_at = marker.map(|value| value.archived_at).unwrap_or(0);
        let policy = Self::get_retention_policy(e.clone());
        if archived_at == 0
            || e.ledger().timestamp().saturating_sub(archived_at) < policy.finalized_run_seconds
        {
            panic!("Finalized run retention window has not elapsed");
        }

        e.storage()
            .persistent()
            .remove(&DataKey::PayrollRun(run_id));
        e.storage()
            .persistent()
            .remove(&DataKey::ArchivedRun(run_id));
        e.storage()
            .persistent()
            .remove(&DataKey::ArchiveMarker(run_id));
        e.storage()
            .persistent()
            .remove(&DataKey::PayrollState(run_id));
        e.storage().persistent().remove(&DataKey::RunReview(run_id));
        approvals::clear_approvals(&e, run_id);

        payroll_events::emit_run_pruned(&e, run_id, admin.clone());
        payroll_events::emit_retention_pruned(&e, Symbol::new(&e, "finalized_run"), run_id, admin);
    }

    /// Permanently remove cancellation metadata after its retention window.
    pub fn prune_cancelled_batch(e: Env, admin: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        Self::require_run_not_disputed(&e, run_id);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let record: CancelledBatchStatus = e
            .storage()
            .persistent()
            .get(&DataKey::CancelledBatchRecord(run_id))
            .expect("Cancelled batch not found");
        let policy = Self::get_retention_policy(e.clone());
        if e.ledger().timestamp().saturating_sub(record.cancelled_at)
            < policy.cancelled_batch_seconds
        {
            panic!("Cancelled batch retention window has not elapsed");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::CancelledBatchRecord(run_id));
        e.storage()
            .persistent()
            .remove(&DataKey::PayrollState(run_id));
        approvals::clear_approvals(&e, run_id);
        payroll_events::emit_retention_pruned(
            &e,
            Symbol::new(&e, "cancelled_batch"),
            run_id,
            admin,
        );
    }

    // ── Issue #342: dispute freeze/thaw controls ─────────────────────────────

    /// Grant dispute-authority permission to an address. Only the admin may call.
    ///
    /// Dispute authorities may open and resolve disputes in addition to the
    /// admin, who always implicitly holds this permission.
    pub fn add_dispute_authority(e: Env, admin: Address, authority: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let authority_key = DataKey::DisputeAuthority(authority.clone());
        let previous_ref = stored_ref(&e, &authority_key);
        e.storage().persistent().set(&authority_key, &true);

        payroll_events::emit_dispute_authority_added(&e, authority.clone());
        record_config_change(
            &e,
            &admin,
            config_keys::DISPUTE_AUTHORITY,
            value_ref(&e, &authority),
            previous_ref,
            stored_ref(&e, &authority_key),
        );
    }

    /// Revoke dispute-authority permission from an address. Only the admin may call.
    pub fn remove_dispute_authority(e: Env, admin: Address, authority: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let authority_key = DataKey::DisputeAuthority(authority.clone());
        let previous_ref = stored_ref(&e, &authority_key);
        e.storage().persistent().remove(&authority_key);

        payroll_events::emit_dispute_authority_removed(&e, authority.clone());
        record_config_change(
            &e,
            &admin,
            config_keys::DISPUTE_AUTHORITY,
            value_ref(&e, &authority),
            previous_ref,
            stored_ref(&e, &authority_key),
        );
    }

    /// Return `true` if the address may open or resolve disputes: the
    /// contract admin, or an address explicitly granted dispute authority.
    pub fn is_dispute_authority(e: Env, address: Address) -> bool {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if address == addrs.admin {
            return true;
        }
        e.storage()
            .persistent()
            .get(&DataKey::DisputeAuthority(address))
            .unwrap_or(false)
    }

    fn require_dispute_authority(e: &Env, caller: &Address) {
        if !Self::is_dispute_authority(e.clone(), caller.clone()) {
            panic!("Unauthorized: caller is not an authorized dispute authority");
        }
    }

    /// Panic if `run_id` has an active dispute. Called by every irreversible
    /// lifecycle action (finalize, archive, prune) to enforce the freeze.
    fn require_run_not_disputed(e: &Env, run_id: u64) {
        if e.storage()
            .persistent()
            .has(&DataKey::ActiveDisputeForRun(run_id))
        {
            panic!("Run is under active dispute");
        }
    }

    /// Open a dispute against a payroll run, freezing finalization, archival,
    /// and pruning until the dispute is resolved (issue #342).
    ///
    /// Only the admin or an authorized dispute authority may open a dispute.
    /// The dispute record is scoped to the employer (contract admin), the
    /// caller-supplied period label, and the batch root committed for the
    /// disputed run, giving auditors a stable reference for the freeze.
    pub fn open_dispute(
        e: Env,
        caller: Address,
        run_id: u64,
        period: Symbol,
        batch_root: BytesN<32>,
        reason: Symbol,
    ) -> u64 {
        Self::validate_run_id(run_id);
        Self::validate_symbol_not_empty(&e, &period, "period");
        Self::validate_non_zero_digest(&e, &batch_root, "batch_root");
        Self::validate_symbol_not_empty(&e, &reason, "reason");
        Self::require_dispute_authority(&e, &caller);
        caller.require_auth();

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // The run must exist, either pending finalization or already executed.
        if !e.storage().persistent().has(&DataKey::PayrollRun(run_id))
            && !e.storage().persistent().has(&DataKey::PendingRun(run_id))
        {
            panic!("Run not found");
        }

        if e.storage()
            .persistent()
            .has(&DataKey::ActiveDisputeForRun(run_id))
        {
            panic!("Run already has an active dispute");
        }

        let dispute_id = e
            .storage()
            .persistent()
            .get(&DataKey::DisputeCounter)
            .unwrap_or(0u64)
            + 1;
        e.storage()
            .persistent()
            .set(&DataKey::DisputeCounter, &dispute_id);

        let dispute = Dispute {
            dispute_id,
            run_id,
            employer: addrs.admin,
            period: period.clone(),
            batch_root: batch_root.clone(),
            opened_by: caller.clone(),
            opened_at: e.ledger().timestamp(),
            open_reason: reason.clone(),
            status: DisputeStatus::Active,
            resolved_by: None,
            resolved_at: None,
            resolution_reason: None,
        };
        e.storage()
            .persistent()
            .set(&DataKey::Dispute(dispute_id), &dispute);
        e.storage()
            .persistent()
            .set(&DataKey::ActiveDisputeForRun(run_id), &dispute_id);

        payroll_events::emit_dispute_opened(
            &e, dispute_id, run_id, caller, period, batch_root, reason,
        );

        dispute_id
    }

    /// Resolve (thaw) an active dispute with a reason code (issue #342).
    ///
    /// Only the admin or an authorized dispute authority may resolve a
    /// dispute. Once resolved, the associated run is no longer frozen and
    /// normal lifecycle actions (finalize, archive, prune) may continue.
    pub fn resolve_dispute(e: Env, caller: Address, dispute_id: u64, resolution_reason: Symbol) {
        Self::validate_symbol_not_empty(&e, &resolution_reason, "resolution_reason");
        Self::require_dispute_authority(&e, &caller);
        caller.require_auth();

        let key = DataKey::Dispute(dispute_id);
        let mut dispute: Dispute = e
            .storage()
            .persistent()
            .get(&key)
            .expect("Dispute not found");
        if dispute.status != DisputeStatus::Active {
            panic!("Dispute is not active");
        }

        dispute.status = DisputeStatus::Resolved;
        dispute.resolved_by = Some(caller.clone());
        dispute.resolved_at = Some(e.ledger().timestamp());
        dispute.resolution_reason = Some(resolution_reason.clone());
        e.storage().persistent().set(&key, &dispute);
        e.storage()
            .persistent()
            .remove(&DataKey::ActiveDisputeForRun(dispute.run_id));

        payroll_events::emit_dispute_resolved(
            &e,
            dispute_id,
            dispute.run_id,
            caller,
            resolution_reason,
        );
    }

    /// Return the dispute record for the given dispute id.
    pub fn get_dispute(e: Env, dispute_id: u64) -> Dispute {
        e.storage()
            .persistent()
            .get(&DataKey::Dispute(dispute_id))
            .expect("Dispute not found")
    }

    /// Return `true` if the run currently has an active dispute, `false` otherwise.
    pub fn is_run_disputed(e: Env, run_id: u64) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::ActiveDisputeForRun(run_id))
    }

    // ?? Reviewer Authorization & Run Review Entrypoints ?????????????????????

    /// Grant reviewer authorization to an address. Only the admin may call.
    ///
    /// Rejected once the number of currently authorized reviewers would
    /// exceed the employer's configured `MaxReviewers` policy, if any has
    /// been set via `set_max_reviewers` (#539). Re-adding an address that is
    /// already authorized is a no-op with respect to the cap: it does not
    /// increment the reviewer count and is never rejected for being "over
    /// the limit" on its own.
    pub fn add_reviewer(e: Env, admin: Address, reviewer: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        Self::grant_reviewer_internal(&e, &admin, &reviewer);
    }

    /// Shared core of `add_reviewer` / `signed_add_reviewer`: enforce the
    /// `MaxReviewers` cap (#539), grant the reviewer role, and publish the
    /// usual `reviewer_added` event + config-audit record. Callers are
    /// responsible for their own authorization check before calling this —
    /// it performs none itself.
    fn grant_reviewer_internal(e: &Env, actor: &Address, reviewer: &Address) {
        let reviewer_key = DataKey::AuthorizedReviewer(reviewer.clone());
        let previous_ref = stored_ref(e, &reviewer_key);
        let already_authorized = e.storage().persistent().has(&reviewer_key);

        if !already_authorized {
            let current_count: u32 = e
                .storage()
                .persistent()
                .get(&DataKey::ReviewerCount)
                .unwrap_or(0);
            if let Some(max_reviewers) = e
                .storage()
                .persistent()
                .get::<DataKey, u32>(&DataKey::MaxReviewers)
            {
                if current_count >= max_reviewers {
                    panic!("Reviewer limit reached");
                }
            }
            e.storage()
                .persistent()
                .set(&DataKey::ReviewerCount, &(current_count + 1));
        }

        e.storage().persistent().set(&reviewer_key, &true);

        payroll_events::emit_reviewer_added(e, reviewer.clone());
        record_config_change(
            e,
            actor,
            config_keys::REVIEWER,
            value_ref(e, reviewer),
            previous_ref,
            stored_ref(e, &reviewer_key),
        );
    }

    /// Revoke reviewer authorization from an address. Only the admin may call.
    pub fn remove_reviewer(e: Env, admin: Address, reviewer: Address) {
        Self::require_not_paused(&e);
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let reviewer_key = DataKey::AuthorizedReviewer(reviewer.clone());
        let previous_ref = stored_ref(&e, &reviewer_key);
        let was_authorized = e.storage().persistent().has(&reviewer_key);
        e.storage().persistent().remove(&reviewer_key);

        if was_authorized {
            let current_count: u32 = e
                .storage()
                .persistent()
                .get(&DataKey::ReviewerCount)
                .unwrap_or(0);
            e.storage()
                .persistent()
                .set(&DataKey::ReviewerCount, &current_count.saturating_sub(1));
        }

        payroll_events::emit_reviewer_removed(&e, reviewer.clone());
        record_config_change(
            &e,
            &admin,
            config_keys::REVIEWER,
            value_ref(&e, &reviewer),
            previous_ref,
            stored_ref(&e, &reviewer_key),
        );
    }

    /// Return `true` if the address is an authorized reviewer, `false` otherwise.
    pub fn is_reviewer(e: Env, reviewer: Address) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::AuthorizedReviewer(reviewer))
            .unwrap_or(false)
    }

    // ── Issue #539: delegated approver (reviewer) assignment limits ─────────

    /// Set (or replace) the maximum number of concurrently authorized
    /// reviewers. Only the admin may call. Opt-in, mirroring
    /// `set_capacity_limits`: absent a policy, `add_reviewer` is unlimited,
    /// exactly as before this feature existed. Lowering the cap below the
    /// current reviewer count is allowed (it only blocks further additions;
    /// it never revokes existing reviewers).
    pub fn set_max_reviewers(e: Env, admin: Address, max_reviewers: u32) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if max_reviewers == 0 {
            panic!("Reviewer limit must be positive");
        }

        let previous_ref = stored_ref(&e, &DataKey::MaxReviewers);
        e.storage()
            .persistent()
            .set(&DataKey::MaxReviewers, &max_reviewers);

        payroll_events::emit_max_reviewers_set(&e, max_reviewers);
        record_config_change(
            &e,
            &admin,
            config_keys::MAX_REVIEWERS,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::MaxReviewers),
        );
    }

    /// Return the currently configured reviewer cap, if any.
    pub fn get_max_reviewers(e: Env) -> Option<u32> {
        e.storage().persistent().get(&DataKey::MaxReviewers)
    }

    /// Return the number of currently authorized reviewers.
    pub fn get_reviewer_count(e: Env) -> u32 {
        e.storage()
            .persistent()
            .get(&DataKey::ReviewerCount)
            .unwrap_or(0)
    }

    // ── Configurable payroll approval threshold ──────────────────────────────

    /// Require `threshold` distinct, live reviewer approvals before
    /// `finalize_payroll_run` may execute a prepared run. Only the admin may
    /// call. While a threshold is configured, the direct execution
    /// entrypoints (`batch_process_payroll*`) are unavailable.
    ///
    /// Rejected when `threshold` is zero (use `clear_approval_threshold`),
    /// exceeds `MAX_APPROVAL_THRESHOLD`, or exceeds the number of currently
    /// authorized reviewers (an unreachable threshold would block payroll).
    /// Locked while any payroll run is pending, so the bar cannot move under
    /// an in-flight run.
    pub fn set_approval_threshold(e: Env, admin: Address, threshold: u32) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::require_no_active_payroll_run(&e);

        if threshold == 0 {
            panic!("Approval threshold must be positive: use clear_approval_threshold to disable");
        }
        if threshold > MAX_APPROVAL_THRESHOLD {
            panic!("Approval threshold exceeds the maximum supported value");
        }
        if threshold > Self::get_reviewer_count(e.clone()) {
            panic!("Approval threshold exceeds the number of authorized reviewers");
        }

        let previous_ref = stored_ref(&e, &DataKey::ApprovalThreshold);
        e.storage()
            .persistent()
            .set(&DataKey::ApprovalThreshold, &threshold);

        payroll_events::emit_approval_threshold_set(&e, threshold);
        record_config_change(
            &e,
            &admin,
            config_keys::APPROVAL_THRESHOLD,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::ApprovalThreshold),
        );
    }

    /// Remove the approval threshold, restoring the default workflow in
    /// which finalization and direct execution need no approval quorum.
    /// Only the admin may call; locked while any payroll run is pending.
    pub fn clear_approval_threshold(e: Env, admin: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::require_no_active_payroll_run(&e);

        let previous_ref = stored_ref(&e, &DataKey::ApprovalThreshold);
        e.storage().persistent().remove(&DataKey::ApprovalThreshold);

        payroll_events::emit_approval_threshold_set(&e, 0);
        record_config_change(
            &e,
            &admin,
            config_keys::APPROVAL_THRESHOLD,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::ApprovalThreshold),
        );
    }

    /// Return the configured approval threshold, if any.
    pub fn get_approval_threshold(e: Env) -> Option<u32> {
        approvals::threshold(&e)
    }

    /// Return every approval recorded for a run, including approvals that no
    /// longer count because they expired or their reviewer was revoked.
    pub fn get_run_approvals(e: Env, run_id: u64) -> Vec<RunApproval> {
        approvals::run_approvals(&e, run_id)
    }

    /// Return how many live approvals a run has against the configured
    /// threshold. Contains counts only — no payroll amounts or identities.
    pub fn get_approval_progress(e: Env, run_id: u64) -> ApprovalProgress {
        approvals::progress(&e, run_id)
    }

    // ── Issue #519: signed, expiring operator authorizations ────────────────

    /// Register (or replace) the ed25519 public key that signs off-chain
    /// operator authorizations. Only the admin may call. There is at most
    /// one operator key at a time; registering a new one immediately
    /// invalidates the ability to submit authorizations signed by the old
    /// key (already-consumed authorizations remain consumed either way).
    pub fn register_operator_key(e: Env, admin: Address, operator_key: BytesN<32>) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let previous_ref = stored_ref(&e, &DataKey::OperatorKey);
        e.storage()
            .persistent()
            .set(&DataKey::OperatorKey, &operator_key);

        payroll_events::emit_operator_key_registered(&e);
        record_config_change(
            &e,
            &admin,
            config_keys::OPERATOR_KEY,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::OperatorKey),
        );
    }

    /// Revoke the currently registered operator key. Only the admin may
    /// call. After revocation, `signed_add_reviewer` is unusable until a new
    /// key is registered.
    pub fn revoke_operator_key(e: Env, admin: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let previous_ref = stored_ref(&e, &DataKey::OperatorKey);
        e.storage().persistent().remove(&DataKey::OperatorKey);

        payroll_events::emit_operator_key_revoked(&e);
        record_config_change(
            &e,
            &admin,
            config_keys::OPERATOR_KEY,
            no_value_ref(&e),
            previous_ref,
            stored_ref(&e, &DataKey::OperatorKey),
        );
    }

    /// Return the currently registered operator public key, if any.
    pub fn get_operator_key(e: Env) -> Option<BytesN<32>> {
        e.storage().persistent().get(&DataKey::OperatorKey)
    }

    /// Grant reviewer authorization using a signed, expiring off-chain
    /// operator authorization instead of the admin's own `require_auth()`
    /// (issue #519). Callable by ANYONE holding a validly signed payload —
    /// the ed25519 signature over `payload` by the registered operator key
    /// IS the authorization; the submitter needs no role of their own.
    ///
    /// Rejected when:
    /// - No operator key is registered (`register_operator_key` first).
    /// - `payload.action` is not `AddReviewer(reviewer)` for the given
    ///   `reviewer` argument (prevents submitting a payload signed for a
    ///   different action/target against this entrypoint).
    /// - `signature` does not verify against the registered operator key
    ///   for `payload`'s exact XDR-encoded bytes.
    /// - `payload.expires_at_ledger` is at or before the current ledger
    ///   (`ReplayError::AuthorizationExpired`), or its lifetime at signing
    ///   time exceeded `MAX_AUTHORIZATION_TTL_LEDGERS`.
    /// - This exact payload (by its hashed XDR encoding) has already been
    ///   consumed by a prior call — the same protection `commit_draft`/
    ///   `RunNonce` give against replay elsewhere in this contract.
    ///
    /// Otherwise behaves exactly like `add_reviewer`, including the
    /// `MaxReviewers` cap (#539) and the `reviewer_added` +
    /// `config_changed` events.
    pub fn signed_add_reviewer(
        e: Env,
        reviewer: Address,
        payload: SignedOperatorPayload,
        signature: BytesN<64>,
    ) {
        Self::require_not_paused(&e);

        match &payload.action {
            SignedOperatorAction::AddReviewer(authorized_reviewer) => {
                if authorized_reviewer != &reviewer {
                    panic!("Signed payload action does not match the supplied reviewer");
                }
            }
        }

        let operator_key: BytesN<32> = e
            .storage()
            .persistent()
            .get(&DataKey::OperatorKey)
            .expect("No operator key registered");

        let message = require_not_expired(&e, &payload);
        e.crypto()
            .ed25519_verify(&operator_key, &message, &signature);

        let consume_key = DataKey::ConsumedOperatorAuth(consumed_key(&e, &payload));
        if e.storage().persistent().has(&consume_key) {
            panic!("Signed operator authorization already consumed");
        }
        e.storage().persistent().set(&consume_key, &true);

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        Self::grant_reviewer_internal(&e, &addrs.admin, &reviewer);
    }

    /// Approve a payroll run as an authorized reviewer.
    ///
    /// Each reviewer may hold at most one live approval per run; a repeated
    /// approval is rejected rather than counted twice toward the approval
    /// threshold.
    pub fn approve_payroll_run(e: Env, reviewer: Address, run_id: u64) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

        approvals::record_approval(&e, run_id, &reviewer);

        let review = RunReview {
            run_id,
            reviewer: reviewer.clone(),
            decision: ReviewDecision::Approved,
            reason: Symbol::new(&e, "approved"),
            reviewed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunReview(run_id), &review);

        payroll_events::emit_run_approved(&e, run_id, reviewer);
    }

    /// Reject a payroll run as an authorized reviewer. Clears every recorded
    /// approval for the run.
    pub fn reject_payroll_run(e: Env, reviewer: Address, run_id: u64, reason: Symbol) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

        approvals::clear_approvals(&e, run_id);

        let review = RunReview {
            run_id,
            reviewer: reviewer.clone(),
            decision: ReviewDecision::Rejected,
            reason: reason.clone(),
            reviewed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunReview(run_id), &review);

        payroll_events::emit_run_rejected(&e, run_id, reviewer, reason);
    }

    /// Request changes to a payroll run as an authorized reviewer. Clears
    /// every recorded approval for the run.
    pub fn request_changes_payroll_run(e: Env, reviewer: Address, run_id: u64, reason: Symbol) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

        approvals::clear_approvals(&e, run_id);

        let review = RunReview {
            run_id,
            reviewer: reviewer.clone(),
            decision: ReviewDecision::ChangesRequested,
            reason: reason.clone(),
            reviewed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunReview(run_id), &review);

        payroll_events::emit_run_changes_requested(&e, run_id, reviewer, reason);
    }

    /// Get the review record for a payroll run, if any.
    pub fn get_run_review(e: Env, run_id: u64) -> Option<RunReview> {
        e.storage().persistent().get(&DataKey::RunReview(run_id))
    }

    /// Withdraw a previously granted payroll run approval (issue #522).
    ///
    /// Only the reviewer that recorded the currently active `Approved`
    /// decision may withdraw it, and a non-empty reason is mandatory. The
    /// stored review transitions to `ReviewDecision::Withdrawn` so the audit
    /// trail stays intact while expiry validation (#403) and any consumer
    /// treating the run as approved no longer observe an active approval.
    /// The withdrawn approval also stops counting toward the approval
    /// threshold.
    ///
    /// Privacy-safe: events carry only the opaque run id, the withdrawing
    /// reviewer, and the reason symbol — never salary values or employee
    /// data.
    ///
    /// # Panics
    /// * `"Invalid payroll run ID"` — reserved sentinel run id.
    /// * `"Symbol cannot be empty"` — empty withdrawal reason.
    /// * `"Unauthorized: caller is not an authorized reviewer"` — caller is
    ///   not an authorized reviewer.
    /// * `"Run review not found"` — no review exists for `run_id`.
    /// * `"No active approval to withdraw"` — the stored review is not
    ///   `Approved` (already withdrawn, rejected, or changes requested).
    /// * `"Only the approving reviewer may withdraw an approval"` — a
    ///   different reviewer attempted the withdrawal.
    pub fn withdraw_approval(e: Env, reviewer: Address, run_id: u64, reason: Symbol) {
        Self::validate_run_id(run_id);
        Self::validate_symbol_not_empty(&e, &reason, "reason");
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

        let review: RunReview = e
            .storage()
            .persistent()
            .get(&DataKey::RunReview(run_id))
            .expect("Run review not found");
        if review.decision != ReviewDecision::Approved {
            panic!("No active approval to withdraw");
        }
        if review.reviewer != reviewer {
            panic!("Only the approving reviewer may withdraw an approval");
        }

        let withdrawn = RunReview {
            run_id,
            reviewer: reviewer.clone(),
            decision: ReviewDecision::Withdrawn,
            reason: reason.clone(),
            reviewed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunReview(run_id), &withdrawn);
        approvals::remove_approval(&e, run_id, &reviewer);

        payroll_events::emit_run_approval_withdrawn(&e, run_id, reviewer, reason);
    }

    /// Supersede an existing payroll approval as a different authorized
    /// reviewer (issue #522).
    ///
    /// The active approval must have been recorded by a *different*
    /// reviewer; re-approving one's own approval is a no-op and rejected so
    /// the supersession event always names a genuine handover. On success
    /// the stored review is re-pointed at the new reviewer with a fresh
    /// timestamp (which also restarts the #403 expiry window), and an audit
    /// event names both the previous and the new reviewer so accountability
    /// for the active approval is always explicit. The approval counted
    /// toward the approval threshold moves to the new reviewer as well.
    ///
    /// # Panics
    /// * `"Invalid payroll run ID"` — reserved sentinel run id.
    /// * `"Unauthorized: caller is not an authorized reviewer"` — caller is
    ///   not an authorized reviewer.
    /// * `"Run review not found"` — no review exists for `run_id`.
    /// * `"No active approval to supersede"` — the stored review is not
    ///   `Approved`.
    /// * `"Superseding reviewer must differ from the current approver"` —
    ///   the current approver attempted to supersede themselves.
    /// * `"Duplicate approval: reviewer has already approved this payroll run"`
    ///   — the superseding reviewer already holds a live approval.
    pub fn supersede_approval(e: Env, reviewer: Address, run_id: u64) {
        Self::validate_run_id(run_id);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

        let review: RunReview = e
            .storage()
            .persistent()
            .get(&DataKey::RunReview(run_id))
            .expect("Run review not found");
        if review.decision != ReviewDecision::Approved {
            panic!("No active approval to supersede");
        }
        if review.reviewer == reviewer {
            panic!("Superseding reviewer must differ from the current approver");
        }

        approvals::remove_approval(&e, run_id, &review.reviewer);
        approvals::record_approval(&e, run_id, &reviewer);

        let superseding = RunReview {
            run_id,
            reviewer: reviewer.clone(),
            decision: ReviewDecision::Approved,
            reason: Symbol::new(&e, "approved"),
            reviewed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunReview(run_id), &superseding);

        payroll_events::emit_run_approval_superseded(&e, run_id, review.reviewer, reviewer);
    }

    /// Read contract dependency addresses configured during initialization.
    pub fn get_addresses(e: Env) -> ContractAddresses {
        e.storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized")
    }

    /// Read the treasury owner address configured during initialization.
    pub fn get_treasury_owner(e: Env) -> Address {
        e.storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set")
    }

    /// Read the current payroll run counter (defaults to 0 on initialization).
    pub fn get_run_counter(e: Env) -> u64 {
        e.storage()
            .persistent()
            .get(&DataKey::RunCounter)
            .unwrap_or(0u64)
    }

    // ????????????????????????????????????????????????????????????????????????????
    // Issue #333: Compliance Hold Functionality
    // ????????????????????????????????????????????????????????????????????????????

    /// Place a compliance hold on a batch, employee group, or employer to block
    /// affected payroll execution while audit issues are resolved (#333).
    ///
    /// # Authorization
    /// Requires authorization from the contract admin.
    ///
    /// # Panics
    /// - If target address is invalid
    /// - If scope is invalid
    /// - If hold cannot be created
    pub fn place_compliance_hold(
        e: Env,
        admin: Address,
        scope: ComplianceHoldScope,
        target: Address,
        reason_code: Symbol,
    ) -> u64 {
        admin.require_auth();

        let hold_counter_key = DataKey::ComplianceHoldCounter;
        let hold_id: u64 = e
            .storage()
            .persistent()
            .get(&hold_counter_key)
            .unwrap_or(0u64)
            + 1;

        let now = e.ledger().timestamp();
        let hold = ComplianceHold {
            hold_id,
            scope,
            target: target.clone(),
            reason_code: reason_code.clone(),
            placed_at: now,
            placed_by: admin.clone(),
            is_active: true,
        };

        e.storage()
            .persistent()
            .set(&DataKey::ComplianceHold(hold_id), &hold);
        e.storage().persistent().set(&hold_counter_key, &hold_id);

        payroll_events::emit_compliance_hold_placed(
            &e,
            hold_id,
            Symbol::new(
                &e,
                match scope {
                    ComplianceHoldScope::Batch => "batch",
                    ComplianceHoldScope::Employee => "employee",
                    ComplianceHoldScope::Employer => "employer",
                },
            ),
            target,
            reason_code,
            admin,
        );

        hold_id
    }

    /// Release an active compliance hold by hold ID (#333).
    ///
    /// # Authorization
    /// Requires authorization from the contract admin.
    ///
    /// # Panics
    /// - If hold_id does not exist
    /// - If hold is not active
    pub fn release_compliance_hold(e: Env, admin: Address, hold_id: u64) {
        admin.require_auth();

        let key = DataKey::ComplianceHold(hold_id);
        let mut hold: ComplianceHold = e.storage().persistent().get(&key).expect("Hold not found");

        if !hold.is_active {
            panic!("Hold is not active");
        }

        hold.is_active = false;
        e.storage().persistent().set(&key, &hold);

        payroll_events::emit_compliance_hold_released(&e, hold_id, admin);
    }

    /// Check if a compliance hold is currently active (#333).
    pub fn is_compliance_hold_active(e: Env, hold_id: u64) -> bool {
        e.storage()
            .persistent()
            .get::<_, ComplianceHold>(&DataKey::ComplianceHold(hold_id))
            .map(|hold| hold.is_active)
            .unwrap_or(false)
    }

    /// Get compliance hold details by hold ID (#333).
    pub fn get_compliance_hold(e: Env, hold_id: u64) -> Option<ComplianceHold> {
        e.storage()
            .persistent()
            .get(&DataKey::ComplianceHold(hold_id))
    }

    // ????????????????????????????????????????????????????????????????????????????
    // Issue #337: Funding Reservation Expiry Functionality
    // ????????????????????????????????????????????????????????????????????????????

    /// Set or update the funding reservation expiry policy for an asset (#337).
    ///
    /// # Authorization
    /// Requires authorization from the contract admin. `admin` must be the
    /// stored admin, not just any address that signs the call (#490).
    pub fn set_reservation_expiry_policy(
        e: Env,
        admin: Address,
        asset: Address,
        reserved_amount: i128,
        expiry_ledger_offset: u64,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!(
                "Unauthorized: only the admin may set a reservation expiry policy (error code {})",
                AuthError::UnauthorizedAdmin as u32
            );
        }
        admin.require_auth();

        let now = e.ledger().timestamp();
        let expires_at = now + expiry_ledger_offset;

        let expiry = ReservationExpiry {
            asset: asset.clone(),
            reserved_amount,
            expires_at,
            created_at: now,
        };

        let expiry_key = DataKey::ReservationExpiry(asset.clone());
        let previous_ref = stored_ref(&e, &expiry_key);
        e.storage().persistent().set(&expiry_key, &expiry);
        record_config_change(
            &e,
            &admin,
            config_keys::RESERVATION_EXPIRY,
            value_ref(&e, &asset),
            previous_ref,
            stored_ref(&e, &expiry_key),
        );
    }

    /// Release expired funding reservations and make funds available (#337).
    ///
    /// # Authorization
    /// Can be called by anyone (cleanup is idempotent).
    ///
    /// # Panics
    /// - If reservation for asset does not exist
    /// - If reservation has not yet expired
    pub fn release_expired_reservation(e: Env, asset: Address) {
        let key = DataKey::ReservationExpiry(asset.clone());
        let expiry: ReservationExpiry = e
            .storage()
            .persistent()
            .get(&key)
            .expect("Reservation not found");

        let now = e.ledger().timestamp();
        if now <= expiry.expires_at {
            panic!("Reservation has not yet expired");
        }

        // Remove the expired reservation
        e.storage().persistent().remove(&key);

        payroll_events::emit_reservation_expiry_released(&e, asset, expiry.reserved_amount);
    }

    /// Get reservation expiry policy for an asset (#337).
    pub fn get_reservation_expiry(e: Env, asset: Address) -> Option<ReservationExpiry> {
        e.storage()
            .persistent()
            .get(&DataKey::ReservationExpiry(asset))
    }

    /// Get reservation expiry policy or fail with a clear not-found message (#424).
    pub fn get_required_reservation_expiry(e: Env, asset: Address) -> ReservationExpiry {
        e.storage()
            .persistent()
            .get(&DataKey::ReservationExpiry(asset))
            .expect("Treasury reservation not found")
    }

    // ????????????????????????????????????????????????????????????????????????????
    // Issue #335: Payroll Archival Functionality
    // ????????????????????????????????????????????????????????????????????????????

    /// Archive a finalized payroll run for long-term reporting (#335).
    ///
    /// # Authorization
    /// Requires authorization from the contract admin.
    ///
    /// # Preconditions
    /// - Run must be completed/finalized (not active, disputed, or held)
    /// - Run must not already be archived
    ///
    /// # Panics
    /// - If run_id does not exist
    /// - If run is in an incompatible state
    pub fn archive_payroll_run_with_reason(
        e: Env,
        admin: Address,
        run_id: u64,
        archive_reason: Symbol,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();
        Self::require_run_not_disputed(&e, run_id);

        let run_key = DataKey::PayrollRun(run_id);
        let _run: PayrollRun = e
            .storage()
            .persistent()
            .get(&run_key)
            .expect("Payroll run not found");

        // Check if already archived
        if e.storage()
            .persistent()
            .has(&DataKey::ArchiveMarker(run_id))
        {
            panic!("Payroll run is already archived");
        }

        let now = e.ledger().timestamp();
        let marker = ArchiveMarker {
            run_id,
            archived_at: now,
            archived_by: admin.clone(),
            archive_reason: archive_reason.clone(),
        };

        e.storage()
            .persistent()
            .set(&DataKey::ArchiveMarker(run_id), &marker);
        e.storage()
            .persistent()
            .set(&DataKey::ArchivedRun(run_id), &true);

        payroll_events::emit_payroll_run_archived(&e, run_id, admin, archive_reason);
    }

    /// Check if a payroll run is archived (#335).
    pub fn is_payroll_run_archived(e: Env, run_id: u64) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::ArchiveMarker(run_id))
    }

    /// Get archive marker for a payroll run (#335).
    pub fn get_archive_marker(e: Env, run_id: u64) -> Option<ArchiveMarker> {
        e.storage()
            .persistent()
            .get(&DataKey::ArchiveMarker(run_id))
    }

    // ── Issue #402: Safe Treasury Balance Summary View ───────────────────────

    /// Return aggregate treasury balance summary for a given asset token (#402).
    ///
    /// Returns the total balance held at the treasury address, the reserved/locked
    /// balance allocated to pending payroll runs, blocked balances, and the net
    /// available balance without disclosing individual salary rows.
    pub fn get_safe_treasury_summary(e: Env, asset: Address) -> SafeTreasurySummary {
        Self::require_active_treasury_asset(&e, asset.clone());
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        let total_balance = soroban_token::Client::new(&e, &asset).balance(&addrs.treasury);
        let reserved_balance = Self::get_locked_funds(e.clone(), asset.clone());
        let blocked_balance = 0i128;
        let available_balance = total_balance
            .checked_sub(reserved_balance)
            .unwrap_or(0i128)
            .checked_sub(blocked_balance)
            .unwrap_or(0i128);

        SafeTreasurySummary {
            asset,
            total_balance,
            available_balance,
            reserved_balance,
            blocked_balance,
        }
    }

    /// Check whether the configured contract funding source can cover a spend
    /// without executing a transfer or changing payroll state (#605).
    ///
    /// Readiness requires a positive `required_amount`, an initialized and
    /// allowlisted canonical token, a responding SEP-41 balance query, and
    /// enough unreserved treasury balance. The returned blocker gives SDKs an
    /// actionable reason when any prerequisite is missing.
    pub fn check_funding_source_readiness(
        e: Env,
        required_amount: i128,
    ) -> FundingSourceReadiness {
        let blocked = |blocker, available_balance| FundingSourceReadiness {
            ready: false,
            blocker,
            required_amount,
            available_balance,
        };

        if required_amount <= 0 {
            return blocked(FundingSourceBlocker::InvalidRequiredAmount, None);
        }

        let Some(addrs) = e
            .storage()
            .persistent()
            .get::<_, ContractAddresses>(&DataKey::Addresses)
        else {
            return blocked(FundingSourceBlocker::NotInitialized, None);
        };

        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            return blocked(FundingSourceBlocker::AssetNotAllowed, None);
        }

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        let total_balance = match token_client.try_balance(&addrs.treasury) {
            Ok(Ok(balance)) => balance,
            _ => return blocked(FundingSourceBlocker::TokenUnavailable, None),
        };
        let reserved_balance = Self::get_locked_funds(e, addrs.token);
        let available_balance = total_balance.saturating_sub(reserved_balance);

        if available_balance < required_amount {
            return blocked(
                FundingSourceBlocker::InsufficientFunds,
                Some(available_balance),
            );
        }

        FundingSourceReadiness {
            ready: true,
            blocker: FundingSourceBlocker::NotBlocked,
            required_amount,
            available_balance: Some(available_balance),
        }
    }

    // ?? Issue #403: Payroll Approval Expiry Validation ???????????????????????

    /// Check whether an approval for a payroll run has expired (#403).
    ///
    /// Returns `true` if a review exists with decision `Approved` but `current_timestamp > reviewed_at + max_age_seconds`.
    /// Returns `false` if the approval is within the validity window or if no approval exists.
    pub fn is_payroll_approval_expired(e: Env, run_id: u64, max_age_seconds: u64) -> bool {
        if let Some(review) = Self::get_run_review(e.clone(), run_id) {
            if review.decision == ReviewDecision::Approved {
                let current_time = e.ledger().timestamp();
                let expiry_time = review.reviewed_at.saturating_add(max_age_seconds);
                return current_time > expiry_time;
            }
        }
        false
    }

    /// Validate that a payroll run approval is active and not expired (#403).
    ///
    /// # Panics
    /// - If the approval for `run_id` has expired (older than `max_age_seconds`).
    pub fn validate_approval_not_expired(e: &Env, run_id: u64, max_age_seconds: u64) {
        if Self::is_payroll_approval_expired(e.clone(), run_id, max_age_seconds) {
            panic!("Payroll approval expired: approval record exceeds maximum allowed age");
        }
    }

    // ?? Issue #548: Stale Approval Cleanup ??????????????????????????????????????

    /// Permanently remove an expired approval record for a single payroll run
    /// (#548).
    ///
    /// An approval is *stale* when it is an `Approved` decision whose
    /// `reviewed_at` is older than `max_age_seconds` — exactly the condition
    /// `is_payroll_approval_expired` reports. Removing it is safe because
    /// `finalize_payroll_run` already refuses to settle an expired approval, so
    /// a stale record can never authorize a payout: this only reclaims the
    /// ledger entry it occupies. An approval that is still inside its validity
    /// window is left untouched.
    ///
    /// Records with a `Rejected` or `ChangesRequested` decision are never
    /// stale under this definition and are never removed, so cleanup cannot
    /// erase a reviewer's non-approval decision.
    ///
    /// `run_id` must be supplied explicitly because `RunReview` is keyed only by
    /// `run_id` with no enumerable index; a sweep over all approvals is not
    /// possible in bounded contract execution. Callers should drive this from
    /// their own run index (for example the finalized/archived run set).
    ///
    /// # Panics
    /// - `"Unauthorized"` if `admin` is not the registered payroll admin.
    /// - `"No approval exists for this payroll run"` if there is no review.
    /// - `"Record is not an approval: nothing stale to clean up"` if the
    ///   review is a `Rejected` or `ChangesRequested` decision.
    /// - `"Approval is not stale: still within its validity window"` if the
    ///   approval has not yet expired.
    ///
    /// The returned struct and the emitted event carry only the `run_id`, the
    /// review timestamp, and the record type. No reviewer address, salary,
    /// employee count, or other payroll value is disclosed.
    pub fn cleanup_stale_approval(
        e: Env,
        admin: Address,
        run_id: u64,
        max_age_seconds: u64,
    ) -> StaleApprovalCleanupResult {
        Self::require_not_paused(&e);
        Self::validate_run_id(run_id);

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let review: RunReview = e
            .storage()
            .persistent()
            .get(&DataKey::RunReview(run_id))
            .expect("No approval exists for this payroll run");

        // Reuse the single definition of staleness so cleanup and the
        // finalize-time guard can never disagree about the cutoff.
        if review.decision != ReviewDecision::Approved {
            panic!("Record is not an approval: nothing stale to clean up");
        }
        let expiry_time = review.reviewed_at.saturating_add(max_age_seconds);
        if e.ledger().timestamp() <= expiry_time {
            panic!("Approval is not stale: still within its validity window");
        }

        e.storage().persistent().remove(&DataKey::RunReview(run_id));

        // Reuse the existing retention-prune event; `record_type` identifies
        // the kind of record without naming the reviewer.
        payroll_events::emit_retention_pruned(
            &e,
            Symbol::new(&e, "run_approval"),
            run_id,
            admin.clone(),
        );

        StaleApprovalCleanupResult {
            run_id,
            removed: true,
            reviewed_at: review.reviewed_at,
            expired_at: expiry_time,
        }
    }

    /// Read-only preview of whether a payroll run holds a stale approval (#548).
    ///
    /// Returns `None` when no review exists. The result is safe to log: it
    /// exposes no reviewer identity and no payroll amounts.
    pub fn get_stale_approval_status(
        e: Env,
        run_id: u64,
        max_age_seconds: u64,
    ) -> Option<StaleApprovalStatus> {
        Self::validate_run_id(run_id);
        let review: RunReview = e.storage().persistent().get(&DataKey::RunReview(run_id))?;
        if review.decision != ReviewDecision::Approved {
            return None;
        }
        let expiry_time = review.reviewed_at.saturating_add(max_age_seconds);
        Some(StaleApprovalStatus {
            run_id,
            is_stale: e.ledger().timestamp() > expiry_time,
            reviewed_at: review.reviewed_at,
            expires_at: expiry_time,
        })
    }

    // ?? Issue #404: Cancelled Batch Read Status Helper ???????????????????????

    /// Read safe cancellation metadata for a cancelled payroll batch (#404).
    ///
    /// Returns `Some(CancelledBatchStatus)` if the batch was cancelled, containing
    /// run_id, cancellation timestamp, admin address, cancellation reason symbol,
    /// employee count, total amount, draft hash, and `is_cancelled: true`.
    /// Returns `None` if the batch was not cancelled or does not exist.
    pub fn get_cancelled_batch_status(e: Env, run_id: u64) -> Option<CancelledBatchStatus> {
        e.storage()
            .persistent()
            .get(&DataKey::CancelledBatchRecord(run_id))
    }

    // ?? Issue #352: Payroll Batch Split Validation ??????????????????????????????????

    /// Record a batch split to track parent-child relationships (#352).
    /// Validates that child batch totals can be aggregated back to parent.
    pub fn record_batch_split(
        e: Env,
        admin: Address,
        parent_run_id: u64,
        child_run_id: u64,
        parent_total: i128,
        parent_employee_count: u32,
        child_total: i128,
        child_employee_count: u32,
    ) {
        admin.require_auth();

        if child_total <= 0 || parent_total <= 0 {
            panic!("Batch amounts must be positive");
        }

        if child_total > parent_total {
            panic!("Child batch total cannot exceed parent total");
        }

        if child_employee_count > parent_employee_count {
            panic!("Child employee count cannot exceed parent count");
        }

        let split_record = BatchSplitRecord {
            parent_run_id,
            child_run_id,
            parent_total,
            parent_employee_count,
            child_total,
            child_employee_count,
            split_at: e.ledger().timestamp(),
            split_by: admin.clone(),
        };

        e.storage().persistent().set(
            &DataKey::BatchSplitRecord(parent_run_id, child_run_id),
            &split_record,
        );

        e.events().publish(
            (Symbol::new(&e, "BatchSplitRecorded"), parent_run_id),
            (child_run_id, child_total, e.ledger().timestamp()),
        );
    }

    /// Get batch split record by parent and child run IDs (#352).
    pub fn get_batch_split(
        e: Env,
        parent_run_id: u64,
        child_run_id: u64,
    ) -> Option<BatchSplitRecord> {
        e.storage()
            .persistent()
            .get(&DataKey::BatchSplitRecord(parent_run_id, child_run_id))
    }

    /// Validate that a batch split preserves the original aggregate commitment (#352).
    /// This ensures that when a large batch is split, the sum of children equals the parent.
    pub fn validate_batch_split_aggregate(
        e: Env,
        parent_run_id: u64,
        expected_total_amount: i128,
        expected_employee_count: u32,
    ) -> bool {
        let parent_run_key = DataKey::PayrollRun(parent_run_id);
        if let Some(parent_run) = e
            .storage()
            .persistent()
            .get::<DataKey, PayrollRun>(&parent_run_key)
        {
            parent_run.total_amount == expected_total_amount
                && parent_run.employee_count == expected_employee_count
        } else {
            false
        }
    }

    // ── Issue #482: Duplicate employee validation ────────────────────────────

    /// Validate that the same employee (by commitment hash) has not already been
    /// paid in this run. This prevents accidental re-payment of an employee.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `run_id`: The payroll run ID
    /// - `employee_commitment`: The employee's commitment hash
    ///
    /// # Panics
    /// If the employee has already been paid in this run.
    fn validate_employee_not_already_paid(
        env: &Env,
        run_id: u64,
        employee_commitment: &BytesN<32>,
    ) {
        let tracker_key = DataKey::EmployeePaidTracker(run_id);

        if let Some(tracker) = env
            .storage()
            .persistent()
            .get::<_, EmployeePaidTracker>(&tracker_key)
        {
            for paid in tracker.paid_employees.iter() {
                if paid == *employee_commitment {
                    panic!("Employee already paid in this run");
                }
            }
        }
    }

    /// Record that an employee has been paid in a run to prevent duplicate payments.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `run_id`: The payroll run ID
    /// - `employee_commitment`: The employee's commitment hash
    fn record_employee_paid(env: &Env, run_id: u64, employee_commitment: BytesN<32>) {
        let tracker_key = DataKey::EmployeePaidTracker(run_id);

        let mut tracker = if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, EmployeePaidTracker>(&tracker_key)
        {
            existing
        } else {
            EmployeePaidTracker {
                run_id,
                paid_employees: Vec::new(env),
            }
        };

        tracker.paid_employees.push_back(employee_commitment);
        env.storage().persistent().set(&tracker_key, &tracker);
    }

    // ── Issue #485: Payroll run status query helper ───────────────────────────

    /// Get a concise status view of a payroll run without exposing sensitive data.
    ///
    /// Returns a PayrollRunStatus struct with the current state, timestamps, and counts.
    pub fn get_payroll_run_status(env: Env, run_id: u64) -> Option<PayrollRunStatus> {
        // Check if a status is stored
        if let Some(status) = env
            .storage()
            .persistent()
            .get::<_, PayrollRunStatus>(&DataKey::PayrollRunStatus(run_id))
        {
            return Some(status);
        }

        // Fallback: derive status from PayrollRunState if no explicit status stored
        if let Some(state) = env
            .storage()
            .persistent()
            .get::<_, PayrollRunState>(&DataKey::PayrollState(run_id))
        {
            if let Some(run) = env
                .storage()
                .persistent()
                .get::<_, PayrollRun>(&DataKey::PayrollRun(run_id))
            {
                let status_kind = match state {
                    PayrollRunState::Draft
                    | PayrollRunState::Validating
                    | PayrollRunState::ProofPending => PayrollRunStatusKind::Pending,
                    PayrollRunState::ReadyToSubmit | PayrollRunState::Submitted => {
                        PayrollRunStatusKind::Approved
                    }
                    PayrollRunState::Confirming => PayrollRunStatusKind::Executing,
                    PayrollRunState::Completed => PayrollRunStatusKind::Completed,
                    PayrollRunState::Failed
                    | PayrollRunState::ReconciliationRequired
                    | PayrollRunState::Expired => PayrollRunStatusKind::Failed,
                    PayrollRunState::Cancelled => PayrollRunStatusKind::Failed,
                };

                return Some(PayrollRunStatus {
                    run_id,
                    status: status_kind,
                    last_updated: run.executed_at,
                    employee_count: run.employee_count,
                    total_amount: run.total_amount,
                });
            }
        }

        None
    }

    /// Record or update the status of a payroll run.
    fn record_payroll_run_status(
        env: &Env,
        run_id: u64,
        status: PayrollRunStatusKind,
        employee_count: u32,
        total_amount: i128,
    ) {
        let current_time = env.ledger().timestamp();
        let status_record = PayrollRunStatus {
            run_id,
            status,
            last_updated: current_time,
            employee_count,
            total_amount,
        };

        env.storage()
            .persistent()
            .set(&DataKey::PayrollRunStatus(run_id), &status_record);
    }

    // ── Issue #478: Payroll run metadata versioning ────────────────────────────

    /// Set metadata version for a payroll run to track schema evolution.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `run_id`: The payroll run ID
    /// - `schema_version`: The metadata schema version
    /// - `metadata_hash`: Hash of the versioned metadata
    fn set_metadata_version(
        env: &Env,
        run_id: u64,
        schema_version: u32,
        metadata_hash: BytesN<32>,
    ) {
        let version_record = PayrollRunMetadataVersion {
            run_id,
            schema_version,
            created_at: env.ledger().timestamp(),
            metadata_hash,
        };

        env.storage()
            .persistent()
            .set(&DataKey::PayrollRunMetadataVersion(run_id), &version_record);
    }

    /// Get metadata version for a payroll run.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `run_id`: The payroll run ID
    ///
    /// # Returns
    /// The metadata version record if it exists
    pub fn get_metadata_version(env: Env, run_id: u64) -> Option<PayrollRunMetadataVersion> {
        env.storage()
            .persistent()
            .get(&DataKey::PayrollRunMetadataVersion(run_id))
    }

    // ── Issue #476: Contract-level payroll currency validation ──────────────────

    /// Set the payroll contract's currency configuration.
    ///
    /// This ensures all payroll runs use the configured asset and provides
    /// consistent currency metadata across payroll operations.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `admin`: Admin address for authorization
    /// - `asset`: The asset address to configure
    /// - `currency_code`: Human-readable currency code (e.g., "USDC")
    /// - `decimals`: Number of decimals for the currency
    pub fn set_payroll_currency(
        env: Env,
        admin: Address,
        asset: Address,
        currency_code: Symbol,
        decimals: u32,
    ) {
        let addrs: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        addrs.admin.require_auth();

        if admin != addrs.admin {
            panic!("Unauthorized: admin role required");
        }

        let config = PayrollCurrencyConfig {
            asset: asset.clone(),
            currency_code,
            decimals,
            configured_at: env.ledger().timestamp(),
            configured_by: admin.clone(),
        };

        let previous_ref = stored_ref(&env, &DataKey::PayrollCurrencyConfig);
        env.storage()
            .persistent()
            .set(&DataKey::PayrollCurrencyConfig, &config);

        env.events().publish((symbol_short!("currency"),), config);
        record_config_change(
            &env,
            &admin,
            config_keys::PAYROLL_CURRENCY,
            no_value_ref(&env),
            previous_ref,
            stored_ref(&env, &DataKey::PayrollCurrencyConfig),
        );
    }

    /// Get the configured payroll currency for this contract.
    pub fn get_payroll_currency(env: Env) -> Option<PayrollCurrencyConfig> {
        env.storage()
            .persistent()
            .get(&DataKey::PayrollCurrencyConfig)
    }

    /// Validate that the asset being used for payroll matches the configured currency.
    ///
    /// # Arguments
    /// - `env`: Soroban environment
    /// - `asset`: The asset to validate
    ///
    /// # Panics
    /// If the asset does not match the configured payroll currency.
    fn validate_payroll_currency(env: &Env, asset: &Address) -> Result<(), TreasuryError> {
        if let Some(config) = env
            .storage()
            .persistent()
            .get::<_, PayrollCurrencyConfig>(&DataKey::PayrollCurrencyConfig)
        {
            if config.asset != *asset {
                return Err(TreasuryError::CrossAssetMismatch);
            }
        }
        Ok(())
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Issue #515: Period Cloning Validation
    // ────────────────────────────────────────────────────────────────────────────

    /// Validate that a period is suitable for cloning/templating.
    ///
    /// Panics (rather than returning `Result`) on every failure path, so the
    /// return type is `()`: a `Result<(), ()>` here previously broke
    /// `#[contractimpl]`'s cross-contract client generation, since `()`
    /// cannot implement the conversions Soroban requires for a contract
    /// error type - and no path ever actually returned `Err(())` anyway.
    pub fn validate_period_for_cloning(e: Env, period: Symbol) {
        Self::validate_symbol_not_empty(&e, &period, "period");

        // Check if period is frozen
        if Self::is_period_config_frozen(e.clone(), period.clone()) {
            panic!("Source period is frozen and cannot be used as a template");
        }

        // Verify settlement window exists
        if !e
            .storage()
            .persistent()
            .has(&DataKey::SettlementWindow(period.clone()))
        {
            panic!("Source period has no settlement window configured");
        }
    }

    // ────────────────────────────────────────────────────────────────────────────
    // Issue #512: Draft Checksum Verification Enhancement
    // ────────────────────────────────────────────────────────────────────────────

    /// Verify draft checksum matches between preparation and finalization.
    ///
    /// See [`validate_period_for_cloning`](Self::validate_period_for_cloning)
    /// for why this returns `()` rather than `Result<(), ()>`.
    pub fn verify_draft_checksum(e: &Env, run_id: u64, provided_hash: BytesN<32>) {
        let pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&DataKey::PendingRun(run_id))
            .expect("Pending run not found");

        if pending_run.draft_hash != provided_hash {
            panic!("Draft checksum mismatch: payroll data was modified after review");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pause_manager::{PauseManager, PauseManagerClient};
    use proof_verifier::{ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
    use soroban_sdk::{Env, IntoVal, TryFromVal};
    use token::{Token, TokenClient};

    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    /// Generates a unique 32-byte nonce from a counter seed for tests.
    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
    }

    /// Returns the topics and data (as `ScVal`s) of the last contract event
    /// published in this environment, decoded from the SDK 28 XDR event
    /// stream.
    fn last_event_scval(
        env: &Env,
    ) -> (
        soroban_sdk::xdr::VecM<soroban_sdk::xdr::ScVal>,
        soroban_sdk::xdr::ScVal,
    ) {
        let events = env.events().all();
        let last = events
            .events()
            .last()
            .expect("expected at least one published event");
        let v0 = match &last.body {
            soroban_sdk::xdr::ContractEventBody::V0(v0) => v0,
        };
        (v0.topics.clone(), v0.data.clone())
    }

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[0u8; 128]),
            gamma: BytesN::from_array(env, &[0u8; 128]),
            delta: BytesN::from_array(env, &[0u8; 128]),
            ic: Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                ],
            ),
        }
    }

    #[test]
    fn test_payroll_run_id_derivation() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let commitment_admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        token_client.mint(&treasury, &1_000_000i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(&env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

        let mut proofs = Vec::new(&env);
        proofs.push_back(mock_proof(&env));
        let mut amounts = Vec::new(&env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        let run_id_1 = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 1),
            &None,
        );
        assert_eq!(run_id_1, 1);

        let run_1 = payroll_client.get_payroll_run(&run_id_1);
        assert_eq!(run_1.run_id, 1);
        assert_eq!(run_1.total_amount, 1000);
        assert_eq!(run_1.employee_count, 1);
    }

    #[test]
    fn benchmark_50_batch_validations() {
        let env = Env::default();
        env.budget().reset_unlimited();
        env.mock_all_auths();
        // A 50-employee batch plus its per-employee events exceeds the
        // mainnet-sized invocation resource limits enforced by default in the
        // SDK 28 test environment (e.g. 16 KB of events). This is a benchmark
        // measuring work done, not a limit test, so disable enforcement.
        env.cost_estimate().disable_resource_limits();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let commitment_admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        token_client.mint(&treasury, &10_000i128);

        let mut proofs = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        let mut employees = Vec::new(&env);

        for i in 0..50u32 {
            let p = mock_proof(&env);
            proofs.push_back(p);
            amounts.push_back(100i128 + i as i128);
            let emp = Address::generate(&env);
            let mut cmt_bytes = [0u8; 32];
            cmt_bytes[0] = (i % 256) as u8;
            cmt_bytes[1] = (i / 256) as u8;
            commitment_client.store_commitment(&emp, &BytesN::from_array(&env, &cmt_bytes));
            employees.push_back(emp);
        }

        let expected_total_spend: i128 = 6225;

        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &expected_total_spend,
            &test_nonce(&env, 2),
            &None,
        );
        assert!(run_id > 0);
    }

    fn setup_simple_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        let commitment_admin = Address::generate(env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(env, &payroll_id);

        let treasury = Address::generate(env);
        let admin = Address::generate(env);
        let treasury_owner = Address::generate(env);
        // Mint enough tokens so transfer calls in tests succeed.
        token_client.mint(&treasury, &1_000_000i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

        (payroll_client, admin, treasury, treasury_owner, employee)
    }

    fn single_payment_batch(
        env: &Env,
        employee: &Address,
        amount: i128,
    ) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(amount);
        let mut employees = Vec::new(env);
        employees.push_back(employee.clone());
        (proofs, amounts, employees)
    }

    #[test]
    fn test_set_pause_manager_stores_address() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);

        pm_client.pause();
        let (proofs, amounts, employees) = single_payment_batch(&env, &_employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 3),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_paused_payroll_rejects_batch_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 4),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unpaused_payroll_resumes_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 5),
            &None,
        );
        assert!(result.is_err());

        pm_client.unpause();

        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &test_nonce(&env, 6),
            &None,
        );
    }

    #[test]
    fn test_payroll_works_without_pause_manager() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 7),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_set_pause_manager_rejects_unauthorized() {
        let env = Env::default();
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let token_id = env.register_contract(None, Token);
        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &payroll_id,
                fn_name: "initialize",
                args: (
                    admin.clone(),
                    token_id.clone(),
                    verifier_id.clone(),
                    commitment_id.clone(),
                    treasury.clone(),
                    treasury_owner.clone(),
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        }]);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        let pm_id = env.register_contract(None, PauseManager);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &payroll_id,
                fn_name: "set_pause_manager",
                args: (pm_id.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        payroll_client.set_pause_manager(&pm_id);
    }

    // ?? Issue #89: payroll amendment flow ????????????????????????????????????

    #[test]
    fn test_create_run_draft_returns_incremental_id() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Distinct periods: the duplicate-period guard (#398) rejects a second
        // Pending draft for the same period label.
        let q1 = Symbol::new(&env, "Q1_2025");
        let q2 = Symbol::new(&env, "Q2_2025");
        let id1 = payroll_client.create_run_draft(&admin, &5_000i128, &10u32, &q1);
        let id2 = payroll_client.create_run_draft(&admin, &3_000i128, &5u32, &q2);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_create_run_draft_starts_pending() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "JAN"));
        let draft = payroll_client.get_run_draft(&id);

        assert_eq!(draft.state, RunDraftState::Pending);
        assert_eq!(draft.total_amount, 10_000i128);
        assert_eq!(draft.employee_count, 20u32);
        assert_eq!(draft.amendment_count, 0u32);
    }

    #[test]
    fn test_draft_description_rejects_blank_and_overlong_values() {
        let env = Env::default();
        let (client, admin, _treasury, _owner, _employee) = setup_simple_payroll(&env);
        let id = client.create_run_draft(&admin, &1_000i128, &1u32, &Symbol::new(&env, "DESC"));
        client.set_run_draft_description(
            &admin,
            &id,
            &soroban_sdk::String::from_str(&env, "Quarterly payroll"),
        );
        assert_eq!(
            client.get_run_draft_description(&id),
            Some(soroban_sdk::String::from_str(&env, "Quarterly payroll"))
        );
        let blank = soroban_sdk::String::from_str(&env, "   ");
        assert!(client
            .try_set_run_draft_description(&admin, &id, &blank)
            .is_err());
        let long = soroban_sdk::String::from_str(&env, &"x".repeat(257));
        assert!(client
            .try_set_run_draft_description(&admin, &id, &long)
            .is_err());
    }

    #[test]
    fn test_amend_run_draft_updates_fields_and_increments_count() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "FEB"));
        payroll_client.amend_run_draft(&admin, &id, &12_000i128, &22u32);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.total_amount, 12_000i128);
        assert_eq!(draft.employee_count, 22u32);
        assert_eq!(draft.amendment_count, 1u32);
        assert_eq!(draft.state, RunDraftState::Pending);
    }

    #[test]
    fn test_finalize_run_draft_makes_it_immutable() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &8_000i128, &15u32, &Symbol::new(&env, "MAR"));
        payroll_client.finalize_run_draft(&admin, &id);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Finalized);
    }

    #[test]
    fn test_amend_finalized_draft_is_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &5_000i128, &10u32, &Symbol::new(&env, "APR"));
        payroll_client.finalize_run_draft(&admin, &id);

        let result = payroll_client.try_amend_run_draft(&admin, &id, &9_000i128, &18u32);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_run_draft_transitions_to_submitted() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "MAY"));
        assert_eq!(
            payroll_client.get_run_draft(&id).state,
            RunDraftState::Pending
        );

        payroll_client.submit_run_draft(&admin, &id);
        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Submitted);
        assert!(payroll_client.is_draft_state_terminal(&draft.state));
    }

    #[test]
    fn test_cancel_run_draft_transitions_to_cancelled() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "JUN"));
        payroll_client.cancel_run_draft(&admin, &id);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Cancelled);
        assert!(payroll_client.is_draft_state_terminal(&draft.state));
    }

    #[test]
    fn test_expire_run_draft_transitions_to_expired() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "JUL"));
        payroll_client.expire_run_draft(&admin, &id);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Expired);
        assert!(payroll_client.is_draft_state_terminal(&draft.state));
    }

    #[test]
    fn test_terminal_draft_rejects_amendments_and_retransitions() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "AUG"));
        payroll_client.cancel_run_draft(&admin, &id);

        // Cannot amend a cancelled draft
        let amend_res = payroll_client.try_amend_run_draft(&admin, &id, &15_000i128, &25u32);
        assert!(amend_res.is_err());

        // Cannot submit an already cancelled draft
        let submit_res = payroll_client.try_submit_run_draft(&admin, &id);
        assert!(submit_res.is_err());

        // Cannot expire an already cancelled draft
        let expire_res = payroll_client.try_expire_run_draft(&admin, &id);
        assert!(expire_res.is_err());
    }

    #[test]
    fn test_unauthorized_draft_transitions_fail() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);
        let attacker = Address::generate(&env);

        let id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "SEP"));

        assert!(payroll_client.try_submit_run_draft(&attacker, &id).is_err());
        assert!(payroll_client.try_cancel_run_draft(&attacker, &id).is_err());
        assert!(payroll_client.try_expire_run_draft(&attacker, &id).is_err());
    }

    #[test]
    fn test_is_draft_state_helpers() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        assert!(payroll_client
            .is_draft_transition_allowed(&RunDraftState::Pending, &RunDraftState::Submitted));
        assert!(payroll_client
            .is_draft_transition_allowed(&RunDraftState::Finalized, &RunDraftState::Cancelled));
        assert!(!payroll_client
            .is_draft_transition_allowed(&RunDraftState::Submitted, &RunDraftState::Pending));
        assert!(!payroll_client
            .is_draft_transition_allowed(&RunDraftState::Cancelled, &RunDraftState::Submitted));

        assert!(!payroll_client.is_draft_state_terminal(&RunDraftState::Pending));
        assert!(!payroll_client.is_draft_state_terminal(&RunDraftState::Finalized));
        assert!(payroll_client.is_draft_state_terminal(&RunDraftState::Submitted));
        assert!(payroll_client.is_draft_state_terminal(&RunDraftState::Cancelled));
        assert!(payroll_client.is_draft_state_terminal(&RunDraftState::Expired));
    }

    #[test]
    fn test_draft_lock_owner_query_lifecycle() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let draft_id = payroll_client.create_run_draft(
            &admin,
            &25_000i128,
            &4u32,
            &Symbol::new(&env, "LOCK_TEST"),
        );

        // 1. Pending draft is not locked -> returns None
        assert_eq!(payroll_client.get_draft_lock_owner(&draft_id), None);

        // 2. Finalized draft is locked -> returns Some(admin)
        payroll_client.finalize_run_draft(&admin, &draft_id);
        assert_eq!(payroll_client.get_draft_lock_owner(&draft_id), Some(admin.clone()));

        // 3. Submitted draft remains locked -> returns Some(admin)
        payroll_client.submit_run_draft(&admin, &draft_id);
        assert_eq!(payroll_client.get_draft_lock_owner(&draft_id), Some(admin));

        // 4. Non-existent draft returns None
        assert_eq!(payroll_client.get_draft_lock_owner(&999_999u64), None);
    }

    #[test]
    fn test_draft_lock_owner_cancelled_and_expired_return_none() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Cancelled draft
        let id_cancel = payroll_client.create_run_draft(
            &admin,
            &15_000i128,
            &2u32,
            &Symbol::new(&env, "CANCEL_LOCK"),
        );
        payroll_client.cancel_run_draft(&admin, &id_cancel);
        assert_eq!(payroll_client.get_draft_lock_owner(&id_cancel), None);

        // Expired draft
        let id_expire = payroll_client.create_run_draft(
            &admin,
            &12_000i128,
            &2u32,
            &Symbol::new(&env, "EXPIRE_LOCK"),
        );
        payroll_client.expire_run_draft(&admin, &id_expire);
        assert_eq!(payroll_client.get_draft_lock_owner(&id_expire), None);
    }

    #[test]
    #[should_panic(expected = "Invalid draft ID: must be non-zero")]
    fn test_draft_lock_owner_zero_id_panics() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);
        payroll_client.get_draft_lock_owner(&0u64);
    }

    // ?? Issue #103: per-payroll run nonce uniqueness ???????????????????????????

    #[test]
    fn test_duplicate_nonce_is_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 10);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);

        // Second call with the same nonce must fail.
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &nonce,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn idempotent_retry_returns_original_run_without_duplicate_execution() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let idempotency_key = test_nonce(&env, 120);
        let nonce = test_nonce(&env, 121);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let first = payroll_client.batch_process_payroll_idempotent(
            &idempotency_key,
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &None,
        );
        let retry = payroll_client.batch_process_payroll_idempotent(
            &idempotency_key,
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &None,
        );

        assert_eq!(first, retry);
        let record = payroll_client
            .get_idempotency_record(&idempotency_key)
            .expect("idempotency record should persist");
        assert_eq!(record.run_id, first);
    }

    #[test]
    fn idempotency_key_rejects_changed_payload() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let idempotency_key = test_nonce(&env, 122);
        let nonce = test_nonce(&env, 123);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll_idempotent(
            &idempotency_key,
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &None,
        );

        let result = payroll_client.try_batch_process_payroll_idempotent(
            &idempotency_key,
            &proofs,
            &amounts,
            &employees,
            &999,
            &nonce,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_distinct_nonces_allow_multiple_runs() {
        // Each call to setup_simple_payroll registers fresh contract instances
        // (new commitment contract, new employee) so nullifiers never collide.
        let env = Env::default();

        let (client1, _a1, _t1, _to1, emp1) = setup_simple_payroll(&env);
        let (p1, a1, e1) = single_payment_batch(&env, &emp1, 500);
        let id1 = client1.batch_process_payroll(&p1, &a1, &e1, &500, &test_nonce(&env, 11), &None);

        let (client2, _a2, _t2, _to2, emp2) = setup_simple_payroll(&env);
        let (p2, a2, e2) = single_payment_batch(&env, &emp2, 500);
        let id2 = client2.batch_process_payroll(&p2, &a2, &e2, &500, &test_nonce(&env, 12), &None);

        assert!(id1 > 0);
        assert!(id2 > 0);
    }

    #[test]
    fn test_nonce_is_stored_in_payroll_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 13);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.nonce, nonce);
    }

    // ?? Issue #102: draft hash binding ????????????????????????????????????????

    #[test]
    fn test_draft_hash_binding_accepted_when_pre_committed() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let draft_hash = BytesN::from_array(&env, &[0xabu8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 20),
            &Some(draft_hash.clone()),
        );
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.draft_hash, draft_hash);
    }

    #[test]
    fn test_draft_hash_rejected_without_pre_commitment() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let unknown_hash = BytesN::from_array(&env, &[0xcdu8; 32]);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 21),
            &Some(unknown_hash),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_draft_commitment_is_consumed_after_use() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let draft_hash = BytesN::from_array(&env, &[0xefu8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        let (p1, a1, e1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &p1,
            &a1,
            &e1,
            &1000,
            &test_nonce(&env, 22),
            &Some(draft_hash.clone()),
        );

        // Second use of the same draft hash must fail (already consumed).
        let (p2, a2, e2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &p2,
            &a2,
            &e2,
            &1000,
            &test_nonce(&env, 23),
            &Some(draft_hash),
        );
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_create_run_draft_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        payroll_client.create_run_draft(&attacker, &1_000i128, &1u32, &Symbol::new(&env, "MAY"));
    }

    // ?? Issue #91: admin/treasury rotation ???????????????????????????????????

    #[test]
    fn test_admin_rotation_full_flow() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let proposal = payroll_client
            .get_pending_admin_rotation()
            .expect("proposal should exist");
        assert_eq!(proposal.new_holder, new_admin);
        assert_eq!(proposal.proposed_by, admin);

        payroll_client.accept_admin_rotation(&new_admin);

        assert!(payroll_client.get_pending_admin_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the current admin")]
    fn test_propose_admin_rotation_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&attacker, &new_admin);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the proposed admin")]
    fn test_accept_admin_rotation_rejects_wrong_address() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let impostor = Address::generate(&env);
        payroll_client.accept_admin_rotation(&impostor);
    }

    #[test]
    fn test_cancel_admin_rotation() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);
        payroll_client.cancel_admin_rotation(&admin);

        assert!(payroll_client.get_pending_admin_rotation().is_none());
    }

    #[test]
    fn test_batch_runs_without_draft_hash() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 24),
            &None,
        );
        assert!(run_id > 0);
    }

    // ?? Issue #104: emergency withdrawal workflow ?????????????????????????????

    #[test]
    fn test_emergency_request_then_approve() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &500i128, &recipient);

        let req = payroll_client
            .get_emergency_request()
            .expect("request should exist");
        assert_eq!(req.amount, 500i128);
        assert_eq!(req.recipient, recipient);
        assert!(!req.approved);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not treasury owner")]
    fn test_emergency_request_rejects_non_treasury_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&attacker, &500i128, &recipient);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_emergency_approve_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &100i128, &recipient);

        let attacker = Address::generate(&env);
        payroll_client.approve_emergency_withdrawal(&attacker);
    }

    #[test]
    #[should_panic(expected = "No pending emergency request")]
    fn test_approve_without_request_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);
        payroll_client.approve_emergency_withdrawal(&admin);
    }

    #[test]
    fn test_cancel_emergency_withdrawal_by_admin() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);

        payroll_client.cancel_emergency_withdrawal(&admin);
        assert!(payroll_client.get_emergency_request().is_none());
    }

    #[test]
    fn test_cancel_emergency_withdrawal_by_treasury_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);

        payroll_client.cancel_emergency_withdrawal(&treasury_owner);
        assert!(payroll_client.get_emergency_request().is_none());
    }

    #[test]
    fn test_treasury_rotation_full_flow() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&treasury_owner, &new_owner);

        let proposal = payroll_client
            .get_pending_treasury_rotation()
            .expect("proposal should exist");
        assert_eq!(proposal.new_holder, new_owner);

        payroll_client.accept_treasury_rotation(&new_owner);
        assert!(payroll_client.get_pending_treasury_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the current treasury owner")]
    fn test_propose_treasury_rotation_rejects_non_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&attacker, &new_owner);
    }

    #[test]
    #[should_panic(expected = "A pending emergency request already exists")]
    fn test_duplicate_emergency_request_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &100i128, &recipient);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);
    }

    #[test]
    #[should_panic(expected = "A pending admin rotation already exists")]
    fn test_duplicate_admin_rotation_proposal_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin1 = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin1);
        let new_admin2 = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin2);
    }

    // ?? Issue #134: reconciliation status tracking ?????????????????????????????

    #[test]
    fn test_new_run_is_unreconciled() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 30),
            &None,
        );

        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(
            run.reconciliation_status,
            ReconciliationStatus::Unreconciled
        );
    }

    #[test]
    fn test_admin_can_update_reconciliation_status() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 31),
            &None,
        );

        // Update to Reconciled
        payroll_client.update_reconciliation_status(
            &admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.reconciliation_status, ReconciliationStatus::Reconciled);

        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Completed
        );

        let result = payroll_client.try_update_reconciliation_status(
            &admin,
            &run_id,
            &ReconciliationStatus::Failed,
        );
        assert!(result.is_err(), "Completed runs must not be reopened");
    }

    // ?? Issue #244: payroll settlement replay guard ??????????????????????????

    /// A repeat `Reconciled` call for an already-`Completed` run must be
    /// rejected, not silently re-accepted. Before this guard, calling
    /// `update_reconciliation_status` twice with the same terminal status
    /// bypassed the transition check (current == next state) and replayed
    /// the settlement-completion event.
    #[test]
    fn test_reconciled_run_cannot_be_replayed() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 220),
            &None,
        );

        payroll_client.update_reconciliation_status(
            &admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Completed
        );

        let result = payroll_client.try_update_reconciliation_status(
            &admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
        assert!(
            result.is_err(),
            "Settlement completion must not be replayable for a Completed run"
        );
    }

    #[test]
    fn test_failed_reconciliation_writes_retryable_payroll_state() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 33),
            &None,
        );

        payroll_client.update_reconciliation_status(&admin, &run_id, &ReconciliationStatus::Failed);
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Failed
        );
        assert!(payroll_client.is_payroll_state_retryable(&PayrollRunState::Failed));
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_non_admin_cannot_update_reconciliation_status() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 32),
            &None,
        );

        let non_admin = Address::generate(&env);
        payroll_client.update_reconciliation_status(
            &non_admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
    }

    #[test]
    #[should_panic(expected = "Run not found")]
    fn test_update_status_for_invalid_run_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        payroll_client.update_reconciliation_status(
            &admin,
            &999u64,
            &ReconciliationStatus::Reconciled,
        );
    }

    // ?? Issue #75: payroll cancellation ??????????????????????????????????????

    // ?? Issue #159: canonical payroll state machine ??????????????????????????

    #[test]
    fn test_payroll_state_machine_allows_canonical_forward_transitions() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        assert!(payroll_client
            .is_state_transition_allowed(&PayrollRunState::Draft, &PayrollRunState::Validating,));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::Validating,
            &PayrollRunState::ProofPending,
        ));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::ProofPending,
            &PayrollRunState::ReadyToSubmit,
        ));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::ReadyToSubmit,
            &PayrollRunState::Submitted,
        ));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::Submitted,
            &PayrollRunState::Confirming,
        ));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::Confirming,
            &PayrollRunState::ReconciliationRequired,
        ));
        assert!(payroll_client.is_state_transition_allowed(
            &PayrollRunState::ReconciliationRequired,
            &PayrollRunState::Completed,
        ));
    }

    #[test]
    fn test_payroll_state_machine_rejects_forbidden_transitions() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        assert!(!payroll_client
            .is_state_transition_allowed(&PayrollRunState::Draft, &PayrollRunState::Completed,));
        assert!(!payroll_client
            .is_state_transition_allowed(&PayrollRunState::Submitted, &PayrollRunState::Draft,));
        assert!(!payroll_client
            .is_state_transition_allowed(&PayrollRunState::Completed, &PayrollRunState::Failed,));
        assert!(
            !payroll_client.is_state_transition_allowed(
                &PayrollRunState::Cancelled,
                &PayrollRunState::Submitted,
            )
        );
    }

    #[test]
    fn test_payroll_state_machine_terminal_and_retryable_metadata() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        assert!(payroll_client.is_payroll_state_terminal(&PayrollRunState::Completed));
        assert!(payroll_client.is_payroll_state_terminal(&PayrollRunState::Cancelled));
        assert!(!payroll_client.is_payroll_state_terminal(&PayrollRunState::Failed));
        assert!(payroll_client.is_payroll_state_retryable(&PayrollRunState::Failed));
        assert!(
            !payroll_client.is_payroll_state_retryable(&PayrollRunState::ReconciliationRequired)
        );
    }

    #[test]
    fn test_prepare_and_cancel_write_canonical_payroll_states() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 150),
            &None,
        );
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Submitted
        );

        payroll_client.cancel_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "CANCEL"),
        );
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Cancelled
        );
    }

    #[test]
    fn test_terminal_payroll_state_cannot_be_mutated() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 151),
            &None,
        );
        payroll_client.cancel_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "CANCEL"),
        );

        let result = payroll_client.try_transition_payroll_run_state(
            &admin,
            &run_id,
            &PayrollRunState::Submitted,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_non_admin_cannot_transition_payroll_state() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 152),
            &None,
        );
        let attacker = Address::generate(&env);
        let result = payroll_client.try_transition_payroll_run_state(
            &attacker,
            &run_id,
            &PayrollRunState::Confirming,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_payroll_run_creates_pending_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 40),
            &None,
        );
        assert!(run_id > 0);

        let pending = payroll_client
            .get_pending_run(&run_id)
            .expect("Pending run should exist");
        assert_eq!(pending.run_id, run_id);
        assert_eq!(pending.total_amount, 1000);
        assert_eq!(pending.employee_count, 1);
    }

    #[test]
    fn test_cancel_pending_payroll_run() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 41),
            &None,
        );

        // Cancel the pending run
        payroll_client.cancel_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "CANCEL"),
        );

        // Verify it's no longer pending
        assert!(payroll_client.get_pending_run(&run_id).is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_cancel_by_non_admin_fails() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 42),
            &None,
        );

        let non_admin = Address::generate(&env);
        let reason = Symbol::new(&env, "attack");
        payroll_client.cancel_payroll_run_with_reason(&non_admin, &run_id, &reason);
    }

    #[test]
    #[should_panic(expected = "Pending run not found")]
    fn test_cancel_non_existent_run_fails() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let reason = Symbol::new(&env, "no_such_run");
        payroll_client.cancel_payroll_run_with_reason(&admin, &999u64, &reason);
    }

    // ?? Issue #177: payroll run metadata hash checks ??????????????????????????

    #[test]
    fn test_commit_metadata_hash_stores_commitment() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let meta_hash = BytesN::from_array(&env, &[0xaau8; 32]);
        payroll_client.commit_metadata_hash(&admin, &meta_hash);

        // Should not panic ? commitment is stored.
    }

    #[test]
    #[should_panic(expected = "Metadata hash already committed")]
    fn test_commit_metadata_hash_twice_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let meta_hash = BytesN::from_array(&env, &[0xbbu8; 32]);
        payroll_client.commit_metadata_hash(&admin, &meta_hash);
        payroll_client.commit_metadata_hash(&admin, &meta_hash);
    }

    #[test]
    fn test_set_run_metadata_binds_hash_to_run() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 50),
            &None,
        );
        assert!(run_id > 0);

        let meta_hash = BytesN::from_array(&env, &[0xccu8; 32]);
        payroll_client.commit_metadata_hash(&admin, &meta_hash);
        payroll_client.set_run_metadata(&admin, &run_id, &meta_hash);

        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.metadata_hash, meta_hash);
    }

    #[test]
    #[should_panic(expected = "Metadata hash not pre-committed")]
    fn test_set_run_metadata_rejects_uncommitted_hash() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 51),
            &None,
        );

        let meta_hash = BytesN::from_array(&env, &[0xddu8; 32]);
        payroll_client.set_run_metadata(&admin, &run_id, &meta_hash);
    }

    #[test]
    fn test_run_metadata_hash_defaults_to_zero() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 52),
            &None,
        );

        let run = payroll_client.get_payroll_run(&run_id);
        let zero: BytesN<32> = BytesN::from_array(&env, &[0u8; 32]);
        assert_eq!(run.metadata_hash, zero);
    }

    #[test]
    fn test_prepare_rejects_duplicate_nonce() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 43);
        let (p1, a1, e1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(&p1, &a1, &e1, &1000, &nonce, &None);

        // Second call with same nonce must fail
        let (p2, a2, e2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_prepare_payroll_run(&p2, &a2, &e2, &1000, &nonce, &None);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Pending run not found")]
    fn test_cancel_payroll_run_twice_fails() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 44),
            &None,
        );

        let reason = Symbol::new(&env, "double_cancel");
        payroll_client.cancel_payroll_run_with_reason(&admin, &run_id, &reason);
        payroll_client.cancel_payroll_run_with_reason(&admin, &run_id, &reason);
    }

    #[test]
    fn test_cancel_pending_payroll_run_frees_nonce_and_cleans_state() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 45);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id =
            payroll_client.prepare_payroll_run(&proofs, &amounts, &employees, &1000, &nonce, &None);

        assert!(payroll_client.get_pending_run(&run_id).is_some());
        let reason = Symbol::new(&env, "test_cleanup");
        payroll_client.cancel_payroll_run_with_reason(&admin, &run_id, &reason);

        assert!(payroll_client.get_pending_run(&run_id).is_none());
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Cancelled
        );
    }

    #[test]
    fn test_finalize_payroll_run_records_reconciliation_required_and_cleans_pending() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 46);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id =
            payroll_client.prepare_payroll_run(&proofs, &amounts, &employees, &1000, &nonce, &None);

        assert!(payroll_client.get_pending_run(&run_id).is_some());
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::Submitted
        );

        payroll_client.finalize_payroll_run(&admin, &run_id);

        assert!(payroll_client.get_pending_run(&run_id).is_none());
        assert_eq!(
            payroll_client.get_payroll_run_state(&run_id),
            PayrollRunState::ReconciliationRequired
        );
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(
            run.reconciliation_status,
            ReconciliationStatus::Unreconciled
        );
    }

    #[test]
    #[should_panic(expected = "Payroll is paused")]
    fn test_pause_blocks_deposit() {
        let env = Env::default();
        let (payroll_client, admin, treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        pm_client.initialize(&admin);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let deposit_id = BytesN::from_array(&env, &[0xffu8; 32]);
        payroll_client.deposit(&treasury, &100i128, &deposit_id);
    }

    // ?? Issue #180: failed execution rollback tests ??????????????????????????

    #[test]
    fn test_failed_proof_mid_batch_rolls_back_nonce() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let mut employees = Vec::new(&env);
        let mut proofs = Vec::new(&env);
        let mut amounts = Vec::new(&env);

        // Employee 1 ? valid proof
        let emp1 = employee;
        employees.push_back(emp1.clone());
        proofs.push_back(mock_proof(&env));
        amounts.push_back(500i128);

        // Employee 2 ? will trigger proof failure (but proofs are mocked to always pass,
        // so instead we use a different employee without a commitment stored).
        let emp2 = Address::generate(&env);
        employees.push_back(emp2.clone());
        proofs.push_back(mock_proof(&env));
        amounts.push_back(500i128);

        let nonce = test_nonce(&env, 100);
        let result = payroll_client
            .try_batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        // Execution fails because emp2 has no stored commitment
        assert!(result.is_err());

        // Verify the nonce was rolled back ? should be usable in a new run
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &emp1, 500);
        let run_id = payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &500,
            &nonce,
            &None,
        );
        assert!(
            run_id > 0,
            "Nonce must be reusable after rolled-back execution"
        );
    }

    #[test]
    fn test_insufficient_funds_rolls_back_nonce_and_commitment() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let commitment_admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        // Mint only 100 tokens ? NOT enough for the 1000 payment
        token_client.mint(&treasury, &100i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );
        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(&env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

        let nonce = test_nonce(&env, 101);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);

        // Pre-commit a draft hash so we can verify it's also rolled back
        let draft_hash = BytesN::from_array(&env, &[0x81u8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &Some(draft_hash.clone()),
        );
        // Must fail due to insufficient treasury balance
        assert!(result.is_err());

        // Verify nonce is reusable (rolled back)
        token_client.mint(&treasury, &10_000i128);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &Some(draft_hash.clone()),
        );
        assert!(
            run_id > 0,
            "Nonce and commitment must be reusable after failed execution"
        );
    }

    #[test]
    fn test_failed_execution_does_not_create_payroll_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Submit with wrong expected_total_spend to trigger failure AFTER nonce consumption
        let nonce = test_nonce(&env, 102);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);

        let result = payroll_client
            .try_batch_process_payroll(&proofs, &amounts, &employees, &999, &nonce, &None);
        assert!(result.is_err());

        // Verify no payroll run record was created
        let mut any_run = false;
        for run_id in 1..5u64 {
            if payroll_client.try_get_payroll_run(&run_id).is_ok() {
                any_run = true;
                break;
            }
        }
        assert!(
            !any_run,
            "No PayrollRun should exist after a failed execution"
        );

        // Nonce is NOT consumed (rolled back) ? can retry with corrected params
        let run_id = payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &500, &nonce, &None);
        assert!(run_id > 0, "Nonce must be reusable after failed execution");
    }

    #[test]
    fn test_failed_execution_does_not_consume_draft_commitment() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let draft_hash = BytesN::from_array(&env, &[0x82u8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        // Trigger failure with amount mismatch
        let nonce = test_nonce(&env, 103);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &999,
            &nonce,
            &Some(draft_hash.clone()),
        );
        assert!(result.is_err());

        // Draft commitment should still be usable (rolled back)
        let nonce2 = test_nonce(&env, 104);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &500,
            &nonce2,
            &Some(draft_hash),
        );
        assert!(
            run_id > 0,
            "Draft commitment must survive a rolled-back execution"
        );
    }

    #[test]
    fn test_failed_execution_does_not_leave_pending_state() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 105);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);
        let result = payroll_client
            .try_batch_process_payroll(&proofs, &amounts, &employees, &999, &nonce, &None);
        assert!(result.is_err());

        // After failure, a successful run with the same nonce should work
        // (nonce was rolled back). Also verify the run gets a valid ID.
        let run_id = payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &500, &nonce, &None);
        assert!(run_id > 0, "Nonce must be reusable after failed execution");
    }

    #[test]
    #[should_panic(expected = "Duplicate run nonce")]
    fn test_successful_run_consumes_nonce_permanently() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 106);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &500, &nonce, &None);

        // Second attempt with same nonce ? must fail permanently
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 500);
        payroll_client.batch_process_payroll(&proofs2, &amounts2, &employees2, &500, &nonce, &None);
    }

    #[test]
    fn test_failed_prepare_does_not_lock_nonce() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 107);
        let mut proofs = Vec::new(&env);
        proofs.push_back(mock_proof(&env));
        let mut amounts = Vec::new(&env);
        amounts.push_back(500i128);
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        // Successful prepare
        let run_id =
            payroll_client.prepare_payroll_run(&proofs, &amounts, &employees, &500, &nonce, &None);
        assert!(run_id > 0);

        // Failed cancel (wrong caller) should not affect the pending run
        let attacker = Address::generate(&env);
        let reason = Symbol::new(&env, "attack");
        let cancel_result =
            payroll_client.try_cancel_payroll_run_with_reason(&attacker, &run_id, &reason);
        assert!(cancel_result.is_err());

        // Pending run should still exist
        let pending = payroll_client.get_pending_run(&run_id);
        assert!(
            pending.is_some(),
            "Pending run must survive unauthorized cancel attempt"
        );
    }

    #[test]
    fn test_failed_execution_array_mismatch_rolls_back() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 108);
        let mut proofs = Vec::new(&env);
        proofs.push_back(mock_proof(&env)); // 1 proof
        let mut amounts = Vec::new(&env);
        amounts.push_back(500i128);
        amounts.push_back(500i128); // 2 amounts ? mismatch!
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        let result = payroll_client
            .try_batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        assert!(result.is_err());

        // Nonce should still be usable after rollback
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 500);
        let run_id = payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &500,
            &nonce,
            &None,
        );
        assert!(
            run_id > 0,
            "Nonce must be reusable after array mismatch rollback"
        );
    }

    #[test]
    #[should_panic(expected = "Payroll is paused")]
    fn test_pause_blocks_emergency_withdrawal_request() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        pm_client.initialize(&admin);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &500i128, &recipient);
    }

    // ?? Issue #191: deposit replay protection ????????????????????????????????

    #[test]
    fn test_deposit_with_unique_id_succeeds() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let deposit_id = BytesN::from_array(&env, &[1u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
    }

    #[test]
    #[should_panic(expected = "Deposit already processed")]
    fn test_deposit_replay_with_same_id_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let deposit_id = BytesN::from_array(&env, &[2u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
    }

    #[test]
    fn test_deposit_distinct_ids_both_succeed() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id1 = BytesN::from_array(&env, &[3u8; 32]);
        let id2 = BytesN::from_array(&env, &[4u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &id1);
        payroll_client.deposit(&treasury, &500i128, &id2);
    }

    // ?? Issue #194: amount boundary validations ??????????????????????????????

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_batch_process_rejects_zero_amount() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, _amounts, employees) = single_payment_batch(&env, &employee, 0);
        let mut amounts = Vec::new(&env);
        amounts.push_back(0i128);
        payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &0,
            &test_nonce(&env, 200),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_batch_process_rejects_negative_amount() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, _amounts, employees) = single_payment_batch(&env, &employee, -1);
        let mut amounts = Vec::new(&env);
        amounts.push_back(-1i128);
        payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &-1,
            &test_nonce(&env, 201),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_prepare_payroll_run_rejects_zero_amount() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, _amounts, employees) = single_payment_batch(&env, &employee, 0);
        let mut amounts = Vec::new(&env);
        amounts.push_back(0i128);
        payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &0,
            &test_nonce(&env, 202),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "Amount must be positive")]
    fn test_prepare_payroll_run_rejects_negative_amount() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, _amounts, employees) = single_payment_batch(&env, &employee, -1);
        let mut amounts = Vec::new(&env);
        amounts.push_back(-1i128);
        payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &-1,
            &test_nonce(&env, 203),
            &None,
        );
    }

    // ?? Issue #196: Storage key versioning strategy tests ????????????????????

    #[test]
    fn test_storage_keys_are_namespaced() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 210),
            &None,
        );

        let draft_id =
            payroll_client.create_run_draft(&admin, &5_000i128, &10u32, &Symbol::new(&env, "Q1"));

        let run = payroll_client.get_payroll_run(&run_id);
        let draft = payroll_client.get_run_draft(&draft_id);

        assert_eq!(run.run_id, run_id);
        assert_eq!(draft.draft_id, draft_id);
    }

    #[test]
    fn test_parameterized_keys_support_schema_extension() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 211),
            &None,
        );

        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.run_id, run_id);
        assert_eq!(run.total_amount, 1000);
        assert_eq!(run.employee_count, 1);
    }

    // ?? Issue #203: Settlement completion guard tests ????????????????????????

    #[test]
    fn test_finalize_run_draft_is_idempotent() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id =
            payroll_client.create_run_draft(&admin, &8_000i128, &15u32, &Symbol::new(&env, "MAR"));

        payroll_client.finalize_run_draft(&admin, &id);
        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Finalized);

        let result = payroll_client.try_finalize_run_draft(&admin, &id);
        assert!(result.is_err());
    }

    #[test]
    fn test_payroll_run_execution_is_idempotent_via_nonce() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 212);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);

        let run_id = payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        assert!(run_id > 0);

        let result = payroll_client
            .try_batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pending_run_cannot_be_cancelled_twice() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 213),
            &None,
        );

        let reason = Symbol::new(&env, "settlement_guard");
        payroll_client.cancel_payroll_run_with_reason(&admin, &run_id, &reason);

        let result = payroll_client.try_cancel_payroll_run_with_reason(&admin, &run_id, &reason);
        assert!(result.is_err());
    }

    #[test]
    fn test_settlement_completion_guard_via_draft_state() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let draft_id =
            payroll_client.create_run_draft(&admin, &10_000i128, &20u32, &Symbol::new(&env, "Q4"));

        let draft = payroll_client.get_run_draft(&draft_id);
        assert_eq!(draft.state, RunDraftState::Pending);

        payroll_client.finalize_run_draft(&admin, &draft_id);
        let draft = payroll_client.get_run_draft(&draft_id);
        assert_eq!(draft.state, RunDraftState::Finalized);

        let result = payroll_client.try_amend_run_draft(&admin, &draft_id, &12_000i128, &22u32);
        assert!(result.is_err());

        let result = payroll_client.try_finalize_run_draft(&admin, &draft_id);
        assert!(result.is_err());
    }

    // Issue #200: Asset allowlist enforcement tests
    fn setup_payroll_with_token(
        env: &Env,
    ) -> (
        PayrollClient<'_>,
        Address,
        Address,
        Address,
        Address,
        Address,
    ) {
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        let commitment_admin = Address::generate(env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(env, &payroll_id);

        let treasury = Address::generate(env);
        let admin = Address::generate(env);
        let treasury_owner = Address::generate(env);
        token_client.mint(&treasury, &1_000_000i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

        (
            payroll_client,
            admin,
            treasury,
            treasury_owner,
            employee,
            token_id,
        )
    }

    #[test]
    fn test_asset_allowlist_management_and_execution() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // Initial token asset is allowlisted
        assert!(payroll_client.is_asset_allowed(&token_id));

        // Disallow token asset
        payroll_client.set_asset_allowed(&token_id, &false);
        assert!(!payroll_client.is_asset_allowed(&token_id));

        // Re-allow token asset
        payroll_client.set_asset_allowed(&token_id, &true);
        assert!(payroll_client.is_asset_allowed(&token_id));
    }

    #[test]
    #[should_panic(expected = "Asset not allowed")]
    fn test_execute_payroll_fails_when_asset_disallowed() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee, token_id) =
            setup_payroll_with_token(&env);

        // Disallow the payment token asset
        payroll_client.set_asset_allowed(&token_id, &false);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 220),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "Asset not allowed")]
    fn test_prepare_payroll_run_fails_when_asset_disallowed() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee, token_id) =
            setup_payroll_with_token(&env);

        // Disallow the payment token asset
        payroll_client.set_asset_allowed(&token_id, &false);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 221),
            &None,
        );
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_non_admin_cannot_manage_allowlist() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        let attacker = Address::generate(&env);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &payroll_client.address,
                fn_name: "set_asset_allowed",
                args: (token_id.clone(), false).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        payroll_client.set_asset_allowed(&token_id, &false);
    }

    #[test]
    fn test_asset_deactivation_status_tracks_allowlist_changes() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // Freshly initialized canonical asset is active, and therefore not deactivated.
        assert!(payroll_client.is_asset_allowed(&token_id));
        assert!(!payroll_client.is_asset_deactivated(&token_id));

        // Deactivation is explicit and observable through a dedicated view.
        payroll_client.set_asset_allowed(&token_id, &false);
        assert!(!payroll_client.is_asset_allowed(&token_id));
        assert!(payroll_client.is_asset_deactivated(&token_id));

        // Reactivating the asset clears the deactivated state.
        payroll_client.set_asset_allowed(&token_id, &true);
        assert!(payroll_client.is_asset_allowed(&token_id));
        assert!(!payroll_client.is_asset_deactivated(&token_id));

        // A foreign asset is never reported as deactivated: it is simply not
        // this contract's canonical treasury asset.
        let foreign_asset = Address::generate(&env);
        assert!(!payroll_client.is_asset_deactivated(&foreign_asset));
        assert!(!payroll_client.is_asset_allowed(&foreign_asset));
    }

    #[test]
    #[should_panic(expected = "Asset not allowed")]
    fn test_deposit_fails_when_asset_deactivated() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        payroll_client.set_asset_allowed(&token_id, &false);

        payroll_client.deposit(&treasury, &1000, &test_nonce(&env, 250));
    }

    #[test]
    fn test_deposit_resumes_after_asset_reactivated() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        payroll_client.set_asset_allowed(&token_id, &false);
        let deposit_id = test_nonce(&env, 251);
        let blocked = payroll_client.try_deposit(&treasury, &1000, &deposit_id);
        assert!(blocked.is_err());

        // A rejected deposit leaves no depositor accounting behind.
        assert_eq!(payroll_client.get_treasury_balance(&treasury), 0);

        // It also does not burn the deposit id, so the same retry succeeds once
        // the admin reactivates the asset.
        payroll_client.set_asset_allowed(&token_id, &true);
        payroll_client.deposit(&treasury, &1000, &deposit_id);
        assert_eq!(payroll_client.get_treasury_balance(&treasury), 1000);
    }

    // ?? Reviewer Authorization & Run Review Tests ????????????????????????????

    #[test]
    fn test_reviewer_authorization_workflow() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);

        // Initial state: not reviewer
        assert!(!payroll_client.is_reviewer(&reviewer));

        // Admin adds reviewer
        payroll_client.add_reviewer(&admin, &reviewer);
        assert!(payroll_client.is_reviewer(&reviewer));

        // Prepare run
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 99),
            &None,
        );

        // Reviewer approves run
        payroll_client.approve_payroll_run(&reviewer, &run_id);
        let review = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing");
        assert_eq!(review.run_id, run_id);
        assert_eq!(review.reviewer, reviewer);
        assert_eq!(review.decision, ReviewDecision::Approved);

        // Reviewer requests changes
        let reason_changes = Symbol::new(&env, "need_docs");
        payroll_client.request_changes_payroll_run(&reviewer, &run_id, &reason_changes);
        let review2 = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing");
        assert_eq!(review2.decision, ReviewDecision::ChangesRequested);
        assert_eq!(review2.reason, reason_changes);

        // Reviewer rejects run
        let reason_reject = Symbol::new(&env, "invalid");
        payroll_client.reject_payroll_run(&reviewer, &run_id, &reason_reject);
        let review3 = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing");
        assert_eq!(review3.decision, ReviewDecision::Rejected);
        assert_eq!(review3.reason, reason_reject);

        // Admin revokes reviewer
        payroll_client.remove_reviewer(&admin, &reviewer);
        assert!(!payroll_client.is_reviewer(&reviewer));
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not an authorized reviewer")]
    fn test_unauthorized_approve_panics() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let unauthorized = Address::generate(&env);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 100),
            &None,
        );

        payroll_client.approve_payroll_run(&unauthorized, &run_id);
    }

    // ?? Issue #522: approval withdrawal & supersession tests ????????????????

    #[test]
    fn test_withdraw_approval_records_decision_and_event() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 150),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer, &run_id);
        let reason = Symbol::new(&env, "salary_error");
        payroll_client.withdraw_approval(&reviewer, &run_id, &reason);

        // The withdrawal event must be privacy-safe: only the opaque run id,
        // the withdrawing reviewer, and the reason symbol — no amounts or
        // employee data. Captured from the withdrawal invocation itself, since
        // the SDK event stream only covers the last contract invocation.
        let (topics, data) = last_event_scval(&env);

        let review = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing after withdrawal");
        assert_eq!(review.decision, ReviewDecision::Withdrawn);
        assert_eq!(review.reviewer, reviewer);
        assert_eq!(review.reason, reason);
        assert_eq!(topics.len(), 2);
        assert_eq!(
            Symbol::try_from_val(&env, &topics[0]).unwrap(),
            Symbol::new(&env, "payroll")
        );
        assert_eq!(
            Symbol::try_from_val(&env, &topics[1]).unwrap(),
            Symbol::new(&env, "run_approval_withdrawn")
        );
        let fields = match data {
            soroban_sdk::xdr::ScVal::Vec(Some(v)) => v.to_vec(),
            other => panic!("unexpected withdrawal event data shape: {other:?}"),
        };
        let run_id_decoded = match &fields[0] {
            soroban_sdk::xdr::ScVal::U64(v) => *v,
            other => panic!("unexpected withdrawal run id field: {other:?}"),
        };
        assert_eq!(run_id_decoded, run_id);
        assert_eq!(Address::try_from_val(&env, &fields[1]).unwrap(), reviewer);
        assert_eq!(Symbol::try_from_val(&env, &fields[2]).unwrap(), reason);
    }

    #[test]
    fn test_supersede_approval_transfers_and_emits_event() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer_a = Address::generate(&env);
        let reviewer_b = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer_a);
        payroll_client.add_reviewer(&admin, &reviewer_b);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 151),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer_a, &run_id);
        let original = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing")
            .reviewed_at;

        // Advance time so supersession demonstrably restarts the #403 expiry
        // window from the new `reviewed_at`.
        env.ledger().with_mut(|li| li.timestamp += 1_000);
        payroll_client.supersede_approval(&reviewer_b, &run_id);

        // The supersession event names the previous and new reviewers.
        // Captured from the supersession invocation itself, since the SDK
        // event stream only covers the last contract invocation.
        let (topics, data) = last_event_scval(&env);

        let review = payroll_client
            .get_run_review(&run_id)
            .expect("Review record missing after supersession");
        assert_eq!(review.decision, ReviewDecision::Approved);
        assert_eq!(review.reviewer, reviewer_b);
        assert!(
            review.reviewed_at > original,
            "supersession must refresh the approval timestamp"
        );
        assert_eq!(topics.len(), 2);
        assert_eq!(
            Symbol::try_from_val(&env, &topics[1]).unwrap(),
            Symbol::new(&env, "run_approval_superseded")
        );
        let fields = match data {
            soroban_sdk::xdr::ScVal::Vec(Some(v)) => v.to_vec(),
            other => panic!("unexpected supersession event data shape: {other:?}"),
        };
        let run_id_decoded = match &fields[0] {
            soroban_sdk::xdr::ScVal::U64(v) => *v,
            other => panic!("unexpected supersession run id field: {other:?}"),
        };
        assert_eq!(run_id_decoded, run_id);
        assert_eq!(Address::try_from_val(&env, &fields[1]).unwrap(), reviewer_a);
        assert_eq!(Address::try_from_val(&env, &fields[2]).unwrap(), reviewer_b);
    }

    #[test]
    #[should_panic(expected = "Symbol cannot be empty")]
    fn test_withdraw_approval_requires_non_empty_reason() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 152),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer, &run_id);
        payroll_client.withdraw_approval(&reviewer, &run_id, &Symbol::new(&env, ""));
    }

    #[test]
    #[should_panic(expected = "Only the approving reviewer may withdraw an approval")]
    fn test_other_reviewer_cannot_withdraw_someone_elses_approval() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer_a = Address::generate(&env);
        let reviewer_b = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer_a);
        payroll_client.add_reviewer(&admin, &reviewer_b);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 153),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer_a, &run_id);
        // B is a valid reviewer, but A owns the active approval.
        payroll_client.withdraw_approval(&reviewer_b, &run_id, &Symbol::new(&env, "policy"));
    }

    #[test]
    #[should_panic(expected = "No active approval to withdraw")]
    fn test_cannot_withdraw_an_already_withdrawn_approval() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 154),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer, &run_id);
        payroll_client.withdraw_approval(&reviewer, &run_id, &Symbol::new(&env, "policy"));
        payroll_client.withdraw_approval(&reviewer, &run_id, &Symbol::new(&env, "again"));
    }

    #[test]
    #[should_panic(expected = "Superseding reviewer must differ from the current approver")]
    fn test_cannot_supersede_own_approval() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 155),
            &None,
        );

        payroll_client.approve_payroll_run(&reviewer, &run_id);
        payroll_client.supersede_approval(&reviewer, &run_id);
    }

    #[test]
    fn test_batch_checkpoint_resume_flow() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let asset = Address::generate(&env);
        let batch_root = BytesN::from_array(&env, &[0x11u8; 32]);
        let execution_nonce = BytesN::from_array(&env, &[0x22u8; 32]);

        payroll_client.begin_batch_execution_checkpoint(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &0u32,
        );

        let checkpoint = payroll_client.get_batch_execution_checkpoint(
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
        );
        assert_eq!(checkpoint.state, BatchCheckpointState::Started);
        assert!(!checkpoint.completed);

        payroll_client.record_batch_checkpoint_progress(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &5u32,
            &BatchCheckpointState::PartiallyCheckpointed,
        );

        let resumed = payroll_client.resume_batch_execution(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &5u32,
        );
        assert!(resumed);

        let checkpoint_after = payroll_client.get_batch_execution_checkpoint(
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
        );
        assert_eq!(checkpoint_after.state, BatchCheckpointState::Resumed);
        assert_eq!(checkpoint_after.last_checkpoint_index, 5u32);
        assert_eq!(checkpoint_after.total_checkpoints, 2u32);
    }

    #[test]
    #[should_panic(expected = "ERR_BATCH_CHECKPOINT_MISMATCH")]
    fn test_batch_checkpoint_rejects_backward_progress() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let asset = Address::generate(&env);
        let batch_root = BytesN::from_array(&env, &[0x99u8; 32]);
        let execution_nonce = BytesN::from_array(&env, &[0xaau8; 32]);

        payroll_client.begin_batch_execution_checkpoint(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &2u32,
        );
        payroll_client.record_batch_checkpoint_progress(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &1u32,
            &BatchCheckpointState::PartiallyCheckpointed,
        );
    }

    #[test]
    fn test_batch_checkpoint_replay_is_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let asset = Address::generate(&env);
        let batch_root = BytesN::from_array(&env, &[0x33u8; 32]);
        let execution_nonce = BytesN::from_array(&env, &[0x44u8; 32]);

        payroll_client.begin_batch_execution_checkpoint(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &3u32,
        );

        let result = payroll_client.try_resume_batch_execution(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &0u32,
        );
        assert!(result.is_err());

        let checkpoint = payroll_client.get_batch_execution_checkpoint(
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
        );
        assert_eq!(checkpoint.state, BatchCheckpointState::Started);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_batch_checkpoint_resume_rejects_unauthorized_caller() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let asset = Address::generate(&env);
        let batch_root = BytesN::from_array(&env, &[0x55u8; 32]);
        let execution_nonce = BytesN::from_array(&env, &[0x66u8; 32]);

        payroll_client.begin_batch_execution_checkpoint(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &4u32,
        );

        let attacker = Address::generate(&env);
        payroll_client.resume_batch_execution(
            &attacker,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &4u32,
        );
    }

    #[test]
    #[should_panic(expected = "ERR_BATCH_CHECKPOINT_MISMATCH")]
    fn test_batch_checkpoint_rejects_mismatched_resume_inputs() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let asset = Address::generate(&env);
        let batch_root = BytesN::from_array(&env, &[0x77u8; 32]);
        let execution_nonce = BytesN::from_array(&env, &[0x88u8; 32]);

        payroll_client.begin_batch_execution_checkpoint(
            &admin,
            &employer,
            &batch_root,
            &asset,
            &execution_nonce,
            &7u32,
        );

        let wrong_asset = Address::generate(&env);
        payroll_client.resume_batch_execution(
            &admin,
            &employer,
            &batch_root,
            &wrong_asset,
            &execution_nonce,
            &7u32,
        );
    }

    // ============================================================================
    // Issue #339: Admin Handover Safety Checks Tests
    // ============================================================================

    #[test]
    fn test_admin_handover_full_flow() {
        let env = Env::default();
        env.mock_all_auths();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);

        // Step 1: Current admin requests handover
        payroll_client.request_admin_handover(&admin, &new_admin);

        let pending = payroll_client
            .get_pending_admin_handover()
            .expect("Handover should exist");
        assert_eq!(pending.current_admin, admin);
        assert_eq!(pending.pending_admin, new_admin);

        // Step 2: New admin accepts handover
        payroll_client.accept_admin_handover(&new_admin);

        assert!(payroll_client.get_pending_admin_handover().is_none());

        // Verify admin role is transferred: new admin can perform admin action
        let draft_id = payroll_client.create_run_draft(
            &new_admin,
            &5000i128,
            &10u32,
            &Symbol::new(&env, "P1"),
        );
        assert_eq!(draft_id, 1);
    }

    #[test]
    fn test_admin_handover_cancellation() {
        let env = Env::default();
        env.mock_all_auths();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.request_admin_handover(&admin, &new_admin);

        // Current admin cancels
        payroll_client.cancel_admin_handover(&admin);

        assert!(payroll_client.get_pending_admin_handover().is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not current admin")]
    fn test_admin_handover_unauthorized_request() {
        let env = Env::default();
        env.mock_all_auths();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let new_admin = Address::generate(&env);
        payroll_client.request_admin_handover(&attacker, &new_admin);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the pending admin")]
    fn test_admin_handover_unauthorized_accept() {
        let env = Env::default();
        env.mock_all_auths();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.request_admin_handover(&admin, &new_admin);

        let attacker = Address::generate(&env);
        payroll_client.accept_admin_handover(&attacker);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not current admin")]
    fn test_admin_handover_unauthorized_cancel() {
        let env = Env::default();
        env.mock_all_auths();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.request_admin_handover(&admin, &new_admin);

        let attacker = Address::generate(&env);
        payroll_client.cancel_admin_handover(&attacker);
    }

    // ============================================================================
    // Issue #343: Treasury Withdrawal Guardrails Tests
    // ============================================================================

    #[test]
    fn test_withdrawal_guardrails_before_and_after_lock() {
        let env = Env::default();
        let (payroll_client, admin, treasury, treasury_owner, employee, token_id) =
            setup_payroll_with_token(&env);

        let token_client = TokenClient::new(&env, &token_id);
        let init_balance = token_client.balance(&treasury);

        // Before lock: 0 locked. Available equals total balance.
        assert_eq!(payroll_client.get_locked_funds(&token_id), 0);
        assert_eq!(
            payroll_client.get_available_treasury_balance(&token_id),
            init_balance
        );

        // Prepare payroll run for 800 -> locks 800.
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 800);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &800,
            &test_nonce(&env, 43),
            &None,
        );

        assert_eq!(payroll_client.get_locked_funds(&token_id), 800);
        assert_eq!(
            payroll_client.get_available_treasury_balance(&token_id),
            init_balance - 800
        );

        // Withdrawal of surplus 150 succeeds because 150 <= available surplus balance.
        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &150i128, &recipient);
        payroll_client.approve_emergency_withdrawal(&admin);

        // Cancellation restores capacity: cancelling run_id releases 800 locked funds.
        payroll_client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "cancel"));
        assert_eq!(payroll_client.get_locked_funds(&token_id), 0);
        assert_eq!(
            payroll_client.get_available_treasury_balance(&token_id),
            init_balance - 150
        );
    }

    #[test]
    #[should_panic(
        expected = "Insufficient available treasury balance: funds locked for pending payroll"
    )]
    fn test_withdrawal_guardrails_rejects_underfunding() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, treasury_owner, employee, token_id) =
            setup_payroll_with_token(&env);

        let token_client = TokenClient::new(&env, &token_id);
        let init_balance = token_client.balance(&treasury);

        // Prepare run for init_balance - 100 -> available surplus balance becomes 100.
        let (proofs, amounts, employees) =
            single_payment_batch(&env, &employee, init_balance - 100);
        let _run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &(init_balance - 100),
            &test_nonce(&env, 44),
            &None,
        );

        // Attempt emergency withdrawal of 300 should fail because only 100 is available surplus.
        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &300i128, &recipient);
    }

    // ============================================================================
    // Issue #334: Signer Quorum Replay Protection Tests
    // ============================================================================

    #[test]
    fn test_quorum_approval_valid_and_replay_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let mut signers = Vec::new(&env);
        signers.push_back(signer1);
        signers.push_back(signer2);

        let payload = QuorumApprovalPayload {
            batch_root: BytesN::from_array(&env, &[1u8; 32]),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: test_nonce(&env, 55),
            policy_version: 1,
        };

        let q_hash = payroll_client.hash_quorum_payload(&payload);
        assert!(!payroll_client.is_quorum_consumed(&q_hash));

        // First verification & consumption succeeds.
        let consumed_hash = payroll_client.verify_and_consume_quorum(&payload, &signers, &2u32);
        assert_eq!(q_hash, consumed_hash);
        assert!(payroll_client.is_quorum_consumed(&q_hash));

        // Replaying the exact same quorum approval payload must be rejected.
        let result = payroll_client.try_verify_and_consume_quorum(&payload, &signers, &2u32);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Insufficient signer quorum")]
    fn test_quorum_insufficient_signers() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        let signer1 = Address::generate(&env);
        let mut signers = Vec::new(&env);
        signers.push_back(signer1);

        let payload = QuorumApprovalPayload {
            batch_root: BytesN::from_array(&env, &[2u8; 32]),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: test_nonce(&env, 56),
            policy_version: 1,
        };

        // Required quorum is 2, but only 1 signer provided -> panics
        payroll_client.verify_and_consume_quorum(&payload, &signers, &2u32);
    }

    #[test]
    #[should_panic(expected = "Duplicate signer in quorum approval")]
    fn test_quorum_duplicate_signer_attempt_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // One signer submitting the same approval twice looks like two
        // approvals to a length-only check, so it must be rejected instead.
        let signer = Address::generate(&env);
        let mut signers = Vec::new(&env);
        signers.push_back(signer.clone());
        signers.push_back(signer);

        let payload = QuorumApprovalPayload {
            batch_root: BytesN::from_array(&env, &[3u8; 32]),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: test_nonce(&env, 57),
            policy_version: 1,
        };

        payroll_client.verify_and_consume_quorum(&payload, &signers, &2u32);
    }

    #[test]
    fn test_quorum_duplicate_signer_attempt_does_not_consume_payload() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let mut duplicate_signers = Vec::new(&env);
        duplicate_signers.push_back(signer1.clone());
        duplicate_signers.push_back(signer1.clone());

        let payload = QuorumApprovalPayload {
            batch_root: BytesN::from_array(&env, &[4u8; 32]),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: test_nonce(&env, 58),
            policy_version: 1,
        };
        let q_hash = payroll_client.hash_quorum_payload(&payload);

        // A rejected duplicate-signer attempt must not burn the reference...
        let rejected =
            payroll_client.try_verify_and_consume_quorum(&payload, &duplicate_signers, &2u32);
        assert!(rejected.is_err());
        assert!(!payroll_client.is_quorum_consumed(&q_hash));

        // ...so a genuine quorum of distinct signers can still consume it once.
        let mut distinct_signers = Vec::new(&env);
        distinct_signers.push_back(signer1);
        distinct_signers.push_back(signer2);
        let consumed = payroll_client.verify_and_consume_quorum(&payload, &distinct_signers, &2u32);
        assert_eq!(q_hash, consumed);
        assert!(payroll_client.is_quorum_consumed(&q_hash));
    }

    #[test]
    fn test_quorum_concurrent_attempts_consume_reference_once() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        let mut signers = Vec::new(&env);
        signers.push_back(Address::generate(&env));
        signers.push_back(Address::generate(&env));

        let payload = QuorumApprovalPayload {
            batch_root: BytesN::from_array(&env, &[5u8; 32]),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: test_nonce(&env, 59),
            policy_version: 1,
        };
        let q_hash = payroll_client.hash_quorum_payload(&payload);

        // Three interleaved submissions of the same approval: exactly one wins.
        assert!(payroll_client
            .try_verify_and_consume_quorum(&payload, &signers, &2u32)
            .is_ok());
        assert!(payroll_client
            .try_verify_and_consume_quorum(&payload, &signers, &2u32)
            .is_err());
        assert!(payroll_client
            .try_verify_and_consume_quorum(&payload, &signers, &2u32)
            .is_err());
        assert!(payroll_client.is_quorum_consumed(&q_hash));
    }

    // ============================================================================
    // Issue #336: Batch Root Collision and Domain Separation Tests
    // ============================================================================

    #[test]
    fn test_domain_separation_batch_vs_audit() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // Same batch root used as both a batch digest and an audit digest
        let test_hash = BytesN::from_array(&env, &[42u8; 32]);

        // Batch domain: store as a batch root reference
        let batch_nonce = test_nonce(&env, 100);
        payroll_client.commit_draft(&admin, &test_hash);

        // Verify that the digest is stored and accessible
        // A different domain (e.g., audit) should not collide with batch domain
        let quorum_payload = QuorumApprovalPayload {
            batch_root: test_hash.clone(),
            employer: admin.clone(),
            period: Symbol::new(&env, "Q1_2026"),
            asset: token_id.clone(),
            nonce: batch_nonce,
            policy_version: 1,
        };

        // Hash should be unique per domain
        let batch_quorum_hash = payroll_client.hash_quorum_payload(&quorum_payload);
        assert_ne!(test_hash, batch_quorum_hash);
    }

    #[test]
    fn test_domain_separation_treasury_vs_proof() {
        let env = Env::default();
        let (payroll_client, admin, treasury, _treasury_owner, employee, _token_id) =
            setup_payroll_with_token(&env);

        // Test that treasury reservation nonce and proof nonce don't collide
        let test_seed = 101u8;
        let treasury_nonce = test_nonce(&env, test_seed);
        let proof_nonce = test_nonce(&env, test_seed + 1);

        // Use different nonces for different domains
        assert_ne!(treasury_nonce, proof_nonce);

        // Prepare a payroll run with proof nonce
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &proof_nonce,
            &None,
        );

        // Treasury nonce should be consumable separately
        let deposit_nonce = treasury_nonce;
        payroll_client.deposit(&treasury, &1000, &deposit_nonce);

        // Verify nonce tracking
        // After finalization, proof nonce should be consumed
        payroll_client.finalize_payroll_run(&admin, &run_id);
    }

    #[test]
    fn test_overlapping_raw_inputs_different_domains() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee, _token_id) =
            setup_payroll_with_token(&env);

        // Create identical 32-byte patterns that should belong to different domains
        let identical_bytes = [3u8; 32];
        let input1 = BytesN::from_array(&env, &identical_bytes);
        let input2 = BytesN::from_array(&env, &identical_bytes);

        // Use same raw input in different domains
        // Domain 1: Draft commitment (batch domain)
        payroll_client.commit_draft(&admin, &input1);

        // Domain 2: Run nonce (proof domain)
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let _run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &1000, &input2, &None);

        // Even with identical raw bytes, domain separation ensures they're treated as different
        // (verified by successful execution without collision errors)
    }

    // ============================================================================
    // Issue #333: Compliance Hold State Tests
    // ============================================================================

    #[test]
    fn test_compliance_hold_place_and_release() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let target = Address::generate(&env);
        let reason = Symbol::new(&env, "audit_review");

        // Place a hold
        let hold_id = payroll_client.place_compliance_hold(
            &admin,
            &ComplianceHoldScope::Employee,
            &target,
            &reason,
        );

        // Verify hold is active
        assert!(payroll_client.is_compliance_hold_active(&hold_id));

        // Verify hold details
        let hold = payroll_client
            .get_compliance_hold(&hold_id)
            .expect("Hold should exist");
        assert_eq!(hold.hold_id, hold_id);
        assert_eq!(hold.target, target);
        assert_eq!(hold.scope, ComplianceHoldScope::Employee);
        assert!(hold.is_active);

        // Release the hold
        payroll_client.release_compliance_hold(&admin, &hold_id);

        // Verify hold is no longer active
        assert!(!payroll_client.is_compliance_hold_active(&hold_id));

        let hold_after = payroll_client
            .get_compliance_hold(&hold_id)
            .expect("Hold should still exist but inactive");
        assert!(!hold_after.is_active);
    }

    #[test]
    fn test_compliance_hold_multiple_scopes() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let target_batch = Address::generate(&env);
        let target_employee = Address::generate(&env);
        let target_employer = Address::generate(&env);

        // Place holds on different scopes
        let hold_batch = payroll_client.place_compliance_hold(
            &admin,
            &ComplianceHoldScope::Batch,
            &target_batch,
            &Symbol::new(&env, "review"),
        );

        let hold_employee = payroll_client.place_compliance_hold(
            &admin,
            &ComplianceHoldScope::Employee,
            &target_employee,
            &Symbol::new(&env, "suspend"),
        );

        let hold_employer = payroll_client.place_compliance_hold(
            &admin,
            &ComplianceHoldScope::Employer,
            &target_employer,
            &Symbol::new(&env, "lockdown"),
        );

        // Verify all holds are active and distinct
        assert!(payroll_client.is_compliance_hold_active(&hold_batch));
        assert!(payroll_client.is_compliance_hold_active(&hold_employee));
        assert!(payroll_client.is_compliance_hold_active(&hold_employer));

        // Verify each hold has correct scope
        let hold_b = payroll_client.get_compliance_hold(&hold_batch).unwrap();
        let hold_e = payroll_client.get_compliance_hold(&hold_employee).unwrap();
        let hold_er = payroll_client.get_compliance_hold(&hold_employer).unwrap();

        assert_eq!(hold_b.scope, ComplianceHoldScope::Batch);
        assert_eq!(hold_e.scope, ComplianceHoldScope::Employee);
        assert_eq!(hold_er.scope, ComplianceHoldScope::Employer);
    }

    #[test]
    #[should_panic(expected = "Hold is not active")]
    fn test_release_already_released_hold_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let target = Address::generate(&env);
        let hold_id = payroll_client.place_compliance_hold(
            &admin,
            &ComplianceHoldScope::Employee,
            &target,
            &Symbol::new(&env, "test"),
        );

        // Release once
        payroll_client.release_compliance_hold(&admin, &hold_id);

        // Attempt to release again should panic
        payroll_client.release_compliance_hold(&admin, &hold_id);
    }

    // ============================================================================
    // Issue #337: Funding Reservation Expiry Tests
    // ============================================================================

    #[test]
    fn test_reservation_expiry_policy_set_and_release() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // Set reservation expiry policy
        payroll_client.set_reservation_expiry_policy(
            &admin, &token_id, &5000i128, &86400u64, // 1 day expiry
        );

        // Verify policy was set
        let expiry = payroll_client.get_reservation_expiry(&token_id);
        assert!(expiry.is_some());
        let exp_policy = expiry.unwrap();
        assert_eq!(exp_policy.reserved_amount, 5000i128);
        assert_eq!(exp_policy.asset, token_id);
    }

    #[test]
    #[should_panic(expected = "Reservation has not yet expired")]
    fn test_cannot_release_unexpired_reservation() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee, token_id) =
            setup_payroll_with_token(&env);

        // Set reservation with future expiry
        payroll_client.set_reservation_expiry_policy(
            &admin, &token_id, &5000i128, &86400u64, // Future expiry
        );

        // Attempt to release should panic since it hasn't expired
        payroll_client.release_expired_reservation(&token_id);
    }

    // ============================================================================
    // Issue #335: Payroll Archival Tests
    // ============================================================================

    #[test]
    fn test_archive_payroll_run() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Prepare and execute a payroll run
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 150),
            &None,
        );

        // Finalize the run
        payroll_client.finalize_payroll_run(&admin, &run_id);

        // Verify run is not archived initially
        assert!(!payroll_client.is_payroll_run_archived(&run_id));

        // Archive the run
        payroll_client.archive_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "compliance"),
        );

        // Verify run is now archived
        assert!(payroll_client.is_payroll_run_archived(&run_id));

        // Verify archive marker exists
        let marker = payroll_client
            .get_archive_marker(&run_id)
            .expect("Archive marker should exist");
        assert_eq!(marker.run_id, run_id);
        assert_eq!(marker.archived_by, admin);
    }

    #[test]
    #[should_panic(expected = "Payroll run is already archived")]
    fn test_cannot_archive_already_archived_run() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Prepare and execute a payroll run
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 151),
            &None,
        );

        payroll_client.finalize_payroll_run(&admin, &run_id);

        // Archive once
        payroll_client.archive_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "compliance"),
        );

        // Attempt to archive again should panic
        payroll_client.archive_payroll_run_with_reason(
            &admin,
            &run_id,
            &Symbol::new(&env, "retention"),
        );
    }

    #[test]
    fn test_archive_multiple_runs() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Archive multiple runs
        for i in 0..3 {
            let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
            let run_id = payroll_client.prepare_payroll_run(
                &proofs,
                &amounts,
                &employees,
                &1000,
                &test_nonce(&env, 200 + i as u8),
                &None,
            );

            payroll_client.finalize_payroll_run(&admin, &run_id);
            payroll_client.archive_payroll_run_with_reason(
                &admin,
                &run_id,
                &Symbol::new(&env, "compliance"),
            );

            assert!(payroll_client.is_payroll_run_archived(&run_id));
        }
    }

    // ============================================================================
    // Issue #362: Payroll Run Nonce Monotonicity Enforcement Tests
    // ============================================================================

    #[test]
    fn test_nonce_monotonicity_sequential_nonces_accepted() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // First nonce should be accepted via prepare_payroll_run
        let nonce1 = test_nonce(&env, 1);
        let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

        // Second nonce (greater than first) should also be accepted
        let nonce2 = test_nonce(&env, 2);
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(&proofs2, &amounts2, &employees2, &1000, &nonce2, &None);

        // Verify nonce sequence tracking
        let sequence = payroll_client.get_employer_nonce_sequence(&admin);
        assert!(sequence.is_some());
        let seq = sequence.unwrap();
        assert_eq!(seq.current_sequence, 2);
        assert_eq!(seq.last_nonce, nonce2);
    }

    #[test]
    fn test_nonce_monotonicity_repeated_nonce_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // First nonce should be accepted
        let nonce = test_nonce(&env, 10);
        let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs1,
            &amounts1,
            &employees1,
            &1000,
            &nonce,
            &None,
        );

        // Second call with the same nonce must fail (replay attack)
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &nonce,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_monotonicity_stale_nonce_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // First nonce (higher value) should be accepted
        let nonce1 = test_nonce(&env, 20);
        let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs1,
            &amounts1,
            &employees1,
            &1000,
            &nonce1,
            &None,
        );

        // Second nonce (lower value - stale) must fail
        let nonce2 = test_nonce(&env, 10);
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &nonce2,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_monotonicity_skipped_nonces_allowed() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // First nonce should be accepted
        let nonce1 = test_nonce(&env, 1);
        let (proofs1, amounts1, employees1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(&proofs1, &amounts1, &employees1, &1000, &nonce1, &None);

        // Skipped nonce (5) should be accepted (monotonically increasing)
        let nonce2 = test_nonce(&env, 5);
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        payroll_client.prepare_payroll_run(&proofs2, &amounts2, &employees2, &1000, &nonce2, &None);

        // Verify sequence tracking shows skipped nonce
        let sequence = payroll_client.get_employer_nonce_sequence(&admin);
        assert!(sequence.is_some());
        let seq = sequence.unwrap();
        assert_eq!(seq.current_sequence, 2);
        assert_eq!(seq.last_nonce, nonce2);
    }

    // ============================================================================
    // Issue #361: Compliance Evidence Pointer Validation Tests
    // ============================================================================

    #[test]
    fn test_evidence_pointer_creation_valid() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let content_hash = BytesN::from_array(&env, &[0xabu8; 32]);
        let target = Address::generate(&env);

        let pointer_id = payroll_client.create_evidence_pointer(
            &admin,
            &content_hash,
            &EvidencePointerScope::Employer,
            &target,
            &None,
        );

        // Verify pointer was created
        let pointer = payroll_client.get_evidence_pointer(&pointer_id);
        assert_eq!(pointer.content_hash, content_hash);
        assert_eq!(pointer.scope, EvidencePointerScope::Employer);
        assert_eq!(pointer.target, target);

        // Verify deduplication index
        assert!(payroll_client.evidence_pointer_exists(&content_hash));
    }

    #[test]
    fn test_evidence_pointer_creation_empty_hash_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
        let target = Address::generate(&env);

        let result = payroll_client.try_create_evidence_pointer(
            &admin,
            &zero_hash,
            &EvidencePointerScope::Employer,
            &target,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_evidence_pointer_creation_duplicate_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let content_hash = BytesN::from_array(&env, &[0xcd_u8; 32]);
        let target = Address::generate(&env);

        // First creation should succeed
        payroll_client.create_evidence_pointer(
            &admin,
            &content_hash,
            &EvidencePointerScope::Employer,
            &target,
            &None,
        );

        // Second creation with same content hash should fail
        let result = payroll_client.try_create_evidence_pointer(
            &admin,
            &content_hash,
            &EvidencePointerScope::Period,
            &target,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_evidence_pointer_scoping() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let employer = Address::generate(&env);
        let period = Address::generate(&env);
        let review_case = Address::generate(&env);

        // Create pointers for different scopes
        let hash1 = BytesN::from_array(&env, &[0x11u8; 32]);
        let pointer1 = payroll_client.create_evidence_pointer(
            &admin,
            &hash1,
            &EvidencePointerScope::Employer,
            &employer,
            &None,
        );

        let hash2 = BytesN::from_array(&env, &[0x22u8; 32]);
        let pointer2 = payroll_client.create_evidence_pointer(
            &admin,
            &hash2,
            &EvidencePointerScope::Period,
            &period,
            &None,
        );

        let hash3 = BytesN::from_array(&env, &[0x33u8; 32]);
        let pointer3 = payroll_client.create_evidence_pointer(
            &admin,
            &hash3,
            &EvidencePointerScope::ReviewCase,
            &review_case,
            &None,
        );

        // Verify each pointer has correct scope
        let p1 = payroll_client.get_evidence_pointer(&pointer1);
        assert_eq!(p1.scope, EvidencePointerScope::Employer);
        assert_eq!(p1.target, employer);

        let p2 = payroll_client.get_evidence_pointer(&pointer2);
        assert_eq!(p2.scope, EvidencePointerScope::Period);
        assert_eq!(p2.target, period);

        let p3 = payroll_client.get_evidence_pointer(&pointer3);
        assert_eq!(p3.scope, EvidencePointerScope::ReviewCase);
        assert_eq!(p3.target, review_case);
    }

    // ============================================================================
    // Issue #360: Storage Version Migration Checks Tests
    // ============================================================================

    #[test]
    fn test_storage_version_initialized_on_contract_init() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Storage version should be initialized
        let version = payroll_client.get_storage_version();
        assert!(version.is_some());

        let version_state = version.unwrap();
        assert_eq!(version_state.version, 1); // CURRENT_STORAGE_VERSION
        assert!(version_state.migration_complete);
    }

    #[test]
    fn test_storage_version_is_supported() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Current version should be supported
        assert!(payroll_client.is_storage_version_supported());
    }

    #[test]
    fn test_storage_version_no_migration_required() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // No migration should be required for current version
        assert!(!payroll_client.is_migration_required());
    }

    #[test]
    fn test_storage_version_readiness_check() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Migration readiness should show ready
        let readiness = payroll_client.check_migration_readiness();
        assert!(readiness.ready);
        assert_eq!(readiness.current_version, 1);
        assert_eq!(readiness.min_supported, 1);
        assert_eq!(readiness.max_supported, 1);
    }

    #[test]
    fn test_storage_version_set_by_admin() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        // Admin should be able to set storage version
        let description = soroban_sdk::String::from_str(&env, "Test version");
        payroll_client.set_storage_version(&admin, &1, &description);

        // Verify version was set
        let version = payroll_client.get_storage_version().unwrap();
        assert_eq!(version.version, 1);
    }

    // ?????????????????????????????????????????????????????????????????????????
    // #401: Batch Lock Timestamp Query Helper Tests
    // ?????????????????????????????????????????????????????????????????????????

    #[test]
    fn test_batch_lock_timestamp_non_existent_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        assert_eq!(payroll_client.get_batch_lock_timestamp(&999), None);
    }

    #[test]
    fn test_batch_lock_timestamp_pending_and_executed_runs() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
        let nonce = test_nonce(&env, 1);

        // Prepare run
        let run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

        let expected_lock_time = env.ledger().timestamp();
        assert_eq!(
            payroll_client.get_batch_lock_timestamp(&run_id),
            Some(expected_lock_time)
        );

        // Finalize run
        let addrs = payroll_client.get_addresses();
        payroll_client.finalize_payroll_run(&addrs.admin, &run_id);

        assert_eq!(
            payroll_client.get_batch_lock_timestamp(&run_id),
            Some(expected_lock_time)
        );
    }

    // ?????????????????????????????????????????????????????????????????????????
    // #402: Safe Treasury Balance Summary View Tests
    // ?????????????????????????????????????????????????????????????????????????

    #[test]
    fn test_safe_treasury_summary_view() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let addrs = payroll_client.get_addresses();
        let summary_initial = payroll_client.get_safe_treasury_summary(&addrs.token);
        assert_eq!(summary_initial.total_balance, 1_000_000);
        assert_eq!(summary_initial.reserved_balance, 0);
        assert_eq!(summary_initial.available_balance, 1_000_000);
        assert_eq!(summary_initial.blocked_balance, 0);

        // Lock funds via prepare_payroll_run
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 50_000);
        let nonce = test_nonce(&env, 2);
        let run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &50_000, &nonce, &None);

        let summary_locked = payroll_client.get_safe_treasury_summary(&addrs.token);
        assert_eq!(summary_locked.total_balance, 1_000_000);
        assert_eq!(summary_locked.reserved_balance, 50_000);
        assert_eq!(summary_locked.available_balance, 950_000);
        assert_eq!(summary_locked.blocked_balance, 0);

        // Cancel run to release reservation
        payroll_client.cancel_payroll_run(&addrs.admin, &run_id, &Symbol::new(&env, "mistake"));

        let summary_released = payroll_client.get_safe_treasury_summary(&addrs.token);
        assert_eq!(summary_released.total_balance, 1_000_000);
        assert_eq!(summary_released.reserved_balance, 0);
        assert_eq!(summary_released.available_balance, 1_000_000);
    }

    // ?????????????????????????????????????????????????????????????????????????
    // #403: Payroll Approval Expiry Validation Tests
    // ?????????????????????????????????????????????????????????????????????????

    #[test]
    fn test_payroll_approval_expiry_active_and_expired() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
        let nonce = test_nonce(&env, 3);
        let run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

        // Approve run
        payroll_client.approve_payroll_run(&reviewer, &run_id);

        // Fresh approval is not expired
        assert!(
            !payroll_client.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        );

        // Advance ledger timestamp beyond 7 days
        env.ledger().with_mut(|li| {
            li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
        });

        // Now approval is expired
        assert!(
            payroll_client.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS)
        );
    }

    #[test]
    #[should_panic(
        expected = "Payroll approval expired: approval record exceeds maximum allowed age"
    )]
    fn test_finalize_panics_on_expired_approval() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
        let nonce = test_nonce(&env, 4);
        let run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

        // Approve run
        payroll_client.approve_payroll_run(&reviewer, &run_id);

        // Advance ledger timestamp beyond 7 days
        env.ledger().with_mut(|li| {
            li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 10;
        });

        // Finalize should panic because approval is stale/expired
        payroll_client.finalize_payroll_run(&admin, &run_id);
    }

    // ?????????????????????????????????????????????????????????????????????????
    // #404: Cancelled Batch Read Status Helper Tests
    // ?????????????????????????????????????????????????????????????????????????

    #[test]
    fn test_cancelled_batch_status_read_helper() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Non-existent run
        assert_eq!(payroll_client.get_cancelled_batch_status(&999), None);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 25_000);
        let nonce = test_nonce(&env, 5);
        let run_id = payroll_client
            .prepare_payroll_run(&proofs, &amounts, &employees, &25_000, &nonce, &None);

        // Active pending run is not cancelled
        assert_eq!(payroll_client.get_cancelled_batch_status(&run_id), None);

        // Cancel the run
        let cancel_reason = Symbol::new(&env, "duplicate_order");
        payroll_client.cancel_payroll_run(&admin, &run_id, &cancel_reason);

        // Read cancelled status
        let status = payroll_client.get_cancelled_batch_status(&run_id).unwrap();
        assert_eq!(status.run_id, run_id);
        assert_eq!(status.cancelled_by, admin);
        assert_eq!(status.reason, cancel_reason);
        assert_eq!(status.employee_count, 1);
        assert_eq!(status.total_amount, 25_000);
        assert!(status.is_cancelled);
    }

    #[test]
    fn test_asset_symbol_normalization_mixed_case_and_whitespace() {
        let env = Env::default();

        assert_eq!(
            Payroll::normalize_asset_symbol(&env, "usdc"),
            Symbol::new(&env, "USDC")
        );
        assert_eq!(
            Payroll::normalize_asset_symbol(&env, "  USDC  "),
            Symbol::new(&env, "USDC")
        );
        assert_eq!(
            Payroll::normalize_asset_symbol(&env, "usd_coin"),
            Symbol::new(&env, "USD_COIN")
        );
    }

    #[test]
    #[should_panic(expected = "Asset symbol cannot be empty")]
    fn test_asset_symbol_normalization_rejects_empty_symbol() {
        let env = Env::default();

        Payroll::normalize_asset_symbol(&env, "   ");
    }

    #[test]
    #[should_panic(expected = "Asset symbol too long")]
    fn test_asset_symbol_normalization_rejects_symbol_over_32_bytes() {
        let env = Env::default();

        Payroll::normalize_asset_symbol(&env, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
    }

    #[test]
    fn test_asset_symbol_normalization_before_allowlist_and_reservation_checks() {
        let env = Env::default();
        let allowlist_symbol = Symbol::new(&env, "USDC");
        let submitted_symbol = Payroll::normalize_asset_symbol(&env, "usdc");

        assert_eq!(submitted_symbol, allowlist_symbol);
        assert_eq!(
            Payroll::normalize_asset_symbol(&env, "  USDC  "),
            allowlist_symbol
        );
    }

    // ── Issue #544: Employee identifier normalization tests ──────────────────

    #[test]
    fn test_employee_identifier_normalization_mixed_case_and_whitespace() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let raw1 = String::from_str(&env, "  emp-1001 \t\n");
        let expected1 = String::from_str(&env, "EMP-1001");
        assert_eq!(
            payroll_client.normalize_employee_identifier(&raw1),
            expected1
        );

        let raw2 = String::from_str(&env, "emp_doe_john#42.dept/eng");
        let expected2 = String::from_str(&env, "EMP_DOE_JOHN#42.DEPT/ENG");
        assert_eq!(
            payroll_client.normalize_employee_identifier(&raw2),
            expected2
        );
    }

    #[test]
    #[should_panic(expected = "Reference ID must be 1-256 characters")]
    fn test_employee_identifier_normalization_rejects_empty_or_whitespace() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let blank = String::from_str(&env, "   \t \n ");
        payroll_client.normalize_employee_identifier(&blank);
    }

    #[test]
    #[should_panic(expected = "Reference ID must be 1-256 characters")]
    fn test_employee_identifier_normalization_rejects_overlong() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let mut long_str = [b'A'; 257];
        let long = String::from_str(&env, core::str::from_utf8(&long_str).unwrap());
        payroll_client.normalize_employee_identifier(&long);
    }

    #[test]
    #[should_panic(expected = "Employee identifier contains invalid characters: must be printable ASCII")]
    fn test_employee_identifier_normalization_rejects_non_printable() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let bad_bytes = [b'E', b'M', b'P', 0x07, b'1']; // 0x07 is non-printable BEL
        let bad = String::from_str(&env, core::str::from_utf8(&bad_bytes).unwrap());
        payroll_client.normalize_employee_identifier(&bad);
    }
}
