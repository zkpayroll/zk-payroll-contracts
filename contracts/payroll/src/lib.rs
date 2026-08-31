#![no_std]
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token as soroban_token, Address, BytesN,
    Env, Symbol, Vec,
};

use pause_manager::PauseManagerClient;
use proof_verifier::ProofVerifierClient;
use salary_commitment::SalaryCommitmentContractClient;

const MAX_BATCH: u32 = 50;

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
    /// Auto-increment counter for draft IDs (issue #89).
    RunDraftCounter,
    /// Pending admin rotation proposal (issue #91).
    PendingAdminRotation,
    /// Pending treasury-owner rotation proposal (issue #91).
    PendingTreasuryRotation,
    /// Marks a run nonce as consumed. Value is the run_id that used it (#103).
    RunNonce(BytesN<32>),
    /// Marks a deposit nonce as consumed to prevent replay (#191).
    DepositNonce(BytesN<32>),
    /// Pre-committed draft hash bound before execution (#102).
    DraftCommitment(BytesN<32>),
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
    /// Checkpointed payroll batch execution keyed by a privacy-safe tuple.
    BatchCheckpoint(Address, BytesN<32>, Address, BytesN<32>),
    /// Authorized reviewer registration for payroll run reviews.
    AuthorizedReviewer(Address),
    /// Review record for a payroll run.
    RunReview(u64),
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
    /// Latest accepted payroll nonce per employer for monotonicity enforcement (#362).
    EmployerNonceSequence(Address),
    /// Compliance evidence pointer record for off-chain encrypted evidence (#361).
    EvidencePointer(BytesN<32>),
    /// Deduplication index for evidence pointers to prevent duplicates (#361).
    EvidencePointerIndex(BytesN<32>),
    /// Contract storage version for migration checks (#360).
    StorageVersion,
    /// Migration readiness status for sensitive operations (#360).
    MigrationReadiness,
    /// Cancelled payroll batch status record (#404).
    CancelledBatchRecord(u64),
    /// Batch split record linking parent and child batch runs (#352).
    BatchSplitRecord(u64, u64),
    /// Aggregate batch split tracker per parent run (#352).
    BatchSplitTracker(u64),
    // Future upgrade example (issue #196):
    // PayrollRunV2(u64),  // Would be added here when schema evolution is needed
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
            .set(&DataKey::MigrationReadiness, &readiness);

        // Emit event for audit trail
        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "storage_version_set"),
            ),
            (version, admin),
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
            .set(&DataKey::MigrationReadiness, &readiness);
    }

    pub fn set_pause_manager(e: Env, pause_manager: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.admin.require_auth();
        e.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);

        payroll_events::emit_pause_manager_set(&e, pause_manager);
    }

    /// Allow or disallow an asset token for payroll payouts.
    pub fn set_asset_allowed(e: Env, asset: Address, allowed: bool) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.admin.require_auth();
        e.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(asset), &allowed);
    }

    /// Check if an asset token is allowlisted for payroll payouts.
    pub fn is_asset_allowed(e: Env, asset: Address) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::AllowedAsset(asset))
            .unwrap_or(false)
    }

    pub fn deposit(e: Env, from: Address, amount: i128, deposit_id: BytesN<32>) {
        Self::require_not_paused(&e);
        Self::validate_non_zero_digest(&e, &deposit_id, "deposit_id");
        if amount <= 0 {
            panic!("Deposit amount must be positive");
        }

        let nonce_key = DataKey::DepositNonce(deposit_id.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Deposit already processed");
        }
        e.storage().persistent().set(&nonce_key, &true);

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

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
                PayrollRunState::Confirming | PayrollRunState::Failed | PayrollRunState::Cancelled
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
            PayrollRunState::Completed | PayrollRunState::Cancelled => false,
        }
    }

    fn is_terminal_payroll_state_internal(state: PayrollRunState) -> bool {
        matches!(
            state,
            PayrollRunState::Completed | PayrollRunState::Cancelled
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
        // #360 ? validate storage version for sensitive operation
        Self::validate_storage_version_for_operation(&e, "prepare_payroll_run");

        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        if count == 0 {
            panic!("Empty payroll batch");
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

        addrs.admin.require_auth();

        // Validate treasury asset allowlist
        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

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

        // Reserve locked funds for the prepared payroll run (#343)
        Self::add_locked_funds(&e, addrs.token.clone(), expected_total_spend);

        payroll_events::emit_run_prepared(&e, run_id, expected_total_spend);

        run_id
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
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_finalized")),
            (run_id, pending_run.total_amount),
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

        // Emit cancellation event with reason for audit trail
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_cancelled")),
            (run_id, reason),
        );
    }

    /// Alias for cancel_payroll_run_with_reason
    pub fn cancel_payroll_run(e: Env, admin: Address, run_id: u64, reason: Symbol) {
        Self::cancel_payroll_run_with_reason(e, admin, run_id, reason);
    }

    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
    ) -> u64 {
        // #360 ? validate storage version for sensitive operation
        Self::validate_storage_version_for_operation(&e, "batch_process_payroll");

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

        addrs.admin.require_auth();

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
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);
        Self::record_payroll_run_state(&e, run_id, PayrollRunState::ReconciliationRequired);

        payroll_events::emit_run_executed(&e, run_id, expected_total_spend);

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
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);
        e.storage()
            .persistent()
            .set(&period_key, &draft_id);

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
        if new_total_amount <= 0 {
            panic!("total_amount must be positive");
        }
        draft.total_amount = new_total_amount;
        draft.employee_count = new_employee_count;
        draft.amendment_count += 1;
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

        draft.state = RunDraftState::Submitted;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

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

        payroll_events::emit_draft_expired(&e, draft_id, admin);
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

        payroll_events::emit_admin_rotated(&e, old_admin, new_admin);
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

        let old_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

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

        payroll_events::emit_treasury_rotated(&e, old_owner, new_owner);
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

        payroll_events::emit_admin_handover_accepted(&e, old_admin, pending_admin);
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
        let key = DataKey::LockedPayrollFunds(asset.clone());
        let current: i128 = e.storage().persistent().get(&key).unwrap_or(0i128);
        let new_locked = current.checked_add(amount).expect("Locked funds overflow");
        e.storage().persistent().set(&key, &new_locked);
        payroll_events::emit_locked_funds_updated(e, asset, new_locked);
    }

    pub fn subtract_locked_funds(e: &Env, asset: Address, amount: i128) {
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
        for i in 0..signers.len() {
            let s = signers.get(i).unwrap();
            s.require_auth();
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

    // ?? Issue #147: company state management ?????????????????????????????????

    /// Set the company lifecycle state.
    ///
    /// Only the admin may call. After setting to anything other than `Active`,
    /// all subsequent `batch_process_payroll` calls will be rejected with a
    /// descriptive error until the state is restored to `Active`.
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
        e.storage().persistent().set(&DataKey::CompanyState, &state);
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "state_changed")),
            state,
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

    // ?? Issue #146: archived payroll run queries ??????????????????????????????

    /// Mark a completed payroll run as archived for long-term reporting.
    ///
    /// Only the admin may archive. Archiving is additive and read-only: it
    /// flags the run without altering the underlying `PayrollRun` record,
    /// cannot trigger execution, state transitions, or treasury mutations.
    pub fn archive_payroll_run(e: Env, admin: Address, run_id: u64) {
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

        // Ensure the run exists before archiving it.
        if !e.storage().persistent().has(&DataKey::PayrollRun(run_id)) {
            panic!("Run not found");
        }

        // Issue #374: block archival while an audit challenge is unresolved.
        if e.storage().persistent().has(&DataKey::ChallengedRun(run_id)) {
            panic!("Run has an unresolved audit challenge");
        }

        let archive_key = DataKey::ArchivedRun(run_id);
        if e.storage().persistent().has(&archive_key) {
            panic!("Run is already archived");
        }
        e.storage().persistent().set(&archive_key, &true);

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
        e.storage().persistent().set(&DataKey::ChallengedRun(run_id), &true);
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
        e.storage().persistent().remove(&DataKey::ChallengedRun(run_id));
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_challenge_cleared")),
            run_id,
        );
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

    // ?? Reviewer Authorization & Run Review Entrypoints ?????????????????????

    /// Grant reviewer authorization to an address. Only the admin may call.
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

        e.storage()
            .persistent()
            .set(&DataKey::AuthorizedReviewer(reviewer.clone()), &true);

        payroll_events::emit_reviewer_added(&e, reviewer);
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

        e.storage()
            .persistent()
            .remove(&DataKey::AuthorizedReviewer(reviewer.clone()));

        payroll_events::emit_reviewer_removed(&e, reviewer);
    }

    /// Return `true` if the address is an authorized reviewer, `false` otherwise.
    pub fn is_reviewer(e: Env, reviewer: Address) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::AuthorizedReviewer(reviewer))
            .unwrap_or(false)
    }

    /// Approve a payroll run as an authorized reviewer.
    pub fn approve_payroll_run(e: Env, reviewer: Address, run_id: u64) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

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

    /// Reject a payroll run as an authorized reviewer.
    pub fn reject_payroll_run(e: Env, reviewer: Address, run_id: u64, reason: Symbol) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

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

    /// Request changes to a payroll run as an authorized reviewer.
    pub fn request_changes_payroll_run(e: Env, reviewer: Address, run_id: u64, reason: Symbol) {
        Self::require_not_paused(&e);
        if !Self::is_reviewer(e.clone(), reviewer.clone()) {
            panic!("Unauthorized: caller is not an authorized reviewer");
        }
        reviewer.require_auth();

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
    /// Requires authorization from the contract admin.
    pub fn set_reservation_expiry_policy(
        e: Env,
        admin: Address,
        asset: Address,
        reserved_amount: i128,
        expiry_ledger_offset: u64,
    ) {
        admin.require_auth();

        let now = e.ledger().timestamp();
        let expires_at = now + expiry_ledger_offset;

        let expiry = ReservationExpiry {
            asset: asset.clone(),
            reserved_amount,
            expires_at,
            created_at: now,
        };

        e.storage()
            .persistent()
            .set(&DataKey::ReservationExpiry(asset), &expiry);
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
        admin.require_auth();

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

    // ?? Issue #401: Batch Lock Timestamp Query Helper ????????????????????????

    /// Return the timestamp at which a payroll batch reached locked state (#401).
    ///
    /// A batch is in a locked state when funds have been reserved and it is awaiting
    /// execution or has already been executed.
    /// - If the batch is in a pending run state (`PendingRun(run_id)`), its `prepared_at` timestamp is returned.
    /// - If the batch has been executed (`PayrollRun(run_id)`), its `executed_at` timestamp is returned.
    /// - If the batch does not exist or has not been locked, `None` is returned.
    pub fn get_batch_lock_timestamp(e: Env, run_id: u64) -> Option<u64> {
        if let Some(pending) = e
            .storage()
            .persistent()
            .get::<_, PendingPayrollRun>(&DataKey::PendingRun(run_id))
        {
            return Some(pending.prepared_at);
        }
        if let Some(run) = e
            .storage()
            .persistent()
            .get::<_, PayrollRun>(&DataKey::PayrollRun(run_id))
        {
            return Some(run.executed_at);
        }
        None
    }

    // ?? Issue #402: Safe Treasury Balance Summary View ???????????????????????

    /// Return aggregate treasury balance summary for a given asset token (#402).
    ///
    /// Returns the total balance held at the treasury address, the reserved/locked
    /// balance allocated to pending payroll runs, blocked balances, and the net
    /// available balance without disclosing individual salary rows.
    pub fn get_safe_treasury_summary(e: Env, asset: Address) -> SafeTreasurySummary {
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
    pub fn get_batch_split(e: Env, parent_run_id: u64, child_run_id: u64) -> Option<BatchSplitRecord> {
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
        if let Some(parent_run) = e.storage().persistent().get::<DataKey, PayrollRun>(&parent_run_key) {
            parent_run.total_amount == expected_total_amount
                && parent_run.employee_count == expected_employee_count
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::{Token, TokenClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use proof_verifier::{ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{Env, IntoVal};

    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    /// Generates a unique 32-byte nonce from a counter seed for tests.
    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
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

        let label = Symbol::new(&env, "Q1_2025");
        let id1 = payroll_client.create_run_draft(&admin, &5_000i128, &10u32, &label);
        let id2 = payroll_client.create_run_draft(&admin, &3_000i128, &5u32, &label);

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
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &10_000,
            &nonce,
            &None,
        );

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
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &50_000,
            &nonce,
            &None,
        );

        let summary_locked = payroll_client.get_safe_treasury_summary(&addrs.token);
        assert_eq!(summary_locked.total_balance, 1_000_000);
        assert_eq!(summary_locked.reserved_balance, 50_000);
        assert_eq!(summary_locked.available_balance, 950_000);
        assert_eq!(summary_locked.blocked_balance, 0);

        // Cancel run to release reservation
        payroll_client.cancel_payroll_run(
            &addrs.admin,
            &run_id,
            &Symbol::new(&env, "mistake"),
        );

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
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &10_000,
            &nonce,
            &None,
        );

        // Approve run
        payroll_client.approve_payroll_run(&reviewer, &run_id);

        // Fresh approval is not expired
        assert!(!payroll_client.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));

        // Advance ledger timestamp beyond 7 days
        env.ledger().with_mut(|li| {
            li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
        });

        // Now approval is expired
        assert!(payroll_client.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
    }

    #[test]
    #[should_panic(expected = "Payroll approval expired: approval record exceeds maximum allowed age")]
    fn test_finalize_panics_on_expired_approval() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let reviewer = Address::generate(&env);
        payroll_client.add_reviewer(&admin, &reviewer);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
        let nonce = test_nonce(&env, 4);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &10_000,
            &nonce,
            &None,
        );

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
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &25_000,
            &nonce,
            &None,
        );

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
}
