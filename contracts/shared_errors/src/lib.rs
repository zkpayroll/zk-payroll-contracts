#![no_std]

use soroban_sdk::contracterror;

// ─────────────────────────────────────────────────────────────────────────────
// Centralized Error Taxonomy
// ─────────────────────────────────────────────────────────────────────────────
//
// This module provides a deterministic error taxonomy across all ZK Payroll
// contracts. All contract errors are grouped by category (Authorization,
// Proof Verification, Audit, Payment, Treasury, Storage State), assigned
// stable numeric identifiers, and documented for SDK consumers.
//
// Error ID ranges (reserved to prevent collisions):
//   - 1-99:   Common/Authorization errors
//   - 100-199: Proof Verification & Cryptography
//   - 200-299: Audit & Access Control
//   - 300-399: Payment Execution
//   - 400-499: Treasury & Assets
//   - 500-599: Payroll State Machine
//   - 600-699: Replay Protection & Idempotency
//   - 700-799: Storage & Versioning
//
// Usage by SDK/Dashboard:
// - Map error IDs to user-facing messages by category
// - Use error categories to determine retry vs. non-retry behavior
// - All errors are stable across contract versions
// ─────────────────────────────────────────────────────────────────────────────

/// Authorization and Access Control Errors (1-99)
///
/// These errors indicate that the caller lacks proper authorization or
/// that an account, role, or permission constraint was violated.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthError {
    /// Caller is not the designated admin for this company.
    UnauthorizedAdmin = 1,
    /// Caller is not the designated treasury owner.
    UnauthorizedTreasuryOwner = 2,
    /// Caller is not an authorized auditor for this scope.
    UnauthorizedAuditor = 3,
    /// Caller is not the address being rotated to.
    UnauthorizedRotationTarget = 4,
    /// Caller is not the designated reviewer.
    UnauthorizedReviewer = 5,
    /// Required authorization was not provided (host `require_auth` failed).
    AuthorizationFailed = 6,
    /// The caller is not the pending handover recipient.
    UnauthorizedHandoverTarget = 7,
}

/// Proof Verification and Cryptographic Errors (100-199)
///
/// These errors indicate that a ZK proof, commitment, or cryptographic
/// verification failed. Non-retryable — requires regenerating proofs.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ProofError {
    /// The supplied proof bytes are malformed or do not match the verifier schema.
    InvalidProofFormat = 100,
    /// The Groth16 proof failed verification (public inputs or proof data incorrect).
    ProofVerificationFailed = 101,
    /// The salary amount + blinding factor do not match the stored commitment.
    CommitmentMismatch = 102,
    /// The proof timestamp is outside the accepted freshness window.
    ProofExpired = 103,
    /// The proof contains an invalid public input or has too few/many inputs.
    InvalidPublicInputs = 104,
    /// The verifying key does not match the proof schema.
    VerifyingKeyMismatch = 105,
    /// An invalid or malformed nullifier was provided in the proof.
    InvalidNullifier = 106,
}

/// Audit Access and Scope Errors (200-299)
///
/// These errors relate to audit permissions, view keys, and scope violations.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AuditError {
    /// No view key is stored for this auditor.
    ViewKeyNotFound = 200,
    /// The provided view key does not match the auditor's stored key.
    InvalidViewKey = 201,
    /// The auditor's view key has expired by ledger sequence.
    ViewKeyExpired = 202,
    /// The auditor's scope is insufficient for the requested operation.
    InsufficientAuditScope = 203,
    /// The auditor is not authorized to create or respond to challenges.
    UnauthorizedChallengeParticipant = 204,
    /// A challenge with this ID does not exist.
    ChallengeNotFound = 205,
    /// The challenge deadline has passed — no further responses accepted.
    ChallengeExpired = 206,
    /// The challenge has already been resolved.
    ChallengeAlreadyResolved = 207,
    /// An invalid challenge ID or out-of-scope challenge was submitted.
    InvalidChallenge = 208,
    /// The challenge response timestamp is outside the acceptance window.
    InvalidResponseTimestamp = 209,
}

/// Payment Execution Errors (300-399)
///
/// These errors occur during payment processing, period management, and
/// employee payment state transitions.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PaymentError {
    /// The payroll period does not exist.
    PeriodNotFound = 300,
    /// The payroll period is closed — no new payments allowed.
    PeriodClosed = 301,
    /// Attempt to create a duplicate period for this company.
    PeriodAlreadyExists = 302,
    /// An employee has already been paid for this period.
    EmployeeAlreadyPaid = 303,
    /// The payment amount is invalid (non-positive or exceeds limits).
    InvalidPaymentAmount = 304,
    /// The employee record does not exist or is incomplete.
    EmployeeNotFound = 305,
    /// The company record does not exist.
    CompanyNotFound = 306,
    /// The salary commitment for this employee is locked (audit hold, etc.).
    CommitmentLocked = 307,
    /// Empty payroll batches are rejected to avoid silent no-op execution.
    EmptyBatch = 308,
    /// Provided array lengths do not match (employees, amounts, proofs, etc.).
    ArrayLengthMismatch = 309,
}

/// Treasury and Asset Errors (400-499)
///
/// These errors relate to treasury operations, asset management, and
/// fund availability.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TreasuryError {
    /// Treasury does not hold sufficient balance for the requested transfer.
    InsufficientTreasuryBalance = 400,
    /// The requested asset is not in the allowed asset list.
    AssetNotAllowed = 401,
    /// A treasury withdrawal request is already pending.
    WithdrawalRequestPending = 402,
    /// No pending withdrawal request exists for this approval.
    WithdrawalRequestNotFound = 403,
    /// The treasury cannot perform this operation (locked, paused, etc.).
    TreasuryLocked = 404,
    /// Reserved funds exceed available balance for this asset.
    InsufficientUnreservedBalance = 405,
    /// The asset configuration is invalid or incomplete.
    InvalidAssetConfiguration = 406,
}

/// Payroll State Machine and Lifecycle Errors (500-599)
///
/// These errors relate to payroll run state transitions, draft workflows,
/// and company/employee lifecycle states.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum StateError {
    /// The payroll run does not exist or has been archived.
    PayrollRunNotFound = 500,
    /// The pending payroll run does not exist.
    PendingRunNotFound = 501,
    /// The draft run does not exist.
    DraftNotFound = 502,
    /// The payroll run is in an invalid state for this operation.
    InvalidPayrollState = 503,
    /// The draft is locked (finalized) and cannot be amended.
    DraftLocked = 504,
    /// The company is in an invalid state (paused, archived, etc.).
    InvalidCompanyState = 505,
    /// The employee is in an invalid status for this operation.
    InvalidEmployeeStatus = 506,
    /// The employee eligibility check failed (inactive, incomplete, etc.).
    EmployeeIneligible = 507,
    /// The compliance hold blocks this payroll operation.
    ComplianceHoldActive = 508,
}

/// Replay Protection and Idempotency Errors (600-699)
///
/// These errors prevent duplicate execution, protect against replays,
/// and ensure safe retry semantics.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ReplayError {
    /// This nonce has already been consumed — payroll run is a duplicate.
    NonceAlreadyUsed = 600,
    /// A payroll execution with this identity has already completed.
    PayrollAlreadyExecuted = 601,
    /// The proof nullifier has already been used (duplicate proof submission).
    NullifierAlreadyUsed = 602,
    /// The payload has been modified after the original submission.
    ConflictingPayloadData = 603,
    /// The stored execution record matches but the client provided conflicting details.
    ExecutionIdentityMismatch = 604,
    /// The authorization (quorum signature, sequence number) is no longer valid.
    AuthorizationExpired = 605,
    /// Cross-company or cross-asset payload reuse detected.
    InvalidPayloadContext = 606,
}

/// Storage and Versioning Errors (700-799)
///
/// These errors relate to contract storage, schema versioning, and
/// data consistency.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum StorageError {
    /// The contract has not been initialized yet.
    NotInitialized = 700,
    /// The contract is already initialized (cannot re-initialize).
    AlreadyInitialized = 701,
    /// Storage schema version is incompatible with this contract version.
    StorageVersionMismatch = 702,
    /// A required storage record is corrupted or invalid.
    StorageCorruption = 703,
    /// Cannot migrate storage — dependency contract is missing or invalid.
    MigrationFailed = 704,
}

/// Conversion helper for cross-contract error mapping
impl StorageError {
    /// Convert to a generic u32 for contract invocation
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl TreasuryError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl StateError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl PaymentError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl AuditError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl ProofError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl AuthError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

impl ReplayError {
    pub fn code(self) -> u32 {
        self as u32
    }
}
