#![no_std]

use soroban_sdk::contracterror;

// ?????????????????????????????????????????????????????????????????????????????
// Centralized Error Taxonomy
// ?????????????????????????????????????????????????????????????????????????????
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
// ?????????????????????????????????????????????????????????????????????????????

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
/// verification failed. Non-retryable ? requires regenerating proofs.
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
    /// The challenge deadline has passed ? no further responses accepted.
    ChallengeExpired = 206,
    /// The challenge has already been resolved.
    ChallengeAlreadyResolved = 207,
    /// An invalid challenge ID or out-of-scope challenge was submitted.
    InvalidChallenge = 208,
    /// The challenge response timestamp is outside the acceptance window.
    InvalidResponseTimestamp = 209,
    /// The proof reference hash is invalid (empty or all-zero sentinel).
    InvalidProofReference = 210,
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
    /// The payroll period is closed ? no new payments allowed.
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
    /// Execution was attempted before the period's settlement window has
    /// opened for execution (issue #316).
    SettlementWindowNotYetOpen = 310,
    /// Execution was attempted after the period's settlement window has
    /// closed for execution (grace period or fully closed) (issue #316).
    SettlementWindowClosed = 311,
    /// A settlement window configuration was rejected because its open,
    /// execution, grace, and close timestamps are not monotonically ordered
    /// (issue #316).
    InvalidSettlementWindowConfig = 312,
    /// A settlement window overlaps the calendar range of another payroll
    /// period (issue: payroll calendar overlap detection).
    SettlementWindowOverlap = 313,
    /// Per-company withholding configuration has not been initialized before execution (issue #538).
    WithholdingConfigMissing = 314,
    /// Combined withholding basis points exceed 100% (10_000 bps) (issue #538).
    InvalidWithholdingRate = 315,
    /// Computed net payout after withholding falls below the company minimum floor (issue #538).
    NetAmountBelowMinimum = 316,
    /// Gross payout amount exceeds the company per-payment cap (issue #538).
    GrossAmountExceedsCap = 317,
    /// Settlement receipt ID has already been consumed by an earlier batch (issue #551).
    SettlementReceiptAlreadyUsed = 318,
    /// Batch employee count exceeds the configured company or contract batch size limit (issue #510).
    BatchTooLarge = 319,
    /// Attempted to reopen a payroll period that is already open (issue #484).
    PeriodAlreadyOpen = 320,
    /// Aggregate batch payout total or cumulative company total overflowed `i128::MAX` (issue #814).
    PayoutTotalOverflow = 321,
}

/// Structured documentation descriptor for a payroll execution failure code (issue #823).
///
/// Contains only static, privacy-safe operational metadata so SDKs, CLI tools,
/// and operator dashboards can surface actionable diagnostics without ever
/// exposing employee addresses, commitments, or salary values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureCodeSpec {
    /// Numeric error code (`300..=321`).
    pub code: u32,
    /// Canonical enum variant identifier.
    pub name: &'static str,
    /// Concise human-readable explanation of the failure condition.
    pub summary: &'static str,
    /// Actionable operator/integrator remediation guidance.
    pub remediation: &'static str,
    /// Whether the failed call can succeed on a later retry after external state/time advances
    /// without regenerating employee commitments.
    pub retryable: bool,
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
    /// The requested treasury reservation was not found.
    ReservationNotFound = 407,
    /// The asset symbol cannot be normalized before allowlist or reservation checks.
    InvalidAssetSymbol = 408,
    /// The provided asset symbol does not match its normalized on-chain form.
    AssetSymbolMismatch = 409,
    /// The requested asset differs from the contract's canonical treasury asset.
    CrossAssetMismatch = 410,
    /// The requested asset contract does not represent the configured issuer.
    AssetIssuerMismatch = 411,
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
    /// This nonce has already been consumed ? payroll run is a duplicate.
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
    /// Cannot migrate storage ? dependency contract is missing or invalid.
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
    pub const MIN_CODE: u32 = Self::PeriodNotFound as u32;
    pub const MAX_CODE: u32 = Self::PayoutTotalOverflow as u32;

    pub const ALL: [Self; 22] = [
        Self::PeriodNotFound,
        Self::PeriodClosed,
        Self::PeriodAlreadyExists,
        Self::EmployeeAlreadyPaid,
        Self::InvalidPaymentAmount,
        Self::EmployeeNotFound,
        Self::CompanyNotFound,
        Self::CommitmentLocked,
        Self::EmptyBatch,
        Self::ArrayLengthMismatch,
        Self::SettlementWindowNotYetOpen,
        Self::SettlementWindowClosed,
        Self::InvalidSettlementWindowConfig,
        Self::SettlementWindowOverlap,
        Self::WithholdingConfigMissing,
        Self::InvalidWithholdingRate,
        Self::NetAmountBelowMinimum,
        Self::GrossAmountExceedsCap,
        Self::SettlementReceiptAlreadyUsed,
        Self::BatchTooLarge,
        Self::PeriodAlreadyOpen,
        Self::PayoutTotalOverflow,
    ];

    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Resolve a numeric error code (`300..=321`) into a typed [`PaymentError`] (issue #823).
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            300 => Some(Self::PeriodNotFound),
            301 => Some(Self::PeriodClosed),
            302 => Some(Self::PeriodAlreadyExists),
            303 => Some(Self::EmployeeAlreadyPaid),
            304 => Some(Self::InvalidPaymentAmount),
            305 => Some(Self::EmployeeNotFound),
            306 => Some(Self::CompanyNotFound),
            307 => Some(Self::CommitmentLocked),
            308 => Some(Self::EmptyBatch),
            309 => Some(Self::ArrayLengthMismatch),
            310 => Some(Self::SettlementWindowNotYetOpen),
            311 => Some(Self::SettlementWindowClosed),
            312 => Some(Self::InvalidSettlementWindowConfig),
            313 => Some(Self::SettlementWindowOverlap),
            314 => Some(Self::WithholdingConfigMissing),
            315 => Some(Self::InvalidWithholdingRate),
            316 => Some(Self::NetAmountBelowMinimum),
            317 => Some(Self::GrossAmountExceedsCap),
            318 => Some(Self::SettlementReceiptAlreadyUsed),
            319 => Some(Self::BatchTooLarge),
            320 => Some(Self::PeriodAlreadyOpen),
            321 => Some(Self::PayoutTotalOverflow),
            _ => None,
        }
    }

    /// Canonical identifier of the failure code (issue #823).
    pub const fn name(self) -> &'static str {
        match self {
            Self::PeriodNotFound => "PeriodNotFound",
            Self::PeriodClosed => "PeriodClosed",
            Self::PeriodAlreadyExists => "PeriodAlreadyExists",
            Self::EmployeeAlreadyPaid => "EmployeeAlreadyPaid",
            Self::InvalidPaymentAmount => "InvalidPaymentAmount",
            Self::EmployeeNotFound => "EmployeeNotFound",
            Self::CompanyNotFound => "CompanyNotFound",
            Self::CommitmentLocked => "CommitmentLocked",
            Self::EmptyBatch => "EmptyBatch",
            Self::ArrayLengthMismatch => "ArrayLengthMismatch",
            Self::SettlementWindowNotYetOpen => "SettlementWindowNotYetOpen",
            Self::SettlementWindowClosed => "SettlementWindowClosed",
            Self::InvalidSettlementWindowConfig => "InvalidSettlementWindowConfig",
            Self::SettlementWindowOverlap => "SettlementWindowOverlap",
            Self::WithholdingConfigMissing => "WithholdingConfigMissing",
            Self::InvalidWithholdingRate => "InvalidWithholdingRate",
            Self::NetAmountBelowMinimum => "NetAmountBelowMinimum",
            Self::GrossAmountExceedsCap => "GrossAmountExceedsCap",
            Self::SettlementReceiptAlreadyUsed => "SettlementReceiptAlreadyUsed",
            Self::BatchTooLarge => "BatchTooLarge",
            Self::PeriodAlreadyOpen => "PeriodAlreadyOpen",
            Self::PayoutTotalOverflow => "PayoutTotalOverflow",
        }
    }

    /// Privacy-safe summary of the failure condition (issue #823).
    pub const fn description(self) -> &'static str {
        match self {
            Self::PeriodNotFound => "Target payroll period does not exist for the company.",
            Self::PeriodClosed => "Target payroll period is closed and accepts no new disbursements.",
            Self::PeriodAlreadyExists => "An open payroll period already exists for the company.",
            Self::EmployeeAlreadyPaid => "Target recipient has already been settled in the specified period.",
            Self::InvalidPaymentAmount => "Payout amount is non-positive or fails asset decimal normalization.",
            Self::EmployeeNotFound => "Recipient record is not registered or is incomplete for the company.",
            Self::CompanyNotFound => "Company identifier is not registered in the payroll registry.",
            Self::CommitmentLocked => "Salary commitment is locked by an active audit or compliance hold.",
            Self::EmptyBatch => "Batch payroll submission contains zero payment entries.",
            Self::ArrayLengthMismatch => "Batch input vectors (recipients, amounts, proofs, nullifiers) have mismatched lengths.",
            Self::SettlementWindowNotYetOpen => "Current ledger timestamp precedes the period execution window.",
            Self::SettlementWindowClosed => "Current ledger timestamp is past the period execution/grace window.",
            Self::InvalidSettlementWindowConfig => "Settlement window timestamps are not monotonically ordered.",
            Self::SettlementWindowOverlap => "Proposed settlement window overlaps an existing non-cancelled company period.",
            Self::WithholdingConfigMissing => "Company withholding configuration has not been set prior to payment execution.",
            Self::InvalidWithholdingRate => "Combined tax and social withholding rates exceed 10,000 basis points (100%).",
            Self::NetAmountBelowMinimum => "Net payout after withholding deductions is below the configured floor.",
            Self::GrossAmountExceedsCap => "Gross payout exceeds the configured per-payment maximum cap.",
            Self::SettlementReceiptAlreadyUsed => "Settlement receipt identifier was already consumed by a completed batch.",
            Self::BatchTooLarge => "Batch size exceeds the company or contract maximum batch size limit.",
            Self::PeriodAlreadyOpen => "Cannot reopen a payroll period that is already open.",
            Self::PayoutTotalOverflow => "Aggregate batch payout or cumulative company total exceeded i128::MAX.",
        }
    }

    /// Actionable remediation steps for operators and integrators (issue #823).
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::PeriodNotFound => "Create the payroll period via create_period or verify the period ID.",
            Self::PeriodClosed => "Reopen the period with reopen_period or create the next sequential period.",
            Self::PeriodAlreadyExists => "Close the active period before opening a new one, or submit against the active period.",
            Self::EmployeeAlreadyPaid => "Skip the already-settled entry when retrying a partially completed batch.",
            Self::InvalidPaymentAmount => "Ensure the amount is non-negative and normalized to the configured asset decimals.",
            Self::EmployeeNotFound => "Onboard the recipient and store their commitment before executing payroll.",
            Self::CompanyNotFound => "Register the company in payroll_registry and use the returned company_id.",
            Self::CommitmentLocked => "Release the audit/compliance hold or wait for lock resolution before retrying.",
            Self::EmptyBatch => "Include at least one valid payment instruction in the batch call.",
            Self::ArrayLengthMismatch => "Ensure employees, amounts, proofs_a/b/c, and nullifiers all have identical length.",
            Self::SettlementWindowNotYetOpen => "Wait until the ledger timestamp reaches execute_at, then retry.",
            Self::SettlementWindowClosed => "Open a new settlement window for the next cycle or extend before expiry.",
            Self::InvalidSettlementWindowConfig => "Supply timestamps satisfying open_at <= execute_at <= grace_until <= close_at.",
            Self::SettlementWindowOverlap => "Schedule the new period at or after the previous period's close_at boundary.",
            Self::WithholdingConfigMissing => "Configure company withholding parameters via set_withholding_config first.",
            Self::InvalidWithholdingRate => "Set income_tax_bps + social_tax_bps <= 10_000.",
            Self::NetAmountBelowMinimum => "Adjust min_net_per_payment or verify the payment amount meets the net floor.",
            Self::GrossAmountExceedsCap => "Split the disbursement across periods or raise max_gross_per_payment.",
            Self::SettlementReceiptAlreadyUsed => "Treat the prior batch as settled or generate a fresh receipt_id for a new batch.",
            Self::BatchTooLarge => "Chunk the batch into smaller slices at or below get_max_batch_size.",
            Self::PeriodAlreadyOpen => "Proceed with payment execution directly; no reopen call is needed.",
            Self::PayoutTotalOverflow => "Split the batch or rotate company accounting before exceeding i128::MAX.",
        }
    }

    /// True if the failure is transient with respect to time/locks and can succeed on retry
    /// once the blocking condition clears (issue #823).
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::PeriodClosed
                | Self::CommitmentLocked
                | Self::SettlementWindowNotYetOpen
                | Self::WithholdingConfigMissing
        )
    }

    /// Return the full structured documentation descriptor for this failure code (issue #823).
    pub const fn spec(self) -> FailureCodeSpec {
        FailureCodeSpec {
            code: self.code(),
            name: self.name(),
            summary: self.description(),
            remediation: self.remediation(),
            retryable: self.is_retryable(),
        }
    }
}

/// Look up the structured documentation descriptor for a numeric `PaymentError` code (issue #823).
pub const fn describe_payment_failure_code(code: u32) -> Option<FailureCodeSpec> {
    match PaymentError::from_code(code) {
        Some(err) => Some(err.spec()),
        None => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_payment_failure_code_is_documented_and_roundtrips() {
        assert_eq!(PaymentError::MIN_CODE, 300);
        assert_eq!(PaymentError::MAX_CODE, 321);

        for (offset, variant) in PaymentError::ALL.iter().copied().enumerate() {
            let expected_code = 300 + offset as u32;
            assert_eq!(variant.code(), expected_code);
            assert_eq!(PaymentError::from_code(expected_code), Some(variant));

            let spec = describe_payment_failure_code(expected_code)
                .expect("every PaymentError code in 300..=321 must have a documented spec");
            assert_eq!(spec.code, expected_code);
            assert!(!spec.name.is_empty());
            assert!(!spec.summary.is_empty());
            assert!(!spec.remediation.is_empty());
            // Privacy check: static error descriptions must never embed raw addresses or amounts.
            assert!(!spec.summary.contains("GAAA"));
        }
    }

    #[test]
    fn test_unknown_and_out_of_range_payment_failure_codes_rejected() {
        for invalid_code in [0u32, 1, 99, 299, 322, 400, u32::MAX] {
            assert_eq!(PaymentError::from_code(invalid_code), None);
            assert_eq!(describe_payment_failure_code(invalid_code), None);
        }
    }

    #[test]
    fn test_payment_failure_code_boundary_and_retryability_classification() {
        let first = describe_payment_failure_code(PaymentError::MIN_CODE).unwrap();
        assert_eq!(first.name, "PeriodNotFound");
        assert!(!first.retryable);

        let last = describe_payment_failure_code(PaymentError::MAX_CODE).unwrap();
        assert_eq!(last.name, "PayoutTotalOverflow");
        assert!(!last.retryable);

        let window_wait = PaymentError::SettlementWindowNotYetOpen.spec();
        assert!(window_wait.retryable);
    }
}
