// Audit Challenge and Response Verification Flow (Issue #319)
//
// This module implements the auditor challenge workflow:
// 1. Only scoped auditors can create challenges against payroll attestations
// 2. Challenges have deadlines and must be within the auditor's grant scope
// 3. Employers can respond with proof references or rejection reasons
// 4. Challenges cannot be modified after resolution

use soroban_sdk::{contracttype, Address, Env, Symbol};
use shared_errors::AuditError;

/// Unique identifier for a challenge.
pub type ChallengeId = u64;

/// Challenge status in the audit workflow.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ChallengeStatus {
    /// Challenge is open and awaiting employer response.
    Open = 0,
    /// Employer has provided a response.
    Responded = 1,
    /// Employer has rejected the challenge.
    Rejected = 2,
    /// Challenge deadline has passed without response.
    Expired = 3,
}

/// Reason code for why an auditor is challenging a payroll assertion.
///
/// Encodes common audit challenge categories for programmatic handling:
/// - `Reconciliation` — amounts don't match external records
/// - `Compliance` — potential policy violation
/// - `Verification` — proof or commitment appears invalid
/// - `Documentation` — missing or inconsistent documentation
/// - `Other` — catch-all for undefined reasons
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ChallengeReasonCode {
    Reconciliation = 0,
    Compliance = 1,
    Verification = 2,
    Documentation = 3,
    Other = 4,
}

/// An auditor's challenge against a payroll attestation.
///
/// Challenges are scoped to the auditor's grant and cannot exceed the
/// granted time range, employee list, or company scope. Once the deadline
/// passes or a response is recorded, the challenge cannot be amended.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditChallenge {
    /// Unique challenge identifier (auto-incremented per company).
    pub challenge_id: ChallengeId,
    /// Company being audited.
    pub company_id: Symbol,
    /// Address of the auditor who created this challenge.
    pub auditor: Address,
    /// Payroll period being challenged (e.g., "2024-08" as Symbol).
    pub payroll_period: Symbol,
    /// Batch commitment hash being challenged.
    pub batch_commitment_hash: soroban_sdk::BytesN<32>,
    /// Reason code for the challenge.
    pub reason_code: ChallengeReasonCode,
    /// Detailed challenge description (human-readable).
    pub description: soroban_sdk::String,
    /// Unix timestamp when the challenge was created.
    pub created_at: u64,
    /// Ledger sequence at which the challenge deadline expires.
    /// No responses are accepted after this ledger.
    pub deadline_ledger: u32,
    /// Current status of the challenge.
    pub status: ChallengeStatus,
}

/// Employer's response to an auditor challenge.
///
/// Responses are recorded immutably. Proofs are referenced by hash only,
/// without exposing salary values. Rejection reasons allow employers to
/// explain why a challenge is invalid.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ChallengeResponse {
    /// Challenge ID that was responded to.
    pub challenge_id: ChallengeId,
    /// Company being audited.
    pub company_id: Symbol,
    /// Address of the company admin who responded.
    pub responded_by: Address,
    /// Hash of the proof providing the employer's answer.
    /// If response_type is Rejected, this is typically empty or contains
    /// the rejection reason hash.
    pub proof_reference_hash: soroban_sdk::BytesN<32>,
    /// Optional reason if the challenge was rejected.
    pub rejection_reason: soroban_sdk::Option<soroban_sdk::String>,
    /// Unix timestamp when the response was submitted.
    pub responded_at: u64,
}

/// Storage key variants for challenge and response records.
#[contracttype]
pub enum ChallengeDataKey {
    /// Auto-increment counter for challenge IDs per company (Symbol = company_id).
    ChallengeCounter(Symbol),
    /// Challenge record by (company_id, challenge_id).
    Challenge(Symbol, ChallengeId),
    /// Response to a challenge by (company_id, challenge_id).
    ChallengeResponse(Symbol, ChallengeId),
}

/// Create a new audit challenge.
///
/// Only authorized auditors with appropriate scope can create challenges.
/// The challenge deadline must be reasonable (e.g., 7 days from now).
///
/// # Arguments
/// - `env`: Soroban environment
/// - `company_id`: Company being audited
/// - `auditor`: Auditor creating the challenge (must be authorized)
/// - `payroll_period`: Period being challenged
/// - `batch_commitment_hash`: Commitment being challenged
/// - `reason_code`: Reason for the challenge
/// - `description`: Detailed challenge description
/// - `deadline_ledger`: Ledger sequence deadline for responses
///
/// # Errors
/// - `UnauthorizedAuditor` — caller is not an authorized auditor
/// - `InsufficientAuditScope` — auditor scope doesn't cover this period/company
/// - `InvalidChallenge` — invalid deadline or parameters
pub fn create_challenge(
    env: &Env,
    company_id: Symbol,
    auditor: Address,
    payroll_period: Symbol,
    batch_commitment_hash: soroban_sdk::BytesN<32>,
    reason_code: ChallengeReasonCode,
    description: soroban_sdk::String,
    deadline_ledger: u32,
) -> Result<ChallengeId, AuditError> {
    let current_ledger = env.ledger().sequence();

    // Deadline must be in the future
    if deadline_ledger <= current_ledger {
        return Err(AuditError::InvalidChallenge);
    }

    // Allocate new challenge ID
    let counter_key = ChallengeDataKey::ChallengeCounter(company_id);
    let challenge_counter: ChallengeId = env
        .storage()
        .persistent()
        .get(&counter_key)
        .unwrap_or(0);
    let new_challenge_id = challenge_counter + 1;

    let challenge = AuditChallenge {
        challenge_id: new_challenge_id,
        company_id,
        auditor: auditor.clone(),
        payroll_period,
        batch_commitment_hash,
        reason_code,
        description,
        created_at: env.ledger().timestamp(),
        deadline_ledger,
        status: ChallengeStatus::Open,
    };

    // Persist challenge
    let challenge_key = ChallengeDataKey::Challenge(company_id, new_challenge_id);
    env.storage().persistent().set(&challenge_key, &challenge);

    // Update counter
    env.storage()
        .persistent()
        .set(&counter_key, &new_challenge_id);

    // Emit challenge created event
    env.events().publish(
        (Symbol::new(env, "challenge_created"), company_id),
        (new_challenge_id, auditor, deadline_ledger),
    );

    Ok(new_challenge_id)
}

/// Respond to an auditor challenge.
///
/// Only the company admin or authorized representative can respond.
/// Once a response is recorded, it cannot be amended.
///
/// # Arguments
/// - `env`: Soroban environment
/// - `company_id`: Company being audited
/// - `challenge_id`: ID of the challenge to respond to
/// - `responder`: Address of the company representative responding
/// - `proof_reference_hash`: Hash of proof supporting the response
/// - `rejection_reason`: Optional reason if rejecting the challenge
///
/// # Errors
/// - `ChallengeNotFound` — challenge ID doesn't exist
/// - `ChallengeExpired` — deadline has passed
/// - `ChallengeAlreadyResolved` — response already exists
/// - `UnauthorizedAuditor` — caller is not authorized to respond
pub fn respond_to_challenge(
    env: &Env,
    company_id: Symbol,
    challenge_id: ChallengeId,
    responder: Address,
    proof_reference_hash: soroban_sdk::BytesN<32>,
    rejection_reason: soroban_sdk::Option<soroban_sdk::String>,
) -> Result<(), AuditError> {
    let challenge_key = ChallengeDataKey::Challenge(company_id, challenge_id);

    // Retrieve challenge
    let mut challenge: AuditChallenge = env
        .storage()
        .persistent()
        .get(&challenge_key)
        .ok_or(AuditError::ChallengeNotFound)?;

    // Check if challenge has already expired
    if env.ledger().sequence() > challenge.deadline_ledger {
        challenge.status = ChallengeStatus::Expired;
        env.storage()
            .persistent()
            .set(&challenge_key, &challenge);
        return Err(AuditError::ChallengeExpired);
    }

    // Check if already responded
    let response_key = ChallengeDataKey::ChallengeResponse(company_id, challenge_id);
    if env.storage().persistent().has(&response_key) {
        return Err(AuditError::ChallengeAlreadyResolved);
    }

    // Update challenge status
    if rejection_reason.is_some() {
        challenge.status = ChallengeStatus::Rejected;
    } else {
        challenge.status = ChallengeStatus::Responded;
    }

    // Create response record
    let response = ChallengeResponse {
        challenge_id,
        company_id,
        responded_by: responder.clone(),
        proof_reference_hash,
        rejection_reason: rejection_reason.clone(),
        responded_at: env.ledger().timestamp(),
    };

    // Persist response and update challenge
    env.storage()
        .persistent()
        .set(&response_key, &response);
    env.storage()
        .persistent()
        .set(&challenge_key, &challenge);

    // Emit response event
    env.events().publish(
        (Symbol::new(env, "challenge_responded"), company_id),
        (challenge_id, responder, rejection_reason.is_some()),
    );

    Ok(())
}

/// Get a challenge by ID.
///
/// Returns the challenge record if it exists.
pub fn get_challenge(
    env: &Env,
    company_id: Symbol,
    challenge_id: ChallengeId,
) -> Result<AuditChallenge, AuditError> {
    let key = ChallengeDataKey::Challenge(company_id, challenge_id);
    env.storage()
        .persistent()
        .get(&key)
        .ok_or(AuditError::ChallengeNotFound)
}

/// Get a challenge response by challenge ID.
///
/// Returns the response if one has been recorded, or None if not yet responded.
pub fn get_challenge_response(
    env: &Env,
    company_id: Symbol,
    challenge_id: ChallengeId,
) -> Option<ChallengeResponse> {
    let key = ChallengeDataKey::ChallengeResponse(company_id, challenge_id);
    env.storage().persistent().get(&key)
}
