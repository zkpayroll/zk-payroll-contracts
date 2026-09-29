#![no_std]

//! # Payroll Commitment Retention and Pruning Policy — Issue #321
//!
//! Defines retention windows for finalized batches, cancelled batches, expired
//! audit grants, and challenge records. Provides admin-controlled pruning
//! operations with safety checks that prevent removal of records still needed
//! for active audits or disputes.
//!
//! ## Retention categories
//!
//! | Record type          | Default window (ledgers) | Notes                        |
//! |----------------------|--------------------------|------------------------------|
//! | Finalized batch      | 365 days × 86400 s       | Compliance minimum           |
//! | Cancelled batch      | 90 days × 86400 s        | Shorter — no value disbursed |
//! | Expired audit grant  | 30 days × 86400 s        | After grant expiration       |
//! | Challenge record     | 730 days × 86400 s       | Longest — dispute evidence   |
//!
//! All timestamps are Unix seconds from `env.ledger().timestamp()`.
//!
//! ## Safety guards
//!
//! - A record with an active audit grant or open challenge cannot be pruned.
//! - Pruning emits a `RetentionPruned` event for off-chain archive systems.
//! - Pruning is authorized (admin-only); the system does not auto-prune.

use pause_manager::PauseManagerClient;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Constants — default retention windows in seconds
// ---------------------------------------------------------------------------

/// Retention window for finalized payroll batches (1 year).
const FINALIZED_RETENTION_SECS: u64 = 365 * 24 * 60 * 60;
/// Retention window for cancelled payroll batches (90 days).
const CANCELLED_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;
/// Retention window for expired audit grants after the grant's expiry (30 days).
const AUDIT_GRANT_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
/// Retention window for challenge / dispute records (2 years).
const CHALLENGE_RETENTION_SECS: u64 = 730 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed errors returned by the retention manager.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RetentionError {
    /// The record was not found in the retention registry.
    RecordNotFound = 1,
    /// The record is still within its retention window; pruning is not allowed.
    RetentionWindowActive = 2,
    /// An active audit grant protects this record from pruning.
    ActiveAuditBlock = 3,
    /// An open challenge / dispute protects this record from pruning.
    ActiveChallengeBlock = 4,
    /// The caller is not the admin.
    Unauthorized = 5,
    /// The record type is not recognised.
    UnknownRecordType = 6,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Category of a retained record, which determines the retention window.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RecordType {
    /// A payroll batch that completed successfully.
    FinalizedBatch = 0,
    /// A payroll batch that was cancelled before execution.
    CancelledBatch = 1,
    /// An audit grant that has expired.
    ExpiredAuditGrant = 2,
    /// A challenge or dispute record.
    ChallengeRecord = 3,
}

/// Metadata entry stored in the retention registry for a managed record.
///
/// Privacy note: no salary amounts, employee addresses, or commitment bytes
/// are stored here — only identifiers and timestamps sufficient for retention
/// policy enforcement.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RetentionRecord {
    /// Opaque record identifier supplied by the caller (e.g. run_id, grant_id).
    pub record_id: u64,
    /// Broad category determining the retention window.
    pub record_type: RecordType,
    /// Unix timestamp when the record was registered for retention tracking.
    pub registered_at: u64,
    /// Unix timestamp after which pruning becomes eligible
    /// (= `registered_at + retention_window_for(record_type)`).
    pub eligible_after: u64,
    /// True when an active audit grant protects this record.
    pub audit_block: bool,
    /// True when an open challenge/dispute protects this record.
    pub challenge_block: bool,
    /// True when this record has been pruned (tombstone entry retained briefly).
    pub pruned: bool,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Admin address.
    Admin,
    /// Optional pause manager.
    PauseManager,
    /// `RetentionRecord` keyed by (company_id, record_id, record_type).
    Record(u64, u64, u32),
    /// Custom retention window override keyed by (company_id, RecordType).
    /// Absent = use the global constant.
    RetentionOverride(u64, u32),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct RetentionManagerContract;

#[contractimpl]
impl RetentionManagerContract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Initialise the contract. One-time call.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        payroll_events::emit_retention_manager_initialized(&env, admin);
    }

    /// Set or replace the pause manager. Only the admin may call.
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a record for retention tracking.
    ///
    /// `company_id` — owning company.
    /// `record_id`  — caller-supplied opaque identifier (run_id, grant_id, …).
    /// `record_type` — determines the retention window.
    pub fn register_record(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
    ) -> RetentionRecord {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let now = env.ledger().timestamp();
        let window = Self::retention_window_for(&env, company_id, &record_type);
        let entry = RetentionRecord {
            record_id,
            record_type,
            registered_at: now,
            eligible_after: now + window,
            audit_block: false,
            challenge_block: false,
            pruned: false,
        };

        env.storage().persistent().set(
            &Self::record_key(company_id, record_id, &record_type),
            &entry,
        );

        payroll_events::emit_retention_record_registered(
            &env,
            company_id,
            record_id,
            Self::record_type_symbol(&env, &record_type),
            now + window,
        );

        entry
    }

    // -----------------------------------------------------------------------
    // Audit and challenge block management
    // -----------------------------------------------------------------------

    /// Set or clear the audit block on a retention record.
    ///
    /// When `blocked = true` the record is protected from pruning even if the
    /// retention window has elapsed. Only the admin may change this flag.
    pub fn set_audit_block(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
        blocked: bool,
    ) -> Result<RetentionRecord, RetentionError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let key = Self::record_key(company_id, record_id, &record_type);
        let mut entry: RetentionRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(RetentionError::RecordNotFound)?;

        entry.audit_block = blocked;
        env.storage().persistent().set(&key, &entry);

        payroll_events::emit_retention_block_changed(
            &env,
            company_id,
            record_id,
            Symbol::new(&env, "audit"),
            blocked,
        );

        Ok(entry)
    }

    /// Set or clear the challenge block on a retention record.
    ///
    /// When `blocked = true` the record is protected from pruning even if the
    /// retention window has elapsed. Only the admin may change this flag.
    pub fn set_challenge_block(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
        blocked: bool,
    ) -> Result<RetentionRecord, RetentionError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let key = Self::record_key(company_id, record_id, &record_type);
        let mut entry: RetentionRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(RetentionError::RecordNotFound)?;

        entry.challenge_block = blocked;
        env.storage().persistent().set(&key, &entry);

        payroll_events::emit_retention_block_changed(
            &env,
            company_id,
            record_id,
            Symbol::new(&env, "challenge"),
            blocked,
        );

        Ok(entry)
    }

    // -----------------------------------------------------------------------
    // Pruning
    // -----------------------------------------------------------------------

    /// Prune an eligible record.
    ///
    /// Safety checks (all must pass):
    ///   1. Record exists.
    ///   2. Not already pruned.
    ///   3. `now >= eligible_after` (retention window elapsed).
    ///   4. `audit_block == false`.
    ///   5. `challenge_block == false`.
    ///
    /// On success, the record is marked as pruned (tombstoned) and a
    /// `RetentionPruned` event is emitted for off-chain archive systems.
    /// The tombstone itself is not removed — it serves as an on-chain proof
    /// that pruning occurred at a specific time.
    pub fn prune_record(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
    ) -> Result<(), RetentionError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let key = Self::record_key(company_id, record_id, &record_type);
        let mut entry: RetentionRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(RetentionError::RecordNotFound)?;

        if entry.pruned {
            // Idempotent — already pruned; treat as success.
            return Ok(());
        }

        let now = env.ledger().timestamp();

        if now < entry.eligible_after {
            return Err(RetentionError::RetentionWindowActive);
        }
        if entry.audit_block {
            return Err(RetentionError::ActiveAuditBlock);
        }
        if entry.challenge_block {
            return Err(RetentionError::ActiveChallengeBlock);
        }

        entry.pruned = true;
        env.storage().persistent().set(&key, &entry);

        payroll_events::emit_retention_record_pruned(
            &env,
            company_id,
            record_id,
            Self::record_type_symbol(&env, &record_type),
            now,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Custom retention window
    // -----------------------------------------------------------------------

    /// Override the global retention window for a specific (company, record_type).
    ///
    /// Allows companies with stricter compliance requirements to extend the
    /// default window. Admin-only. Setting to 0 restores the global default.
    pub fn set_retention_override(
        env: Env,
        company_id: u64,
        record_type: RecordType,
        window_secs: u64,
    ) {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let key = DataKey::RetentionOverride(company_id, record_type as u32);
        if window_secs == 0 {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &window_secs);
        }
    }

    // -----------------------------------------------------------------------
    // Read-only queries
    // -----------------------------------------------------------------------

    /// Return the retention record, or `None` if not found.
    pub fn get_record(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
    ) -> Option<RetentionRecord> {
        env.storage()
            .persistent()
            .get(&Self::record_key(company_id, record_id, &record_type))
    }

    /// Return whether the record is eligible for pruning right now.
    pub fn is_eligible_for_pruning(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
    ) -> bool {
        let key = Self::record_key(company_id, record_id, &record_type);
        match env
            .storage()
            .persistent()
            .get::<DataKey, RetentionRecord>(&key)
        {
            Some(entry) => {
                !entry.pruned
                    && !entry.audit_block
                    && !entry.challenge_block
                    && env.ledger().timestamp() >= entry.eligible_after
            }
            None => false,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        admin.require_auth();
    }

    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let client = PauseManagerClient::new(env, &addr);
            if client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    fn record_key(company_id: u64, record_id: u64, record_type: &RecordType) -> DataKey {
        DataKey::Record(company_id, record_id, *record_type as u32)
    }

    fn retention_window_for(env: &Env, company_id: u64, record_type: &RecordType) -> u64 {
        let override_key = DataKey::RetentionOverride(company_id, *record_type as u32);
        if let Some(override_secs) = env
            .storage()
            .persistent()
            .get::<DataKey, u64>(&override_key)
        {
            return override_secs;
        }
        match record_type {
            RecordType::FinalizedBatch => FINALIZED_RETENTION_SECS,
            RecordType::CancelledBatch => CANCELLED_RETENTION_SECS,
            RecordType::ExpiredAuditGrant => AUDIT_GRANT_RETENTION_SECS,
            RecordType::ChallengeRecord => CHALLENGE_RETENTION_SECS,
        }
    }

    fn record_type_symbol(env: &Env, record_type: &RecordType) -> Symbol {
        match record_type {
            RecordType::FinalizedBatch => Symbol::new(env, "finalized"),
            RecordType::CancelledBatch => Symbol::new(env, "cancelled"),
            RecordType::ExpiredAuditGrant => Symbol::new(env, "audit_grant"),
            RecordType::ChallengeRecord => Symbol::new(env, "challenge"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — Issue #321
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::Env;

    fn setup() -> (Env, Address, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RetentionManagerContract);
        let admin = Address::generate(&env);
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        (env, contract_id, admin)
    }

    // ── Eligible pruning ────────────────────────────────────────────────────

    #[test]
    fn test_prune_eligible_finalized_batch() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 1u64;
        let record_id = 42u64;

        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        // Advance time past the retention window
        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + FINALIZED_RETENTION_SECS + 1;
        });

        client.prune_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        let record = client
            .get_record(&company_id, &record_id, &RecordType::FinalizedBatch)
            .unwrap();
        assert!(record.pruned);
    }

    // ── Ineligible: window still active ─────────────────────────────────────

    #[test]
    fn test_prune_rejected_within_window() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 2u64;
        let record_id = 1u64;

        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        // Time has NOT advanced — should be rejected
        let result = client.try_prune_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        assert_eq!(
            result.unwrap_err().unwrap(),
            RetentionError::RetentionWindowActive
        );
    }

    // ── Ineligible: active audit block ──────────────────────────────────────

    #[test]
    fn test_prune_blocked_by_active_audit() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 3u64;
        let record_id = 10u64;

        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        client.set_audit_block(&company_id, &record_id, &RecordType::FinalizedBatch, &true);

        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + FINALIZED_RETENTION_SECS + 1;
        });

        let result = client.try_prune_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        assert_eq!(
            result.unwrap_err().unwrap(),
            RetentionError::ActiveAuditBlock
        );
    }

    // ── Ineligible: active challenge block ──────────────────────────────────

    #[test]
    fn test_prune_blocked_by_open_challenge() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 4u64;
        let record_id = 20u64;

        client.register_record(&company_id, &record_id, &RecordType::ChallengeRecord);
        client.set_challenge_block(&company_id, &record_id, &RecordType::ChallengeRecord, &true);

        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + CHALLENGE_RETENTION_SECS + 1;
        });

        let result = client.try_prune_record(&company_id, &record_id, &RecordType::ChallengeRecord);
        assert_eq!(
            result.unwrap_err().unwrap(),
            RetentionError::ActiveChallengeBlock
        );
    }

    // ── Block cleared → pruning succeeds ────────────────────────────────────

    #[test]
    fn test_prune_succeeds_after_audit_block_cleared() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 5u64;
        let record_id = 30u64;

        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        client.set_audit_block(&company_id, &record_id, &RecordType::FinalizedBatch, &true);

        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + FINALIZED_RETENTION_SECS + 1;
        });

        // Clear the audit block
        client.set_audit_block(&company_id, &record_id, &RecordType::FinalizedBatch, &false);

        client.prune_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        let r = client
            .get_record(&company_id, &record_id, &RecordType::FinalizedBatch)
            .unwrap();
        assert!(r.pruned);
    }

    // ── Different record types have different windows ────────────────────────

    #[test]
    fn test_cancelled_batch_shorter_window() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 6u64;

        client.register_record(&company_id, &1u64, &RecordType::CancelledBatch);
        client.register_record(&company_id, &2u64, &RecordType::FinalizedBatch);

        // Advance past CANCELLED_RETENTION but not FINALIZED_RETENTION
        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + CANCELLED_RETENTION_SECS + 1;
        });

        // Cancelled batch is eligible
        assert!(client.is_eligible_for_pruning(&company_id, &1u64, &RecordType::CancelledBatch));
        // Finalized batch is NOT yet eligible
        assert!(!client.is_eligible_for_pruning(&company_id, &2u64, &RecordType::FinalizedBatch));
    }

    // ── Idempotent prune ─────────────────────────────────────────────────────

    #[test]
    fn test_prune_idempotent() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 7u64;
        let record_id = 99u64;

        client.register_record(&company_id, &record_id, &RecordType::ExpiredAuditGrant);

        env.ledger().with_mut(|l| {
            l.timestamp = l.timestamp + AUDIT_GRANT_RETENTION_SECS + 1;
        });

        client.prune_record(&company_id, &record_id, &RecordType::ExpiredAuditGrant);
        // Second call should not error
        client.prune_record(&company_id, &record_id, &RecordType::ExpiredAuditGrant);
    }

    // ── Custom retention override ────────────────────────────────────────────

    #[test]
    fn test_retention_override() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 8u64;
        let record_id = 55u64;

        // Set a very short custom window (1 second)
        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &1u64);
        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        env.ledger().with_mut(|l| l.timestamp = l.timestamp + 2);

        // Should be eligible because custom window (1s) has passed
        assert!(client.is_eligible_for_pruning(
            &company_id,
            &record_id,
            &RecordType::FinalizedBatch
        ));
    }
}
