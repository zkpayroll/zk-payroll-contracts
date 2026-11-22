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
    /// A retention override update would shorten the effective window (#975).
    RetentionWindowShortened = 7,
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
    /// Address authorized to purge retention records. Defaults to admin.
    Purger,
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
        env.storage().persistent().set(&DataKey::Purger, &admin);
        payroll_events::emit_retention_manager_initialized(&env, admin);
    }

    /// Set or replace the pause manager. Only the admin may call.
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    /// Set the independent retention-purge operator. Archive/configuration
    /// administration remains controlled by `Admin`.
    pub fn set_purger(env: Env, purger: Address) {
        Self::require_admin(&env);
        env.storage().persistent().set(&DataKey::Purger, &purger);
    }

    /// Return the current purge operator, falling back to the admin for
    /// instances initialized before the separate role was introduced.
    pub fn get_purger(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Purger)
            .or_else(|| env.storage().persistent().get(&DataKey::Admin))
            .expect("Not initialized")
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a record for retention tracking.
    ///
    /// `company_id` — owning company.
    /// `record_id`  — caller-supplied opaque identifier (run_id, grant_id, …).
    /// `record_type` — determines the retention window.
    ///
    /// Panics if the same (company, record, type) is already registered.
    pub fn register_record(
        env: Env,
        company_id: u64,
        record_id: u64,
        record_type: RecordType,
    ) -> RetentionRecord {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        // Registering again would overwrite the entry: it would clear the audit and challenge
        // blocks and un-prune a tombstone, which is the on-chain proof that pruning happened.
        if env
            .storage()
            .persistent()
            .has(&Self::record_key(company_id, record_id, &record_type))
        {
            panic!("Record already registered");
        }

        let now = env.ledger().timestamp();
        let window = Self::retention_window_for(&env, company_id, &record_type);
        // Saturate instead of panicking on an extreme override or timestamp.
        // Clamping keeps the record effectively non-prunable, which is the
        // privacy-preserving failure mode for retention policy.
        let eligible_after = now.saturating_add(window);
        let entry = RetentionRecord {
            record_id,
            record_type,
            registered_at: now,
            eligible_after,
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
            eligible_after,
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
        Self::require_purger(&env);

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
    ///
    /// # Invariants (#975, #977)
    ///
    /// The effective window is monotonic: a non-zero override must strictly
    /// extend the current window. An update that would shorten it, or merely
    /// restate it, is rejected with `RetentionWindowShortened`. Clearing an
    /// override (0) is the only way to restore the built-in default and is
    /// allowed only while that default is already at least the current
    /// effective window. Existing records keep the `eligible_after` timestamp
    /// frozen at registration; changes affect only future registrations.
    pub fn set_retention_override(
        env: Env,
        company_id: u64,
        record_type: RecordType,
        window_secs: u64,
    ) -> Result<(), RetentionError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let key = DataKey::RetentionOverride(company_id, record_type as u32);
        let current = Self::retention_window_for(&env, company_id, &record_type);
        let default = Self::default_window_for(&record_type);
        // `0` clears the override, so the new effective window is the built-in
        // default. Any other value replaces the effective window directly.
        let new_effective = if window_secs == 0 {
            if default < current {
                return Err(RetentionError::RetentionWindowShortened);
            }
            default
        } else {
            if window_secs <= current {
                return Err(RetentionError::RetentionWindowShortened);
            }
            window_secs
        };

        if window_secs == 0 {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &window_secs);
        }

        payroll_events::emit_retention_override_set(
            &env,
            company_id,
            Self::record_type_symbol(&env, &record_type),
            current,
            new_effective,
        );

        Ok(())
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

    fn require_purger(env: &Env) {
        Self::get_purger(env.clone()).require_auth();
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

    /// The built-in default window for a record type, with no override applied.
    fn default_window_for(record_type: &RecordType) -> u64 {
        match record_type {
            RecordType::FinalizedBatch => FINALIZED_RETENTION_SECS,
            RecordType::CancelledBatch => CANCELLED_RETENTION_SECS,
            RecordType::ExpiredAuditGrant => AUDIT_GRANT_RETENTION_SECS,
            RecordType::ChallengeRecord => CHALLENGE_RETENTION_SECS,
        }
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
        Self::default_window_for(record_type)
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
mod policy_update_regression_tests;

#[cfg(test)]
mod archive_query_migration_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use pause_manager::{PauseManager, PauseManagerClient};
    use soroban_sdk::testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke};
    use soroban_sdk::{Env, IntoVal};

    fn setup() -> (Env, Address, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(RetentionManagerContract, ());
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
    fn test_retention_override_is_monotonic() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 8u64;
        let default = FINALIZED_RETENTION_SECS;

        // Clearing with no override present is an allowed no-op.
        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &0u64);

        // A non-zero override must strictly extend the default.
        assert_eq!(
            client.try_set_retention_override(&company_id, &RecordType::FinalizedBatch, &default),
            Err(Ok(RetentionError::RetentionWindowShortened))
        );
        let extended = default + 100;
        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &extended);

        // Restating the current window or shortening it is rejected.
        assert_eq!(
            client.try_set_retention_override(
                &company_id,
                &RecordType::FinalizedBatch,
                &extended
            ),
            Err(Ok(RetentionError::RetentionWindowShortened))
        );
        assert_eq!(
            client.try_set_retention_override(
                &company_id,
                &RecordType::FinalizedBatch,
                &(extended - 1)
            ),
            Err(Ok(RetentionError::RetentionWindowShortened))
        );
        // Clearing after an extension would shorten retention, so it is rejected.
        assert_eq!(
            client.try_set_retention_override(&company_id, &RecordType::FinalizedBatch, &0u64),
            Err(Ok(RetentionError::RetentionWindowShortened))
        );
    }

    #[test]
    fn test_retention_override_affects_only_new_records() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 9u64;

        client.register_record(&company_id, &1u64, &RecordType::FinalizedBatch);
        let before = client
            .get_record(&company_id, &1u64, &RecordType::FinalizedBatch)
            .unwrap();

        let extended = FINALIZED_RETENTION_SECS + 100;
        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &extended);
        client.register_record(&company_id, &2u64, &RecordType::FinalizedBatch);
        let after = client
            .get_record(&company_id, &2u64, &RecordType::FinalizedBatch)
            .unwrap();

        // Existing records keep the window frozen at their registration time.
        assert_eq!(
            before.eligible_after - before.registered_at,
            FINALIZED_RETENTION_SECS
        );
        assert_eq!(after.eligible_after - after.registered_at, extended);
    }

    #[test]
    fn test_register_record_saturates_eligible_after() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 10u64;

        env.ledger().with_mut(|l| l.timestamp = u64::MAX - 10);
        client.register_record(&company_id, &1u64, &RecordType::FinalizedBatch);
        let record = client
            .get_record(&company_id, &1u64, &RecordType::FinalizedBatch)
            .unwrap();

        assert_eq!(record.eligible_after, u64::MAX);
    }

    // ── Adversarial retention policy updates (issue #978) ─────────────────

    #[test]
    fn test_set_retention_override_requires_admin_auth() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 20u64;

        // Only the attacker's signature is present, never the admin's.
        let attacker = Address::generate(&env);
        env.mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_retention_override",
                args: (company_id, RecordType::FinalizedBatch, 100u64).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        assert!(client
            .try_set_retention_override(&company_id, &RecordType::FinalizedBatch, &100u64)
            .is_err());
    }

    #[test]
    fn test_set_retention_override_rejected_while_paused() {
        let (env, contract_id, admin) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let pm_id = env.register(PauseManager, ());
        let pm = PauseManagerClient::new(&env, &pm_id);
        pm.initialize(&admin);
        client.set_pause_manager(&pm_id);
        pm.pause();

        assert!(client
            .try_set_retention_override(&21u64, &RecordType::ChallengeRecord, &500u64)
            .is_err());
    }

    #[test]
    fn test_zero_override_is_a_noop_without_an_existing_override() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 22u64;
        let record_id = 1u64;

        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &0u64);
        assert_eq!(
            client.try_set_retention_override(&company_id, &RecordType::FinalizedBatch, &1u64),
            Err(Ok(RetentionError::RetentionWindowShortened))
        );
        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        env.ledger().with_mut(|l| l.timestamp += 2);
        assert!(!client.is_eligible_for_pruning(
            &company_id,
            &record_id,
            &RecordType::FinalizedBatch
        ));
    }

    #[test]
    fn test_override_is_scoped_to_company_and_record_type() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        client.set_retention_override(
            &23u64,
            &RecordType::FinalizedBatch,
            &(FINALIZED_RETENTION_SECS + 1),
        );
        client.set_retention_override(
            &24u64,
            &RecordType::FinalizedBatch,
            &(FINALIZED_RETENTION_SECS + 1_000),
        );
        client.set_retention_override(
            &23u64,
            &RecordType::CancelledBatch,
            &(FINALIZED_RETENTION_SECS + 2_000),
        );

        client.register_record(&23u64, &1u64, &RecordType::FinalizedBatch);
        client.register_record(&24u64, &2u64, &RecordType::FinalizedBatch);
        client.register_record(&23u64, &3u64, &RecordType::CancelledBatch);

        env.ledger().with_mut(|l| l.timestamp += FINALIZED_RETENTION_SECS + 2);
        assert!(client.is_eligible_for_pruning(&23u64, &1u64, &RecordType::FinalizedBatch));
        assert!(!client.is_eligible_for_pruning(&24u64, &2u64, &RecordType::FinalizedBatch));
        assert!(!client.is_eligible_for_pruning(&23u64, &3u64, &RecordType::CancelledBatch));
    }

    #[test]
    fn test_extreme_override_clamps_eligible_after() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 25u64;
        let record_id = 4u64;

        client.set_retention_override(&company_id, &RecordType::FinalizedBatch, &u64::MAX);
        env.ledger().with_mut(|l| l.timestamp = 1_000);
        client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);

        let record = client
            .get_record(&company_id, &record_id, &RecordType::FinalizedBatch)
            .unwrap();
        assert_eq!(record.eligible_after, u64::MAX);

        env.ledger().with_mut(|l| l.timestamp = u64::MAX - 1);
        assert!(!client.is_eligible_for_pruning(
            &company_id,
            &record_id,
            &RecordType::FinalizedBatch
        ));

        // At the maximum representable timestamp the clamped window ends.
        env.ledger().with_mut(|l| l.timestamp = u64::MAX);
        assert!(client.is_eligible_for_pruning(
            &company_id,
            &record_id,
            &RecordType::FinalizedBatch
        ));
    }

    #[test]
    fn test_override_does_not_change_existing_record() {
        let (env, contract_id, _) = setup();
        let client = RetentionManagerContractClient::new(&env, &contract_id);
        let company_id = 26u64;
        let record_id = 5u64;

        let before = client.register_record(&company_id, &record_id, &RecordType::FinalizedBatch);
        client.set_retention_override(
            &company_id,
            &RecordType::FinalizedBatch,
            &(FINALIZED_RETENTION_SECS + 1),
        );

        assert_eq!(
            client
                .get_record(&company_id, &record_id, &RecordType::FinalizedBatch)
                .unwrap()
                .eligible_after,
            before.eligible_after
        );
        env.ledger().with_mut(|l| l.timestamp += FINALIZED_RETENTION_SECS + 2);
        assert!(client.is_eligible_for_pruning(
            &company_id,
            &record_id,
            &RecordType::FinalizedBatch
        ));
    }
}
