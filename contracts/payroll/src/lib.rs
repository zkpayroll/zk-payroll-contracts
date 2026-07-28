#![no_std]
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
/// 1. `request_emergency_withdrawal` — called by the `treasury_owner`.
/// 2. `approve_emergency_withdrawal` — called by the `admin`.
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

// ── Issue #89: payroll amendment flow ────────────────────────────────────────

/// Lifecycle state of a payroll run draft.
///
/// Only `Pending` drafts may be amended. `Finalized` drafts are immutable
/// and serve as the canonical audit record.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RunDraftState {
    Pending = 0,
    Finalized = 1,
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

// ── Issue #91: privileged-role rotation ──────────────────────────────────────

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

// ── Storage keys ──────────────────────────────────────────────────────────────
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
//    This design is forward-compatible — new fields can be added to the stored
//    struct without changing the key structure.
//
// 5. **Persistent vs Temporary storage**: Keys map to Persistent storage unless
//    otherwise noted. Temporary storage (not used here) would require a separate
//    key namespace to avoid upgrade confusion.
//
// ## Upgrade-safe patterns
// - ✅ Adding new key variants (append-only)
// - ✅ Adding fields to structs stored under existing keys (Soroban XDR evolution)
// - ✅ Creating parallel V2 keys and migrating data over time
// - ❌ Changing the type signature of an existing key variant (breaks deserialization)
// - ❌ Reusing a key variant for a different data type (silent corruption)
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
    // Future upgrade example (issue #196):
    // PayrollRunV2(u64),  // Would be added here when schema evolution is needed
}

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
            .set(&DataKey::TreasuryOwner, &treasury_owner);
        e.storage().persistent().set(&DataKey::RunCounter, &0u64);
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
    }

    pub fn deposit(e: Env, from: Address, amount: i128, deposit_id: BytesN<32>) {
        Self::require_not_paused(&e);
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "deposit")),
            (from, amount, deposit_id),
        );
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

    pub fn get_payroll_run(e: Env, run_id: u64) -> PayrollRun {
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "meta_committed")),
            metadata_hash,
        );
    }

    /// Bound a pre-committed metadata hash to an existing payroll run.
    /// Consumes the commitment so it cannot be reused. Only the admin may call.
    ///
    /// Must be called with a metadata hash that was previously committed via
    /// `commit_metadata_hash`. Fails if the hash has not been pre-committed.
    pub fn set_run_metadata(e: Env, admin: Address, run_id: u64, metadata_hash: BytesN<32>) {
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "meta_bound")),
            (run_id, metadata_hash),
        );
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_committed")),
            draft_hash,
        );
    }

    /// Request an emergency treasury withdrawal (step 1 of 2 — issue #104).
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

        let request = EmergencyWithdrawalRequest {
            amount,
            recipient: recipient.clone(),
            requested_at: e.ledger().timestamp(),
            approved: false,
        };
        e.storage()
            .persistent()
            .set(&DataKey::EmergencyRequest, &request);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_requested")),
            (amount, recipient),
        );
    }

    /// Approve and execute a pending emergency withdrawal (step 2 of 2 — issue #104).
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

        // Clear before transfer (checks-effects-interactions).
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        token_client.transfer(&addrs.treasury, &request.recipient, &request.amount);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_approved")),
            (request.amount, request.recipient),
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_cancelled")),
            caller,
        );
    }

    /// Returns the pending emergency withdrawal request, if any.
    pub fn get_emergency_request(e: Env) -> Option<EmergencyWithdrawalRequest> {
        e.storage().persistent().get(&DataKey::EmergencyRequest)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payroll run cancellation (issue #75)
    // ─────────────────────────────────────────────────────────────────────────

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
        let count = proofs.len();

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

        addrs.admin.require_auth();

        let run_id = Self::derive_run_id(&e);

        // Mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_prepared")),
            (run_id, expected_total_spend),
        );

        run_id
    }

    /// Get a pending payroll run, if it exists.
    pub fn get_pending_run(e: Env, run_id: u64) -> Option<PendingPayrollRun> {
        e.storage().persistent().get(&DataKey::PendingRun(run_id))
    }

    /// Cancel a pending payroll run without executing any payments.
    ///
    /// Only the admin may cancel. The cancellation frees the nonce for reuse
    /// (actually, the nonce is marked as consumed, so it cannot be reused).
    /// No funds are transferred; this is a pure cleanup operation.
    ///
    /// Cancellation emits an event for audit trails. Finalized runs cannot be
    /// cancelled retroactively.
    pub fn cancel_payroll_run(e: Env, admin: Address, run_id: u64) {
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

        let pending_key = DataKey::PendingRun(run_id);
        let pending_run: PendingPayrollRun = e
            .storage()
            .persistent()
            .get(&pending_key)
            .expect("Pending run not found");

        // Remove the pending run from storage
        e.storage().persistent().remove(&pending_key);

        // Emit cancellation event
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_cancelled")),
            (run_id, pending_run.total_amount),
        );
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
        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        // #103 — reject duplicate run nonces before any other work.
        let nonce_key = DataKey::RunNonce(nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Duplicate run nonce: this payroll batch has already been submitted");
        }

        // #102 — if a draft hash is supplied, verify a pre-commitment exists.
        let resolved_draft_hash: BytesN<32> = if let Some(ref dh) = draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                panic!("Draft hash not pre-committed: call commit_draft first");
            }
            // Consume the commitment — one run per pre-committed draft.
            e.storage().persistent().remove(&commit_key);
            dh.clone()
        } else {
            BytesN::from_array(&e, &[0u8; 32])
        };

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

        // #103 — mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);
        let token_client = soroban_token::Client::new(&e, &addrs.token);

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

            // #178 — lock the employee's commitment so it cannot be silently
            // altered after payroll has been executed for this period.
            commitment_client.lock_commitment_updates(&employee);

            e.events().publish(
                (
                    symbol_short!("payroll"),
                    Symbol::new(&e, "payment_executed"),
                ),
                (employee.clone(), amount),
            );
            // topics : ("payroll", "payment_executed")
            // data   : (employee, amount)
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_executed")),
            (run_id, expected_total_spend),
        );

        run_id
    }

    // ── Issue #89: payroll amendment flow ────────────────────────────────────

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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_created")),
            (draft_id, admin, period_label),
        );

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
        let addrs: ContractAddresses = e.storage().persistent().get(&DataKey::Addresses).expect("Not initialized");
        if admin != addrs.admin { panic!("Unauthorized"); }
        admin.require_auth();
        let mut draft: PayrollRunDraft = e.storage().persistent().get(&DataKey::RunDraft(draft_id)).expect("Draft not found");
        if draft.state != RunDraftState::Pending { panic!("Only pending drafts can be amended"); }
        if new_total_amount <= 0 { panic!("total_amount must be positive"); }
        draft.total_amount=new_total_amount; draft.employee_count=new_employee_count; draft.amendment_count+=1; e.storage().persistent().set(&DataKey::RunDraft(draft_id), &draft); e.events().publish((symbol_short!("payroll"), Symbol::new(&e,"draft_amended")),(draft_id,new_total_amount,draft.amendment_count));
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

        run.reconciliation_status = status.clone();
        e.storage().persistent().set(&run_key, &run);

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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_finalized")),
            (draft_id, draft.total_amount, draft.amendment_count),
        );
    }

    /// Retrieve a payroll run draft by ID.
    pub fn get_run_draft(e: Env, draft_id: u64) -> PayrollRunDraft {
        e.storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found")
    }

    // ── Issue #91: privileged-role rotation ──────────────────────────────────

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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "admin_proposed")),
            (current_admin, new_admin),
        );
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

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "admin_rotated")),
            (old_admin, new_admin),
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

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "admin_rot_cancel"),
            ),
            current_admin,
        );
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

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treasury_proposed"),
            ),
            (current_owner, new_owner),
        );
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

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treasury_rotated"),
            ),
            (old_owner, new_owner),
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

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treas_rot_cancel"),
            ),
            current_owner,
        );
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::{Token, TokenClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use proof_verifier::{ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::Address as _;
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
            commitment_client.store_commitment(&emp, &BytesN::from_array(&env, &[0u8; 32]));
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

    // ── Issue #89: payroll amendment flow ────────────────────────────────────

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

    // ── Issue #103: per-payroll run nonce uniqueness ───────────────────────────

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

    // ── Issue #102: draft hash binding ────────────────────────────────────────

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

    // ── Issue #91: admin/treasury rotation ───────────────────────────────────

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

    // ── Issue #104: emergency withdrawal workflow ─────────────────────────────

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

    // ── Issue #134: reconciliation status tracking ─────────────────────────────

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

        // Update to Failed
        payroll_client.update_reconciliation_status(&admin, &run_id, &ReconciliationStatus::Failed);
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.reconciliation_status, ReconciliationStatus::Failed);
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

    // ── Issue #75: payroll cancellation ──────────────────────────────────────

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
        payroll_client.cancel_payroll_run(&admin, &run_id);

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
        payroll_client.cancel_payroll_run(&non_admin, &run_id);
    }

    #[test]
    #[should_panic(expected = "Pending run not found")]
    fn test_cancel_non_existent_run_fails() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        payroll_client.cancel_payroll_run(&admin, &999u64);
    }

    // ── Issue #177: payroll run metadata hash checks ──────────────────────────

    #[test]
    fn test_commit_metadata_hash_stores_commitment() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let meta_hash = BytesN::from_array(&env, &[0xaau8; 32]);
        payroll_client.commit_metadata_hash(&admin, &meta_hash);

        // Should not panic — commitment is stored.
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
            &proofs, &amounts, &employees, &1000, &test_nonce(&env, 50), &None,
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
            &proofs, &amounts, &employees, &1000, &test_nonce(&env, 51), &None,
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
            &proofs, &amounts, &employees, &1000, &test_nonce(&env, 52), &None,
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

        payroll_client.cancel_payroll_run(&admin, &run_id);
        payroll_client.cancel_payroll_run(&admin, &run_id);
    }

    #[test]
    fn test_cancel_pending_payroll_run_frees_nonce_and_cleans_state() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 45);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &None,
        );

        assert!(payroll_client.get_pending_run(&run_id).is_some());
        payroll_client.cancel_payroll_run(&admin, &run_id);

        assert!(payroll_client.get_pending_run(&run_id).is_none());
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

    // ── Issue #180: failed execution rollback tests ──────────────────────────

    #[test]
    fn test_failed_proof_mid_batch_rolls_back_nonce() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let mut employees = Vec::new(&env);
        let mut proofs = Vec::new(&env);
        let mut amounts = Vec::new(&env);

        // Employee 1 — valid proof
        let emp1 = employee;
        employees.push_back(emp1.clone());
        proofs.push_back(mock_proof(&env));
        amounts.push_back(500i128);

        // Employee 2 — will trigger proof failure (but proofs are mocked to always pass,
        // so instead we use a different employee without a commitment stored).
        let emp2 = Address::generate(&env);
        employees.push_back(emp2.clone());
        proofs.push_back(mock_proof(&env));
        amounts.push_back(500i128);

        let nonce = test_nonce(&env, 100);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &nonce,
            &None,
        );
        // Execution fails because emp2 has no stored commitment
        assert!(result.is_err());

        // Verify the nonce was rolled back — should be usable in a new run
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &emp1, 500);
        let run_id = payroll_client.batch_process_payroll(
            &proofs2, &amounts2, &employees2, &500, &nonce, &None,
        );
        assert!(run_id > 0, "Nonce must be reusable after rolled-back execution");
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

        // Mint only 100 tokens — NOT enough for the 1000 payment
        token_client.mint(&treasury, &100i128);
        payroll_client.initialize(
            &admin, &token_id, &verifier_id, &commitment_id, &treasury, &treasury_owner,
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
            &proofs, &amounts, &employees, &1000, &nonce, &Some(draft_hash.clone()),
        );
        // Must fail due to insufficient treasury balance
        assert!(result.is_err());

        // Verify nonce is reusable (rolled back)
        token_client.mint(&treasury, &10_000i128);
        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &1000, &nonce, &Some(draft_hash.clone()),
        );
        assert!(run_id > 0, "Nonce and commitment must be reusable after failed execution");
    }

    #[test]
    fn test_failed_execution_does_not_create_payroll_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        // Submit with wrong expected_total_spend to trigger failure AFTER nonce consumption
        let nonce = test_nonce(&env, 102);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);

        let result = payroll_client.try_batch_process_payroll(
            &proofs, &amounts, &employees, &999, &nonce, &None,
        );
        assert!(result.is_err());

        // Verify no payroll run record was created
        let mut any_run = false;
        for run_id in 1..5u64 {
            if payroll_client.try_get_payroll_run(&run_id).is_ok() {
                any_run = true;
                break;
            }
        }
        assert!(!any_run, "No PayrollRun should exist after a failed execution");

        // Nonce is NOT consumed (rolled back) — can retry with corrected params
        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &500, &nonce, &None,
        );
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
            &proofs, &amounts, &employees, &999, &nonce, &Some(draft_hash.clone()),
        );
        assert!(result.is_err());

        // Draft commitment should still be usable (rolled back)
        let nonce2 = test_nonce(&env, 104);
        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &500, &nonce2, &Some(draft_hash),
        );
        assert!(run_id > 0, "Draft commitment must survive a rolled-back execution");
    }

    #[test]
    fn test_failed_execution_does_not_leave_pending_state() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 105);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 500);
        let result = payroll_client.try_batch_process_payroll(
            &proofs, &amounts, &employees, &999, &nonce, &None,
        );
        assert!(result.is_err());

        // After failure, a successful run with the same nonce should work
        // (nonce was rolled back). Also verify the run gets a valid ID.
        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &500, &nonce, &None,
        );
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
        payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &500, &nonce, &None,
        );

        // Second attempt with same nonce — must fail permanently
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 500);
        payroll_client.batch_process_payroll(
            &proofs2, &amounts2, &employees2, &500, &nonce, &None,
        );
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
        let run_id = payroll_client.prepare_payroll_run(
            &proofs, &amounts, &employees, &500, &nonce, &None,
        );
        assert!(run_id > 0);

        // Failed cancel (wrong caller) should not affect the pending run
        let attacker = Address::generate(&env);
        let cancel_result = payroll_client.try_cancel_payroll_run(&attacker, &run_id);
        assert!(cancel_result.is_err());

        // Pending run should still exist
        let pending = payroll_client.get_pending_run(&run_id);
        assert!(pending.is_some(), "Pending run must survive unauthorized cancel attempt");
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
        amounts.push_back(500i128); // 2 amounts — mismatch!
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        let result = payroll_client.try_batch_process_payroll(
            &proofs, &amounts, &employees, &1000, &nonce, &None,
        );
        assert!(result.is_err());

        // Nonce should still be usable after rollback
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 500);
        let run_id = payroll_client.batch_process_payroll(
            &proofs2, &amounts2, &employees2, &500, &nonce, &None,
        );
        assert!(run_id > 0, "Nonce must be reusable after array mismatch rollback");
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

    // ── Issue #191: deposit replay protection ────────────────────────────────

    #[test]
    fn test_deposit_with_unique_id_succeeds() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let deposit_id = BytesN::from_array(&env, &[1u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
    }

    #[test]
    #[should_panic(expected = "Deposit already processed")]
    fn test_deposit_replay_with_same_id_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let deposit_id = BytesN::from_array(&env, &[2u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
        payroll_client.deposit(&treasury, &500i128, &deposit_id);
    }

    #[test]
    fn test_deposit_distinct_ids_both_succeed() {
        let env = Env::default();
        let (payroll_client, _admin, treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id1 = BytesN::from_array(&env, &[3u8; 32]);
        let id2 = BytesN::from_array(&env, &[4u8; 32]);
        payroll_client.deposit(&treasury, &500i128, &id1);
        payroll_client.deposit(&treasury, &500i128, &id2);
    }

    // ── Issue #194: amount boundary validations ──────────────────────────────

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
            &proofs, &amounts, &employees, &0, &test_nonce(&env, 200), &None,
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
            &proofs, &amounts, &employees, &-1, &test_nonce(&env, 201), &None,
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
            &proofs, &amounts, &employees, &0, &test_nonce(&env, 202), &None,
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
            &proofs, &amounts, &employees, &-1, &test_nonce(&env, 203), &None,
        );
    }

    // ── Issue #196: Storage key versioning strategy tests ────────────────────

    #[test]
    fn test_storage_keys_are_namespaced() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &1000, &test_nonce(&env, 210), &None,
        );

        let draft_id = payroll_client.create_run_draft(
            &admin,
            &5_000i128,
            &10u32,
            &Symbol::new(&env, "Q1"),
        );

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
            &proofs, &amounts, &employees, &1000, &test_nonce(&env, 211), &None,
        );

        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.run_id, run_id);
        assert_eq!(run.total_amount, 1000);
        assert_eq!(run.employee_count, 1);
    }

    // ── Issue #203: Settlement completion guard tests ────────────────────────

    #[test]
    fn test_finalize_run_draft_is_idempotent() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id = payroll_client.create_run_draft(
            &admin,
            &8_000i128,
            &15u32,
            &Symbol::new(&env, "MAR"),
        );

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

        let run_id = payroll_client.batch_process_payroll(
            &proofs, &amounts, &employees, &1000, &nonce, &None,
        );
        assert!(run_id > 0);

        let result = payroll_client.try_batch_process_payroll(
            &proofs, &amounts, &employees, &1000, &nonce, &None,
        );
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

        payroll_client.cancel_payroll_run(&admin, &run_id);

        let result = payroll_client.try_cancel_payroll_run(&admin, &run_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_settlement_completion_guard_via_draft_state() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let draft_id = payroll_client.create_run_draft(
            &admin,
            &10_000i128,
            &20u32,
            &Symbol::new(&env, "Q4"),
        );

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
}
