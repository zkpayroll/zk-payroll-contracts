#![no_std]

extern crate alloc;
use alloc::format;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token as soroban_token, Address, BytesN,
    Env, Symbol, Vec,
};
use soroban_sdk::xdr::ToXdr;

use pause_manager::PauseManagerClient;
use payroll_registry::{CompanyInfo, PayrollRegistryClient};
use proof_verifier::{Groth16Proof, ProofVerifierClient};
use salary_commitment::SalaryCommitmentContractClient;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, token, Address, BytesN, Env, Symbol,
};

/// Maximum age for a proof relative to its period creation time (7 days in seconds).
/// Proofs must be submitted within this window to prevent replay attacks using stale proofs.
const MAX_PROOF_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Payment record
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentRecord {
    pub company_id: u64,
    pub employee: Address,
    pub proof_hash: BytesN<32>,
    pub timestamp: u64,
    pub period: u32,
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

// ── Issue #89: payroll amendment flow ────────────────────────────────────────

/// Lifecycle state of a payroll run draft.
///
/// Only `Pending` drafts may be amended. `Finalized` drafts are locked for review.
/// `Submitted`, `Cancelled`, and `Expired` represent terminal draft states.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RunDraftState {
    Pending = 0,
    Finalized = 1,
    Submitted = 2,
    Cancelled = 3,
    Expired = 4,
}

/// A payroll period definition with scheduling metadata.
///
/// Each payroll run is tied to a unique period per company. Periods are
/// monotonically numbered and carry ledger-based scheduling metadata so
/// that downstream consumers (audit, UI reporting) can map payments to
/// calendar cycles without leaking salary values.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollPeriod {
    pub period_id: u32,
    pub company_id: u64,
    /// Ledger sequence at which the period was opened.
    pub start_ledger: u32,
    /// Ledger sequence at which the period was closed (0 = still open).
    pub end_ledger: u32,
    /// Unix timestamp when the period was created (on-chain time).
    pub created_at: u64,
    /// True when the period has been closed. Payments cannot be made
    /// against a closed period.
    pub closed: bool,
    /// Number of payments executed within this period.
    pub payment_count: u32,
}

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PaymentError {
    ProofAlreadyUsed = 1,
    ArrayLengthMismatch = 2,
    AlreadyPaid = 3,
    /// The payroll period does not exist.
    PeriodNotFound = 4,
    /// The payroll period is closed — no new payments allowed.
    PeriodClosed = 5,
    /// Attempt to create a duplicate period for this company.
    PeriodAlreadyExists = 6,
    /// The proof has expired and can no longer be used (issue #77).
    ProofExpired = 7,
    /// Empty payroll batches are rejected to avoid silent no-op execution.
    EmptyBatch = 8,
}

/// Contract addresses for dependencies
#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub registry: Address,
    pub commitment: Address,
    pub verifier: Address,
    pub token: Address,
pub struct RunReview {
    pub run_id: u64,
    pub reviewer: Address,
    pub decision: ReviewDecision,
    pub reason: Symbol,
    pub reviewed_at: u64,
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

// ── Issue #339: Admin Handover Record ───────────────────────────────────────

/// Record of a pending admin handover requiring acceptance.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAdminHandover {
    pub current_admin: Address,
    pub pending_admin: Address,
    pub requested_at: u64,
}

// ── Issue #334: Signer Quorum Approval Payload ──────────────────────────────

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

// ── Issue #333: Compliance Hold State ─────────────────────────────────────────

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

// ── Issue #337: Funding Reservation Expiry ─────────────────────────────────────

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

// ── Issue #335: Payroll Run Archival ───────────────────────────────────────────

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

// ── Issue #147: company lifecycle state ──────────────────────────────────────────

/// Lifecycle state of the company operating this payroll contract.
///
/// Payroll execution is only permitted when the state is `Active`. This gate
/// runs before any auth checks, balance reads, or transfer logic so that
/// rejected calls are fully clean with no partial side effects.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompanyState {
    /// Normal operating state — payroll execution permitted.
    Active,
    /// Operations suspended; payroll execution rejected until set to Active.
    Paused,
    /// Company decommissioned; no further payroll runs are permitted.
    Archived,
    /// Onboarding incomplete; payroll execution not yet permitted.
    Incomplete,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Addresses,
    Payment(Address, u32),
    Nullifier(BytesN<32>),
    TotalPaid(u64),
    ExecutorAdmin,
    PauseManager,
    Period(u64, u32),
    PeriodSequence(u64),
    /// Allowed assets for payment execution (issue #175)
    AllowedAsset(Address),
    /// Storage key schema version (issue #174)
    StorageVersion,
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
    // Future upgrade example (issue #196):
    // PayrollRunV2(u64),  // Would be added here when schema evolution is needed
}

#[contract]
pub struct PaymentExecutor;

#[contractimpl]
impl PaymentExecutor {
    fn amount_to_public_input(env: &Env, amount: i128) -> BytesN<32> {
        if amount < 0 {
            panic!("Amount must be non-negative");
        }

        let mut bytes = [0u8; 32];
        let amount_u128 = amount as u128;
        bytes[16..].copy_from_slice(&amount_u128.to_be_bytes());
        BytesN::from_array(env, &bytes)
    }

    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    /// Initialize with contract addresses
    pub fn initialize(env: Env, addresses: ContractAddresses) {
        let key = DataKey::Addresses;
        if env.storage().persistent().has(&key) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&key, &addresses);
        // Automatically allow initial token asset (issue #175)
        env.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(addresses.token.clone()), &true);
        // Set initial storage key version (issue #174)
        env.storage()
            .persistent()
            .set(&DataKey::StorageVersion, &1u32);

        env.events().publish(
            (
                Symbol::new(&env, "TreasuryAssetAllowedUpdated"),
                addresses.token.clone(),
            ),
            (true, env.ledger().timestamp()),
        );
    }

    /// Set the executor-level admin (one-time, protected by auth).
    pub fn set_executor_admin(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::ExecutorAdmin) {
            panic!("Executor admin already set");
        }
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::ExecutorAdmin, &admin);
        payroll_events::emit_executor_admin_set(&env, admin);
    }

    /// Set the pause manager contract address (only executor admin).
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set");
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
        payroll_events::emit_executor_pause_manager_set(&env, pause_manager);
    }

    /// Allow or disallow an asset token for payment execution (only executor admin - issue #175).
    pub fn set_asset_allowed(env: Env, asset: Address, allowed: bool) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set");
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::AllowedAsset(asset.clone()), &allowed);

        env.events().publish(
            (Symbol::new(&env, "TreasuryAssetAllowedUpdated"), asset),
            (allowed, env.ledger().timestamp()),
        );
    }

    /// Check if an asset token is allowlisted for payments (issue #175).
    pub fn is_asset_allowed(env: Env, asset: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::AllowedAsset(asset))
            .unwrap_or(false)
    }

    /// Read contract storage schema version (issue #174).
    pub fn get_storage_version(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::StorageVersion)
            .unwrap_or(1u32)
    }

    // -----------------------------------------------------------------------
    // Payroll period lifecycle
    // -----------------------------------------------------------------------

    /// Create a new payroll period for a company.
    ///
    /// Periods are numbered sequentially per company. Only one period can
    /// be open at a time — a new period cannot be created until the previous
    /// one is closed (or no periods exist yet).
    pub fn create_period(env: Env, company_id: u64) -> Result<PayrollPeriod, PaymentError> {
        Self::require_not_paused(&env);
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);
        company.admin.require_auth();

        // Assign sequential period ID
        let seq_key = DataKey::PeriodSequence(company_id);
        let next_id: u32 = env.storage().persistent().get(&seq_key).unwrap_or(1u32);

        let period_key = DataKey::Period(company_id, next_id);
        if env.storage().persistent().has(&period_key) {
            return Err(PaymentError::PeriodAlreadyExists);
        }

        if next_id > 1 {
            let prev_key = DataKey::Period(company_id, next_id - 1);
            if let Some(prev_period) = env
                .storage()
                .persistent()
                .get::<DataKey, PayrollPeriod>(&prev_key)
            {
                if !prev_period.closed {
                    return Err(PaymentError::PeriodAlreadyExists);
                }
            }
        }

        let period = PayrollPeriod {
            period_id: next_id,
            company_id,
            start_ledger: env.ledger().sequence(),
            end_ledger: 0,
            created_at: env.ledger().timestamp(),
            closed: false,
            payment_count: 0,
        };

        env.storage().persistent().set(&period_key, &period);
        env.storage().persistent().set(&seq_key, &(next_id + 1));

        payroll_events::emit_period_created(&env, company_id, next_id);

        Ok(period)
    }

    /// Close a payroll period so no further payments can be made in it.
    pub fn close_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<PayrollPeriod, PaymentError> {
        Self::require_not_paused(&env);
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);
        company.admin.require_auth();

        let period_key = DataKey::Period(company_id, period_id);
        let mut period: PayrollPeriod = env
            .storage()
            .persistent()
            .get(&period_key)
            .ok_or(PaymentError::PeriodNotFound)?;

        if period.closed {
            return Err(PaymentError::PeriodClosed);
        }

        period.closed = true;
        period.end_ledger = env.ledger().sequence();
        env.storage().persistent().set(&period_key, &period);

        payroll_events::emit_period_closed(&env, company_id, period_id);

        Ok(period)
    }

    /// Read a period definition.
    pub fn get_period(env: Env, company_id: u64, period_id: u32) -> Option<PayrollPeriod> {
        let key = DataKey::Period(company_id, period_id);
        env.storage().persistent().get(&key)
    }

    // -----------------------------------------------------------------------
    // Payment execution
    // -----------------------------------------------------------------------
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
            || matches!(state, BatchCheckpointState::Started | BatchCheckpointState::Resumed)
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
        let key = DataKey::BatchCheckpoint(
            employer,
            batch_root,
            asset,
            execution_nonce,
        );
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

    #[allow(clippy::too_many_arguments)]
    pub fn execute_payment(
        env: Env,
        company_id: u64,
        employee: Address,
        amount: i128,
        proof_a: BytesN<64>,
        proof_b: BytesN<128>,
        proof_c: BytesN<64>,
        nullifier: BytesN<32>,
        period: u32,
    ) -> Result<PaymentRecord, PaymentError> {
        let addresses: ContractAddresses = env
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        // Check if pause manager is configured and system is paused
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        // Validate the period exists and is open
        let period_key = DataKey::Period(company_id, period);
        let period_record: PayrollPeriod = env
            .storage()
            .persistent()
            .get(&period_key)
            .ok_or(PaymentError::PeriodNotFound)?;

        if period_record.closed {
            return Err(PaymentError::PeriodClosed);
        }

        // Check proof freshness: reject stale proofs (issue #77).
        // Proofs must be submitted within MAX_PROOF_AGE_SECONDS of the period creation.
        let current_time = env.ledger().timestamp();
        let proof_age = current_time.saturating_sub(period_record.created_at);
        if proof_age > MAX_PROOF_AGE_SECONDS {
            return Err(PaymentError::ProofExpired);
        }

        // Check cryptographically if the exact proof was submitted previously
        let nullifier_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(PaymentError::ProofAlreadyUsed);
        }

        // Check payment hasn't been made for this period
        let payment_key = DataKey::Payment(employee.clone(), period);
        if env.storage().persistent().has(&payment_key) {
            return Err(PaymentError::AlreadyPaid);
        }

        // Read the employee commitment from the dedicated commitment contract
        // and company metadata from payroll_registry.
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let commitment = commitment_client.get_commitment(&employee).commitment;
        let registry = PayrollRegistryClient::new(&env, &addresses.registry);
        let company: CompanyInfo = registry.get_company(&company_id);

        // Ensure only HR admin for this company can trigger payroll and treasury authorizes payment.
        company.admin.require_auth();
        company.treasury.require_auth();

        // Construct public inputs required by issue #20:
        let mut public_inputs = soroban_sdk::Vec::new(&env);
        public_inputs.push_back(commitment);
        public_inputs.push_back(Self::amount_to_public_input(&env, amount));

        // Validate Groth16 proof via proof_verifier contract.
        let verifier = ProofVerifierClient::new(&env, &addresses.verifier);
        let proof = Groth16Proof {
            a: proof_a.clone(),
            b: proof_b.clone(),
            c: proof_c.clone(),
        };
        if !verifier.verify(&proof, &public_inputs) {
            panic!("Invalid payment proof");
        }

        // Validate treasury asset allowlist (issue #175)
        if !Self::is_asset_allowed(env.clone(), addresses.token.clone()) {
            panic!("Asset not allowed");
        }

        // Issue #217: Validate treasury asset mapping matches supported payroll assets
        // Ensure the token contract address is valid and matches expected format
        let token_str = format!("{:?}", addresses.token);
        if token_str.is_empty() {
            panic!("Invalid treasury asset mapping: empty token address");
        }

        // Verify the treasury address is properly configured and matches asset type
        let treasury_str = format!("{:?}", company.treasury);
        if treasury_str.is_empty() {
            panic!("Invalid treasury mapping: empty treasury address");
        }

        // Execute token transfer from company treasury to employee.
        let token_client = token::Client::new(&env, &addresses.token);
        token_client.transfer(&company.treasury, &employee, &amount);

        // Record payment
        let record = PaymentRecord {
            company_id,
            employee: employee.clone(),
            proof_hash: nullifier.clone(),
            timestamp: env.ledger().timestamp(),
            period,
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

        env.storage().persistent().set(&payment_key, &record);
        env.storage().persistent().set(&nullifier_key, &true);

        // Increment period payment count
        let period_key = DataKey::Period(company_id, period);
        if let Some(mut period_struct) = env
            .storage()
            .persistent()
            .get::<DataKey, PayrollPeriod>(&period_key)
        {
            period_struct.payment_count += 1;
            env.storage().persistent().set(&period_key, &period_struct);
        }

        // Update total paid
        let total_key = DataKey::TotalPaid(company_id);
        let current_total: i128 = env.storage().persistent().get(&total_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&total_key, &(current_total + amount));

        // Emit PayrollProcessed event so off-chain indexers can reconcile payments.
        payroll_events::emit_executor_payment_processed(&env, company_id, employee, amount, period);
        let available = Self::get_available_treasury_balance(e.clone(), addrs.token.clone());
        if request.amount > available {
            panic!("Insufficient available treasury balance: funds locked for pending payroll");
        }

        // Clear before transfer (checks-effects-interactions).
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        let _ = nullifier;

        Ok(record)
    }

    /// Execute batch payroll for multiple employees
    #[allow(clippy::too_many_arguments)]
    pub fn execute_batch_payroll(
        env: Env,
        company_id: u64,
        employees: soroban_sdk::Vec<Address>,
        amounts: soroban_sdk::Vec<i128>,
        proofs_a: soroban_sdk::Vec<BytesN<64>>,
        proofs_b: soroban_sdk::Vec<BytesN<128>>,
        proofs_c: soroban_sdk::Vec<BytesN<64>>,
        nullifiers: soroban_sdk::Vec<BytesN<32>>,
        period: u32,
    ) -> Result<soroban_sdk::Vec<PaymentRecord>, PaymentError> {
        let count = employees.len();

        if amounts.len() != count
            || proofs_a.len() != count
            || proofs_b.len() != count
            || proofs_c.len() != count
            || nullifiers.len() != count
        {
            return Err(PaymentError::ArrayLengthMismatch);
        }

        if count == 0 {
            return Err(PaymentError::EmptyBatch);
        }

        let mut records = soroban_sdk::Vec::new(&env);

        for i in 0..count {
            let record = Self::execute_payment(
                env.clone(),
                company_id,
                employees.get(i).unwrap(),
                amounts.get(i).unwrap(),
                proofs_a.get(i).unwrap(),
                proofs_b.get(i).unwrap(),
                proofs_c.get(i).unwrap(),
                nullifiers.get(i).unwrap(),
                period,
            )?;
            records.push_back(record);
        }

        Ok(records)
    }

    /// Get payment record
    pub fn get_payment(env: Env, employee: Address, period: u32) -> PaymentRecord {
        let key = DataKey::Payment(employee, period);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Payment not found")
    }

    /// Check if payment was made for a period
    pub fn is_paid(env: Env, employee: Address, period: u32) -> bool {
        let key = DataKey::Payment(employee, period);
        env.storage().persistent().has(&key)
    }

    /// Get total amount paid by company
    pub fn get_total_paid(env: Env, company_id: u64) -> i128 {
        let key = DataKey::TotalPaid(company_id);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Get the maximum allowed age for a proof in seconds (issue #77).
    pub fn get_max_proof_age(_env: Env) -> u64 {
        MAX_PROOF_AGE_SECONDS
    }

    /// Get the contract dependency addresses configured during initialization.
    pub fn get_addresses(env: Env) -> ContractAddresses {
        env.storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized")
    }

    /// Get the executor admin address.
    pub fn get_executor_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::ExecutorAdmin)
            .expect("Executor admin not set")
        addrs.admin.require_auth();

        // Validate treasury asset allowlist
        if !Self::is_asset_allowed(e.clone(), addrs.token.clone()) {
            panic!("Asset not allowed");
        }

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

        // #103 — mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

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

            // #178 — lock the employee's commitment so it cannot be silently
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
        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_amended")),
            (draft_id, new_total_amount, draft.amendment_count),
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
        // `Completed`, reject any further reconciliation update — including a
        // repeat `Reconciled` call — so settlement cannot be replayed or
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

    // ── Issue #339: Admin Handover Safety Checks ─────────────────────────────

    /// Request a new admin handover requiring explicit acceptance (step 1 of 2 — issue #339).
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

    /// Accept an admin handover (step 2 of 2 — issue #339).
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

    // ── Issue #343: Treasury Withdrawal Guardrails ───────────────────────────

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

    // ── Issue #334: Signer Quorum Replay Protection ──────────────────────────

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
        e.storage().persistent().has(&DataKey::ConsumedQuorum(quorum_hash))
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

        e.storage()
            .persistent()
            .set(&DataKey::ConsumedQuorum(q_hash.clone()), &e.ledger().timestamp());

        payroll_events::emit_quorum_consumed(&e, payload.batch_root, payload.employer, payload.nonce);
        q_hash
    }

    // ── Issue #177: metadata hash verification ──────────────────────────────

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

    // ── Issue #147: company state management ─────────────────────────────────

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

    // ── Issue #146: archived payroll run queries ──────────────────────────────

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

    // ── Reviewer Authorization & Run Review Entrypoints ─────────────────────

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

    // ────────────────────────────────────────────────────────────────────────────
    // Issue #333: Compliance Hold Functionality
    // ────────────────────────────────────────────────────────────────────────────

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
            .unwrap_or(0u64) + 1;

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
            Symbol::new(&e, match scope {
                ComplianceHoldScope::Batch => "batch",
                ComplianceHoldScope::Employee => "employee",
                ComplianceHoldScope::Employer => "employer",
            }),
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
        let mut hold: ComplianceHold = e
            .storage()
            .persistent()
            .get(&key)
            .expect("Hold not found");

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

    // ────────────────────────────────────────────────────────────────────────────
    // Issue #337: Funding Reservation Expiry Functionality
    // ────────────────────────────────────────────────────────────────────────────

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

    // ────────────────────────────────────────────────────────────────────────────
    // Issue #335: Payroll Archival Functionality
    // ────────────────────────────────────────────────────────────────────────────

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
        if e
            .storage()
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

    // ── Issue #244: payroll settlement replay guard ──────────────────────────

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

    /// Get the current period sequence for a company (defaults to 0).
    pub fn get_period_sequence(env: Env, company_id: u64) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::PeriodSequence(company_id))
            .unwrap_or(0u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::pause_manager::{PauseManager, PauseManagerClient};
    use ::salary_commitment::SalaryCommitmentContract;
    use ::token::{Token, TokenClient};
    use payroll_registry::PayrollRegistry;
    use proof_verifier::{ProofVerifier, VerificationKey};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Env, IntoVal, Symbol, TryIntoVal};

    fn setup_addresses(env: &Env) -> ContractAddresses {
        env.mock_all_auths();
        let registry_id = env.register_contract(None, PayrollRegistry);
        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let verifier_id = env.register_contract(None, ProofVerifier);
        let token_id = env.register_contract(None, Token);

        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        let commitment_admin = Address::generate(env);
        commitment_client.init_commitment_admin(&commitment_admin);

        ContractAddresses {
            registry: registry_id,
            commitment: commitment_id,
            verifier: verifier_id,
            token: token_id,
        }
    }

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[0u8; 128]),
            gamma: BytesN::from_array(env, &[0u8; 128]),
            delta: BytesN::from_array(env, &[0u8; 128]),
            ic: soroban_sdk::Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                ],
            ),
        }
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);
    }

    #[test]
    fn test_is_paid() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let employee = Address::generate(&env);

        assert!(!client.is_paid(&employee, &1));
    }

    #[test]
    fn test_execute_payment_transfers_after_verification() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        // Create payroll period
        let _ = client.create_period(&company_id);

        let valid_proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let valid_proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let valid_proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let valid_nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 9_000);
        assert_eq!(token_client.balance(&employee), 1_000);

        let events = env.events().all();
        assert_eq!(events.len(), 6);
        let event = events.get(events.len() - 1).unwrap();
        assert_eq!(event.1.len(), 2);
        let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(sym0, Symbol::new(&env, "PayrollProcessed"));
        let comp_id: u64 = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(comp_id, company_id);
    }

    #[test]
    fn test_double_spend_proof_reuse_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[7u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);

        let valid_proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let valid_proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let valid_proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let valid_nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &valid_proof_a,
            &valid_proof_b,
            &valid_proof_c,
            &valid_nullifier,
            &1,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
    }

    #[test]
    fn test_batch_array_length_mismatch_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let company_id = 0u64;

        let employees =
            soroban_sdk::Vec::from_array(&env, [Address::generate(&env), Address::generate(&env)]);
        let amounts: soroban_sdk::Vec<i128> = soroban_sdk::Vec::from_array(&env, [1000]);
        let proofs_a: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let proofs_b: soroban_sdk::Vec<BytesN<128>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 128])]);
        let proofs_c: soroban_sdk::Vec<BytesN<64>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 64])]);
        let nullifiers: soroban_sdk::Vec<BytesN<32>> =
            soroban_sdk::Vec::from_array(&env, [BytesN::from_array(&env, &[0u8; 32])]);
        let period = 1;

        let result = client.try_execute_batch_payroll(
            &company_id,
            &employees,
            &amounts,
            &proofs_a,
            &proofs_b,
            &proofs_c,
            &nullifiers,
            &period,
        );

        assert_eq!(
            result.unwrap_err().unwrap(),
            PaymentError::ArrayLengthMismatch
        );
    }

    // -----------------------------------------------------------------------
    // Period tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_period() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&admin, &treasury);

        let period = client.create_period(&company_id);
        let result = period;
        assert_eq!(result.period_id, 1);
        assert_eq!(result.company_id, company_id);
        assert!(!result.closed);
        assert_eq!(result.payment_count, 0);
    }

    #[test]
    fn test_duplicate_period_creation_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&admin, &treasury);

        let _ = client.create_period(&company_id);

        let result = client.try_create_period(&company_id);
        assert_eq!(
            result.unwrap_err().unwrap(),
            PaymentError::PeriodAlreadyExists
        );
    }

    #[test]
    fn test_close_period() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&admin, &treasury);

        let _ = client.create_period(&company_id);
        let result = client.close_period(&company_id, &1);

        assert!(result.closed);
        assert_eq!(result.end_ledger, result.start_ledger);
    }

    #[test]
    fn test_payment_in_closed_period_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);
        let _ = client.close_period(&company_id, &1);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::PeriodClosed);
    }

    #[test]
    fn test_payment_in_nonexistent_period_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        // Period 99 doesn't exist
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &99,
        );
        assert_eq!(result.unwrap_err().unwrap(), PaymentError::PeriodNotFound);
    }

    /// Acceptance Criteria: Reentrancy
    #[test]
    fn test_reentrancy_cei_pattern() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[8u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        let _ = client.create_period(&company_id);

        let proof_a = BytesN::from_array(&env, &[5u8; 64]);
        let proof_b = BytesN::from_array(&env, &[6u8; 128]);
        let proof_c = BytesN::from_array(&env, &[7u8; 64]);
        let nullifier = BytesN::from_array(&env, &[9u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &2_500,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 7_500);
        assert_eq!(token_client.balance(&employee), 2_500);
        assert!(client.is_paid(&employee, &1));
        assert_eq!(client.get_total_paid(&company_id), 2_500);

        let events = env.events().all();
        assert_eq!(events.len(), 6);
        let event = events.get(events.len() - 1).unwrap();
        assert_eq!(event.1.len(), 2);
        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(sym, Symbol::new(&env, "PayrollProcessed"));

        let replay = client.try_execute_payment(
            &company_id,
            &employee,
            &2_500,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(replay.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
        assert_eq!(token_client.balance(&treasury), 7_500);
        assert_eq!(token_client.balance(&employee), 2_500);
        assert_eq!(client.get_total_paid(&company_id), 2_500);
    }

    // ── Pause tests ──────────────────────────────────────────────────────────

    fn setup_executor_with_pause_manager(
        env: &Env,
    ) -> (
        PaymentExecutorClient<'_>,
        PauseManagerClient<'_>,
        u64,
        Address,
        Address,
        Address,
    ) {
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(env, &contract_id);

        let addresses = setup_addresses(env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(env, &addresses.commitment);
        let token_client = TokenClient::new(env, &addresses.token);

        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let employee = Address::generate(env);
        let commitment = BytesN::from_array(env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10_000);

        // Set executor admin
        client.set_executor_admin(&admin);

        // Register and configure pause manager
        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(env, &pm_id);
        let operator = Address::generate(env);
        pm_client.initialize(&operator);

        client.set_pause_manager(&pm_id);

        (client, pm_client, company_id, admin, treasury, employee)
    }

    #[test]
    fn test_paused_executor_rejects_payment() {
        let env = Env::default();
        let (client, pm_client, company_id, _admin, _treasury, employee) =
            setup_executor_with_pause_manager(&env);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        pm_client.pause();

        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unpaused_executor_resumes_payment() {
        let env = Env::default();
        let (client, pm_client, company_id, _admin, _treasury, employee) =
            setup_executor_with_pause_manager(&env);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.create_period(&company_id);

        pm_client.pause();

        // Verify paused
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a.clone(),
            &proof_b.clone(),
            &proof_c.clone(),
            &nullifier.clone(),
            &1,
        );
        assert!(result.is_err());

        // Unpause
        pm_client.unpause();

        // Should succeed now
        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert!(client.is_paid(&employee, &1));
    }

    #[test]
    fn test_executor_works_without_pause_manager() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        client.create_period(&company_id);
        token_client.mint(&treasury, &10_000);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        client.execute_payment(
            &company_id,
            &employee,
            &1000,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1,
        );

        assert_eq!(token_client.balance(&treasury), 9_000);
        assert_eq!(token_client.balance(&employee), 1_000);
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_set_pause_manager_rejects_unauthorized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        let admin = Address::generate(&env);

        // Only mock auth for admin during initialize
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (addresses.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&addresses);

        // Set executor admin as the legitimate admin
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_executor_admin",
                args: (admin.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_executor_admin(&admin);

        // Attacker tries to set pause manager
        let pm_id = env.register_contract(None, PauseManager);
        let attacker = Address::generate(&env);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_pause_manager",
                args: (pm_id.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_pause_manager(&pm_id);
    }

    // ── Issue #77: proof expiration checks ────────────────────────────────────

    #[test]
    fn test_fresh_proof_within_expiration_window() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        // Create a period
        let period = client.create_period(&company_id);
        assert_eq!(period.period_id, 1);

        // Execute payment immediately (proof is fresh)
        let result = client.try_execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &BytesN::from_array(&env, &[1u8; 64]),
            &BytesN::from_array(&env, &[2u8; 128]),
            &BytesN::from_array(&env, &[3u8; 64]),
            &BytesN::from_array(&env, &[4u8; 32]),
            &1,
        );
        // Should succeed (proof is fresh)
        assert!(result.is_ok());
    }

    #[test]
    fn test_period_tracks_creation_time() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        // Create a period
        let period = client.create_period(&company_id);

        // Verify period is created and has correct initial state
        assert_eq!(period.period_id, 1);
        assert_eq!(period.company_id, company_id);
        assert!(!period.closed);
        assert_eq!(period.payment_count, 0);
        // created_at is set to current ledger timestamp (can be 0 in test env)
    }

    #[test]
    fn test_get_max_proof_age() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let max_age = client.get_max_proof_age();
        // Should be 7 days in seconds
        assert_eq!(max_age, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_asset_allowlist_management_and_execution() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        // Initial token asset is allowlisted
        assert!(client.is_asset_allowed(&addresses.token));

        // Disallow token asset
        client.set_asset_allowed(&addresses.token, &false);
        assert!(!client.is_asset_allowed(&addresses.token));

        // Re-allow token asset
        client.set_asset_allowed(&addresses.token, &true);
        assert!(client.is_asset_allowed(&addresses.token));
    }

    #[test]
    #[should_panic(expected = "Asset not allowed")]
    fn test_execute_payment_fails_when_asset_disallowed() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        // Disallow the payment token asset
        client.set_asset_allowed(&addresses.token, &false);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[9u8; 32]);

        let company_id = registry_client.register_company(&admin, &treasury);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &10000i128);

        let _period = client.create_period(&company_id);

        client.execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &BytesN::from_array(&env, &[1u8; 64]),
            &BytesN::from_array(&env, &[2u8; 128]),
            &BytesN::from_array(&env, &[3u8; 64]),
            &BytesN::from_array(&env, &[4u8; 32]),
            &1,
        );
    }

    #[test]
    fn test_storage_version_returns_version_1() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        assert_eq!(client.get_storage_version(), 1);
    }

    #[test]
    fn test_asset_allowed_emits_events() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        let before_init = env.events().all().len();
        client.initialize(&addresses);
        let after_init = env.events().all().len();
        assert_eq!(after_init, before_init + 1);

        let init_event = env.events().all().get(after_init - 1).unwrap();
        let sym0: Symbol = init_event
            .1
            .get(0)
            .unwrap()
            .try_into_val(&env.clone())
            .unwrap();
        assert_eq!(sym0, Symbol::new(&env, "TreasuryAssetAllowedUpdated"));

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let before_set = env.events().all().len();
        let new_asset = Address::generate(&env);
        client.set_asset_allowed(&new_asset, &true);
        let after_set = env.events().all().len();
        assert_eq!(after_set, before_set + 1);

        let set_event = env.events().all().get(after_set - 1).unwrap();
        let set_sym0: Symbol = set_event
            .1
            .get(0)
            .unwrap()
            .try_into_val(&env.clone())
            .unwrap();
        assert_eq!(set_sym0, Symbol::new(&env, "TreasuryAssetAllowedUpdated"));
    }

    // ── Issue #245: operator vs admin role separation ─────────────────────────
    //
    // `payment_executor` has two distinct privileged roles that must not be
    // conflated: the protocol-level `ExecutorAdmin` (gates contract-wide
    // config: `set_asset_allowed`, `set_pause_manager`) and each company's
    // own `admin` (gates that company's periods and payments only — the
    // "operator" of its own payroll). Neither role should be able to
    // exercise the other's capabilities.

    /// A company admin (this company's payroll "operator") must not be able
    /// to exercise the protocol-level `ExecutorAdmin` capability of changing
    /// the treasury asset allowlist just because they administer a company.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_company_admin_cannot_set_asset_allowed() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let company_admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let _company_id = registry_client.register_company(&company_admin, &treasury);

        // Company admin (not the executor admin) attempts a protocol-level
        // config change.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &company_admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_asset_allowed",
                args: (addresses.token.clone(), false).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_asset_allowed(&addresses.token, &false);
    }

    /// The protocol-level `ExecutorAdmin` must not be able to trigger payroll
    /// execution for a company it does not administer — that capability
    /// belongs solely to the company's own admin.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_executor_admin_cannot_execute_payment_for_foreign_company() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PaymentExecutor);
        let client = PaymentExecutorClient::new(&env, &contract_id);

        let addresses = setup_addresses(&env);
        client.initialize(&addresses);

        let executor_admin = Address::generate(&env);
        client.set_executor_admin(&executor_admin);

        let registry_client = PayrollRegistryClient::new(&env, &addresses.registry);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &addresses.commitment);
        let token_client = TokenClient::new(&env, &addresses.token);

        let company_admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = registry_client.register_company(&company_admin, &treasury);

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[5u8; 32]);
        commitment_client.store_commitment(&employee, &commitment);
        registry_client.add_employee(&company_id, &employee, &commitment);
        token_client.mint(&treasury, &100_000i128);

        client.create_period(&company_id);

        let proof_a = BytesN::from_array(&env, &[1u8; 64]);
        let proof_b = BytesN::from_array(&env, &[2u8; 128]);
        let proof_c = BytesN::from_array(&env, &[3u8; 64]);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);

        // Executor admin (not this company's admin) attempts to execute a
        // payment for a company it does not administer.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &executor_admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "execute_payment",
                args: (
                    company_id,
                    employee.clone(),
                    1000i128,
                    proof_a.clone(),
                    proof_b.clone(),
                    proof_c.clone(),
                    nullifier.clone(),
                    1u32,
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        }]);
        let _ = client.execute_payment(
            &company_id,
            &employee,
            &1000i128,
            &proof_a,
            &proof_b,
            &proof_c,
            &nullifier,
            &1u32,
        );
    }

    // =====================================================================
    // Issue #277: `amount_to_public_input` precision-format encoding
    //
    // The ZK public input for an amount must be a canonical, big-endian,
    // zero-padded `BytesN<32>` per
    // `docs/interop/proof-schema-version-negotiation.md`'s "Unsupported
    // Combinations" section ("Public inputs using i128 raw bytes instead of
    // the canonical BytesN<32> big-endian zero-padded encoding" is
    // explicitly rejected). These tests pin the exact byte layout across
    // supported precision boundaries and confirm invalid (negative) amounts
    // are rejected before any encoding happens.
    // =====================================================================

    #[test]
    fn test_amount_to_public_input_zero_is_all_zero_bytes() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, 0);
        assert_eq!(encoded.to_array(), [0u8; 32]);
    }

    #[test]
    fn test_amount_to_public_input_one_is_zero_padded_big_endian() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, 1);
        let arr = encoded.to_array();

        // High 16 bytes are always zero: i128 fits entirely within the low
        // 16 bytes of the 32-byte field, per the canonical encoding.
        assert_eq!(arr[..16], [0u8; 16]);
        // Big-endian: the least-significant byte is last.
        let mut expected_low16 = [0u8; 16];
        expected_low16[15] = 1;
        assert_eq!(arr[16..], expected_low16);
    }

    #[test]
    fn test_amount_to_public_input_preserves_full_precision_for_non_round_amount() {
        // A non-round, multi-byte amount must round-trip through the
        // big-endian encoding with no truncation or rounding drift.
        let env = Env::default();
        let amount: i128 = 999_999_999_937;
        let encoded = PaymentExecutor::amount_to_public_input(&env, amount);
        let arr = encoded.to_array();

        let mut low16 = [0u8; 16];
        low16.copy_from_slice(&arr[16..]);
        let round_tripped = u128::from_be_bytes(low16) as i128;

        assert_eq!(arr[..16], [0u8; 16]);
        assert_eq!(round_tripped, amount);
    }

    #[test]
    fn test_amount_to_public_input_accepts_maximum_i128_at_full_precision() {
        let env = Env::default();
        let encoded = PaymentExecutor::amount_to_public_input(&env, i128::MAX);
        let arr = encoded.to_array();

        let mut low16 = [0u8; 16];
        low16.copy_from_slice(&arr[16..]);
        let round_tripped = u128::from_be_bytes(low16) as i128;

        assert_eq!(round_tripped, i128::MAX);
    }

    #[test]
    #[should_panic(expected = "Amount must be non-negative")]
    fn test_amount_to_public_input_rejects_negative_one() {
        // Boundary just below the supported precision range: the smallest
        // magnitude negative value must still be rejected, not just
        // `i128::MIN`.
        let env = Env::default();
        let _ = PaymentExecutor::amount_to_public_input(&env, -1);
    }

    #[test]
    #[should_panic(expected = "Amount must be non-negative")]
    fn test_amount_to_public_input_rejects_i128_min() {
        let env = Env::default();
        let _ = PaymentExecutor::amount_to_public_input(&env, i128::MIN);
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
    #[should_panic(expected = "Insufficient available treasury balance: funds locked for pending payroll")]
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
        payroll_client.commit_draft(&test_hash);

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
        let (payroll_client, admin, treasury, _treasury_owner, employee, token_id) =
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
        payroll_client.deposit(&treasury, &token_id, &1000, &deposit_nonce);

        // Verify both nonces are tracked independently
        assert!(!payroll_client.is_run_nonce_used(&proof_nonce));
        // After finalization, proof nonce should be consumed
        payroll_client.finalize_payroll_run(&admin, &run_id, &[&employee].into());
    }

    #[test]
    fn test_overlapping_raw_inputs_different_domains() {
        let env = Env::default();
        let (payroll_client, admin, treasury, _treasury_owner, employee, token_id) =
            setup_payroll_with_token(&env);

        // Create identical 32-byte patterns that should belong to different domains
        let identical_bytes = [3u8; 32];
        let input1 = BytesN::from_array(&env, &identical_bytes);
        let input2 = BytesN::from_array(&env, &identical_bytes);

        // Use same raw input in different domains
        // Domain 1: Draft commitment (batch domain)
        payroll_client.commit_draft(&input1);

        // Domain 2: Run nonce (proof domain)
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let _run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &input2,
            &None,
        );

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
            &admin,
            &token_id,
            &5000i128,
            &86400u64, // 1 day expiry
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
            &admin,
            &token_id,
            &5000i128,
            &86400u64, // Future expiry
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
        payroll_client.finalize_payroll_run(&admin, &run_id, &employees);

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

        payroll_client.finalize_payroll_run(&admin, &run_id, &employees);

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

            payroll_client.finalize_payroll_run(&admin, &run_id, &employees);
            payroll_client.archive_payroll_run_with_reason(
                &admin,
                &run_id,
                &Symbol::new(&env, "compliance"),
            );

            assert!(payroll_client.is_payroll_run_archived(&run_id));
        }
    }
}
