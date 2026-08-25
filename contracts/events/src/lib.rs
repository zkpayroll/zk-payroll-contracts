#![no_std]

//! Centralized structured event emission for the zk-payroll contract suite.
//!
//! # Overview
//! This module provides typed helper functions for publishing Soroban contract
//! events across all payroll-related contracts. Every state-changing entrypoint
//! should emit an event through these helpers to ensure consistent, structured
//! event payloads for explorers, indexers, SDKs, and off-chain consumers.
//!
//! # Event Schema
//! Each event uses a consistent topic+data pattern:
//! - **Topics** (indexed): contract domain symbol + event type symbol + entity IDs
//! - **Data** (non-indexed): payload fields (amounts, hashes, addresses, etc.)
//!
//! # Consumers
//! - **SDKs**: Filter by topic symbols for efficient event streaming
//! - **Indexers**: Parse structured data tuples for database storage
//! - **Explorers**: Display human-readable event names and key fields
//!
//! # Naming Convention
//! Event type symbols use `snake_case` for new events. Existing events that
//! predate this module may use other conventions and are preserved for
//! backward compatibility.

use soroban_sdk::{symbol_short, Address, BytesN, Env, Symbol};

// ═════════════════════════════════════════════════════════════════════════════
// Topic helpers
// ═════════════════════════════════════════════════════════════════════════════

/// Returns the "payroll" domain topic used by the Payroll contract.
pub fn payroll_topic() -> Symbol {
    symbol_short!("payroll")
}

// ═════════════════════════════════════════════════════════════════════════════
// Payroll Contract Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when the Payroll contract is initialized.
pub fn emit_payroll_initialized(
    e: &Env,
    admin: Address,
    token: Address,
    verifier: Address,
    commitment: Address,
    treasury: Address,
    treasury_owner: Address,
) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "initialized")),
        (admin, token, verifier, commitment, treasury, treasury_owner),
    );
}

/// Emitted when the pause manager is set or changed.
pub fn emit_pause_manager_set(e: &Env, pause_manager: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "pause_mgr_set")),
        (pause_manager,),
    );
}

/// Emitted when a deposit is made to the treasury.
pub fn emit_deposit(e: &Env, from: Address, amount: i128, deposit_id: BytesN<32>) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "deposit")),
        (from, amount, deposit_id),
    );
}

/// Emitted when a metadata hash is pre-committed.
pub fn emit_metadata_committed(e: &Env, metadata_hash: BytesN<32>) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "meta_committed")),
        metadata_hash,
    );
}

/// Emitted when a metadata hash is bound to a payroll run.
pub fn emit_metadata_bound(e: &Env, run_id: u64, metadata_hash: BytesN<32>) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "meta_bound")),
        (run_id, metadata_hash),
    );
}

/// Emitted when a draft hash is pre-committed on-chain.
pub fn emit_draft_committed(e: &Env, draft_hash: BytesN<32>) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_committed")),
        draft_hash,
    );
}

/// Emitted when an emergency withdrawal is requested.
pub fn emit_emergency_requested(e: &Env, amount: i128, recipient: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "emrg_requested")),
        (amount, recipient),
    );
}

/// Emitted when an emergency withdrawal is approved and executed.
pub fn emit_emergency_approved(e: &Env, amount: i128, recipient: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "emrg_approved")),
        (amount, recipient),
    );
}

/// Emitted when a pending emergency withdrawal is cancelled.
pub fn emit_emergency_cancelled(e: &Env, caller: Address) {
    e.events()
        .publish((payroll_topic(), Symbol::new(e, "emrg_cancelled")), caller);
}

/// Emitted when a pending payroll run is prepared.
pub fn emit_run_prepared(e: &Env, run_id: u64, total_spend: i128) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_prepared")),
        (run_id, total_spend),
    );
}

/// Emitted when a pending payroll run is cancelled.
pub fn emit_run_cancelled(e: &Env, run_id: u64, total_amount: i128) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_cancelled")),
        (run_id, total_amount),
    );
}

/// Emitted for each individual payment within a batch payroll run.
pub fn emit_payment_executed(e: &Env, employee: Address, amount: i128) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "payment_executed")),
        (employee, amount),
    );
}

/// Emitted when a payroll run is fully executed and recorded on-chain.
pub fn emit_run_executed(e: &Env, run_id: u64, total_spend: i128) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_executed")),
        (run_id, total_spend),
    );
}

/// Emitted when a long-running payroll batch starts checkpointing.
pub fn emit_batch_checkpoint_started(
    e: &Env,
    employer: Address,
    batch_root: BytesN<32>,
    asset: Address,
    execution_nonce: BytesN<32>,
    checkpoint_index: u32,
) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "batch_checkpoint_started")),
        (employer, batch_root, asset, execution_nonce, checkpoint_index),
    );
}

/// Emitted when a payroll batch checkpoint advances without exposing salary rows.
pub fn emit_batch_checkpoint_updated(
    e: &Env,
    employer: Address,
    batch_root: BytesN<32>,
    asset: Address,
    execution_nonce: BytesN<32>,
    checkpoint_index: u32,
    state: u32,
) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "batch_checkpoint_updated")),
        (employer, batch_root, asset, execution_nonce, checkpoint_index, state),
    );
}

/// Emitted when a batch checkpoint is resumed after an interruption.
pub fn emit_batch_checkpoint_resumed(
    e: &Env,
    employer: Address,
    batch_root: BytesN<32>,
    asset: Address,
    execution_nonce: BytesN<32>,
    checkpoint_index: u32,
) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "batch_checkpoint_resumed")),
        (employer, batch_root, asset, execution_nonce, checkpoint_index),
    );
}

/// Emitted when a payroll run draft is created.
pub fn emit_draft_created(e: &Env, draft_id: u64, admin: Address, period_label: Symbol) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_created")),
        (draft_id, admin, period_label),
    );
}

/// Emitted when a payroll run draft is amended.
pub fn emit_draft_amended(e: &Env, draft_id: u64, new_total: i128, amendment_count: u32) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_amended")),
        (draft_id, new_total, amendment_count),
    );
}

/// Emitted when a payroll run draft is finalized (locked).
pub fn emit_draft_finalized(e: &Env, draft_id: u64, total: i128, amendment_count: u32) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_finalized")),
        (draft_id, total, amendment_count),
    );
}

/// Emitted when a payroll run draft is submitted.
pub fn emit_draft_submitted(e: &Env, draft_id: u64, admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_submitted")),
        (draft_id, admin),
    );
}

/// Emitted when a payroll run draft is cancelled.
pub fn emit_draft_cancelled(e: &Env, draft_id: u64, admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_cancelled")),
        (draft_id, admin),
    );
}

/// Emitted when a payroll run draft is expired.
pub fn emit_draft_expired(e: &Env, draft_id: u64, admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "draft_expired")),
        (draft_id, admin),
    );
}

/// Emitted when a payroll run's reconciliation status is updated.
pub fn emit_reconciliation_updated(e: &Env, run_id: u64, status: Symbol) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "reconciliation_updated")),
        (run_id, status),
    );
}

/// Emitted when a new admin is proposed (step 1 of 2).
pub fn emit_admin_proposed(e: &Env, current_admin: Address, new_admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_proposed")),
        (current_admin, new_admin),
    );
}

/// Emitted when an admin rotation is completed (step 2 of 2).
pub fn emit_admin_rotated(e: &Env, old_admin: Address, new_admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_rotated")),
        (old_admin, new_admin),
    );
}

/// Emitted when a pending admin rotation is cancelled.
pub fn emit_admin_rotation_cancelled(e: &Env, caller: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_rot_cancel")),
        caller,
    );
}

/// Emitted when an admin handover is requested (#339).
pub fn emit_admin_handover_requested(e: &Env, current_admin: Address, pending_admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_handover_req")),
        (current_admin, pending_admin),
    );
}

/// Emitted when an admin handover is accepted (#339).
pub fn emit_admin_handover_accepted(e: &Env, old_admin: Address, new_admin: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_handover_acc")),
        (old_admin, new_admin),
    );
}

/// Emitted when a pending admin handover is cancelled (#339).
pub fn emit_admin_handover_cancelled(e: &Env, caller: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "admin_handover_can")),
        caller,
    );
}

/// Emitted when a new treasury owner is proposed (step 1 of 2).
pub fn emit_treasury_proposed(e: &Env, current_owner: Address, new_owner: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "treasury_proposed")),
        (current_owner, new_owner),
    );
}

/// Emitted when a treasury owner rotation is completed (step 2 of 2).
pub fn emit_treasury_rotated(e: &Env, old_owner: Address, new_owner: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "treasury_rotated")),
        (old_owner, new_owner),
    );
}

/// Emitted when a pending treasury rotation is cancelled.
pub fn emit_treasury_rotation_cancelled(e: &Env, caller: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "treas_rot_cancel")),
        caller,
    );
}

/// Emitted when a reviewer is authorized by admin.
pub fn emit_reviewer_added(e: &Env, reviewer: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "reviewer_added")),
        reviewer,
    );
}

/// Emitted when a reviewer authorization is revoked by admin.
pub fn emit_reviewer_removed(e: &Env, reviewer: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "reviewer_removed")),
        reviewer,
    );
}

/// Emitted when an authorized reviewer approves a payroll run.
pub fn emit_run_approved(e: &Env, run_id: u64, reviewer: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_approved")),
        (run_id, reviewer),
    );
}

/// Emitted when an authorized reviewer rejects a payroll run.
pub fn emit_run_rejected(e: &Env, run_id: u64, reviewer: Address, reason: Symbol) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_rejected")),
        (run_id, reviewer, reason),
    );
}

/// Emitted when an authorized reviewer requests changes to a payroll run.
pub fn emit_run_changes_requested(e: &Env, run_id: u64, reviewer: Address, reason: Symbol) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "changes_requested")),
        (run_id, reviewer, reason),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Payroll Registry Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when a new company is registered.
pub fn emit_company_registered(e: &Env, company_id: u64, admin: Address, treasury: Address) {
    e.events().publish(
        (Symbol::new(e, "CompanyRegistered"), company_id),
        (admin, treasury),
    );
}

/// Emitted when an employee is added to a company.
pub fn emit_employee_added(e: &Env, company_id: u64, employee: Address, commitment: BytesN<32>) {
    e.events().publish(
        (Symbol::new(e, "EmployeeAdded"), company_id, employee),
        (commitment,),
    );
}

/// Emitted when an employee is removed from a company.
pub fn emit_employee_removed(e: &Env, company_id: u64, employee: Address) {
    e.events().publish(
        (Symbol::new(e, "EmployeeRemoved"), company_id, employee),
        (),
    );
}

/// Emitted when an employee's commitment is updated in the registry.
pub fn emit_registry_commitment_updated(
    e: &Env,
    company_id: u64,
    employee: Address,
    new_commitment: BytesN<32>,
) {
    e.events().publish(
        (Symbol::new(e, "CommitmentUpdated"), company_id, employee),
        (new_commitment,),
    );
}

/// Emitted when an employee's eligibility status is changed.
pub fn emit_employee_status_changed(
    e: &Env,
    company_id: u64,
    employee: Address,
    previous_status: Symbol,
    new_status: Symbol,
) {
    e.events().publish(
        (
            Symbol::new(e, "EmployeeStatusChanged"),
            company_id,
            employee,
        ),
        (previous_status, new_status),
    );
}

/// Emitted when the registry pause manager is set.
pub fn emit_registry_pause_manager_set(e: &Env, pause_manager: Address) {
    e.events()
        .publish((Symbol::new(e, "RegistryPauseMgrSet"),), (pause_manager,));
}

/// Emitted when a company admin rotation is proposed (step 1 of 2).
pub fn emit_company_admin_proposed(
    e: &Env,
    company_id: u64,
    current_admin: Address,
    new_admin: Address,
) {
    e.events().publish(
        (
            Symbol::new(e, "CompanyAdminProposed"),
            company_id,
            current_admin,
        ),
        (new_admin,),
    );
}

/// Emitted when a company admin rotation is accepted (step 2 of 2).
pub fn emit_company_admin_rotated(
    e: &Env,
    company_id: u64,
    old_admin: Address,
    new_admin: Address,
) {
    e.events().publish(
        (Symbol::new(e, "CompanyAdminRotated"), company_id, old_admin),
        (new_admin,),
    );
}

/// Emitted when a company admin rotation is cancelled.
pub fn emit_company_admin_rotation_cancelled(e: &Env, company_id: u64, caller: Address) {
    e.events().publish(
        (
            Symbol::new(e, "CompanyAdminRotCancelled"),
            company_id,
            caller,
        ),
        (),
    );
}

/// Emitted when a company treasury rotation is proposed.
pub fn emit_company_treasury_proposed(
    e: &Env,
    company_id: u64,
    current_admin: Address,
    new_treasury: Address,
) {
    e.events().publish(
        (
            Symbol::new(e, "CompanyTreasProposed"),
            company_id,
            current_admin,
        ),
        (new_treasury,),
    );
}

/// Emitted when a company treasury rotation is accepted.
pub fn emit_company_treasury_rotated(
    e: &Env,
    company_id: u64,
    old_treasury: Address,
    new_treasury: Address,
) {
    e.events().publish(
        (
            Symbol::new(e, "CompanyTreasRotated"),
            company_id,
            old_treasury,
        ),
        (new_treasury,),
    );
}

/// Emitted when a company treasury rotation is cancelled.
pub fn emit_company_treasury_rotation_cancelled(e: &Env, company_id: u64, caller: Address) {
    e.events().publish(
        (
            Symbol::new(e, "CompanyTreasRotCancelled"),
            company_id,
            caller,
        ),
        (),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Salary Commitment Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when a salary commitment is stored for an employee.
pub fn emit_commitment_stored(e: &Env, employee: Address, commitment: BytesN<32>) {
    e.events().publish(
        (Symbol::new(e, "CommitmentUpdated"), employee),
        (commitment,),
    );
}

/// Emitted when a salary commitment is rotated (old revoked, new active).
pub fn emit_commitment_rotated(
    e: &Env,
    employee: Address,
    old_commitment: BytesN<32>,
    new_commitment: BytesN<32>,
) {
    e.events().publish(
        (Symbol::new(e, "CommitmentRotated"), employee),
        (old_commitment, new_commitment),
    );
}

/// Emitted when an employee's commitment is locked (no updates allowed).
pub fn emit_commitment_locked(e: &Env, employee: Address) {
    e.events()
        .publish((Symbol::new(e, "CommitmentLocked"), employee), ());
}

/// Emitted when an employee's commitment is unlocked.
pub fn emit_commitment_unlocked(e: &Env, employee: Address) {
    e.events()
        .publish((Symbol::new(e, "CommitmentUnlocked"), employee), ());
}

/// Emitted when an employee's external reference ID is set.
pub fn emit_reference_id_set(e: &Env, employee: Address, reference_id: soroban_sdk::String) {
    e.events().publish(
        (Symbol::new(e, "ReferenceIdSet"), employee),
        (reference_id,),
    );
}

/// Emitted when a payment nullifier is recorded.
pub fn emit_nullifier_recorded(e: &Env, nullifier: BytesN<32>) {
    e.events()
        .publish((Symbol::new(e, "NullifierRecorded"),), (nullifier,));
}

/// Emitted when the payroll operator is set.
pub fn emit_payroll_operator_set(e: &Env, operator: Address) {
    e.events()
        .publish((Symbol::new(e, "PayrollOperatorSet"),), (operator,));
}

/// Emitted when a commitment admin rotation is proposed.
pub fn emit_commitment_admin_proposed(e: &Env, current_admin: Address, new_admin: Address) {
    e.events().publish(
        (Symbol::new(e, "AdminRotationProposed"), current_admin),
        (new_admin,),
    );
}

/// Emitted when a commitment admin rotation is accepted.
pub fn emit_commitment_admin_accepted(e: &Env, new_admin: Address) {
    e.events()
        .publish((Symbol::new(e, "AdminRotationAccepted"), new_admin), ());
}

/// Emitted when a commitment admin rotation is cancelled.
pub fn emit_commitment_admin_cancelled(e: &Env, current_admin: Address) {
    e.events().publish(
        (Symbol::new(e, "AdminRotationCancelled"), current_admin),
        (),
    );
}

/// Emitted when the salary commitment pause manager is set.
pub fn emit_commitment_pause_manager_set(e: &Env, pause_manager: Address) {
    e.events()
        .publish((Symbol::new(e, "CommitPauseMgrSet"),), (pause_manager,));
}

// ═════════════════════════════════════════════════════════════════════════════
// Payment Executor Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when the payment executor is initialized.
pub fn emit_executor_initialized(e: &Env, registry: Address, token: Address) {
    e.events()
        .publish((Symbol::new(e, "ExecutorInitialized"),), (registry, token));
}

/// Emitted when the executor admin is set.
pub fn emit_executor_admin_set(e: &Env, admin: Address) {
    e.events()
        .publish((Symbol::new(e, "ExecutorAdminSet"),), (admin,));
}

/// Emitted when the executor pause manager is set.
pub fn emit_executor_pause_manager_set(e: &Env, pause_manager: Address) {
    e.events()
        .publish((Symbol::new(e, "ExecutorPauseMgrSet"),), (pause_manager,));
}

/// Emitted when a payroll period is created for a company.
pub fn emit_period_created(e: &Env, company_id: u64, period_id: u32) {
    e.events()
        .publish((Symbol::new(e, "PeriodCreated"), company_id), (period_id,));
}

/// Emitted when a payroll period is closed.
pub fn emit_period_closed(e: &Env, company_id: u64, period_id: u32) {
    e.events()
        .publish((Symbol::new(e, "PeriodClosed"), company_id), (period_id,));
}

/// Emitted when a single payment is executed in the payment executor.
pub fn emit_executor_payment_processed(
    e: &Env,
    company_id: u64,
    employee: Address,
    amount: i128,
    period: u32,
) {
    e.events().publish(
        (Symbol::new(e, "PayrollProcessed"), company_id),
        (employee, amount, period),
    );
}

/// Emitted when an asset token is allowed or disallowed for payments.
pub fn emit_asset_allowed_changed(e: &Env, asset: Address, allowed: bool) {
    e.events()
        .publish((Symbol::new(e, "AssetAllowedChanged"),), (asset, allowed));
}

// ═════════════════════════════════════════════════════════════════════════════
// Pause Manager Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when the pause manager is initialized.
pub fn emit_pause_manager_initialized(e: &Env, operator: Address) {
    e.events().publish(
        (
            Symbol::new(e, "PauseManager"),
            Symbol::new(e, "initialized"),
        ),
        (operator,),
    );
}

/// Emitted when the system is paused.
pub fn emit_paused(e: &Env) {
    e.events().publish(
        (Symbol::new(e, "PauseManager"), Symbol::new(e, "paused")),
        (),
    );
}

/// Emitted when the system is unpaused.
pub fn emit_unpaused(e: &Env) {
    e.events().publish(
        (Symbol::new(e, "PauseManager"), Symbol::new(e, "unpaused")),
        (),
    );
}

/// Emitted when a pause operator rotation is proposed.
pub fn emit_pause_operator_proposed(e: &Env, current: Address, new_op: Address) {
    e.events().publish(
        (
            Symbol::new(e, "PauseManager"),
            Symbol::new(e, "op_proposed"),
        ),
        (current, new_op),
    );
}

/// Emitted when a pause operator rotation is accepted.
pub fn emit_pause_operator_rotated(e: &Env, new_op: Address) {
    e.events().publish(
        (Symbol::new(e, "PauseManager"), Symbol::new(e, "op_rotated")),
        new_op,
    );
}

/// Emitted when a pause operator rotation is cancelled.
pub fn emit_pause_operator_cancelled(e: &Env, current: Address) {
    e.events().publish(
        (
            Symbol::new(e, "PauseManager"),
            Symbol::new(e, "op_cancelled"),
        ),
        current,
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Audit Module Events
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when an audit view key is generated for an auditor.
pub fn emit_view_key_generated(e: &Env, auditor: Address, expiration_ledger: u32) {
    e.events().publish(
        (Symbol::new(e, "ViewKeyGenerated"), auditor),
        (expiration_ledger,),
    );
}

/// Emitted when an audit access view key is revoked.
pub fn emit_audit_access_revoked(e: &Env, admin: Address, auditor: Address) {
    e.events()
        .publish((Symbol::new(e, "AuditAccessRevoked"), admin, auditor), ());
}

/// Emitted when an audit commitment verification succeeds.
pub fn emit_audit_successful(e: &Env, auditor: Address, scope: Symbol) {
    e.events()
        .publish((Symbol::new(e, "AuditSuccessful"), auditor), (scope,));
}

/// Emitted when an aggregate audit report is generated.
pub fn emit_aggregate_audit_generated(
    e: &Env,
    auditor: Address,
    company_id: Symbol,
    period_start: u64,
    period_end: u64,
) {
    e.events().publish(
        (Symbol::new(e, "AggregateAuditGenerated"), auditor),
        (company_id, period_start, period_end),
    );
}

/// Emitted when an audit summary is exported.
pub fn emit_audit_summary_exported(
    e: &Env,
    auditor: Address,
    company_id: Symbol,
    period_start: u64,
    period_end: u64,
    total: u32,
) {
    e.events().publish(
        (Symbol::new(e, "AuditSummaryExported"), auditor),
        (company_id, period_start, period_end, total),
    );
}

/// Emitted when the audit module pause manager is set.
pub fn emit_audit_pause_manager_set(e: &Env, pause_manager: Address) {
    e.events()
        .publish((Symbol::new(e, "AuditPauseMgrSet"),), (pause_manager,));
}

/// Emitted when locked payroll funds are updated (#343).
pub fn emit_locked_funds_updated(e: &Env, asset: Address, locked_amount: i128) {
    e.events().publish(
        (Symbol::new(e, "treasury"), Symbol::new(e, "locked_funds_updated")),
        (asset, locked_amount),
    );
}

/// Emitted when a multi-signer quorum approval payload reference is consumed (#334).
pub fn emit_quorum_consumed(e: &Env, batch_root: BytesN<32>, employer: Address, nonce: BytesN<32>) {
    e.events().publish(
        (Symbol::new(e, "signing"), Symbol::new(e, "quorum_consumed")),
        (batch_root, employer, nonce),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Compliance Hold Events (#333)
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when a compliance hold is placed on a batch, employee group, or employer (#333).
pub fn emit_compliance_hold_placed(
    e: &Env,
    hold_id: u64,
    scope: Symbol,
    target: Address,
    reason_code: Symbol,
    placed_by: Address,
) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "hold_placed")),
        (hold_id, scope, target, reason_code, placed_by),
    );
}

/// Emitted when a compliance hold is released (#333).
pub fn emit_compliance_hold_released(e: &Env, hold_id: u64, released_by: Address) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "hold_released")),
        (hold_id, released_by),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Funding Reservation Expiry Events (#337)
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when a funding reservation expires (#337).
pub fn emit_reservation_expired(e: &Env, asset: Address, amount: i128, expired_at: u64) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "reservation_expired")),
        (asset, amount, expired_at),
    );
}

/// Emitted when an expired reservation is released and funds become available (#337).
pub fn emit_reservation_expiry_released(e: &Env, asset: Address, released_amount: i128) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "reservation_released")),
        (asset, released_amount),
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Payroll Archival Events (#335)
// ═════════════════════════════════════════════════════════════════════════════

/// Emitted when a payroll run is archived for long-term reporting (#335).
pub fn emit_payroll_run_archived(e: &Env, run_id: u64, archived_by: Address, archive_reason: Symbol) {
    e.events().publish(
        (payroll_topic(), Symbol::new(e, "run_archived")),
        (run_id, archived_by, archive_reason),
    );
}
