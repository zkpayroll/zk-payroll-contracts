//! Privacy-safe recovery checkpoints for contract payroll uploads (#782).
//!
//! Upload checkpoints store only opaque identifiers, batch digests, chunk
//! counts, lifecycle state, and timestamps. Payroll rows and proof material
//! remain off-chain and are never included in checkpoint events.

use soroban_sdk::{contracttype, Address, BytesN};

/// Lifecycle of a payroll upload checkpoint.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayrollUploadStatus {
    /// Upload is open and accepts the next sequential chunk.
    InProgress = 0,
    /// All planned chunks have been checkpointed.
    Completed = 1,
    /// Upload was explicitly interrupted and may be resumed by the admin.
    Failed = 2,
}

/// Privacy-safe progress record for one payroll upload.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayrollUploadCheckpoint {
    /// Opaque caller-supplied identifier for this upload.
    pub upload_id: BytesN<32>,
    /// Digest identifying the uploaded payroll batch.
    pub batch_root: BytesN<32>,
    /// Total chunks planned for this upload.
    pub total_chunks: u32,
    /// Number of sequential chunks already checkpointed.
    pub uploaded_chunks: u32,
    /// Current upload lifecycle state.
    pub status: PayrollUploadStatus,
    /// Ledger timestamp when the checkpoint was created.
    pub started_at: u64,
    /// Ledger timestamp of the latest state change.
    pub last_updated: u64,
    /// Admin that performed the latest state change.
    pub updated_by: Address,
}

/// Dedicated storage key for payroll upload checkpoints.
///
/// This stays separate from `DataKey` to avoid changing its contract spec.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayrollUploadKey {
    Checkpoint(BytesN<32>),
}
