//! Deterministic payroll run identifiers (#480).
//!
//! A payroll run is addressed on chain by a sequential `u64` run ID. That ID is
//! allocated in submission order, so an off-chain client cannot know it before
//! the transaction lands. This module adds a second, stable identifier that is a
//! pure hash of request fields every caller already has:
//!
//! ```text
//! identifier = sha256(
//!     b"zkpayroll_run_identifier_v1"
//!     || nonce[32]
//!     || employee_count (u32, big-endian)
//!     || draft_hash[32]   // 32 zero bytes when no draft hash was supplied
//! )
//! ```
//!
//! The nonce is already enforced as contract-wide unique by
//! `prepare_payroll_run` / `batch_process_payroll`, so the identifier is unique
//! without hashing any salary amount, employee address, or commitment value.
//! `employee_count` and `draft_hash` bind the identifier to the payload shape
//! and reviewed draft; neither exposes payroll values.
//!
//! Because the formula uses only immutable run fields, the identifier can be
//! recomputed from an existing `PendingPayrollRun` or `PayrollRun` record. It
//! therefore remains stable across finalization, archival, and transfers of the
//! run's admin.

use soroban_sdk::{contracterror, Bytes, BytesN, Env};

/// Domain separator mixed into every deterministic run identifier.
pub const RUN_IDENTIFIER_DOMAIN: &[u8] = b"zkpayroll_run_identifier_v1";

/// Stable, payload-free errors for deterministic run identifier lookups.
///
/// Codes are append-only and unit-only: no run ID, amount, nonce, employee
/// address, or draft hash is echoed back to the caller.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PayrollRunIdentifierError {
    /// `u64::MAX` is reserved and can never address a payroll run.
    InvalidRunId = 8900,
    /// No pending or executed payroll run exists under this ID.
    RunNotFound = 8901,
}

/// Compute the deterministic identifier for a payroll request.
///
/// This is a pure function: the same inputs always produce the same 32-byte
/// identifier and no storage is read or written. Off-chain clients can
/// reproduce it with SHA-256 using the encoding documented on
/// [`RUN_IDENTIFIER_DOMAIN`].
pub fn compute(
    e: &Env,
    nonce: &BytesN<32>,
    employee_count: u32,
    draft_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::new(e);
    preimage.extend_from_slice(RUN_IDENTIFIER_DOMAIN);
    preimage.extend_from_array(&nonce.to_array());
    preimage.extend_from_array(&employee_count.to_be_bytes());
    preimage.extend_from_array(&draft_hash.to_array());
    e.crypto().sha256(&preimage).into()
}

/// Resolve the deterministic identifier for an existing run.
///
/// Looks up the immutable run fields from the completed `PayrollRun` record
/// first, then from the still-pending record. No admin authorization is needed
/// because the result is derived only from the caller-supplied nonce and two
/// non-sensitive content bindings.
///
/// Returns [`PayrollRunIdentifierError::InvalidRunId`] for the reserved
/// `u64::MAX` sentinel and [`PayrollRunIdentifierError::RunNotFound`] when no
/// run record exists (for example a prepared run that was later cancelled).
pub fn try_for_run(e: &Env, run_id: u64) -> Result<BytesN<32>, PayrollRunIdentifierError> {
    if crate::validate_run_id_checked(run_id).is_err() {
        return Err(PayrollRunIdentifierError::InvalidRunId);
    }

    if let Some(run) = e
        .storage()
        .persistent()
        .get::<_, crate::PayrollRun>(&crate::DataKey::PayrollRun(run_id))
    {
        return Ok(compute(e, &run.nonce, run.employee_count, &run.draft_hash));
    }

    if let Some(pending) = e
        .storage()
        .persistent()
        .get::<_, crate::PendingPayrollRun>(&crate::DataKey::PendingRun(run_id))
    {
        return Ok(compute(
            e,
            &pending.nonce,
            pending.employee_count,
            &pending.draft_hash,
        ));
    }

    Err(PayrollRunIdentifierError::RunNotFound)
}
