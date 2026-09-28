//! Audit trail for payroll configuration changes (issue #490).
//!
//! Every successful change to a payroll configuration setting goes through
//! [`record_config_change`], which bumps a contract-wide configuration
//! revision and publishes exactly one `ConfigChanged` event:
//!
//! ```text
//! topics = ( Symbol("payroll"), Symbol("config_changed"), Symbol(<config key>) )
//! data   = ( actor, subject_ref, previous_ref, new_ref, revision, ledger_sequence, timestamp )
//! ```
//!
//! Configuration values are never published in plaintext. A value is
//! referenced by `sha256(value.to_xdr())` of its canonical XDR encoding, so an
//! auditor can check a change against the value read back from contract
//! storage and chain successive changes to the same setting (`previous_ref`
//! of one change equals `new_ref` of the change before it).
//!
//! A change that leaves the stored value byte-for-byte identical is a no-op:
//! the setter keeps its existing behaviour, but no audit event is published
//! and the revision is not bumped. Failed calls revert, so they publish
//! nothing either.
//!
//! See `docs/config-audit-events.md` for the full schema and how to verify it.

use payroll_events::ConfigChanged;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, Val};

use crate::DataKey;

/// Reference published when there is no value: the previous value of a
/// setting that was never set, the new value of a setting that was removed,
/// and the subject of a setting that is not keyed by an asset, period, or
/// role holder.
pub const NO_VALUE_REF: [u8; 32] = [0; 32];

/// Configuration keys published as the third topic of a `config_changed`
/// event. Each key names one setting and the entrypoint(s) that change it.
pub mod config_keys {
    /// `set_pause_manager` — value: pause manager `Address`.
    pub const PAUSE_MANAGER: &str = "pause_manager";
    /// `set_asset_allowed` — subject: asset; value: `bool`.
    pub const ASSET_ALLOWED: &str = "asset_allowed";
    /// `set_company_state` — value: `CompanyState`.
    pub const COMPANY_STATE: &str = "company_state";
    /// `set_capacity_limits` — value: `CapacityLimits`.
    pub const CAPACITY_LIMITS: &str = "capacity_limits";
    /// `set_settlement_window` — subject: period; value: `SettlementWindow`.
    pub const SETTLEMENT_WINDOW: &str = "settlement_window";
    /// `freeze_period_config` — subject: period; value: `bool`.
    pub const PERIOD_FROZEN: &str = "period_frozen";
    /// `set_retention_policy` — value: `RetentionPolicy`.
    pub const RETENTION_POLICY: &str = "retention_policy";
    /// `add_dispute_authority` / `remove_dispute_authority` — subject:
    /// authority; value: `bool` (absent once removed).
    pub const DISPUTE_AUTHORITY: &str = "dispute_authority";
    /// `add_reviewer` / `remove_reviewer` — subject: reviewer; value: `bool`
    /// (absent once removed).
    pub const REVIEWER: &str = "reviewer";
    /// `set_max_reviewers` — value: `u32` (issue #539).
    pub const MAX_REVIEWERS: &str = "max_reviewers";
    /// `register_operator_key` / `revoke_operator_key` — value: operator
    /// ed25519 public key (absent once revoked) (issue #519).
    pub const OPERATOR_KEY: &str = "operator_key";
    /// `set_reservation_expiry_policy` — subject: asset; value:
    /// `ReservationExpiry`.
    pub const RESERVATION_EXPIRY: &str = "reservation_expiry";
    /// `set_payroll_currency` — value: `PayrollCurrencyConfig`.
    pub const PAYROLL_CURRENCY: &str = "payroll_currency";
    /// `set_storage_version` — value: `StorageVersionState`.
    pub const STORAGE_VERSION: &str = "storage_version";
    /// `accept_admin_rotation` / `accept_admin_handover` — value: admin
    /// `Address`.
    pub const ADMIN: &str = "admin";
    /// `accept_treasury_rotation` — value: treasury owner `Address`.
    pub const TREASURY_OWNER: &str = "treasury_owner";
}

/// `sha256(value.to_xdr())`: the reference published for a configuration
/// value or subject.
pub fn value_ref<T: IntoVal<Env, Val> + Clone>(e: &Env, value: &T) -> BytesN<32> {
    e.crypto().sha256(&value.clone().to_xdr(e)).into()
}

/// [`NO_VALUE_REF`] as a `BytesN<32>`.
pub fn no_value_ref(e: &Env) -> BytesN<32> {
    BytesN::from_array(e, &NO_VALUE_REF)
}

/// Reference of the value currently stored under `key` in persistent
/// storage, or [`NO_VALUE_REF`] when nothing is stored. Hashing the raw
/// stored `Val` yields the same XDR as hashing the typed value returned by
/// the matching getter.
pub(crate) fn stored_ref(e: &Env, key: &DataKey) -> BytesN<32> {
    match e.storage().persistent().get::<DataKey, Val>(key) {
        Some(value) => value_ref(e, &value),
        None => no_value_ref(e),
    }
}

/// Current configuration revision; `0` until the first audited change.
pub(crate) fn config_revision(e: &Env) -> u64 {
    e.storage()
        .persistent()
        .get(&DataKey::ConfigRevision)
        .unwrap_or(0)
}

/// Record a successful configuration change: bump the revision and publish
/// one `ConfigChanged` event. Call it after the new value has been written
/// and only from a setter that has already authorized `actor`.
///
/// Does nothing when `previous_ref == new_ref` (no-op change).
pub(crate) fn record_config_change(
    e: &Env,
    actor: &Address,
    config_key: &str,
    subject_ref: BytesN<32>,
    previous_ref: BytesN<32>,
    new_ref: BytesN<32>,
) {
    if previous_ref == new_ref {
        return;
    }

    let revision = config_revision(e) + 1;
    e.storage()
        .persistent()
        .set(&DataKey::ConfigRevision, &revision);

    ConfigChanged {
        key: Symbol::new(e, config_key),
        actor: actor.clone(),
        subject_ref,
        previous_ref,
        new_ref,
        revision,
        ledger_sequence: e.ledger().sequence(),
        timestamp: e.ledger().timestamp(),
    }
    .publish(e);
}
