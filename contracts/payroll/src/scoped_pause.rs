//! Scoped emergency pause recovery (#349).
//!
//! Extends the global pause_manager with per-scope pause controls so that an
//! operator can freeze individual execution lanes (Funding, Approval,
//! Execution, Audit, Archival) independently.  Pausing `Execution` never
//! affects `Audit` reads, enabling privacy-safe recovery diagnostics to
//! remain available even during an active incident.
//!
//! ## Storage
//! Active scopes are stored as a `Vec<u32>` (ordinals of `PauseScope`)
//! under the instance key `"scoped_pauses"`.  Instance storage avoids
//! extra ledger fees for a small mutable list that changes rarely.
//!
//! ## Events
//! - `("payroll", "scope_paused",  scope_name)` — emitted by `activate_scope_pause`.
//! - `("payroll", "scope_cleared", scope_name)` — emitted by `clear_scope_pause`.

#![allow(unused)]

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec};

// ── Scope enum ────────────────────────────────────────────────────────────────

/// The lanes that can be individually paused.
///
/// Ordinals are fixed so that stored `Vec<u32>` values survive upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PauseScope {
    /// Treasury funding / deposit lane.
    Funding = 0,
    /// Reviewer approval lane.
    Approval = 1,
    /// Payroll execution (batch processing) lane.
    Execution = 2,
    /// Audit / compliance read lane.
    Audit = 3,
    /// Run and record archival lane.
    Archival = 4,
}

impl PauseScope {
    /// Stable string name used in events.  Must be a valid `Symbol` (≤ 18
    /// printable-ASCII chars with no spaces).
    pub fn name(self) -> &'static str {
        match self {
            PauseScope::Funding => "Funding",
            PauseScope::Approval => "Approval",
            PauseScope::Execution => "Execution",
            PauseScope::Audit => "Audit",
            PauseScope::Archival => "Archival",
        }
    }

    /// Reconstruct a `PauseScope` from its stored ordinal.  Returns `None`
    /// for unknown ordinals so a future variant in storage does not panic the
    /// running contract version.
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(PauseScope::Funding),
            1 => Some(PauseScope::Approval),
            2 => Some(PauseScope::Execution),
            3 => Some(PauseScope::Audit),
            4 => Some(PauseScope::Archival),
            _ => None,
        }
    }
}

// ── Storage key ───────────────────────────────────────────────────────────────

/// Instance-storage key under which the active-scope list is persisted.
const STORAGE_KEY: &str = "scoped_pauses";

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Read the active-scope ordinal list, defaulting to an empty vec.
fn load_active_scopes(env: &Env) -> Vec<u32> {
    let key = Symbol::new(env, STORAGE_KEY);
    env.storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Persist the active-scope ordinal list.
fn save_active_scopes(env: &Env, scopes: &Vec<u32>) {
    let key = Symbol::new(env, STORAGE_KEY);
    env.storage().instance().set(&key, scopes);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Pause a specific execution scope.
///
/// Requires `admin` authorization.  If the scope is already paused this is a
/// no-op (idempotent) — no duplicate entry is stored and no event is re-emitted.
///
/// Emits `("payroll", "scope_paused", scope_name)`.
pub fn activate_scope_pause(env: &Env, admin: &Address, scope: PauseScope) {
    admin.require_auth();

    let ordinal = scope as u32;
    let mut active = load_active_scopes(env);

    // Already paused — nothing to do.
    for i in 0..active.len() {
        if active.get(i).unwrap() == ordinal {
            return;
        }
    }

    active.push_back(ordinal);
    save_active_scopes(env, &active);

    env.events().publish(
        (
            Symbol::new(env, "payroll"),
            Symbol::new(env, "scope_paused"),
            Symbol::new(env, scope.name()),
        ),
        (),
    );
}

/// Clear (lift) a previously activated scope pause.
///
/// Requires `admin` authorization.  If the scope is not currently paused this
/// is a no-op — no event is emitted.
///
/// Emits `("payroll", "scope_cleared", scope_name)`.
pub fn clear_scope_pause(env: &Env, admin: &Address, scope: PauseScope) {
    admin.require_auth();

    let ordinal = scope as u32;
    let active = load_active_scopes(env);

    let mut found_idx: Option<u32> = None;
    for i in 0..active.len() {
        if active.get(i).unwrap() == ordinal {
            found_idx = Some(i);
            break;
        }
    }

    let idx = match found_idx {
        Some(i) => i,
        // Not currently paused — nothing to do.
        None => return,
    };

    // Build a new vec without the found entry.
    let mut updated: Vec<u32> = Vec::new(env);
    for i in 0..active.len() {
        if i != idx {
            updated.push_back(active.get(i).unwrap());
        }
    }
    save_active_scopes(env, &updated);

    env.events().publish(
        (
            Symbol::new(env, "payroll"),
            Symbol::new(env, "scope_cleared"),
            Symbol::new(env, scope.name()),
        ),
        (),
    );
}

/// Return `true` if the given scope is currently paused.
///
/// Read-only — safe to call from any context.
pub fn is_scope_paused(env: &Env, scope: PauseScope) -> bool {
    let ordinal = scope as u32;
    let active = load_active_scopes(env);
    for i in 0..active.len() {
        if active.get(i).unwrap() == ordinal {
            return true;
        }
    }
    false
}

/// Guard: panic with `"ScopePaused"` if the given scope is paused.
///
/// Call this at the top of any entry-point that belongs to `scope`.
/// The error message is intentionally terse and contains no salary or
/// employee data.
///
/// Note: pausing `Execution` does NOT affect `Audit` — callers that check
/// `Execution` never need to also check `Audit`, preserving the recovery
/// diagnostic paths described in issue #349.
pub fn assert_scope_active(env: &Env, scope: PauseScope) {
    if is_scope_paused(env, scope) {
        panic!("ScopePaused");
    }
}
