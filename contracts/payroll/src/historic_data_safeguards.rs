//! Historic data retrieval safeguards (#788).
//!
//! Provides bounded, privacy-safe access to historic payroll run identifiers.
//! Only run IDs (opaque `u64` values) are returned — no salary amounts,
//! employee addresses, proof material, or commitment values are disclosed.
//!
//! ## Access control
//!
//! Three scopes are recognised:
//!
//! * `Admin` — the registered contract admin.
//! * `TreasuryOwner` — the registered treasury owner.
//! * `AuditAuthority` — any address registered as an audit-hold release
//!   authority (a superset that naturally includes external auditors).
//!
//! Every retrieval is bounded by `MAX_HISTORIC_QUERY_RANGE` run IDs and
//! `MAX_HISTORIC_PAGE_SIZE` results per call so a single query cannot scan
//! unbounded storage.

use soroban_sdk::{contracterror, contracttype, Address, Env, Vec};

use crate::DataKey;

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum run-id range `[from_run_id, to_run_id]` a single query may span.
pub const MAX_HISTORIC_QUERY_RANGE: u64 = 1_000;

/// Maximum number of run IDs returned per `get_historic_run_ids` call.
pub const MAX_HISTORIC_PAGE_SIZE: u32 = 100;

// ── Types ──────────────────────────────────────────────────────────────────────

/// The caller-requested data access scope.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricDataScope {
    /// Full historic access — restricted to the contract admin.
    Admin,
    /// Treasury-level access — restricted to the treasury owner.
    TreasuryOwner,
    /// Audit access — restricted to registered audit-hold release authorities.
    AuditAuthority,
}

/// Errors that can block historic data retrieval.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HistoricDataError {
    /// The caller is not authorised for the requested scope.
    Unauthorized = 7880,
    /// `from_run_id` is greater than `to_run_id`.
    InvalidRange = 7881,
    /// The requested range exceeds `MAX_HISTORIC_QUERY_RANGE`.
    RangeExceedsLimit = 7882,
    /// The requested page size exceeds `MAX_HISTORIC_PAGE_SIZE`.
    PageSizeExceedsLimit = 7883,
    /// `from_run_id` is zero, which is not a valid run identifier.
    InvalidFromRunId = 7884,
}

/// Preflight verdict returned by `check_historic_data_access`.
///
/// Privacy-safe: reports only the access decision and resolved scope.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricDataAccess {
    /// `true` when the caller may proceed with the retrieval.
    pub allowed: bool,
    /// The scope that was evaluated.
    pub scope: HistoricDataScope,
    /// Stable error code when access is denied (`HistoricDataError` discriminant),
    /// or `None` when access is allowed.  Use [`HistoricDataError`] to
    /// interpret the value:
    /// * 7880 — Unauthorized
    /// * 7881 — InvalidRange
    /// * 7882 — RangeExceedsLimit
    /// * 7883 — PageSizeExceedsLimit
    /// * 7884 — InvalidFromRunId
    pub denial_reason: Option<u32>,
}

/// Parameters for a bounded historic run-id page query.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricDataQuery {
    /// First run ID to include (inclusive, must be ≥ 1).
    pub from_run_id: u64,
    /// Last run ID to include (inclusive).
    pub to_run_id: u64,
    /// Maximum results to return; must be ≤ `MAX_HISTORIC_PAGE_SIZE`.
    pub page_size: u32,
    /// Access scope the caller is asserting.
    pub scope: HistoricDataScope,
}

/// Trait implemented by the `Payroll` contract for historic data access.
pub trait HistoricDataSafeguard {
    /// Preflight access check — read-only, no side effects.
    fn check_historic_data_access(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        scope: HistoricDataScope,
    ) -> HistoricDataAccess;

    /// Retrieve a bounded page of historic run IDs.
    fn get_historic_run_ids(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        query: HistoricDataQuery,
    ) -> soroban_sdk::Vec<u64>;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Determine whether `caller` is authorised for the given `scope`.
fn is_authorised(env: &Env, caller: &Address, scope: HistoricDataScope) -> bool {
    match scope {
        HistoricDataScope::Admin => {
            if let Some(addrs) = env
                .storage()
                .persistent()
                .get::<_, crate::ContractAddresses>(&DataKey::Addresses)
            {
                caller == &addrs.admin
            } else {
                false
            }
        }
        HistoricDataScope::TreasuryOwner => {
            if let Some(treasury_owner) = env
                .storage()
                .persistent()
                .get::<_, Address>(&DataKey::TreasuryOwner)
            {
                caller == &treasury_owner
            } else {
                false
            }
        }
        HistoricDataScope::AuditAuthority => {
            // Any registered audit-hold release authority qualifies.
            env.storage()
                .persistent()
                .has(&DataKey::AuditHoldReleaseAuthority(caller.clone()))
        }
    }
}

// ── Public functions called from `lib.rs` ────────────────────────────────────

/// Preflight whether `caller` may retrieve historic payroll data for `scope`.
///
/// Always returns a [`HistoricDataAccess`] record — never panics — so
/// dashboards and SDKs can display the verdict before submitting a transaction.
pub fn check_access(env: &Env, caller: &Address, scope: HistoricDataScope) -> HistoricDataAccess {
    if is_authorised(env, caller, scope) {
        HistoricDataAccess {
            allowed: true,
            scope,
            denial_reason: None,
        }
    } else {
        HistoricDataAccess {
            allowed: false,
            scope,
            denial_reason: Some(HistoricDataError::Unauthorized as u32),
        }
    }
}

/// Retrieve a bounded, privacy-safe page of historic run IDs.
///
/// Panics with an actionable message when:
/// - the caller is not authorised for the requested scope,
/// - `from_run_id` is zero,
/// - `from_run_id > to_run_id`,
/// - the range exceeds `MAX_HISTORIC_QUERY_RANGE`, or
/// - `page_size` exceeds `MAX_HISTORIC_PAGE_SIZE`.
///
/// Returns only run IDs whose `PayrollRun` storage key exists so callers
/// never receive phantom identifiers.
pub fn retrieve_run_ids(env: &Env, caller: &Address, query: HistoricDataQuery) -> Vec<u64> {
    if !is_authorised(env, caller, query.scope) {
        panic!("Historic data access denied: unauthorized for requested scope");
    }
    if query.from_run_id == 0 {
        panic!("Historic data query: from_run_id must be >= 1");
    }
    if query.from_run_id > query.to_run_id {
        panic!("Historic data query: from_run_id must be <= to_run_id");
    }
    let range = query.to_run_id - query.from_run_id;
    if range > MAX_HISTORIC_QUERY_RANGE {
        panic!("Historic data query: range exceeds MAX_HISTORIC_QUERY_RANGE");
    }
    if query.page_size > MAX_HISTORIC_PAGE_SIZE {
        panic!("Historic data query: page_size exceeds MAX_HISTORIC_PAGE_SIZE");
    }

    let mut ids = Vec::new(env);
    let mut collected: u32 = 0;
    let mut run_id = query.from_run_id;
    while run_id <= query.to_run_id && collected < query.page_size {
        if env.storage().persistent().has(&DataKey::PayrollRun(run_id))
            || env
                .storage()
                .persistent()
                .has(&DataKey::ArchivedRun(run_id))
        {
            ids.push_back(run_id);
            collected += 1;
        }
        run_id += 1;
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn check_access_returns_denied_when_no_admin_configured() {
        let env = Env::default();
        let caller = Address::generate(&env);
        let result = env.as_contract(&env.register(crate::Payroll, ()), || {
            check_access(&env, &caller, HistoricDataScope::Admin)
        });
        assert!(!result.allowed);
        assert_eq!(
            result.denial_reason,
            Some(HistoricDataError::Unauthorized as u32)
        );
    }

    #[test]
    fn check_access_returns_denied_for_audit_authority_when_not_registered() {
        let env = Env::default();
        let caller = Address::generate(&env);
        let result = env.as_contract(&env.register(crate::Payroll, ()), || {
            check_access(&env, &caller, HistoricDataScope::AuditAuthority)
        });
        assert!(!result.allowed);
    }

    #[test]
    fn check_access_returns_allowed_for_registered_audit_authority() {
        let env = Env::default();
        let auditor = Address::generate(&env);
        env.as_contract(&env.register(crate::Payroll, ()), || {
            env.storage()
                .persistent()
                .set(&DataKey::AuditHoldReleaseAuthority(auditor.clone()), &true);
            let result = check_access(&env, &auditor, HistoricDataScope::AuditAuthority);
            assert!(result.allowed);
            assert!(result.denial_reason.is_none());
        });
    }

    #[test]
    #[should_panic(expected = "Historic data access denied: unauthorized for requested scope")]
    fn retrieve_run_ids_panics_on_unauthorized_caller() {
        let env = Env::default();
        let caller = Address::generate(&env);
        let query = HistoricDataQuery {
            from_run_id: 1,
            to_run_id: 10,
            page_size: 10,
            scope: HistoricDataScope::Admin,
        };
        env.as_contract(&env.register(crate::Payroll, ()), || {
            retrieve_run_ids(&env, &caller, query);
        });
    }

    #[test]
    #[should_panic(expected = "Historic data query: from_run_id must be >= 1")]
    fn retrieve_run_ids_panics_on_zero_from_run_id() {
        let env = Env::default();
        let caller = Address::generate(&env);
        env.as_contract(&env.register(crate::Payroll, ()), || {
            env.storage()
                .persistent()
                .set(&DataKey::AuditHoldReleaseAuthority(caller.clone()), &true);
            let query = HistoricDataQuery {
                from_run_id: 0,
                to_run_id: 10,
                page_size: 10,
                scope: HistoricDataScope::AuditAuthority,
            };
            retrieve_run_ids(&env, &caller, query);
        });
    }

    #[test]
    fn retrieve_run_ids_returns_empty_when_no_runs_exist() {
        let env = Env::default();
        let caller = Address::generate(&env);
        env.as_contract(&env.register(crate::Payroll, ()), || {
            env.storage()
                .persistent()
                .set(&DataKey::AuditHoldReleaseAuthority(caller.clone()), &true);
            let query = HistoricDataQuery {
                from_run_id: 1,
                to_run_id: 10,
                page_size: 50,
                scope: HistoricDataScope::AuditAuthority,
            };
            let ids = retrieve_run_ids(&env, &caller, query);
            assert_eq!(ids.len(), 0);
        });
    }
}
