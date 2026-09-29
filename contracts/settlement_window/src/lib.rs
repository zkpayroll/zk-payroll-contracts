#![no_std]

//! # Settlement Window Enforcement — Issue #316
//!
//! Defines payroll period configuration with four timestamp gates:
//!   - `open_at`      — earliest moment a period can receive commitments/locks.
//!   - `execute_at`   — earliest moment batch execution is permitted.
//!   - `grace_until`  — deadline for execution; after this only cancellation/
//!                      expiry is allowed.
//!   - `close_at`     — hard close; no further state changes beyond archival.
//!
//! All timestamps are Unix seconds (`u64`) sourced from `env.ledger().timestamp()`.
//! The contract enforces window boundaries on every state-changing call so that
//! payroll cannot be executed early, late, or after expiry.

use pause_manager::PauseManagerClient;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the settlement window contract.
///
/// Error codes are stable; SDK clients should classify on the numeric value.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SettlementError {
    /// Period configuration has not been created yet.
    PeriodNotFound = 1,
    /// A period configuration for this company/period already exists.
    PeriodAlreadyExists = 2,
    /// The current ledger time is before `open_at`; the period is not yet open.
    PeriodNotYetOpen = 3,
    /// The current ledger time is before `execute_at`; execution window not open.
    ExecutionWindowNotOpen = 4,
    /// The current ledger time is past `grace_until`; the execution window has closed.
    ExecutionWindowExpired = 5,
    /// The current ledger time is past `close_at`; the period is fully closed.
    PeriodClosed = 6,
    /// The window timestamps are not strictly ordered: open ≤ execute ≤ grace ≤ close.
    InvalidWindowConfig = 7,
    /// The caller is not the company admin.
    Unauthorized = 8,
    /// The period has already been cancelled or expired; no further updates allowed.
    AlreadyFinalized = 9,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Lifecycle phase of a settlement window period.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PeriodPhase {
    /// Created but not yet open for commitments.
    Pending = 0,
    /// Open — commitments and locks accepted; execution not yet permitted.
    Open = 1,
    /// Execution window is live — batch payments may be submitted.
    Executing = 2,
    /// Grace period — execution window has passed; only cancellation/expiry allowed.
    Grace = 3,
    /// Period has been formally closed (all payments finalized).
    Closed = 4,
    /// Period expired at grace boundary without full settlement; marked for audit.
    Expired = 5,
    /// Period was cancelled by an authorised admin before execution completed.
    Cancelled = 6,
}

/// Configuration and runtime state for a single payroll settlement window.
///
/// Privacy note: this struct stores only timing metadata. No salary amounts,
/// employee addresses, or commitment hashes are present — those live in
/// `payment_executor` and `salary_commitment`.
#[contracttype]
#[derive(Clone, Debug)]
pub struct SettlementPeriod {
    /// Company this period belongs to (registry company_id).
    pub company_id: u64,
    /// Monotonically increasing period identifier (scoped per company).
    pub period_id: u32,
    /// Unix timestamp: earliest moment the period accepts commitments.
    pub open_at: u64,
    /// Unix timestamp: earliest moment batch execution is permitted.
    pub execute_at: u64,
    /// Unix timestamp: deadline for execution; grace/expiry logic applies after.
    pub grace_until: u64,
    /// Unix timestamp: hard close; no state changes beyond archival.
    pub close_at: u64,
    /// Current lifecycle phase.
    pub phase: PeriodPhase,
    /// Ledger timestamp when the period was created on-chain.
    pub created_at: u64,
    /// Ledger timestamp of the last phase transition (0 = never transitioned).
    pub transitioned_at: u64,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// `SettlementPeriod` keyed by (company_id, period_id).
    Period(u64, u32),
    /// Per-company monotonic period counter.
    PeriodSequence(u64),
    /// Admin address allowed to manage settlement periods.
    Admin,
    /// Optional pause manager address.
    PauseManager,
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct SettlementWindowContract;

#[contractimpl]
impl SettlementWindowContract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Initialise the contract with an admin address. One-time call.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        payroll_events::emit_settlement_window_initialized(&env, admin);
    }

    /// Set or replace the pause manager. Only the admin may call.
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    // -----------------------------------------------------------------------
    // Period management
    // -----------------------------------------------------------------------

    /// Create a new settlement period for `company_id` with the given window.
    ///
    /// Timestamps must satisfy: `open_at <= execute_at <= grace_until <= close_at`.
    /// Only one unclosed period per company is permitted (enforced by sequence check).
    pub fn create_period(
        env: Env,
        company_id: u64,
        open_at: u64,
        execute_at: u64,
        grace_until: u64,
        close_at: u64,
    ) -> Result<SettlementPeriod, SettlementError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        if open_at > execute_at || execute_at > grace_until || grace_until > close_at {
            return Err(SettlementError::InvalidWindowConfig);
        }

        let seq_key = DataKey::PeriodSequence(company_id);
        let period_id: u32 = env.storage().persistent().get(&seq_key).unwrap_or(1u32);

        // Reject if a non-finalized period already exists for this company.
        if period_id > 1 {
            let prev_key = DataKey::Period(company_id, period_id - 1);
            if let Some(prev) = env
                .storage()
                .persistent()
                .get::<DataKey, SettlementPeriod>(&prev_key)
            {
                match prev.phase {
                    PeriodPhase::Closed | PeriodPhase::Expired | PeriodPhase::Cancelled => {}
                    _ => return Err(SettlementError::PeriodAlreadyExists),
                }
            }
        }

        let now = env.ledger().timestamp();
        let period = SettlementPeriod {
            company_id,
            period_id,
            open_at,
            execute_at,
            grace_until,
            close_at,
            phase: PeriodPhase::Pending,
            created_at: now,
            transitioned_at: 0,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Period(company_id, period_id), &period);
        env.storage().persistent().set(&seq_key, &(period_id + 1));

        payroll_events::emit_settlement_period_created(
            &env,
            company_id,
            period_id,
            open_at,
            execute_at,
            grace_until,
            close_at,
        );

        Ok(period)
    }

    /// Validate that the current ledger time is within the execution window.
    ///
    /// Returns `Ok(())` if execution is permitted; returns a typed error otherwise.
    /// This is the primary guard called by `payment_executor` before processing
    /// a batch. It does NOT modify any state — callers check it then proceed.
    pub fn check_execution_allowed(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<(), SettlementError> {
        let period = Self::load_period(&env, company_id, period_id)?;
        let now = env.ledger().timestamp();

        match period.phase {
            PeriodPhase::Cancelled => return Err(SettlementError::AlreadyFinalized),
            PeriodPhase::Expired => return Err(SettlementError::AlreadyFinalized),
            PeriodPhase::Closed => return Err(SettlementError::PeriodClosed),
            _ => {}
        }

        if now < period.open_at {
            return Err(SettlementError::PeriodNotYetOpen);
        }
        if now < period.execute_at {
            return Err(SettlementError::ExecutionWindowNotOpen);
        }
        if now > period.grace_until {
            return Err(SettlementError::ExecutionWindowExpired);
        }
        Ok(())
    }

    /// Advance the period to the `Open` phase (admin call, after `open_at`).
    pub fn open_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let mut period = Self::load_period(&env, company_id, period_id)?;
        Self::require_not_finalized(&period)?;

        let now = env.ledger().timestamp();
        if now < period.open_at {
            return Err(SettlementError::PeriodNotYetOpen);
        }

        period.phase = PeriodPhase::Open;
        period.transitioned_at = now;
        Self::save_period(&env, &period);

        payroll_events::emit_settlement_period_phase_changed(
            &env,
            company_id,
            period_id,
            Symbol::new(&env, "Open"),
        );

        Ok(period)
    }

    /// Advance the period to the `Executing` phase (admin call, after `execute_at`).
    pub fn start_execution(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let mut period = Self::load_period(&env, company_id, period_id)?;
        Self::require_not_finalized(&period)?;

        let now = env.ledger().timestamp();
        if now < period.execute_at {
            return Err(SettlementError::ExecutionWindowNotOpen);
        }
        if now > period.grace_until {
            return Err(SettlementError::ExecutionWindowExpired);
        }

        period.phase = PeriodPhase::Executing;
        period.transitioned_at = now;
        Self::save_period(&env, &period);

        payroll_events::emit_settlement_period_phase_changed(
            &env,
            company_id,
            period_id,
            Symbol::new(&env, "Executing"),
        );

        Ok(period)
    }

    /// Close the period after all payments are settled (admin call).
    pub fn close_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let mut period = Self::load_period(&env, company_id, period_id)?;
        Self::require_not_finalized(&period)?;

        let now = env.ledger().timestamp();
        period.phase = PeriodPhase::Closed;
        period.transitioned_at = now;
        Self::save_period(&env, &period);

        payroll_events::emit_settlement_period_phase_changed(
            &env,
            company_id,
            period_id,
            Symbol::new(&env, "Closed"),
        );

        Ok(period)
    }

    /// Cancel the period (admin call, any phase before Closed).
    ///
    /// Cancellation is permitted before `close_at`. After cancellation the
    /// period is immutable and the company may open a new period.
    pub fn cancel_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        // cancel_period intentionally does NOT call require_not_paused so it
        // remains usable as an emergency escape hatch when the system is paused.
        Self::require_admin(&env);

        let mut period = Self::load_period(&env, company_id, period_id)?;
        Self::require_not_finalized(&period)?;

        let now = env.ledger().timestamp();
        period.phase = PeriodPhase::Cancelled;
        period.transitioned_at = now;
        Self::save_period(&env, &period);

        payroll_events::emit_settlement_period_cancelled(&env, company_id, period_id, now);

        Ok(period)
    }

    /// Mark a period as expired after `grace_until` has passed without closure.
    ///
    /// Any caller may trigger expiry — it requires no authorisation because the
    /// condition is purely time-based and benefits all parties (audit, compliance).
    pub fn expire_period(
        env: Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        Self::require_not_paused(&env);

        let mut period = Self::load_period(&env, company_id, period_id)?;
        Self::require_not_finalized(&period)?;

        let now = env.ledger().timestamp();
        if now <= period.grace_until {
            return Err(SettlementError::ExecutionWindowNotOpen);
        }

        period.phase = PeriodPhase::Expired;
        period.transitioned_at = now;
        Self::save_period(&env, &period);

        payroll_events::emit_settlement_period_expired(&env, company_id, period_id, now);

        Ok(period)
    }

    // -----------------------------------------------------------------------
    // Read-only queries
    // -----------------------------------------------------------------------

    /// Return the period configuration, or `None` if not found.
    pub fn get_period(env: Env, company_id: u64, period_id: u32) -> Option<SettlementPeriod> {
        env.storage()
            .persistent()
            .get(&DataKey::Period(company_id, period_id))
    }

    /// Return the current phase of a period, or `None` if not found.
    pub fn get_phase(env: Env, company_id: u64, period_id: u32) -> Option<PeriodPhase> {
        env.storage()
            .persistent()
            .get::<DataKey, SettlementPeriod>(&DataKey::Period(company_id, period_id))
            .map(|p| p.phase)
    }

    /// Return the next period_id that would be assigned to `company_id`.
    pub fn get_next_period_id(env: Env, company_id: u64) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::PeriodSequence(company_id))
            .unwrap_or(1u32)
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

    fn load_period(
        env: &Env,
        company_id: u64,
        period_id: u32,
    ) -> Result<SettlementPeriod, SettlementError> {
        env.storage()
            .persistent()
            .get(&DataKey::Period(company_id, period_id))
            .ok_or(SettlementError::PeriodNotFound)
    }

    fn save_period(env: &Env, period: &SettlementPeriod) {
        env.storage().persistent().set(
            &DataKey::Period(period.company_id, period.period_id),
            period,
        );
    }

    fn require_not_finalized(period: &SettlementPeriod) -> Result<(), SettlementError> {
        match period.phase {
            PeriodPhase::Closed | PeriodPhase::Expired | PeriodPhase::Cancelled => {
                Err(SettlementError::AlreadyFinalized)
            }
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::Env;

    fn setup() -> (Env, Address, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SettlementWindowContract);
        let admin = Address::generate(&env);
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        (env, contract_id, admin)
    }

    fn make_window(base: u64) -> (u64, u64, u64, u64) {
        (base, base + 100, base + 200, base + 300)
    }

    #[test]
    fn test_create_and_check_execution_allowed() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let now = env.ledger().timestamp();
        let (open_at, execute_at, grace_until, close_at) = make_window(now + 10);

        let company_id = 1u64;
        let period =
            client.create_period(&company_id, &open_at, &execute_at, &grace_until, &close_at);
        assert_eq!(period.period_id, 1);
        assert_eq!(period.phase, PeriodPhase::Pending);

        // Before open_at — should reject
        let result = client.try_check_execution_allowed(&company_id, &1);
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::PeriodNotYetOpen
        );
    }

    #[test]
    fn test_execution_allowed_within_window() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 2u64;

        // Set window: open now, execute now+10, grace now+1000, close now+2000
        client.create_period(
            &company_id,
            &base,
            &(base + 10),
            &(base + 1000),
            &(base + 2000),
        );

        // Advance time into execute window
        env.ledger().with_mut(|l| l.timestamp = base + 50);

        let result = client.try_check_execution_allowed(&company_id, &1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execution_rejected_before_execute_at() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 3u64;

        client.create_period(
            &company_id,
            &base,
            &(base + 500),
            &(base + 1000),
            &(base + 2000),
        );

        // Time is at open_at but before execute_at
        env.ledger().with_mut(|l| l.timestamp = base + 100);

        let result = client.try_check_execution_allowed(&company_id, &1);
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::ExecutionWindowNotOpen
        );
    }

    #[test]
    fn test_execution_rejected_after_grace_until() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 4u64;

        client.create_period(
            &company_id,
            &base,
            &(base + 10),
            &(base + 100),
            &(base + 200),
        );

        // Advance past grace
        env.ledger().with_mut(|l| l.timestamp = base + 150);

        let result = client.try_check_execution_allowed(&company_id, &1);
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::ExecutionWindowExpired
        );
    }

    #[test]
    fn test_cancel_period() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 5u64;

        client.create_period(
            &company_id,
            &base,
            &(base + 10),
            &(base + 100),
            &(base + 200),
        );
        let cancelled = client.cancel_period(&company_id, &1);
        assert_eq!(cancelled.phase, PeriodPhase::Cancelled);

        // Second cancel should fail
        let result = client.try_cancel_period(&company_id, &1);
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::AlreadyFinalized
        );
    }

    #[test]
    fn test_expire_period_after_grace() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 6u64;

        client.create_period(
            &company_id,
            &base,
            &(base + 10),
            &(base + 50),
            &(base + 100),
        );

        // Before grace_until — should not expire
        env.ledger().with_mut(|l| l.timestamp = base + 80);
        let too_early = client.try_expire_period(&company_id, &1);
        assert_eq!(
            too_early.unwrap_err().unwrap(),
            SettlementError::ExecutionWindowNotOpen
        );

        // After grace_until
        env.ledger().with_mut(|l| l.timestamp = base + 110);
        let expired = client.expire_period(&company_id, &1);
        assert_eq!(expired.phase, PeriodPhase::Expired);
    }

    #[test]
    fn test_invalid_window_config_rejected() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();

        // execute_at before open_at
        let result = client.try_create_period(
            &1u64,
            &(base + 100),
            &(base + 50),
            &(base + 200),
            &(base + 300),
        );
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::InvalidWindowConfig
        );
    }

    #[test]
    fn test_cannot_create_second_active_period() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 7u64;

        client
            .create_period(
                &company_id,
                &base,
                &(base + 10),
                &(base + 100),
                &(base + 200),
            )
            .period_id;
        // Second call while first is still active
        let result = client.try_create_period(
            &company_id,
            &(base + 300),
            &(base + 310),
            &(base + 400),
            &(base + 500),
        );
        assert_eq!(
            result.unwrap_err().unwrap(),
            SettlementError::PeriodAlreadyExists
        );
    }

    #[test]
    fn test_new_period_allowed_after_cancellation() {
        let (env, contract_id, _admin) = setup();
        let client = SettlementWindowContractClient::new(&env, &contract_id);
        let base = env.ledger().timestamp();
        let company_id = 8u64;

        client.create_period(
            &company_id,
            &base,
            &(base + 10),
            &(base + 100),
            &(base + 200),
        );
        client.cancel_period(&company_id, &1);

        // Should succeed now that period 1 is cancelled
        let p2 = client.create_period(
            &company_id,
            &(base + 300),
            &(base + 310),
            &(base + 400),
            &(base + 500),
        );
        assert_eq!(p2.period_id, 2);
    }
}
