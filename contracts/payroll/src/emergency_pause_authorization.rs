//! Emergency payroll pause authorization (#698)
//!
//! Provides authorization logic, multi-role guardian control, scope management,
//! and assertion primitives to immediately halt payroll execution during emergencies
//! while preserving transparency and auditability.

#![no_std]

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Error codes for emergency pause operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EmergencyPauseError {
    /// Caller is not authorized as an emergency guardian or contract admin.
    UnauthorizedCaller = 1,
    /// The specified payroll scope is already paused.
    AlreadyPaused = 2,
    /// The specified payroll scope is not currently paused.
    NotPaused = 3,
    /// Invalid pause scope configuration.
    InvalidScope = 4,
    /// The pause duration has exceeded maximum permitted bounds.
    PauseDurationExpired = 5,
    /// Configuration contains invalid parameters (e.g. missing admin).
    InvalidConfiguration = 6,
    /// Execution blocked due to an active emergency pause.
    ExecutionPaused = 7,
}

/// Scope of an emergency pause.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EmergencyPauseScope {
    /// Pauses all payroll executions contract-wide.
    Global = 1,
    /// Pauses payouts specifically for a given payroll run / period ID.
    RunOnly = 2,
    /// Pauses execution specifically for a given batch ID.
    BatchOnly = 3,
}

/// Role classification for pause authorizations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum EmergencyRole {
    /// Emergency guardian permitted to trigger fast-path pause.
    Guardian = 1,
    /// Contract administrator permitted to pause, unpause, and reconfigure.
    Admin = 2,
    /// No emergency authority.
    Unauthorized = 3,
}

/// Configuration defining emergency pause authority.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyPauseConfig {
    /// Primary contract admin address (authorized to pause and unpause)
    pub admin: Address,
    /// List of emergency guardians authorized to trigger fast-path emergency pause
    pub guardians: Vec<Address>,
    /// Maximum duration in seconds that a pause remains active before auto-expiring (0 = indefinite)
    pub max_pause_duration_secs: u64,
}

/// Runtime state of emergency pause.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyPauseState {
    /// True if an emergency pause is currently in effect
    pub is_paused: bool,
    /// Address that triggered the emergency pause
    pub paused_by: Address,
    /// Unix timestamp when pause was enacted
    pub paused_at: u64,
    /// Active pause scope
    pub scope: EmergencyPauseScope,
    /// Target identifier (run_id or batch_id) when scope is RunOnly or BatchOnly
    pub target_id: u64,
    /// Standardized reason code explaining why pause was enacted
    pub reason_code: u32,
}

/// Validates that an emergency pause configuration is well-formed.
pub fn validate_emergency_config(config: &EmergencyPauseConfig) -> Result<(), EmergencyPauseError> {
    // Admin address must be set (guaranteed by soroban address type).
    Ok(())
}

/// Resolves the emergency role of a caller.
pub fn resolve_emergency_role(config: &EmergencyPauseConfig, caller: &Address) -> EmergencyRole {
    if *caller == config.admin {
        return EmergencyRole::Admin;
    }

    for guardian in config.guardians.iter() {
        if guardian == *caller {
            return EmergencyRole::Guardian;
        }
    }

    EmergencyRole::Unauthorized
}

/// Creates a default initialized unpaused state.
pub fn initialize_pause_state(env: &Env, admin: Address) -> EmergencyPauseState {
    EmergencyPauseState {
        is_paused: false,
        paused_by: admin,
        paused_at: 0,
        scope: EmergencyPauseScope::Global,
        target_id: 0,
        reason_code: 0,
    }
}

/// Authorizes and executes an emergency pause.
/// Can be invoked by contract admin or any registered emergency guardian.
pub fn execute_emergency_pause(
    env: &Env,
    config: &EmergencyPauseConfig,
    state: &mut EmergencyPauseState,
    caller: Address,
    scope: EmergencyPauseScope,
    target_id: u64,
    reason_code: u32,
) -> Result<(), EmergencyPauseError> {
    let role = resolve_emergency_role(config, &caller);
    if role == EmergencyRole::Unauthorized {
        return Err(EmergencyPauseError::UnauthorizedCaller);
    }

    if state.is_paused {
        return Err(EmergencyPauseError::AlreadyPaused);
    }

    state.is_paused = true;
    state.paused_by = caller;
    state.paused_at = env.ledger().timestamp();
    state.scope = scope;
    state.target_id = target_id;
    state.reason_code = reason_code;

    Ok(())
}

/// Authorizes and executes unpausing.
/// Only the contract admin can unpause to resume payroll operations.
pub fn execute_emergency_unpause(
    _env: &Env,
    config: &EmergencyPauseConfig,
    state: &mut EmergencyPauseState,
    caller: Address,
) -> Result<(), EmergencyPauseError> {
    if caller != config.admin {
        return Err(EmergencyPauseError::UnauthorizedCaller);
    }

    if !state.is_paused {
        return Err(EmergencyPauseError::NotPaused);
    }

    state.is_paused = false;
    state.scope = EmergencyPauseScope::Global;
    state.target_id = 0;
    state.reason_code = 0;

    Ok(())
}

/// Evaluates whether an operation matching run_id and batch_id is currently paused.
pub fn is_payroll_operation_paused(
    env: &Env,
    config: &EmergencyPauseConfig,
    state: &EmergencyPauseState,
    run_id: u64,
    batch_id: u64,
) -> bool {
    if !state.is_paused {
        return false;
    }

    // Check expiration if configured
    if config.max_pause_duration_secs > 0 {
        let elapsed = env.ledger().timestamp().saturating_sub(state.paused_at);
        if elapsed > config.max_pause_duration_secs {
            return false;
        }
    }

    match state.scope {
        EmergencyPauseScope::Global => true,
        EmergencyPauseScope::RunOnly => state.target_id == run_id,
        EmergencyPauseScope::BatchOnly => state.target_id == batch_id,
    }
}

/// Enforces that payroll execution is not currently paused.
/// Throws `EmergencyPauseError::ExecutionPaused` if paused.
pub fn assert_payroll_not_paused(
    env: &Env,
    config: &EmergencyPauseConfig,
    state: &EmergencyPauseState,
    run_id: u64,
    batch_id: u64,
) -> Result<(), EmergencyPauseError> {
    if is_payroll_operation_paused(env, config, state, run_id, batch_id) {
        Err(EmergencyPauseError::ExecutionPaused)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env, Vec,
    };

    fn setup_test_config(env: &Env) -> (EmergencyPauseConfig, Address, Address, Address) {
        let admin = Address::generate(env);
        let guardian = Address::generate(env);
        let stranger = Address::generate(env);

        let mut guardians = Vec::new(env);
        guardians.push_back(guardian.clone());

        let config = EmergencyPauseConfig {
            admin: admin.clone(),
            guardians,
            max_pause_duration_secs: 3600,
        };

        (config, admin, guardian, stranger)
    }

    #[test]
    fn test_guardian_can_trigger_emergency_pause() {
        let env = Env::default();
        let (config, admin, guardian, _stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin.clone());

        assert!(!state.is_paused);
        assert!(assert_payroll_not_paused(&env, &config, &state, 1, 1).is_ok());

        // Guardian triggers pause
        let result = execute_emergency_pause(
            &env,
            &config,
            &mut state,
            guardian.clone(),
            EmergencyPauseScope::Global,
            0,
            100, // reason: anomaly detected
        );

        assert!(result.is_ok());
        assert!(state.is_paused);
        assert_eq!(state.paused_by, guardian);
        assert_eq!(
            assert_payroll_not_paused(&env, &config, &state, 1, 1),
            Err(EmergencyPauseError::ExecutionPaused)
        );
    }

    #[test]
    fn test_admin_can_unpause() {
        let env = Env::default();
        let (config, admin, guardian, _stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin.clone());

        execute_emergency_pause(
            &env,
            &config,
            &mut state,
            guardian,
            EmergencyPauseScope::Global,
            0,
            100,
        )
        .unwrap();

        assert!(state.is_paused);

        // Admin unpauses
        let unpause_res = execute_emergency_unpause(&env, &config, &mut state, admin);
        assert!(unpause_res.is_ok());
        assert!(!state.is_paused);
        assert!(assert_payroll_not_paused(&env, &config, &state, 1, 1).is_ok());
    }

    #[test]
    fn test_unauthorized_caller_cannot_pause_or_unpause() {
        let env = Env::default();
        let (config, admin, guardian, stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin);

        // Stranger fails to pause
        let res = execute_emergency_pause(
            &env,
            &config,
            &mut state,
            stranger.clone(),
            EmergencyPauseScope::Global,
            0,
            100,
        );
        assert_eq!(res, Err(EmergencyPauseError::UnauthorizedCaller));
        assert!(!state.is_paused);

        // Guardian pauses
        execute_emergency_pause(
            &env,
            &config,
            &mut state,
            guardian.clone(),
            EmergencyPauseScope::Global,
            0,
            100,
        )
        .unwrap();

        // Guardian cannot unpause (only admin)
        assert_eq!(
            execute_emergency_unpause(&env, &config, &mut state, guardian),
            Err(EmergencyPauseError::UnauthorizedCaller)
        );

        // Stranger cannot unpause
        assert_eq!(
            execute_emergency_unpause(&env, &config, &mut state, stranger),
            Err(EmergencyPauseError::UnauthorizedCaller)
        );
    }

    #[test]
    fn test_cannot_pause_twice_or_unpause_when_not_paused() {
        let env = Env::default();
        let (config, admin, _guardian, _stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin.clone());

        // Unpause when not paused
        assert_eq!(
            execute_emergency_unpause(&env, &config, &mut state, admin.clone()),
            Err(EmergencyPauseError::NotPaused)
        );

        // First pause succeeds
        execute_emergency_pause(
            &env,
            &config,
            &mut state,
            admin.clone(),
            EmergencyPauseScope::Global,
            0,
            1,
        )
        .unwrap();

        // Duplicate pause fails
        assert_eq!(
            execute_emergency_pause(
                &env,
                &config,
                &mut state,
                admin,
                EmergencyPauseScope::Global,
                0,
                1
            ),
            Err(EmergencyPauseError::AlreadyPaused)
        );
    }

    #[test]
    fn test_run_specific_pause_scope() {
        let env = Env::default();
        let (config, admin, guardian, _stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin);

        // Pause specifically for run 42
        execute_emergency_pause(
            &env,
            &config,
            &mut state,
            guardian,
            EmergencyPauseScope::RunOnly,
            42,
            200,
        )
        .unwrap();

        // Run 42 is blocked
        assert_eq!(
            assert_payroll_not_paused(&env, &config, &state, 42, 1),
            Err(EmergencyPauseError::ExecutionPaused)
        );

        // Other runs (e.g. 43) are NOT blocked
        assert!(assert_payroll_not_paused(&env, &config, &state, 43, 1).is_ok());
    }

    #[test]
    fn test_pause_duration_expiry() {
        let env = Env::default();
        let (config, admin, guardian, _stranger) = setup_test_config(&env);
        let mut state = initialize_pause_state(&env, admin);

        execute_emergency_pause(
            &env,
            &config,
            &mut state,
            guardian,
            EmergencyPauseScope::Global,
            0,
            1,
        )
        .unwrap();

        assert_eq!(
            assert_payroll_not_paused(&env, &config, &state, 1, 1),
            Err(EmergencyPauseError::ExecutionPaused)
        );

        // Advance ledger past max_pause_duration_secs (3600s)
        env.ledger().set_timestamp(env.ledger().timestamp() + 3601);

        // Pause auto-expired, execution is unblocked
        assert!(assert_payroll_not_paused(&env, &config, &state, 1, 1).is_ok());
    }
}
