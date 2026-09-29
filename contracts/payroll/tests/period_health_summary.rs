//! Tests for Issue #552: Expose payroll period health summary.
//!
//! Covers:
//! - Operational health states: Healthy, Warning, Blocked.
//! - Actionable reasons: Normal, PreOpen, GracePeriod, WindowClosed, ContractPaused, PeriodFrozen, CapacityExceeded.
//! - Non-leaking privacy guarantees: only operational metrics and aggregate counts exposed.
//! - Validation and edge cases: empty period symbol rejection, unconfigured periods, active drafts.

#![cfg(test)]

use ::token::{Token, TokenClient};
use pause_manager::{PauseManager, PauseManagerClient};
use payroll::{
    CapacityLimits, Payroll, PayrollClient, PeriodHealthReason, PeriodHealthStatus,
    SettlementWindowStatus,
};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

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

struct TestContext<'a> {
    env: Env,
    payroll: PayrollClient<'a>,
    admin: Address,
    treasury: Address,
    treasury_owner: Address,
    employee: Address,
    pause_manager_client: PauseManagerClient<'a>,
    import_source: Address,
}

fn setup_payroll(env: &Env) -> TestContext {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);
    token_client.mint(&treasury, &1_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    let pause_manager_id = env.register_contract(None, PauseManager);
    let pause_manager_client = PauseManagerClient::new(env, &pause_manager_id);
    pause_manager_client.initialize(&admin);
    payroll_client.set_pause_manager(&admin, &pause_manager_id);

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

    let import_source = Address::generate(env);
    payroll_client.register_import_source(&import_source, &0u32);

    TestContext {
        env: env.clone(),
        payroll: payroll_client,
        admin,
        treasury,
        treasury_owner,
        employee,
        pause_manager_client,
        import_source,
    }
}

fn set_timestamp(env: &Env, ts: u64) {
    env.ledger().with_mut(|li| {
        li.timestamp = ts;
    });
}

const OPEN_AT: u64 = 1_000;
const EXEC_START: u64 = 2_000;
const EXEC_END: u64 = 3_000;
const CLOSE_AT: u64 = 4_000;

#[test]
fn test_period_health_summary_fresh_period_healthy() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let period = Symbol::new(&env, "2026_Q1");

    ctx.payroll.open_capacity_period(&ctx.admin, &period);

    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.period, period);
    assert_eq!(summary.status, PeriodHealthStatus::Healthy);
    assert_eq!(summary.reason, PeriodHealthReason::Normal);
    assert!(summary.is_current_period);
    assert!(summary.can_execute);
    assert!(!summary.is_frozen);
    assert!(!summary.is_paused);
    assert!(!summary.has_active_draft);
    assert_eq!(summary.window_status, None);
    assert!(!summary.capacity_configured);
    assert_eq!(summary.batch_count, 0);
    assert_eq!(summary.employee_count, 0);
    assert!(!summary.capacity_exceeded);
}

#[test]
fn test_period_health_summary_settlement_window_lifecycle() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let period = Symbol::new(&env, "2026_Q2");

    ctx.payroll.open_capacity_period(&ctx.admin, &period);
    ctx.payroll.set_settlement_window(
        &ctx.admin,
        &period,
        &OPEN_AT,
        &EXEC_START,
        &EXEC_END,
        &CLOSE_AT,
    );

    // 1. PreOpen phase: now = 1500 (between OPEN_AT and EXEC_START)
    set_timestamp(&env, 1_500);
    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.status, PeriodHealthStatus::Blocked);
    assert_eq!(summary.reason, PeriodHealthReason::PreOpen);
    assert!(!summary.can_execute);
    assert_eq!(
        summary.window_status,
        Some(SettlementWindowStatus::PreOpen as u32)
    );

    // 2. Executable phase: now = 2500 (between EXEC_START and EXEC_END)
    set_timestamp(&env, 2_500);
    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.status, PeriodHealthStatus::Healthy);
    assert_eq!(summary.reason, PeriodHealthReason::Normal);
    assert!(summary.can_execute);
    assert_eq!(
        summary.window_status,
        Some(SettlementWindowStatus::Executable as u32)
    );

    // 3. Grace phase: now = 3500 (between EXEC_END and CLOSE_AT)
    set_timestamp(&env, 3_500);
    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.status, PeriodHealthStatus::Warning);
    assert_eq!(summary.reason, PeriodHealthReason::GracePeriod);
    assert!(!summary.can_execute);
    assert_eq!(
        summary.window_status,
        Some(SettlementWindowStatus::Grace as u32)
    );

    // 4. Closed phase: now = 4500 (past CLOSE_AT)
    set_timestamp(&env, 4_500);
    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.status, PeriodHealthStatus::Blocked);
    assert_eq!(summary.reason, PeriodHealthReason::WindowClosed);
    assert!(!summary.can_execute);
    assert_eq!(
        summary.window_status,
        Some(SettlementWindowStatus::Closed as u32)
    );
}

#[test]
fn test_period_health_summary_contract_paused_blocks_execution() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let period = Symbol::new(&env, "2026_Q3");

    ctx.payroll.open_capacity_period(&ctx.admin, &period);

    // Pause contract
    ctx.pause_manager_client.pause(&ctx.admin);

    let summary = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary.status, PeriodHealthStatus::Blocked);
    assert_eq!(summary.reason, PeriodHealthReason::ContractPaused);
    assert!(summary.is_paused);
    assert!(!summary.can_execute);

    // Unpause contract
    ctx.pause_manager_client.unpause(&ctx.admin);

    let summary_unpaused = ctx.payroll.get_period_health_summary(&period);
    assert_eq!(summary_unpaused.status, PeriodHealthStatus::Healthy);
    assert_eq!(summary_unpaused.reason, PeriodHealthReason::Normal);
    assert!(!summary_unpaused.is_paused);
    assert!(summary_unpaused.can_execute);
}

#[test]
fn test_period_health_summary_frozen_period_warning() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let period = Symbol::new(&env, "2026_Q4");

    ctx.payroll.open_capacity_period(&ctx.admin, &period);
    ctx.payroll.freeze_period_config(&ctx.admin, &period);

    let summary = ctx.payroll.get_period_health_summary(&period);
    assert!(summary.is_frozen);
    assert_eq!(summary.status, PeriodHealthStatus::Warning);
    assert_eq!(summary.reason, PeriodHealthReason::PeriodFrozen);
}

#[test]
fn test_period_health_summary_capacity_limits_and_exhaustion() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let period = Symbol::new(&env, "2026_M05");

    ctx.payroll.open_capacity_period(&ctx.admin, &period);

    // Set capacity limits: max 1 batch, 10 employees, 1000 total value
    ctx.payroll.set_capacity_limits(&ctx.admin, &1, &10, &1_000);

    let summary = ctx.payroll.get_period_health_summary(&period);
    assert!(summary.capacity_configured);
    assert!(!summary.capacity_exceeded);
    assert_eq!(summary.status, PeriodHealthStatus::Healthy);
    assert!(summary.can_execute);

    // Execute one payment batch to exhaust the 1-batch capacity limit
    let mut proofs = Vec::new(&env);
    proofs.push_back(mock_proof(&env));
    let mut amounts = Vec::new(&env);
    amounts.push_back(100i128);
    let mut employees = Vec::new(&env);
    employees.push_back(ctx.employee.clone());

    ctx.payroll.batch_process_payroll(
        &ctx.admin,
        &proofs,
        &amounts,
        &employees,
        &100i128,
        &test_nonce(&env, 1),
    );

    let summary_after = ctx.payroll.get_period_health_summary(&period);
    assert!(summary_after.capacity_configured);
    assert!(summary_after.capacity_exceeded);
    assert_eq!(summary_after.batch_count, 1);
    assert_eq!(summary_after.employee_count, 1);
    assert_eq!(summary_after.status, PeriodHealthStatus::Blocked);
    assert_eq!(
        summary_after.reason,
        PeriodHealthReason::BatchCapacityExceeded
    );
    assert!(!summary_after.can_execute);
}

#[test]
#[should_panic(expected = "Symbol cannot be empty")]
fn test_period_health_summary_rejects_empty_symbol() {
    let env = Env::default();
    let ctx = setup_payroll(&env);
    let empty_period = Symbol::new(&env, "");
    ctx.payroll.get_period_health_summary(&empty_period);
}
