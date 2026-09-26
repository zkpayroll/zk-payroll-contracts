//! Payroll period configuration freeze guard tests (#248).
//!
//! Covers: editable periods still accept configuration edits, explicit admin
//! freezes block further edits, settlement-ready periods are implicitly
//! frozen, submitting a run freezes the period it was prepared under, and
//! non-admin freeze attempts are rejected.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, PeriodConfigState, SettlementWindowStatus};
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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
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
fn editable_period_allows_configuration_edits() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_a");

    set_timestamp(&env, OPEN_AT);
    payroll.open_capacity_period(&admin, &period);
    payroll.set_settlement_window(&admin, &period, &OPEN_AT, &EXEC_START, &EXEC_END, &CLOSE_AT);

    assert!(!payroll.is_period_config_frozen(&period));
    assert_eq!(
        payroll.get_period_config_state(&period),
        PeriodConfigState::Editable
    );

    // A second edit while still pre-open succeeds.
    payroll.set_settlement_window(
        &admin,
        &period,
        &OPEN_AT,
        &EXEC_START,
        &(EXEC_END + 10),
        &(CLOSE_AT + 10),
    );
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::PreOpen)
    );
    assert!(!payroll.is_period_config_frozen(&period));
}

#[test]
fn explicit_freeze_blocks_further_edits() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_b");

    set_timestamp(&env, OPEN_AT);
    payroll.open_capacity_period(&admin, &period);
    payroll.set_settlement_window(&admin, &period, &OPEN_AT, &EXEC_START, &EXEC_END, &CLOSE_AT);

    payroll.freeze_period_config(&admin, &period);

    assert!(payroll.is_period_config_frozen(&period));
    assert_eq!(
        payroll.get_period_config_state(&period),
        PeriodConfigState::Frozen
    );

    let result = payroll.try_set_settlement_window(
        &admin,
        &period,
        &OPEN_AT,
        &EXEC_START,
        &(EXEC_END + 1),
        &CLOSE_AT,
    );
    assert!(result.is_err());
}

#[test]
fn settlement_ready_period_is_implicitly_frozen() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_c");

    set_timestamp(&env, OPEN_AT);
    payroll.open_capacity_period(&admin, &period);
    payroll.set_settlement_window(&admin, &period, &OPEN_AT, &EXEC_START, &EXEC_END, &CLOSE_AT);

    // Reach the execution window: the period is now settlement-ready.
    set_timestamp(&env, EXEC_START);
    assert_eq!(
        payroll.get_settlement_window_status(&period),
        Some(SettlementWindowStatus::Executable)
    );
    assert!(payroll.is_period_config_frozen(&period));
    // No explicit freeze marker was recorded.
    assert_eq!(
        payroll.get_period_config_state(&period),
        PeriodConfigState::Editable
    );

    let result = payroll.try_set_settlement_window(
        &admin,
        &period,
        &OPEN_AT,
        &(EXEC_START + 1),
        &EXEC_END,
        &CLOSE_AT,
    );
    assert!(result.is_err());
}

#[test]
fn submitted_run_freezes_period_configuration() {
    let env = Env::default();
    let (payroll, admin, _treasury, _owner, employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_d");

    set_timestamp(&env, EXEC_START);
    payroll.open_capacity_period(&admin, &period);
    payroll.set_settlement_window(&admin, &period, &OPEN_AT, &EXEC_START, &EXEC_END, &CLOSE_AT);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 7);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);
    assert!(run_id > 0);

    assert!(payroll.is_period_config_frozen(&period));

    let result = payroll.try_set_settlement_window(
        &admin,
        &period,
        &OPEN_AT,
        &EXEC_START,
        &(EXEC_END + 1),
        &CLOSE_AT,
    );
    assert!(result.is_err());
}

#[test]
fn non_admin_cannot_freeze_period() {
    let env = Env::default();
    let (payroll, _admin, _treasury, _owner, _employee) = setup_payroll(&env);
    let period = Symbol::new(&env, "period_e");
    let stranger = Address::generate(&env);

    let result = payroll.try_freeze_period_config(&stranger, &period);
    assert!(result.is_err());
}
