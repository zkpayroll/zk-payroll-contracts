//! Execution start boundary for settlement windows (#872).
//!
//! Settlement attempts before the period's start must be rejected in both the
//! contract guard (`check_execution_allowed`) and the admin transition
//! (`start_execution`). These tests pin the exact boundary second.

extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SettlementWindowContract, ());
    let admin = Address::generate(&env);
    SettlementWindowContractClient::new(&env, &contract_id).initialize(&admin);
    (env, contract_id)
}

/// Creates period 1 for company 1 with open_at = now + 100, execute_at = now + 200.
fn create_period(env: &Env, contract_id: &Address) -> (u64, u64) {
    let client = SettlementWindowContractClient::new(env, contract_id);
    let now = env.ledger().timestamp();
    let open_at = now + 100;
    let execute_at = now + 200;
    let grace_until = now + 300;
    let close_at = now + 400;
    client.create_period(&1u64, &open_at, &execute_at, &grace_until, &close_at);
    (open_at, execute_at)
}

#[test]
fn settlement_rejected_one_second_before_open_at() {
    let (env, contract_id) = setup();
    let (open_at, _) = create_period(&env, &contract_id);
    let client = SettlementWindowContractClient::new(&env, &contract_id);

    env.ledger().set_timestamp(open_at - 1);

    assert_eq!(
        client.try_check_execution_allowed(&1u64, &1u32).unwrap_err().unwrap(),
        SettlementError::PeriodNotYetOpen
    );
    assert_eq!(
        client.try_start_execution(&1u64, &1u32).unwrap_err().unwrap(),
        SettlementError::ExecutionWindowNotOpen
    );
}

#[test]
fn settlement_rejected_one_second_before_execute_at_and_allowed_at_it() {
    let (env, contract_id) = setup();
    let (_, execute_at) = create_period(&env, &contract_id);
    let client = SettlementWindowContractClient::new(&env, &contract_id);

    env.ledger().set_timestamp(execute_at - 1);
    assert_eq!(
        client.try_check_execution_allowed(&1u64, &1u32).unwrap_err().unwrap(),
        SettlementError::ExecutionWindowNotOpen
    );

    env.ledger().set_timestamp(execute_at);
    client.check_execution_allowed(&1u64, &1u32);
}

#[test]
fn start_execution_accepted_exactly_at_execute_at() {
    let (env, contract_id) = setup();
    let (_, execute_at) = create_period(&env, &contract_id);
    let client = SettlementWindowContractClient::new(&env, &contract_id);

    env.ledger().set_timestamp(execute_at - 1);
    assert_eq!(
        client.try_start_execution(&1u64, &1u32).unwrap_err().unwrap(),
        SettlementError::ExecutionWindowNotOpen
    );

    env.ledger().set_timestamp(execute_at);
    let period = client.start_execution(&1u64, &1u32);
    assert_eq!(period.phase, PeriodPhase::Executing);
}
