#![cfg(test)]

use payroll::{Payroll, PayrollClient, ReconciliationStatus};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, BytesN, Env, Symbol, TryIntoVal, Val, Vec};
use token::{Token, TokenClient};

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
    reviewer: Address,
    employee: Address,
}

fn setup() -> TestContext<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let reviewer = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier = ProofVerifierClient::new(&env, &verifier_id);
    verifier.init_verifier_admin(&admin);
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);
    let token = TokenClient::new(&env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_id);
    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &Address::generate(&env),
    );
    commitment.set_payroll_operator(&payroll_id);

    let mut blinding = [0u8; 32];
    blinding[31] = 123;
    let commitment_value =
        commitment.compute_commitment(&5000u64, &BytesN::from_array(&env, &blinding));
    commitment.store_commitment(&employee, &commitment_value);
    payroll.add_reviewer(&admin, &reviewer);
    token.mint(&treasury, &10_000i128);

    TestContext {
        env,
        payroll,
        admin,
        reviewer,
        employee,
    }
}

fn event_name(env: &Env, event: &(Address, Vec<Val>, Val)) -> Option<Symbol> {
    let topics = &event.1;
    if topics.len() < 2 {
        return None;
    }
    let domain: Symbol = topics.get(0).unwrap().try_into_val(env).ok()?;
    if domain != Symbol::new(env, "payroll") {
        return None;
    }
    let name: Symbol = topics.get(1).unwrap().try_into_val(env).ok()?;
    if name == Symbol::new(env, "run_state") {
        return None;
    }
    Some(name)
}

fn payroll_event_names(env: &Env) -> Vec<Symbol> {
    let mut names = Vec::new(env);
    for event in env.events().all().iter() {
        if let Some(name) = event_name(env, &event) {
            names.push_back(name);
        }
    }
    names
}

fn nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    BytesN::from_array(env, &bytes)
}

#[test]
fn payroll_events_follow_lifecycle_order() {
    let ctx = setup();
    let env = &ctx.env;

    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[0u8; 256])]);
    let amounts = Vec::from_array(env, [5000i128]);
    let employees = Vec::from_array(env, [ctx.employee.clone()]);

    let prepared_run = ctx.payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &5000,
        &nonce(env, 1),
        &None,
    );
    ctx.payroll
        .approve_payroll_run(&ctx.reviewer, &prepared_run);

    let executed_run = ctx.payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &5000,
        &nonce(env, 2),
        &None,
    );
    ctx.payroll.update_reconciliation_status(
        &ctx.admin,
        &executed_run,
        &ReconciliationStatus::Reconciled,
    );
    let settled_event_count = env.events().all().len();
    assert!(
        ctx.payroll
            .try_update_reconciliation_status(
                &ctx.admin,
                &executed_run,
                &ReconciliationStatus::Reconciled,
            )
            .is_err(),
        "settlement replay must fail"
    );
    assert_eq!(
        env.events().all().len(),
        settled_event_count,
        "settlement replay must not emit another event"
    );

    let names = payroll_event_names(env);
    let expected = Vec::from_array(
        env,
        [
            Symbol::new(env, "run_prepared"),
            Symbol::new(env, "run_approved"),
            Symbol::new(env, "payment_executed"),
            Symbol::new(env, "run_executed"),
            Symbol::new(env, "reconciliation_updated"),
        ],
    );
    assert!(
        names.len() >= expected.len(),
        "payroll lifecycle events missing"
    );
    let start = names.len() - expected.len();
    for index in 0..expected.len() {
        assert_eq!(
            names.get(start + index).unwrap(),
            expected.get(index).unwrap(),
            "payroll lifecycle event order changed at index {}",
            index
        );
    }
}

#[test]
fn unauthorized_approval_emits_no_approval_event() {
    let ctx = setup();
    let env = &ctx.env;
    let unauthorized = Address::generate(env);
    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[0u8; 256])]);
    let amounts = Vec::from_array(env, [5000i128]);
    let employees = Vec::from_array(env, [ctx.employee.clone()]);
    let run_id = ctx.payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &5000,
        &nonce(env, 3),
        &None,
    );
    let event_count = env.events().all().len();

    assert!(
        ctx.payroll
            .try_approve_payroll_run(&unauthorized, &run_id)
            .is_err(),
        "unauthorized approval must fail"
    );
    assert_eq!(
        env.events().all().len(),
        event_count,
        "failed approval must not emit an event"
    );
}
