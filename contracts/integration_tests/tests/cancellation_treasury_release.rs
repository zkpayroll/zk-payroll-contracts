//! Issue #828: cancellation and explicit reserve release across real contracts.
//!
//! Payroll's internal lock and treasury_isolation's accounting reserve are
//! independent. These tests exercise the operator's two-call workflow without
//! inventing an automatic release or a test-only coordinating contract.

use payroll::{Payroll, PayrollClient, PayrollRunState};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    xdr::{ContractEvent, ContractEventBody, ScVal},
    Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};
use token::{Token, TokenClient};
use treasury_isolation::{
    TreasuryIsolationContract, TreasuryIsolationContractClient, TreasuryIsolationError,
};

const COMPANY: u64 = 10;
const OTHER_COMPANY: u64 = 11;
const BALANCE: i128 = 10_000;

struct Fixture {
    env: Env,
    admin: Address,
    operator: Address,
    payroll: Address,
    isolation: Address,
    commitment: Address,
    asset: Address,
    other_asset: Address,
    treasury: Address,
    employees: Vec<Address>,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let operator = Address::generate(&env);
        let treasury = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let asset = env.register(Token, ());
        let other_asset = env.register(Token, ());
        TokenClient::new(&env, &asset).mint(&treasury, &BALANCE);
        let commitment = env.register(SalaryCommitmentContract, ());
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment);
        commitment_client.init_commitment_admin(&admin);
        let employees = Vec::from_array(&env, [Address::generate(&env), Address::generate(&env)]);
        for (index, employee) in employees.iter().enumerate() {
            commitment_client
                .store_commitment(&employee, &BytesN::from_array(&env, &[index as u8 + 1; 32]));
        }
        let payroll = env.register(Payroll, ());
        // Preparation/cancellation do not verify proofs or call the verifier.
        let verifier = Address::generate(&env);
        PayrollClient::new(&env, &payroll).initialize(
            &admin,
            &asset,
            &verifier,
            &commitment,
            &treasury,
            &treasury_owner,
        );
        let isolation = env.register(TreasuryIsolationContract, ());
        let isolation_client = TreasuryIsolationContractClient::new(&env, &isolation);
        isolation_client.initialize(&admin);
        for (company, token) in [
            (COMPANY, &asset),
            (COMPANY, &other_asset),
            (OTHER_COMPANY, &asset),
        ] {
            isolation_client.register_asset(&company, token, token, &Symbol::new(&env, "TEST"));
            isolation_client.credit(&company, token, &BALANCE);
        }
        isolation_client.set_reserve_authorizer(&COMPANY, &operator);
        Self {
            env,
            admin,
            operator,
            payroll,
            isolation,
            commitment,
            asset,
            other_asset,
            treasury,
            employees,
        }
    }

    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll)
    }

    fn isolation(&self) -> TreasuryIsolationContractClient<'_> {
        TreasuryIsolationContractClient::new(&self.env, &self.isolation)
    }

    fn prepare(&self, amounts: [i128; 2], seed: u8) -> u64 {
        let total = amounts[0] + amounts[1];
        let proof = BytesN::from_array(&self.env, &[0; 256]);
        let run = self.payroll().prepare_payroll_run(
            &Vec::from_array(&self.env, [proof.clone(), proof]),
            &Vec::from_array(&self.env, amounts),
            &self.employees,
            &total,
            &BytesN::from_array(&self.env, &[seed; 32]),
            &None,
        );
        self.isolation().reserve(&COMPANY, &self.asset, &total);
        run
    }

    fn cancel(&self, run: u64) {
        self.payroll().cancel_payroll_run_with_reason(
            &self.admin,
            &run,
            &Symbol::new(&self.env, "operator_cancel"),
        );
    }

    fn assert_accounting(&self, locked: i128, reserved: i128) {
        assert_eq!(self.payroll().get_locked_funds(&self.asset), locked);
        assert_eq!(
            self.payroll().get_available_treasury_balance(&self.asset),
            BALANCE - locked,
        );
        let balance = self.isolation().get_balance(&COMPANY, &self.asset).unwrap();
        assert_eq!(balance.balance, BALANCE);
        assert_eq!(balance.reserved, reserved);
    }

    fn assert_no_payment(&self) {
        let token = TokenClient::new(&self.env, &self.asset);
        assert_eq!(token.balance(&self.treasury), BALANCE);
        let commitments = SalaryCommitmentContractClient::new(&self.env, &self.commitment);
        for (index, employee) in self.employees.iter().enumerate() {
            assert_eq!(token.balance(&employee), 0);
            assert!(commitments.is_commitment_active(&employee));
            assert_eq!(
                commitments.get_commitment(&employee).commitment,
                BytesN::from_array(&self.env, &[index as u8 + 1; 32]),
            );
        }
    }
}

fn event_topics(env: &Env, category: &str, name: &str) -> Vec<Val> {
    Vec::from_array(
        env,
        [
            Symbol::new(env, category).into_val(env),
            Symbol::new(env, name).into_val(env),
        ],
    )
}

fn assert_event(env: &Env, event: &ContractEvent, topics: Vec<Val>, data: Val) {
    match &event.body {
        ContractEventBody::V0(body) => {
            assert_eq!(Vec::<Val>::try_from_val(env, &body.topics).unwrap(), topics);
            assert_eq!(body.data, ScVal::try_from_val(env, &data).unwrap());
        }
    }
}

#[test]
fn cancellation_then_release_preserves_other_runs_companies_and_assets() {
    let ctx = Fixture::new();
    let first = ctx.prepare([1_200, 800], 1);
    let second = ctx.prepare([1_800, 1_200], 2);
    ctx.isolation().reserve(&COMPANY, &ctx.other_asset, &700);
    ctx.isolation().reserve(&OTHER_COMPANY, &ctx.asset, &900);
    ctx.assert_accounting(5_000, 5_000);

    ctx.cancel(first);
    // Cancellation alone must not claim to have called treasury_isolation.
    ctx.assert_accounting(3_000, 5_000);
    assert!(ctx.payroll().get_pending_run(&first).is_none());
    assert_eq!(
        ctx.payroll().get_payroll_run_state(&first),
        PayrollRunState::Cancelled
    );
    assert!(ctx.payroll().get_pending_run(&second).is_some());
    assert_eq!(
        ctx.payroll().get_payroll_run_state(&second),
        PayrollRunState::Submitted
    );

    ctx.isolation()
        .release_reserve(&COMPANY, &ctx.asset, &2_000, &ctx.operator);
    ctx.assert_accounting(3_000, 3_000);
    assert_eq!(
        ctx.isolation()
            .get_balance(&COMPANY, &ctx.other_asset)
            .unwrap()
            .reserved,
        700
    );
    assert_eq!(
        ctx.isolation()
            .get_balance(&OTHER_COMPANY, &ctx.asset)
            .unwrap()
            .reserved,
        900
    );
    ctx.assert_no_payment();

    // A fresh run can reuse the released capacity; the other run stays pending.
    let replacement = ctx.prepare([1_200, 800], 3);
    ctx.assert_accounting(5_000, 5_000);
    assert!(ctx.payroll().get_pending_run(&replacement).is_some());
}

#[test]
fn unauthorized_cancellation_preserves_both_reservations() {
    let ctx = Fixture::new();
    let run = ctx.prepare([1_200, 800], 1);
    // mock_all_auths supplies signatures, but does not grant the payroll role.
    assert!(ctx
        .payroll()
        .try_cancel_payroll_run_with_reason(
            &ctx.operator,
            &run,
            &Symbol::new(&ctx.env, "operator_cancel"),
        )
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    ctx.assert_accounting(2_000, 2_000);
    assert!(ctx.payroll().get_pending_run(&run).is_some());
    assert_eq!(
        ctx.payroll().get_payroll_run_state(&run),
        PayrollRunState::Submitted
    );
    ctx.assert_no_payment();
}

#[test]
fn rejected_release_after_cancellation_can_be_retried_with_authority() {
    let ctx = Fixture::new();
    let run = ctx.prepare([1_200, 800], 1);
    ctx.cancel(run);
    let unauthorized = Address::generate(&ctx.env);
    assert_eq!(
        ctx.isolation()
            .try_release_reserve(&COMPANY, &ctx.asset, &2_000, &unauthorized)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::Unauthorized,
    );
    assert!(ctx.env.events().all().events().is_empty());
    ctx.assert_accounting(0, 2_000);
    assert_eq!(
        ctx.payroll().get_payroll_run_state(&run),
        PayrollRunState::Cancelled
    );
    ctx.isolation()
        .release_reserve(&COMPANY, &ctx.asset, &2_000, &ctx.operator);
    ctx.assert_accounting(0, 0);
    ctx.assert_no_payment();
}

#[test]
fn exact_release_clears_reserve_and_replays_or_over_release_do_not_mutate_state() {
    let ctx = Fixture::new();
    let run = ctx.prepare([6_000, 4_000], 1);
    ctx.assert_accounting(BALANCE, BALANCE);
    ctx.cancel(run);
    for (amount, error) in [
        (0, TreasuryIsolationError::InvalidAmount),
        (-1, TreasuryIsolationError::InvalidAmount),
        (BALANCE + 1, TreasuryIsolationError::InsufficientReserve),
    ] {
        assert_eq!(
            ctx.isolation()
                .try_release_reserve(&COMPANY, &ctx.asset, &amount, &ctx.operator)
                .unwrap_err()
                .unwrap(),
            error,
        );
        assert!(ctx.env.events().all().events().is_empty());
        ctx.assert_accounting(0, BALANCE);
    }
    ctx.isolation()
        .release_reserve(&COMPANY, &ctx.asset, &BALANCE, &ctx.operator);
    ctx.assert_accounting(0, 0);
    assert_eq!(
        ctx.isolation()
            .try_release_reserve(&COMPANY, &ctx.asset, &1, &ctx.operator)
            .unwrap_err()
            .unwrap(),
        TreasuryIsolationError::InsufficientReserve,
    );
    assert!(ctx.env.events().all().events().is_empty());
    assert!(ctx
        .payroll()
        .try_cancel_payroll_run_with_reason(
            &ctx.admin,
            &run,
            &Symbol::new(&ctx.env, "operator_cancel"),
        )
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    assert!(ctx
        .payroll()
        .try_finalize_payroll_run(&ctx.admin, &run)
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    ctx.assert_accounting(0, 0);
    ctx.assert_no_payment();

    let proof = BytesN::from_array(&ctx.env, &[0; 256]);
    let proofs = Vec::from_array(&ctx.env, [proof.clone(), proof]);
    let amounts = Vec::from_array(&ctx.env, [6_000, 4_000]);
    assert!(ctx
        .payroll()
        .try_prepare_payroll_run(
            &proofs,
            &amounts,
            &ctx.employees,
            &BALANCE,
            &BytesN::from_array(&ctx.env, &[1; 32]),
            &None,
        )
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    ctx.assert_accounting(0, 0);
    ctx.prepare([6_000, 4_000], 2);
    ctx.assert_accounting(BALANCE, BALANCE);
}

#[test]
fn cancellation_and_release_events_contain_only_operational_and_aggregate_data() {
    let ctx = Fixture::new();
    let run = ctx.prepare([1_200, 800], 1);
    ctx.cancel(run);
    let events = ctx.env.events().all();
    let payroll_events = events.filter_by_contract(&ctx.payroll);
    assert_eq!(events.events().len(), 4);
    assert_eq!(payroll_events.events().len(), 4);
    assert_event(
        &ctx.env,
        &payroll_events.events()[0],
        event_topics(&ctx.env, "treasury", "locked_funds_updated"),
        (ctx.asset.clone(), 0i128).into_val(&ctx.env),
    );
    assert_event(
        &ctx.env,
        &payroll_events.events()[1],
        event_topics(&ctx.env, "payroll", "run_state"),
        (run, PayrollRunState::Cancelled).into_val(&ctx.env),
    );
    assert_event(
        &ctx.env,
        &payroll_events.events()[2],
        event_topics(&ctx.env, "payroll", "run_cancelled"),
        (run, ctx.admin.clone()).into_val(&ctx.env),
    );
    let mut snapshot_topics = event_topics(&ctx.env, "payroll", "treasury_balance_snapshot");
    snapshot_topics.push_back(ctx.asset.clone().into_val(&ctx.env));
    assert_event(
        &ctx.env,
        &payroll_events.events()[3],
        snapshot_topics,
        (
            BALANCE,
            BALANCE,
            0i128,
            0i128,
            ctx.env.ledger().timestamp(),
            Symbol::new(&ctx.env, "run_cancelled"),
        )
            .into_val(&ctx.env),
    );
    ctx.isolation()
        .release_reserve(&COMPANY, &ctx.asset, &2_000, &ctx.operator);
    let events = ctx.env.events().all();
    let isolation_events = events.filter_by_contract(&ctx.isolation);
    assert_eq!(events.events().len(), 1);
    assert_eq!(isolation_events.events().len(), 1);
    assert_event(
        &ctx.env,
        &isolation_events.events()[0],
        event_topics(&ctx.env, "payroll", "treas_reserve_rel"),
        (COMPANY, ctx.asset.clone(), 2_000i128).into_val(&ctx.env),
    );
    ctx.assert_no_payment();
}

#[test]
fn permitted_roles_still_require_signatures_for_cancellation_and_release() {
    let ctx = Fixture::new();
    let run = ctx.prepare([1_200, 800], 1);
    ctx.env.set_auths(&[]);
    assert!(ctx
        .payroll()
        .try_cancel_payroll_run_with_reason(
            &ctx.admin,
            &run,
            &Symbol::new(&ctx.env, "operator_cancel"),
        )
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    assert!(ctx
        .isolation()
        .try_release_reserve(&COMPANY, &ctx.asset, &2_000, &ctx.operator)
        .is_err());
    assert!(ctx.env.events().all().events().is_empty());
    ctx.assert_accounting(2_000, 2_000);
    assert_eq!(
        ctx.payroll().get_payroll_run_state(&run),
        PayrollRunState::Submitted
    );
    ctx.assert_no_payment();

    ctx.env.mock_all_auths();
    ctx.cancel(run);
    ctx.isolation()
        .release_reserve(&COMPANY, &ctx.asset, &2_000, &ctx.operator);
    ctx.assert_accounting(0, 0);
    ctx.assert_no_payment();
}
