// Privacy-safe event for a rejected payroll correction (issue #886).
//
// `check_draft_correction` is a read-only preflight for `amend_run_draft`.
// A rejected correction publishes `correction_rejected` carrying only the
// draft id, period label and a reason code, and writes no draft state.

#![cfg(test)]

use ::token::Token;
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::xdr::ContractEventBody;
use soroban_sdk::{Address, BytesN, Env, Symbol, TryFromVal, TryIntoVal, Val, Vec};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[128u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[64u8; 64]),
            ],
        ),
    }
}

fn setup(env: &Env) -> (PayrollClient<'_>, Address) {
    env.mock_all_auths();
    let verifier_id = env.register(ProofVerifier, ());
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));
    let commitment_id = env.register(SalaryCommitmentContract, ());
    SalaryCommitmentContractClient::new(env, &commitment_id)
        .init_commitment_admin(&Address::generate(env));
    let payroll = PayrollClient::new(env, &env.register(Payroll, ()));
    let admin = Address::generate(env);
    payroll.initialize(
        &admin,
        &env.register(Token, ()),
        &verifier_id,
        &commitment_id,
        &Address::generate(env),
        &Address::generate(env),
    );
    (payroll, admin)
}

/// The most recent `correction_rejected` payload, if one was published.
fn rejected_event(env: &Env) -> Option<(u64, Symbol, Symbol)> {
    let name = Symbol::new(env, "correction_rejected");
    // `.last()` keeps this correct whether events() holds one invocation or many.
    env.events().all().events().iter().filter_map(|event| {
        let ContractEventBody::V0(body) = &event.body;
        let topics: Vec<Val> = Vec::try_from_val(env, &body.topics).ok()?;
        let kind: Symbol = topics.get(1)?.try_into_val(env).ok()?;
        if kind != name {
            return None;
        }
        Val::try_from_val(env, &body.data).ok()?.try_into_val(env).ok()
    })
    .last()
}

#[test]
fn accepted_correction_passes_without_event() {
    let env = Env::default();
    let (payroll, admin) = setup(&env);
    let period = Symbol::new(&env, "nov");
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);

    assert!(payroll.check_draft_correction(&admin, &draft_id, &1_200i128, &3u32));
    assert_eq!(rejected_event(&env), None);
}

#[test]
fn limit_breach_emits_privacy_safe_rejection() {
    let env = Env::default();
    let (payroll, admin) = setup(&env);
    let period = Symbol::new(&env, "nov");
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    payroll.set_correction_auth_limits(&admin, &1u32, &0i128, &0u32);
    payroll.amend_run_draft(&admin, &draft_id, &1_100i128, &3u32);

    assert!(!payroll.check_draft_correction(&admin, &draft_id, &1_150i128, &3u32));
    // Payload is exactly (draft id, period, reason): no amount or headcount.
    assert_eq!(
        rejected_event(&env),
        Some((draft_id, period, Symbol::new(&env, "count_limit")))
    );
    // Preflight wrote nothing.
    assert_eq!(payroll.get_run_draft(&draft_id).total_amount, 1_100);
    assert_eq!(payroll.get_correction_usage(&Symbol::new(&env, "nov")).correction_count, 1);
}

#[test]
fn boundary_delta_exactly_at_cap_passes_and_invalid_total_is_rejected() {
    let env = Env::default();
    let (payroll, admin) = setup(&env);
    let period = Symbol::new(&env, "dec");
    let draft_id = payroll.create_run_draft(&admin, &1_000i128, &3u32, &period);
    payroll.set_correction_auth_limits(&admin, &0u32, &500i128, &0u32);

    assert!(payroll.check_draft_correction(&admin, &draft_id, &1_500i128, &3u32));
    assert!(!payroll.check_draft_correction(&admin, &draft_id, &1_501i128, &3u32));
    assert_eq!(
        rejected_event(&env),
        Some((draft_id, period.clone(), Symbol::new(&env, "delta_limit")))
    );

    assert!(!payroll.check_draft_correction(&admin, &draft_id, &0i128, &3u32));
    assert_eq!(
        rejected_event(&env),
        Some((draft_id, period, Symbol::new(&env, "invalid_total")))
    );
}
