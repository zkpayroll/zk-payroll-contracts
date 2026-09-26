//! Audit events for payroll configuration changes (issue #490).
//!
//! Every configuration setter publishes exactly one
//! `("payroll", "config_changed", key)` event per successful change, carrying
//! the actor, hashed subject/previous/new value references, and a monotonic
//! contract-wide revision. Failed and no-op changes publish nothing and leave
//! the revision untouched.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::config_audit::{config_keys, NO_VALUE_REF};
use payroll::{CompanyState, Payroll, PayrollClient, RetentionPolicy};
use payroll_events::ConfigChanged;
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _};
use soroban_sdk::xdr::{self, Limits, WriteXdr};
use soroban_sdk::{
    symbol_short, Address, BytesN, Env, Event, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

/// Event data tuple: (actor, subject_ref, previous_ref, new_ref, revision,
/// ledger_sequence, timestamp).
type AuditData = (Address, BytesN<32>, BytesN<32>, BytesN<32>, u64, u32, u64);

const LEDGER_SEQUENCE: u32 = 4_242;
const LEDGER_TIMESTAMP: u64 = 500;

struct Ctx<'a> {
    env: Env,
    payroll: PayrollClient<'a>,
    payroll_id: Address,
    admin: Address,
    token: Address,
    treasury_owner: Address,
    commitment: SalaryCommitmentContractClient<'a>,
    token_client: TokenClient<'a>,
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

fn setup<'a>() -> Ctx<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.sequence_number = LEDGER_SEQUENCE;
        l.timestamp = LEDGER_TIMESTAMP;
    });

    let verifier_id = env.register(ProofVerifier, ());
    let verifier = ProofVerifierClient::new(&env, &verifier_id);
    verifier.init_verifier_admin(&Address::generate(&env));
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register(SalaryCommitmentContract, ());
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&Address::generate(&env));

    let token = env.register(Token, ());
    let token_client = TokenClient::new(&env, &token);
    let treasury = Address::generate(&env);
    token_client.mint(&treasury, &1_000_000i128);

    let payroll_id = env.register(Payroll, ());
    let payroll = PayrollClient::new(&env, &payroll_id);
    let admin = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    payroll.initialize(
        &admin,
        &token,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );
    commitment.set_payroll_operator(&payroll_id);

    Ctx {
        env,
        payroll,
        payroll_id,
        admin,
        token,
        treasury_owner,
        commitment,
        token_client,
    }
}

/// `sha256(value.to_xdr())`, recomputed independently of the contract.
fn sha<T: IntoVal<Env, Val>>(env: &Env, value: T) -> BytesN<32> {
    use soroban_sdk::xdr::ToXdr;
    env.crypto().sha256(&value.to_xdr(env)).into()
}

fn none(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &NO_VALUE_REF)
}

fn is_audit_event(ev: &xdr::ContractEvent) -> bool {
    let xdr::ContractEventBody::V0(body) = &ev.body;
    let marker = xdr::ScVal::Symbol(xdr::ScSymbol("config_changed".try_into().unwrap()));
    body.topics.get(1) == Some(&marker)
}

/// Audit events published by the payroll contract in the last invocation.
/// Must be read before any other contract call, which resets the event log.
fn audit_events(ctx: &Ctx) -> std::vec::Vec<xdr::ContractEvent> {
    ctx.env
        .events()
        .all()
        .filter_by_contract(&ctx.payroll_id)
        .events()
        .iter()
        .filter(|ev| is_audit_event(ev))
        .cloned()
        .collect()
}

fn decode(env: &Env, ev: &xdr::ContractEvent) -> (Symbol, AuditData) {
    let xdr::ContractEventBody::V0(body) = &ev.body;
    let key = Val::try_from_val(env, &body.topics[2]).unwrap();
    let data = Val::try_from_val(env, &body.data).unwrap();
    (
        Symbol::try_from_val(env, &key).unwrap(),
        AuditData::try_from_val(env, &data).unwrap(),
    )
}

/// The single audit event a successful change with these fields must publish.
fn expected(
    ctx: &Ctx,
    key: &str,
    actor: &Address,
    subject_ref: BytesN<32>,
    previous_ref: BytesN<32>,
    new_ref: BytesN<32>,
    revision: u64,
) -> xdr::ContractEvent {
    ConfigChanged {
        key: Symbol::new(&ctx.env, key),
        actor: actor.clone(),
        subject_ref,
        previous_ref,
        new_ref,
        revision,
        ledger_sequence: LEDGER_SEQUENCE,
        timestamp: LEDGER_TIMESTAMP,
    }
    .to_xdr(&ctx.env, &ctx.payroll_id)
}

fn event_bytes(ev: &xdr::ContractEvent) -> std::vec::Vec<u8> {
    WriteXdr::to_xdr(ev, Limits::none()).unwrap()
}

fn scval_bytes<T: IntoVal<Env, Val>>(env: &Env, value: T) -> std::vec::Vec<u8> {
    let scval = xdr::ScVal::try_from_val(env, &value.into_val(env)).unwrap();
    WriteXdr::to_xdr(&scval, Limits::none()).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// 1. Every configuration setter emits exactly one audit event.
// ---------------------------------------------------------------------------

#[test]
fn every_config_setter_emits_exactly_one_audit_event() {
    let ctx = setup();
    let env = &ctx.env;
    let admin = ctx.admin.clone();
    let mut revision = 0u64;

    // Asset allowlist (initialize allowed the canonical token).
    ctx.payroll.set_asset_allowed(&ctx.token, &false);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::ASSET_ALLOWED,
            &admin,
            sha(env, ctx.token.clone()),
            sha(env, true),
            sha(env, false),
            revision,
        )]
    );

    // Company state (never set: getter defaults to Active, storage is empty).
    ctx.payroll.set_company_state(&admin, &CompanyState::Paused);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::COMPANY_STATE,
            &admin,
            none(env),
            none(env),
            sha(env, CompanyState::Paused),
            revision,
        )]
    );

    // Capacity limits.
    ctx.payroll
        .set_capacity_limits(&admin, &10u32, &100u32, &1_000_000i128);
    revision += 1;
    let events = audit_events(&ctx);
    let limits = ctx.payroll.get_capacity_limits().unwrap();
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::CAPACITY_LIMITS,
            &admin,
            none(env),
            none(env),
            sha(env, limits),
            revision,
        )]
    );

    // Settlement window for a period.
    let period = symbol_short!("2026_09");
    ctx.payroll
        .set_settlement_window(&admin, &period, &1_000u64, &2_000u64, &3_000u64, &4_000u64);
    revision += 1;
    let events = audit_events(&ctx);
    let window = ctx.payroll.get_settlement_window(&period).unwrap();
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::SETTLEMENT_WINDOW,
            &admin,
            sha(env, period.clone()),
            none(env),
            sha(env, window),
            revision,
        )]
    );

    // Period configuration freeze.
    ctx.payroll.freeze_period_config(&admin, &period);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::PERIOD_FROZEN,
            &admin,
            sha(env, period.clone()),
            none(env),
            sha(env, true),
            revision,
        )]
    );

    // Retention policy (initialize stored a default policy).
    let old_policy = ctx.payroll.get_retention_policy();
    let policy = RetentionPolicy {
        finalized_run_seconds: 60,
        cancelled_batch_seconds: 120,
        challenge_seconds: 180,
    };
    ctx.payroll.set_retention_policy(&admin, &policy);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::RETENTION_POLICY,
            &admin,
            none(env),
            sha(env, old_policy),
            sha(env, policy),
            revision,
        )]
    );

    // Dispute authority grant + revoke.
    let authority = Address::generate(env);
    ctx.payroll.add_dispute_authority(&admin, &authority);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::DISPUTE_AUTHORITY,
            &admin,
            sha(env, authority.clone()),
            none(env),
            sha(env, true),
            revision,
        )]
    );
    ctx.payroll.remove_dispute_authority(&admin, &authority);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::DISPUTE_AUTHORITY,
            &admin,
            sha(env, authority.clone()),
            sha(env, true),
            none(env),
            revision,
        )]
    );

    // Reviewer grant + revoke.
    let reviewer = Address::generate(env);
    ctx.payroll.add_reviewer(&admin, &reviewer);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::REVIEWER,
            &admin,
            sha(env, reviewer.clone()),
            none(env),
            sha(env, true),
            revision,
        )]
    );
    ctx.payroll.remove_reviewer(&admin, &reviewer);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::REVIEWER,
            &admin,
            sha(env, reviewer.clone()),
            sha(env, true),
            none(env),
            revision,
        )]
    );

    // Reservation expiry policy.
    ctx.payroll
        .set_reservation_expiry_policy(&admin, &ctx.token, &5_000i128, &3_600u64);
    revision += 1;
    let events = audit_events(&ctx);
    let expiry = ctx.payroll.get_reservation_expiry(&ctx.token).unwrap();
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::RESERVATION_EXPIRY,
            &admin,
            sha(env, ctx.token.clone()),
            none(env),
            sha(env, expiry),
            revision,
        )]
    );

    // Payroll currency.
    ctx.payroll
        .set_payroll_currency(&admin, &ctx.token, &Symbol::new(env, "USDC"), &7u32);
    revision += 1;
    let events = audit_events(&ctx);
    let currency = ctx.payroll.get_payroll_currency().unwrap();
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::PAYROLL_CURRENCY,
            &admin,
            none(env),
            none(env),
            sha(env, currency),
            revision,
        )]
    );

    // Storage version (initialize stored the initial version state).
    let old_version = ctx.payroll.get_storage_version().unwrap();
    ctx.payroll
        .set_storage_version(&admin, &1u32, &String::from_str(env, "v1 migrated"));
    revision += 1;
    let events = audit_events(&ctx);
    let new_version = ctx.payroll.get_storage_version().unwrap();
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::STORAGE_VERSION,
            &admin,
            none(env),
            sha(env, old_version),
            sha(env, new_version),
            revision,
        )]
    );

    // Admin rotation: proposing is inert, accepting is the audited change and
    // the actor is the newly authorised admin.
    let second_admin = Address::generate(env);
    ctx.payroll.propose_admin_rotation(&admin, &second_admin);
    assert!(audit_events(&ctx).is_empty());
    ctx.payroll.accept_admin_rotation(&second_admin);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::ADMIN,
            &second_admin,
            none(env),
            sha(env, admin.clone()),
            sha(env, second_admin.clone()),
            revision,
        )]
    );

    // Treasury-owner rotation.
    let new_owner = Address::generate(env);
    ctx.payroll
        .propose_treasury_rotation(&ctx.treasury_owner, &new_owner);
    assert!(audit_events(&ctx).is_empty());
    ctx.payroll.accept_treasury_rotation(&new_owner);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::TREASURY_OWNER,
            &new_owner,
            none(env),
            sha(env, ctx.treasury_owner.clone()),
            sha(env, new_owner.clone()),
            revision,
        )]
    );

    // Admin handover (#339) is a second path to the same `admin` setting.
    let third_admin = Address::generate(env);
    ctx.payroll
        .request_admin_handover(&second_admin, &third_admin);
    assert!(audit_events(&ctx).is_empty());
    ctx.payroll.accept_admin_handover(&third_admin);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::ADMIN,
            &third_admin,
            none(env),
            sha(env, second_admin.clone()),
            sha(env, third_admin.clone()),
            revision,
        )]
    );

    // Pause manager (set last: later setters would call into it).
    let pause_manager = Address::generate(env);
    ctx.payroll.set_pause_manager(&pause_manager);
    revision += 1;
    let events = audit_events(&ctx);
    assert_eq!(
        events,
        [expected(
            &ctx,
            config_keys::PAUSE_MANAGER,
            &third_admin,
            none(env),
            none(env),
            sha(env, pause_manager),
            revision,
        )]
    );

    assert_eq!(revision, 17);
    assert_eq!(ctx.payroll.get_config_revision(), revision);
}

// ---------------------------------------------------------------------------
// 2–4. "none" marker, revision increments, chaining, hash of real value.
// ---------------------------------------------------------------------------

#[test]
fn config_revision_starts_at_zero() {
    let ctx = setup();
    assert_eq!(ctx.payroll.get_config_revision(), 0);
}

#[test]
fn first_ever_set_uses_the_no_value_reference() {
    let ctx = setup();
    ctx.payroll
        .set_capacity_limits(&ctx.admin, &1u32, &2u32, &3i128);
    let events = audit_events(&ctx);
    assert_eq!(events.len(), 1);
    let (key, (_, subject_ref, previous_ref, new_ref, revision, _, _)) =
        decode(&ctx.env, &events[0]);
    assert_eq!(key, Symbol::new(&ctx.env, config_keys::CAPACITY_LIMITS));
    assert_eq!(previous_ref.to_array(), NO_VALUE_REF);
    assert_eq!(subject_ref.to_array(), NO_VALUE_REF);
    assert_ne!(new_ref.to_array(), NO_VALUE_REF);
    assert_eq!(revision, 1);
}

#[test]
fn consecutive_changes_chain_and_increment_revision_by_one() {
    let ctx = setup();
    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    let first = decode(&ctx.env, &audit_events(&ctx)[0]).1;

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &20u32, &200u32, &2_000i128);
    let second = decode(&ctx.env, &audit_events(&ctx)[0]).1;

    assert_eq!(second.4, first.4 + 1, "revision increments by exactly one");
    assert_eq!(
        second.2, first.3,
        "previous_ref chains to the prior new_ref"
    );
    assert_ne!(second.2, second.3);
    assert_eq!(ctx.payroll.get_config_revision(), second.4);
}

#[test]
fn previous_ref_is_sha256_of_the_actual_previous_value() {
    let ctx = setup();
    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    let stored_before = ctx.payroll.get_capacity_limits().unwrap();

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &11u32, &100u32, &1_000i128);
    let events = audit_events(&ctx);
    let stored_after = ctx.payroll.get_capacity_limits().unwrap();
    let (_, (_, _, previous_ref, new_ref, _, _, _)) = decode(&ctx.env, &events[0]);

    assert_eq!(previous_ref, sha(&ctx.env, stored_before));
    assert_eq!(new_ref, sha(&ctx.env, stored_after));
}

// ---------------------------------------------------------------------------
// 5–6. Failed changes: no event, no revision bump.
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_caller_is_rejected_without_event_or_revision_bump() {
    let ctx = setup();
    ctx.payroll
        .add_reviewer(&ctx.admin, &Address::generate(&ctx.env));
    let revision = ctx.payroll.get_config_revision();
    let stranger = Address::generate(&ctx.env);

    let result = ctx
        .payroll
        .try_set_capacity_limits(&stranger, &10u32, &100u32, &1_000i128);
    assert!(result.is_err());
    assert!(audit_events(&ctx).is_empty());
    assert_eq!(ctx.payroll.get_config_revision(), revision);
    assert!(ctx.payroll.get_capacity_limits().is_none());

    // Previously any signer could set a reservation policy (#490 auth fix).
    let result = ctx
        .payroll
        .try_set_reservation_expiry_policy(&stranger, &ctx.token, &5_000i128, &3_600u64);
    assert!(result.is_err());
    assert!(audit_events(&ctx).is_empty());
    assert_eq!(ctx.payroll.get_config_revision(), revision);
    assert!(ctx.payroll.get_reservation_expiry(&ctx.token).is_none());
}

#[test]
#[should_panic(
    expected = "Unauthorized: only the admin may set a reservation expiry policy (error code 1)"
)]
fn unauthorized_reservation_policy_error_is_actionable_and_value_free() {
    let ctx = setup();
    // The failure message names the role and error code only; the reserved
    // amount supplied by the caller is never echoed back.
    ctx.payroll.set_reservation_expiry_policy(
        &Address::generate(&ctx.env),
        &ctx.token,
        &987_654_321_123i128,
        &3_600u64,
    );
}

#[test]
fn invalid_input_is_rejected_without_event_or_revision_bump() {
    let ctx = setup();
    let revision = ctx.payroll.get_config_revision();

    assert!(ctx
        .payroll
        .try_set_capacity_limits(&ctx.admin, &0u32, &100u32, &1_000i128)
        .is_err());
    assert!(audit_events(&ctx).is_empty());

    assert!(ctx
        .payroll
        .try_set_settlement_window(
            &ctx.admin,
            &symbol_short!("2026_09"),
            &4_000u64,
            &3_000u64,
            &2_000u64,
            &1_000u64,
        )
        .is_err());
    assert!(audit_events(&ctx).is_empty());

    assert!(ctx
        .payroll
        .try_set_asset_allowed(&Address::generate(&ctx.env), &true)
        .is_err());
    assert!(audit_events(&ctx).is_empty());

    assert_eq!(ctx.payroll.get_config_revision(), revision);
}

// ---------------------------------------------------------------------------
// 7. No-op changes.
// ---------------------------------------------------------------------------

#[test]
fn no_op_change_keeps_setter_behaviour_but_emits_no_audit_event() {
    let ctx = setup();
    let reviewer = Address::generate(&ctx.env);
    ctx.payroll.add_reviewer(&ctx.admin, &reviewer);
    let revision = ctx.payroll.get_config_revision();

    // Re-adding an existing reviewer still succeeds and still publishes the
    // existing `reviewer_added` event, but records no configuration change.
    ctx.payroll.add_reviewer(&ctx.admin, &reviewer);
    let all = ctx.env.events().all().filter_by_contract(&ctx.payroll_id);
    assert_eq!(all.events().len(), 1);
    assert!(!is_audit_event(&all.events()[0]));
    assert_eq!(ctx.payroll.get_config_revision(), revision);

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    assert!(audit_events(&ctx).is_empty());

    ctx.payroll.set_asset_allowed(&ctx.token, &true);
    assert!(audit_events(&ctx).is_empty());

    assert_eq!(ctx.payroll.get_config_revision(), revision + 1);
}

// ---------------------------------------------------------------------------
// 8. Privacy: no plaintext configuration values in audit events.
// ---------------------------------------------------------------------------

#[test]
fn audit_events_never_contain_plaintext_values() {
    let ctx = setup();
    let env = &ctx.env;
    let reserved_amount = 987_654_321_123i128;
    let max_total_value = 123_456_789_987i128;
    let reviewer = Address::generate(env);

    ctx.payroll
        .set_reservation_expiry_policy(&ctx.admin, &ctx.token, &reserved_amount, &3_600u64);
    // This setter has no pre-existing event, so nothing it publishes may
    // contain the reserved amount.
    let all = env.events().all().filter_by_contract(&ctx.payroll_id);
    assert_eq!(all.events().len(), 1);
    let bytes = event_bytes(&all.events()[0]);
    assert!(!contains(&bytes, &scval_bytes(env, reserved_amount)));
    assert!(!contains(&bytes, &scval_bytes(env, ctx.token.clone())));

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &max_total_value);
    let events = audit_events(&ctx);
    assert_eq!(events.len(), 1);
    assert!(!contains(
        &event_bytes(&events[0]),
        &scval_bytes(env, max_total_value)
    ));

    ctx.payroll.add_reviewer(&ctx.admin, &reviewer);
    let events = audit_events(&ctx);
    assert_eq!(events.len(), 1);
    assert!(!contains(
        &event_bytes(&events[0]),
        &scval_bytes(env, reviewer.clone())
    ));

    // The only address in an audit event is the actor.
    let (_, (actor, ..)) = decode(env, &events[0]);
    assert_eq!(actor, ctx.admin);
}

// ---------------------------------------------------------------------------
// 10. Regression: a full payroll run still works after configuration changes.
// ---------------------------------------------------------------------------

#[test]
fn payroll_run_still_executes_after_config_changes() {
    let ctx = setup();
    let env = &ctx.env;
    ctx.payroll
        .add_reviewer(&ctx.admin, &Address::generate(env));
    ctx.payroll.set_retention_policy(
        &ctx.admin,
        &RetentionPolicy {
            finalized_run_seconds: 60,
            cancelled_batch_seconds: 60,
            challenge_seconds: 60,
        },
    );
    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000_000i128);
    ctx.payroll
        .set_payroll_currency(&ctx.admin, &ctx.token, &Symbol::new(env, "USDC"), &7u32);
    let revision = ctx.payroll.get_config_revision();
    assert_eq!(revision, 4);

    let mut proofs = Vec::new(env);
    let mut amounts = Vec::new(env);
    let mut employees = Vec::new(env);
    for i in 0..3u8 {
        let employee = Address::generate(env);
        let mut seed = [0u8; 32];
        seed[0] = i + 1;
        ctx.commitment
            .store_commitment(&employee, &BytesN::from_array(env, &seed));
        proofs.push_back(BytesN::from_array(env, &[0u8; 256]));
        amounts.push_back(1_000i128);
        employees.push_back(employee);
    }
    let mut nonce = [0u8; 32];
    nonce[0] = 9;

    let run_id = ctx.payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &BytesN::from_array(env, &nonce),
        &None,
    );
    assert!(run_id > 0);
    assert!(
        audit_events(&ctx).is_empty(),
        "execution is not a config change"
    );
    for employee in employees.iter() {
        assert_eq!(ctx.token_client.balance(&employee), 1_000i128);
    }
    assert_eq!(ctx.payroll.get_config_revision(), revision);
}

// ---------------------------------------------------------------------------
// 11. The recorded actor is the address whose authorization was required.
// ---------------------------------------------------------------------------

#[test]
fn config_setters_require_the_actor_to_authorize() {
    let ctx = setup();
    let env = &ctx.env;

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    assert_eq!(
        env.auths(),
        std::vec![(
            ctx.admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    ctx.payroll_id.clone(),
                    Symbol::new(env, "set_capacity_limits"),
                    (ctx.admin.clone(), 10u32, 100u32, 1_000i128).into_val(env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );

    ctx.payroll
        .set_reservation_expiry_policy(&ctx.admin, &ctx.token, &5_000i128, &3_600u64);
    assert_eq!(
        env.auths(),
        std::vec![(
            ctx.admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    ctx.payroll_id.clone(),
                    Symbol::new(env, "set_reservation_expiry_policy"),
                    (ctx.admin.clone(), ctx.token.clone(), 5_000i128, 3_600u64).into_val(env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );

    // Without any authorization the change is rejected and nothing is audited.
    let revision = ctx.payroll.get_config_revision();
    env.mock_auths(&[]);
    assert!(ctx
        .payroll
        .try_set_capacity_limits(&ctx.admin, &20u32, &100u32, &1_000i128)
        .is_err());
    assert!(audit_events(&ctx).is_empty());
    env.mock_all_auths();
    assert_eq!(ctx.payroll.get_config_revision(), revision);
}
