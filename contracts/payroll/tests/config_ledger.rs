//! On-chain configuration change ledger (issue #707).
//!
//! Every audited configuration change persists a `ConfigLedgerEntry` keyed by
//! the revision it created, with the same fields as the `config_changed`
//! event. No-op, failed, and unauthorized changes persist nothing.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::config_audit::{config_keys, NO_VALUE_REF};
use payroll::{ConfigLedgerEntry, Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::xdr;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec};

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

/// Set the canonical token's allowlist flag (initialized to `true`).
fn set_asset(ctx: &Ctx, allowed: bool) {
    ctx.payroll.set_asset_allowed(&ctx.token, &allowed);
}

// ---------------------------------------------------------------------------
// 1. Entry matches the event and the previous_ref/new_ref chain.
// ---------------------------------------------------------------------------

#[test]
fn entry_matches_event_for_first_change() {
    let ctx = setup();
    let env = &ctx.env;

    set_asset(&ctx, false);
    let events = audit_events(&ctx);
    assert_eq!(events.len(), 1);
    let (key, (actor, subject, previous, new, revision, sequence, timestamp)) =
        decode(env, &events[0]);

    let entry = ctx.payroll.get_config_change(&1u64).unwrap();
    assert_eq!(
        entry,
        ConfigLedgerEntry {
            key,
            actor,
            subject_ref: subject,
            previous_ref: previous,
            new_ref: new,
            revision,
            ledger_sequence: sequence,
            timestamp,
        }
    );

    // And against independently computed expectations.
    assert_eq!(entry.key, Symbol::new(env, config_keys::ASSET_ALLOWED));
    assert_eq!(entry.actor, ctx.admin);
    assert_eq!(entry.subject_ref, sha(env, ctx.token.clone()));
    assert_eq!(entry.previous_ref, sha(env, true));
    assert_eq!(entry.new_ref, sha(env, false));
    assert_eq!(entry.revision, 1);
    assert_eq!(entry.ledger_sequence, LEDGER_SEQUENCE);
    assert_eq!(entry.timestamp, LEDGER_TIMESTAMP);
    assert_eq!(ctx.payroll.get_config_revision(), 1);
}

#[test]
fn consecutive_changes_have_contiguous_revisions_and_chain_refs() {
    let ctx = setup();
    let env = &ctx.env;

    set_asset(&ctx, false);
    set_asset(&ctx, true);

    let first = ctx.payroll.get_config_change(&1u64).unwrap();
    let second = ctx.payroll.get_config_change(&2u64).unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(second.revision, 2);
    assert_eq!(ctx.payroll.get_config_revision(), 2);
    assert_eq!(second.previous_ref, first.new_ref);
    assert_eq!(first.new_ref, sha(env, false));
    assert_eq!(second.new_ref, sha(env, true));
    assert!(ctx.payroll.get_config_change(&3u64).is_none());
}

#[test]
fn entry_with_no_previous_value_uses_the_zero_reference() {
    let ctx = setup();
    let env = &ctx.env;

    ctx.payroll
        .set_capacity_limits(&ctx.admin, &10u32, &100u32, &1_000i128);
    let entry = ctx.payroll.get_config_change(&1u64).unwrap();
    assert_eq!(entry.key, Symbol::new(env, config_keys::CAPACITY_LIMITS));
    assert_eq!(entry.subject_ref, none(env));
    assert_eq!(entry.previous_ref, none(env));
    assert_eq!(
        entry.new_ref,
        sha(env, ctx.payroll.get_capacity_limits().unwrap())
    );
}

// ---------------------------------------------------------------------------
// 2. No-op, failed, and unauthorized changes add no entry.
// ---------------------------------------------------------------------------

#[test]
fn no_op_change_adds_no_entry() {
    let ctx = setup();

    set_asset(&ctx, false);
    assert_eq!(ctx.payroll.get_config_revision(), 1);

    // Same value again: the setter succeeds but nothing is recorded.
    set_asset(&ctx, false);
    assert_eq!(ctx.payroll.get_config_revision(), 1);
    assert!(ctx.payroll.get_config_change(&2u64).is_none());
    assert_eq!(ctx.payroll.get_config_ledger(&1u64, &10u32).len(), 1);
}

#[test]
fn failed_change_adds_no_entry() {
    let ctx = setup();
    set_asset(&ctx, false);

    // Invalid input (zero capacity) reverts.
    assert!(ctx
        .payroll
        .try_set_capacity_limits(&ctx.admin, &0u32, &100u32, &1_000i128)
        .is_err());

    assert_eq!(ctx.payroll.get_config_revision(), 1);
    assert!(ctx.payroll.get_config_change(&2u64).is_none());
    assert_eq!(ctx.payroll.get_config_ledger(&1u64, &10u32).len(), 1);
}

#[test]
fn unauthorized_change_adds_no_entry() {
    let ctx = setup();
    set_asset(&ctx, false);
    let stranger = Address::generate(&ctx.env);

    assert!(ctx
        .payroll
        .try_set_capacity_limits(&stranger, &10u32, &100u32, &1_000i128)
        .is_err());

    assert_eq!(ctx.payroll.get_config_revision(), 1);
    assert!(ctx.payroll.get_config_change(&2u64).is_none());
    assert_eq!(ctx.payroll.get_config_ledger(&1u64, &10u32).len(), 1);
}

// ---------------------------------------------------------------------------
// 3. get_config_ledger pagination, cap, and bounds.
// ---------------------------------------------------------------------------

/// Make `n` real changes by alternating the asset allowlist flag.
fn make_changes(ctx: &Ctx, n: u64) {
    for i in 0..n {
        // The flag starts `true`, so the first change sets `false`.
        set_asset(ctx, i % 2 == 1);
    }
    assert_eq!(ctx.payroll.get_config_revision(), n);
}

fn revisions(entries: &Vec<ConfigLedgerEntry>) -> std::vec::Vec<u64> {
    entries.iter().map(|e| e.revision).collect()
}

#[test]
fn ledger_pagination_returns_consecutive_pages() {
    let ctx = setup();
    make_changes(&ctx, 7);

    assert_eq!(
        revisions(&ctx.payroll.get_config_ledger(&1u64, &3u32)),
        [1, 2, 3]
    );
    assert_eq!(
        revisions(&ctx.payroll.get_config_ledger(&4u64, &3u32)),
        [4, 5, 6]
    );
    // Final page is short.
    assert_eq!(revisions(&ctx.payroll.get_config_ledger(&7u64, &3u32)), [7]);
    // A limit larger than the remaining entries stops at the latest revision.
    assert_eq!(
        revisions(&ctx.payroll.get_config_ledger(&5u64, &40u32)),
        [5, 6, 7]
    );
    // Entries equal the single-entry getter.
    let page = ctx.payroll.get_config_ledger(&2u64, &2u32);
    assert_eq!(
        page.get(0).unwrap(),
        ctx.payroll.get_config_change(&2u64).unwrap()
    );
    assert_eq!(
        page.get(1).unwrap(),
        ctx.payroll.get_config_change(&3u64).unwrap()
    );
}

#[test]
fn ledger_limit_is_capped_at_fifty() {
    let ctx = setup();
    make_changes(&ctx, 60);

    let page = ctx.payroll.get_config_ledger(&1u64, &1_000u32);
    assert_eq!(page.len(), 50);
    assert_eq!(page.get(0).unwrap().revision, 1);
    assert_eq!(page.get(49).unwrap().revision, 50);

    assert_eq!(ctx.payroll.get_config_ledger(&1u64, &50u32).len(), 50);

    let rest = ctx.payroll.get_config_ledger(&51u64, &u32::MAX);
    assert_eq!(rest.len(), 10);
    assert_eq!(rest.get(9).unwrap().revision, 60);
}

#[test]
fn ledger_is_empty_for_zero_start_past_latest_or_zero_limit() {
    let ctx = setup();
    // No changes yet.
    assert!(ctx.payroll.get_config_ledger(&1u64, &10u32).is_empty());

    make_changes(&ctx, 3);
    assert!(ctx.payroll.get_config_ledger(&0u64, &10u32).is_empty());
    assert!(ctx.payroll.get_config_ledger(&4u64, &10u32).is_empty());
    assert!(ctx.payroll.get_config_ledger(&u64::MAX, &10u32).is_empty());
    assert!(ctx.payroll.get_config_ledger(&1u64, &0u32).is_empty());
}

// ---------------------------------------------------------------------------
// 4. Unknown revisions.
// ---------------------------------------------------------------------------

#[test]
fn unknown_revision_returns_none() {
    let ctx = setup();
    assert!(ctx.payroll.get_config_change(&0u64).is_none());
    assert!(ctx.payroll.get_config_change(&1u64).is_none());

    set_asset(&ctx, false);
    assert!(ctx.payroll.get_config_change(&1u64).is_some());
    assert!(ctx.payroll.get_config_change(&0u64).is_none());
    assert!(ctx.payroll.get_config_change(&2u64).is_none());
    assert!(ctx.payroll.get_config_change(&u64::MAX).is_none());
}
