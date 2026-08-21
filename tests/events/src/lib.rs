
//! # Audit Grant Revocation Event Tests (issue #284)
//!
//! Pins down the exact on-chain event schema `audit_module` emits around
//! view-key revocation, and confirms two properties the issue calls out
//! specifically:
//!
//! 1. "Revocation should be visible to auditors" — `revoke_view_key` emits a
//!    precisely-structured `AuditAccessRevoked` event on success, and a
//!    *failed* revocation attempt (wrong granter, unknown auditor) emits no
//!    event at all, so observers never see a misleading revocation signal.
//! 2. "Confirm the change does not expose private payroll values in ...
//!    events" — `ViewKeyGenerated`'s event data is checked to hold only the
//!    expiration ledger, never the raw 32-byte key material itself (which
//!    would let anyone bypass the keyed-commitment scheme without holding
//!    the actual key).
//!
//! `docs/events.md` previously claimed `AuditAccessRevoked` carries a
//! `timestamp` in its data and `ViewKeyGenerated` carries the raw
//! `key_bytes` — neither matches the actual emission code in
//! `contracts/events/src/lib.rs`. These tests assert the real schema so the
//! docs (now corrected) and the contract can't silently drift apart again.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p audit_revocation_event_tests
//! ```

#[cfg(test)]
mod tests {
    use audit_module::{AuditModule, AuditModuleClient};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Address, Env, Symbol, TryIntoVal};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AuditModule);
        (env, contract_id)
    }

    // ── AuditAccessRevoked: exact schema on success ───────────────────────────

    #[test]
    fn test_audit_access_revoked_topics_are_symbol_admin_auditor() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let admin = contract_id.clone();
        let before = env.events().all().len();
        client.revoke_view_key(&admin, &auditor);
        let after = env.events().all().len();
        assert_eq!(after, before + 1, "revocation must emit exactly one event");

        let event = env.events().all().get(after - 1).unwrap();
        assert_eq!(event.1.len(), 3, "topics must be (Symbol, admin, auditor)");

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "AuditAccessRevoked"));

        let topic_admin: Address = event.1.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_admin, admin);

        let topic_auditor: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_auditor, auditor);
    }

    /// The event carries no data payload at all — in particular no salary,
    /// commitment, or key material. Pinning this down as `()` protects
    /// against a future change accidentally attaching a sensitive value.
    #[test]
    fn test_audit_access_revoked_data_is_empty() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();
        let data: Result<(), _> = event.2.try_into_val(&env);
        assert!(data.is_ok(), "AuditAccessRevoked data must decode as empty");
    }

    // ── No event on a failed revocation attempt ───────────────────────────────

    /// An unauthorized revocation attempt must be a complete no-op,
    /// including no event — an observer watching for `AuditAccessRevoked`
    /// must never see a signal for a grant that is still fully live.
    #[test]
    fn test_failed_revoke_wrong_granter_emits_no_event() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let before = env.events().all().len();
        let interloper = Address::generate(&env);
        let result = client.try_revoke_view_key(&interloper, &auditor);
        assert!(result.is_err());

        let after = env.events().all().len();
        assert_eq!(
            after, before,
            "a rejected revocation must not emit any event"
        );
    }

    /// Revoking an auditor who was never granted a key must also be a
    /// silent, event-free failure.
    #[test]
    fn test_failed_revoke_unknown_auditor_emits_no_event() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let before = env.events().all().len();

        let admin = contract_id.clone();
        let result = client.try_revoke_view_key(&admin, &stranger);
        assert!(result.is_err());

        let after = env.events().all().len();
        assert_eq!(
            after, before,
            "revoking an unknown auditor must not emit any event"
        );
    }

    // ── Revocation event targets exactly the intended auditor ────────────────

    /// When two auditors hold live grants, revoking one must emit an event
    /// naming exactly that auditor — never the other one.
    #[test]
    fn test_revoked_event_names_exactly_the_targeted_auditor() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor_a = Address::generate(&env);
        let auditor_b = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor_a, &(seq + 1_000));
        client.generate_view_key(&auditor_b, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor_a);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();
        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "AuditAccessRevoked"));
        let named_auditor: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(named_auditor, auditor_a);
        assert_ne!(named_auditor, auditor_b);
    }

    // ── ViewKeyGenerated: privacy of the event payload ────────────────────────

    /// The generated key material itself must never appear in the public
    /// event — only the expiration ledger. Leaking the raw key bytes would
    /// let anyone perform keyed-commitment checks without ever holding a
    /// genuine grant, defeating the point of a per-auditor view key.
    #[test]
    fn test_view_key_generated_event_data_excludes_raw_key_bytes() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        let expiration = seq + 1_000;
        let key_bytes = client.generate_view_key(&auditor, &expiration);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "ViewKeyGenerated"));

        // The data payload decodes as exactly one u32 (expiration_ledger).
        // Soroban's tuple decoding enforces exact arity — if the payload
        // also carried the 32-byte key material, this single-field decode
        // would fail (and does, if you widen the target type), so a
        // successful decode here is itself the proof that no extra field —
        // in particular no key bytes — is present.
        let data: (u32,) = event.2.try_into_val(&env).unwrap();
        assert_eq!(data.0, expiration);

        // Sanity: the key returned to the caller is still real 32-byte
        // material — it's just never published in the event.
        assert_eq!(key_bytes.len(), 32);
    }
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
    topics.get(1).unwrap().try_into_val(env).ok()
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
