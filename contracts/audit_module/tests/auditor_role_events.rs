use audit_module::{AuditModule, AuditModuleClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, Env, IntoVal, Symbol};

// soroban-sdk 27.x changed `Events::all()` to return a `ContractEvents`
// struct instead of an indexable/iterable `Vec`. `.events()` still exposes
// the raw XDR events as a plain slice (usable for count checks), and
// `ContractEvents` keeps a backward-compatible `PartialEq` against a full
// `Vec<(Address, Vec<Val>, Val)>`, which the content checks below use.
fn event_count(env: &Env) -> u32 {
    env.events().all().events().len() as u32
}

#[test]
fn assignment_and_removal_events_have_stable_privacy_safe_payloads() {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract);
    let auditor = Address::generate(&env);
    let admin = contract.clone();
    let expiration = env.ledger().sequence() + 1_000;

    client.generate_view_key(&auditor, &expiration);
    assert_eq!(
        env.events().all(),
        soroban_sdk::vec![
            &env,
            (
                contract.clone(),
                soroban_sdk::vec![
                    &env,
                    Symbol::new(&env, "ViewKeyGenerated").into_val(&env),
                    auditor.clone().into_val(&env),
                ],
                (expiration,).into_val(&env),
            ),
        ]
    );

    // `env.events().all()` scopes to the *last* invocation only (soroban-sdk
    // 27.x), so after this call only `AuditAccessRevoked` is present — the
    // earlier `ViewKeyGenerated` event is not carried over.
    client.revoke_view_key(&admin, &auditor);
    assert_eq!(
        env.events().all(),
        soroban_sdk::vec![
            &env,
            (
                contract.clone(),
                soroban_sdk::vec![
                    &env,
                    Symbol::new(&env, "AuditAccessRevoked").into_val(&env),
                    admin.clone().into_val(&env),
                    auditor.clone().into_val(&env),
                ],
                ().into_val(&env),
            ),
        ]
    );
}

#[test]
fn failed_removal_emits_no_role_event_and_keeps_assignment() {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract);
    let auditor = Address::generate(&env);

    client.generate_view_key(&auditor, &(env.ledger().sequence() + 1_000));

    // A failed (`Err`-returning) invocation is rolled back by Soroban's
    // atomicity guarantee, so `env.events().all()` reports zero events for
    // it regardless of what ran beforehand — confirming no removal-style
    // event (or anything else) was emitted for this rejected call.
    assert!(client
        .try_revoke_view_key(&Address::generate(&env), &auditor)
        .is_err());
    assert_eq!(event_count(&env), 0);
    assert!(client.verify_access(&auditor));
}
