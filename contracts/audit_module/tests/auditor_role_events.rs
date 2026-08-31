use audit_module::{AuditModule, AuditModuleClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{Address, Env, Symbol, TryFromVal, TryIntoVal};

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
    let assigned = env.events().all().last().unwrap();
    assert_eq!(assigned.1.len(), 2);
    assert_eq!(
        Symbol::try_from_val(&env, &assigned.1.get(0).unwrap()).unwrap(),
        Symbol::new(&env, "ViewKeyGenerated")
    );
    assert_eq!(
        Address::try_from_val(&env, &assigned.1.get(1).unwrap()).unwrap(),
        auditor
    );
    let assignment_data: (u32,) = assigned.2.try_into_val(&env).unwrap();
    assert_eq!(assignment_data, (expiration,));

    client.revoke_view_key(&admin, &auditor);
    let removed = env.events().all().last().unwrap();
    assert_eq!(removed.1.len(), 3);
    assert_eq!(
        Symbol::try_from_val(&env, &removed.1.get(0).unwrap()).unwrap(),
        Symbol::new(&env, "AuditAccessRevoked")
    );
    assert_eq!(
        Address::try_from_val(&env, &removed.1.get(1).unwrap()).unwrap(),
        admin
    );
    assert_eq!(
        Address::try_from_val(&env, &removed.1.get(2).unwrap()).unwrap(),
        auditor
    );
    let removal_data: () = removed.2.try_into_val(&env).unwrap();
    assert_eq!(removal_data, ());
}

#[test]
fn failed_removal_emits_no_role_event_and_keeps_assignment() {
    let env = Env::default();
    env.mock_all_auths();
    let contract = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract);
    let auditor = Address::generate(&env);

    client.generate_view_key(&auditor, &(env.ledger().sequence() + 1_000));
    let event_count = env.events().all().len();

    assert!(client
        .try_revoke_view_key(&Address::generate(&env), &auditor)
        .is_err());
    assert_eq!(env.events().all().len(), event_count);
    assert!(client.verify_access(&auditor));
}
