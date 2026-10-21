use audit_module::{AuditError, AuditLifecycleStage, AuditModule, AuditModuleClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Env, Symbol, Vec};

#[test]
fn test_audit_event_sequence_verification_success_path() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    let canonical_events: Vec<Symbol> = vec![
        &env,
        Symbol::new(&env, "ViewKeyGenerated"),
        Symbol::new(&env, "ViewKeyRefreshed"),
        Symbol::new(&env, "AuditSuccessful"),
        Symbol::new(&env, "AuditSummaryExported"),
        Symbol::new(&env, "AuditAccessRevoked"),
        Symbol::new(&env, "AuditGrantPruned"),
    ];

    let result = client.verify_audit_event_sequence(&canonical_events);
    assert_eq!(result, true);
}

#[test]
fn test_audit_event_sequence_verification_failure_path_out_of_order() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    // Fails because AuditSuccessful occurs before ViewKeyGenerated
    let invalid_sequence: Vec<Symbol> = vec![
        &env,
        Symbol::new(&env, "AuditSuccessful"),
        Symbol::new(&env, "ViewKeyGenerated"),
    ];

    let result = client.try_verify_audit_event_sequence(&invalid_sequence);
    assert_eq!(result.unwrap_err().unwrap(), AuditError::InvalidEventSequence);

    // Fails because AuditGrantPruned occurs without prior revocation/expiry
    let premature_prune: Vec<Symbol> = vec![
        &env,
        Symbol::new(&env, "ViewKeyGenerated"),
        Symbol::new(&env, "AuditGrantPruned"),
    ];

    let prune_result = client.try_verify_audit_event_sequence(&premature_prune);
    assert_eq!(prune_result.unwrap_err().unwrap(), AuditError::InvalidEventSequence);
}

#[test]
fn test_audit_event_sequence_verification_edge_cases() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    // Edge case 1: Empty event sequence
    let empty_events: Vec<Symbol> = vec![&env];
    let empty_result = client.try_verify_audit_event_sequence(&empty_events);
    assert_eq!(empty_result.unwrap_err().unwrap(), AuditError::InvalidEventSequence);

    // Edge case 2: Duplicate key generation event
    let duplicate_gen: Vec<Symbol> = vec![
        &env,
        Symbol::new(&env, "ViewKeyGenerated"),
        Symbol::new(&env, "ViewKeyGenerated"),
    ];
    let dup_result = client.try_verify_audit_event_sequence(&duplicate_gen);
    assert_eq!(dup_result.unwrap_err().unwrap(), AuditError::InvalidEventSequence);

    // Edge case 3: Event after AuditGrantPruned
    let post_prune: Vec<Symbol> = vec![
        &env,
        Symbol::new(&env, "ViewKeyGenerated"),
        Symbol::new(&env, "AuditAccessRevoked"),
        Symbol::new(&env, "AuditGrantPruned"),
        Symbol::new(&env, "AuditSuccessful"),
    ];
    let post_prune_result = client.try_verify_audit_event_sequence(&post_prune);
    assert_eq!(post_prune_result.unwrap_err().unwrap(), AuditError::InvalidEventSequence);
}

#[test]
fn test_audit_lifecycle_stage_transitions() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let admin = contract_id.clone();
    let expiration = env.ledger().sequence() + 1_000;

    // Initially None
    assert_eq!(client.get_audit_lifecycle_stage(&auditor), AuditLifecycleStage::None);

    // After key generation -> Granted
    client.generate_view_key(&auditor, &expiration);
    assert_eq!(client.get_audit_lifecycle_stage(&auditor), AuditLifecycleStage::Granted);

    // After refresh -> Active
    client.refresh_view_key(&admin, &auditor, &(expiration + 500));
    assert_eq!(client.get_audit_lifecycle_stage(&auditor), AuditLifecycleStage::Active);

    // After revocation -> Revoked
    client.revoke_view_key(&admin, &auditor);
    assert_eq!(client.get_audit_lifecycle_stage(&auditor), AuditLifecycleStage::Revoked);
}
