//! Archive queries after a retention policy migration (issue #891).
//!
//! Off-chain archive systems read `get_record` and `is_eligible_for_pruning`.
//! A policy migration (`set_retention_override`) must not change what those
//! queries return for records registered before it, including tombstones,
//! and must not leak across companies.
extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};

const COMPANY: u64 = 11;
const OTHER_COMPANY: u64 = 12;
const KIND: RecordType = RecordType::CancelledBatch;
const MIGRATED_WINDOW: u64 = CANCELLED_RETENTION_SECS * 2;

fn setup() -> (Env, RetentionManagerContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 5_000_000);
    let contract_id = env.register(RetentionManagerContract, ());
    let client = RetentionManagerContractClient::new(&env, &contract_id);
    client.initialize(&Address::generate(&env));
    (env, client)
}

fn advance(env: &Env, secs: u64) {
    env.ledger().with_mut(|l| l.timestamp += secs);
}

fn migrate(client: &RetentionManagerContractClient) {
    client.set_retention_override(&COMPANY, &KIND, &MIGRATED_WINDOW);
}

fn assert_same_record(a: &RetentionRecord, b: &RetentionRecord) {
    assert_eq!(a.record_id, b.record_id);
    assert_eq!(a.record_type, b.record_type);
    assert_eq!(a.registered_at, b.registered_at);
    assert_eq!(a.eligible_after, b.eligible_after);
    assert_eq!(a.audit_block, b.audit_block);
    assert_eq!(a.challenge_block, b.challenge_block);
    assert_eq!(a.pruned, b.pruned);
}

#[test]
fn existing_record_reads_back_unchanged_after_migration() {
    let (env, client) = setup();
    client.register_record(&COMPANY, &1u64, &KIND);
    client.set_audit_block(&COMPANY, &1u64, &KIND, &true);
    let before = client.get_record(&COMPANY, &1u64, &KIND).unwrap();

    migrate(&client);
    advance(&env, 1);

    let after = client.get_record(&COMPANY, &1u64, &KIND).unwrap();
    assert_same_record(&before, &after);
    assert_eq!(
        after.eligible_after,
        after.registered_at + CANCELLED_RETENTION_SECS
    );
}

#[test]
fn tombstone_pruned_before_migration_stays_queryable_and_final() {
    let (env, client) = setup();
    client.register_record(&COMPANY, &2u64, &KIND);
    advance(&env, CANCELLED_RETENTION_SECS);
    client.prune_record(&COMPANY, &2u64, &KIND);
    let tombstone = client.get_record(&COMPANY, &2u64, &KIND).unwrap();

    migrate(&client);

    let after = client.get_record(&COMPANY, &2u64, &KIND).unwrap();
    assert_same_record(&tombstone, &after);
    assert!(after.pruned);
    assert!(!client.is_eligible_for_pruning(&COMPANY, &2u64, &KIND));
    assert_eq!(client.try_prune_record(&COMPANY, &2u64, &KIND), Ok(Ok(())));
}

#[test]
fn mixed_cohorts_answer_eligibility_by_their_own_registration_policy() {
    let (env, client) = setup();
    client.register_record(&COMPANY, &10u64, &KIND);
    migrate(&client);
    let migrated = client.register_record(&COMPANY, &20u64, &KIND);
    assert_eq!(
        migrated.eligible_after,
        migrated.registered_at + MIGRATED_WINDOW
    );

    advance(&env, CANCELLED_RETENTION_SECS);
    assert!(client.is_eligible_for_pruning(&COMPANY, &10u64, &KIND));
    assert!(!client.is_eligible_for_pruning(&COMPANY, &20u64, &KIND));
    assert_eq!(
        client.try_prune_record(&COMPANY, &20u64, &KIND),
        Err(Ok(RetentionError::RetentionWindowActive))
    );

    advance(&env, MIGRATED_WINDOW - CANCELLED_RETENTION_SECS);
    assert!(client.is_eligible_for_pruning(&COMPANY, &20u64, &KIND));
}

#[test]
fn migration_for_one_company_does_not_change_another_companys_queries() {
    let (env, client) = setup();
    let other = client.register_record(&OTHER_COMPANY, &1u64, &KIND);
    migrate(&client);
    let other_new = client.register_record(&OTHER_COMPANY, &2u64, &KIND);

    assert_eq!(
        other_new.eligible_after,
        other_new.registered_at + CANCELLED_RETENTION_SECS
    );
    assert_same_record(
        &other,
        &client.get_record(&OTHER_COMPANY, &1u64, &KIND).unwrap(),
    );
    advance(&env, CANCELLED_RETENTION_SECS);
    assert!(client.is_eligible_for_pruning(&OTHER_COMPANY, &2u64, &KIND));
}

#[test]
fn migration_for_one_record_type_leaves_other_types_on_defaults() {
    let (_env, client) = setup();
    migrate(&client);
    let finalized = client.register_record(&COMPANY, &3u64, &RecordType::FinalizedBatch);
    assert_eq!(
        finalized.eligible_after,
        finalized.registered_at + FINALIZED_RETENTION_SECS
    );
}

#[test]
fn unknown_records_stay_absent_after_migration() {
    let (_env, client) = setup();
    migrate(&client);
    assert!(client.get_record(&COMPANY, &99u64, &KIND).is_none());
    assert!(!client.is_eligible_for_pruning(&COMPANY, &99u64, &KIND));
    assert_eq!(
        client.try_prune_record(&COMPANY, &99u64, &KIND),
        Err(Ok(RetentionError::RecordNotFound))
    );
}
