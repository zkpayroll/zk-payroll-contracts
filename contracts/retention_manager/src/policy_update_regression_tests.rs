//! Regression tests for retention policy updates (issue #974).
//!
//! A policy update is `set_retention_override`. The rule these tests hold in place: an update
//! applies to records registered after it, never to records already registered, and it never
//! weakens a protection (a block, a tombstone) that an earlier record already has.
extern crate std;

use super::*;
use pause_manager::{PauseManager, PauseManagerClient};
use soroban_sdk::testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke};
use soroban_sdk::{Env, IntoVal};

const COMPANY: u64 = 7;

fn setup() -> (
    Env,
    Address,
    Address,
    RetentionManagerContractClient<'static>,
) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_000_000);
    let contract_id = env.register(RetentionManagerContract, ());
    let admin = Address::generate(&env);
    let client = RetentionManagerContractClient::new(&env, &contract_id);
    client.initialize(&admin);
    (env, contract_id, admin, client)
}

fn advance(env: &Env, secs: u64) {
    env.ledger().with_mut(|l| l.timestamp += secs);
}

fn eligible(client: &RetentionManagerContractClient, id: u64, kind: RecordType) -> bool {
    client.is_eligible_for_pruning(&COMPANY, &id, &kind)
}

fn paused(
    env: &Env,
    admin: &Address,
    client: &RetentionManagerContractClient,
) -> PauseManagerClient<'static> {
    let pm_id = env.register(PauseManager, ());
    let pm = PauseManagerClient::new(env, &pm_id);
    pm.initialize(admin);
    client.set_pause_manager(&pm_id);
    pm.pause();
    pm
}

// ── Default windows ─────────────────────────────────────────────────────────────────────────────

#[test]
fn each_record_type_gets_its_documented_default_window() {
    let (env, _id, _admin, client) = setup();
    let now = env.ledger().timestamp();
    let cases = [
        (RecordType::FinalizedBatch, 365u64 * 86_400),
        (RecordType::CancelledBatch, 90 * 86_400),
        (RecordType::ExpiredAuditGrant, 30 * 86_400),
        (RecordType::ChallengeRecord, 730 * 86_400),
    ];
    for (i, (kind, window)) in cases.iter().enumerate() {
        let record = client.register_record(&COMPANY, &(i as u64 + 1), kind);
        assert_eq!(record.eligible_after, now + window);
        assert_eq!(record.registered_at, now);
    }
}

// ── The boundary ────────────────────────────────────────────────────────────────────────────────

#[test]
fn eligible_at_exactly_eligible_after_and_not_one_second_before() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &100u64);
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    advance(&env, 99);
    assert!(!eligible(&client, 1, RecordType::FinalizedBatch));
    advance(&env, 1);
    assert!(eligible(&client, 1, RecordType::FinalizedBatch));
}

#[test]
fn prune_at_the_boundary_succeeds_and_one_second_before_is_refused() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::CancelledBatch, &50u64);
    client.register_record(&COMPANY, &1u64, &RecordType::CancelledBatch);

    advance(&env, 49);
    assert_eq!(
        client
            .try_prune_record(&COMPANY, &1u64, &RecordType::CancelledBatch)
            .unwrap_err()
            .unwrap(),
        RetentionError::RetentionWindowActive
    );
    advance(&env, 1);
    client.prune_record(&COMPANY, &1u64, &RecordType::CancelledBatch);
    assert!(
        client
            .get_record(&COMPANY, &1u64, &RecordType::CancelledBatch)
            .unwrap()
            .pruned
    );
}

// ── An update only reaches records registered after it ──────────────────────────────────────────

#[test]
fn lengthening_the_window_does_not_extend_an_existing_record() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &10u64);
    let before = client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1_000_000u64);

    advance(&env, 10);
    assert!(eligible(&client, 1, RecordType::FinalizedBatch));
    assert_eq!(
        client
            .get_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
            .unwrap()
            .eligible_after,
        before.eligible_after
    );
}

#[test]
fn a_later_update_replaces_an_earlier_one_for_new_records_only() {
    let (env, _id, _admin, client) = setup();
    let now = env.ledger().timestamp();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &10u64);
    let first = client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &20u64);
    let second = client.register_record(&COMPANY, &2u64, &RecordType::FinalizedBatch);
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &30u64);
    let third = client.register_record(&COMPANY, &3u64, &RecordType::FinalizedBatch);

    assert_eq!(first.eligible_after, now + 10);
    assert_eq!(second.eligible_after, now + 20);
    assert_eq!(third.eligible_after, now + 30);
}

#[test]
fn clearing_an_override_gives_new_records_the_default_and_keeps_old_ones() {
    let (env, _id, _admin, client) = setup();
    let now = env.ledger().timestamp();
    client.set_retention_override(&COMPANY, &RecordType::ChallengeRecord, &5u64);
    let old = client.register_record(&COMPANY, &1u64, &RecordType::ChallengeRecord);
    client.set_retention_override(&COMPANY, &RecordType::ChallengeRecord, &0u64);
    let new = client.register_record(&COMPANY, &2u64, &RecordType::ChallengeRecord);

    assert_eq!(old.eligible_after, now + 5);
    assert_eq!(new.eligible_after, now + CHALLENGE_RETENTION_SECS);
    advance(&env, 5);
    assert!(eligible(&client, 1, RecordType::ChallengeRecord));
    assert!(!eligible(&client, 2, RecordType::ChallengeRecord));
}

#[test]
fn clearing_an_override_that_was_never_set_changes_nothing() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &0u64);

    let record = client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    assert_eq!(
        record.eligible_after,
        env.ledger().timestamp() + FINALIZED_RETENTION_SECS
    );
}

#[test]
fn an_override_for_one_record_type_leaves_the_other_types_on_defaults() {
    let (env, _id, _admin, client) = setup();
    let now = env.ledger().timestamp();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);

    assert_eq!(
        client
            .register_record(&COMPANY, &1u64, &RecordType::CancelledBatch)
            .eligible_after,
        now + CANCELLED_RETENTION_SECS
    );
    assert_eq!(
        client
            .register_record(&COMPANY, &2u64, &RecordType::ExpiredAuditGrant)
            .eligible_after,
        now + AUDIT_GRANT_RETENTION_SECS
    );
    assert_eq!(
        client
            .register_record(&COMPANY, &3u64, &RecordType::ChallengeRecord)
            .eligible_after,
        now + CHALLENGE_RETENTION_SECS
    );
}

#[test]
fn an_override_can_be_set_for_a_company_with_no_records() {
    let (_env, _id, _admin, client) = setup();

    client.set_retention_override(&999u64, &RecordType::ChallengeRecord, &42u64);

    let record = client.register_record(&999u64, &1u64, &RecordType::ChallengeRecord);
    assert_eq!(record.eligible_after - record.registered_at, 42);
}

// ── A policy update never weakens a protection ──────────────────────────────────────────────────

#[test]
fn a_shorter_window_does_not_lift_an_audit_block() {
    let (env, _id, _admin, client) = setup();
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    client.set_audit_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &true);

    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);
    advance(&env, FINALIZED_RETENTION_SECS + 1);

    assert!(!eligible(&client, 1, RecordType::FinalizedBatch));
    assert_eq!(
        client
            .try_prune_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
            .unwrap_err()
            .unwrap(),
        RetentionError::ActiveAuditBlock
    );
}

#[test]
fn a_shorter_window_does_not_lift_a_challenge_block() {
    let (env, _id, _admin, client) = setup();
    client.register_record(&COMPANY, &1u64, &RecordType::ChallengeRecord);
    client.set_challenge_block(&COMPANY, &1u64, &RecordType::ChallengeRecord, &true);

    client.set_retention_override(&COMPANY, &RecordType::ChallengeRecord, &1u64);
    advance(&env, CHALLENGE_RETENTION_SECS + 1);

    assert_eq!(
        client
            .try_prune_record(&COMPANY, &1u64, &RecordType::ChallengeRecord)
            .unwrap_err()
            .unwrap(),
        RetentionError::ActiveChallengeBlock
    );
}

#[test]
fn both_blocks_must_clear_before_a_record_can_be_pruned() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    client.set_audit_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &true);
    client.set_challenge_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &true);
    advance(&env, 5);

    client.set_audit_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &false);
    assert!(
        !eligible(&client, 1, RecordType::FinalizedBatch),
        "challenge still blocks"
    );
    client.set_challenge_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &false);
    assert!(eligible(&client, 1, RecordType::FinalizedBatch));
}

#[test]
fn registering_an_existing_record_again_is_rejected() {
    let (_env, _id, _admin, client) = setup();
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    assert!(client
        .try_register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
        .is_err());
}

#[test]
fn registering_again_cannot_clear_a_block() {
    let (_env, _id, _admin, client) = setup();
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    client.set_audit_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &true);
    client.set_challenge_block(&COMPANY, &1u64, &RecordType::FinalizedBatch, &true);

    let _ = client.try_register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    let record = client
        .get_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
        .unwrap();
    assert!(record.audit_block && record.challenge_block);
}

#[test]
fn registering_again_cannot_un_prune_a_tombstone_even_with_a_new_policy() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    advance(&env, 1);
    client.prune_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1_000u64);
    let _ = client.try_register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    assert!(
        client
            .get_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
            .unwrap()
            .pruned
    );
    assert!(
        !eligible(&client, 1, RecordType::FinalizedBatch),
        "a pruned record is never eligible"
    );
}

#[test]
fn the_same_record_id_under_another_type_or_company_registers_independently() {
    let (_env, _id, _admin, client) = setup();
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    client.register_record(&COMPANY, &1u64, &RecordType::CancelledBatch);
    client.register_record(&(COMPANY + 1), &1u64, &RecordType::FinalizedBatch);
}

#[test]
fn a_pruned_record_does_not_make_a_sibling_eligible_or_pruned() {
    let (env, _id, _admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    client.register_record(&COMPANY, &2u64, &RecordType::CancelledBatch);
    advance(&env, 1);
    client.prune_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);

    assert!(
        !client
            .get_record(&COMPANY, &2u64, &RecordType::CancelledBatch)
            .unwrap()
            .pruned
    );
    assert!(!eligible(&client, 2, RecordType::CancelledBatch));
}

// ── Who may change the policy, and when ─────────────────────────────────────────────────────────

#[test]
fn the_purger_cannot_change_the_retention_policy() {
    let (env, contract_id, _admin, client) = setup();
    let purger = Address::generate(&env);
    client.set_purger(&purger);

    env.mock_auths(&[MockAuth {
        address: &purger,
        invoke: &MockAuthInvoke {
            contract: &contract_id,
            fn_name: "set_retention_override",
            args: (COMPANY, RecordType::FinalizedBatch, 1u64).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    assert!(client
        .try_set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64)
        .is_err());
}

#[test]
fn a_rejected_policy_update_leaves_the_current_policy_in_force() {
    let (env, contract_id, _admin, client) = setup();
    let now = env.ledger().timestamp();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &500u64);

    let attacker = Address::generate(&env);
    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &contract_id,
            fn_name: "set_retention_override",
            args: (COMPANY, RecordType::FinalizedBatch, 1u64).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    let _ = client.try_set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);

    env.mock_all_auths();
    let record = client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    assert_eq!(record.eligible_after, now + 500);
}

#[test]
fn a_paused_contract_refuses_a_policy_update_and_keeps_the_old_policy() {
    let (env, _id, admin, client) = setup();
    let now = env.ledger().timestamp();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &500u64);
    let pm = paused(&env, &admin, &client);

    assert!(client
        .try_set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64)
        .is_err());

    pm.unpause();
    let record = client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    assert_eq!(record.eligible_after, now + 500);
}

#[test]
fn a_paused_contract_refuses_to_register_and_to_prune() {
    let (env, _id, admin, client) = setup();
    client.set_retention_override(&COMPANY, &RecordType::FinalizedBatch, &1u64);
    client.register_record(&COMPANY, &1u64, &RecordType::FinalizedBatch);
    advance(&env, 1);
    let _pm = paused(&env, &admin, &client);

    assert!(client
        .try_register_record(&COMPANY, &2u64, &RecordType::FinalizedBatch)
        .is_err());
    assert!(client
        .try_prune_record(&COMPANY, &1u64, &RecordType::FinalizedBatch)
        .is_err());
}
