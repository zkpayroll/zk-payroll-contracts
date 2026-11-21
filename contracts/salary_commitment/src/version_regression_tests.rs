//! Regression tests for salary commitment versions (issue #954).
//!
//! The version invariants are documented at the top of `lib.rs`. These tests pin the cases the
//! original suite does not reach: storing twice for one employee, the counter at its ceiling,
//! versions after rejected calls, and the link between the live version and the archived history.
extern crate std;

use super::*;
use soroban_sdk::testutils::Address as _;

fn setup() -> (Env, Address, SalaryCommitmentContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SalaryCommitmentContract, ());
    let client = SalaryCommitmentContractClient::new(&env, &contract_id);
    client.init_commitment_admin(&Address::generate(&env));
    (env, contract_id, client)
}

fn value(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}

/// Writes the live version straight into storage, standing in for an employee who has been through
/// an enormous number of rotations.
fn force_version(env: &Env, contract_id: &Address, employee: &Address, version: u32) {
    env.as_contract(contract_id, || {
        let key = DataKey::Commitment(employee.clone());
        let mut record: SalaryCommitment = env.storage().persistent().get(&key).unwrap();
        record.version = version;
        env.storage().persistent().set(&key, &record);
    });
}

// ── I-V1 / I-V4: the counter cannot be reset by storing again ───────────────────────────────────

#[test]
fn second_store_for_the_same_employee_is_rejected() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));

    assert!(client
        .try_store_commitment(&employee, &value(&env, 2))
        .is_err());
}

#[test]
fn rejected_second_store_leaves_version_commitment_and_history_untouched() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.update_commitment(&employee, &value(&env, 2));
    client.update_commitment(&employee, &value(&env, 3));

    let _ = client.try_store_commitment(&employee, &value(&env, 4));

    let live = client.get_commitment(&employee);
    assert_eq!(live.version, 3, "version must not be reset to 1");
    assert_eq!(live.commitment, value(&env, 3));
    assert_eq!(client.get_commitment_history(&employee).len(), 2);
}

#[test]
fn rejected_second_store_does_not_reserve_the_new_value() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    let _ = client.try_store_commitment(&employee, &value(&env, 2));

    // The rejected value was never bound, so another employee can still use it.
    client.store_commitment(&Address::generate(&env), &value(&env, 2));
}

#[test]
fn storing_after_rotation_is_still_rejected() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.rotate_commitment(&employee, &value(&env, 2));

    assert!(client
        .try_store_commitment(&employee, &value(&env, 3))
        .is_err());
    assert_eq!(client.get_commitment(&employee).version, 2);
}

// ── Boundary: the counter at u32::MAX ───────────────────────────────────────────────────────────

#[test]
fn update_at_the_version_ceiling_saturates_instead_of_panicking() {
    let (env, id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    force_version(&env, &id, &employee, u32::MAX);

    let updated = client.update_commitment(&employee, &value(&env, 2));

    assert_eq!(updated.version, u32::MAX);
    assert_eq!(updated.commitment, value(&env, 2));
}

#[test]
fn rotate_at_the_version_ceiling_saturates_instead_of_panicking() {
    let (env, id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    force_version(&env, &id, &employee, u32::MAX);

    let rotated = client.rotate_commitment(&employee, &value(&env, 2));

    assert_eq!(rotated.version, u32::MAX);
}

#[test]
fn rotate_approved_at_the_version_ceiling_saturates_instead_of_panicking() {
    let (env, id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.lock_commitment_updates(&employee);
    force_version(&env, &id, &employee, u32::MAX);

    let rotated = client.rotate_approved_commitment(&employee, &value(&env, 2));

    assert_eq!(rotated.version, u32::MAX);
    assert!(
        client.is_commitment_locked(&employee),
        "the lock must survive"
    );
}

#[test]
fn the_ceiling_still_archives_the_outgoing_commitment_with_its_own_version() {
    let (env, id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    force_version(&env, &id, &employee, u32::MAX);

    client.update_commitment(&employee, &value(&env, 2));

    let history = client.get_commitment_history(&employee);
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(0).unwrap().version, u32::MAX);
    assert_eq!(history.get(0).unwrap().commitment, value(&env, 1));
}

#[test]
fn one_below_the_ceiling_still_counts_normally() {
    let (env, id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    force_version(&env, &id, &employee, u32::MAX - 1);

    assert_eq!(
        client.update_commitment(&employee, &value(&env, 2)).version,
        u32::MAX
    );
}

// ── Rejected calls never move the counter ───────────────────────────────────────────────────────

#[test]
fn update_rejected_by_the_lock_keeps_the_version() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.lock_commitment_updates(&employee);

    assert!(client
        .try_update_commitment(&employee, &value(&env, 2))
        .is_err());

    assert_eq!(client.get_commitment(&employee).version, 1);
    assert_eq!(client.get_commitment_history(&employee).len(), 0);
}

#[test]
fn update_to_a_value_bound_to_someone_else_keeps_the_version() {
    let (env, _id, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.store_commitment(&bob, &value(&env, 2));

    assert!(client
        .try_update_commitment(&alice, &value(&env, 2))
        .is_err());

    assert_eq!(client.get_commitment(&alice).version, 1);
    assert_eq!(client.get_commitment_history(&alice).len(), 0);
}

#[test]
fn update_to_the_zero_value_keeps_the_version() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));

    assert!(client
        .try_update_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]))
        .is_err());

    assert_eq!(client.get_commitment(&employee).version, 1);
}

#[test]
fn update_for_an_employee_without_a_commitment_is_rejected() {
    let (env, _id, client) = setup();

    assert!(client
        .try_update_commitment(&Address::generate(&env), &value(&env, 1))
        .is_err());
}

#[test]
fn rotate_rejected_by_the_lock_keeps_the_version() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.lock_commitment_updates(&employee);

    assert!(client
        .try_rotate_commitment(&employee, &value(&env, 2))
        .is_err());

    assert_eq!(client.get_commitment(&employee).version, 1);
}

// ── The live version and the history stay in step ───────────────────────────────────────────────

#[test]
fn history_holds_every_earlier_version_in_order() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.update_commitment(&employee, &value(&env, 2));
    client.rotate_commitment(&employee, &value(&env, 3));
    client.update_commitment(&employee, &value(&env, 4));

    let live = client.get_commitment(&employee);
    let history = client.get_commitment_history(&employee);

    assert_eq!(live.version, 4);
    assert_eq!(
        history.len(),
        live.version - 1,
        "one snapshot per superseded version"
    );
    for (i, snapshot) in history.iter().enumerate() {
        assert_eq!(
            snapshot.version,
            i as u32 + 1,
            "snapshots run 1..n-1 in order"
        );
        assert_eq!(snapshot.commitment, value(&env, i as u8 + 1));
    }
}

#[test]
fn a_new_commitment_has_an_empty_history() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));

    assert_eq!(client.get_commitment(&employee).version, 1);
    assert_eq!(client.get_commitment_history(&employee).len(), 0);
}

#[test]
fn archived_snapshots_do_not_change_when_the_commitment_moves_on() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.update_commitment(&employee, &value(&env, 2));
    let before = client.get_commitment_history(&employee).get(0).unwrap();

    client.update_commitment(&employee, &value(&env, 3));
    client.rotate_commitment(&employee, &value(&env, 4));

    let after = client.get_commitment_history(&employee).get(0).unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.commitment, before.commitment);
    assert_eq!(after.rotated_at, before.rotated_at);
}

#[test]
fn updating_one_employee_does_not_touch_another_employees_history() {
    let (env, _id, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.store_commitment(&bob, &value(&env, 2));
    client.update_commitment(&alice, &value(&env, 3));
    client.update_commitment(&alice, &value(&env, 4));

    assert_eq!(client.get_commitment(&bob).version, 1);
    assert_eq!(client.get_commitment_history(&bob).len(), 0);
    assert_eq!(client.get_commitment_history(&alice).len(), 2);
}

#[test]
fn created_at_survives_updates_while_updated_at_moves() {
    use soroban_sdk::testutils::Ledger;
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    env.ledger().set_timestamp(1_000);
    client.store_commitment(&employee, &value(&env, 1));
    env.ledger().set_timestamp(2_000);
    let updated = client.update_commitment(&employee, &value(&env, 2));

    assert_eq!(updated.created_at, 1_000);
    assert_eq!(updated.updated_at, 2_000);
    assert_eq!(updated.version, 2);
}

#[test]
fn a_rotated_out_value_stays_revoked_and_the_new_one_is_active() {
    let (env, _id, client) = setup();
    let employee = Address::generate(&env);
    client.store_commitment(&employee, &value(&env, 1));
    client.rotate_commitment(&employee, &value(&env, 2));

    let live = client.get_commitment(&employee);
    assert_eq!(live.commitment, value(&env, 2));
    assert!(!live.revoked);
    assert!(client.is_commitment_active(&employee));
}
