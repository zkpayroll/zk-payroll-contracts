//! Adversarial tests for beneficiary changes (issue #963).
//!
//! In this contract the beneficiary of a payroll entry is the employee address, bound to a salary
//! commitment and optionally to an external reference id. A "beneficiary change" is anything that
//! re-points one of those bindings: updating or rotating a commitment, remapping a reference id,
//! or handing the admin role to someone else. Each test plays an attacker or a mistake and checks
//! that the existing bindings survive. The invariants are written up in
//! `docs/beneficiary-change-invariants.md`.
extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{IntoVal, String as SorobanString};

fn setup() -> (
    Env,
    Address,
    Address,
    SalaryCommitmentContractClient<'static>,
) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SalaryCommitmentContract, ());
    let client = SalaryCommitmentContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init_commitment_admin(&admin);
    (env, contract_id, admin, client)
}

fn value(env: &Env, n: u8) -> BytesN<32> {
    BytesN::from_array(env, &[n; 32])
}

fn id(env: &Env, text: &str) -> SorobanString {
    SorobanString::from_str(env, text)
}

/// Only `signer` authorises the next call to `fn_name`; the admin's signature is absent.
fn only_signer(
    env: &Env,
    contract_id: &Address,
    signer: &Address,
    fn_name: &'static str,
    args: soroban_sdk::Vec<soroban_sdk::Val>,
) {
    env.mock_auths(&[MockAuth {
        address: signer,
        invoke: &MockAuthInvoke {
            contract: contract_id,
            fn_name,
            args,
            sub_invokes: &[],
        },
    }]);
}

// ── Commitment re-binding ───────────────────────────────────────────────────────────────────────

#[test]
fn one_employee_cannot_take_over_anothers_commitment_value() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.store_commitment(&bob, &value(&env, 2));

    assert!(client.try_update_commitment(&bob, &value(&env, 1)).is_err());
    assert!(client.try_rotate_commitment(&bob, &value(&env, 1)).is_err());

    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 1));
    assert_eq!(client.get_commitment(&bob).commitment, value(&env, 2));
}

#[test]
fn a_retired_value_cannot_be_given_to_another_employee() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.store_commitment(&bob, &value(&env, 2));
    client.update_commitment(&alice, &value(&env, 3));

    assert!(client.try_update_commitment(&bob, &value(&env, 1)).is_err());
    assert!(client
        .try_store_commitment(&Address::generate(&env), &value(&env, 1))
        .is_err());
}

#[test]
fn an_employee_cannot_return_to_a_retired_value_of_their_own() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.update_commitment(&alice, &value(&env, 2));

    assert!(client
        .try_update_commitment(&alice, &value(&env, 1))
        .is_err());
    assert!(client
        .try_rotate_commitment(&alice, &value(&env, 1))
        .is_err());
    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 2));
}

#[test]
fn a_change_to_the_same_value_is_rejected_and_leaves_no_trace() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));

    assert!(client
        .try_update_commitment(&alice, &value(&env, 1))
        .is_err());

    assert_eq!(client.get_commitment(&alice).version, 1);
    assert_eq!(client.get_commitment_history(&alice).len(), 0);
}

#[test]
fn a_rejected_change_does_not_reserve_the_attempted_value() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.lock_commitment_updates(&alice);

    assert!(client
        .try_update_commitment(&alice, &value(&env, 9))
        .is_err());

    // The locked attempt never bound 9, so someone else can still use it.
    client.store_commitment(&bob, &value(&env, 9));
}

#[test]
fn changing_a_commitment_for_an_unknown_employee_creates_nothing() {
    let (env, _id, _admin, client) = setup();
    let ghost = Address::generate(&env);

    assert!(client
        .try_update_commitment(&ghost, &value(&env, 1))
        .is_err());
    assert!(client
        .try_rotate_commitment(&ghost, &value(&env, 1))
        .is_err());

    assert!(!client.has_commitment(&ghost));
}

#[test]
fn the_all_zero_value_cannot_be_the_target_of_any_change() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.lock_commitment_updates(&alice);
    let zero = BytesN::from_array(&env, &[0u8; 32]);

    assert!(client
        .try_rotate_approved_commitment(&alice, &zero)
        .is_err());
    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 1));
}

// ── Who may change a binding ────────────────────────────────────────────────────────────────────

#[test]
fn the_employee_cannot_change_their_own_commitment() {
    let (env, contract_id, _admin, client) = setup();
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));

    only_signer(
        &env,
        &contract_id,
        &alice,
        "update_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );

    assert!(client
        .try_update_commitment(&alice, &value(&env, 2))
        .is_err());
    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 1));
}

#[test]
fn a_payroll_operator_cannot_rotate_or_update_a_commitment() {
    let (env, contract_id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let operator = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.set_payroll_operator(&operator);

    only_signer(
        &env,
        &contract_id,
        &operator,
        "rotate_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );
    assert!(client
        .try_rotate_commitment(&alice, &value(&env, 2))
        .is_err());
    only_signer(
        &env,
        &contract_id,
        &operator,
        "update_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );
    assert!(client
        .try_update_commitment(&alice, &value(&env, 2))
        .is_err());

    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 1));
}

#[test]
fn a_stranger_cannot_lock_unlock_or_approve_a_rotation() {
    let (env, contract_id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.lock_commitment_updates(&alice);

    only_signer(
        &env,
        &contract_id,
        &stranger,
        "unlock_commitment_updates",
        (alice.clone(),).into_val(&env),
    );
    assert!(client.try_unlock_commitment_updates(&alice).is_err());
    only_signer(
        &env,
        &contract_id,
        &stranger,
        "rotate_approved_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );
    assert!(client
        .try_rotate_approved_commitment(&alice, &value(&env, 2))
        .is_err());

    assert!(client.is_commitment_locked(&alice));
    assert_eq!(client.get_commitment(&alice).commitment, value(&env, 1));
}

#[test]
fn a_lock_on_one_employee_does_not_stop_a_change_for_another() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.store_commitment(&bob, &value(&env, 2));
    client.lock_commitment_updates(&alice);

    client.update_commitment(&bob, &value(&env, 3));

    assert!(client.is_commitment_locked(&alice));
    assert_eq!(client.get_commitment(&bob).version, 2);
}

// ── Reference id remapping ──────────────────────────────────────────────────────────────────────

#[test]
fn a_reference_id_held_by_one_employee_cannot_be_claimed_by_another() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));

    assert!(client
        .try_set_employee_reference_id(&bob, &id(&env, "EMP1"))
        .is_err());

    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP1")),
        Some(alice)
    );
    assert_eq!(client.get_employee_reference_id(&bob), None);
}

#[test]
fn case_and_padding_do_not_make_a_second_claim_on_the_same_id() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));

    for variant in ["emp1", "Emp1", " EMP1", "EMP1 ", "  emp1  "] {
        assert!(
            client
                .try_set_employee_reference_id(&bob, &id(&env, variant))
                .is_err(),
            "{variant:?} must collide with EMP1"
        );
    }
    assert_eq!(client.get_employee_reference_id(&bob), None);
}

#[test]
fn changing_an_employees_reference_id_frees_the_old_one_and_only_the_old_one() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));
    client.set_employee_reference_id(&alice, &id(&env, "EMP2"));

    assert_eq!(client.get_employee_by_reference_id(&id(&env, "EMP1")), None);
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP2")),
        Some(alice.clone())
    );
    assert_eq!(
        client.get_employee_reference_id(&alice),
        Some(id(&env, "EMP2"))
    );

    // The freed id is available again, the held one is not.
    client.set_employee_reference_id(&bob, &id(&env, "EMP1"));
    assert!(client
        .try_set_employee_reference_id(&bob, &id(&env, "EMP2"))
        .is_err());
}

#[test]
fn a_failed_remap_keeps_the_employees_existing_reference_id() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));
    client.set_employee_reference_id(&bob, &id(&env, "EMP2"));

    assert!(client
        .try_set_employee_reference_id(&alice, &id(&env, "EMP2"))
        .is_err());

    assert_eq!(
        client.get_employee_reference_id(&alice),
        Some(id(&env, "EMP1"))
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP1")),
        Some(alice)
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP2")),
        Some(bob)
    );
}

#[test]
fn setting_the_same_reference_id_again_is_harmless() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));
    client.set_employee_reference_id(&alice, &id(&env, "emp1"));

    assert_eq!(
        client.get_employee_reference_id(&alice),
        Some(id(&env, "EMP1"))
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "EMP1")),
        Some(alice)
    );
}

#[test]
fn two_employees_can_swap_reference_ids_only_through_a_free_id() {
    let (env, _id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "A"));
    client.set_employee_reference_id(&bob, &id(&env, "B"));

    // A direct swap is impossible: each id is still held by the other.
    assert!(client
        .try_set_employee_reference_id(&alice, &id(&env, "B"))
        .is_err());
    assert!(client
        .try_set_employee_reference_id(&bob, &id(&env, "A"))
        .is_err());

    // Through a free id it works, and no id ends up with two owners.
    client.set_employee_reference_id(&alice, &id(&env, "TMP"));
    client.set_employee_reference_id(&bob, &id(&env, "A"));
    client.set_employee_reference_id(&alice, &id(&env, "B"));
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "A")),
        Some(bob)
    );
    assert_eq!(
        client.get_employee_by_reference_id(&id(&env, "B")),
        Some(alice)
    );
    assert_eq!(client.get_employee_by_reference_id(&id(&env, "TMP")), None);
}

#[test]
fn only_the_admin_can_remap_a_reference_id() {
    let (env, contract_id, _admin, client) = setup();
    let alice = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));

    only_signer(
        &env,
        &contract_id,
        &stranger,
        "set_employee_reference_id",
        (alice.clone(), id(&env, "EMP9")).into_val(&env),
    );

    assert!(client
        .try_set_employee_reference_id(&alice, &id(&env, "EMP9"))
        .is_err());
    assert_eq!(
        client.get_employee_reference_id(&alice),
        Some(id(&env, "EMP1"))
    );
}

// ── Admin handover ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_stranger_cannot_propose_an_admin_handover() {
    let (env, _id, _admin, client) = setup();
    let stranger = Address::generate(&env);

    assert!(client
        .try_propose_admin_rotation(&stranger, &stranger)
        .is_err());

    assert!(client.get_pending_admin_rotation().is_none());
    assert_ne!(client.get_commitment_admin(), stranger);
}

#[test]
fn only_the_proposed_address_can_accept_a_handover() {
    let (env, _id, admin, client) = setup();
    let next = Address::generate(&env);
    let intruder = Address::generate(&env);
    client.propose_admin_rotation(&admin, &next);

    assert!(client.try_accept_admin_rotation(&intruder).is_err());

    assert_eq!(client.get_commitment_admin(), admin);
    assert!(client.get_pending_admin_rotation().is_some());
}

#[test]
fn a_second_proposal_cannot_overwrite_a_pending_one() {
    let (env, _id, admin, client) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    client.propose_admin_rotation(&admin, &first);

    assert!(client.try_propose_admin_rotation(&admin, &second).is_err());

    assert_eq!(
        client.get_pending_admin_rotation().unwrap().new_holder,
        first
    );
}

#[test]
fn a_cancelled_handover_cannot_be_accepted() {
    let (env, _id, admin, client) = setup();
    let next = Address::generate(&env);
    client.propose_admin_rotation(&admin, &next);
    client.cancel_admin_rotation(&admin);

    assert!(client.try_accept_admin_rotation(&next).is_err());
    assert_eq!(client.get_commitment_admin(), admin);
}

#[test]
fn an_accepted_handover_cannot_be_accepted_twice_and_clears_the_proposal() {
    let (env, _id, admin, client) = setup();
    let next = Address::generate(&env);
    client.propose_admin_rotation(&admin, &next);
    client.accept_admin_rotation(&next);

    assert_eq!(client.get_commitment_admin(), next);
    assert!(client.get_pending_admin_rotation().is_none());
    assert!(client.try_accept_admin_rotation(&next).is_err());
}

#[test]
fn after_a_handover_the_old_admin_can_no_longer_change_bindings() {
    let (env, contract_id, admin, client) = setup();
    let next = Address::generate(&env);
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.propose_admin_rotation(&admin, &next);
    client.accept_admin_rotation(&next);

    only_signer(
        &env,
        &contract_id,
        &admin,
        "update_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );
    assert!(client
        .try_update_commitment(&alice, &value(&env, 2))
        .is_err());
    assert!(client.try_propose_admin_rotation(&admin, &admin).is_err());

    only_signer(
        &env,
        &contract_id,
        &next,
        "update_commitment",
        (alice.clone(), value(&env, 2)).into_val(&env),
    );
    assert_eq!(client.update_commitment(&alice, &value(&env, 2)).version, 2);
}

#[test]
fn a_handover_leaves_every_existing_binding_untouched() {
    let (env, _id, admin, client) = setup();
    let next = Address::generate(&env);
    let alice = Address::generate(&env);
    client.store_commitment(&alice, &value(&env, 1));
    client.update_commitment(&alice, &value(&env, 2));
    client.set_employee_reference_id(&alice, &id(&env, "EMP1"));
    client.lock_commitment_updates(&alice);

    client.propose_admin_rotation(&admin, &next);
    client.accept_admin_rotation(&next);

    let live = client.get_commitment(&alice);
    assert_eq!((live.commitment, live.version), (value(&env, 2), 2));
    assert_eq!(client.get_commitment_history(&alice).len(), 1);
    assert_eq!(
        client.get_employee_reference_id(&alice),
        Some(id(&env, "EMP1"))
    );
    assert!(client.is_commitment_locked(&alice));
}
