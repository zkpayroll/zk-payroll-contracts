//! Snapshot coverage for every event emitted by the Salary Commitment
//! contract (`contracts/events/src/lib.rs`, "Salary Commitment Events"
//! section).

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, dynamic, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn case_commitment_stored(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[20u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_stored(env, employee.clone(), commitment.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CommitmentUpdated"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.CommitmentUpdated topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (commitment,),
        "salary_commitment.CommitmentUpdated payload changed"
    );
    out.insert(
        "salary_commitment.CommitmentUpdated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentUpdated"), dynamic("Address")],
            data: vec![field("commitment", "BytesN<32>")],
        },
    );
}

fn case_commitment_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let old_commitment = BytesN::from_array(env, &[21u8; 32]);
    let new_commitment = BytesN::from_array(env, &[22u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_rotated(
            env,
            employee.clone(),
            old_commitment.clone(),
            new_commitment.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CommitmentRotated"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.CommitmentRotated topics changed"
    );
    let decoded: (BytesN<32>, BytesN<32>) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (old_commitment, new_commitment),
        "salary_commitment.CommitmentRotated payload changed"
    );
    out.insert(
        "salary_commitment.CommitmentRotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentRotated"), dynamic("Address")],
            data: vec![
                field("old_commitment", "BytesN<32>"),
                field("new_commitment", "BytesN<32>"),
            ],
        },
    );
}

fn case_commitment_locked(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_locked(env, employee.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CommitmentLocked"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.CommitmentLocked topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "salary_commitment.CommitmentLocked payload changed"
    );
    out.insert(
        "salary_commitment.CommitmentLocked".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentLocked"), dynamic("Address")],
            data: vec![],
        },
    );
}

fn case_commitment_unlocked(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_unlocked(env, employee.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "CommitmentUnlocked"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.CommitmentUnlocked topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "salary_commitment.CommitmentUnlocked payload changed"
    );
    out.insert(
        "salary_commitment.CommitmentUnlocked".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitmentUnlocked"), dynamic("Address")],
            data: vec![],
        },
    );
}

fn case_reference_id_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let reference_id = soroban_sdk::String::from_str(env, "EMP-0042");
    env.as_contract(cid, || {
        payroll_events::emit_reference_id_set(env, employee.clone(), reference_id.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "ReferenceIdSet"), employee.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.ReferenceIdSet topics changed"
    );
    let decoded: (soroban_sdk::String,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (reference_id,),
        "salary_commitment.ReferenceIdSet payload changed"
    );
    out.insert(
        "salary_commitment.ReferenceIdSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("ReferenceIdSet"), dynamic("Address")],
            data: vec![field("reference_id", "String")],
        },
    );
}

fn case_nullifier_recorded(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let nullifier = BytesN::from_array(env, &[23u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_nullifier_recorded(env, nullifier.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "NullifierRecorded"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.NullifierRecorded topics changed"
    );
    let decoded: (BytesN<32>,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (nullifier,),
        "salary_commitment.NullifierRecorded payload changed"
    );
    out.insert(
        "salary_commitment.NullifierRecorded".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("NullifierRecorded")],
            data: vec![field("nullifier", "BytesN<32>")],
        },
    );
}

fn case_payroll_operator_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let operator = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_payroll_operator_set(env, operator.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "PayrollOperatorSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.PayrollOperatorSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (operator,),
        "salary_commitment.PayrollOperatorSet payload changed"
    );
    out.insert(
        "salary_commitment.PayrollOperatorSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("PayrollOperatorSet")],
            data: vec![field("operator", "Address")],
        },
    );
}

fn case_commitment_admin_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current_admin = Address::generate(env);
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_admin_proposed(
            env,
            current_admin.clone(),
            new_admin.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "AdminRotationProposed"),
        current_admin.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.AdminRotationProposed topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (new_admin,),
        "salary_commitment.AdminRotationProposed payload changed"
    );
    out.insert(
        "salary_commitment.AdminRotationProposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AdminRotationProposed"), dynamic("Address")],
            data: vec![field("new_admin", "Address")],
        },
    );
}

fn case_commitment_admin_accepted(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_admin_accepted(env, new_admin.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> =
        (Symbol::new(env, "AdminRotationAccepted"), new_admin.clone()).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.AdminRotationAccepted topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "salary_commitment.AdminRotationAccepted payload changed"
    );
    out.insert(
        "salary_commitment.AdminRotationAccepted".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AdminRotationAccepted"), dynamic("Address")],
            data: vec![],
        },
    );
}

fn case_commitment_admin_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_admin_cancelled(env, current_admin.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (
        Symbol::new(env, "AdminRotationCancelled"),
        current_admin.clone(),
    )
        .into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.AdminRotationCancelled topics changed"
    );
    let decoded: () = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (),
        "salary_commitment.AdminRotationCancelled payload changed"
    );
    out.insert(
        "salary_commitment.AdminRotationCancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("AdminRotationCancelled"), dynamic("Address")],
            data: vec![],
        },
    );
}

fn case_commitment_pause_manager_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let pause_manager = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_commitment_pause_manager_set(env, pause_manager.clone());
    });
    let (_, topics, data) = last_event(env);
    let expected_topics: SVec<Val> = (Symbol::new(env, "CommitPauseMgrSet"),).into_val(env);
    assert_eq!(
        topics, expected_topics,
        "salary_commitment.CommitPauseMgrSet topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (pause_manager,),
        "salary_commitment.CommitPauseMgrSet payload changed"
    );
    out.insert(
        "salary_commitment.CommitPauseMgrSet".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("CommitPauseMgrSet")],
            data: vec![field("pause_manager", "Address")],
        },
    );
}

#[test]
fn salary_commitment_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_commitment_stored(&env, &cid, &mut observed);
    case_commitment_rotated(&env, &cid, &mut observed);
    case_commitment_locked(&env, &cid, &mut observed);
    case_commitment_unlocked(&env, &cid, &mut observed);
    case_reference_id_set(&env, &cid, &mut observed);
    case_nullifier_recorded(&env, &cid, &mut observed);
    case_payroll_operator_set(&env, &cid, &mut observed);
    case_commitment_admin_proposed(&env, &cid, &mut observed);
    case_commitment_admin_accepted(&env, &cid, &mut observed);
    case_commitment_admin_cancelled(&env, &cid, &mut observed);
    case_commitment_pause_manager_set(&env, &cid, &mut observed);

    assert_matches_fixture(
        "salary_commitment",
        include_str!("../fixtures/events/salary_commitment.json"),
        observed,
    );
}
