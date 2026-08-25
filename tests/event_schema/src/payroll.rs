//! Snapshot coverage for every event emitted by the Payroll contract
//! (`contracts/events/src/lib.rs`, "Payroll Contract Events" section).
//!
//! All events in this domain share the same topic prefix,
//! `(payroll_events::payroll_topic(), Symbol(<action>))`.

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, TryIntoVal, Val, Vec as SVec};

use crate::support::{
    assert_matches_fixture, field, last_event, new_env, sym, EventSchema, SchemaMap,
};

fn topic(env: &Env, action: &str) -> SVec<Val> {
    (payroll_events::payroll_topic(), Symbol::new(env, action)).into_val(env)
}

fn case_initialized(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let admin = Address::generate(env);
    let token = Address::generate(env);
    let verifier = Address::generate(env);
    let commitment = Address::generate(env);
    let treasury = Address::generate(env);
    let treasury_owner = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_payroll_initialized(
            env,
            admin.clone(),
            token.clone(),
            verifier.clone(),
            commitment.clone(),
            treasury.clone(),
            treasury_owner.clone(),
        );
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "initialized"),
        "payroll.initialized topics changed"
    );
    let decoded: (Address, Address, Address, Address, Address, Address) =
        data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (admin, token, verifier, commitment, treasury, treasury_owner),
        "payroll.initialized payload changed"
    );
    out.insert(
        "payroll.initialized".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("initialized")],
            data: vec![
                field("admin", "Address"),
                field("token", "Address"),
                field("verifier", "Address"),
                field("commitment", "Address"),
                field("treasury", "Address"),
                field("treasury_owner", "Address"),
            ],
        },
    );
}

fn case_pause_manager_set(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let pause_manager = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_pause_manager_set(env, pause_manager.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "pause_mgr_set"),
        "payroll.pause_mgr_set topics changed"
    );
    let decoded: (Address,) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (pause_manager,),
        "payroll.pause_mgr_set payload changed"
    );
    out.insert(
        "payroll.pause_mgr_set".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("pause_mgr_set")],
            data: vec![field("pause_manager", "Address")],
        },
    );
}

fn case_deposit(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let from = Address::generate(env);
    let amount: i128 = 5_000;
    let deposit_id = BytesN::from_array(env, &[1u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_deposit(env, from.clone(), amount, deposit_id.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "deposit"),
        "payroll.deposit topics changed"
    );
    let decoded: (Address, i128, BytesN<32>) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (from, amount, deposit_id),
        "payroll.deposit payload changed"
    );
    out.insert(
        "payroll.deposit".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("deposit")],
            data: vec![
                field("from", "Address"),
                field("amount", "i128"),
                field("deposit_id", "BytesN<32>"),
            ],
        },
    );
}

fn case_metadata_committed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let metadata_hash = BytesN::from_array(env, &[2u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_metadata_committed(env, metadata_hash.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "meta_committed"),
        "payroll.meta_committed topics changed"
    );
    let decoded: BytesN<32> = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded, metadata_hash,
        "payroll.meta_committed payload changed"
    );
    out.insert(
        "payroll.meta_committed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("meta_committed")],
            data: vec![field("metadata_hash", "BytesN<32>")],
        },
    );
}

fn case_metadata_bound(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 7;
    let metadata_hash = BytesN::from_array(env, &[3u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_metadata_bound(env, run_id, metadata_hash.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "meta_bound"),
        "payroll.meta_bound topics changed"
    );
    let decoded: (u64, BytesN<32>) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, metadata_hash),
        "payroll.meta_bound payload changed"
    );
    out.insert(
        "payroll.meta_bound".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("meta_bound")],
            data: vec![field("run_id", "u64"), field("metadata_hash", "BytesN<32>")],
        },
    );
}

fn case_draft_committed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_hash = BytesN::from_array(env, &[4u8; 32]);
    env.as_contract(cid, || {
        payroll_events::emit_draft_committed(env, draft_hash.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_committed"),
        "payroll.draft_committed topics changed"
    );
    let decoded: BytesN<32> = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded, draft_hash,
        "payroll.draft_committed payload changed"
    );
    out.insert(
        "payroll.draft_committed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_committed")],
            data: vec![field("draft_hash", "BytesN<32>")],
        },
    );
}

fn case_emergency_requested(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let amount: i128 = 1_234;
    let recipient = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_emergency_requested(env, amount, recipient.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "emrg_requested"),
        "payroll.emrg_requested topics changed"
    );
    let decoded: (i128, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (amount, recipient),
        "payroll.emrg_requested payload changed"
    );
    out.insert(
        "payroll.emrg_requested".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("emrg_requested")],
            data: vec![field("amount", "i128"), field("recipient", "Address")],
        },
    );
}

fn case_emergency_approved(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let amount: i128 = 4_321;
    let recipient = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_emergency_approved(env, amount, recipient.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "emrg_approved"),
        "payroll.emrg_approved topics changed"
    );
    let decoded: (i128, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (amount, recipient),
        "payroll.emrg_approved payload changed"
    );
    out.insert(
        "payroll.emrg_approved".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("emrg_approved")],
            data: vec![field("amount", "i128"), field("recipient", "Address")],
        },
    );
}

fn case_emergency_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let caller = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_emergency_cancelled(env, caller.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "emrg_cancelled"),
        "payroll.emrg_cancelled topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(decoded, caller, "payroll.emrg_cancelled payload changed");
    out.insert(
        "payroll.emrg_cancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("emrg_cancelled")],
            data: vec![field("caller", "Address")],
        },
    );
}

fn case_run_prepared(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 11;
    let total_spend: i128 = 9_000;
    env.as_contract(cid, || {
        payroll_events::emit_run_prepared(env, run_id, total_spend);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "run_prepared"),
        "payroll.run_prepared topics changed"
    );
    let decoded: (u64, i128) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, total_spend),
        "payroll.run_prepared payload changed"
    );
    out.insert(
        "payroll.run_prepared".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("run_prepared")],
            data: vec![field("run_id", "u64"), field("total_spend", "i128")],
        },
    );
}

fn case_run_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 12;
    let total_amount: i128 = 8_000;
    env.as_contract(cid, || {
        payroll_events::emit_run_cancelled(env, run_id, total_amount);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "run_cancelled"),
        "payroll.run_cancelled topics changed"
    );
    let decoded: (u64, i128) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, total_amount),
        "payroll.run_cancelled payload changed"
    );
    out.insert(
        "payroll.run_cancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("run_cancelled")],
            data: vec![field("run_id", "u64"), field("total_amount", "i128")],
        },
    );
}

fn case_payment_executed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let employee = Address::generate(env);
    let amount: i128 = 2_500;
    env.as_contract(cid, || {
        payroll_events::emit_payment_executed(env, employee.clone(), amount);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "payment_executed"),
        "payroll.payment_executed topics changed"
    );
    let decoded: (Address, i128) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (employee, amount),
        "payroll.payment_executed payload changed"
    );
    out.insert(
        "payroll.payment_executed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("payment_executed")],
            data: vec![field("employee", "Address"), field("amount", "i128")],
        },
    );
}

fn case_run_executed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 13;
    let total_spend: i128 = 7_500;
    env.as_contract(cid, || {
        payroll_events::emit_run_executed(env, run_id, total_spend);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "run_executed"),
        "payroll.run_executed topics changed"
    );
    let decoded: (u64, i128) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, total_spend),
        "payroll.run_executed payload changed"
    );
    out.insert(
        "payroll.run_executed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("run_executed")],
            data: vec![field("run_id", "u64"), field("total_spend", "i128")],
        },
    );
}

fn case_draft_created(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 21;
    let admin = Address::generate(env);
    let period_label = Symbol::new(env, "period_1");
    env.as_contract(cid, || {
        payroll_events::emit_draft_created(env, draft_id, admin.clone(), period_label.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_created"),
        "payroll.draft_created topics changed"
    );
    let decoded: (u64, Address, Symbol) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, admin, period_label),
        "payroll.draft_created payload changed"
    );
    out.insert(
        "payroll.draft_created".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_created")],
            data: vec![
                field("draft_id", "u64"),
                field("admin", "Address"),
                field("period_label", "Symbol"),
            ],
        },
    );
}

fn case_draft_amended(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 22;
    let new_total: i128 = 6_600;
    let amendment_count: u32 = 2;
    env.as_contract(cid, || {
        payroll_events::emit_draft_amended(env, draft_id, new_total, amendment_count);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_amended"),
        "payroll.draft_amended topics changed"
    );
    let decoded: (u64, i128, u32) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, new_total, amendment_count),
        "payroll.draft_amended payload changed"
    );
    out.insert(
        "payroll.draft_amended".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_amended")],
            data: vec![
                field("draft_id", "u64"),
                field("new_total", "i128"),
                field("amendment_count", "u32"),
            ],
        },
    );
}

fn case_draft_finalized(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 23;
    let total: i128 = 6_700;
    let amendment_count: u32 = 3;
    env.as_contract(cid, || {
        payroll_events::emit_draft_finalized(env, draft_id, total, amendment_count);
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_finalized"),
        "payroll.draft_finalized topics changed"
    );
    let decoded: (u64, i128, u32) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, total, amendment_count),
        "payroll.draft_finalized payload changed"
    );
    out.insert(
        "payroll.draft_finalized".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_finalized")],
            data: vec![
                field("draft_id", "u64"),
                field("total", "i128"),
                field("amendment_count", "u32"),
            ],
        },
    );
}

fn case_draft_submitted(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 24;
    let admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_draft_submitted(env, draft_id, admin.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_submitted"),
        "payroll.draft_submitted topics changed"
    );
    let decoded: (u64, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, admin),
        "payroll.draft_submitted payload changed"
    );
    out.insert(
        "payroll.draft_submitted".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_submitted")],
            data: vec![field("draft_id", "u64"), field("admin", "Address")],
        },
    );
}

fn case_draft_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 25;
    let admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_draft_cancelled(env, draft_id, admin.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_cancelled"),
        "payroll.draft_cancelled topics changed"
    );
    let decoded: (u64, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, admin),
        "payroll.draft_cancelled payload changed"
    );
    out.insert(
        "payroll.draft_cancelled".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_cancelled")],
            data: vec![field("draft_id", "u64"), field("admin", "Address")],
        },
    );
}

fn case_draft_expired(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let draft_id: u64 = 26;
    let admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_draft_expired(env, draft_id, admin.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "draft_expired"),
        "payroll.draft_expired topics changed"
    );
    let decoded: (u64, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (draft_id, admin),
        "payroll.draft_expired payload changed"
    );
    out.insert(
        "payroll.draft_expired".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("draft_expired")],
            data: vec![field("draft_id", "u64"), field("admin", "Address")],
        },
    );
}

fn case_reconciliation_updated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 27;
    let status = Symbol::new(env, "reconciled");
    env.as_contract(cid, || {
        payroll_events::emit_reconciliation_updated(env, run_id, status.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "reconciliation_updated"),
        "payroll.reconciliation_updated topics changed"
    );
    let decoded: (u64, Symbol) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, status),
        "payroll.reconciliation_updated payload changed"
    );
    out.insert(
        "payroll.reconciliation_updated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("reconciliation_updated")],
            data: vec![field("run_id", "u64"), field("status", "Symbol")],
        },
    );
}

fn case_admin_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current_admin = Address::generate(env);
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_admin_proposed(env, current_admin.clone(), new_admin.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "admin_proposed"),
        "payroll.admin_proposed topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (current_admin, new_admin),
        "payroll.admin_proposed payload changed"
    );
    out.insert(
        "payroll.admin_proposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("admin_proposed")],
            data: vec![
                field("current_admin", "Address"),
                field("new_admin", "Address"),
            ],
        },
    );
}

fn case_admin_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let old_admin = Address::generate(env);
    let new_admin = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_admin_rotated(env, old_admin.clone(), new_admin.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "admin_rotated"),
        "payroll.admin_rotated topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (old_admin, new_admin),
        "payroll.admin_rotated payload changed"
    );
    out.insert(
        "payroll.admin_rotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("admin_rotated")],
            data: vec![field("old_admin", "Address"), field("new_admin", "Address")],
        },
    );
}

fn case_admin_rotation_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let caller = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_admin_rotation_cancelled(env, caller.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "admin_rot_cancel"),
        "payroll.admin_rot_cancel topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(decoded, caller, "payroll.admin_rot_cancel payload changed");
    out.insert(
        "payroll.admin_rot_cancel".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("admin_rot_cancel")],
            data: vec![field("caller", "Address")],
        },
    );
}

fn case_treasury_proposed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let current_owner = Address::generate(env);
    let new_owner = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_treasury_proposed(env, current_owner.clone(), new_owner.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "treasury_proposed"),
        "payroll.treasury_proposed topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (current_owner, new_owner),
        "payroll.treasury_proposed payload changed"
    );
    out.insert(
        "payroll.treasury_proposed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("treasury_proposed")],
            data: vec![
                field("current_owner", "Address"),
                field("new_owner", "Address"),
            ],
        },
    );
}

fn case_treasury_rotated(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let old_owner = Address::generate(env);
    let new_owner = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_treasury_rotated(env, old_owner.clone(), new_owner.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "treasury_rotated"),
        "payroll.treasury_rotated topics changed"
    );
    let decoded: (Address, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (old_owner, new_owner),
        "payroll.treasury_rotated payload changed"
    );
    out.insert(
        "payroll.treasury_rotated".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("treasury_rotated")],
            data: vec![field("old_owner", "Address"), field("new_owner", "Address")],
        },
    );
}

fn case_treasury_rotation_cancelled(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let caller = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_treasury_rotation_cancelled(env, caller.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "treas_rot_cancel"),
        "payroll.treas_rot_cancel topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(decoded, caller, "payroll.treas_rot_cancel payload changed");
    out.insert(
        "payroll.treas_rot_cancel".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("treas_rot_cancel")],
            data: vec![field("caller", "Address")],
        },
    );
}

fn case_reviewer_added(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let reviewer = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_reviewer_added(env, reviewer.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "reviewer_added"),
        "payroll.reviewer_added topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(decoded, reviewer, "payroll.reviewer_added payload changed");
    out.insert(
        "payroll.reviewer_added".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("reviewer_added")],
            data: vec![field("reviewer", "Address")],
        },
    );
}

fn case_reviewer_removed(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let reviewer = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_reviewer_removed(env, reviewer.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "reviewer_removed"),
        "payroll.reviewer_removed topics changed"
    );
    let decoded: Address = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded, reviewer,
        "payroll.reviewer_removed payload changed"
    );
    out.insert(
        "payroll.reviewer_removed".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("reviewer_removed")],
            data: vec![field("reviewer", "Address")],
        },
    );
}

fn case_run_approved(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 31;
    let reviewer = Address::generate(env);
    env.as_contract(cid, || {
        payroll_events::emit_run_approved(env, run_id, reviewer.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "run_approved"),
        "payroll.run_approved topics changed"
    );
    let decoded: (u64, Address) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, reviewer),
        "payroll.run_approved payload changed"
    );
    out.insert(
        "payroll.run_approved".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("run_approved")],
            data: vec![field("run_id", "u64"), field("reviewer", "Address")],
        },
    );
}

fn case_run_rejected(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 32;
    let reviewer = Address::generate(env);
    let reason = Symbol::new(env, "policy");
    env.as_contract(cid, || {
        payroll_events::emit_run_rejected(env, run_id, reviewer.clone(), reason.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "run_rejected"),
        "payroll.run_rejected topics changed"
    );
    let decoded: (u64, Address, Symbol) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, reviewer, reason),
        "payroll.run_rejected payload changed"
    );
    out.insert(
        "payroll.run_rejected".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("run_rejected")],
            data: vec![
                field("run_id", "u64"),
                field("reviewer", "Address"),
                field("reason", "Symbol"),
            ],
        },
    );
}

fn case_run_changes_requested(env: &Env, cid: &Address, out: &mut SchemaMap) {
    let run_id: u64 = 33;
    let reviewer = Address::generate(env);
    let reason = Symbol::new(env, "missing_docs");
    env.as_contract(cid, || {
        payroll_events::emit_run_changes_requested(env, run_id, reviewer.clone(), reason.clone());
    });
    let (_, topics, data) = last_event(env);
    assert_eq!(
        topics,
        topic(env, "changes_requested"),
        "payroll.changes_requested topics changed"
    );
    let decoded: (u64, Address, Symbol) = data.try_into_val(env).unwrap();
    assert_eq!(
        decoded,
        (run_id, reviewer, reason),
        "payroll.changes_requested payload changed"
    );
    out.insert(
        "payroll.changes_requested".to_string(),
        EventSchema {
            schema_version: 1,
            topics: vec![sym("payroll"), sym("changes_requested")],
            data: vec![
                field("run_id", "u64"),
                field("reviewer", "Address"),
                field("reason", "Symbol"),
            ],
        },
    );
}

#[test]
fn payroll_events_match_fixture() {
    let (env, cid) = new_env();
    let mut observed = SchemaMap::new();

    case_initialized(&env, &cid, &mut observed);
    case_pause_manager_set(&env, &cid, &mut observed);
    case_deposit(&env, &cid, &mut observed);
    case_metadata_committed(&env, &cid, &mut observed);
    case_metadata_bound(&env, &cid, &mut observed);
    case_draft_committed(&env, &cid, &mut observed);
    case_emergency_requested(&env, &cid, &mut observed);
    case_emergency_approved(&env, &cid, &mut observed);
    case_emergency_cancelled(&env, &cid, &mut observed);
    case_run_prepared(&env, &cid, &mut observed);
    case_run_cancelled(&env, &cid, &mut observed);
    case_payment_executed(&env, &cid, &mut observed);
    case_run_executed(&env, &cid, &mut observed);
    case_draft_created(&env, &cid, &mut observed);
    case_draft_amended(&env, &cid, &mut observed);
    case_draft_finalized(&env, &cid, &mut observed);
    case_draft_submitted(&env, &cid, &mut observed);
    case_draft_cancelled(&env, &cid, &mut observed);
    case_draft_expired(&env, &cid, &mut observed);
    case_reconciliation_updated(&env, &cid, &mut observed);
    case_admin_proposed(&env, &cid, &mut observed);
    case_admin_rotated(&env, &cid, &mut observed);
    case_admin_rotation_cancelled(&env, &cid, &mut observed);
    case_treasury_proposed(&env, &cid, &mut observed);
    case_treasury_rotated(&env, &cid, &mut observed);
    case_treasury_rotation_cancelled(&env, &cid, &mut observed);
    case_reviewer_added(&env, &cid, &mut observed);
    case_reviewer_removed(&env, &cid, &mut observed);
    case_run_approved(&env, &cid, &mut observed);
    case_run_rejected(&env, &cid, &mut observed);
    case_run_changes_requested(&env, &cid, &mut observed);

    assert_matches_fixture(
        "payroll",
        include_str!("../fixtures/events/payroll.json"),
        observed,
    );
}
