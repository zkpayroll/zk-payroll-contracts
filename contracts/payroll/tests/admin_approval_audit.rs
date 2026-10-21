//! Contract administrator approval audit history (#791).
//!
//! `finalize_payroll_run` and `approve_emergency_withdrawal` are approvals the
//! contract admin takes alone. These tests pin that each one is recorded on
//! chain with the approver, kind, target and ledger time, in order; that a
//! rejected approval writes nothing; and that the history can only be read in
//! bounded pages, with typed errors for an empty or oversized page.

#![cfg(test)]

mod common;

use payroll::{AdminApprovalAuditError, AdminApprovalKind, PayrollClient, MAX_ADMIN_APPROVAL_PAGE};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{xdr, Address, BytesN, Env, TryFromVal, Val, Vec};

/// Prepares a run (marker `n` keeps nonces distinct) and returns its id.
fn prepare_run(env: &Env, client: &PayrollClient, marker: u8) -> u64 {
    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]);
    let amounts = Vec::from_array(env, [100_i128]);
    let employees = Vec::from_array(env, [Address::generate(env)]);
    client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(env, marker),
        &None,
    )
}

#[test]
fn history_is_empty_before_any_admin_approval() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    assert_eq!(client.get_admin_approval_count(), 0);
    assert_eq!(client.get_admin_approval(&1), None);
    assert_eq!(client.get_admin_approval_history(&0, &10).len(), 0);
}

#[test]
fn finalizing_a_run_records_the_admin_approval() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;
    env.ledger().with_mut(|li| {
        li.timestamp = 1_700_000_000;
        li.sequence_number = 4_242;
    });

    let run_id = prepare_run(&env, &client, 1);
    client.finalize_payroll_run(&admin, &run_id);
    // Read before any other call, which resets the event log.
    let events = env.events().all().filter_by_contract(&client.address);

    assert_eq!(client.get_admin_approval_count(), 1);
    let record = client.get_admin_approval(&1).unwrap();
    assert_eq!(record.sequence, 1);
    assert_eq!(record.approver, admin);
    assert_eq!(record.kind, AdminApprovalKind::PayrollRunFinalized);
    assert_eq!(record.target_id, run_id);
    assert_eq!(record.approved_at, 1_700_000_000);
    assert_eq!(record.ledger_sequence, 4_242);

    // The approval is announced on chain with the same fields.
    let marker = xdr::ScVal::Symbol(xdr::ScSymbol("admin_approval_recorded".try_into().unwrap()));
    let recorded: std::vec::Vec<&xdr::ContractEvent> = events
        .events()
        .iter()
        .filter(|ev| {
            let xdr::ContractEventBody::V0(body) = &ev.body;
            body.topics.get(1) == Some(&marker)
        })
        .collect();
    assert_eq!(recorded.len(), 1);
    let xdr::ContractEventBody::V0(body) = &recorded[0].body;
    let data = Val::try_from_val(&env, &body.data).unwrap();
    let data = <(u64, Address, u32, u64, u64)>::try_from_val(&env, &data).unwrap();
    assert_eq!(
        data,
        (
            1,
            admin,
            AdminApprovalKind::PayrollRunFinalized as u32,
            run_id,
            1_700_000_000
        )
    );
}

#[test]
fn approvals_of_different_kinds_are_kept_in_order() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;
    let owner = client.get_treasury_owner();

    let first_run = prepare_run(&env, &client, 1);
    client.finalize_payroll_run(&admin, &first_run);

    env.ledger().with_mut(|li| li.timestamp += 60);
    client.request_emergency_withdrawal(&owner, &500, &Address::generate(&env));
    client.approve_emergency_withdrawal(&admin);

    env.ledger().with_mut(|li| li.timestamp += 60);
    let second_run = prepare_run(&env, &client, 2);
    client.finalize_payroll_run(&admin, &second_run);

    let history = client.get_admin_approval_history(&0, &MAX_ADMIN_APPROVAL_PAGE);
    assert_eq!(history.len(), 3);

    let kinds: [(u64, AdminApprovalKind, u64); 3] = [
        (1, AdminApprovalKind::PayrollRunFinalized, first_run),
        (2, AdminApprovalKind::EmergencyWithdrawal, 0),
        (3, AdminApprovalKind::PayrollRunFinalized, second_run),
    ];
    for (i, (sequence, kind, target_id)) in kinds.iter().enumerate() {
        let record = history.get(i as u32).unwrap();
        assert_eq!(record.sequence, *sequence);
        assert_eq!(record.kind, *kind);
        assert_eq!(record.target_id, *target_id);
        assert_eq!(record.approver, admin);
    }
    assert!(history.get(0).unwrap().approved_at < history.get(1).unwrap().approved_at);
    assert!(history.get(1).unwrap().approved_at < history.get(2).unwrap().approved_at);
}

#[test]
fn a_rejected_approval_writes_nothing() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let run_id = prepare_run(&env, &client, 1);
    let intruder = Address::generate(&env);

    // Not the contract admin: both approvals are rejected.
    assert!(client.try_finalize_payroll_run(&intruder, &run_id).is_err());
    let owner = client.get_treasury_owner();
    client.request_emergency_withdrawal(&owner, &500, &Address::generate(&env));
    assert!(client.try_approve_emergency_withdrawal(&intruder).is_err());

    // The admin, but with nothing pending to approve.
    let admin = client.get_addresses().admin;
    client.cancel_emergency_withdrawal(&admin);
    assert!(client.try_approve_emergency_withdrawal(&admin).is_err());

    assert_eq!(client.get_admin_approval_count(), 0);
    assert_eq!(client.get_admin_approval_history(&0, &10).len(), 0);
}

#[test]
fn an_empty_or_oversized_page_is_rejected_with_a_typed_error() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    assert_eq!(
        client.try_get_admin_approval_history(&0, &0),
        Err(Ok(AdminApprovalAuditError::PageLimitZero))
    );
    assert_eq!(
        client.try_get_admin_approval_history(&0, &(MAX_ADMIN_APPROVAL_PAGE + 1)),
        Err(Ok(AdminApprovalAuditError::PageLimitTooLarge))
    );
    // The largest allowed page is accepted.
    assert!(client
        .try_get_admin_approval_history(&0, &MAX_ADMIN_APPROVAL_PAGE)
        .is_ok());
}

#[test]
fn pages_walk_the_history_without_gaps_or_overlap() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let admin = client.get_addresses().admin;
    for marker in 1..=5u8 {
        let run_id = prepare_run(&env, &client, marker);
        client.finalize_payroll_run(&admin, &run_id);
    }
    assert_eq!(client.get_admin_approval_count(), 5);

    let first = client.get_admin_approval_history(&0, &2);
    let second = client.get_admin_approval_history(&2, &2);
    let last = client.get_admin_approval_history(&4, &2);
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 2);
    // A page that runs past the end is cut short, not padded or rejected.
    assert_eq!(last.len(), 1);
    assert_eq!(first.get(0).unwrap().sequence, 1);
    assert_eq!(first.get(1).unwrap().sequence, 2);
    assert_eq!(second.get(0).unwrap().sequence, 3);
    assert_eq!(second.get(1).unwrap().sequence, 4);
    assert_eq!(last.get(0).unwrap().sequence, 5);

    // Starting at or past the end yields an empty page.
    assert_eq!(client.get_admin_approval_history(&5, &2).len(), 0);
    assert_eq!(client.get_admin_approval_history(&u64::MAX, &2).len(), 0);
    assert_eq!(client.get_admin_approval(&6), None);
}
