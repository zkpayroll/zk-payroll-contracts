//! Payroll responsibility delegation audit (#714).
//!
//! `transfer_pending_run_admin` hands a pending run's responsibility to another
//! admin. These tests pin that every handover is recorded on chain, that the
//! trail outlives the pending run, that it can be paged and verified, and that
//! a rejected handover writes nothing.

#![cfg(test)]

mod common;

use payroll::{
    check_can_record, clamp_page_size, verify_records, DelegationAuditIssue, DelegationAuditKey,
    DelegationIssue, DelegationRecord, PayrollClient, MAX_DELEGATIONS_PER_RUN,
    MAX_DELEGATION_AUDIT_PAGE,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};

/// Prepares a run (marker `n` keeps nonces distinct) and returns its id and
/// its admin, the contract admin it starts with.
fn prepare_run(env: &Env, client: &PayrollClient, marker: u8) -> (u64, Address) {
    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]);
    let amounts = Vec::from_array(env, [100_i128]);
    let employees = Vec::from_array(env, [Address::generate(env)]);
    let run_id = client.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &100,
        &common::nonce(env, marker),
        &None,
    );
    let admin = client.get_pending_run(&run_id).unwrap().admin;
    (run_id, admin)
}

/// Hands the run along `path`, starting from the run's current admin.
fn hand_over(client: &PayrollClient, run_id: u64, from: &Address, path: &[Address]) {
    let mut holder = from.clone();
    for next in path {
        client.transfer_pending_run_admin(&holder, &run_id, next);
        holder = next.clone();
    }
}

fn contract_event_count(env: &Env, client: &PayrollClient) -> u32 {
    env.events()
        .all()
        .filter_by_contract(&client.address)
        .events()
        .len() as u32
}

#[test]
fn a_run_that_was_never_handed_over_has_an_empty_consistent_trail() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    assert_eq!(client.get_run_delegation_count(&run_id), 0);
    assert!(client.get_run_delegation(&run_id, &1).is_none());
    assert_eq!(client.get_run_delegation_audit(&run_id, &0, &10).len(), 0);

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert_eq!(verdict.entries, 0);
    assert!(verdict.consistent);
    assert_eq!(verdict.issue, DelegationAuditIssue::NoIssue);
    assert_eq!(verdict.issue_at, 0);
    assert!(verdict.run_pending);
    assert_eq!(verdict.current_holder, Some(admin));
}

#[test]
fn a_handover_is_recorded_with_who_to_whom_and_when() {
    let env = Env::default();
    env.ledger().with_mut(|li| {
        li.timestamp = 1_800_000_000;
        li.sequence_number = 4_242;
    });
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let new_admin = Address::generate(&env);

    client.transfer_pending_run_admin(&admin, &run_id, &new_admin);

    assert_eq!(client.get_run_delegation_count(&run_id), 1);
    let record = client.get_run_delegation(&run_id, &1).unwrap();
    assert_eq!(
        record,
        DelegationRecord {
            run_id,
            sequence: 1,
            delegator: admin,
            delegate: new_admin.clone(),
            delegated_at: 1_800_000_000,
            ledger_sequence: 4_242,
        }
    );
    // The pending run itself still shows only the current admin.
    assert_eq!(client.get_pending_run(&run_id).unwrap().admin, new_admin);
}

#[test]
fn a_chain_of_handovers_is_recorded_in_order_and_verifies() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let b = Address::generate(&env);
    let c = Address::generate(&env);
    let d = Address::generate(&env);

    hand_over(&client, run_id, &admin, &[b.clone(), c.clone(), d.clone()]);

    let trail = client.get_run_delegation_audit(&run_id, &0, &10);
    assert_eq!(trail.len(), 3);
    let steps: std::vec::Vec<(u32, Address, Address)> = trail
        .iter()
        .map(|r| (r.sequence, r.delegator, r.delegate))
        .collect();
    assert_eq!(
        steps,
        std::vec![
            (1, admin.clone(), b.clone()),
            (2, b, c.clone()),
            (3, c, d.clone()),
        ]
    );

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(verdict.consistent);
    assert_eq!(verdict.entries, 3);
    assert_eq!(verdict.current_holder, Some(d));
    // The first delegator is the admin the run was prepared under.
    assert_eq!(trail.get(0).unwrap().delegator, admin);
}

#[test]
fn handing_the_run_back_is_a_new_record_not_a_rewrite() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let other = Address::generate(&env);

    hand_over(&client, run_id, &admin, &[other.clone(), admin.clone()]);

    assert_eq!(client.get_run_delegation_count(&run_id), 2);
    assert_eq!(
        client.get_run_delegation(&run_id, &2).unwrap().delegate,
        admin
    );
    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(verdict.consistent);
    assert_eq!(verdict.current_holder, Some(admin));
}

#[test]
fn the_trail_survives_the_run_being_cancelled() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let b = Address::generate(&env);
    let c = Address::generate(&env);
    hand_over(&client, run_id, &admin, &[b, c.clone()]);

    client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "replan"));

    assert!(client.get_pending_run(&run_id).is_none());
    assert_eq!(client.get_run_delegation_count(&run_id), 2);
    assert_eq!(client.get_run_delegation_audit(&run_id, &0, &10).len(), 2);

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(verdict.consistent);
    assert!(!verdict.run_pending);
    // With the run gone, the last delegate is the last known holder.
    assert_eq!(verdict.current_holder, Some(c));
}

#[test]
fn a_cancelled_run_that_was_never_handed_over_has_no_holder() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "replan"));

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(verdict.consistent);
    assert!(!verdict.run_pending);
    assert_eq!(verdict.entries, 0);
    assert_eq!(verdict.current_holder, None);
}

#[test]
fn a_rejected_handover_writes_nothing() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);

    // Not the run's admin.
    assert!(client
        .try_transfer_pending_run_admin(&stranger, &run_id, &target)
        .is_err());
    // Handing the run to oneself.
    assert!(client
        .try_transfer_pending_run_admin(&admin, &run_id, &admin)
        .is_err());
    // A run that does not exist.
    assert!(client
        .try_transfer_pending_run_admin(&admin, &run_id.wrapping_add(7_777), &target)
        .is_err());

    assert_eq!(client.get_run_delegation_count(&run_id), 0);
    assert_eq!(client.get_run_delegation_audit(&run_id, &0, &10).len(), 0);
    assert_eq!(
        client.get_run_delegation_count(&run_id.wrapping_add(7_777)),
        0
    );
    assert_eq!(client.get_pending_run(&run_id).unwrap().admin, admin);
}

#[test]
fn each_run_has_its_own_trail() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (first, admin) = prepare_run(&env, &client, 1);
    let (second, _) = prepare_run(&env, &client, 2);
    let to_first = Address::generate(&env);
    let to_second = Address::generate(&env);

    client.transfer_pending_run_admin(&admin, &first, &to_first);
    client.transfer_pending_run_admin(&admin, &second, &to_second);

    assert_eq!(client.get_run_delegation_count(&first), 1);
    assert_eq!(client.get_run_delegation_count(&second), 1);
    assert_eq!(
        client.get_run_delegation(&first, &1).unwrap().delegate,
        to_first
    );
    assert_eq!(
        client.get_run_delegation(&second, &1).unwrap().delegate,
        to_second
    );
    assert!(client.verify_run_delegation_audit(&first).consistent);
    assert!(client.verify_run_delegation_audit(&second).consistent);
}

#[test]
fn the_trail_is_paged_by_the_last_sequence_seen() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let path: std::vec::Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();
    hand_over(&client, run_id, &admin, &path);

    let seqs = |after: u32, limit: u32| -> std::vec::Vec<u32> {
        client
            .get_run_delegation_audit(&run_id, &after, &limit)
            .iter()
            .map(|r| r.sequence)
            .collect()
    };

    assert_eq!(seqs(0, 2), std::vec![1, 2]);
    assert_eq!(seqs(2, 2), std::vec![3, 4]);
    assert_eq!(seqs(4, 2), std::vec![5]);
    assert_eq!(seqs(5, 2), std::vec::Vec::<u32>::new());
    assert_eq!(seqs(0, 0), std::vec::Vec::<u32>::new());
    assert_eq!(seqs(0, u32::MAX), std::vec![1, 2, 3, 4, 5]);
    // A cursor far past the end is just an empty page.
    assert_eq!(seqs(u32::MAX, 10), std::vec::Vec::<u32>::new());
    assert!(client.get_run_delegation(&run_id, &6).is_none());
    assert!(client.get_run_delegation(&run_id, &0).is_none());
}

#[test]
fn a_page_never_exceeds_the_page_ceiling() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    // Bounce the run between two admins so the trail outgrows one page.
    bounce(&client, run_id, &admin, MAX_DELEGATION_AUDIT_PAGE + 5);

    let page = client.get_run_delegation_audit(&run_id, &0, &u32::MAX);
    assert_eq!(page.len(), MAX_DELEGATION_AUDIT_PAGE);
    assert_eq!(page.last().unwrap().sequence, MAX_DELEGATION_AUDIT_PAGE);
    let rest = client.get_run_delegation_audit(&run_id, &MAX_DELEGATION_AUDIT_PAGE, &u32::MAX);
    assert_eq!(rest.len(), 5);
    assert!(client.verify_run_delegation_audit(&run_id).consistent);
}

/// Bounces a run between two admins `times` times.
fn bounce(client: &PayrollClient, run_id: u64, admin: &Address, times: u32) {
    let other = Address::generate(&client.env);
    let mut holder = admin.clone();
    for i in 0..times {
        let next = if i % 2 == 0 {
            other.clone()
        } else {
            admin.clone()
        };
        client.transfer_pending_run_admin(&holder, &run_id, &next);
        holder = next;
    }
}

#[test]
fn a_run_can_be_handed_over_up_to_the_ceiling() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    bounce(&client, run_id, &admin, MAX_DELEGATIONS_PER_RUN);

    assert_eq!(
        client.get_run_delegation_count(&run_id),
        MAX_DELEGATIONS_PER_RUN
    );
    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(verdict.consistent);
    assert_eq!(verdict.entries, MAX_DELEGATIONS_PER_RUN);
}

#[test]
#[should_panic(
    expected = "Delegation limit reached: this run has already been handed over 100 times"
)]
fn one_handover_past_the_ceiling_is_rejected_with_a_reason() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    bounce(&client, run_id, &admin, MAX_DELEGATIONS_PER_RUN + 1);
}

#[test]
fn a_handover_past_the_ceiling_changes_nothing() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    bounce(&client, run_id, &admin, MAX_DELEGATIONS_PER_RUN);
    let holder = client.get_pending_run(&run_id).unwrap().admin;

    let result = client.try_transfer_pending_run_admin(&holder, &run_id, &Address::generate(&env));

    assert!(result.is_err());
    assert_eq!(
        client.get_run_delegation_count(&run_id),
        MAX_DELEGATIONS_PER_RUN
    );
    assert_eq!(client.get_pending_run(&run_id).unwrap().admin, holder);
}

#[test]
fn a_handover_publishes_the_existing_event_plus_the_audit_record() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);

    client.transfer_pending_run_admin(&admin, &run_id, &Address::generate(&env));

    // `run_admin_transferred` (unchanged) and `delegation_recorded`.
    assert_eq!(contract_event_count(&env, &client), 2);
}

// ---------------------------------------------------------------------------
// Verification catches a trail that no longer adds up.
// ---------------------------------------------------------------------------

fn overwrite(env: &Env, client: &PayrollClient, key: DelegationAuditKey, value: &DelegationRecord) {
    env.as_contract(&client.address, || {
        env.storage().persistent().set(&key, value);
    });
}

fn remove(env: &Env, client: &PayrollClient, key: DelegationAuditKey) {
    env.as_contract(&client.address, || {
        env.storage().persistent().remove(&key);
    });
}

fn three_step_trail(env: &Env) -> (PayrollClient<'_>, u64, Address, std::vec::Vec<Address>) {
    let (client, _token, _employee) = common::setup(env);
    let (run_id, admin) = prepare_run(env, &client, 1);
    let path: std::vec::Vec<Address> = (0..3).map(|_| Address::generate(env)).collect();
    hand_over(&client, run_id, &admin, &path);
    (client, run_id, admin, path)
}

#[test]
fn a_record_that_does_not_continue_the_chain_is_reported() {
    let env = Env::default();
    let (client, run_id, _admin, _path) = three_step_trail(&env);
    let mut record = client.get_run_delegation(&run_id, &2).unwrap();
    record.delegator = Address::generate(&env);
    overwrite(&env, &client, DelegationAuditKey::Entry(run_id, 2), &record);

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(!verdict.consistent);
    assert_eq!(verdict.issue, DelegationAuditIssue::BrokenChain);
    assert_eq!(verdict.issue_at, 2);
}

#[test]
fn a_missing_record_is_reported_as_a_sequence_gap() {
    let env = Env::default();
    let (client, run_id, _admin, _path) = three_step_trail(&env);
    remove(&env, &client, DelegationAuditKey::Entry(run_id, 2));

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(!verdict.consistent);
    assert_eq!(verdict.issue, DelegationAuditIssue::SequenceGap);
    assert_eq!(verdict.issue_at, 2);
    // `entries` is the stored count (3), not the number of records still readable (2).
    assert_eq!(verdict.entries, 3);
}

#[test]
fn a_trail_that_ends_elsewhere_than_the_pending_admin_is_reported() {
    let env = Env::default();
    let (client, run_id, _admin, _path) = three_step_trail(&env);
    let mut record = client.get_run_delegation(&run_id, &3).unwrap();
    record.delegate = Address::generate(&env);
    overwrite(&env, &client, DelegationAuditKey::Entry(run_id, 3), &record);

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(!verdict.consistent);
    assert_eq!(verdict.issue, DelegationAuditIssue::CurrentHolderMismatch);
    assert_eq!(verdict.issue_at, 3);
}

#[test]
fn a_self_handover_record_is_reported() {
    let env = Env::default();
    let (client, run_id, _admin, _path) = three_step_trail(&env);
    let mut record = client.get_run_delegation(&run_id, &1).unwrap();
    record.delegate = record.delegator.clone();
    overwrite(&env, &client, DelegationAuditKey::Entry(run_id, 1), &record);

    let verdict = client.verify_run_delegation_audit(&run_id);
    assert!(!verdict.consistent);
    assert_eq!(verdict.issue, DelegationAuditIssue::SelfDelegation);
    assert_eq!(verdict.issue_at, 1);
}

// ---------------------------------------------------------------------------
// Existing behaviour is untouched.
// ---------------------------------------------------------------------------

#[test]
fn the_pending_run_keeps_working_after_handovers() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let (run_id, admin) = prepare_run(&env, &client, 1);
    let new_admin = Address::generate(&env);
    client.transfer_pending_run_admin(&admin, &run_id, &new_admin);

    let pending = client.get_pending_run(&run_id).unwrap();
    assert_eq!(pending.admin, new_admin);
    assert_eq!(pending.total_amount, 100);
    assert_eq!(pending.employee_count, 1);
}

// ---------------------------------------------------------------------------
// The pure checks behind the audit.
// ---------------------------------------------------------------------------

fn record(sequence: u32, from: &Address, to: &Address) -> DelegationRecord {
    DelegationRecord {
        run_id: 1,
        sequence,
        delegator: from.clone(),
        delegate: to.clone(),
        delegated_at: 0,
        ledger_sequence: 0,
    }
}

fn chain(e: &Env, addrs: &[Address]) -> Vec<DelegationRecord> {
    let mut out = Vec::new(e);
    for (i, pair) in addrs.windows(2).enumerate() {
        out.push_back(record(i as u32 + 1, &pair[0], &pair[1]));
    }
    out
}

#[test]
fn an_empty_trail_is_consistent() {
    let e = Env::default();
    let records: Vec<DelegationRecord> = Vec::new(&e);
    assert_eq!(
        verify_records(&records, None),
        (DelegationAuditIssue::NoIssue, 0)
    );
    let admin = Address::generate(&e);
    assert_eq!(
        verify_records(&records, Some(&admin)),
        (DelegationAuditIssue::NoIssue, 0)
    );
}

#[test]
fn a_continuous_trail_ending_at_the_current_admin_is_consistent() {
    let e = Env::default();
    let a = Address::generate(&e);
    let b = Address::generate(&e);
    let c = Address::generate(&e);
    let records = chain(&e, &[a.clone(), b.clone(), c.clone()]);

    assert_eq!(
        verify_records(&records, Some(&c)),
        (DelegationAuditIssue::NoIssue, 0)
    );
    // A run that no longer exists has no current admin to compare against.
    assert_eq!(
        verify_records(&records, None),
        (DelegationAuditIssue::NoIssue, 0)
    );
}

#[test]
fn a_trail_ending_somewhere_else_than_the_current_admin_is_flagged() {
    let e = Env::default();
    let a = Address::generate(&e);
    let b = Address::generate(&e);
    let stranger = Address::generate(&e);
    let records = chain(&e, &[a, b]);

    assert_eq!(
        verify_records(&records, Some(&stranger)),
        (DelegationAuditIssue::CurrentHolderMismatch, 1)
    );
}

#[test]
fn a_handover_that_does_not_start_from_the_previous_delegate_is_flagged() {
    let e = Env::default();
    let a = Address::generate(&e);
    let b = Address::generate(&e);
    let c = Address::generate(&e);
    let d = Address::generate(&e);
    let mut records = Vec::new(&e);
    records.push_back(record(1, &a, &b));
    records.push_back(record(2, &c, &d)); // should start from b

    assert_eq!(
        verify_records(&records, Some(&d)),
        (DelegationAuditIssue::BrokenChain, 2)
    );
}

#[test]
fn a_missing_or_reordered_record_is_a_sequence_gap() {
    let e = Env::default();
    let a = Address::generate(&e);
    let b = Address::generate(&e);
    let c = Address::generate(&e);
    let mut records = Vec::new(&e);
    records.push_back(record(1, &a, &b));
    records.push_back(record(3, &b, &c)); // 2 is missing

    assert_eq!(
        verify_records(&records, Some(&c)),
        (DelegationAuditIssue::SequenceGap, 2)
    );

    let mut starts_late = Vec::new(&e);
    starts_late.push_back(record(2, &a, &b));
    assert_eq!(
        verify_records(&starts_late, None),
        (DelegationAuditIssue::SequenceGap, 1)
    );
}

#[test]
fn handing_responsibility_to_oneself_is_flagged() {
    let e = Env::default();
    let a = Address::generate(&e);
    let mut records = Vec::new(&e);
    records.push_back(record(1, &a, &a));

    assert_eq!(
        verify_records(&records, None),
        (DelegationAuditIssue::SelfDelegation, 1)
    );
}

#[test]
fn the_first_problem_is_the_one_reported() {
    let e = Env::default();
    let a = Address::generate(&e);
    let b = Address::generate(&e);
    let c = Address::generate(&e);
    let mut records = Vec::new(&e);
    records.push_back(record(2, &a, &b)); // gap at 1
    records.push_back(record(3, &c, &c)); // would also break the chain and self-delegate

    assert_eq!(
        verify_records(&records, None),
        (DelegationAuditIssue::SequenceGap, 1)
    );
}

#[test]
fn recording_is_allowed_up_to_the_ceiling_and_no_further() {
    assert_eq!(check_can_record(0), Ok(1));
    assert_eq!(
        check_can_record(MAX_DELEGATIONS_PER_RUN - 1),
        Ok(MAX_DELEGATIONS_PER_RUN)
    );
    assert_eq!(
        check_can_record(MAX_DELEGATIONS_PER_RUN),
        Err(DelegationIssue::LimitReached)
    );
    assert_eq!(
        check_can_record(u32::MAX),
        Err(DelegationIssue::LimitReached)
    );
}

#[test]
fn page_size_is_clamped() {
    assert_eq!(clamp_page_size(0), 0);
    assert_eq!(clamp_page_size(10), 10);
    assert_eq!(
        clamp_page_size(MAX_DELEGATION_AUDIT_PAGE),
        MAX_DELEGATION_AUDIT_PAGE
    );
    assert_eq!(clamp_page_size(u32::MAX), MAX_DELEGATION_AUDIT_PAGE);
}

#[test]
fn issues_have_stable_codes() {
    let codes = [
        (DelegationAuditIssue::NoIssue, "no_issue"),
        (DelegationAuditIssue::SequenceGap, "sequence_gap"),
        (DelegationAuditIssue::BrokenChain, "broken_chain"),
        (DelegationAuditIssue::SelfDelegation, "self_delegation"),
        (
            DelegationAuditIssue::CurrentHolderMismatch,
            "current_holder_mismatch",
        ),
    ];
    for (issue, code) in codes {
        assert_eq!(issue.as_str(), code);
    }
}
