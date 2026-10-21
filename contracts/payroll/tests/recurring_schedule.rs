//! Tests for recurring payroll schedule state machine (#351).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

use payroll::recurring_schedule::{
    advance_schedule_by_time, create_schedule, get_schedule, get_schedule_state,
    is_valid_transition, transition_schedule, ScheduleState,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn company_id(e: &Env) -> BytesN<32> {
    BytesN::from_array(e, &[42u8; 32])
}

/// Creates a schedule with a sensible default window starting at `base_time`.
fn make_schedule(e: &Env, admin: &Address, base_time: u64) -> BytesN<32> {
    let period_start = base_time;
    let period_end = base_time + 86_400 * 30; // 30 days
    let exec_open = base_time + 86_400 * 28; // opens 28 days in
    let exec_close = base_time + 86_400 * 29; // closes 29 days in

    create_schedule(
        e,
        admin.clone(),
        company_id(e),
        period_start,
        period_end,
        exec_open,
        exec_close,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_create_schedule_draft() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    e.ledger().set_timestamp(1_000_000);

    let schedule_id = make_schedule(&e, &admin, 1_000_000);

    let schedule = get_schedule(&e, &schedule_id).expect("schedule should exist");
    assert_eq!(schedule.state, ScheduleState::Draft);
    assert_eq!(schedule.company_id, company_id(&e));
}

#[test]
fn test_valid_transitions() {
    // Draft -> Locked
    assert!(is_valid_transition(
        &ScheduleState::Draft,
        &ScheduleState::Locked
    ));
    // Draft -> Cancelled
    assert!(is_valid_transition(
        &ScheduleState::Draft,
        &ScheduleState::Cancelled
    ));
    // Locked -> Cancelled
    assert!(is_valid_transition(
        &ScheduleState::Locked,
        &ScheduleState::Cancelled
    ));
    // Executable -> Finalized
    assert!(is_valid_transition(
        &ScheduleState::Executable,
        &ScheduleState::Finalized
    ));
}

#[test]
fn test_invalid_transitions_rejected() {
    // Cannot go backwards
    assert!(!is_valid_transition(
        &ScheduleState::Finalized,
        &ScheduleState::Draft
    ));
    // Cannot skip states
    assert!(!is_valid_transition(
        &ScheduleState::Draft,
        &ScheduleState::Finalized
    ));
    // Cannot go from Missed anywhere manually
    assert!(!is_valid_transition(
        &ScheduleState::Missed,
        &ScheduleState::Finalized
    ));
    // Cannot go from Executable to Cancelled (only Finalized)
    assert!(!is_valid_transition(
        &ScheduleState::Executable,
        &ScheduleState::Cancelled
    ));
}

#[test]
fn test_manual_transition_draft_to_locked() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    e.ledger().set_timestamp(1_000_000);
    let schedule_id = make_schedule(&e, &admin, 1_000_000);

    transition_schedule(&e, admin.clone(), schedule_id.clone(), ScheduleState::Locked);

    let state = get_schedule_state(&e, &schedule_id).unwrap();
    assert_eq!(state, ScheduleState::Locked);
}

#[test]
#[should_panic(expected = "Invalid transition")]
fn test_invalid_transition_rejected() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    e.ledger().set_timestamp(1_000_000);
    let schedule_id = make_schedule(&e, &admin, 1_000_000);

    // Draft -> Finalized is not a valid manual arc
    transition_schedule(
        &e,
        admin.clone(),
        schedule_id.clone(),
        ScheduleState::Finalized,
    );
}

#[test]
fn test_time_based_advance_locked_to_executable() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let base = 1_000_000u64;
    e.ledger().set_timestamp(base);

    let schedule_id = make_schedule(&e, &admin, base);
    transition_schedule(&e, admin.clone(), schedule_id.clone(), ScheduleState::Locked);

    // Advance time to execution window (28 days in)
    e.ledger().set_timestamp(base + 86_400 * 28);
    advance_schedule_by_time(&e, schedule_id.clone());

    let state = get_schedule_state(&e, &schedule_id).unwrap();
    assert_eq!(state, ScheduleState::Executable);
}

#[test]
fn test_missed_window_transition() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let base = 1_000_000u64;
    e.ledger().set_timestamp(base);

    let schedule_id = make_schedule(&e, &admin, base);
    transition_schedule(&e, admin.clone(), schedule_id.clone(), ScheduleState::Locked);

    // Advance past the close window (30+ days in)
    e.ledger().set_timestamp(base + 86_400 * 31);
    advance_schedule_by_time(&e, schedule_id.clone());

    let state = get_schedule_state(&e, &schedule_id).unwrap();
    assert_eq!(state, ScheduleState::Missed);
}

#[test]
fn test_executable_to_missed_if_window_closes() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let base = 1_000_000u64;
    e.ledger().set_timestamp(base);

    let schedule_id = make_schedule(&e, &admin, base);
    transition_schedule(&e, admin.clone(), schedule_id.clone(), ScheduleState::Locked);

    // Advance to execution window open
    e.ledger().set_timestamp(base + 86_400 * 28);
    advance_schedule_by_time(&e, schedule_id.clone());
    assert_eq!(
        get_schedule_state(&e, &schedule_id).unwrap(),
        ScheduleState::Executable
    );

    // Now advance past execution window close
    e.ledger().set_timestamp(base + 86_400 * 30 + 1);
    advance_schedule_by_time(&e, schedule_id.clone());
    assert_eq!(
        get_schedule_state(&e, &schedule_id).unwrap(),
        ScheduleState::Missed
    );
}

#[test]
#[should_panic(expected = "already finalized")]
fn test_cannot_transition_finalized_schedule() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let base = 1_000_000u64;
    e.ledger().set_timestamp(base);

    let schedule_id = make_schedule(&e, &admin, base);

    // Bring to Executable state via time advancement
    transition_schedule(&e, admin.clone(), schedule_id.clone(), ScheduleState::Locked);
    e.ledger().set_timestamp(base + 86_400 * 28);
    advance_schedule_by_time(&e, schedule_id.clone());

    // Finalize
    transition_schedule(
        &e,
        admin.clone(),
        schedule_id.clone(),
        ScheduleState::Finalized,
    );

    // Should panic
    transition_schedule(
        &e,
        admin.clone(),
        schedule_id.clone(),
        ScheduleState::Cancelled,
    );
}

#[test]
fn test_advance_no_op_for_draft() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    e.ledger().set_timestamp(1_000_000);
    let schedule_id = make_schedule(&e, &admin, 1_000_000);

    // advance_schedule_by_time on a Draft should be a no-op
    e.ledger().set_timestamp(2_000_000_000);
    advance_schedule_by_time(&e, schedule_id.clone());

    let state = get_schedule_state(&e, &schedule_id).unwrap();
    assert_eq!(state, ScheduleState::Draft);
}
