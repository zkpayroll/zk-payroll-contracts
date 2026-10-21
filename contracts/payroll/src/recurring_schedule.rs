//! Recurring payroll schedule state machine (#351).
//!
//! Recurring payroll schedules progress through a predictable set of states
//! so dashboard and SDK clients share the same lifecycle model without
//! inventing conflicting timing rules.
//!
//! ## State diagram
//!
//! ```text
//!  ┌───────┐           ┌────────┐          ┌────────────┐          ┌───────────┐
//!  │ Draft │──lock────▶│ Locked │──open────▶│ Executable │──exec───▶│ Finalized │
//!  └───────┘           └────────┘          └────────────┘          └───────────┘
//!      │                   │                     │
//!      │cancel             │miss/cancel           │miss (window closes without exec)
//!      ▼                   ▼                     ▼
//!  ┌──────────┐        ┌────────┐          ┌────────┐
//!  │ Cancelled│        │ Missed │          │ Missed │
//!  └──────────┘        └────────┘          └────────┘
//! ```
//!
//! Allowed manual transitions (admin-driven):
//! - `Draft    → Locked`     (lock the schedule for execution)
//! - `Draft    → Cancelled`  (abandon before locking)
//! - `Locked   → Cancelled`  (abandon after locking, before execution window)
//! - `Executable → Finalized` (mark execution complete)
//!
//! Allowed time-driven transitions (permissionless via `advance_schedule_by_time`):
//! - `Locked → Executable`  (when `ledger_timestamp >= execution_window_open`)
//! - `Locked → Missed`      (when `ledger_timestamp > execution_window_close`)
//! - `Executable → Missed`  (when `ledger_timestamp > execution_window_close`)
//!
//! Privacy: only schedule IDs, company IDs, state labels, and timestamps are
//! stored or emitted. No salary amounts, employee identities, or proof
//! material are involved.

use soroban_sdk::{contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol};

/// Lifecycle state of a recurring payroll schedule period.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ScheduleState {
    /// Created but not yet locked for execution. Editable.
    Draft = 0,
    /// Locked; awaiting the execution window to open.
    Locked = 1,
    /// Inside the execution window; execution is permitted.
    Executable = 2,
    /// Execution window passed without a payroll run being finalized.
    Missed = 3,
    /// Payroll was successfully executed and the period is complete.
    Finalized = 4,
    /// Deliberately abandoned before execution.
    Cancelled = 5,
}

/// Why a schedule transition was rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ScheduleTransitionError {
    /// The requested state transition is not permitted from the current state.
    InvalidTransition = 1,
    /// No schedule record exists for the given schedule ID.
    ScheduleNotFound = 2,
    /// The schedule is already in a finalized terminal state.
    AlreadyFinalized = 3,
    /// The schedule is already in a cancelled terminal state.
    AlreadyCancelled = 4,
    /// The execution window has not opened yet.
    NotExecutableYet = 5,
    /// The execution window has passed; the period is missed.
    WindowMissed = 6,
    /// The caller is not authorized to perform this transition.
    UnauthorizedTransition = 7,
}

impl ScheduleTransitionError {
    pub fn code(self) -> u32 {
        self as u32
    }
}

/// A recurring payroll schedule period.
///
/// Carries the window boundaries and state, but deliberately no salary
/// amounts, employee lists, or commitment hashes.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulePeriod {
    /// Opaque schedule identifier (SHA-256 of creation parameters).
    pub schedule_id: BytesN<32>,
    /// Company this schedule belongs to.
    pub company_id: BytesN<32>,
    /// Current lifecycle state.
    pub state: ScheduleState,
    /// Inclusive start of the payroll period (ledger timestamp).
    pub period_start: u64,
    /// Inclusive end of the payroll period (ledger timestamp).
    pub period_end: u64,
    /// Earliest ledger timestamp at which the run may be executed.
    pub execution_window_open: u64,
    /// Latest ledger timestamp at which the run may be executed. After this
    /// the period transitions to `Missed`.
    pub execution_window_close: u64,
    /// Ledger timestamp when this schedule was created.
    pub created_at: u64,
    /// Ledger timestamp of the most recent state update.
    pub updated_at: u64,
}

/// Storage key for schedule periods.
///
/// Deliberately separate from [`crate::DataKey`] to avoid exhausting the
/// variant ceiling of that enum.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleKey {
    /// Schedule period record keyed by its opaque ID.
    RecurringSchedule(BytesN<32>),
}

// ── Pure transition guard ─────────────────────────────────────────────────────

/// Return `true` iff a manual (admin-driven) transition from `from` to `to`
/// is a permitted arc in the state diagram.
///
/// This function is pure (no storage I/O) so it can be unit-tested directly
/// without a Soroban host.
pub fn is_valid_transition(from: &ScheduleState, to: &ScheduleState) -> bool {
    matches!(
        (from, to),
        (ScheduleState::Draft, ScheduleState::Locked)
            | (ScheduleState::Draft, ScheduleState::Cancelled)
            | (ScheduleState::Locked, ScheduleState::Cancelled)
            | (ScheduleState::Executable, ScheduleState::Finalized)
    )
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Create a new recurring payroll schedule in the `Draft` state.
///
/// Validates that the window boundaries are consistent:
/// - `period_start <= period_end`
/// - `execution_window_open <= execution_window_close`
/// - `execution_window_open >= period_start`
/// - `execution_window_close <= period_end`
///
/// Requires `admin.require_auth()`.
/// Emits `("payroll", "schedule_created")`.
/// Returns the new schedule ID.
pub fn create_schedule(
    e: &Env,
    admin: Address,
    company_id: BytesN<32>,
    period_start: u64,
    period_end: u64,
    execution_window_open: u64,
    execution_window_close: u64,
) -> BytesN<32> {
    admin.require_auth();

    assert!(
        period_start <= period_end,
        "Invalid period boundaries: period_start must be <= period_end"
    );
    assert!(
        execution_window_open <= execution_window_close,
        "Invalid execution window: execution_window_open must be <= execution_window_close"
    );
    assert!(
        execution_window_open >= period_start,
        "Invalid execution window: execution_window_open must be >= period_start"
    );
    assert!(
        execution_window_close <= period_end,
        "Invalid execution window: execution_window_close must be <= period_end"
    );

    let now = e.ledger().timestamp();

    // Derive a deterministic schedule ID from the creation parameters.
    let mut preimage = soroban_sdk::Bytes::new(e);
    preimage.extend_from_array(&company_id.to_array());
    preimage.extend_from_array(&period_start.to_be_bytes());
    preimage.extend_from_array(&period_end.to_be_bytes());
    preimage.extend_from_array(&execution_window_open.to_be_bytes());
    preimage.extend_from_array(&execution_window_close.to_be_bytes());
    preimage.extend_from_array(&now.to_be_bytes());
    let schedule_id: BytesN<32> = e.crypto().sha256(&preimage).into();

    let schedule = SchedulePeriod {
        schedule_id: schedule_id.clone(),
        company_id: company_id.clone(),
        state: ScheduleState::Draft,
        period_start,
        period_end,
        execution_window_open,
        execution_window_close,
        created_at: now,
        updated_at: now,
    };

    let key = ScheduleKey::RecurringSchedule(schedule_id.clone());
    e.storage().persistent().set(&key, &schedule);

    e.events().publish(
        (
            symbol_short!("payroll"),
            Symbol::new(e, "schedule_created"),
        ),
        (schedule_id.clone(), company_id, now),
    );

    schedule_id
}

/// Apply an admin-driven manual transition to `schedule_id`.
///
/// Only the transitions listed in [`is_valid_transition`] are accepted.
/// Time-driven transitions (`Locked → Executable`, `Locked → Missed`,
/// `Executable → Missed`) must go through [`advance_schedule_by_time`].
///
/// Requires `admin.require_auth()`.
/// Emits `("payroll", "schedule_transitioned")`.
pub fn transition_schedule(
    e: &Env,
    admin: Address,
    schedule_id: BytesN<32>,
    target_state: ScheduleState,
) {
    admin.require_auth();

    let key = ScheduleKey::RecurringSchedule(schedule_id.clone());
    let mut schedule: SchedulePeriod = e
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| {
            panic!(
                "Schedule not found: no recurring schedule exists for this ID \
                 (ScheduleTransitionError::{})",
                ScheduleTransitionError::ScheduleNotFound.code()
            )
        });

    if matches!(schedule.state, ScheduleState::Finalized) {
        panic!(
            "Schedule already finalized: this schedule period is complete and cannot transition \
             further (ScheduleTransitionError::{})",
            ScheduleTransitionError::AlreadyFinalized.code()
        );
    }
    if matches!(schedule.state, ScheduleState::Cancelled) {
        panic!(
            "Schedule already cancelled: this schedule period has been abandoned \
             (ScheduleTransitionError::{})",
            ScheduleTransitionError::AlreadyCancelled.code()
        );
    }

    if !is_valid_transition(&schedule.state, &target_state) {
        panic!(
            "Invalid transition: cannot move schedule from its current state to the requested \
             target state — check the allowed arcs in the schedule state diagram \
             (ScheduleTransitionError::{})",
            ScheduleTransitionError::InvalidTransition.code()
        );
    }

    let old_state = schedule.state;
    let now = e.ledger().timestamp();
    schedule.state = target_state;
    schedule.updated_at = now;

    e.storage().persistent().set(&key, &schedule);

    emit_transitioned(e, &schedule_id, old_state, target_state, now);
}

/// Return the full schedule period record for `schedule_id`, if it exists.
pub fn get_schedule(e: &Env, schedule_id: &BytesN<32>) -> Option<SchedulePeriod> {
    let key = ScheduleKey::RecurringSchedule(schedule_id.clone());
    e.storage().persistent().get(&key)
}

/// Return only the current state of `schedule_id`, if it exists.
pub fn get_schedule_state(e: &Env, schedule_id: &BytesN<32>) -> Option<ScheduleState> {
    get_schedule(e, schedule_id).map(|s| s.state)
}

/// Permissionlessly advance a `Locked` or `Executable` schedule based on the
/// current ledger timestamp.
///
/// - `Locked → Executable`  when `now >= execution_window_open`
/// - `Locked → Missed`      when `now > execution_window_close`
/// - `Executable → Missed`  when `now > execution_window_close`
///
/// No-ops if the schedule is already in a terminal state or no time-based
/// transition applies yet. Does not require authorization — anyone may call
/// this to advance a stale schedule.
///
/// Emits `("payroll", "schedule_transitioned")` when a transition occurs.
pub fn advance_schedule_by_time(e: &Env, schedule_id: BytesN<32>) {
    let key = ScheduleKey::RecurringSchedule(schedule_id.clone());
    let mut schedule: SchedulePeriod = match e.storage().persistent().get(&key) {
        Some(s) => s,
        None => return, // no-op for unknown IDs
    };

    let now = e.ledger().timestamp();
    let old_state = schedule.state;

    let new_state = match schedule.state {
        ScheduleState::Locked => {
            if now > schedule.execution_window_close {
                Some(ScheduleState::Missed)
            } else if now >= schedule.execution_window_open {
                Some(ScheduleState::Executable)
            } else {
                None
            }
        }
        ScheduleState::Executable => {
            if now > schedule.execution_window_close {
                Some(ScheduleState::Missed)
            } else {
                None
            }
        }
        // All other states are either terminal or not time-driven.
        _ => None,
    };

    if let Some(target) = new_state {
        schedule.state = target;
        schedule.updated_at = now;
        e.storage().persistent().set(&key, &schedule);
        emit_transitioned(e, &schedule_id, old_state, target, now);
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn emit_transitioned(
    e: &Env,
    schedule_id: &BytesN<32>,
    old_state: ScheduleState,
    new_state: ScheduleState,
    now: u64,
) {
    e.events().publish(
        (
            symbol_short!("payroll"),
            Symbol::new(e, "schedule_transitioned"),
        ),
        (schedule_id.clone(), old_state as u32, new_state as u32, now),
    );
}
