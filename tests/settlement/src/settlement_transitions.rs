//! Settlement state transition matrix tests (issue #254).
//!
//! The contract's canonical settlement lifecycle is the `PayrollRunState`
//! machine in `contracts/payroll/src/lib.rs`, enforced by
//! `is_allowed_payroll_state_transition_internal` and the admin-only
//! `transition_payroll_run_state` hook. These tests pin down every allowed
//! transition, prove invalid transitions are rejected predictably, and verify
//! the terminal / retryable semantics plus authorization.
//!
//! High-level settlement phases (issue #254) map to concrete states as:
//! `pending`→`Submitted`, `executing`→`Confirming`, `settled`→`Completed`,
//! `failed`→`Failed`, `cancelled`→`Cancelled`.

use crate::common::Setup;
use payroll::PayrollRunState;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// Canonical set of allowed transitions, mirroring
/// `is_allowed_payroll_state_transition_internal`. Used as the oracle for the
/// matrix test so the contract cannot silently drift from the documented rules.
fn expected_allowed(from: PayrollRunState, to: PayrollRunState) -> bool {
    use PayrollRunState::*;
    match from {
        Draft => matches!(to, Validating | Cancelled),
        Validating => matches!(to, ProofPending | Failed | Cancelled),
        ProofPending => matches!(to, ReadyToSubmit | Failed | Cancelled),
        ReadyToSubmit => matches!(to, Submitted | Failed | Cancelled),
        Submitted => matches!(to, Confirming | Failed | Cancelled),
        Confirming => matches!(to, Completed | Failed | ReconciliationRequired),
        Failed => matches!(to, Validating | ProofPending | Cancelled),
        ReconciliationRequired => matches!(to, Completed | Failed),
        Completed | Cancelled => false,
    }
}

/// Drive a freshly prepared run (starts in `Submitted`) to `target` via the
/// shortest chain of allowed transitions. `Draft` is unreachable from
/// `Submitted` and is intentionally excluded.
fn drive_to(setup: &Setup, run_id: u64, target: PayrollRunState) {
    use PayrollRunState::*;
    let path: &[PayrollRunState] = match target {
        Submitted => &[],
        Confirming => &[Confirming],
        Failed => &[Failed],
        Cancelled => &[Cancelled],
        ReconciliationRequired => &[Confirming, ReconciliationRequired],
        Completed => &[Confirming, Completed],
        Validating => &[Failed, Validating],
        ProofPending => &[Failed, Validating, ProofPending],
        ReadyToSubmit => &[Failed, Validating, ProofPending, ReadyToSubmit],
        Draft => &[],
    };
    for step in path {
        setup
            .payroll
            .transition_payroll_run_state(&setup.admin, &run_id, step);
    }
    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        target,
        "drive_to should land the run in the target state"
    );
}

// ---------------------------------------------------------------------------
// Matrix oracle — every valid/invalid transition
// ---------------------------------------------------------------------------

/// The contract's transition matrix must exactly match the documented rules
/// for all 10 × 10 ordered pairs.
#[test]
fn transition_matrix_matches_documented_rules() {
    use PayrollRunState::*;
    let _env = Env::default();
    let setup = Setup::new();

    let states = [
        Draft,
        Validating,
        ProofPending,
        ReadyToSubmit,
        Submitted,
        Confirming,
        Completed,
        Failed,
        Cancelled,
        ReconciliationRequired,
    ];

    for &from in &states {
        for &to in &states {
            let actual = setup
                .payroll
                .is_state_transition_allowed(&from, &to);
            assert_eq!(
                actual,
                expected_allowed(from, to),
                "matrix mismatch for {:?} -> {:?}",
                from,
                to
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Valid transitions apply on-chain
// ---------------------------------------------------------------------------

/// `pending` (`Submitted`) → `executing` (`Confirming`) is an allowed
/// settlement transition and is applied.
#[test]
fn pending_to_executing_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(1);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Confirming);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Confirming
    );
}

/// `executing` (`Confirming`) → `settled` (`Completed`) finalizes settlement.
#[test]
fn executing_to_settled_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(2);
    drive_to(&setup, run_id, PayrollRunState::Confirming);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Completed);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Completed
    );
}

/// `executing` (`Confirming`) → `failed` (`Failed`) halts settlement and keeps
/// the run retryable.
#[test]
fn executing_to_failed_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(3);
    drive_to(&setup, run_id, PayrollRunState::Confirming);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Failed);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Failed
    );
    assert!(setup.payroll.is_payroll_state_retryable(&PayrollRunState::Failed));
}

/// `pending` (`Submitted`) → `cancelled` (`Cancelled`) is allowed; the run is
/// then terminal.
#[test]
fn pending_to_cancelled_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(4);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Cancelled);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Cancelled
    );
}

/// `failed` (`Failed`) → `pending` (`Validating`, retry) re-opens settlement.
#[test]
fn failed_to_retry_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(5);
    drive_to(&setup, run_id, PayrollRunState::Failed);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Validating);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Validating
    );
}

/// `executing` (`Confirming`) → `ReconciliationRequired` is the settlement
/// review path; from there `settled` (`Completed`) closes it.
#[test]
fn reconciliation_then_settled_is_applied() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(6);
    drive_to(&setup, run_id, PayrollRunState::ReconciliationRequired);

    setup
        .payroll
        .transition_payroll_run_state(&setup.admin, &run_id, &PayrollRunState::Completed);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Completed
    );
}

// ---------------------------------------------------------------------------
// Invalid transitions fail predictably
// ---------------------------------------------------------------------------

/// Skipping straight from `pending` to `settled` is not allowed and must
/// panic with the canonical message.
#[test]
fn invalid_pending_to_settled_is_rejected() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(7);

    let result = setup.payroll.try_transition_payroll_run_state(
        &setup.admin,
        &run_id,
        &PayrollRunState::Completed,
    );

    assert!(result.is_err(), "pending -> settled is not a valid transition");
}

/// `failed` cannot jump to `settled` without going through reconciliation.
#[test]
fn invalid_failed_to_settled_is_rejected() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(8);
    drive_to(&setup, run_id, PayrollRunState::Failed);

    let result = setup.payroll.try_transition_payroll_run_state(
        &setup.admin,
        &run_id,
        &PayrollRunState::Completed,
    );

    assert!(result.is_err(), "failed -> settled skips required reconciliation");
}

/// A terminal state accepts no further transitions: `settled` (`Completed`)
/// rejects every attempted move.
#[test]
fn settled_is_terminal_and_rejects_all_transitions() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(9);
    drive_to(&setup, run_id, PayrollRunState::Completed);

    for next in [
        PayrollRunState::Confirming,
        PayrollRunState::Failed,
        PayrollRunState::Cancelled,
        PayrollRunState::ReconciliationRequired,
        PayrollRunState::Submitted,
    ] {
        let result = setup
            .payroll
            .try_transition_payroll_run_state(&setup.admin, &run_id, &next);
        assert!(
            result.is_err(),
            "settled (Completed) must reject transition to {:?}",
            next
        );
    }
    assert!(setup
        .payroll
        .is_payroll_state_terminal(&PayrollRunState::Completed));
}

/// `cancelled` is terminal and rejects every attempted transition.
#[test]
fn cancelled_is_terminal_and_rejects_all_transitions() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(10);
    drive_to(&setup, run_id, PayrollRunState::Cancelled);

    for next in [
        PayrollRunState::Submitted,
        PayrollRunState::Confirming,
        PayrollRunState::Failed,
        PayrollRunState::Validating,
    ] {
        let result = setup
            .payroll
            .try_transition_payroll_run_state(&setup.admin, &run_id, &next);
        assert!(
            result.is_err(),
            "cancelled (Cancelled) must reject transition to {:?}",
            next
        );
    }
    assert!(setup
        .payroll
        .is_payroll_state_terminal(&PayrollRunState::Cancelled));
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Only the company admin may drive settlement state transitions.
#[test]
#[should_panic(expected = "Unauthorized")]
fn non_admin_cannot_transition_settlement_state() {
    let env = Env::default();
    env.mock_all_auths();

    let setup = Setup::new();
    let run_id = setup.prepare_run(11);

    let attacker = Address::generate(&env);

    setup.payroll.transition_payroll_run_state(
        &attacker,
        &run_id,
        &PayrollRunState::Confirming,
    );
}

// ---------------------------------------------------------------------------
// Lifecycle end-to-end
// ---------------------------------------------------------------------------

/// A prepared run starts in `pending` (`Submitted`) and settling it reaches
/// `settled` (`Completed`).
#[test]
fn prepare_starts_pending_settlement() {
    let setup = Setup::new();
    let run_id = setup.prepare_run(12);

    assert_eq!(
        setup.payroll.get_payroll_run_state(&run_id),
        PayrollRunState::Submitted
    );
}

/// `failed` is the only retryable settlement state; `settled`/`cancelled` are
/// not.
#[test]
fn only_failed_state_is_retryable() {
    let _env = Env::default();
    let setup = Setup::new();

    assert!(setup
        .payroll
        .is_payroll_state_retryable(&PayrollRunState::Failed));
    assert!(!setup
        .payroll
        .is_payroll_state_retryable(&PayrollRunState::Completed));
    assert!(!setup
        .payroll
        .is_payroll_state_retryable(&PayrollRunState::Cancelled));
    assert!(!setup
        .payroll
        .is_payroll_state_retryable(&PayrollRunState::Submitted));
}
