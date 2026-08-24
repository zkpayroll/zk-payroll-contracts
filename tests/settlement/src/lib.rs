//! # Settlement State Transition Tests (issue #254)
//!
//! Verifies the canonical payroll **settlement** lifecycle enforced by
//! `contracts/payroll/src/lib.rs`. The contract models the lifecycle with the
//! `PayrollRunState` enum and the `is_allowed_payroll_state_transition_internal`
//! matrix; the high-level settlement phases requested in the issue map onto it
//! as follows:
//!
//! | Settlement phase (issue #254) | `PayrollRunState` |
//! | ----------------------------- | ---------------- |
//! | `pending`                     | `Submitted`      |
//! | `executing`                   | `Confirming`    |
//! | `settled`                     | `Completed`     |
//! | `failed`                      | `Failed`        |
//! | `cancelled`                   | `Cancelled`     |
//!
//! ## Structure
//!
//! - [`common`] — Shared test environment that wires the payroll contract
//!   (verifier, commitment, token) and prepares a run in `Submitted`.
//!
//! - [`settlement_transitions`] — The allowed/blocked transition matrix:
//!   every valid transition, predictably rejected invalid transitions,
//!   terminal/immutable states, retryability, and authorization.
//!
//! ## Usage
//!
//! ```bash
//! cargo test -p settlement_state_tests
//! ```

#[cfg(test)]
mod common;
#[cfg(test)]
mod settlement_transitions;
