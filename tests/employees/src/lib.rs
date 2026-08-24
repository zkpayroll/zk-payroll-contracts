//! # Employee Status Transition Tests (issue #249)
//!
//! Verifies the employee lifecycle enforced by `payroll_registry` and that
//! payroll execution respects employee status.
//!
//! ## Structure
//!
//! - [`common`] — Shared test environment helpers (contract wiring, company
//!   and employee seeding, payment executor plumbing).
//!
//! - [`status_transitions`] — The allowed/blocked status transition matrix:
//!   every supported status change, idempotent no-ops, unauthorized calls,
//!   unknown companies/employees, and removal semantics.
//!
//! - [`payroll_eligibility`] — End-to-end checks that `payment_executor`
//!   pays only `Active` employees and blocks inactive, incomplete, removed,
//!   or unregistered ones.
//!
//! ## Usage
//!
//! ```bash
//! cargo test -p employee_status_tests
//! ```

#[cfg(test)]
mod common;
#[cfg(test)]
mod payroll_eligibility;
#[cfg(test)]
mod status_transitions;
