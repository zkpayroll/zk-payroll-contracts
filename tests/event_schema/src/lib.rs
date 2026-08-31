#![cfg(test)]

//! Snapshot tests that pin the wire shape of every Soroban contract event
//! emitted through the `payroll_events` crate.
//!
//! # Why this exists
//! SDKs, dashboards, indexers, and audit exports all depend on event topics
//! and payload shapes staying stable. A one-line change to an `emit_*`
//! helper (reordering a tuple, adding a field, renaming a topic symbol) is
//! invisible in a normal unit test but silently breaks every off-chain
//! consumer parsing that event. These tests make that kind of change loud:
//! they fail if a topic list or payload shape drifts from the checked-in
//! fixture in `fixtures/events/`.
//!
//! # Layout
//! - `support.rs` — shared capture/compare scaffolding.
//! - one module per contract domain (`payroll`, `registry`,
//!   `salary_commitment`, `payment_executor`, `pause_manager`,
//!   `audit_module`), each with one `#[test]` per emitted event.
//! - `fixtures/events/*.json` — the checked-in expected schema per domain.
//! - `fixtures/events/README.md` — how to update a fixture on an intentional
//!   schema change.

mod support;

mod audit_module;
mod pause_manager;
mod payment_executor;
mod payroll;
mod registry;
mod salary_commitment;
