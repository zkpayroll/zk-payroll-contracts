//! # Migration Test Framework
//!
//! This module provides a comprehensive framework for testing contract state
//! compatibility across schema upgrades.
//!
//! ## Structure
//!
//! - [`state_fixtures`] — Representative pre-upgrade state fixtures for all
//!   contract data types (companies, employees, payroll runs, audit permissions, etc.)
//!
//! - [`migration_helpers`] — Reusable migration test utilities including
//!   `MigrationContext`, state setup, upgrade simulation, and assertion helpers.
//!
//! - [`migration_tests`] — All migration test cases (positive and negative).
//!
//! ## Usage
//!
//! ```bash
//! cargo test -p migration_tests
//! # or include in integration_tests:
//! cargo test -p integration_tests migration_
//! ```
//!
//! ## Adding New Tests
//!
//! 1. Add a new fixture constructor in `state_fixtures` if needed.
//! 2. Add assertion helpers in `migration_helpers`.
//! 3. Write the test in `migration_tests` following the `mg_*` naming convention.
//! 4. Document the invariants the test verifies.

pub mod migration_helpers;
pub mod migration_tests;
pub mod state_fixtures;
