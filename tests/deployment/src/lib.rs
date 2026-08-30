//! # Deployment Parameter Validation Tests
//!
//! Tests for deployment-time validation of contract initialization
//! parameters (admin address, supported assets, network id, and initial
//! treasury configuration) across the `payroll` and `payment_executor`
//! contracts.
//!
//! ## Structure
//!
//! - [`helpers`] — Shared deployment fixtures (contract registration,
//!   valid parameter sets, network-id string builders).
//!
//! - [`payroll_deployment_tests`] — `dp_*` tests covering `Payroll::initialize`
//!   validation and the one-time network-id record.
//!
//! - [`executor_deployment_tests`] — `de_*` tests covering
//!   `PaymentExecutor::initialize` wiring validation.
//!
//! ## Usage
//!
//! ```bash
//! cargo test -p deployment_tests
//! ```

#[cfg(test)]
pub mod executor_deployment_tests;
#[cfg(test)]
pub mod helpers;
#[cfg(test)]
pub mod payroll_deployment_tests;
