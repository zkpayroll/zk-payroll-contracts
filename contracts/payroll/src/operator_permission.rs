//! Payroll operator permission validation (#652).
//!
//! Prior to this module, every privileged payroll action was gated by a single
//! admin address check (`ContractAddresses::admin.require_auth()`).  This
//! works for a company running payroll from a single account, but breaks down
//! for organisations where different roles must be delegated without granting
//! full admin access: a payroll processor should be able to submit runs but
//! not change fee schedules; an auditor should be able to read period state
//! but not initiate payments.
//!
//! This module introduces a *capability-based* operator model.  An operator
//! is any address that an admin registers with an explicit set of
//! [`OperatorCapability`] flags.  Before a privileged action proceeds, the
//! contract calls [`require_operator_capability`] for the specific capability
//! the action needs; the call passes only if the operator's stored grant
//! includes that flag.
//!
//! The admin address retains all capabilities implicitly and is never required
//! to be registered as an operator.
//!
//! Privacy: only addresses, capability flags, and timestamps are stored.  No
//! salary amount, employee identity, or proof material is read or emitted.

use soroban_sdk::{contracttype, Address, Env};

use shared_errors::AuthError;

/// Fine-grained capabilities an operator address may hold.
///
/// Serialised as a stable u32 so off-chain consumers can persist and
/// pattern-match on capability grants across contract upgrades.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OperatorCapability {
    /// May initiate or submit payroll runs (execute, batch-process).
    ExecutePayroll = 1,
    /// May record or withdraw approval for a payroll run.
    ApprovePayroll = 2,
    /// May update payroll configuration (fee rates, settlement windows).
    Configure = 3,
    /// May read period state, employee records, and audit logs.
    Read = 4,
}

/// A grant of capabilities assigned to one operator address.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorGrant {
    /// The address this grant belongs to.
    pub operator: Address,
    /// The capabilities the operator may exercise.
    pub capabilities: soroban_sdk::Vec<OperatorCapability>,
    /// Ledger timestamp when the grant was created or last updated.
    pub granted_at: u64,
    /// Admin address that created the grant.
    pub granted_by: Address,
}

/// Privacy-safe snapshot returned by a permission pre-flight check.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorPermissionCheck {
    /// The address that was checked.
    pub operator: Address,
    /// The capability that was required.
    pub required: OperatorCapability,
    /// `true` iff the operator holds the required capability.
    pub authorized: bool,
}

/// Check whether `operator` holds `required` without requiring auth.
///
/// Returns a [`OperatorPermissionCheck`] snapshot suitable for dashboards and
/// SDK preflight calls.  Does **not** call `operator.require_auth()` — use
/// [`require_operator_capability`] on the hot path instead.
pub fn check_operator_capability(
    env: &Env,
    operator: &Address,
    required: OperatorCapability,
    grant: Option<&OperatorGrant>,
) -> OperatorPermissionCheck {
    let authorized = grant.map_or(false, |g| {
        g.capabilities.iter().any(|c| c == required)
    });
    OperatorPermissionCheck {
        operator: operator.clone(),
        required,
        authorized,
    }
}

/// Require `operator` to be authenticated **and** hold `required`.
///
/// Calls `operator.require_auth()` first so the host verifier records the
/// auth; then checks the stored grant.  Returns `Err(AuthError::UnauthorizedAdmin)`
/// when the operator is not registered or lacks the required capability.
pub fn require_operator_capability(
    env: &Env,
    operator: &Address,
    required: OperatorCapability,
    grant: Option<&OperatorGrant>,
) -> Result<(), AuthError> {
    operator.require_auth();
    let check = check_operator_capability(env, operator, required, grant);
    if check.authorized {
        Ok(())
    } else {
        Err(AuthError::UnauthorizedAdmin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Env};

    fn make_grant(
        env: &Env,
        operator: &Address,
        caps: soroban_sdk::Vec<OperatorCapability>,
    ) -> OperatorGrant {
        OperatorGrant {
            operator: operator.clone(),
            capabilities: caps,
            granted_at: env.ledger().timestamp(),
            granted_by: Address::generate(env),
        }
    }

    #[test]
    fn operator_with_matching_capability_is_authorized() {
        let env = Env::default();
        let op = Address::generate(&env);
        let grant = make_grant(&env, &op, vec![&env, OperatorCapability::ExecutePayroll]);
        let check = check_operator_capability(&env, &op, OperatorCapability::ExecutePayroll, Some(&grant));
        assert!(check.authorized);
    }

    #[test]
    fn operator_without_required_capability_is_not_authorized() {
        let env = Env::default();
        let op = Address::generate(&env);
        let grant = make_grant(&env, &op, vec![&env, OperatorCapability::Read]);
        let check = check_operator_capability(&env, &op, OperatorCapability::ExecutePayroll, Some(&grant));
        assert!(!check.authorized);
    }

    #[test]
    fn unregistered_operator_is_not_authorized() {
        let env = Env::default();
        let op = Address::generate(&env);
        let check = check_operator_capability(&env, &op, OperatorCapability::ApprovePayroll, None);
        assert!(!check.authorized);
    }

    #[test]
    fn operator_with_multiple_capabilities_satisfies_any_one() {
        let env = Env::default();
        let op = Address::generate(&env);
        let grant = make_grant(
            &env,
            &op,
            vec![
                &env,
                OperatorCapability::Read,
                OperatorCapability::ApprovePayroll,
                OperatorCapability::Configure,
            ],
        );
        for cap in [
            OperatorCapability::Read,
            OperatorCapability::ApprovePayroll,
            OperatorCapability::Configure,
        ] {
            let check = check_operator_capability(&env, &op, cap, Some(&grant));
            assert!(check.authorized, "expected authorized for {:?}", cap);
        }
        let check = check_operator_capability(&env, &op, OperatorCapability::ExecutePayroll, Some(&grant));
        assert!(!check.authorized);
    }

    #[test]
    fn permission_check_snapshot_carries_correct_fields() {
        let env = Env::default();
        let op = Address::generate(&env);
        let grant = make_grant(&env, &op, vec![&env, OperatorCapability::Configure]);
        let check = check_operator_capability(&env, &op, OperatorCapability::Configure, Some(&grant));
        assert_eq!(check.operator, op);
        assert_eq!(check.required, OperatorCapability::Configure);
        assert!(check.authorized);
    }
}
