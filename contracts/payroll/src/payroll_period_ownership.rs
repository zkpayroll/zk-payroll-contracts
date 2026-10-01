use soroban_sdk::{contracttype, Address, Env};
use shared_errors::AuthError;

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayrollPeriodOwnership {
    pub period_id: u64,
    pub owner: Address,
    pub company: Address,
    pub created_at: u64,
}

/// Verifies that the caller matches the recorded owner of a payroll period (#568).
pub fn verify_payroll_period_owner(
    env: &Env,
    stored_owner: &Address,
    caller: &Address,
) -> Result<(), AuthError> {
    caller.require_auth();
    if stored_owner != caller {
        return Err(AuthError::UnauthorizedAdmin);
    }
    Ok(())
}

/// Asserts ownership without throwing host auth if already authenticated.
pub fn assert_payroll_period_owner(
    stored_owner: &Address,
    invoker: &Address,
) -> Result<(), AuthError> {
    if stored_owner != invoker {
        return Err(AuthError::UnauthorizedAdmin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_payroll_period_ownership_success() {
        let env = Env::default();
        let owner = Address::generate(&env);
        assert!(assert_payroll_period_owner(&owner, &owner).is_ok());
    }

    #[test]
    fn test_payroll_period_ownership_mismatch() {
        let env = Env::default();
        let owner = Address::generate(&env);
        let caller = Address::generate(&env);
        assert_eq!(
            assert_payroll_period_owner(&owner, &caller),
            Err(AuthError::UnauthorizedAdmin)
        );
    }
}
