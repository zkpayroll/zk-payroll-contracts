use soroban_sdk::contracttype;
use shared_errors::StateError;

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EmployeeStatus {
    Active = 0,
    Suspended = 1,
    Terminated = 2,
    OnLeave = 3,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayrollPayoutRule {
    pub allow_payout_during_suspension: bool,
    pub suspension_allowance_bps: u32, // e.g. 5000 = 50% allowance
}

/// Evaluates employee status and applies suspension payout rules (#580).
pub fn evaluate_suspension_payout(
    status: EmployeeStatus,
    base_amount: i128,
    rule: &PayrollPayoutRule,
) -> Result<i128, StateError> {
    match status {
        EmployeeStatus::Active => Ok(base_amount),
        EmployeeStatus::OnLeave => Ok(base_amount),
        EmployeeStatus::Terminated => Err(StateError::InvalidEmployeeStatus),
        EmployeeStatus::Suspended => {
            if !rule.allow_payout_during_suspension {
                return Err(StateError::InvalidEmployeeStatus);
            }
            if rule.suspension_allowance_bps == 0 {
                return Ok(0);
            }
            let allowance = base_amount
                .checked_mul(rule.suspension_allowance_bps as i128)
                .unwrap_or(0)
                / 10000;
            Ok(allowance)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_employee_full_payout() {
        let rule = PayrollPayoutRule {
            allow_payout_during_suspension: false,
            suspension_allowance_bps: 0,
        };
        assert_eq!(
            evaluate_suspension_payout(EmployeeStatus::Active, 1000, &rule),
            Ok(1000)
        );
    }

    #[test]
    fn test_suspended_employee_disallowed() {
        let rule = PayrollPayoutRule {
            allow_payout_during_suspension: false,
            suspension_allowance_bps: 0,
        };
        assert_eq!(
            evaluate_suspension_payout(EmployeeStatus::Suspended, 1000, &rule),
            Err(StateError::InvalidEmployeeStatus)
        );
    }

    #[test]
    fn test_suspended_employee_partial_allowance() {
        let rule = PayrollPayoutRule {
            allow_payout_during_suspension: true,
            suspension_allowance_bps: 5000, // 50%
        };
        assert_eq!(
            evaluate_suspension_payout(EmployeeStatus::Suspended, 1000, &rule),
            Ok(500)
        );
    }
}
