use soroban_sdk::contracttype;
use shared_errors::PaymentError;

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentInstruction {
    pub instruction_id: u64,
    pub period_id: u64,
    pub employee_id: u64,
    pub amount: i128,
    pub valid_until: u64,
    pub created_at: u64,
}

/// Enforces payment instruction expiry against current ledger timestamp (#570).
pub fn enforce_payment_instruction_expiry(
    current_timestamp: u64,
    valid_until: u64,
) -> Result<(), PaymentError> {
    if current_timestamp > valid_until {
        return Err(PaymentError::SettlementWindowClosed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_instruction_valid() {
        assert!(enforce_payment_instruction_expiry(1000, 2000).is_ok());
    }

    #[test]
    fn test_payment_instruction_expired() {
        assert_eq!(
            enforce_payment_instruction_expiry(2001, 2000),
            Err(PaymentError::SettlementWindowClosed)
        );
    }
}
