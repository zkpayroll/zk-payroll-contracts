//! Employee payment destination confirmation (#704)
//!
//! Ensures employees confirm their payment destinations before payroll execution.

#![no_std]

use soroban_sdk::{contracttype, Address, Env, String};

/// Error codes for payment destination confirmation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DestinationConfirmationError {
    /// The payment destination is not confirmed.
    NotConfirmed = 1,
    /// The confirmation has expired.
    ConfirmationExpired = 2,
    /// The destination address is invalid.
    InvalidDestination = 3,
    /// The employee is not authorized to confirm.
    Unauthorized = 4,
    /// The confirmation already exists.
    AlreadyConfirmed = 5,
}

/// Confirmation status for a payment destination.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ConfirmationStatus {
    /// Awaiting employee confirmation.
    Pending = 0,
    /// Employee confirmed the destination.
    Confirmed = 1,
    /// Confirmation was rejected.
    Rejected = 2,
    /// Confirmation has expired.
    Expired = 3,
}

/// A payment destination confirmation record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationConfirmation {
    /// The employee address.
    pub employee: Address,
    /// The payment destination (wallet address).
    pub destination: Address,
    /// The confirmation status.
    pub status: ConfirmationStatus,
    /// Unix timestamp when the confirmation was requested.
    pub requested_at: u64,
    /// Unix timestamp when the confirmation expires.
    pub expires_at: u64,
    /// Unix timestamp when the employee confirmed.
    pub confirmed_at: u64,
    /// Optional confirmation note.
    pub note: String,
}

/// Default confirmation expiry period (7 days in seconds).
pub const DEFAULT_CONFIRMATION_EXPIRY: u64 = 7 * 24 * 60 * 60;

/// Request confirmation for a payment destination.
pub fn request_destination_confirmation(
    env: &Env,
    employee: &Address,
    destination: &Address,
    expiry_seconds: u64,
) -> Result<DestinationConfirmation, DestinationConfirmationError> {
    let now = env.ledger().timestamp();

    // Validate destination is not zero address
    if destination == &Address::from_string(&env, &String::from_str(&env, "")) {
        return Err(DestinationConfirmationError::InvalidDestination);
    }

    let expiry = if expiry_seconds > 0 {
        expiry_seconds
    } else {
        DEFAULT_CONFIRMATION_EXPIRY
    };

    Ok(DestinationConfirmation {
        employee: employee.clone(),
        destination: destination.clone(),
        status: ConfirmationStatus::Pending,
        requested_at: now,
        expires_at: now + expiry,
        confirmed_at: 0,
        note: String::from_str(&env, ""),
    })
}

/// Confirm a payment destination.
pub fn confirm_destination(
    env: &Env,
    confirmation: &mut DestinationConfirmation,
    employee: &Address,
) -> Result<(), DestinationConfirmationError> {
    let now = env.ledger().timestamp();

    // Only the employee can confirm
    if confirmation.employee != *employee {
        return Err(DestinationConfirmationError::Unauthorized);
    }

    // Check if already confirmed
    if confirmation.status == ConfirmationStatus::Confirmed {
        return Err(DestinationConfirmationError::AlreadyConfirmed);
    }

    // Check if expired
    if now > confirmation.expires_at {
        confirmation.status = ConfirmationStatus::Expired;
        return Err(DestinationConfirmationError::ConfirmationExpired);
    }

    confirmation.status = ConfirmationStatus::Confirmed;
    confirmation.confirmed_at = now;

    Ok(())
}

/// Check if a destination is confirmed and not expired.
pub fn is_destination_confirmed(env: &Env, confirmation: &DestinationConfirmation) -> bool {
    let now = env.ledger().timestamp();
    confirmation.status == ConfirmationStatus::Confirmed
        && now <= confirmation.expires_at
}

/// Reject a payment destination.
pub fn reject_destination(
    _env: &Env,
    confirmation: &mut DestinationConfirmation,
    employee: &Address,
) -> Result<(), DestinationConfirmationError> {
    // Only the employee can reject
    if confirmation.employee != *employee {
        return Err(DestinationConfirmationError::Unauthorized);
    }

    if confirmation.status == ConfirmationStatus::Confirmed {
        return Err(DestinationConfirmationError::AlreadyConfirmed);
    }

    confirmation.status = ConfirmationStatus::Rejected;

    Ok(())
}

/// Check if a confirmation has expired.
pub fn is_confirmation_expired(env: &Env, confirmation: &DestinationConfirmation) -> bool {
    env.ledger().timestamp() > confirmation.expires_at
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{Env, String};

    #[test]
    fn test_request_confirmation() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let employee = Address::generate(&env);
        let destination = Address::generate(&env);

        let result = request_destination_confirmation(&env, &employee, &destination, 0);
        assert!(result.is_ok());

        let confirmation = result.unwrap();
        assert_eq!(confirmation.employee, employee);
        assert_eq!(confirmation.destination, destination);
        assert_eq!(confirmation.status, ConfirmationStatus::Pending);
    }

    #[test]
    fn test_confirm_destination() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let employee = Address::generate(&env);
        let destination = Address::generate(&env);

        let mut confirmation =
            request_destination_confirmation(&env, &employee, &destination, 0).unwrap();

        let result = confirm_destination(&env, &mut confirmation, &employee);
        assert!(result.is_ok());
        assert_eq!(confirmation.status, ConfirmationStatus::Confirmed);
    }

    #[test]
    fn test_confirm_unauthorized() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let employee = Address::generate(&env);
        let other = Address::generate(&env);
        let destination = Address::generate(&env);

        let mut confirmation =
            request_destination_confirmation(&env, &employee, &destination, 0).unwrap();

        let result = confirm_destination(&env, &mut confirmation, &other);
        assert_eq!(result, Err(DestinationConfirmationError::Unauthorized));
    }

    #[test]
    fn test_confirm_expired() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let employee = Address::generate(&env);
        let destination = Address::generate(&env);

        let mut confirmation =
            request_destination_confirmation(&env, &employee, &destination, 100).unwrap();

        // Advance time past expiry
        env.ledger().with_mut(|li| li.timestamp = 2000);

        let result = confirm_destination(&env, &mut confirmation, &employee);
        assert_eq!(result, Err(DestinationConfirmationError::ConfirmationExpired));
    }

    #[test]
    fn test_is_destination_confirmed() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 1000);

        let employee = Address::generate(&env);
        let destination = Address::generate(&env);

        let mut confirmation =
            request_destination_confirmation(&env, &employee, &destination, 0).unwrap();

        // Not confirmed yet
        assert!(!is_destination_confirmed(&env, &confirmation));

        // Confirm
        confirm_destination(&env, &mut confirmation, &employee).unwrap();
        assert!(is_destination_confirmed(&env, &confirmation));
    }
}
