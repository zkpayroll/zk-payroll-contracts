//! Payroll approval quorum validation (#697)
//!
//! Enforces threshold and quorum validation for multi-signature payroll run approvals
//! before execution.

#![no_std]

use soroban_sdk::{contracttype, Address, Env, Vec};

/// Error codes for payroll approval quorum validation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ApprovalQuorumError {
    /// Quorum requirement must be greater than zero.
    InvalidQuorumConfig = 1,
    /// Required approvals exceed the total count of eligible approvers.
    QuorumExceedsApprovers = 2,
    /// Approver is not in the authorized approvers roster.
    UnauthorizedApprover = 3,
    /// Approver has already approved this payroll draft/run.
    DuplicateApproval = 4,
    /// The number of approvals collected has not met the required quorum.
    QuorumNotMet = 5,
    /// The approval submission has expired.
    ApprovalExpired = 6,
    /// The approval proposal is already fully finalized/executed.
    AlreadyExecuted = 7,
}

/// Configuration for payroll approval quorum.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayrollQuorumConfig {
    /// Minimum number of distinct approver signatures required (e.g. 2 for 2-of-3)
    pub threshold: u32,
    /// List of addresses authorized to approve payroll runs
    pub approvers: Vec<Address>,
    /// Optional expiration window in seconds from creation (0 = no expiry)
    pub expiration_window_secs: u64,
}

/// Tracks approvals collected for a specific payroll run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayrollApprovalRecord {
    /// Unique identifier of the payroll run / draft
    pub payroll_run_id: u64,
    /// List of approver addresses that have approved so far
    pub confirmed_approvers: Vec<Address>,
    /// Unix timestamp when the approval record was initiated
    pub created_at: u64,
    /// Whether the quorum has been met and execution authorized
    pub is_ready: bool,
    /// Whether execution has completed
    pub executed: bool,
}

/// Validates that a quorum configuration is well-formed.
pub fn validate_quorum_config(config: &PayrollQuorumConfig) -> Result<(), ApprovalQuorumError> {
    if config.threshold == 0 {
        return Err(ApprovalQuorumError::InvalidQuorumConfig);
    }
    if config.threshold > config.approvers.len() {
        return Err(ApprovalQuorumError::QuorumExceedsApprovers);
    }
    Ok(())
}

/// Initializes an approval record for a payroll run.
pub fn initialize_approval_record(
    env: &Env,
    payroll_run_id: u64,
) -> PayrollApprovalRecord {
    PayrollApprovalRecord {
        payroll_run_id,
        confirmed_approvers: Vec::new(env),
        created_at: env.ledger().timestamp(),
        is_ready: false,
        executed: false,
    }
}

/// Adds an approval to the record and validates quorum compliance.
pub fn add_approval(
    env: &Env,
    record: &mut PayrollApprovalRecord,
    config: &PayrollQuorumConfig,
    approver: Address,
) -> Result<bool, ApprovalQuorumError> {
    validate_quorum_config(config)?;

    if record.executed {
        return Err(ApprovalQuorumError::AlreadyExecuted);
    }

    if config.expiration_window_secs > 0 {
        let now = env.ledger().timestamp();
        if now > record.created_at + config.expiration_window_secs {
            return Err(ApprovalQuorumError::ApprovalExpired);
        }
    }

    // Check approver authorization
    let mut is_authorized = false;
    for authorized in config.approvers.iter() {
        if authorized == approver {
            is_authorized = true;
            break;
        }
    }
    if !is_authorized {
        return Err(ApprovalQuorumError::UnauthorizedApprover);
    }

    // Check duplicate
    for existing in record.confirmed_approvers.iter() {
        if existing == approver {
            return Err(ApprovalQuorumError::DuplicateApproval);
        }
    }

    record.confirmed_approvers.push_back(approver);
    record.is_ready = record.confirmed_approvers.len() >= config.threshold;

    Ok(record.is_ready)
}

/// Validates that the approval record currently satisfies the quorum requirements.
pub fn validate_quorum_met(
    record: &PayrollApprovalRecord,
    config: &PayrollQuorumConfig,
) -> Result<(), ApprovalQuorumError> {
    validate_quorum_config(config)?;

    if record.confirmed_approvers.len() < config.threshold {
        return Err(ApprovalQuorumError::QuorumNotMet);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env, Vec,
    };

    #[test]
    fn test_valid_quorum_config_and_progression() {
        let env = Env::default();
        let approver1 = Address::generate(&env);
        let approver2 = Address::generate(&env);
        let approver3 = Address::generate(&env);

        let mut approvers = Vec::new(&env);
        approvers.push_back(approver1.clone());
        approvers.push_back(approver2.clone());
        approvers.push_back(approver3.clone());

        let config = PayrollQuorumConfig {
            threshold: 2,
            approvers,
            expiration_window_secs: 3600,
        };

        assert!(validate_quorum_config(&config).is_ok());

        let mut record = initialize_approval_record(&env, 101);
        assert!(!record.is_ready);

        // First approval
        let is_ready = add_approval(&env, &mut record, &config, approver1.clone()).unwrap();
        assert!(!is_ready);
        assert!(!record.is_ready);
        assert_eq!(validate_quorum_met(&record, &config), Err(ApprovalQuorumError::QuorumNotMet));

        // Second approval satisfies quorum
        let is_ready_now = add_approval(&env, &mut record, &config, approver2.clone()).unwrap();
        assert!(is_ready_now);
        assert!(record.is_ready);
        assert!(validate_quorum_met(&record, &config).is_ok());
    }

    #[test]
    fn test_rejects_unauthorized_and_duplicate_approvals() {
        let env = Env::default();
        let approver1 = Address::generate(&env);
        let stranger = Address::generate(&env);

        let mut approvers = Vec::new(&env);
        approvers.push_back(approver1.clone());

        let config = PayrollQuorumConfig {
            threshold: 1,
            approvers,
            expiration_window_secs: 0,
        };

        let mut record = initialize_approval_record(&env, 102);

        // Stranger fails
        assert_eq!(
            add_approval(&env, &mut record, &config, stranger),
            Err(ApprovalQuorumError::UnauthorizedApprover)
        );

        // Authorized succeeds
        assert!(add_approval(&env, &mut record, &config, approver1.clone()).is_ok());

        // Duplicate fails
        assert_eq!(
            add_approval(&env, &mut record, &config, approver1),
            Err(ApprovalQuorumError::DuplicateApproval)
        );
    }

    #[test]
    fn test_expired_approval_window_fails() {
        let env = Env::default();
        let approver1 = Address::generate(&env);
        let mut approvers = Vec::new(&env);
        approvers.push_back(approver1.clone());

        let config = PayrollQuorumConfig {
            threshold: 1,
            approvers,
            expiration_window_secs: 60,
        };

        let mut record = initialize_approval_record(&env, 103);
        env.ledger().set_timestamp(env.ledger().timestamp() + 100);

        assert_eq!(
            add_approval(&env, &mut record, &config, approver1),
            Err(ApprovalQuorumError::ApprovalExpired)
        );
    }
}
