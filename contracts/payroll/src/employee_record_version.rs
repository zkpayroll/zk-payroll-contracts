use soroban_sdk::{contracttype, BytesN};
use shared_errors::StorageError;

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmployeeRecord {
    pub employee_id: u64,
    pub version: u64,
    pub salary_commitment: BytesN<32>,
    pub is_suspended: bool,
    pub updated_at: u64,
}

/// Detects version conflict when updating employee record (#569).
pub fn detect_version_conflict(
    current_version: u64,
    expected_version: u64,
) -> Result<(), StorageError> {
    if current_version != expected_version {
        return Err(StorageError::StorageVersionMismatch);
    }
    Ok(())
}

/// Increments record version on successful update.
pub fn increment_employee_version(record: &mut EmployeeRecord) -> u64 {
    record.version = record.version.saturating_add(1);
    record.version
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_match() {
        assert!(detect_version_conflict(5, 5).is_ok());
    }

    #[test]
    fn test_version_conflict() {
        assert_eq!(
            detect_version_conflict(5, 4),
            Err(StorageError::StorageVersionMismatch)
        );
    }
}
