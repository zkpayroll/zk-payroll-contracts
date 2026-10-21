//! Bulk employee edit concurrency controls (Issue #655).
//!
//! Enables editing multiple employee records in a single operation while
//! ensuring version consistency across all records. If any employee's version
//! has changed since the edit was initiated, the entire operation is rejected
//! to prevent lost updates.
//!
//! # Privacy design
//! - Only employee identifiers (u64 IDs) and version numbers are checked.
//! - Salary commitments, blinding factors, and per-employee data are NOT
//!   exposed in error messages or return values.
//! - The operation is atomic: either all updates succeed or none do.

use crate::employee_record_version::EmployeeRecord;
use soroban_sdk::{contracttype, BytesN, String};

/// Represents a single employee update in a bulk edit operation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct BulkEmployeeEdit {
    /// Employee ID (unique per employer)
    pub employee_id: u64,
    /// Expected version before the edit (for conflict detection)
    pub expected_version: u64,
    /// New salary commitment (hash of off-chain salary data)
    pub new_salary_commitment: BytesN<32>,
    /// New suspension status
    pub new_is_suspended: bool,
}

/// Error returned when a version conflict is detected during a bulk edit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkEditError {
    /// At least one employee's version has changed since the edit was initiated.
    /// The caller should re-read the current versions and retry.
    VersionConflict {
        /// The employee ID that had a version mismatch.
        employee_id: u64,
        /// The current version of the employee record.
        current_version: u64,
        /// The expected version the caller had.
        expected_version: u64,
    },
    /// One or more employee IDs were not found in the system.
    EmployeeNotFound {
        /// The employee ID that was not found.
        employee_id: u64,
    },
    /// The bulk edit operation would exceed safe limits.
    /// (e.g., too many employees, invalid data, etc.)
    InvalidOperation {
        /// Description of what went wrong.
        reason: String,
    },
}

/// Result of a bulk employee edit operation.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkEditResult {
    /// Number of employee records successfully updated.
    pub updated_count: u32,
    /// Whether the operation was fully successful (all records) or partially failed.
    pub fully_successful: bool,
}

/// Checks for version conflicts across a batch of employee edits.
/// #
/// # Arguments
/// - `current_versions`: `(employee_id, current_version)` pairs from storage
/// - `edits`: The batch of edits to validate
///
/// # Returns
/// - `Ok(())` if no conflicts detected
/// - `Err(BulkEditError::VersionConflict)` if any employee version mismatch
pub fn check_bulk_edit_conflicts(
    current_versions: &[(u64, u64)],
    edits: &[BulkEmployeeEdit],
) -> Result<(), BulkEditError> {
    for edit in edits {
        let current_version = match current_versions
            .iter()
            .find(|(id, _)| *id == edit.employee_id)
        {
            Some(&(_, v)) => v,
            None => {
                return Err(BulkEditError::EmployeeNotFound {
                    employee_id: edit.employee_id,
                })
            }
        };

        if current_version != edit.expected_version {
            return Err(BulkEditError::VersionConflict {
                employee_id: edit.employee_id,
                current_version,
                expected_version: edit.expected_version,
            });
        }
    }
    Ok(())
}

/// Increments the version for each successfully updated employee record.
/// #
/// # Arguments
/// - `records`: A mutable slice of EmployeeRecord objects to update
///
/// # Returns
/// - A `BulkEditResult` indicating how many records were updated
pub fn increment_bulk_employee_versions(records: &mut [EmployeeRecord]) -> BulkEditResult {
    let mut updated_count = 0u32;

    for record in records.iter_mut() {
        record.version = record.version.saturating_add(1);
        updated_count += 1;
    }

    BulkEditResult {
        updated_count,
        fully_successful: updated_count == records.len() as u32 && !records.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn edit(env: &Env, employee_id: u64, expected_version: u64, marker: u8) -> BulkEmployeeEdit {
        BulkEmployeeEdit {
            employee_id,
            expected_version,
            new_salary_commitment: BytesN::from_array(env, &[marker; 32]),
            new_is_suspended: marker != 0,
        }
    }

    fn record(env: &Env, employee_id: u64, version: u64, marker: u8) -> EmployeeRecord {
        EmployeeRecord {
            employee_id,
            version,
            salary_commitment: BytesN::from_array(env, &[marker; 32]),
            is_suspended: marker != 0,
            updated_at: 0,
        }
    }

    #[test]
    fn test_bulk_edit_no_conflict() {
        let env = Env::default();
        let current_versions = [(1, 5), (2, 3)];
        let edits = [edit(&env, 1, 5, 0), edit(&env, 2, 3, 1)];

        assert!(check_bulk_edit_conflicts(&current_versions, &edits).is_ok());
    }

    #[test]
    fn test_bulk_edit_version_conflict() {
        let env = Env::default();
        let current_versions = [(1, 6)]; // version changed to 6
        let edits = [edit(&env, 1, 5, 0)]; // caller had old version 5

        let result = check_bulk_edit_conflicts(&current_versions, &edits);
        assert_eq!(
            result,
            Err(BulkEditError::VersionConflict {
                employee_id: 1,
                current_version: 6,
                expected_version: 5
            })
        );
    }

    #[test]
    fn test_bulk_edit_employee_not_found() {
        let env = Env::default();
        let edits = [edit(&env, 999, 1, 0)];

        let result = check_bulk_edit_conflicts(&[], &edits);
        assert_eq!(
            result,
            Err(BulkEditError::EmployeeNotFound { employee_id: 999 })
        );
    }

    #[test]
    fn test_increment_bulk_employee_versions() {
        let env = Env::default();
        let mut records = [record(&env, 1, 5, 0), record(&env, 2, 3, 1)];

        let result = increment_bulk_employee_versions(&mut records);

        assert_eq!(result.updated_count, 2);
        assert!(result.fully_successful);
        assert_eq!(records[0].version, 6);
        assert_eq!(records[1].version, 4);
    }

    #[test]
    fn test_increment_bulk_employee_versions_empty() {
        let mut records: [EmployeeRecord; 0] = [];

        let result = increment_bulk_employee_versions(&mut records);

        assert_eq!(result.updated_count, 0);
        assert!(!result.fully_successful);
    }
}
