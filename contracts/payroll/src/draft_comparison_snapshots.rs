//! Draft payroll comparison snapshots (#710)
//!
//! Captures and compares payroll draft states for change tracking and audit.

#![no_std]

use soroban_sdk::{contracttype, Address, Env, String, Vec};

/// Error codes for draft comparison.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DraftComparisonError {
    /// No snapshot exists for comparison.
    NoSnapshot = 1,
    /// Snapshots are from different drafts.
    DifferentDrafts = 2,
    /// Invalid snapshot reference.
    InvalidSnapshot = 3,
    /// Snapshot limit exceeded.
    SnapshotLimitExceeded = 4,
}

/// Maximum number of snapshots per draft.
pub const MAX_SNAPSHOTS_PER_DRAFT: u32 = 50;

/// A single field change in a comparison.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldChange {
    /// Name of the changed field.
    pub field: String,
    /// Previous value (as string representation).
    pub old_value: String,
    /// New value (as string representation).
    pub new_value: String,
}

/// Result of comparing two snapshots.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparisonResult {
    /// Whether the drafts are identical.
    pub is_identical: bool,
    /// Number of fields that changed.
    pub change_count: u32,
    /// List of field changes.
    pub changes: Vec<FieldChange>,
}

/// A payroll draft snapshot.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftSnapshot {
    /// Unique snapshot identifier.
    pub id: u32,
    /// The draft this snapshot belongs to.
    pub draft_id: u32,
    /// Unix timestamp when the snapshot was taken.
    pub captured_at: u64,
    /// Who captured the snapshot.
    pub captured_by: Address,
    /// Serialized draft state (as key-value pairs).
    pub state_keys: Vec<String>,
    /// Serialized draft values (parallel to state_keys).
    pub state_values: Vec<String>,
    /// Snapshot label/description.
    pub label: String,
}

/// Create a new draft snapshot.
pub fn create_snapshot(
    env: &Env,
    id: u32,
    draft_id: u32,
    captured_by: &Address,
    state_keys: Vec<String>,
    state_values: Vec<String>,
    label: String,
) -> Result<DraftSnapshot, DraftComparisonError> {
    // Validate parallel arrays
    if state_keys.len() != state_values.len() {
        return Err(DraftComparisonError::InvalidSnapshot);
    }

    Ok(DraftSnapshot {
        id,
        draft_id,
        captured_at: env.ledger().timestamp(),
        captured_by: captured_by.clone(),
        state_keys,
        state_values,
        label,
    })
}

/// Compare two snapshots and return the differences.
pub fn compare_snapshots(
    snapshot_a: &DraftSnapshot,
    snapshot_b: &DraftSnapshot,
) -> Result<ComparisonResult, DraftComparisonError> {
    // Verify snapshots are from the same draft
    if snapshot_a.draft_id != snapshot_b.draft_id {
        return Err(DraftComparisonError::DifferentDrafts);
    }

    let env = &snapshot_a.state_keys.env();
    let mut changes: Vec<FieldChange> = Vec::new(env);
    let mut change_count = 0u32;

    // Compare each field in snapshot_a with snapshot_b
    for i in 0..snapshot_a.state_keys.len() {
        let key = snapshot_a.state_keys.get(i).unwrap();
        let old_value = snapshot_a.state_values.get(i).unwrap();

        // Find matching key in snapshot_b
        let mut found = false;
        for j in 0..snapshot_b.state_keys.len() {
            let b_key = snapshot_b.state_keys.get(j).unwrap();
            if b_key == key {
                let new_value = snapshot_b.state_values.get(j).unwrap();
                if old_value != new_value {
                    changes.push_back(FieldChange {
                        field: key.clone(),
                        old_value: old_value.clone(),
                        new_value: new_value.clone(),
                    });
                    change_count += 1;
                }
                found = true;
                break;
            }
        }

        // Field was removed in snapshot_b
        if !found {
            changes.push_back(FieldChange {
                field: key.clone(),
                old_value: old_value.clone(),
                new_value: String::from_str(env, "<removed>"),
            });
            change_count += 1;
        }
    }

    // Check for new fields in snapshot_b
    for j in 0..snapshot_b.state_keys.len() {
        let b_key = snapshot_b.state_keys.get(j).unwrap();
        let mut found = false;
        for i in 0..snapshot_a.state_keys.len() {
            if snapshot_a.state_keys.get(i).unwrap() == b_key {
                found = true;
                break;
            }
        }

        if !found {
            let new_value = snapshot_b.state_values.get(j).unwrap();
            changes.push_back(FieldChange {
                field: b_key.clone(),
                old_value: String::from_str(env, "<added>"),
                new_value: new_value.clone(),
            });
            change_count += 1;
        }
    }

    Ok(ComparisonResult {
        is_identical: change_count == 0,
        change_count,
        changes,
    })
}

/// Get a summary of changes between snapshots.
pub fn get_change_summary(comparison: &ComparisonResult) -> String {
    let env = &comparison.changes.env();
    if comparison.is_identical {
        return String::from_str(env, "No changes detected");
    }

    String::from_str(env, "Changes detected")
}

/// Validate that a snapshot collection doesn't exceed limits.
pub fn validate_snapshot_limit(
    existing_count: u32,
) -> Result<(), DraftComparisonError> {
    if existing_count >= MAX_SNAPSHOTS_PER_DRAFT {
        return Err(DraftComparisonError::SnapshotLimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env, String, Vec};

    fn create_test_snapshot(env: &Env, id: u32, values: &[&str]) -> DraftSnapshot {
        let captured_by = Address::generate(env);
        let mut keys = Vec::new(env);
        let mut vals = Vec::new(env);

        keys.push_back(String::from_str(env, "total_amount"));
        keys.push_back(String::from_str(env, "employee_count"));
        keys.push_back(String::from_str(env, "status"));

        for v in values {
            vals.push_back(String::from_str(env, v));
        }

        create_snapshot(env, id, 1, &captured_by, keys, vals, String::from_str(env, "test")).unwrap()
    }

    #[test]
    fn test_create_snapshot() {
        let env = Env::default();
        let snapshot = create_test_snapshot(&env, 1, &["1000", "5", "draft"]);
        assert_eq!(snapshot.id, 1);
        assert_eq!(snapshot.draft_id, 1);
        assert_eq!(snapshot.state_keys.len(), 3);
    }

    #[test]
    fn test_compare_identical() {
        let env = Env::default();
        let a = create_test_snapshot(&env, 1, &["1000", "5", "draft"]);
        let b = create_test_snapshot(&env, 2, &["1000", "5", "draft"]);

        let result = compare_snapshots(&a, &b).unwrap();
        assert!(result.is_identical);
        assert_eq!(result.change_count, 0);
    }

    #[test]
    fn test_compare_different() {
        let env = Env::default();
        let a = create_test_snapshot(&env, 1, &["1000", "5", "draft"]);
        let b = create_test_snapshot(&env, 2, &["2000", "10", "approved"]);

        let result = compare_snapshots(&a, &b).unwrap();
        assert!(!result.is_identical);
        assert_eq!(result.change_count, 3);
    }

    #[test]
    fn test_compare_different_drafts() {
        let env = Env::default();
        let mut a = create_test_snapshot(&env, 1, &["1000", "5", "draft"]);
        a.draft_id = 1;

        let mut b = create_test_snapshot(&env, 2, &["1000", "5", "draft"]);
        b.draft_id = 2;

        let result = compare_snapshots(&a, &b);
        assert_eq!(result, Err(DraftComparisonError::DifferentDrafts));
    }

    #[test]
    fn test_snapshot_limit() {
        assert!(validate_snapshot_limit(0).is_ok());
        assert!(validate_snapshot_limit(MAX_SNAPSHOTS_PER_DRAFT - 1).is_ok());
        assert_eq!(
            validate_snapshot_limit(MAX_SNAPSHOTS_PER_DRAFT),
            Err(DraftComparisonError::SnapshotLimitExceeded)
        );
    }
}
