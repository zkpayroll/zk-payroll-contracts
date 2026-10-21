//! Privacy-safe error context filtering for contract error reporting.
//!
//! This module provides types and functions for filtering and redacting
//! error context fields so that error messages surfaced to integrators
//! never expose salary amounts, employee identities, commitment hashes,
//! or other sensitive payroll data.

use soroban_sdk::{contracttype, String, Symbol, Vec, Env};

/// Maximum number of context fields allowed in a single error context.
pub const MAX_ERROR_CONTEXT_FIELDS: u32 = 8;

/// Maximum byte length for a single context field value.
pub const MAX_ERROR_CONTEXT_VALUE_BYTES: u32 = 128;

/// A key-value pair carrying safe, non-sensitive error context.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorContext {
    /// Stable symbolic key for this field.
    pub key: Symbol,
    /// Safe string value (must not contain salary, commitment, or employee data).
    pub value: String,
}

/// An error context payload with a bounded set of fields.
///
/// Privacy note: callers are responsible for ensuring no sensitive data is
/// included. This type enforces only structural bounds (field count, value
/// byte length).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorContextFilter {
    /// Filtered context fields ready for external consumption.
    pub fields: Vec<ErrorContext>,
    /// Number of fields that were redacted due to policy violations.
    pub redacted_count: u32,
}

/// A redacted error context with all potentially sensitive fields removed.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorContextRedaction {
    /// The original field count before redaction.
    pub original_count: u32,
    /// Number of fields that were redacted.
    pub redacted_count: u32,
    /// The filtered, safe fields.
    pub safe_fields: Vec<ErrorContext>,
}

/// Why an error context operation was rejected.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorContextFilterError {
    /// The context has more fields than [`MAX_ERROR_CONTEXT_FIELDS`].
    TooManyFields = 1,
    /// A field value exceeds [`MAX_ERROR_CONTEXT_VALUE_BYTES`].
    ValueTooLong = 2,
}

/// Filter an error context, enforcing structural bounds.
///
/// Returns an `ErrorContextFilter` with only the fields that pass the
/// structural checks. Fields that exceed value length limits are redacted.
pub fn filter_error_context(e: &Env, fields: Vec<ErrorContext>) -> ErrorContextFilter {
    let mut safe = Vec::new(e);
    let mut redacted_count = 0u32;

    let limit = fields.len().min(MAX_ERROR_CONTEXT_FIELDS);
    for i in 0..limit {
        let field = fields.get(i).unwrap();
        if field.value.len() <= MAX_ERROR_CONTEXT_VALUE_BYTES {
            safe.push_back(field);
        } else {
            redacted_count += 1;
        }
    }

    // Count any fields beyond the field limit as redacted too
    if fields.len() > MAX_ERROR_CONTEXT_FIELDS {
        redacted_count += fields.len() - MAX_ERROR_CONTEXT_FIELDS;
    }

    ErrorContextFilter {
        fields: safe,
        redacted_count,
    }
}

/// Redact all fields from an error context, returning only the counts.
///
/// Use this on error paths where even safe-looking context might leak
/// operational details about a failed operation.
pub fn redact_error_context(e: &Env, fields: Vec<ErrorContext>) -> ErrorContextRedaction {
    let original_count = fields.len();
    ErrorContextRedaction {
        original_count,
        redacted_count: original_count,
        safe_fields: Vec::new(e),
    }
}
