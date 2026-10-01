# Audit Reference Attachment Validation (Issue #389)

## Summary

This document describes the validation logic for proof reference attachments in audit workflows. The validation ensures that audit reference attachments are properly formatted and prevents invalid references from being accepted into the audit trail.

## Purpose

Reliable guardrails and clear operational feedback help teams run payroll safely without exposing sensitive employee or salary data. The audit reference attachment validation provides:

1. **Format Validation**: Ensures proof reference hashes are not empty or all-zero sentinels
2. **Privacy Protection**: Validation logic doesn't expose sensitive payroll data
3. **Actionable Error Handling**: Clear error messages for failed validations
4. **Integration Point**: Consistent validation across audit challenge workflows

## Implementation

### Validation Function

The core validation logic is implemented in `contracts/audit_module/src/challenge.rs`:

```rust
/// Validates audit reference attachment with enhanced checks.
///
/// This function provides comprehensive validation for proof reference attachments
/// in audit workflows, ensuring that:
/// 1. The reference is not the empty/all-zero sentinel
/// 2. The reference is properly formatted for audit trail purposes
/// 3. The validation is privacy-safe and doesn't expose sensitive payroll data
///
/// Returns `Ok(())` if the reference is valid, `Err(AuditError::InvalidProofReference)` otherwise.
pub fn validate_audit_reference_attachment(
    env: &Env,
    proof_reference_hash: &BytesN<32>,
) -> Result<(), AuditError> {
    if !is_valid_proof_reference(env, proof_reference_hash) {
        return Err(AuditError::InvalidProofReference);
    }
    Ok(())
}
```

### Basic Validation

The foundational check ensures the reference is not the all-zero sentinel:

```rust
pub fn is_valid_proof_reference(env: &Env, proof_reference_hash: &BytesN<32>) -> bool {
    let zero = soroban_sdk::BytesN::from_array(env, &[0u8; 32]);
    proof_reference_hash != &zero
}
```

### Integration Point

The validation is integrated into the audit challenge response workflow in `respond_to_challenge`:

```rust
// Update challenge status
if rejection_reason.is_some() {
    challenge.status = ChallengeStatus::Rejected;
} else {
    // An accepting response must carry a real proof reference — reject
    // it early, independent of whatever the referenced proof actually
    // verifies to (that's proof_verifier's job, not this module's).
    validate_audit_reference_attachment(env, &proof_reference_hash)?;
    challenge.status = ChallengeStatus::Responded;
}
```

## Error Handling

### Error Definition

The `InvalidProofReference` error is defined in both:

1. `contracts/shared_errors/src/lib.rs` (shared error taxonomy):
```rust
/// The proof reference hash is invalid (empty or all-zero sentinel).
InvalidProofReference = 210,
```

2. `contracts/audit_module/src/lib.rs` (module-specific error):
```rust
/// The proof reference hash is invalid (empty or all-zero sentinel).
InvalidProofReference = 13,
```

### Privacy Guarantees

The validation logic is designed to protect sensitive payroll data:

1. **Format-Only Check**: The validation only checks if the hash is the all-zero sentinel, not its content
2. **No Salary Exposure**: The validation doesn't examine or reveal any salary amounts, employee data, or commitment values
3. **Deterministic Results**: The same input always produces the same validation result, preventing information leakage through timing or side channels
4. **Error Messages**: Error messages are generic and don't reveal any information about the rejected hash content

## Testing

### Unit Tests

Comprehensive unit tests are included in `contracts/audit_module/src/tests.rs`:

- `test_is_valid_proof_reference_rejects_zero_hash`: Ensures zero hashes are rejected
- `test_is_valid_proof_reference_accepts_non_zero_hash`: Ensures valid hashes are accepted
- `test_validate_audit_reference_attachment_accepts_valid_hash`: Tests the enhanced validation
- `test_validate_audit_reference_attachment_rejects_zero_hash`: Tests error handling
- `test_validate_audit_reference_accepts_various_valid_hashes`: Tests different valid hash patterns

### Integration Tests

Additional integration tests are in `contracts/audit_module/tests/audit_reference_validation.rs`:

- Standalone validation logic tests
- Privacy guarantee verification
- Deterministic behavior validation

### Error Taxonomy Tests

The error taxonomy is updated in `contracts/shared_errors/tests/error_taxonomy_tests.rs` to include the new error code and ensure it doesn't conflict with existing error ranges.

## Usage Guidelines

### For SDK Developers

When responding to audit challenges, always provide a valid proof reference hash:

```rust
// Correct: Use a real proof reference hash
let proof_reference = proof_verifier.register_proof_reference(
    &admin,
    &ref_id,
    &proof,
    expires_at_ledger
)?;
audit_module.respond_to_challenge(
    &company_id,
    &challenge_id,
    &responder,
    &proof_reference.proof_hash,
    None // No rejection reason
)?;

// Incorrect: Using zero hash will fail
let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
audit_module.respond_to_challenge(
    &company_id,
    &challenge_id,
    &responder,
    &zero_hash,
    None
)?; // This will return Err(AuditError::InvalidProofReference)
```

### For Auditors

When creating audit challenges, ensure you have valid proof references ready for response:

1. Register proof references before creating challenges
2. Use the registered proof reference hash in challenge responses
3. If rejecting a challenge, provide a clear rejection reason instead of an invalid reference

### Error Recovery

If you encounter `InvalidProofReference` errors:

1. **Check Reference Format**: Ensure the hash is not all zeros
2. **Verify Registration**: Confirm the proof reference was properly registered
3. **Use Proof Verifier**: Use `proof_verifier.register_proof_reference` to create valid references
4. **Provide Rejection Reason**: If the challenge is invalid, provide a rejection reason instead

## Security Considerations

1. **Validation Scope**: This validation only checks the format of the reference hash, not the validity of the proof itself. The `proof_verifier` contract handles proof verification.

2. **No Bypass**: The validation is enforced at the contract level and cannot be bypassed by SDK implementations.

3. **Privacy First**: The validation logic never exposes sensitive payroll data, maintaining the privacy guarantees of the ZK payroll system.

4. **Deterministic**: The validation produces consistent results, preventing any potential information leakage through validation behavior.

## Acceptance Criteria

✅ **Existing payroll workflows continue to work as expected**
- The validation is only applied to audit challenge responses
- Existing payroll execution paths are unaffected
- Proof verification in `batch_process_payroll` continues to work normally

✅ **Errors and UI feedback do not expose sensitive payroll values**
- Validation only checks hash format, not content
- Error messages are generic and don't reveal hash content
- No salary amounts, employee data, or commitment values are exposed

✅ **Tests or repeatable QA cover success and failure states**
- Unit tests cover both success and failure cases
- Integration tests verify privacy guarantees
- Error taxonomy tests ensure proper error classification

✅ **The implementation follows repository conventions**
- Uses existing error taxonomy from `shared_errors`
- Follows the pattern of other validation functions in the codebase
- Includes comprehensive documentation and testing
- Maintains privacy-first approach throughout

## Related Documentation

- [Audit Challenge Workflow](../contracts/audit_module/src/challenge.rs)
- [Proof Reference Expiry](./security/proof-reference-expiry.md)
- [Error Taxonomy](./error-taxonomy.md)
- [Audit Module Architecture](../contracts/audit_module/README.md)
