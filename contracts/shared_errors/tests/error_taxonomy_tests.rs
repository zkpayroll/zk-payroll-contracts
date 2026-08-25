// Error Taxonomy Tests
//
// This module validates that all error codes are unique, stable, and correctly
// categorized by verifying:
// 1. No duplicate error codes exist across categories
// 2. Error codes remain stable across contract versions
// 3. Error category ranges do not overlap
// 4. All documented errors have corresponding code definitions

#[cfg(test)]
mod error_taxonomy_tests {
    use shared_errors::*;

    /// Test that all error codes are unique within their ranges
    #[test]
    fn test_error_codes_unique_within_categories() {
        // Authorization (1-99)
        assert_eq!(AuthError::UnauthorizedAdmin as u32, 1);
        assert_eq!(AuthError::UnauthorizedTreasuryOwner as u32, 2);
        assert_eq!(AuthError::UnauthorizedAuditor as u32, 3);
        assert_eq!(AuthError::UnauthorizedRotationTarget as u32, 4);
        assert_eq!(AuthError::UnauthorizedReviewer as u32, 5);
        assert_eq!(AuthError::AuthorizationFailed as u32, 6);
        assert_eq!(AuthError::UnauthorizedHandoverTarget as u32, 7);

        // Proof Verification (100-199)
        assert_eq!(ProofError::InvalidProofFormat as u32, 100);
        assert_eq!(ProofError::ProofVerificationFailed as u32, 101);
        assert_eq!(ProofError::CommitmentMismatch as u32, 102);
        assert_eq!(ProofError::ProofExpired as u32, 103);
        assert_eq!(ProofError::InvalidPublicInputs as u32, 104);
        assert_eq!(ProofError::VerifyingKeyMismatch as u32, 105);
        assert_eq!(ProofError::InvalidNullifier as u32, 106);

        // Audit (200-299)
        assert_eq!(AuditError::ViewKeyNotFound as u32, 200);
        assert_eq!(AuditError::InvalidViewKey as u32, 201);
        assert_eq!(AuditError::ViewKeyExpired as u32, 202);
        assert_eq!(AuditError::InsufficientAuditScope as u32, 203);
        assert_eq!(AuditError::UnauthorizedChallengeParticipant as u32, 204);
        assert_eq!(AuditError::ChallengeNotFound as u32, 205);
        assert_eq!(AuditError::ChallengeExpired as u32, 206);
        assert_eq!(AuditError::ChallengeAlreadyResolved as u32, 207);
        assert_eq!(AuditError::InvalidChallenge as u32, 208);
        assert_eq!(AuditError::InvalidResponseTimestamp as u32, 209);

        // Payment (300-399)
        assert_eq!(PaymentError::PeriodNotFound as u32, 300);
        assert_eq!(PaymentError::PeriodClosed as u32, 301);
        assert_eq!(PaymentError::PeriodAlreadyExists as u32, 302);
        assert_eq!(PaymentError::EmployeeAlreadyPaid as u32, 303);
        assert_eq!(PaymentError::InvalidPaymentAmount as u32, 304);
        assert_eq!(PaymentError::EmployeeNotFound as u32, 305);
        assert_eq!(PaymentError::CompanyNotFound as u32, 306);
        assert_eq!(PaymentError::CommitmentLocked as u32, 307);
        assert_eq!(PaymentError::EmptyBatch as u32, 308);
        assert_eq!(PaymentError::ArrayLengthMismatch as u32, 309);

        // Treasury (400-499)
        assert_eq!(TreasuryError::InsufficientTreasuryBalance as u32, 400);
        assert_eq!(TreasuryError::AssetNotAllowed as u32, 401);
        assert_eq!(TreasuryError::WithdrawalRequestPending as u32, 402);
        assert_eq!(TreasuryError::WithdrawalRequestNotFound as u32, 403);
        assert_eq!(TreasuryError::TreasuryLocked as u32, 404);
        assert_eq!(TreasuryError::InsufficientUnreservedBalance as u32, 405);
        assert_eq!(TreasuryError::InvalidAssetConfiguration as u32, 406);

        // State (500-599)
        assert_eq!(StateError::PayrollRunNotFound as u32, 500);
        assert_eq!(StateError::PendingRunNotFound as u32, 501);
        assert_eq!(StateError::DraftNotFound as u32, 502);
        assert_eq!(StateError::InvalidPayrollState as u32, 503);
        assert_eq!(StateError::DraftLocked as u32, 504);
        assert_eq!(StateError::InvalidCompanyState as u32, 505);
        assert_eq!(StateError::InvalidEmployeeStatus as u32, 506);
        assert_eq!(StateError::EmployeeIneligible as u32, 507);
        assert_eq!(StateError::ComplianceHoldActive as u32, 508);

        // Replay (600-699)
        assert_eq!(ReplayError::NonceAlreadyUsed as u32, 600);
        assert_eq!(ReplayError::PayrollAlreadyExecuted as u32, 601);
        assert_eq!(ReplayError::NullifierAlreadyUsed as u32, 602);
        assert_eq!(ReplayError::ConflictingPayloadData as u32, 603);
        assert_eq!(ReplayError::ExecutionIdentityMismatch as u32, 604);
        assert_eq!(ReplayError::AuthorizationExpired as u32, 605);
        assert_eq!(ReplayError::InvalidPayloadContext as u32, 606);

        // Storage (700-799)
        assert_eq!(StorageError::NotInitialized as u32, 700);
        assert_eq!(StorageError::AlreadyInitialized as u32, 701);
        assert_eq!(StorageError::StorageVersionMismatch as u32, 702);
        assert_eq!(StorageError::StorageCorruption as u32, 703);
        assert_eq!(StorageError::MigrationFailed as u32, 704);
    }

    /// Test that error category ranges do not overlap
    #[test]
    fn test_error_category_ranges_non_overlapping() {
        // Authorization: 1-99
        let auth_error = AuthError::AuthorizationFailed;
        assert!(auth_error as u32 < 100);

        // Proof: 100-199
        let proof_error = ProofError::InvalidNullifier;
        assert!(proof_error as u32 >= 100 && proof_error as u32 < 200);

        // Audit: 200-299
        let audit_error = AuditError::InvalidResponseTimestamp;
        assert!(audit_error as u32 >= 200 && audit_error as u32 < 300);

        // Payment: 300-399
        let payment_error = PaymentError::ArrayLengthMismatch;
        assert!(payment_error as u32 >= 300 && payment_error as u32 < 400);

        // Treasury: 400-499
        let treasury_error = TreasuryError::InvalidAssetConfiguration;
        assert!(treasury_error as u32 >= 400 && treasury_error as u32 < 500);

        // State: 500-599
        let state_error = StateError::ComplianceHoldActive;
        assert!(state_error as u32 >= 500 && state_error as u32 < 600);

        // Replay: 600-699
        let replay_error = ReplayError::InvalidPayloadContext;
        assert!(replay_error as u32 >= 600 && replay_error as u32 < 700);

        // Storage: 700-799
        let storage_error = StorageError::MigrationFailed;
        assert!(storage_error as u32 >= 700 && storage_error as u32 < 800);
    }

    /// Test that all error enums support the code() conversion method
    #[test]
    fn test_error_code_conversion_methods() {
        let auth_code = AuthError::UnauthorizedAdmin.code();
        assert_eq!(auth_code, 1u32);

        let proof_code = ProofError::InvalidProofFormat.code();
        assert_eq!(proof_code, 100u32);

        let audit_code = AuditError::ViewKeyNotFound.code();
        assert_eq!(audit_code, 200u32);

        let payment_code = PaymentError::PeriodNotFound.code();
        assert_eq!(payment_code, 300u32);

        let treasury_code = TreasuryError::InsufficientTreasuryBalance.code();
        assert_eq!(treasury_code, 400u32);

        let state_code = StateError::PayrollRunNotFound.code();
        assert_eq!(state_code, 500u32);

        let replay_code = ReplayError::NonceAlreadyUsed.code();
        assert_eq!(replay_code, 600u32);

        let storage_code = StorageError::NotInitialized.code();
        assert_eq!(storage_code, 700u32);
    }

    /// Test that specific important error cases are stable
    ///
    /// This test locks in the most critical error codes that SDKs rely on.
    /// If you need to change one of these, coordinate with SDK maintainers.
    #[test]
    fn test_critical_error_stability() {
        // Proof replay prevention
        assert_eq!(ReplayError::NonceAlreadyUsed as u32, 600);
        assert_eq!(ReplayError::PayrollAlreadyExecuted as u32, 601);
        assert_eq!(ReplayError::NullifierAlreadyUsed as u32, 602);

        // Authorization failures
        assert_eq!(AuthError::UnauthorizedAdmin as u32, 1);
        assert_eq!(AuthError::AuthorizationFailed as u32, 6);

        // Audit and compliance
        assert_eq!(AuditError::ViewKeyExpired as u32, 202);
        assert_eq!(AuditError::InsufficientAuditScope as u32, 203);

        // Payment state
        assert_eq!(PaymentError::PeriodNotFound as u32, 300);
        assert_eq!(PaymentError::EmployeeAlreadyPaid as u32, 303);

        // Treasury funding
        assert_eq!(TreasuryError::InsufficientTreasuryBalance as u32, 400);
        assert_eq!(TreasuryError::AssetNotAllowed as u32, 401);

        // Initialization
        assert_eq!(StorageError::NotInitialized as u32, 700);
        assert_eq!(StorageError::AlreadyInitialized as u32, 701);
    }

    /// Test error cloning and comparison
    ///
    /// Ensures errors can be matched and compared in pattern matching code.
    #[test]
    fn test_error_cloning_and_comparison() {
        let err1 = AuthError::UnauthorizedAdmin;
        let err1_clone = err1;

        assert_eq!(err1, err1_clone);
        assert_ne!(err1, AuthError::UnauthorizedTreasuryOwner);

        let err2 = ProofError::InvalidProofFormat;
        let err2_clone = err2;

        assert_eq!(err2, err2_clone);
        assert_ne!(err2, ProofError::ProofExpired);
    }
}
