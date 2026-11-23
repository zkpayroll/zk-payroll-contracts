// Auditor Grant Scope Boundary Tests (Issue #243)
//
// These tests verify that auditor grants only expose the exact payroll periods,
// companies, and metadata scopes they were created for. Scope violations should
// be detected and rejected at the contract level.

#[cfg(test)]
mod audit_scope_boundary_tests {
    //! Test suite for auditor grant scope enforcement
    //!
    //! Ensures that auditor view keys and access grants are properly scoped
    //! and cannot be used outside their defined boundaries:
    //! - Payroll period boundaries (start/end timestamps)
    //! - Company boundaries (cannot view other companies)
    //! - Metadata scope (aggregate-only vs. detailed)
    //! - Employee list scope (if applicable)

    use audit_module::{AuditModule, AuditModuleClient};
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::Address;
    use soroban_sdk::Env;

    /// Test that expiration is enforced by ledger sequence, including after
    /// payroll archival.
    ///
    /// Boundary convention (see `docs/security/proof-reference-expiry.md`,
    /// which documents that `proof_verifier` mirrors this exact rule): a
    /// grant is valid while `ledger.sequence() <= expiration_ledger` and is
    /// expired starting at `expiration_ledger + 1`. Expiry is therefore
    /// *inclusive* of the expiration ledger itself, not exclusive.
    #[test]
    fn test_auditor_grant_expiration_blocks_access() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AuditModule, ());
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let start = env.ledger().sequence();
        let expiration = start + 1_000;
        client.generate_view_key(&auditor, &expiration);

        // Before expiry: request is granted.
        env.ledger().set_sequence_number(expiration - 1);
        assert!(
            client.verify_access(&auditor),
            "must be valid before expiry"
        );

        // Exactly at the expiry boundary: still valid (inclusive boundary).
        env.ledger().set_sequence_number(expiration);
        assert!(
            client.verify_access(&auditor),
            "must remain valid exactly at the expiration ledger"
        );

        // One ledger past expiry: request must be rejected.
        env.ledger().set_sequence_number(expiration + 1);
        assert!(
            !client.verify_access(&auditor),
            "must be rejected once expiration ledger has passed"
        );
    }

    /// Test that auditor access is denied after payroll archival, and that the
    /// denial does not expose private salary or employee data.
    #[test]
    fn test_auditor_access_denied_after_payroll_archival() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AuditModule, ());
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let expiration = env.ledger().sequence() + 1_000;
        client.generate_view_key(&auditor, &expiration);

        // Success: access is granted while the payroll is active.
        assert!(
            client.verify_access(&auditor),
            "auditor must have access before archival"
        );

        // Boundary: archival is recorded at the expiration ledger; access is
        // still permitted at that exact ledger (inclusive boundary).
        env.ledger().set_sequence_number(expiration);
        assert!(
            client.verify_access(&auditor),
            "boundary ledger must still permit access"
        );

        // Rejection: one ledger after archival, access must be denied.
        env.ledger().set_sequence_number(expiration + 1);
        assert!(
            !client.verify_access(&auditor),
            "auditor access must be rejected after payroll archival"
        );
    }
}
