//! # Audit Grant Revocation Tests (issue #284)
//!
//! Top-level, black-box coverage for `audit_module`'s view-key revocation
//! flow: `revoke_view_key` must be effective immediately across every
//! restricted entrypoint, and the main success/failure/edge-case behaviors
//! must be locked in as regression tests.
//!
//! This complements the per-entrypoint revocation tests already in
//! `contracts/audit_module/src/tests.rs` (issue #172) with a single
//! consolidated "revocation blocks everything, immediately" acceptance test
//! plus edge cases that weren't previously covered: double revocation,
//! revoking a grant that was never issued, and revoking an already-expired
//! (but not yet cleaned up) grant.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p audit_revocation_tests
//! ```

#[cfg(test)]
mod tests {
    use audit_module::{AuditError, AuditModule, AuditModuleClient, AuditScope};
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{Address, BytesN, Env};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AuditModule);
        (env, contract_id)
    }

    fn commitment(env: &Env, amount: i128, blinding: &BytesN<32>) -> BytesN<32> {
        let mut preimage = soroban_sdk::Bytes::new(env);
        preimage.extend_from_array(&amount.to_le_bytes());
        let blinding_slice: [u8; 32] = blinding.into();
        preimage.extend_from_array(&blinding_slice);
        env.crypto().sha256(&preimage).into()
    }

    // ── Success path ───────────────────────────────────────────────────────────

    /// Main expected path: a live grant lets an auditor verify a commitment;
    /// after revocation the exact same call is rejected.
    #[test]
    fn test_revoke_success_path_blocks_subsequent_verification() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let amount: i128 = 250_000;
        let blinding = BytesN::from_array(&env, &[0x40; 32]);
        let stored = commitment(&env, amount, &blinding);

        assert!(client.verify_commitment_with_key(
            &auditor,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList
        ));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor);

        let blocked = client.try_verify_commitment_with_key(
            &auditor,
            &stored,
            &amount,
            &blinding,
            &AuditScope::EmployeeList,
        );
        assert_eq!(blocked.unwrap_err().unwrap(), AuditError::KeyNotFound);
    }

    /// Consolidated acceptance check: once revoked, every restricted
    /// entrypoint rejects the former auditor in the same call, not just one
    /// of them — revocation must be a single, complete cutoff.
    #[test]
    fn test_revoke_blocks_every_restricted_entrypoint_immediately() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        let key = client.generate_view_key(&auditor, &(seq + 1_000));

        let amount: i128 = 60_000;
        let blinding = BytesN::from_array(&env, &[0x41; 32]);
        let stored = commitment(&env, amount, &blinding);
        let company_id = soroban_sdk::Symbol::new(&env, "ACME");
        let now = env.ledger().timestamp();

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor);

        assert!(
            !client.verify_access(&auditor),
            "verify_access must report false"
        );
        assert_eq!(
            client.try_get_view_key(&auditor).unwrap_err().unwrap(),
            AuditError::KeyNotFound
        );
        assert_eq!(
            client
                .try_verify_commitment_with_key(
                    &auditor,
                    &stored,
                    &amount,
                    &blinding,
                    &AuditScope::EmployeeList
                )
                .unwrap_err()
                .unwrap(),
            AuditError::KeyNotFound
        );
        assert_eq!(
            client
                .try_verify_commitment_with_view_key(
                    &auditor,
                    &key,
                    &stored,
                    &amount,
                    &blinding,
                    &AuditScope::EmployeeList
                )
                .unwrap_err()
                .unwrap(),
            AuditError::KeyNotFound
        );
        assert_eq!(
            client
                .try_generate_aggregate_report(&auditor, &company_id, &now, &(now + 86_400))
                .unwrap_err()
                .unwrap(),
            AuditError::KeyNotFound
        );
        assert_eq!(
            client
                .try_export_audit_summary(&auditor, &company_id, &0u64, &(now + 1_000))
                .unwrap_err()
                .unwrap(),
            AuditError::KeyNotFound
        );
        let hash = BytesN::from_array(&env, &[0x42; 32]);
        assert_eq!(
            client
                .try_verify_payroll_metadata(&auditor, &hash, &hash, &AuditScope::FullCompany)
                .unwrap_err()
                .unwrap(),
            AuditError::KeyNotFound
        );
    }

    // ── Failure path ───────────────────────────────────────────────────────────

    /// A caller who did not grant the key cannot revoke it — the grant must
    /// survive an unauthorized revocation attempt untouched.
    #[test]
    fn test_revoke_failure_wrong_granter_leaves_grant_intact() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let interloper = Address::generate(&env);
        let result = client.try_revoke_view_key(&interloper, &auditor);
        assert_eq!(result.unwrap_err().unwrap(), AuditError::NotKeyGranter);

        // The grant is untouched: the auditor still has live access.
        assert!(client.verify_access(&auditor));
        assert!(client.try_get_view_key(&auditor).is_ok());
    }

    // ── Edge cases ─────────────────────────────────────────────────────────────

    /// Revoking a grant that was never issued must fail cleanly with
    /// `KeyNotFound`, the same as revoking any other unknown auditor.
    #[test]
    fn test_revoke_edge_case_never_granted_returns_key_not_found() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let never_granted = Address::generate(&env);
        let admin = contract_id.clone();
        let result = client.try_revoke_view_key(&admin, &never_granted);
        assert_eq!(result.unwrap_err().unwrap(), AuditError::KeyNotFound);
    }

    /// Revoking an already-revoked grant must fail with `KeyNotFound` rather
    /// than silently succeeding a second time — revocation is not idempotent
    /// storage cleanup, it's a one-time state transition.
    #[test]
    fn test_revoke_edge_case_double_revoke_fails_second_time() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor);

        let second = client.try_revoke_view_key(&admin, &auditor);
        assert_eq!(second.unwrap_err().unwrap(), AuditError::KeyNotFound);
    }

    /// A grant that has already expired (but was never explicitly revoked)
    /// can still be revoked for cleanup/audit-trail purposes — expiration
    /// and revocation are independent lifecycle events.
    #[test]
    fn test_revoke_edge_case_already_expired_grant_still_revocable() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        let expiration = seq + 10;
        client.generate_view_key(&auditor, &expiration);

        env.ledger().set_sequence_number(expiration + 1);
        assert!(
            !client.verify_access(&auditor),
            "key should read as expired"
        );

        let admin = contract_id.clone();
        let result = client.try_revoke_view_key(&admin, &auditor);
        assert!(
            result.is_ok(),
            "an expired-but-not-yet-cleaned-up grant must still be revocable"
        );

        // And now it is gone entirely, not just expired.
        assert_eq!(
            client.try_get_view_key(&auditor).unwrap_err().unwrap(),
            AuditError::KeyNotFound
        );
    }

    /// Revocation must be scoped to exactly the targeted auditor — an
    /// unrelated auditor's live grant and restricted access must be
    /// completely unaffected.
    #[test]
    fn test_revoke_edge_case_does_not_affect_other_auditors() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let revoked = Address::generate(&env);
        let unaffected = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&revoked, &(seq + 1_000));
        client.generate_view_key(&unaffected, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &revoked);

        assert!(!client.verify_access(&revoked));
        assert!(client.verify_access(&unaffected));

        let company_id = soroban_sdk::Symbol::new(&env, "ACME");
        let now = env.ledger().timestamp();
        assert!(client
            .try_generate_aggregate_report(&unaffected, &company_id, &now, &(now + 86_400))
            .is_ok());
    }
}
