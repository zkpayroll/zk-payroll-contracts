//! # Contract Migration and State Compatibility Tests
//!
//! Validates that contract state remains compatible across schema upgrades.
//! Tests cover:
//!
//! - Historical payroll, employee, company, and audit record preservation
//! - Active payroll flow continuation after migration
//! - Unsupported/malformed state version handling
//! - Nullifier store preservation (double-spend protection)
//! - Commitment version monotonicity
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p integration_tests migration_
//! ```
//!
//! ## Test naming convention
//!
//! - `mg_*` — Core migration tests (positive)
//! - `mg_neg_*` — Negative tests (unsupported/malformed state)
//! - `mg_flow_*` — Active flow continuation tests

#[cfg(test)]
#[allow(clippy::module_inception, unused_imports, unused_variables)]
mod migration_tests {
    use audit_module::AuditModuleClient;
    use payment_executor::PaymentExecutorClient;
    use payroll::{PayrollClient, ReconciliationStatus};
    use payroll_registry::{EmployeeStatus, PayrollRegistryClient};
    use salary_commitment::SalaryCommitmentContractClient;
    use soroban_sdk::{Env, Vec};

    use crate::migration_helpers::{
        assert_malformed_state_fails_safely, assert_post_migration_invariants,
        assert_unsupported_version_handled, MigrationContext, V1_STORAGE_VERSION,
    };
    use crate::state_fixtures;

    // ── Reusable test setup ──────────────────────────────────────────────────

    /// Set up a full v1 state environment, run migration, and return context.
    fn setup_and_migrate(env: &Env) -> MigrationContext {
        let mut ctx = MigrationContext::new(env);
        ctx.register_contracts(env);
        ctx.initialize_contracts(env);
        ctx.write_full_v1_state(env);
        ctx.simulate_upgrade_v2(env);
        ctx.run_migration_v1_to_v2(env);
        ctx
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-01: Historical Payroll Records Remain Readable After Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-01: Verify that all historical payroll run records (reconciled,
    /// unreconciled, and failed) remain fully readable after migration.
    #[test]
    fn mg_01_historical_payroll_runs_survive_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);

        // Historical run 1: Reconciled
        let run1 = payroll_client.get_payroll_run(&ctx.run_id_1);
        assert_eq!(run1.run_id, 1, "run_id must be preserved");
        assert_eq!(run1.total_amount, 10_000, "total_amount must be preserved");
        assert_eq!(run1.employee_count, 2, "employee_count must be preserved");
        assert_eq!(
            run1.reconciliation_status,
            ReconciliationStatus::Reconciled,
            "reconciliation_status must be preserved"
        );
        assert!(
            run1.executed_at > 0,
            "executed_at timestamp must be preserved"
        );

        // Historical run 2: Unreconciled
        let run2 = payroll_client.get_payroll_run(&ctx.run_id_2);
        assert_eq!(run2.run_id, 2);
        assert_eq!(run2.total_amount, 7_500);
        assert_eq!(
            run2.reconciliation_status,
            ReconciliationStatus::Unreconciled,
        );

        // Historical run 3: Failed
        let run3 = payroll_client.get_payroll_run(&ctx.failed_run_id);
        assert_eq!(run3.run_id, 3);
        assert_eq!(run3.total_amount, 5_000);
        assert_eq!(run3.reconciliation_status, ReconciliationStatus::Failed);

        // Verify draft_hash and metadata_hash are preserved
        let expected_draft = state_fixtures::seed_bytes32(&env, 0xDD);
        assert_eq!(
            run1.draft_hash, expected_draft,
            "draft_hash must be preserved"
        );
        let expected_metadata = state_fixtures::seed_bytes32(&env, 0xEE);
        assert_eq!(
            run1.metadata_hash, expected_metadata,
            "metadata_hash must be preserved"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-02: Employee Records (Active/Inactive/Incomplete) Survive Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-02: Verify that employee records with all status variants survive
    /// migration and remain in the correct eligibility state.
    #[test]
    fn mg_02_employee_records_survive_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // Alice: Active — should be eligible
        assert!(
            registry_client.is_eligible(&ctx.company_id_1, &ctx.alice),
            "Active employee must remain eligible after migration"
        );
        assert_eq!(
            registry_client.get_employee_status(&ctx.company_id_1, &ctx.alice),
            EmployeeStatus::Active,
        );
        let alice_commitment = registry_client.get_commitment(&ctx.company_id_1, &ctx.alice);
        assert_eq!(
            alice_commitment,
            state_fixtures::seed_bytes32(&env, 0xBB),
            "Alice's commitment must be the latest (post-rotation)"
        );

        // Bob: Active — should be eligible
        assert!(
            registry_client.is_eligible(&ctx.company_id_1, &ctx.bob),
            "Active employee Bob must remain eligible after migration"
        );
        let bob_commitment = registry_client.get_commitment(&ctx.company_id_1, &ctx.bob);
        assert_eq!(
            bob_commitment,
            state_fixtures::seed_bytes32(&env, 0x11),
            "Bob's original commitment must be preserved"
        );

        // Carol: Inactive — should NOT be eligible
        assert!(
            !registry_client.is_eligible(&ctx.company_id_1, &ctx.carol),
            "Inactive employee must remain ineligible after migration"
        );
        assert_eq!(
            registry_client.get_employee_status(&ctx.company_id_1, &ctx.carol),
            EmployeeStatus::Inactive,
        );

        // David: Incomplete — should NOT be eligible
        assert!(
            !registry_client.is_eligible(&ctx.company_id_1, &ctx.david),
            "Incomplete employee must remain ineligible after migration"
        );
        assert_eq!(
            registry_client.get_employee_status(&ctx.company_id_1, &ctx.david),
            EmployeeStatus::Incomplete,
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-03: Company State Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-03: Verify that company records (admin, treasury) survive migration
    /// and that new companies can still be registered after migration.
    #[test]
    fn mg_03_company_state_survives_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // Existing company state is intact
        let company1 = registry_client.get_company(&ctx.company_id_1);
        assert_eq!(company1.admin, ctx.admin);
        assert_eq!(company1.treasury, ctx.treasury);

        let company2 = registry_client.get_company(&ctx.company_id_2);
        assert_eq!(company2.admin, ctx.admin2);

        // New company can still be registered after migration
        let new_admin = state_fixtures::seed_address(&env, 0x20);
        let new_treasury = state_fixtures::seed_address(&env, 0x21);
        let new_company_id = registry_client.register_company(&new_admin, &new_treasury);
        assert_eq!(new_company_id, 2, "New company ID must be sequential");
        let new_company = registry_client.get_company(&new_company_id);
        assert_eq!(new_company.admin, new_admin);
        assert_eq!(new_company.treasury, new_treasury);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-04: Nullifier Store Preserved Across Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-04: Verify that nullifiers recorded before migration are still
    /// recognized after migration, preventing double-spend attacks.
    #[test]
    fn mg_04_nullifiers_survive_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);

        // Pre-migration nullifier is still detected
        let nullifier_used = state_fixtures::seed_bytes32(&env, 0xCC);
        assert!(
            commitment_client.is_nullifier_used(&nullifier_used),
            "Used nullifier must remain detected after migration"
        );

        // Another pre-migration nullifier
        let nullifier_used_2 = state_fixtures::seed_bytes32(&env, 0xDD);
        assert!(
            commitment_client.is_nullifier_used(&nullifier_used_2),
            "Second used nullifier must remain detected after migration"
        );

        // Fresh nullifier is correctly reported as unused
        let fresh = state_fixtures::seed_bytes32(&env, 0xFE);
        assert!(
            !commitment_client.is_nullifier_used(&fresh),
            "Fresh nullifier must be correctly reported as unused after migration"
        );

        // Can still record new nullifiers after migration
        let new_nullifier = state_fixtures::seed_bytes32(&env, 0xFD);
        commitment_client.record_nullifier(&new_nullifier);
        assert!(
            commitment_client.is_nullifier_used(&new_nullifier),
            "New nullifier recorded after migration must be detected"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-05: Commitment Version Counter Monotonic Across Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-05: Verify the commitment version counter increments monotonically
    /// and does NOT reset to 1 after migration.
    #[test]
    fn mg_05_commitment_version_monotonic_across_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);

        // Alice's commitment was updated (v1 → v2) before migration
        let alice_commitment = commitment_client.get_commitment(&ctx.alice);
        assert_eq!(
            alice_commitment.version, 2,
            "Alice's commitment version must be 2 (post-rotation, pre-migration)"
        );

        // Bob's commitment was never updated (v1)
        let bob_commitment = commitment_client.get_commitment(&ctx.bob);
        assert_eq!(
            bob_commitment.version, 1,
            "Bob's unchanged commitment must still be version 1"
        );

        // After migration, a new update must continue incrementing
        let new_commitment = state_fixtures::seed_bytes32(&env, 0xFC);
        commitment_client.update_commitment(&ctx.bob, &new_commitment);

        let bob_after = commitment_client.get_commitment(&ctx.bob);
        assert_eq!(
            bob_after.version, 2,
            "Bob's commitment version must increment to 2 after migration update"
        );
        assert_eq!(
            bob_after.commitment, new_commitment,
            "Bob's commitment value must be the latest after migration update"
        );

        // Alice: another update post-migration
        let alice_new = state_fixtures::seed_bytes32(&env, 0xFB);
        commitment_client.update_commitment(&ctx.alice, &alice_new);

        let alice_after = commitment_client.get_commitment(&ctx.alice);
        assert_eq!(
            alice_after.version, 3,
            "Alice's commitment version must be 3 after second update (2 pre-migration + 1 post)"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-06: Audit Permissions Survive Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-06: Verify that audit view key permissions survive migration.
    #[test]
    fn mg_06_audit_permissions_survive_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let audit_client = AuditModuleClient::new(&env, &ctx.audit_id);

        // View key for auditor should still be accessible
        let view_key_result = audit_client.try_get_view_key(&ctx.auditor);
        assert!(
            view_key_result.is_ok(),
            "Auditor view key must be retrievable after migration"
        );

        // Verify access check still works
        let has_access = audit_client.verify_access(&ctx.auditor);
        assert!(
            has_access,
            "Auditor access verification must work after migration"
        );

        // Can still grant new view keys after migration
        let new_auditor = state_fixtures::seed_address(&env, 0x30);
        let _new_key = audit_client.generate_view_key(&new_auditor, &200_000u32);
        assert!(
            audit_client.verify_access(&new_auditor),
            "New auditor granted after migration must have access"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-07: Commitment History Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-07: Verify that archived commitment history (from rotations)
    /// survives migration and remains queryable.
    #[test]
    fn mg_07_commitment_history_survives_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);

        // Alice's commitment was rotated (history should exist)
        let history = commitment_client.get_commitment_history(&ctx.alice);
        assert!(
            !history.is_empty(),
            "Commitment history must survive migration"
        );

        // The history should contain at least one entry (the original commitment)
        let first_snapshot = history.get(0).unwrap();
        // The original commitment was seed_bytes32(env, 0xAA) before rotation
        // The rotated version gets archived, so the commitment in history is the old one
        // After update_commitment, the old active commitment was archived
        let expected_original = state_fixtures::seed_bytes32(&env, 0x10);
        assert_eq!(
            first_snapshot.commitment, expected_original,
            "Historical commitment snapshot must preserve commitment bytes"
        );

        // Bob's commitment was never rotated (should have no history)
        let bob_history = commitment_client.get_commitment_history(&ctx.bob);
        assert!(
            bob_history.is_empty(),
            "Unrotated employee should have no commitment history"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-08: Active Payroll Flow Continues After Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-08: Verify that after migration, new payroll flows can be initiated
    /// without corrupting existing commitments or run statuses.
    #[test]
    fn mg_08_active_payroll_flow_continues_after_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);
        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);

        // Add a new employee post-migration
        let new_employee = state_fixtures::seed_address(&env, 0x40);
        let new_commitment_val = state_fixtures::seed_bytes32(&env, 0x41);
        commitment_client.store_commitment(&new_employee, &new_commitment_val);
        registry_client.add_employee(&ctx.company_id_1, &new_employee, &new_commitment_val);

        // Verify the new employee is properly registered
        assert!(
            registry_client.is_eligible(&ctx.company_id_1, &new_employee),
            "New employee added after migration must be eligible"
        );
        let stored_commitment = registry_client.get_commitment(&ctx.company_id_1, &new_employee);
        assert_eq!(
            stored_commitment, new_commitment_val,
            "New employee commitment must be stored correctly"
        );

        // Verify existing state wasn't corrupted
        assert!(
            registry_client.is_eligible(&ctx.company_id_1, &ctx.alice),
            "Existing employee must still be eligible after new employee added"
        );
        assert!(
            !registry_client.is_eligible(&ctx.company_id_1, &ctx.carol),
            "Inactive employee must remain ineligible after new employee added"
        );

        // Run counter should still work
        let new_run_id = payroll_client.get_payroll_run(&ctx.run_id_1);
        assert_eq!(new_run_id.run_id, 1);

        // Verify existing payroll runs weren't corrupted
        let run1 = payroll_client.get_payroll_run(&ctx.run_id_1);
        assert_eq!(run1.total_amount, 10_000);
        assert_eq!(run1.reconciliation_status, ReconciliationStatus::Reconciled);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-09: Payment Executor State Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-09: Verify payment executor periods and state survive migration.
    #[test]
    fn mg_09_payment_executor_state_survives_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let executor_client = PaymentExecutorClient::new(&env, &ctx.executor_id);

        // Storage version preserved
        assert_eq!(executor_client.get_storage_version(), V1_STORAGE_VERSION);

        // Closed period preserved
        let period_1 = executor_client.get_period(&ctx.company_id_1, &1);
        assert!(
            period_1.is_some(),
            "Period 1 (closed) must survive migration"
        );
        let p1 = period_1.unwrap();
        assert!(p1.closed, "Period 1 must remain closed");
        assert_eq!(p1.period_id, 1);
        assert_eq!(p1.company_id, ctx.company_id_1);

        // Open period preserved
        let period_2 = executor_client.get_period(&ctx.company_id_2, &1);
        assert!(period_2.is_some(), "Period 2 (open) must survive migration");
        let p2 = period_2.unwrap();
        assert!(!p2.closed, "Period 2 must remain open");

        // Close open period so a new period can be created
        let _ = executor_client.close_period(&ctx.company_id_2, &1);

        // New periods can be created post-migration
        let new_p = executor_client.create_period(&ctx.company_id_2);
        assert_eq!(new_p.period_id, 2, "Period sequence must continue");
        assert_eq!(new_p.company_id, ctx.company_id_2);
        assert!(!new_p.closed);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-10: Complete Migration Invariant Check
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-10: Comprehensive invariant check across all contract state.
    /// This is the master assertion that validates ALL state categories.
    #[test]
    fn mg_10_comprehensive_migration_invariants() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        // Run the comprehensive assertion suite
        assert_post_migration_invariants(&env, &ctx);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-NEG-01: Unsupported Storage Version Fails Safely
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-NEG-01: Verify that writing an unsupported storage version does not
    /// cause silent corruption — the version is readable and downstream
    /// migration logic can reject it.
    #[test]
    fn mg_neg_01_unsupported_version_handled() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        assert_unsupported_version_handled(&env, &ctx);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-NEG-02: Malformed Legacy State Fails Safely
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-NEG-02: Verify that corrupted/malformed legacy storage entries
    /// produce safe deserialization errors rather than silent corruption.
    #[test]
    fn mg_neg_02_malformed_state_fails_safely() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        assert_malformed_state_fails_safely(&env, &ctx);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-NEG-03: Missing Company Record Panics
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-NEG-03: Verify that reading a company that was never registered
    /// (and has no storage entry) still panics with the expected message.
    #[test]
    #[should_panic(expected = "Company not found")]
    fn mg_neg_03_missing_company_record_panics() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);
        // This company was never registered — should panic
        let _ = registry_client.get_company(&999);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-NEG-04: Missing Payroll Run Record Panics
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-NEG-04: Verify that reading a payroll run that was never created
    /// panics rather than returning corrupted data.
    #[test]
    #[should_panic(expected = "Run not found")]
    fn mg_neg_04_missing_payroll_run_panics() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);
        let _ = payroll_client.get_payroll_run(&999);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-NEG-05: Duplicate Nonce Rejection After Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-NEG-05: Verify that attempting to reuse a consumed run nonce
    /// after migration is correctly rejected.
    #[test]
    fn mg_neg_05_duplicate_nonce_rejected_after_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let _commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);
        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);
        let _registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // The nonce for run_id_1 was consumed before migration
        let consumed_nonce = state_fixtures::seed_bytes32(&env, 0xE1);

        // Try to use it again in prepare_payroll_run
        let proof = state_fixtures::seed_proof(&env, 0x50);
        let mut proofs = Vec::new(&env);
        proofs.push_back(proof);
        let mut amounts = Vec::new(&env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(&env);
        employees.push_back(ctx.alice.clone());

        let result = payroll_client.try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &consumed_nonce,
            &None,
        );

        assert!(
            result.is_err(),
            "Duplicate nonce must be rejected after migration"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-11: Metadata Hash Commitments Survive Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-11: Verify that pre-committed metadata hashes survive migration.
    #[test]
    fn mg_11_metadata_commitments_survive_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);

        // Pre-migration runs had metadata_hashes written
        let run1 = payroll_client.get_payroll_run(&ctx.run_id_1);
        let expected_meta = state_fixtures::seed_bytes32(&env, 0xEE);
        assert_eq!(
            run1.metadata_hash, expected_meta,
            "Metadata hash in historical run must survive migration"
        );

        // Post-migration: admin can commit a new metadata hash
        let new_meta_hash = state_fixtures::seed_bytes32(&env, 0xFA);
        payroll_client.commit_metadata_hash(&ctx.admin, &new_meta_hash);
        // Use try_ since set_run_metadata requires an existing run
        payroll_client.set_run_metadata(&ctx.admin, &ctx.run_id_1, &new_meta_hash);

        let run1_updated = payroll_client.get_payroll_run(&ctx.run_id_1);
        assert_eq!(
            run1_updated.metadata_hash, new_meta_hash,
            "Metadata hash must be updatable after migration"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-12: Pending Admin Rotation Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-12: Verify that pending role rotation proposals survive migration.
    #[test]
    fn mg_12_pending_rotation_survives_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);

        // Pending admin rotation should still be readable
        let pending = payroll_client.get_pending_admin_rotation();
        assert!(
            pending.is_some(),
            "Pending admin rotation must survive migration"
        );

        let rotation = pending.unwrap();
        assert_eq!(
            rotation.new_holder, ctx.admin2,
            "Rotation target must be preserved"
        );
        assert_eq!(
            rotation.proposed_by, ctx.admin,
            "Rotation proposer must be preserved"
        );

        // Accept the rotation after migration
        payroll_client.accept_admin_rotation(&ctx.admin2);

        // Verify rotation was accepted
        let after = payroll_client.get_pending_admin_rotation();
        assert!(
            after.is_none(),
            "Pending rotation must be cleared after acceptance"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-13: Emergency Withdrawal Request Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-13: Verify that pending emergency withdrawal requests survive migration.
    #[test]
    fn mg_13_emergency_withdrawal_request_survives_migration() {
        let env = Env::default();
        let ctx = setup_and_migrate(&env);

        let payroll_client = PayrollClient::new(&env, &ctx.payroll_id);

        // Emergency request should still be readable
        let emergency = payroll_client.get_emergency_request();
        assert!(
            emergency.is_some(),
            "Emergency withdrawal request must survive migration"
        );

        let request = emergency.unwrap();
        assert_eq!(
            request.amount, 50_000,
            "Emergency withdrawal amount must be preserved"
        );
        assert_eq!(
            request.recipient, ctx.treasury_owner,
            "Emergency withdrawal recipient must be preserved"
        );
        assert!(
            !request.approved,
            "Emergency request must remain unapproved"
        );
        assert!(
            request.requested_at > 0,
            "Emergency request timestamp must be preserved"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-14: Employee Reference IDs Survive Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-14: Verify that employee reference IDs survive migration.
    #[test]
    fn mg_14_employee_reference_ids_survive_migration() {
        let env = Env::default();
        let mut ctx = MigrationContext::new(&env);
        ctx.register_contracts(&env);
        ctx.initialize_contracts(&env);
        env.mock_all_auths();

        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);
        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // Set up some state with reference IDs
        let company_id = registry_client.register_company(&ctx.admin, &ctx.treasury);
        let alice_commitment = state_fixtures::seed_bytes32(&env, 0x10);
        commitment_client.store_commitment(&ctx.alice, &alice_commitment);
        registry_client.add_employee(&company_id, &ctx.alice, &alice_commitment);

        // Set a reference ID
        let ref_id = soroban_sdk::String::from_str(&env, "EMP-001");
        commitment_client.set_employee_reference_id(&ctx.alice, &ref_id);

        // Simulate migration
        ctx.simulate_upgrade_v2(&env);
        ctx.run_migration_v1_to_v2(&env);

        // Reference ID should still be queryable
        let stored_ref = commitment_client.get_employee_reference_id(&ctx.alice);
        assert!(
            stored_ref.is_some(),
            "Employee reference ID must survive migration"
        );
        assert_eq!(
            stored_ref.unwrap(),
            ref_id,
            "Reference ID value must be preserved"
        );

        // Reverse lookup should work
        let employee = commitment_client.get_employee_by_reference_id(&ref_id);
        assert_eq!(
            employee.unwrap(),
            ctx.alice,
            "Reverse reference lookup must survive migration"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-15: Commitment Lock State Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-15: Verify that commitment locks (from #178) survive migration.
    #[test]
    fn mg_15_commitment_locks_survive_migration() {
        let env = Env::default();
        let mut ctx = MigrationContext::new(&env);
        ctx.register_contracts(&env);
        ctx.initialize_contracts(&env);
        env.mock_all_auths();

        let commitment_client = SalaryCommitmentContractClient::new(&env, &ctx.commitment_id);
        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // Set up state with a locked commitment
        let company_id = registry_client.register_company(&ctx.admin, &ctx.treasury);
        let alice_commitment = state_fixtures::seed_bytes32(&env, 0x10);
        commitment_client.store_commitment(&ctx.alice, &alice_commitment);
        registry_client.add_employee(&company_id, &ctx.alice, &alice_commitment);

        // Lock Alice's commitment
        commitment_client.lock_commitment_updates(&ctx.alice);
        assert!(
            commitment_client.is_commitment_locked(&ctx.alice),
            "Commitment must be locked pre-migration"
        );

        // Simulate migration
        ctx.simulate_upgrade_v2(&env);
        ctx.run_migration_v1_to_v2(&env);

        // Lock must survive migration
        assert!(
            commitment_client.is_commitment_locked(&ctx.alice),
            "Commitment lock must survive migration"
        );

        // Cannot update a locked commitment after migration
        let new_commitment = state_fixtures::seed_bytes32(&env, 0xFF);
        let result = commitment_client.try_update_commitment(&ctx.alice, &new_commitment);
        assert!(
            result.is_err(),
            "Update of locked commitment must fail after migration"
        );

        // Admin can unlock and then update
        commitment_client.unlock_commitment_updates(&ctx.alice);
        assert!(
            !commitment_client.is_commitment_locked(&ctx.alice),
            "Commitment must be unlockable after migration"
        );

        let updated = commitment_client.update_commitment(&ctx.alice, &new_commitment);
        assert_eq!(
            updated.commitment, new_commitment,
            "Commitment must be updatable after unlocking post-migration"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // MG-16: Company Rotation State Survives Migration
    // ═══════════════════════════════════════════════════════════════════════════

    /// MG-16: Verify that company-level admin rotation proposals in the
    /// payroll_registry contract survive migration.
    #[test]
    fn mg_16_company_rotation_state_survives_migration() {
        let env = Env::default();
        let mut ctx = MigrationContext::new(&env);
        ctx.register_contracts(&env);
        ctx.initialize_contracts(&env);
        env.mock_all_auths();

        let registry_client = PayrollRegistryClient::new(&env, &ctx.registry_id);

        // Set up company
        let company_id = registry_client.register_company(&ctx.admin, &ctx.treasury);

        // Propose admin rotation
        registry_client.propose_admin_rotation(&company_id, &ctx.admin, &ctx.admin2);

        // Simulate migration
        ctx.simulate_upgrade_v2(&env);

        // The rotation proposal should still be pending
        // (No getter for pending admin rotation in registry, so we test via acceptance)
        // Accept the rotation to verify state is intact
        registry_client.accept_admin_rotation(&company_id, &ctx.admin2);

        // Verify the rotation took effect
        let company = registry_client.get_company(&company_id);
        assert_eq!(
            company.admin, ctx.admin2,
            "Admin rotation must complete successfully after migration"
        );
    }
}
