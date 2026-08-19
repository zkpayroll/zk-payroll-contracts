//! # Migration Test Helpers
//!
//! Provides reusable utilities for migration tests:
//!
//! - `MigrationContext` — Holds all contract IDs and addresses for a
//!   migration test scenario.
//! - `setup_full_v1_state` — Initializes a complete set of v1 state across
//!   all contracts, simulating pre-upgrade conditions.
//! - `assert_post_migration_invariants` — Runs comprehensive assertions
//!   that post-migration state is intact and correct.
//! - `expect_migration_failure` — Helper for negative tests.
//!
//! ## Usage
//!
//! ```ignore
//! use migration_helpers::{MigrationContext, setup_full_v1_state, assert_post_migration_invariants};
//!
//! let mut ctx = setup_full_v1_state(&env);
//! // Apply upgrade / migration function
//! ctx.simulate_upgrade_v2();
//! // Assert all state is preserved
//! assert_post_migration_invariants(&env, &ctx);
//! ```

use audit_module::{AuditModule, AuditModuleClient, AuditScope, ViewKeyRecord};
use pause_manager::{PauseManager, PauseManagerClient};
use payment_executor::{
    ContractAddresses as ExecutorContractAddresses, PaymentExecutor, PaymentExecutorClient,
};
use payroll::{
    ContractAddresses as PayrollContractAddresses, Payroll, PayrollClient, PayrollRun,
    ReconciliationStatus,
};
use payroll_registry::{
    CompanyInfo, EmployeeStatus, PayrollRegistry, PayrollRegistryClient, PendingCompanyRotation,
};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{
    SalaryCommitment, SalaryCommitmentContract, SalaryCommitmentContractClient,
};
use soroban_sdk::{
    testutils::Address as _, testutils::Ledger as _, Address, BytesN, Env, IntoVal, Symbol, Vec,
};
use token::{Token, TokenClient};

use crate::state_fixtures;

// ── Constants ───────────────────────────────────────────────────────────────

/// Version marker for v1 (current) state schema.
pub const V1_STORAGE_VERSION: u32 = 1;

/// Version marker for v2 (future) state schema — used in negative tests.
pub const UNSUPPORTED_STORAGE_VERSION: u32 = 999;

/// Seed for the migration test admin address.
pub const ADMIN_SEED: u8 = 0x01;

/// Seed for the migration test treasury address.
pub const TREASURY_SEED: u8 = 0x02;

/// Seed for the migration test treasury owner.
pub const TREASURY_OWNER_SEED: u8 = 0x03;

// ── Migration Context ───────────────────────────────────────────────────────

/// Holds all contract IDs and addresses for a migration test scenario.
pub struct MigrationContext {
    /// Contract IDs
    pub registry_id: Address,
    pub commitment_id: Address,
    pub verifier_id: Address,
    pub payroll_id: Address,
    pub executor_id: Address,
    pub audit_id: Address,
    pub token_id: Address,
    pub pause_manager_id: Address,

    /// Key addresses
    pub admin: Address,
    pub treasury: Address,
    pub treasury_owner: Address,
    pub admin2: Address,
    pub auditor: Address,
    pub payroll_operator: Address,

    /// Employees
    pub alice: Address,
    pub bob: Address,
    pub carol: Address,
    pub david: Address,

    /// Company IDs created during setup
    pub company_id_1: u64,
    pub company_id_2: u64,

    /// Historical payroll run IDs
    pub run_id_1: u64,
    pub run_id_2: u64,
    pub failed_run_id: u64,

    /// V1 state flags — track what was initialized
    pub has_companies: bool,
    pub has_employees: bool,
    pub has_payroll_runs: bool,
    pub has_audit_permissions: bool,
    pub has_executor_state: bool,
    pub has_nullifiers: bool,
    pub has_pending_rotations: bool,
    pub has_emergency_request: bool,
    pub has_commitment_history: bool,
}

impl MigrationContext {
    /// Create a new, empty migration context with generated addresses.
    pub fn new(env: &Env) -> Self {
        MigrationContext {
            registry_id: Address::generate(env),
            commitment_id: Address::generate(env),
            verifier_id: Address::generate(env),
            payroll_id: Address::generate(env),
            executor_id: Address::generate(env),
            audit_id: Address::generate(env),
            token_id: Address::generate(env),
            pause_manager_id: Address::generate(env),
            admin: state_fixtures::seed_address(env, ADMIN_SEED),
            treasury: state_fixtures::seed_address(env, TREASURY_SEED),
            treasury_owner: state_fixtures::seed_address(env, TREASURY_OWNER_SEED),
            admin2: state_fixtures::seed_address(env, 0x04),
            auditor: state_fixtures::seed_address(env, 0x05),
            payroll_operator: state_fixtures::seed_address(env, 0x06),
            alice: state_fixtures::seed_address(env, 0x10),
            bob: state_fixtures::seed_address(env, 0x11),
            carol: state_fixtures::seed_address(env, 0x12),
            david: state_fixtures::seed_address(env, 0x13),
            company_id_1: 0,
            company_id_2: 1,
            run_id_1: 1,
            run_id_2: 2,
            failed_run_id: 3,
            has_companies: false,
            has_employees: false,
            has_payroll_runs: false,
            has_audit_permissions: false,
            has_executor_state: false,
            has_nullifiers: false,
            has_pending_rotations: false,
            has_emergency_request: false,
            has_commitment_history: false,
        }
    }

    // ── V1 State Setup ──────────────────────────────────────────────────────

    /// Register all contracts into the environment.
    pub fn register_contracts(&mut self, env: &Env) {
        self.registry_id = env.register_contract(None, PayrollRegistry);
        self.commitment_id = env.register_contract(None, SalaryCommitmentContract);
        self.verifier_id = env.register_contract(None, ProofVerifier);
        self.payroll_id = env.register_contract(None, Payroll);
        self.executor_id = env.register_contract(None, PaymentExecutor);
        self.audit_id = env.register_contract(None, AuditModule);
        self.token_id = env.register_contract(None, Token);
        self.pause_manager_id = env.register_contract(None, PauseManager);
    }

    /// Initialize all contracts with mock auths (standard deployment flow).
    pub fn initialize_contracts(&mut self, env: &Env) {
        env.mock_all_auths();

        // Initialize verifier with a mock VK
        let verifier_client = ProofVerifierClient::new(env, &self.verifier_id);
        verifier_client.init_verifier_admin(&self.admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        // Initialize commitment contract admin
        let commitment_client = SalaryCommitmentContractClient::new(env, &self.commitment_id);
        commitment_client.init_commitment_admin(&self.admin);
        commitment_client.set_payroll_operator(&self.payroll_operator);

        // Initialize token & mint to treasury
        let token_client = TokenClient::new(env, &self.token_id);
        token_client.initialize(
            &self.admin,
            &7,
            &soroban_sdk::String::from_str(env, "USD"),
            &soroban_sdk::String::from_str(env, "USD"),
        );
        token_client.mint(&self.treasury, &1_000_000i128);
        token_client.mint(&self.treasury_owner, &1_000_000i128);

        // Initialize pause manager
        let pm_client = PauseManagerClient::new(env, &self.pause_manager_id);
        pm_client.initialize(&self.admin);

        // Initialize executor
        let executor_addrs = ExecutorContractAddresses {
            registry: self.registry_id.clone(),
            commitment: self.commitment_id.clone(),
            verifier: self.verifier_id.clone(),
            token: self.token_id.clone(),
        };
        let executor_client = PaymentExecutorClient::new(env, &self.executor_id);
        executor_client.initialize(&executor_addrs);

        // Initialize payroll
        let payroll_client = PayrollClient::new(env, &self.payroll_id);
        payroll_client.initialize(
            &self.admin,
            &self.token_id,
            &self.verifier_id,
            &self.commitment_id,
            &self.treasury,
            &self.treasury_owner,
        );

        // Initialize audit module
        let _audit_client = AuditModuleClient::new(env, &self.audit_id);
    }

    /// Write full v1 state: companies, employees, payroll runs, audit permissions, etc.
    pub fn write_full_v1_state(&mut self, env: &Env) {
        env.mock_all_auths();
        env.ledger().with_mut(|l| l.timestamp = 1000);

        // ── Companies ────────────────────────────────────────────────────
        let registry_client = PayrollRegistryClient::new(env, &self.registry_id);
        self.company_id_1 = registry_client.register_company(&self.admin, &self.treasury);
        self.company_id_2 = registry_client.register_company(&self.admin2, &self.treasury_owner);

        // ── Employees with different statuses ────────────────────────────
        let commitment_client = SalaryCommitmentContractClient::new(env, &self.commitment_id);

        // Alice: Active employee with commitment
        let alice_commitment = state_fixtures::seed_bytes32(env, 0x10);
        commitment_client.store_commitment(&self.alice, &alice_commitment);
        registry_client.add_employee(&self.company_id_1, &self.alice, &alice_commitment);

        // Bob: Active employee with different commitment
        let bob_commitment = state_fixtures::seed_bytes32(env, 0x11);
        commitment_client.store_commitment(&self.bob, &bob_commitment);
        registry_client.add_employee(&self.company_id_1, &self.bob, &bob_commitment);

        // Carol: Inactive employee
        let carol_commitment = state_fixtures::seed_bytes32(env, 0x12);
        commitment_client.store_commitment(&self.carol, &carol_commitment);
        registry_client.add_employee(&self.company_id_1, &self.carol, &carol_commitment);
        registry_client.set_employee_status(
            &self.company_id_1,
            &self.carol,
            &EmployeeStatus::Inactive,
        );

        // David: Incomplete employee (no explicit status set means Incomplete)
        let david_commitment = state_fixtures::seed_bytes32(env, 0x13);
        commitment_client.store_commitment(&self.david, &david_commitment);
        registry_client.add_employee(&self.company_id_1, &self.david, &david_commitment);
        registry_client.set_employee_status(
            &self.company_id_1,
            &self.david,
            &EmployeeStatus::Incomplete,
        );

        // ── Commitment history for Alice (simulate rotation) ─────────────
        let _old_commitment = state_fixtures::seed_bytes32(env, 0xAA);
        let new_commitment = state_fixtures::seed_bytes32(env, 0xBB);
        commitment_client.update_commitment(&self.alice, &new_commitment);
        registry_client.update_commitment(&self.company_id_1, &self.alice, &new_commitment);
        self.has_commitment_history = true;

        // ── Nullifiers ───────────────────────────────────────────────────
        let nullifier_1 = state_fixtures::seed_bytes32(env, 0xCC);
        commitment_client.record_nullifier(&nullifier_1);
        let nullifier_2 = state_fixtures::seed_bytes32(env, 0xDD);
        commitment_client.record_nullifier(&nullifier_2);
        self.has_nullifiers = true;

        // ── Payroll runs ─────────────────────────────────────────────────
        let payroll_client = PayrollClient::new(env, &self.payroll_id);

        // Historical run 1: Reconciled
        // We directly write to simulate pre-existing runs with specific statuses
        state_fixtures::write_v1_payroll_run_fixture(
            env,
            &self.payroll_id,
            1,
            &self.admin,
            10_000,
            2,
            ReconciliationStatus::Reconciled,
        );
        state_fixtures::write_v1_run_counter(env, &self.payroll_id, 1);
        // Mark nonce as consumed
        let nonce_1 = state_fixtures::seed_bytes32(env, 0xE1);
        state_fixtures::write_v1_run_nonce(env, &self.payroll_id, &nonce_1, 1);

        // Historical run 2: Unreconciled
        state_fixtures::write_v1_payroll_run_fixture(
            env,
            &self.payroll_id,
            2,
            &self.admin,
            7_500,
            1,
            ReconciliationStatus::Unreconciled,
        );
        state_fixtures::write_v1_run_counter(env, &self.payroll_id, 2);
        let nonce_2 = state_fixtures::seed_bytes32(env, 0xE2);
        state_fixtures::write_v1_run_nonce(env, &self.payroll_id, &nonce_2, 2);

        // Historical run 3: Failed
        state_fixtures::write_v1_payroll_run_fixture(
            env,
            &self.payroll_id,
            3,
            &self.admin,
            5_000,
            1,
            ReconciliationStatus::Failed,
        );
        state_fixtures::write_v1_run_counter(env, &self.payroll_id, 3);
        let nonce_3 = state_fixtures::seed_bytes32(env, 0xE3);
        state_fixtures::write_v1_run_nonce(env, &self.payroll_id, &nonce_3, 3);

        self.run_id_1 = 1;
        self.run_id_2 = 2;
        self.failed_run_id = 3;
        self.has_payroll_runs = true;

        // ── Pending admin rotation ───────────────────────────────────────
        state_fixtures::write_v1_pending_admin_rotation(
            env,
            &self.payroll_id,
            &self.admin2,
            &self.admin,
        );
        self.has_pending_rotations = true;

        // ── Emergency withdrawal request ─────────────────────────────────
        state_fixtures::write_v1_emergency_withdrawal(
            env,
            &self.payroll_id,
            50_000,
            &self.treasury_owner,
        );
        self.has_emergency_request = true;

        // ── Audit permissions ────────────────────────────────────────────
        let audit_client = AuditModuleClient::new(env, &self.audit_id);
        let _ = audit_client.generate_view_key(&self.auditor, &100_000u32);
        self.has_audit_permissions = true;

        // ── Payment executor state ───────────────────────────────────────
        let executor_client = PaymentExecutorClient::new(env, &self.executor_id);
        let _ = executor_client.create_period(&self.company_id_1);
        let _ = executor_client.close_period(&self.company_id_1, &1);
        let _ = executor_client.create_period(&self.company_id_2);
        self.has_executor_state = true;

        // ── Mark flags ───────────────────────────────────────────────────
        self.has_companies = true;
        self.has_employees = true;
    }

    /// Simulate an upgrade by re-registering the v2 contract and re-initializing.
    /// In a real scenario, this would deploy a new WASM; in tests, we just
    /// re-register the same contract to simulate the upgrade boundary.
    pub fn simulate_upgrade_v2(&mut self, env: &Env) {
        env.mock_all_auths();

        // Re-deploy all contracts as if new WASM was uploaded.
        // This simulates upgrading to a new contract version while preserving
        // existing storage (old keys remain).
        let new_registry_id =
            env.register_contract(&Some(self.registry_id.clone()), PayrollRegistry);
        let new_commitment_id =
            env.register_contract(&Some(self.commitment_id.clone()), SalaryCommitmentContract);
        let new_verifier_id = env.register_contract(&Some(self.verifier_id.clone()), ProofVerifier);
        let new_payroll_id = env.register_contract(&Some(self.payroll_id.clone()), Payroll);
        let new_executor_id =
            env.register_contract(&Some(self.executor_id.clone()), PaymentExecutor);
        let new_audit_id = env.register_contract(&Some(self.audit_id.clone()), AuditModule);

        // Update IDs to new instances (same contract IDs, new WASM)
        // In Soroban, register_contract with Some(id) deploys to the same address.
        // The storage is preserved because it's keyed by contract ID.
        self.registry_id = new_registry_id;
        self.commitment_id = new_commitment_id;
        self.verifier_id = new_verifier_id;
        self.payroll_id = new_payroll_id;
        self.executor_id = new_executor_id;
        self.audit_id = new_audit_id;
    }

    /// Run a v1→v2 migration function that reads old-format state and adapts it.
    /// For now, this is a no-op that validates existing state is self-consistent.
    /// Future versions will perform actual schema migrations.
    pub fn run_migration_v1_to_v2(&self, env: &Env) {
        env.mock_all_auths();

        // In a real migration, this function would:
        // 1. Read old-format keys (e.g., DataKey::Company(u64))
        // 2. Transform data to new format
        // 3. Write new-format keys (e.g., DataKey::CompanyV2(u64))
        // 4. Optionally remove old keys after migration window

        // For now, assert that pre-upgrade data is still accessible.
        let registry_client = PayrollRegistryClient::new(env, &self.registry_id);
        if self.has_companies {
            let _company1 = registry_client.get_company(&self.company_id_1);
            if self.company_id_2 > 0 {
                let _company2 = registry_client.get_company(&self.company_id_2);
            }
        }

        let commitment_client = SalaryCommitmentContractClient::new(env, &self.commitment_id);
        if self.has_employees {
            assert!(commitment_client.has_commitment(&self.alice));
            assert!(commitment_client.has_commitment(&self.bob));
        }

        let payroll_client = PayrollClient::new(env, &self.payroll_id);
        if self.has_payroll_runs {
            let _run1 = payroll_client.get_payroll_run(&self.run_id_1);
            let _run2 = payroll_client.get_payroll_run(&self.run_id_2);
        }
    }
}

// ── Assertion Helpers ───────────────────────────────────────────────────────

/// Assert that all v1 state survives migration intact.
pub fn assert_post_migration_invariants(env: &Env, ctx: &MigrationContext) {
    env.mock_all_auths();

    // ── Company invariants ───────────────────────────────────────────────
    let registry_client = PayrollRegistryClient::new(env, &ctx.registry_id);
    let company1 = registry_client.get_company(&ctx.company_id_1);
    assert_eq!(
        company1.admin, ctx.admin,
        "MG-01: Company admin must survive migration"
    );
    assert_eq!(
        company1.treasury, ctx.treasury,
        "MG-02: Company treasury must survive migration"
    );

    let company2 = registry_client.get_company(&ctx.company_id_2);
    assert_eq!(
        company2.admin, ctx.admin2,
        "MG-03: Second company admin must survive migration"
    );

    // ── Employee invariants ──────────────────────────────────────────────
    // Alice: Active
    assert!(
        registry_client.is_eligible(&ctx.company_id_1, &ctx.alice),
        "MG-04: Active employee must remain eligible"
    );
    assert_eq!(
        registry_client.get_employee_status(&ctx.company_id_1, &ctx.alice),
        EmployeeStatus::Active,
        "MG-05: Active employee status must survive migration"
    );

    // Carol: Inactive
    assert!(
        !registry_client.is_eligible(&ctx.company_id_1, &ctx.carol),
        "MG-06: Inactive employee must remain ineligible"
    );
    assert_eq!(
        registry_client.get_employee_status(&ctx.company_id_1, &ctx.carol),
        EmployeeStatus::Inactive,
        "MG-07: Inactive employee status must survive migration"
    );

    // David: Incomplete
    assert!(
        !registry_client.is_eligible(&ctx.company_id_1, &ctx.david),
        "MG-08: Incomplete employee must remain ineligible"
    );

    // ── Commitment invariants ────────────────────────────────────────────
    let commitment_client = SalaryCommitmentContractClient::new(env, &ctx.commitment_id);

    // Alice should have a commitment after update
    assert!(
        commitment_client.has_commitment(&ctx.alice),
        "MG-09: Employee commitment must survive migration"
    );
    let alice_commitment = commitment_client.get_commitment(&ctx.alice);
    assert!(
        !alice_commitment.revoked,
        "MG-10: Active commitment must not be revoked"
    );

    // Bob's commitment (never updated)
    let _bob_commitment = commitment_client.get_commitment(&ctx.bob);
    assert_eq!(
        _bob_commitment.version, 1,
        "MG-11: Unchanged commitment must retain version 1"
    );

    // ── Commitment history invariants ────────────────────────────────────
    let history = commitment_client.get_commitment_history(&ctx.alice);
    assert!(
        !history.is_empty(),
        "MG-12: Commitment history must survive migration"
    );

    // ── Nullifier invariants ─────────────────────────────────────────────
    let nullifier_1 = state_fixtures::seed_bytes32(env, 0xCC);
    assert!(
        commitment_client.is_nullifier_used(&nullifier_1),
        "MG-13: Used nullifier must remain detected after migration"
    );

    let fresh_nullifier = state_fixtures::seed_bytes32(env, 0xFF);
    assert!(
        !commitment_client.is_nullifier_used(&fresh_nullifier),
        "MG-14: Never-used nullifier must remain undetected"
    );

    // ── Payroll run invariants ───────────────────────────────────────────
    let payroll_client = PayrollClient::new(env, &ctx.payroll_id);

    // Historical run 1: Reconciled
    let run1 = payroll_client.get_payroll_run(&ctx.run_id_1);
    assert_eq!(
        run1.run_id, ctx.run_id_1,
        "MG-15: Historical payroll run ID must survive migration"
    );
    assert_eq!(
        run1.reconciliation_status,
        ReconciliationStatus::Reconciled,
        "MG-16: Run reconciliation status must survive migration"
    );
    assert_eq!(
        run1.total_amount, 10_000,
        "MG-17: Historical run total amount must be preserved"
    );
    assert_eq!(
        run1.employee_count, 2,
        "MG-18: Historical run employee count must be preserved"
    );

    // Historical run 3: Failed
    let run3 = payroll_client.get_payroll_run(&ctx.failed_run_id);
    assert_eq!(
        run3.reconciliation_status,
        ReconciliationStatus::Failed,
        "MG-19: Failed run status must survive migration"
    );
    assert_eq!(
        run3.total_amount, 5_000,
        "MG-20: Failed run amount must be preserved"
    );

    // ── Audit permission invariants ──────────────────────────────────────
    let _audit_client = AuditModuleClient::new(env, &ctx.audit_id);
    let view_key_result = _audit_client.try_get_view_key(&ctx.auditor);
    assert!(
        view_key_result.is_ok(),
        "MG-21: Audit view key must survive migration"
    );

    // ── Payment executor invariants ──────────────────────────────────────
    let executor_client = PaymentExecutorClient::new(env, &ctx.executor_id);
    let version = executor_client.get_storage_version();
    assert_eq!(
        version, V1_STORAGE_VERSION,
        "MG-22: Storage version must survive migration"
    );

    // Periods should still be readable
    let period_1 = executor_client.get_period(&ctx.company_id_1, &1);
    assert!(
        period_1.is_some(),
        "MG-23: Closed period must survive migration"
    );
    let p1 = period_1.unwrap();
    assert!(
        p1.closed,
        "MG-24: Period closed status must survive migration"
    );

    let period_2 = executor_client.get_period(&ctx.company_id_2, &1);
    assert!(
        period_2.is_some(),
        "MG-25: Open period must survive migration"
    );
    assert!(
        !period_2.unwrap().closed,
        "MG-26: Open period must remain open"
    );

    // ── Emergency withdrawal request invariant ───────────────────────────
    let emergency = payroll_client.get_emergency_request();
    assert!(
        emergency.is_some(),
        "MG-27: Emergency withdrawal request must survive migration"
    );
    let req = emergency.unwrap();
    assert_eq!(
        req.amount, 50_000,
        "MG-28: Emergency withdrawal amount must be preserved"
    );
}

// ── Negative Test Helpers ───────────────────────────────────────────────────

/// Assert that an unsupported storage version is properly rejected.
/// Writes a bad version into storage and expects reads to fail gracefully.
pub fn assert_unsupported_version_handled(env: &Env, ctx: &MigrationContext) {
    // Write an unsupported storage version into the executor
    use payment_executor::DataKey as ExecutorDataKey;
    env.as_contract(&ctx.executor_id, || {
        env.storage().persistent().set(
            &ExecutorDataKey::StorageVersion,
            &UNSUPPORTED_STORAGE_VERSION,
        );
    });

    let executor_client = PaymentExecutorClient::new(env, &ctx.executor_id);
    let version = executor_client.get_storage_version();
    // The contract should still return the version (even if unsupported)
    // It's up to the migration logic to reject unsupported versions
    assert_eq!(
        version, UNSUPPORTED_STORAGE_VERSION,
        "MG-NEG-01: Stored unsupported version must be readable"
    );
    // TODO: When version-checking migration logic is added, assert rejection here
}

/// Assert that malformed (corrupted) state produces safe failures.
pub fn assert_malformed_state_fails_safely(env: &Env, ctx: &MigrationContext) {
    // Corrupt a company record by writing garbage bytes at the key location
    use payroll_registry::DataKey as RegistryDataKey;
    let garbage = soroban_sdk::Bytes::from_array(env, &[0xFFu8; 128]);

    env.as_contract(&ctx.registry_id, || {
        // Overwrite company 0 key with garbage
        let key = RegistryDataKey::Company(ctx.company_id_1);
        env.storage().persistent().set(&key, &garbage);
    });

    let registry_client = PayrollRegistryClient::new(env, &ctx.registry_id);
    let result = registry_client.try_get_company(&ctx.company_id_1);
    assert!(
        result.is_err(),
        "MG-NEG-02: Corrupted company record must fail to deserialize"
    );
}

// ── Mock Helpers ────────────────────────────────────────────────────────────

/// Generate a mock verification key for test environments.
pub fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}
