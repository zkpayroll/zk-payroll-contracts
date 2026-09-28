// Issue #517: Pre-activation contract upgrade compatibility checks
//
// `PaymentExecutor::check_upgrade_compatibility` is run against the *currently
// deployed* contract immediately before an upgraded WASM implementation is
// activated. It validates that the persistent data an upgraded implementation
// will read is still intact, and fails with a typed `StorageError` when it is
// not.
//
// Checks covered:
//   C-1. Success path — a production-ready executor reports its schema version
//        and readiness flags for a forward-compatible target version.
//   C-2. The check is read-only — running it against a live executor holding
//        payment history leaves that history untouched and payroll keeps working.
//   C-3. Uninitialized contract — nothing to validate, so the check fails.
//   C-4. Invalid / downgrading target version is rejected.
//   C-5. Missing executor admin is rejected (the upgraded implementation would
//        have no authority for asset and period administration).
//   C-6. Treasury asset removed from the allowlist is rejected.
//   C-7. Missing asset decimal configuration is rejected (it would otherwise
//        surface as `AssetDecimalsMissing` on the first payroll run).
//   C-8. Failure states are actionable and privacy-safe — the report carries
//        only schema versions and readiness flags, never payroll values.

use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use shared_errors::StorageError;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

/// Decimal precision configured for the treasury asset in these tests.
const TREASURY_DECIMALS: u32 = 7;

// ---------------------------------------------------------------------------
// Shared helpers (mirrors the pattern used in invariant_tests.rs)
// ---------------------------------------------------------------------------

fn mock_vk(env: &Env) -> VerificationKey {
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

/// How much of the executor's upgrade-relevant configuration is present.
///
/// Each variant models a degraded state that an upgrade must not silently
/// inherit from a live deployment.
#[derive(Clone, Copy)]
enum Readiness {
    /// Initialized only — no admin, no decimal configuration.
    Bare,
    /// Initialized with an admin but no treasury decimal configuration.
    NoDecimals,
    /// Fully production-ready.
    Ready,
}

/// Wired-up contract handles for a single test.
struct Executor<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitment: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    token_address: Address,
}

/// Register all contracts, initialize the executor, and apply `readiness`.
fn setup_executor<'a>(env: &'a Env, readiness: Readiness) -> Executor<'a> {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);
    commitment_client.set_payroll_operator(&executor_id);

    match readiness {
        Readiness::Bare => {}
        Readiness::NoDecimals => {
            executor.set_executor_admin(&Address::generate(env));
        }
        Readiness::Ready => {
            executor.set_executor_admin(&Address::generate(env));
            executor.set_asset_decimals(&addresses.token, &TREASURY_DECIMALS);
        }
    }

    Executor {
        executor,
        registry,
        commitment: commitment_client,
        token,
        token_address: addresses.token,
    }
}

/// Register a company, open period 1, and fund the treasury.
fn open_company(env: &Env, ctx: &Executor, treasury_balance: i128) -> u64 {
    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = ctx.registry.register_company(&admin, &treasury);
    let _ = ctx.executor.create_period(&company_id);
    ctx.token.mint(&treasury, &treasury_balance);

    // Issue #538: set zero-rate withholding config so execute_payment is unblocked
    let tax_addr = Address::generate(env);
    ctx.executor.set_withholding_config(
        &company_id,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    company_id
}

/// Register an employee and store their commitment in one call.
fn register_employee(ctx: &Executor, env: &Env, company_id: u64, seed: u8) -> Address {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    ctx.commitment.store_commitment(&employee, &commitment);
    ctx.registry
        .add_employee(&company_id, &employee, &commitment);
    employee
}

/// Build proof + nullifier byte arrays for a payment.
/// `seed` must be unique per payment so proofs/nullifiers never collide.
fn make_proof(env: &Env, seed: u8) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 128]),
        BytesN::from_array(env, &[seed; 64]),
        BytesN::from_array(env, &[seed; 32]),
    )
}

// ===========================================================================
// C-1. Success path
// ===========================================================================

/// A fully configured executor passes the check and reports the schema
/// versions and readiness flags an operator records in the upgrade checklist.
#[test]
fn test_check_upgrade_compatibility_passes_for_initialized_state() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);

    let report = ctx
        .executor
        .try_check_upgrade_compatibility(&1)
        .unwrap()
        .unwrap();

    assert_eq!(report.current_version, 1);
    assert_eq!(report.target_version, 1);
    assert!(report.initialized);
    assert!(report.admin_configured);
    assert!(report.treasury_asset_allowed);
    assert!(report.treasury_asset_decimals_configured);
}

/// Forward compatibility: an implementation declaring a newer schema than the
/// one persisted on chain passes, because older records remain readable and
/// additive fields take their defaults.
#[test]
fn test_check_upgrade_compatibility_allows_forward_schema() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);

    let report = ctx
        .executor
        .try_check_upgrade_compatibility(&2)
        .unwrap()
        .unwrap();

    assert_eq!(report.current_version, 1);
    assert_eq!(report.target_version, 2);
}

// ===========================================================================
// C-2. The check is read-only and does not break payroll workflows
// ===========================================================================

/// Running the preflight against a live executor must not disturb stored
/// payment history, and the payroll workflow must still work afterwards.
#[test]
fn test_check_upgrade_compatibility_is_read_only() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);
    let company_id = open_company(&env, &ctx, 500_000);

    // Pre-upgrade state: one completed payment inside period 1.
    let employee = register_employee(&ctx, &env, company_id, 21);
    let (pa, pb, pc, null) = make_proof(&env, 21);
    ctx.executor
        .execute_payment(&company_id, &employee, &30_000, &pa, &pb, &pc, &null, &1);

    let total_before = ctx.executor.get_total_paid(&company_id);
    let period_before = ctx.executor.get_period(&company_id, &1).unwrap();
    assert_eq!(total_before, 30_000);

    // Pre-activation preflight against the live contract.
    let report = ctx
        .executor
        .try_check_upgrade_compatibility(&2)
        .unwrap()
        .unwrap();
    assert_eq!(report.current_version, 1);

    // No payroll state was mutated by the check itself.
    assert_eq!(ctx.executor.get_storage_version(), 1);
    assert_eq!(ctx.executor.get_total_paid(&company_id), total_before);
    assert!(ctx.executor.is_paid(&employee, &1));
    let period_after = ctx.executor.get_period(&company_id, &1).unwrap();
    assert_eq!(
        period_after.period_id, period_before.period_id,
        "compatibility check must not alter the period identity"
    );
    assert_eq!(
        period_after.closed, period_before.closed,
        "compatibility check must not close a period"
    );
    assert_eq!(
        period_after.payment_count, period_before.payment_count,
        "compatibility check must not alter the period payment count"
    );
    assert_eq!(
        period_after.created_at, period_before.created_at,
        "compatibility check must not rewrite period timestamps"
    );

    // The payroll workflow continues normally after the check.
    let employee_2 = register_employee(&ctx, &env, company_id, 22);
    let (pa2, pb2, pc2, null2) = make_proof(&env, 22);
    ctx.executor.execute_payment(
        &company_id,
        &employee_2,
        &20_000,
        &pa2,
        &pb2,
        &pc2,
        &null2,
        &1,
    );

    assert_eq!(ctx.executor.get_total_paid(&company_id), 50_000);
    assert!(ctx.executor.is_paid(&employee_2, &1));

    // A new period can still be opened after the preflight.
    let period_2 = ctx.executor.create_period(&company_id);
    assert_eq!(period_2.period_id, 2);
    assert_eq!(ctx.executor.get_period_sequence(&company_id), 2);
}

// ===========================================================================
// C-3. Edge case — uninitialized contract
// ===========================================================================

/// An executor that was never initialized has no persistent data to validate.
#[test]
fn test_check_upgrade_compatibility_rejects_uninitialized_contract() {
    let env = Env::default();
    env.mock_all_auths();
    let executor_id = env.register_contract(None, PaymentExecutor);
    let executor = PaymentExecutorClient::new(&env, &executor_id);

    let result = executor.try_check_upgrade_compatibility(&1);

    assert_eq!(result, Err(Ok(StorageError::NotInitialized)));
}

// ===========================================================================
// C-4. Edge case — invalid / downgrading target version
// ===========================================================================

/// A target version below the persisted schema version is a downgrade:
/// existing records would become unreadable, so it is rejected rather than
/// silently accepted. Version `0` is never a valid schema.
#[test]
fn test_check_upgrade_compatibility_rejects_invalid_target_version() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);

    // The persisted schema version is 1, so version 0 is not a valid target.
    assert_eq!(
        ctx.executor.try_check_upgrade_compatibility(&0),
        Err(Ok(StorageError::StorageVersionMismatch))
    );
}

// ===========================================================================
// C-5. Edge case — missing executor admin
// ===========================================================================

/// Without an executor admin the upgraded implementation would have no
/// authority for asset and period administration.
#[test]
fn test_check_upgrade_compatibility_rejects_missing_executor_admin() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Bare);

    let result = ctx.executor.try_check_upgrade_compatibility(&1);

    assert_eq!(result, Err(Ok(StorageError::StorageCorruption)));
}

// ===========================================================================
// C-6. Edge case — treasury asset removed from the allowlist
// ===========================================================================

/// Dropping the treasury asset from the allowlist would leave the upgraded
/// implementation unable to settle payroll, so the check must fail.
#[test]
fn test_check_upgrade_compatibility_rejects_disallowed_treasury_asset() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);
    let token_address = ctx.token_address.clone();

    ctx.executor.set_asset_allowed(&token_address, &false);

    let result = ctx.executor.try_check_upgrade_compatibility(&1);

    assert_eq!(result, Err(Ok(StorageError::StorageCorruption)));
}

// ===========================================================================
// C-7. Edge case — missing asset decimal configuration
// ===========================================================================

/// Missing decimal configuration blocks `execute_payment`. Surfacing it in the
/// preflight means the operator fixes it before activation instead of on the
/// first payroll run.
#[test]
fn test_check_upgrade_compatibility_rejects_missing_asset_decimals() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::NoDecimals);

    let result = ctx.executor.try_check_upgrade_compatibility(&1);

    assert_eq!(result, Err(Ok(StorageError::StorageCorruption)));
}

// ===========================================================================
// C-8. Privacy — failure states are actionable without exposing payroll values
// ===========================================================================

/// The report is a fixed metadata surface: two schema versions and four
/// readiness flags. Nothing payroll-valued (amounts, commitments, employee
/// addresses) belongs in it, because upgrade tooling prints it verbatim.
#[test]
fn test_check_upgrade_compatibility_report_is_privacy_safe() {
    let env = Env::default();
    let ctx = setup_executor(&env, Readiness::Ready);
    let company_id = open_company(&env, &ctx, 500_000);
    let employee = register_employee(&ctx, &env, company_id, 31);
    let (pa, pb, pc, null) = make_proof(&env, 31);
    ctx.executor
        .execute_payment(&company_id, &employee, &30_000, &pa, &pb, &pc, &null, &1);

    let report = ctx
        .executor
        .try_check_upgrade_compatibility(&1)
        .unwrap()
        .unwrap();

    // Only versions and boolean readiness flags are reported, regardless of
    // how much payroll state the executor holds.
    assert_eq!(report.current_version, 1);
    assert_eq!(report.target_version, 1);
    assert!(report.initialized);
    assert!(report.admin_configured);
    assert!(report.treasury_asset_allowed);
    assert!(report.treasury_asset_decimals_configured);

    // The report is stable across repeated preflights: it describes the
    // contract's configuration, not the call or the caller.
    let repeat = ctx
        .executor
        .try_check_upgrade_compatibility(&1)
        .unwrap()
        .unwrap();
    assert_eq!(repeat, report);
}
