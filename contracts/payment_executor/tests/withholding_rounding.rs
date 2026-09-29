use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

// Issue #547: multi-asset rounding characterisation tests.
//
// `validate_and_compute_withholding` (payment_executor/src/lib.rs:561-564)
// computes each withholding leg with a truncating integer division:
//
//     let income_tax = gross_amount * config.income_tax_bps as i128 / 10_000;
//     let social_tax = gross_amount * config.social_tax_bps as i128 / 10_000;
//     let net_amount = gross_amount - income_tax - social_tax;
//
// Rust truncates toward zero, so for a non-negative gross each tax leg always
// rounds DOWN and the employee therefore always rounds UP. These tests pin that
// direction, and pin the conservation property that follows from `net_amount`
// being derived by subtraction rather than by computing
// `gross * (10_000 - total_bps) / 10_000`:
//
//     net + income_tax + social_tax == gross,  exactly,  always.
//
// The truncation remainder is therefore never minted and never lost: it stays
// behind in the treasury. These are characterisation tests only - they document
// existing behaviour and assert no change to it.
//
// SCOPE NOTE ("multi-asset"): the payout path is deliberately single-asset.
// `ContractAddresses.token` is the only asset that may be allowlisted or
// transferred (see docs/cross-asset-treasury.md), and `set_asset_allowed`
// panics on any other address. A multi-asset payroll is therefore modelled as
// N separate single-asset batches, never one batch mixing assets. `treasury_isolation`
// tracks per-(company, asset) balances but performs no division at all. As a
// result there is no cross-asset shared-denominator rounding to test; the only
// rounding an operator can observe at payout time is the per-asset bps split
// below, and these fixtures parameterise the asset's decimal precision to show
// that the decimal-precision guard does not perturb it.

/// Decimal precision configured for the treasury asset in these tests.
///
/// 7 matches Stellar XLM. It is also the value that makes the
/// `max_amount_for_decimals / 1_000_000_000` floor in `execute_payment`
/// collapse to 0 (fixture E), so with 7 decimals that guard is inert and the
/// only rounding in play is the withholding bps division.
const TREASURY_DECIMALS: u32 = 7;

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: soroban_sdk::Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

/// Per-test context: the executor plus the two withholding recipients, which
/// must be distinct so the tests can prove each leg is routed independently.
struct Ctx<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitment: salary_commitment::SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
    treasury: Address,
    income_tax_recipient: Address,
    social_tax_recipient: Address,
}

/// Build a wired-up system with the treasury asset's decimals configured.
///
/// `set_executor_admin` must run before `set_asset_decimals` and
/// `set_withholding_config`: both read `ExecutorAdmin` and panic with
/// "Executor admin not set" if it is absent. `set_asset_decimals` is required
/// because `execute_payment` returns `AssetDecimalsMissing` when the asset has
/// no configured precision. This mirrors the working `Readiness::Ready`
/// pattern in `upgrade_compatibility_tests.rs:116-119`.
fn setup_system<'a>(env: &'a Env, decimals: u32) -> Ctx<'a> {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitment_client =
        salary_commitment::SalaryCommitmentContractClient::new(env, &commitment_id);
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

    // Issue #538 requires this; it is also the prerequisite for
    // `set_asset_decimals` below.
    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&addresses.token, &decimals);

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);
    executor.create_period(&company_id).unwrap();

    Ctx {
        executor,
        registry,
        commitment: commitment_client,
        token,
        company_id,
        treasury,
        // Deliberately distinct: a shared address would mask a leg that is
        // transferred to the wrong recipient.
        income_tax_recipient: Address::generate(env),
        social_tax_recipient: Address::generate(env),
    }
}

/// Set the per-company withholding rates. Both caps are 0, which disables the
/// gross cap and the net floor (both are only enforced when > 0), so these
/// tests isolate the bps division from unrelated validation.
fn set_withholding(ctx: &Ctx, income_tax_bps: u32, social_tax_bps: u32) {
    ctx.executor
        .set_withholding_config(
            &ctx.company_id,
            &income_tax_bps,
            &social_tax_bps,
            &ctx.income_tax_recipient,
            &ctx.social_tax_recipient,
            &0i128,
            &0i128,
        )
        .expect("withholding config is valid: combined bps < 10_000");
}

/// Enrol a fresh employee in the company and pay them `gross`, funding the
/// treasury with exactly `gross` so the post-payment treasury balance is a
/// direct readout of how much was actually disbursed.
fn pay(ctx: &Ctx, env: &Env, gross: i128, seed: u8) {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    ctx.commitment.store_commitment(&employee, &commitment);
    ctx.registry
        .add_employee(&ctx.company_id, &employee, &commitment);
    ctx.token.mint(&ctx.treasury, &gross);

    ctx.executor
        .execute_payment(
            &ctx.company_id,
            &employee,
            &gross,
            &BytesN::from_array(env, &[seed; 64]),
            &BytesN::from_array(env, &[seed; 128]),
            &BytesN::from_array(env, &[seed; 64]),
            &BytesN::from_array(env, &[seed; 32]),
            &1,
        )
        .expect("payment succeeds: asset is configured, period is open, mock proof verifies");
}

/// Fixture A - happy path with clean division, no remainder anywhere.
///
/// gross = 1_000_000_000, income 2000 bps, social 1000 bps:
///   income_tax = 1_000_000_000 * 2_000 / 10_000 = 200_000_000  (exact)
///   social_tax = 1_000_000_000 * 1_000 / 10_000 = 100_000_000  (exact)
///   net        = 1_000_000_000 - 200_000_000 - 100_000_000  = 700_000_000
///   700_000_000 + 200_000_000 + 100_000_000                = 1_000_000_000
#[test]
fn exact_division_happy_path_disburses_gross_in_full() {
    let env = Env::default();
    let ctx = setup_system(&env, TREASURY_DECIMALS);
    set_withholding(&ctx, 2_000, 1_000);

    let gross = 1_000_000_000i128;
    pay(&ctx, &env, gross, 1);

    assert_eq!(ctx.token.balance(&ctx.treasury), 0, "gross fully disbursed");
    assert_eq!(ctx.token.balance(&ctx.income_tax_recipient), 200_000_000);
    assert_eq!(ctx.token.balance(&ctx.social_tax_recipient), 100_000_000);

    // Conservation: the two tax legs plus the implied net account for exactly
    // the gross, with no remainder created or destroyed. (`pay` funds the
    // treasury with exactly `gross`, so a zero treasury balance proves the
    // employee received the remaining 700_000_000.)
    assert_eq!(200_000_000 + 100_000_000 + 700_000_000, gross);
    assert_eq!(
        ctx.executor.get_total_paid(&ctx.company_id),
        gross,
        "executor records the gross, not the post-withholding net"
    );
}

/// Fixture B - division is inexact, so both legs truncate and the remainder
/// stays in the treasury.
///
/// gross = 333_333_333, income 1500 bps, social 750 bps:
///   income_tax = 333_333_333 * 1_500 / 10_000
///              = 499_999_999_500 / 10_000 = 49_999_999.95
///              -> 49_999_999   (remainder 9_500)
///   social_tax = 333_333_333 * 750 / 10_000
///              = 249_999_999_750 / 10_000 = 24_999_999.975
///              -> 24_999_999   (remainder 9_750)
///   net        = 333_333_333 - 49_999_999 - 24_999_999 = 258_333_335
///   legs sum   = 258_333_335 + 49_999_999 + 24_999_999 = 333_333_333
///
/// Both legs round DOWN. The ideal net was 333_333_333 * 0.775 = 258_333_332.9,
/// so the employee is over-paid by ~2.1 units - the remainder is retained by
/// the company, never burned.
#[test]
fn inexact_division_rounds_each_tax_leg_down_and_retains_remainder() {
    let env = Env::default();
    let ctx = setup_system(&env, TREASURY_DECIMALS);
    set_withholding(&ctx, 1_500, 750);

    let gross = 333_333_333i128;
    pay(&ctx, &env, gross, 2);

    // Truncated, not rounded: both are strictly less than the exact value.
    assert_eq!(ctx.token.balance(&ctx.income_tax_recipient), 49_999_999);
    assert_eq!(ctx.token.balance(&ctx.social_tax_recipient), 24_999_999);

    // Conservation still holds exactly - the three legs sum to the gross, so
    // the 19_250 combined remainder is left in the treasury rather than lost.
    let net = gross - 49_999_999 - 24_999_999;
    assert_eq!(net, 258_333_335);
    assert_eq!(net + 49_999_999 + 24_999_999, gross);
}

/// Fixture C - boundary: a single stroop against a non-zero rate. This is the
/// maximum-relative-error case the bps division can produce.
///
/// gross = 1, income 1 bps, social 1 bps:
///   income_tax = 1 * 1 / 10_000 = 0.0001 -> 0   (remainder 1)
///   social_tax = 1 * 1 / 10_000 = 0.0001 -> 0   (remainder 1)
///   net        = 1 - 0 - 0 = 1
///
/// 100% of each tax is lost to truncation, but the error is bounded below one
/// stroop per leg and always favours the employee. Both tax transfers are
/// skipped entirely by the `if income_tax > 0` / `if social_tax > 0` guards in
/// `execute_payment`, so the recipients are left at exactly zero.
#[test]
fn single_stroop_gross_rounds_both_tax_legs_to_zero() {
    let env = Env::default();
    let ctx = setup_system(&env, TREASURY_DECIMALS);
    set_withholding(&ctx, 1, 1);

    let gross = 1i128;
    pay(&ctx, &env, gross, 3);

    // Both tax recipients are left at exactly zero - the guards at
    // payment_executor/src/lib.rs:892-905 skip the transfers entirely.
    assert_eq!(ctx.token.balance(&ctx.income_tax_recipient), 0);
    assert_eq!(ctx.token.balance(&ctx.social_tax_recipient), 0);

    // The single stroop is not withheld at all: net = 1 - 0 - 0 = 1, so the
    // whole amount is paid out to the employee and the treasury is drained.
    // Conservation still holds exactly (1 + 0 + 0 == gross).
    assert_eq!(ctx.token.balance(&ctx.treasury), 0);

    // Recorded as paid, and the recorded total is the gross.
    assert_eq!(ctx.executor.get_total_paid(&ctx.company_id), gross);
}

/// Fixture D - boundary: a zero-rate leg alongside a non-zero leg. The zero
/// bps leg must contribute exactly 0 and must not perturb the other leg.
///
/// gross = 1_000_001, income 0 bps, social 2500 bps:
///   income_tax = 1_000_001 * 0 / 10_000   = 0                (exact)
///   social_tax = 1_000_001 * 2_500 / 10_000
///              = 2_500_002_500 / 10_000 = 250_000.25
///              -> 250_000                (remainder 2_500)
///   net        = 1_000_001 - 0 - 250_000 = 750_001
#[test]
fn zero_rate_leg_contributes_nothing_and_does_not_perturb_other_leg() {
    let env = Env::default();
    let ctx = setup_system(&env, TREASURY_DECIMALS);
    set_withholding(&ctx, 0, 2_500);

    let gross = 1_000_001i128;
    pay(&ctx, &env, gross, 4);

    assert_eq!(ctx.token.balance(&ctx.income_tax_recipient), 0);
    assert_eq!(ctx.token.balance(&ctx.social_tax_recipient), 250_000);

    let net = gross - 0 - 250_000;
    assert_eq!(net, 750_001);
    assert_eq!(net + 0 + 250_000, gross);
}

/// Fixture E - boundary: the asset's decimal precision does not change the
/// withholding arithmetic, but it does decide whether a small amount is
/// payable at all.
///
/// `execute_payment` (payment_executor/src/lib.rs:876-879) computes:
///     let max_amount_for_decimals = 10i128.pow(asset_decimals);
///     if amount > 0 && amount < max_amount_for_decimals / 1_000_000_000 { reject }
///
/// `10^7 / 1_000_000_000 == 0`, so for a 7-decimal asset the threshold is 0 and
/// the guard can never fire - it is completely inert. By contrast
/// `10^12 / 1_000_000_000 == 1_000`, so a 12-decimal asset rejects any positive
/// amount below 1_000. Stellar XLM is 7 decimals, so the inert case is the
/// realistic one.
///
/// This documents the current threshold. It is a characterisation test: the
/// asymmetry is pre-existing and is NOT changed here.
#[test]
fn decimal_precision_gates_minimum_amount_but_not_withholding_arithmetic() {
    // --- 7 decimals: floor is 10^7 / 1_000_000_000 = 0, guard is inert. ---
    let env7 = Env::default();
    let ctx7 = setup_system(&env7, 7);
    set_withholding(&ctx7, 1_000, 500);

    // Amount 1 is below the 12-decimal threshold but must be accepted here.
    pay(&ctx7, &env7, 1_000i128, 5);
    assert_eq!(ctx7.token.balance(&ctx7.income_tax_recipient), 100);
    assert_eq!(ctx7.token.balance(&ctx7.social_tax_recipient), 50);

    // --- 12 decimals: floor is 10^12 / 1_000_000_000 = 1_000, guard is live. ---
    let env12 = Env::default();
    let ctx12 = setup_system(&env12, 12);
    set_withholding(&ctx12, 1_000, 500);

    let employee = Address::generate(&env12);
    let commitment = BytesN::from_array(&env12, &[6u8; 32]);
    ctx12.commitment.store_commitment(&employee, &commitment);
    ctx12
        .registry
        .add_employee(&ctx12.company_id, &employee, &commitment);
    ctx12.token.mint(&ctx12.treasury, &1_000i128);

    // Amount 1 sits below the 1_000 threshold and must be rejected before any
    // transfer occurs - the withholding split is never even reached.
    let result = ctx12.executor.try_execute_payment(
        &ctx12.company_id,
        &employee,
        &1i128,
        &BytesN::from_array(&env12, &[6u8; 64]),
        &BytesN::from_array(&env12, &[6u8; 128]),
        &BytesN::from_array(&env12, &[6u8; 64]),
        &BytesN::from_array(&env12, &[6u8; 32]),
        &1,
    );
    assert_eq!(
        result.unwrap_err().unwrap(),
        payment_executor::PaymentError::AssetDecimalsMismatch
    );
    assert_eq!(
        ctx12.token.balance(&ctx12.treasury),
        1_000,
        "no funds moved"
    );

    // Exactly at the threshold is accepted, and the bps split is unchanged by
    // the decimal precision: 1_000 * 1_000 / 10_000 = 100 exactly.
    ctx12
        .executor
        .execute_payment(
            &ctx12.company_id,
            &employee,
            &1_000i128,
            &BytesN::from_array(&env12, &[7u8; 64]),
            &BytesN::from_array(&env12, &[7u8; 128]),
            &BytesN::from_array(&env12, &[7u8; 64]),
            &BytesN::from_array(&env12, &[7u8; 32]),
            &1,
        )
        .expect("1_000 sits exactly at the 12-decimal threshold and is payable");
    assert_eq!(ctx12.token.balance(&ctx12.income_tax_recipient), 100);
    assert_eq!(ctx12.token.balance(&ctx12.social_tax_recipient), 50);
}
