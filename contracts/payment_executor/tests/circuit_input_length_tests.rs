//! Issue #821: the executor validates the circuit input length before
//! proof verification.
//!
//! `execute_payment` builds the v1 public inputs `[commitment, amount]` and
//! asks the verifier to `validate_public_inputs` before `verify`. When the
//! verifier's stored key expects a different count (a circuit or schema
//! version mismatch), the payment fails with the typed
//! `PaymentError::InvalidPublicInputLength` instead of the generic
//! "Invalid payment proof" panic, before any transfer or state write.

use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

/// Stand-in for a verifier deployed before issue #821: it has `verify` but
/// no `validate_public_inputs` entrypoint.
mod legacy_verifier {
    use proof_verifier::Groth16Proof;
    use soroban_sdk::{contract, contractimpl, BytesN, Env, Vec};

    #[contract]
    pub struct LegacyVerifier;

    #[contractimpl]
    impl LegacyVerifier {
        pub fn verify(_env: Env, _proof: Groth16Proof, _public_inputs: Vec<BytesN<32>>) -> bool {
            true
        }
    }
}

const SALARY: i128 = 1_000;
const FUNDING: i128 = 10_000;

struct Fixture<'a> {
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    commitments: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
    treasury: Address,
}

enum Verifier {
    /// Current verifier with a key holding `ic_len` IC points, so it
    /// expects `ic_len - 1` public inputs.
    Current { ic_len: u32 },
    /// Current verifier, never initialized with a key.
    Uninitialized,
    /// Pre-#821 verifier without `validate_public_inputs`.
    Legacy,
}

fn vk_with_ic_len(env: &Env, ic_len: u32) -> VerificationKey {
    let mut ic = Vec::new(env);
    for _ in 0..ic_len {
        ic.push_back(BytesN::from_array(env, &[0u8; 64]));
    }
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic,
    }
}

fn setup(env: &Env, verifier: Verifier) -> Fixture<'_> {
    env.mock_all_auths();

    let executor_id = env.register(PaymentExecutor, ());
    let registry_id = env.register(PayrollRegistry, ());
    let commitment_id = env.register(SalaryCommitmentContract, ());
    let token_id = env.register(Token, ());
    let verifier_id = match verifier {
        Verifier::Legacy => env.register(legacy_verifier::LegacyVerifier, ()),
        Verifier::Uninitialized => env.register(ProofVerifier, ()),
        Verifier::Current { ic_len } => {
            let id = env.register(ProofVerifier, ());
            let client = ProofVerifierClient::new(env, &id);
            client.init_verifier_admin(&Address::generate(env));
            client.initialize_verifier(&vk_with_ic_len(env, ic_len));
            id
        }
    };

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitments = SalaryCommitmentContractClient::new(env, &commitment_id);
    let token = TokenClient::new(env, &token_id);

    executor.initialize(&ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id.clone(),
    });
    commitments.init_commitment_admin(&Address::generate(env));
    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&token_id, &7u32);

    let treasury = Address::generate(env);
    let company_id = registry.register_company(&Address::generate(env), &treasury);
    let tax = Address::generate(env);
    executor.set_withholding_config(&company_id, &0u32, &0u32, &tax, &tax, &0i128, &0i128);
    executor.create_period(&company_id);
    token.mint(&treasury, &FUNDING);

    Fixture {
        executor,
        registry,
        commitments,
        token,
        company_id,
        treasury,
    }
}

fn employee(env: &Env, f: &Fixture, seed: u8) -> Address {
    let employee = Address::generate(env);
    let commitment = BytesN::from_array(env, &[seed; 32]);
    f.commitments.store_commitment(&employee, &commitment);
    f.registry
        .add_employee(&f.company_id, &employee, &commitment);
    employee
}

fn try_pay(
    env: &Env,
    f: &Fixture,
    who: &Address,
    seed: u8,
) -> Result<
    Result<payment_executor::PaymentRecord, soroban_sdk::ConversionError>,
    Result<PaymentError, soroban_sdk::InvokeError>,
> {
    f.executor.try_execute_payment(
        &f.company_id,
        who,
        &SALARY,
        &BytesN::from_array(env, &[seed; 64]),
        &BytesN::from_array(env, &[seed; 128]),
        &BytesN::from_array(env, &[seed; 64]),
        &BytesN::from_array(env, &[seed; 32]),
        &1,
    )
}

/// Asserts that nothing was paid, recorded, or counted.
fn assert_untouched(f: &Fixture, who: &Address) {
    assert_eq!(f.executor.get_total_paid(&f.company_id), 0);
    assert_eq!(f.token.balance(&f.treasury), FUNDING);
    assert_eq!(f.token.balance(who), 0);
    assert!(!f.executor.is_paid(who, &1));
    assert_eq!(
        f.executor
            .get_period(&f.company_id, &1)
            .unwrap()
            .payment_count,
        0
    );
}

// --- success -------------------------------------------------------------

/// The v1 key (`ic.len() == 3`) matches the executor's two inputs, so the
/// payment goes through.
#[test]
fn test_matching_input_length_pays() {
    let env = Env::default();
    let f = setup(&env, Verifier::Current { ic_len: 3 });
    let alice = employee(&env, &f, 1);

    try_pay(&env, &f, &alice, 10).unwrap().unwrap();

    assert!(f.executor.is_paid(&alice, &1));
    assert_eq!(f.token.balance(&alice), SALARY);
    assert_eq!(f.executor.get_total_paid(&f.company_id), SALARY);
}

// --- rejected ------------------------------------------------------------

/// A verifier keyed for the legacy three-output circuit
/// (`circuits/payment.circom`: commitment, nullifier, recipient hash) needs
/// one input more than the executor supplies. This returns the typed error,
/// not "Invalid payment proof".
#[test]
fn test_verifier_expecting_more_inputs_rejects_with_typed_error() {
    let env = Env::default();
    let f = setup(&env, Verifier::Current { ic_len: 4 });
    let alice = employee(&env, &f, 2);

    assert_eq!(
        try_pay(&env, &f, &alice, 20).unwrap_err().unwrap(),
        PaymentError::InvalidPublicInputLength
    );
    assert_untouched(&f, &alice);
}

/// A key expecting fewer inputs than the executor supplies.
#[test]
fn test_verifier_expecting_fewer_inputs_rejects_with_typed_error() {
    let env = Env::default();
    let f = setup(&env, Verifier::Current { ic_len: 2 });
    let alice = employee(&env, &f, 3);

    assert_eq!(
        try_pay(&env, &f, &alice, 30).unwrap_err().unwrap(),
        PaymentError::InvalidPublicInputLength
    );
    assert_untouched(&f, &alice);
}

/// A batch against a mismatched key is rejected before any row is paid.
#[test]
fn test_batch_against_mismatched_key_rejects_whole_batch() {
    let env = Env::default();
    let f = setup(&env, Verifier::Current { ic_len: 4 });
    let alice = employee(&env, &f, 4);
    let bob = employee(&env, &f, 5);

    let row = |seed: u8| {
        (
            BytesN::<64>::from_array(&env, &[seed; 64]),
            BytesN::<128>::from_array(&env, &[seed; 128]),
            BytesN::<64>::from_array(&env, &[seed; 64]),
            BytesN::<32>::from_array(&env, &[seed; 32]),
        )
    };
    let (a1, b1, c1, n1) = row(40);
    let (a2, b2, c2, n2) = row(41);

    let err = f
        .executor
        .try_execute_batch_payroll(
            &f.company_id,
            &Vec::from_array(&env, [alice.clone(), bob.clone()]),
            &Vec::from_array(&env, [SALARY, SALARY]),
            &Vec::from_array(&env, [a1, a2]),
            &Vec::from_array(&env, [b1, b2]),
            &Vec::from_array(&env, [c1, c2]),
            &Vec::from_array(&env, [n1, n2]),
            &1,
        )
        .unwrap_err()
        .unwrap();

    assert_eq!(err, PaymentError::InvalidPublicInputLength);
    assert_untouched(&f, &alice);
    assert!(!f.executor.is_paid(&bob, &1));
}

// --- boundary / compatibility ----------------------------------------------

/// Boundary: a key expecting zero inputs (`ic.len() == 1`) is still a
/// mismatch for the executor's two.
#[test]
fn test_verifier_expecting_no_inputs_rejects_with_typed_error() {
    let env = Env::default();
    let f = setup(&env, Verifier::Current { ic_len: 1 });
    let alice = employee(&env, &f, 6);

    assert_eq!(
        try_pay(&env, &f, &alice, 60).unwrap_err().unwrap(),
        PaymentError::InvalidPublicInputLength
    );
    assert_untouched(&f, &alice);
}

/// An uninitialized verifier is not reported as a length problem. It keeps
/// failing through `verify`, exactly as before this change.
#[test]
fn test_uninitialized_verifier_is_not_reported_as_length_mismatch() {
    let env = Env::default();
    let f = setup(&env, Verifier::Uninitialized);
    let alice = employee(&env, &f, 7);

    let result = try_pay(&env, &f, &alice, 70);
    assert!(result.is_err());
    assert!(!matches!(
        result,
        Err(Ok(PaymentError::InvalidPublicInputLength))
    ));
    assert_untouched(&f, &alice);
}

/// Backward compatibility: a verifier deployed before this change has no
/// `validate_public_inputs`. The executor falls back to `verify` and the
/// payment still succeeds.
#[test]
fn test_legacy_verifier_without_validation_entrypoint_still_pays() {
    let env = Env::default();
    let f = setup(&env, Verifier::Legacy);
    let alice = employee(&env, &f, 8);

    try_pay(&env, &f, &alice, 80).unwrap().unwrap();

    assert!(f.executor.is_paid(&alice, &1));
    assert_eq!(f.token.balance(&alice), SALARY);
}

/// The error is a bare, stable code with no commitment or amount attached.
#[test]
fn test_error_code_is_stable() {
    assert_eq!(PaymentError::InvalidPublicInputLength as u32, 21);
}
