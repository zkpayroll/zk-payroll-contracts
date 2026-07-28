use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::SalaryCommitmentContract;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

// Issue #173: high-priority contract amount boundary tests.
//
// `execute_payment` accepts a raw `i128` amount that is folded into the
// Groth16 public inputs, transferred via the token contract, and summed into
// a per-company running total. These tests cover the amount boundaries that
// can cause financial correctness bugs: zero, negative, the maximum `i128`
// value, arithmetic overflow of the running total, and precision loss across
// non-round amounts.

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

/// Same wiring as `security_tests::setup_system`, but leaves the treasury
/// unfunded so each test can mint exactly the balance its amount-boundary
/// scenario needs (e.g. `i128::MAX`).
fn setup_system<'a>(
    env: &'a Env,
) -> (
    PaymentExecutorClient<'a>,
    PayrollRegistryClient<'a>,
    salary_commitment::SalaryCommitmentContractClient<'a>,
    TokenClient<'a>,
    u64,
    Address,
) {
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

    let admin = Address::generate(env);
    let treasury = Address::generate(env);
    let company_id = registry.register_company(&admin, &treasury);

    executor.create_period(&company_id);

    (
        executor,
        registry,
        commitment_client,
        token,
        company_id,
        treasury,
    )
}

/// Boundary: zero is a valid `i128` value and the contract does not reject
/// it. A zero-amount payment must not panic and must not move any funds.
#[test]
fn test_zero_amount_payment_succeeds_without_moving_funds() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[1u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);
    token.mint(&treasury, &1_000i128);

    executor.execute_payment(
        &company_id,
        &employee,
        &0i128,
        &BytesN::from_array(&env, &[1u8; 64]),
        &BytesN::from_array(&env, &[2u8; 128]),
        &BytesN::from_array(&env, &[3u8; 64]),
        &BytesN::from_array(&env, &[4u8; 32]),
        &1,
    );

    assert_eq!(token.balance(&treasury), 1_000i128);
    assert_eq!(token.balance(&employee), 0i128);
    assert_eq!(executor.get_total_paid(&company_id), 0i128);
    assert!(executor.is_paid(&employee, &1));
}

/// Boundary: `i128::MIN` is the extreme negative value (its own negation
/// overflows, so a naive `-amount` fix would panic differently). The
/// contract must reject it with the documented "non-negative" error.
#[test]
#[should_panic(expected = "Amount must be non-negative")]
fn test_negative_amount_payment_is_rejected() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[2u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);
    token.mint(&treasury, &1_000i128);

    executor.execute_payment(
        &company_id,
        &employee,
        &i128::MIN,
        &BytesN::from_array(&env, &[1u8; 64]),
        &BytesN::from_array(&env, &[2u8; 128]),
        &BytesN::from_array(&env, &[3u8; 64]),
        &BytesN::from_array(&env, &[4u8; 32]),
        &1,
    );
}

/// Boundary: the maximum representable `i128` amount must transfer and
/// record exactly, with no truncation.
#[test]
fn test_maximum_i128_amount_payment_succeeds() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[3u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);
    token.mint(&treasury, &i128::MAX);

    executor.execute_payment(
        &company_id,
        &employee,
        &i128::MAX,
        &BytesN::from_array(&env, &[1u8; 64]),
        &BytesN::from_array(&env, &[2u8; 128]),
        &BytesN::from_array(&env, &[3u8; 64]),
        &BytesN::from_array(&env, &[4u8; 32]),
        &1,
    );

    assert_eq!(token.balance(&employee), i128::MAX);
    assert_eq!(token.balance(&treasury), 0i128);
    assert_eq!(executor.get_total_paid(&company_id), i128::MAX);
}

/// Overflow-prone: `get_total_paid` accumulates every payment for a company
/// via plain `i128` addition with no upper bound of its own. A treasury can
/// be fully drained and re-minted, so the running total can legitimately be
/// pushed past `i128::MAX` across two payments — this must panic on
/// overflow rather than silently wrap to a negative "total paid".
#[test]
#[should_panic(expected = "overflow")]
fn test_total_paid_overflow_panics_after_treasury_replenishment() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[4u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    token.mint(&treasury, &i128::MAX);
    executor.execute_payment(
        &company_id,
        &employee,
        &i128::MAX,
        &BytesN::from_array(&env, &[1u8; 64]),
        &BytesN::from_array(&env, &[2u8; 128]),
        &BytesN::from_array(&env, &[3u8; 64]),
        &BytesN::from_array(&env, &[4u8; 32]),
        &1,
    );
    assert_eq!(executor.get_total_paid(&company_id), i128::MAX);

    // Treasury is now drained to 0; replenishing it and paying again is a
    // legitimate flow that pushes the running total past `i128::MAX`.
    token.mint(&treasury, &100i128);
    executor.create_period(&company_id);
    executor.execute_payment(
        &company_id,
        &employee,
        &100i128,
        &BytesN::from_array(&env, &[5u8; 64]),
        &BytesN::from_array(&env, &[6u8; 128]),
        &BytesN::from_array(&env, &[7u8; 64]),
        &BytesN::from_array(&env, &[8u8; 32]),
        &2,
    );
}

/// Precision-sensitive: non-round, differently-sized amounts across several
/// payments must sum and transfer exactly — no rounding or truncation drift
/// anywhere in the `i128` arithmetic path.
#[test]
fn test_precision_preserved_across_multiple_non_round_payments() {
    let env = Env::default();
    let (executor, registry, commitment_client, token, company_id, treasury) = setup_system(&env);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[5u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    let payment_amounts: [i128; 3] = [1, 333_333_333, 999_999_937];
    let mut expected_total: i128 = 0;

    for (i, amount) in payment_amounts.into_iter().enumerate() {
        expected_total += amount;
        token.mint(&treasury, &amount);

        if i > 0 {
            executor.create_period(&company_id);
        }

        let seed = 10u8 + i as u8;
        executor.execute_payment(
            &company_id,
            &employee,
            &amount,
            &BytesN::from_array(&env, &[seed; 64]),
            &BytesN::from_array(&env, &[seed; 128]),
            &BytesN::from_array(&env, &[seed; 64]),
            &BytesN::from_array(&env, &[seed; 32]),
            &((i + 1) as u32),
        );
    }

    assert_eq!(executor.get_total_paid(&company_id), expected_total);
    assert_eq!(token.balance(&employee), expected_total);
}
