use ::token::{Token, TokenClient};
use payment_executor::{ContractAddresses, PaymentError, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

// Issue #889: payout finalization must be refused when the recipient does not
// resolve to a payable employee — no active salary commitment, or the company
// treasury / executor itself — before any transfer or state write.

const PERIOD: u32 = 1;

struct System<'a> {
    executor: PaymentExecutorClient<'a>,
    commitments: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
    treasury: Address,
}

fn mock_vk(env: &Env) -> VerificationKey {
    let g1 = BytesN::from_array(env, &[0u8; 64]);
    let g2 = BytesN::from_array(env, &[0u8; 128]);
    VerificationKey {
        alpha: g1.clone(),
        beta: g2.clone(),
        gamma: g2.clone(),
        delta: g2,
        ic: soroban_sdk::Vec::from_array(env, [g1.clone(), g1.clone(), g1]),
    }
}

fn setup(env: &Env) -> System<'_> {
    env.mock_all_auths();
    let executor_id = env.register(PaymentExecutor, ());
    let registry_id = env.register(PayrollRegistry, ());
    let commitment_id = env.register(SalaryCommitmentContract, ());
    let verifier_id = env.register(ProofVerifier, ());
    let token_id = env.register(Token, ());

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let commitments = SalaryCommitmentContractClient::new(env, &commitment_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    executor.initialize(&ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id.clone(),
    });
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));
    commitments.init_commitment_admin(&Address::generate(env));

    let treasury = Address::generate(env);
    let company_id = registry.register_company(&Address::generate(env), &treasury);
    executor.create_period(&company_id);
    executor.set_executor_admin(&Address::generate(env));
    executor.set_asset_decimals(&token_id, &7u32);
    let tax = Address::generate(env);
    executor.set_withholding_config(&company_id, &0u32, &0u32, &tax, &tax, &0i128, &0i128);
    token.mint(&treasury, &1_000_000i128);

    System { executor, commitments, token, company_id, treasury }
}

fn pay(env: &Env, sys: &System, recipient: &Address, seed: u8) -> Result<(), PaymentError> {
    sys.executor
        .try_execute_payment(
            &sys.company_id,
            recipient,
            &10_000i128,
            &BytesN::from_array(env, &[1u8; 64]),
            &BytesN::from_array(env, &[2u8; 128]),
            &BytesN::from_array(env, &[3u8; 64]),
            &BytesN::from_array(env, &[seed; 32]),
            &PERIOD,
        )
        .map(|_| ())
        .map_err(|e| e.expect("typed payment error"))
}

fn assert_nothing_moved(sys: &System, recipient: &Address) {
    assert_eq!(sys.token.balance(&sys.treasury), 1_000_000i128);
    assert_eq!(sys.executor.get_total_paid(&sys.company_id), 0);
    assert!(!sys.executor.is_paid(recipient, &PERIOD));
}

#[test]
fn recipient_without_commitment_is_rejected_without_side_effects() {
    let env = Env::default();
    let sys = setup(&env);
    let stranger = Address::generate(&env);

    assert_eq!(pay(&env, &sys, &stranger, 9), Err(PaymentError::RecipientUnresolved));
    assert_nothing_moved(&sys, &stranger);
}

#[test]
fn treasury_as_recipient_is_rejected() {
    let env = Env::default();
    let sys = setup(&env);
    let treasury = sys.treasury.clone();
    sys.commitments.store_commitment(&treasury, &BytesN::from_array(&env, &[7u8; 32]));

    assert_eq!(pay(&env, &sys, &treasury, 9), Err(PaymentError::RecipientUnresolved));
    assert_nothing_moved(&sys, &treasury);
}

#[test]
fn executor_contract_as_recipient_is_rejected() {
    let env = Env::default();
    let sys = setup(&env);
    let executor = sys.executor.address.clone();
    sys.commitments.store_commitment(&executor, &BytesN::from_array(&env, &[8u8; 32]));

    assert_eq!(pay(&env, &sys, &executor, 9), Err(PaymentError::RecipientUnresolved));
    assert_eq!(sys.executor.get_total_paid(&sys.company_id), 0);
}

#[test]
fn resolved_recipient_is_paid() {
    let env = Env::default();
    let sys = setup(&env);
    let employee = Address::generate(&env);
    sys.commitments.store_commitment(&employee, &BytesN::from_array(&env, &[5u8; 32]));

    assert_eq!(pay(&env, &sys, &employee, 9), Ok(()));
    assert!(sys.executor.is_paid(&employee, &PERIOD));
    assert_eq!(sys.token.balance(&employee), 10_000i128);
}

#[test]
fn rejected_attempt_does_not_burn_the_nullifier() {
    let env = Env::default();
    let sys = setup(&env);
    let employee = Address::generate(&env);

    // First attempt fails because the commitment is not registered yet...
    assert_eq!(pay(&env, &sys, &employee, 4), Err(PaymentError::RecipientUnresolved));
    // ...and once it is, the same proof nullifier is still usable.
    sys.commitments.store_commitment(&employee, &BytesN::from_array(&env, &[6u8; 32]));
    assert_eq!(pay(&env, &sys, &employee, 4), Ok(()));
}
