/// Confidential memo hash registry tests - issue #347.
///
/// # Coverage
/// | Test | Scenario |
/// |------|----------|
/// | `test_register_and_get_memo_hash_success` | Full happy path: register, get |
/// | `test_register_zero_hash_rejected` | `register_memo_hash` panics on the all-zero digest |
/// | `test_register_empty_period_rejected` | `register_memo_hash` panics on an empty period symbol |
/// | `test_register_duplicate_batch_rejected` | Re-registering a memo hash for the same (employer, period, batch_id) panics |
/// | `test_register_by_non_admin_rejected` | Only the admin may register a memo hash |
/// | `test_get_unregistered_memo_hash_rejected` | Querying an unregistered (employer, period, batch_id) fails |
/// | `test_memo_hash_scoped_to_employer` | The same period and batch_id for a different employer is an independent slot |
/// | `test_memo_hash_scoped_to_period` | The same employer and batch_id for a different period is an independent slot |
/// | `test_memo_hash_scoped_to_batch_id` | The same employer and period with a different batch_id is an independent slot |
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{symbol_short, testutils::Address as _, Address, BytesN, Env, Symbol, Vec};
use token::{Token, TokenClient};

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
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

struct Ctx {
    env: Env,
    admin: Address,
    payroll_id: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);
    let payroll_id = env.register_contract(None, Payroll);

    let payroll_client = PayrollClient::new(&env, &payroll_id);
    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    let _token_client = TokenClient::new(&env, &token_id);

    Ctx {
        env,
        admin,
        payroll_id,
    }
}

fn batch_id(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn memo_hash(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0xABu8; 32];
    arr[31] = seed;
    BytesN::from_array(env, &arr)
}

#[test]
fn test_register_and_get_memo_hash_success() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);
    let hash = memo_hash(&ctx.env, 1);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch, &hash);

    assert_eq!(
        ctx.payroll().get_memo_hash(&employer, &period, &batch),
        hash
    );
}

#[test]
#[should_panic(expected = "Digest cannot be all-zero bytes")]
fn test_register_zero_hash_rejected() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);
    let zero = BytesN::from_array(&ctx.env, &[0u8; 32]);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch, &zero);
}

#[test]
fn test_register_empty_period_rejected() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let empty_period = Symbol::new(&ctx.env, "");
    let batch = batch_id(&ctx.env, 1);
    let hash = memo_hash(&ctx.env, 1);

    let result =
        ctx.payroll()
            .try_register_memo_hash(&ctx.admin, &employer, &empty_period, &batch, &hash);
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Memo hash already registered for this batch")]
fn test_register_duplicate_batch_rejected() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);
    let hash = memo_hash(&ctx.env, 1);
    let other_hash = memo_hash(&ctx.env, 2);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch, &hash);
    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch, &other_hash);
}

#[test]
fn test_register_by_non_admin_rejected() {
    let ctx = setup();
    let stranger = Address::generate(&ctx.env);
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);
    let hash = memo_hash(&ctx.env, 1);

    let result = ctx
        .payroll()
        .try_register_memo_hash(&stranger, &employer, &period, &batch, &hash);
    assert!(result.is_err());
}

#[test]
fn test_get_unregistered_memo_hash_rejected() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);

    let result = ctx.payroll().try_get_memo_hash(&employer, &period, &batch);
    assert!(result.is_err());
}

#[test]
fn test_memo_hash_scoped_to_employer() {
    let ctx = setup();
    let employer_a = Address::generate(&ctx.env);
    let employer_b = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch = batch_id(&ctx.env, 1);
    let hash_a = memo_hash(&ctx.env, 1);
    let hash_b = memo_hash(&ctx.env, 2);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer_a, &period, &batch, &hash_a);
    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer_b, &period, &batch, &hash_b);

    assert_eq!(
        ctx.payroll().get_memo_hash(&employer_a, &period, &batch),
        hash_a
    );
    assert_eq!(
        ctx.payroll().get_memo_hash(&employer_b, &period, &batch),
        hash_b
    );
}

#[test]
fn test_memo_hash_scoped_to_period() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period_a = symbol_short!("p2026m01");
    let period_b = symbol_short!("p2026m02");
    let batch = batch_id(&ctx.env, 1);
    let hash_a = memo_hash(&ctx.env, 1);
    let hash_b = memo_hash(&ctx.env, 2);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period_a, &batch, &hash_a);
    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period_b, &batch, &hash_b);

    assert_eq!(
        ctx.payroll().get_memo_hash(&employer, &period_a, &batch),
        hash_a
    );
    assert_eq!(
        ctx.payroll().get_memo_hash(&employer, &period_b, &batch),
        hash_b
    );
}

#[test]
fn test_memo_hash_scoped_to_batch_id() {
    let ctx = setup();
    let employer = Address::generate(&ctx.env);
    let period = symbol_short!("p2026m01");
    let batch_a = batch_id(&ctx.env, 1);
    let batch_b = batch_id(&ctx.env, 2);
    let hash_a = memo_hash(&ctx.env, 1);
    let hash_b = memo_hash(&ctx.env, 2);

    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch_a, &hash_a);
    ctx.payroll()
        .register_memo_hash(&ctx.admin, &employer, &period, &batch_b, &hash_b);

    assert_eq!(
        ctx.payroll().get_memo_hash(&employer, &period, &batch_a),
        hash_a
    );
    assert_eq!(
        ctx.payroll().get_memo_hash(&employer, &period, &batch_b),
        hash_b
    );
}
