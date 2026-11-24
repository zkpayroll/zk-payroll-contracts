//! Payout retry behavior when the token contract is paused (issue #893).
//!
//! A paused token rejects transfers. These tests pin what that means for the
//! executor: the payout fails as a whole, nothing is recorded (no paid flag, no
//! total, no consumed nullifier, no balance change), and the very same payout
//! can be retried once the token resumes. No salary data appears in any
//! assertion beyond the amounts the test itself supplies.

use crate::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Vec};

#[contracttype]
#[derive(Clone)]
enum TokenKey {
    Paused,
    Balance(Address),
}

/// A minimal token whose transfers can be paused, standing in for an asset
/// contract that has been halted by its issuer.
#[contract]
struct PausableToken;

#[contractimpl]
impl PausableToken {
    pub fn set_paused(env: Env, paused: bool) {
        env.storage().instance().set(&TokenKey::Paused, &paused);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&TokenKey::Balance(to), &(current + amount));
    }

    /// Matches the decimals configured on the executor in `setup`, so the
    /// executor's on-chain decimal precision check passes.
    pub fn decimals(_env: Env) -> u32 {
        7
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let paused: bool = env
            .storage()
            .instance()
            .get(&TokenKey::Paused)
            .unwrap_or(false);
        if paused {
            panic!("token is paused");
        }
        let from_balance = Self::balance(env.clone(), from.clone());
        if from_balance < amount {
            panic!("insufficient balance");
        }
        let to_balance = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&TokenKey::Balance(from), &(from_balance - amount));
        env.storage()
            .persistent()
            .set(&TokenKey::Balance(to), &(to_balance + amount));
    }
}

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

struct Fixture {
    env: Env,
    executor_id: Address,
    token_id: Address,
    company_id: u64,
    treasury: Address,
    employee: Address,
}

impl Fixture {
    fn client(&self) -> PaymentExecutorClient<'_> {
        PaymentExecutorClient::new(&self.env, &self.executor_id)
    }

    fn token(&self) -> PausableTokenClient<'_> {
        PausableTokenClient::new(&self.env, &self.token_id)
    }
}

fn setup() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register(PayrollRegistry, ());
    let commitment_id = env.register(SalaryCommitmentContract, ());
    let verifier_id = env.register(ProofVerifier, ());
    let token_id = env.register(PausableToken, ());

    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(&env));
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(&env));

    let executor_id = env.register(PaymentExecutor, ());
    let client = PaymentExecutorClient::new(&env, &executor_id);
    client.initialize(&ContractAddresses {
        registry: registry_id.clone(),
        commitment: commitment_id.clone(),
        verifier: verifier_id,
        token: token_id.clone(),
    });

    let registry_client = PayrollRegistryClient::new(&env, &registry_id);
    let token = PausableTokenClient::new(&env, &token_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);

    let company_id = registry_client.register_company(&admin, &treasury);
    commitment_client.store_commitment(&employee, &commitment);
    registry_client.add_employee(&company_id, &employee, &commitment);
    token.mint(&treasury, &10_000);

    let _ = client.create_period(&company_id);

    // execute_payment requires an executor admin, asset decimals and a
    // withholding config; use a zero-rate config so the full amount is paid.
    client.set_executor_admin(&Address::generate(&env));
    client.set_asset_decimals(&token_id, &7u32);
    let tax_addr = Address::generate(&env);
    client.set_withholding_config(
        &company_id,
        &0u32,
        &0u32,
        &tax_addr,
        &tax_addr,
        &0i128,
        &0i128,
    );

    Fixture {
        env,
        executor_id,
        token_id,
        company_id,
        treasury,
        employee,
    }
}

fn proof(env: &Env) -> (BytesN<64>, BytesN<128>, BytesN<64>, BytesN<32>) {
    (
        BytesN::from_array(env, &[1u8; 64]),
        BytesN::from_array(env, &[2u8; 128]),
        BytesN::from_array(env, &[3u8; 64]),
        BytesN::from_array(env, &[4u8; 32]),
    )
}

#[test]
fn test_payout_fails_atomically_while_the_token_is_paused() {
    let f = setup();
    let (a, b, c, nullifier) = proof(&f.env);

    f.token().set_paused(&true);
    let result = f.client().try_execute_payment(
        &f.company_id,
        &f.employee,
        &1000,
        &a,
        &b,
        &c,
        &nullifier,
        &1,
    );

    assert!(result.is_err());
    assert!(!f.client().is_paid(&f.employee, &1));
    assert_eq!(f.client().get_total_paid(&f.company_id), 0);
    assert_eq!(f.token().balance(&f.treasury), 10_000);
    assert_eq!(f.token().balance(&f.employee), 0);
}

#[test]
fn test_same_payout_succeeds_on_retry_once_the_token_resumes() {
    let f = setup();
    let (a, b, c, nullifier) = proof(&f.env);

    f.token().set_paused(&true);
    assert!(f
        .client()
        .try_execute_payment(
            &f.company_id,
            &f.employee,
            &1000,
            &a,
            &b,
            &c,
            &nullifier,
            &1
        )
        .is_err());

    f.token().set_paused(&false);
    // Retry with the identical proof and nullifier: the failed attempt must not
    // have consumed them.
    f.client().execute_payment(
        &f.company_id,
        &f.employee,
        &1000,
        &a,
        &b,
        &c,
        &nullifier,
        &1,
    );

    assert!(f.client().is_paid(&f.employee, &1));
    assert_eq!(f.client().get_total_paid(&f.company_id), 1000);
    assert_eq!(f.token().balance(&f.treasury), 9_000);
    assert_eq!(f.token().balance(&f.employee), 1_000);
}

#[test]
fn test_repeated_failed_retries_while_paused_accumulate_nothing() {
    let f = setup();
    let (a, b, c, nullifier) = proof(&f.env);

    f.token().set_paused(&true);
    for _ in 0..3 {
        assert!(f
            .client()
            .try_execute_payment(
                &f.company_id,
                &f.employee,
                &1000,
                &a,
                &b,
                &c,
                &nullifier,
                &1
            )
            .is_err());
    }
    assert_eq!(f.client().get_total_paid(&f.company_id), 0);
    assert_eq!(f.token().balance(&f.treasury), 10_000);

    // Boundary: after all those failures the payout still goes through exactly once.
    f.token().set_paused(&false);
    f.client().execute_payment(
        &f.company_id,
        &f.employee,
        &1000,
        &a,
        &b,
        &c,
        &nullifier,
        &1,
    );
    assert_eq!(f.client().get_total_paid(&f.company_id), 1000);

    // A further retry after success is rejected and moves no funds.
    assert!(f
        .client()
        .try_execute_payment(
            &f.company_id,
            &f.employee,
            &1000,
            &a,
            &b,
            &c,
            &nullifier,
            &1
        )
        .is_err());
    assert_eq!(f.token().balance(&f.employee), 1_000);
    assert_eq!(f.token().balance(&f.treasury), 9_000);
}
