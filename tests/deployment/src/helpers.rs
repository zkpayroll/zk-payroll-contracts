//! Shared fixtures for deployment parameter validation tests.

use payment_executor::{ContractAddresses as ExecutorAddresses, PaymentExecutor};
use payroll::{Payroll, MAX_NETWORK_ID_LEN};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

/// A freshly registered (but uninitialized) contract suite.
pub struct DeploymentFixture {
    pub payroll_id: Address,
    pub executor_id: Address,
    pub admin: Address,
    pub treasury: Address,
    pub treasury_owner: Address,
    pub token: Address,
    pub verifier: Address,
    pub commitment: Address,
    pub registry: Address,
}

/// Register every contract with distinct, valid addresses.
pub fn deploy_contracts(env: &Env) -> DeploymentFixture {
    DeploymentFixture {
        payroll_id: env.register_contract(None, Payroll),
        executor_id: env.register_contract(None, PaymentExecutor),
        admin: Address::generate(env),
        treasury: Address::generate(env),
        treasury_owner: Address::generate(env),
        token: Address::generate(env),
        verifier: Address::generate(env),
        commitment: Address::generate(env),
        registry: Address::generate(env),
    }
}

/// A fully valid `payroll` initialization parameter set.
pub fn valid_payroll_params(
    f: &DeploymentFixture,
) -> (Address, Address, Address, Address, Address, Address) {
    (
        f.admin.clone(),
        f.token.clone(),
        f.verifier.clone(),
        f.commitment.clone(),
        f.treasury.clone(),
        f.treasury_owner.clone(),
    )
}

/// A fully valid `payment_executor` wiring parameter set.
pub fn valid_executor_params(f: &DeploymentFixture) -> ExecutorAddresses {
    ExecutorAddresses {
        registry: f.registry.clone(),
        commitment: f.commitment.clone(),
        verifier: f.verifier.clone(),
        token: f.token.clone(),
    }
}

/// Build a network-id string of the given length.
pub fn network_id_of_len(env: &Env, len: usize) -> String {
    let s: std::string::String = "n".repeat(len);
    String::from_str(env, &s)
}

/// The maximum accepted network-id length.
pub const MAX_NETWORK_ID: usize = MAX_NETWORK_ID_LEN as usize;
