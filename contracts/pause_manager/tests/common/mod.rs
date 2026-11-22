#![allow(dead_code)]

//! Shared fixtures for the pause-manager regression and adversarial suites.

use pause_manager::{PauseManager, PauseManagerClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, IntoVal, Val, Vec};

/// Register the contract without initializing or installing any auth mocks.
pub fn uninitialized() -> (Env, Address) {
    let env = Env::default();
    let id = env.register(PauseManager, ());
    (env, id)
}

/// Register and initialize with a single operator, with all auths mocked for setup.
pub fn initialized() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(PauseManager, ());
    let operator = Address::generate(&env);
    PauseManagerClient::new(&env, &id).initialize(&operator);
    (env, id, operator)
}

/// Restrict authorization to exactly one signer for one entrypoint call.
pub fn mock_signer(
    env: &Env,
    contract: &Address,
    signer: &Address,
    fn_name: &str,
    args: Vec<Val>,
) {
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: signer,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract,
            fn_name,
            args,
            sub_invokes: &[],
        },
    }]);
}

pub fn no_args(env: &Env) -> Vec<Val> {
    ().into_val(env)
}
