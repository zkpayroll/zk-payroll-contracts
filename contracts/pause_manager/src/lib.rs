#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub enum DataKey {
    Paused,
    Operator,
}

#[cfg(feature = "contract")]
#[contract]
pub struct PauseManager;

#[cfg(feature = "contract")]
#[contractimpl]
impl PauseManager {
    pub fn initialize(e: Env, operator: Address) {
        if e.storage().persistent().has(&DataKey::Operator) {
            panic!("Already initialized");
        }
        e.storage().persistent().set(&DataKey::Operator, &operator);
        e.storage().persistent().set(&DataKey::Paused, &false);
    }

    pub fn pause(e: Env) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        operator.require_auth();
        e.storage().persistent().set(&DataKey::Paused, &true);
        e.events().publish(
            (Symbol::new(&e, "PauseManager"), Symbol::new(&e, "paused")),
            (),
        );
    }

    pub fn unpause(e: Env) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        operator.require_auth();
        e.storage().persistent().set(&DataKey::Paused, &false);
        e.events().publish(
            (Symbol::new(&e, "PauseManager"), Symbol::new(&e, "unpaused")),
            (),
        );
    }

    pub fn is_paused(e: Env) -> bool {
        e.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn set_operator(e: Env, new_operator: Address) {
        let operator: Address = e
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("Not initialized");
        operator.require_auth();
        e.storage()
            .persistent()
            .set(&DataKey::Operator, &new_operator);
    }
}

#[cfg(not(feature = "contract"))]
pub struct PauseManagerClient<'a>(pub &'a Env, pub &'a Address);

#[cfg(not(feature = "contract"))]
impl<'a> PauseManagerClient<'a> {
    pub fn new(env: &'a Env, contract_id: &'a Address) -> Self {
        Self(env, contract_id)
    }

    pub fn initialize(&self, operator: &Address) {
        self.0.invoke_contract(
            &self.1,
            &Symbol::new(self.0, "initialize"),
            (operator.clone(),),
        );
    }

    pub fn pause(&self) {
        self.0
            .invoke_contract(&self.1, &Symbol::new(self.0, "pause"), ());
    }

    pub fn unpause(&self) {
        self.0
            .invoke_contract(&self.1, &Symbol::new(self.0, "unpause"), ());
    }

    pub fn is_paused(&self) -> bool {
        self.0
            .invoke_contract(&self.1, &Symbol::new(self.0, "is_paused"), ())
    }

    pub fn set_operator(&self, new_operator: &Address) {
        self.0.invoke_contract(
            &self.1,
            &Symbol::new(self.0, "set_operator"),
            (new_operator.clone(),),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, IntoVal};

    fn setup() -> (Env, PauseManagerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);
        (env, client)
    }

    #[test]
    fn test_initialize_sets_operator_and_unpaused() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        assert!(!client.is_paused());
    }

    #[test]
    #[should_panic(expected = "Already initialized")]
    fn test_initialize_cannot_be_called_twice() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);
        client.initialize(&operator);
    }

    #[test]
    fn test_pause_sets_paused_state() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    fn test_unpause_resumes_state() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
        client.unpause();
        assert!(!client.is_paused());
    }

    #[test]
    fn test_can_pause_multiple_times() {
        let (_env, client) = setup();
        client.pause();
        assert!(client.is_paused());
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    fn test_set_operator_changes_operator() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        let operator = Address::generate(&env);
        client.initialize(&operator);

        let new_operator = Address::generate(&env);
        client.set_operator(&new_operator);

        // New operator can pause
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_unauthorized_pause_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&operator);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "pause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.pause();
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_unauthorized_unpause_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "initialize",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.initialize(&operator);

        // Pause as operator
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "pause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.pause();

        // Try to unpause as attacker
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "unpause",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.unpause();
    }

    #[test]
    fn test_is_paused_returns_false_when_not_initialized() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        assert!(!client.is_paused());
    }

    #[test]
    #[should_panic(expected = "Not initialized")]
    fn test_pause_panics_when_not_initialized() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PauseManager);
        let client = PauseManagerClient::new(&env, &contract_id);
        client.pause();
    }
}
