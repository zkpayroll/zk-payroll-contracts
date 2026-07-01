#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ModuleError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
}

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contracttype]
pub struct InitializedEvent {
    pub admin: Address,
    pub ledger: u32,
}

#[contract]
pub struct ModuleTemplate;

#[contractimpl]
impl ModuleTemplate {
    pub fn initialize(e: Env, admin: Address) -> Result<(), ModuleError> {
        if e.storage().persistent().has(&DataKey::Admin) {
            return Err(ModuleError::AlreadyInitialized);
        }
        admin.require_auth();
        e.storage().persistent().set(&DataKey::Admin, &admin);

        e.events().publish(
            (symbol_short!("module"), Symbol::new(&e, "initialized")),
            InitializedEvent {
                admin: admin.clone(),
                ledger: e.ledger().sequence(),
            },
        );
        Ok(())
    }

    pub fn get_admin(e: Env) -> Result<Address, ModuleError> {
        e.storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ModuleError::NotInitialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_initialize_sets_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ModuleTemplate);
        let client = ModuleTemplateClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
    }

    #[test]
    fn test_double_initialize_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ModuleTemplate);
        let client = ModuleTemplateClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        let result = client.try_initialize(&admin);
        assert_eq!(result, Err(Ok(ModuleError::AlreadyInitialized)));
    }
}
