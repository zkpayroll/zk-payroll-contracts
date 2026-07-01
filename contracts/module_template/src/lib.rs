//! Contract module scaffold — copy this directory to bootstrap a new zk-payroll
//! module and replace every occurrence of `ModuleTemplate` / `module_template`
//! with your module name.
//!
//! Checklist (mirrors `docs/contributor-module-checklist.md`):
//!   [ ] Define a `ContractError` enum (`#[contracterror]`, `u32` discriminants,
//!       append-only).
//!   [ ] Define a `DataKey` enum (`#[contracttype]`) — one variant per storage
//!       slot, keyed per record where possible.
//!   [ ] Emit events for every state-mutating action.
//!   [ ] Gate all state-mutating entry-points with `address.require_auth()`.
//!   [ ] Store all primary records with `env.storage().persistent()`.
//!   [ ] Run `cargo fmt --all` and
//!       `cargo clippy --workspace --all-targets -- -D warnings` before pushing.

#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol,
};

// ── Errors ────────────────────────────────────────────────────────────────────

/// All recoverable error codes for this module.
///
/// Discriminants are stable — add new variants at the end only.
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

// ── Storage keys ──────────────────────────────────────────────────────────────

/// One variant per logical storage slot.
///
/// Use parameterised variants (e.g. `Record(u64)`) for per-record keys rather
/// than storing a bulk `Vec` — this avoids read/write amplification.
#[contracttype]
pub enum DataKey {
    /// Contract admin address (set once at initialization).
    Admin,
    // TODO: add module-specific keys here.
    // Example per-record key:
    //   Record(u64),
}

// ── Event types ───────────────────────────────────────────────────────────────

/// Emitted when the contract is initialized.
///
/// Event taxonomy: `(symbol_short!("module"), Symbol::new(&e, "action"))`.
#[contracttype]
pub struct InitializedEvent {
    pub admin: Address,
    pub ledger: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ModuleTemplate;

#[contractimpl]
impl ModuleTemplate {
    /// Initialize the contract and designate an admin.
    ///
    /// May only be called once. The `admin` address receives authority over all
    /// subsequent state-mutating operations.
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

    /// Returns the current admin address.
    pub fn get_admin(e: Env) -> Result<Address, ModuleError> {
        e.storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(ModuleError::NotInitialized)
    }
}


    // TODO: implement module-specific entry-points below.
    //
    // Pattern for admin-gated mutation:
    //
    //   pub fn some_action(e: Env, admin: Address, ...) -> Result<(), ModuleError> {
    //       let stored: Address = e
    //           .storage()
    //           .persistent()
    //           .get(&DataKey::Admin)
    //           .ok_or(ModuleError::NotInitialized)?;
    //       if admin != stored { return Err(ModuleError::Unauthorized); }
    //       admin.require_auth();
    //
    //       // ... mutate state ...
    //
    //       e.events().publish(
    //           (symbol_short!("module"), Symbol::new(&e, "some_action")),
    //           /* event data */,
    //       );
    //       Ok(())
    //   }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

        let contract_id = env.register_contract(None, ModuleTemplate);
        let client = ModuleTemplateClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.initialize(&admin);

        let result = client.try_initialize(&admin);
        assert_eq!(result, Err(Ok(ModuleError::AlreadyInitialized)));
    }

    #[test]
    fn test_get_admin_before_init_returns_error() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ModuleTemplate);
        let client = ModuleTemplateClient::new(&env, &contract_id);

        let result = client.try_get_admin();
        assert_eq!(result, Err(Ok(ModuleError::NotInitialized)));
    }
}
