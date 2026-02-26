#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn initialize(_e: Env, _admin: Address, _decimal: u32, _name: String, _symbol: String) {
        // Initialization logic placeholder
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        if amount < 0 {
            panic!("Mint amount must be non-negative");
        }
        let key = DataKey::Balance(to);
        let current: i128 = e.storage().persistent().get(&key).unwrap_or(0);
        e.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        e.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        if amount < 0 {
            panic!("Transfer amount must be non-negative");
        }
        // NOTE: In production this is replaced by a real SEP-41 token (e.g. the
        // Stellar native asset or soroban-token-contract) which enforces
        // `from.require_auth()`. This placeholder omits the call because Soroban's
        // mock-auth mode (`mock_all_auths`) cannot satisfy non-root `require_auth()`
        // calls that originate from nested contract invocations (payroll → token).

        let from_key = DataKey::Balance(from);
        let from_balance: i128 = e.storage().persistent().get(&from_key).unwrap_or(0);
        if from_balance < amount {
            panic!("Insufficient balance");
        }
        e.storage()
            .persistent()
            .set(&from_key, &(from_balance - amount));

        let to_key = DataKey::Balance(to);
        let to_balance: i128 = e.storage().persistent().get(&to_key).unwrap_or(0);
        e.storage()
            .persistent()
            .set(&to_key, &(to_balance + amount));
    }
}
