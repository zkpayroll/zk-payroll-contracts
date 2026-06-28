#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Persistent company record. Keyed by auto-incremented u64 company ID.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CompanyInfo {
    pub admin: Address,
    pub treasury: Address,
}

/// Storage key space for the payroll registry.
///
/// - `Company(u64)`         → `CompanyInfo`   (Persistent)
/// - `Employee(u64, Address)` → `BytesN<32>`  (Persistent, Poseidon commitment)
#[contracttype]
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
}

// ---------------------------------------------------------------------------
// Trait — canonical interface specification for #12
// ---------------------------------------------------------------------------

pub trait PayrollRegistryTrait {
    /// Register a new company. Returns the assigned company ID.
    /// Requires authorisation from the provided admin address.
    fn register_company(env: Env, company_id: u64, admin: Address, treasury: Address) -> u64;

    /// Update the admin of a company.
    /// Requires authorisation from the current admin.
    fn update_admin(env: Env, company_id: u64, new_admin: Address);

    /// Add an employee commitment under a company.
    /// Requires authorisation from the company admin.
    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>);

    /// Permanently remove an employee record from storage.
    /// Requires authorisation from the company admin.
    fn remove_employee(env: Env, company_id: u64, employee: Address);

    /// Replace an employee's active Poseidon commitment.
    /// Requires authorisation from the company admin.
    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>);

    /// Read company metadata by company ID.
    fn get_company(env: Env, company_id: u64) -> CompanyInfo;

    /// Read an employee's active commitment under a company.
    fn get_commitment(env: Env, company_id: u64, employee: Address) -> BytesN<32>;
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PayrollRegistry;

#[contractimpl]
impl PayrollRegistryTrait for PayrollRegistry {
    fn register_company(env: Env, company_id: u64, admin: Address, treasury: Address) -> u64 {
        admin.require_auth();

        let key = DataKey::Company(company_id);
        if env.storage().persistent().has(&key) {
            panic!("Company already registered");
        }

        let info = CompanyInfo { admin: admin.clone(), treasury: treasury.clone() };
        env.storage().persistent().set(&key, &info);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "CompanyRegistered"), company_id),
            (admin, treasury),
        );
        
        company_id
    }

    fn update_admin(env: Env, company_id: u64, new_admin: Address) {
        let key = DataKey::Company(company_id);
        let mut info: CompanyInfo = env.storage().persistent().get(&key).expect("Company not found");
        info.admin.require_auth();

        info.admin = new_admin.clone();
        env.storage().persistent().set(&key, &info);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "AdminUpdated"), company_id),
            new_admin,
        );
    }

    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::Employee(company_id, employee), &commitment);
    }

    fn remove_employee(env: Env, company_id: u64, employee: Address) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        env.storage()
            .persistent()
            .remove(&DataKey::Employee(company_id, employee));
    }

    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        let key = DataKey::Employee(company_id, employee);
        if !env.storage().persistent().has(&key) {
            panic!("Employee not found");
        }

        env.storage().persistent().set(&key, &new_commitment);
    }

    fn get_company(env: Env, company_id: u64) -> CompanyInfo {
        env.storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found")
    }

    fn get_commitment(env: Env, company_id: u64, employee: Address) -> BytesN<32> {
        env.storage()
            .persistent()
            .get(&DataKey::Employee(company_id, employee))
            .expect("Employee not found")
    }
}

#[cfg(test)]
mod tests;
