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
/// - `CompanySequence`      → `u64`           (Persistent, auto-increment counter)
#[contracttype]
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    CompanySequence,
}

// ---------------------------------------------------------------------------
// Trait — canonical interface specification for #12
// ---------------------------------------------------------------------------

pub trait PayrollRegistryTrait {
    /// Register a new company. Returns the newly assigned company ID.
    /// Requires authorisation from the provided admin address.
    fn register_company(env: Env, admin: Address, treasury: Address) -> u64;

    /// Add an employee commitment under a company.
    /// Requires authorisation from the company admin.
    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>);

    /// Permanently remove an employee record from storage.
    /// Requires authorisation from the company admin.
    fn remove_employee(env: Env, company_id: u64, employee: Address);

    /// Replace an employee's active Poseidon commitment.
    /// Requires authorisation from the company admin.
    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>);
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PayrollRegistry;

#[contractimpl]
impl PayrollRegistryTrait for PayrollRegistry {
    fn register_company(env: Env, admin: Address, treasury: Address) -> u64 {
        admin.require_auth();

        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::CompanySequence)
            .unwrap_or(0u64);

        let next = id + 1;
        env.storage()
            .persistent()
            .set(&DataKey::CompanySequence, &next);

        let info = CompanyInfo { admin, treasury };
        env.storage().persistent().set(&DataKey::Company(id), &info);

        id
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
}

#[cfg(test)]
mod tests;
