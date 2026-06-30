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
    pub status: CompanyStatus,
}

/// Company lifecycle state.
///
/// Transitions are explicit:
/// - `Onboarding` -> `Active` or `Archived`
/// - `Active` -> `Paused` or `Archived`
/// - `Paused` -> `Active` or `Archived`
/// - `Archived` is terminal
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanyStatus {
    Onboarding,
    Active,
    Paused,
    Archived,
}

/// Privacy-preserving employee metadata.
///
/// The registry stores only opaque 32-byte hashes for mutable business metadata.
/// Employee identity (`Address`) and payroll eligibility (`commitment`) remain in
/// their dedicated registry keys and cannot be changed through metadata updates.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmployeeMetadata {
    pub profile_hash: BytesN<32>,
    pub role_hash: BytesN<32>,
}

/// Storage key space for the payroll registry.
///
/// - `Company(u64)`         → `CompanyInfo`   (Persistent)
/// - `Employee(u64, Address)` → `BytesN<32>`  (Persistent, Poseidon commitment)
/// - `EmployeeMetadata(u64, Address)` → `EmployeeMetadata` (Persistent, mutable opaque hashes)
/// - `CompanySequence`      → `u64`           (Persistent, auto-increment counter)
#[contracttype]
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    EmployeeMetadata(u64, Address),
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

    /// Update the mutable profile metadata hash for an existing employee.
    /// Requires authorisation from the company admin.
    fn update_employee_profile_hash(
        env: Env,
        company_id: u64,
        employee: Address,
        profile_hash: BytesN<32>,
    );

    /// Update the mutable role metadata hash for an existing employee.
    /// Requires authorisation from the company admin.
    fn update_employee_role_hash(
        env: Env,
        company_id: u64,
        employee: Address,
        role_hash: BytesN<32>,
    );

    /// Read mutable employee metadata hashes.
    fn get_employee_metadata(env: Env, company_id: u64, employee: Address) -> EmployeeMetadata;

    /// Move a company from onboarding to active.
    /// Requires authorisation from the company admin.
    fn activate_company(env: Env, company_id: u64);

    /// Temporarily pause an active company.
    /// Requires authorisation from the company admin.
    fn pause_company(env: Env, company_id: u64);

    /// Resume a paused company by returning it to active.
    /// Requires authorisation from the company admin.
    fn resume_company(env: Env, company_id: u64);

    /// Archive a company. Archived companies are terminal and reject mutations.
    /// Requires authorisation from the company admin.
    fn archive_company(env: Env, company_id: u64);

    /// Read company metadata by company ID.
    fn get_company(env: Env, company_id: u64) -> CompanyInfo;

    /// Read company lifecycle status by company ID.
    fn get_company_status(env: Env, company_id: u64) -> CompanyStatus;

    /// Read an employee's active commitment under a company.
    fn get_commitment(env: Env, company_id: u64, employee: Address) -> BytesN<32>;
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PayrollRegistry;

impl PayrollRegistry {
    fn empty_metadata(env: &Env) -> EmployeeMetadata {
        EmployeeMetadata {
            profile_hash: BytesN::from_array(env, &[0u8; 32]),
            role_hash: BytesN::from_array(env, &[0u8; 32]),
        }
    }

    fn require_company_admin(env: &Env, company_id: u64) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();
    }

    fn require_company_allows_employee_changes(env: &Env, company_id: u64) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        match info.status {
            CompanyStatus::Onboarding | CompanyStatus::Active => {}
            CompanyStatus::Paused => panic!("Company is paused"),
            CompanyStatus::Archived => panic!("Company is archived"),
        }
    }

    fn set_company_status(env: &Env, company_id: u64, next_status: CompanyStatus) {
        let key = DataKey::Company(company_id);
        let mut info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Company not found");

        info.admin.require_auth();

        let allowed = matches!(
            (info.status, next_status),
            (CompanyStatus::Onboarding, CompanyStatus::Active)
                | (CompanyStatus::Onboarding, CompanyStatus::Archived)
                | (CompanyStatus::Active, CompanyStatus::Paused)
                | (CompanyStatus::Active, CompanyStatus::Archived)
                | (CompanyStatus::Paused, CompanyStatus::Active)
                | (CompanyStatus::Paused, CompanyStatus::Archived)
        );

        if !allowed {
            panic!("Invalid company status transition");
        }

        info.status = next_status;
        env.storage().persistent().set(&key, &info);
    }

    fn require_employee_exists(env: &Env, company_id: u64, employee: &Address) {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()))
        {
            panic!("Employee not found");
        }
    }
}

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

        let info = CompanyInfo {
            admin,
            treasury,
            status: CompanyStatus::Onboarding,
        };
        env.storage().persistent().set(&DataKey::Company(id), &info);

        id
    }

    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>) {
        Self::require_company_admin(&env, company_id);
        Self::require_company_allows_employee_changes(&env, company_id);

        info.admin.require_auth();

        let key = DataKey::Employee(company_id, employee.clone());
        if env.storage().persistent().has(&key) {
            panic!("Employee already exists");
        }

        env.storage().persistent().set(&key, &commitment);
    }

    fn remove_employee(env: Env, company_id: u64, employee: Address) {
        Self::require_company_admin(&env, company_id);
        Self::require_company_allows_employee_changes(&env, company_id);

        env.storage()
            .persistent()
            .remove(&DataKey::Employee(company_id, employee.clone()));
        env.storage()
            .persistent()
            .remove(&DataKey::EmployeeMetadata(company_id, employee));
    }

    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>) {
        Self::require_company_admin(&env, company_id);
        Self::require_company_allows_employee_changes(&env, company_id);

        let key = DataKey::Employee(company_id, employee);
        if !env.storage().persistent().has(&key) {
            panic!("Employee not found");
        }

        env.storage().persistent().set(&key, &new_commitment);
    }

    fn update_employee_profile_hash(
        env: Env,
        company_id: u64,
        employee: Address,
        profile_hash: BytesN<32>,
    ) {
        Self::require_company_admin(&env, company_id);
        Self::require_company_allows_employee_changes(&env, company_id);
        Self::require_employee_exists(&env, company_id, &employee);

        let key = DataKey::EmployeeMetadata(company_id, employee);
        let mut metadata: EmployeeMetadata = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Self::empty_metadata(&env));
        metadata.profile_hash = profile_hash;
        env.storage().persistent().set(&key, &metadata);
    }

    fn update_employee_role_hash(
        env: Env,
        company_id: u64,
        employee: Address,
        role_hash: BytesN<32>,
    ) {
        Self::require_company_admin(&env, company_id);
        Self::require_company_allows_employee_changes(&env, company_id);
        Self::require_employee_exists(&env, company_id, &employee);

        let key = DataKey::EmployeeMetadata(company_id, employee);
        let mut metadata: EmployeeMetadata = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Self::empty_metadata(&env));
        metadata.role_hash = role_hash;
        env.storage().persistent().set(&key, &metadata);
    }

    fn get_employee_metadata(env: Env, company_id: u64, employee: Address) -> EmployeeMetadata {
        Self::require_employee_exists(&env, company_id, &employee);

        env.storage()
            .persistent()
            .get(&DataKey::EmployeeMetadata(company_id, employee))
            .unwrap_or_else(|| Self::empty_metadata(&env))
    }

    fn activate_company(env: Env, company_id: u64) {
        Self::set_company_status(&env, company_id, CompanyStatus::Active);
    }

    fn pause_company(env: Env, company_id: u64) {
        Self::set_company_status(&env, company_id, CompanyStatus::Paused);
    }

    fn resume_company(env: Env, company_id: u64) {
        Self::set_company_status(&env, company_id, CompanyStatus::Active);
    }

    fn archive_company(env: Env, company_id: u64) {
        Self::set_company_status(&env, company_id, CompanyStatus::Archived);
    }

    fn get_company(env: Env, company_id: u64) -> CompanyInfo {
        env.storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found")
    }

    fn get_company_status(env: Env, company_id: u64) -> CompanyStatus {
        Self::get_company(env, company_id).status
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
