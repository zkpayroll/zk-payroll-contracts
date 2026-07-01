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

// ── Issue #90: employee eligibility ──────────────────────────────────────────

/// Registration state for an employee.
///
/// Eligibility checks use this to decide whether an employee can be included
/// in a payroll execution:
///   - `Active`     → eligible; commitment is registered and record is complete.
///   - `Inactive`   → temporarily ineligible (e.g. on leave, terminated).
///   - `Incomplete` → missing required registration data; never eligible until
///                    the record is corrected and marked `Active`.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EmployeeStatus {
    Active = 0,
    Inactive = 1,
    Incomplete = 2,
}

// ── Issue #91: privileged-role rotation ──────────────────────────────────────

/// Pending two-step company admin or treasury rotation.
///
/// The current holder proposes a successor, and the successor must explicitly
/// accept. Proposals can be cancelled by the current holder before acceptance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingCompanyRotation {
    pub new_holder: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

/// Storage key space for the payroll registry.
///
/// - `Company(u64)`               → `CompanyInfo`              (Persistent)
/// - `Employee(u64, Address)`     → `BytesN<32>`               (Persistent, commitment)
/// - `EmpStatus(u64, Address)`    → `EmployeeStatus`           (Persistent, eligibility)
/// - `CompanySequence`            → `u64`                      (Persistent, counter)
/// - `PendingAdminRotation(u64)`  → `PendingCompanyRotation`   (Persistent, issue #91)
/// - `PendingTreasuryRotation(u64)` → `PendingCompanyRotation` (Persistent, issue #91)
#[contracttype]
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    CompanySequence,
    /// Per-employee eligibility status (issue #90).
    EmpStatus(u64, Address),
    /// Pending admin rotation for a company (issue #91).
    PendingAdminRotation(u64),
    /// Pending treasury rotation for a company (issue #91).
    PendingTreasuryRotation(u64),
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
    /// The employee's initial status is set to `Active`.
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

    // ── Issue #90: employee eligibility ──────────────────────────────────────

    /// Set the eligibility status for a registered employee.
    /// Requires authorisation from the company admin.
    fn set_employee_status(
        env: Env,
        company_id: u64,
        employee: Address,
        status: EmployeeStatus,
    );

    /// Return the eligibility status of an employee.
    /// Returns `Incomplete` if no explicit status has been set.
    fn get_employee_status(env: Env, company_id: u64, employee: Address) -> EmployeeStatus;

    /// Return `true` iff the employee is registered AND has `Active` status.
    fn is_eligible(env: Env, company_id: u64, employee: Address) -> bool;

    // ── Issue #91: company-level admin/treasury rotation ─────────────────────

    /// Propose a new company admin (step 1 of 2).
    fn propose_admin_rotation(env: Env, company_id: u64, current_admin: Address, new_admin: Address);

    /// Accept a pending admin rotation (step 2 of 2).
    fn accept_admin_rotation(env: Env, company_id: u64, new_admin: Address);

    /// Cancel a pending admin rotation.
    fn cancel_admin_rotation(env: Env, company_id: u64, current_admin: Address);

    /// Propose a new company treasury address (step 1 of 2).
    fn propose_treasury_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_treasury: Address,
    );

    /// Accept a pending treasury rotation (step 2 of 2).
    fn accept_treasury_rotation(env: Env, company_id: u64, new_treasury: Address);
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
            .set(&DataKey::Employee(company_id, employee.clone()), &commitment);

        // Default status for newly registered employees is Active (issue #90).
        env.storage().persistent().set(
            &DataKey::EmpStatus(company_id, employee),
            &EmployeeStatus::Active,
        );
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

    // ── Issue #90: employee eligibility ──────────────────────────────────────

    fn set_employee_status(
        env: Env,
        company_id: u64,
        employee: Address,
        status: EmployeeStatus,
    ) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        info.admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()))
        {
            panic!("Employee not found");
        }

        env.storage()
            .persistent()
            .set(&DataKey::EmpStatus(company_id, employee), &status);
    }

    fn get_employee_status(env: Env, company_id: u64, employee: Address) -> EmployeeStatus {
        env.storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee))
            .unwrap_or(EmployeeStatus::Incomplete)
    }

    fn is_eligible(env: Env, company_id: u64, employee: Address) -> bool {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()))
        {
            return false;
        }
        let status: EmployeeStatus = env
            .storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee))
            .unwrap_or(EmployeeStatus::Incomplete);
        status == EmployeeStatus::Active
    }

    // ── Issue #91: company-level admin/treasury rotation ─────────────────────

    fn propose_admin_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_admin: Address,
    ) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized: caller is not the company admin");
        }
        current_admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation(company_id))
        {
            panic!("A pending admin rotation already exists for this company");
        }

        let proposal = PendingCompanyRotation {
            new_holder: new_admin,
            proposed_by: current_admin,
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdminRotation(company_id), &proposal);
    }

    fn accept_admin_rotation(env: Env, company_id: u64, new_admin: Address) {
        let proposal: PendingCompanyRotation = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation(company_id))
            .expect("No pending admin rotation for this company");

        if new_admin != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed admin");
        }
        new_admin.require_auth();

        let mut info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin = new_admin;
        env.storage()
            .persistent()
            .set(&DataKey::Company(company_id), &info);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation(company_id));
    }

    fn cancel_admin_rotation(env: Env, company_id: u64, current_admin: Address) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation(company_id))
        {
            panic!("No pending admin rotation to cancel");
        }
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation(company_id));
    }

    fn propose_treasury_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_treasury: Address,
    ) {
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized: caller is not the company admin");
        }
        current_admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation(company_id))
        {
            panic!("A pending treasury rotation already exists for this company");
        }

        let proposal = PendingCompanyRotation {
            new_holder: new_treasury,
            proposed_by: current_admin,
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PendingTreasuryRotation(company_id), &proposal);
    }

    fn accept_treasury_rotation(env: Env, company_id: u64, new_treasury: Address) {
        let proposal: PendingCompanyRotation = env
            .storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation(company_id))
            .expect("No pending treasury rotation for this company");

        if new_treasury != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed treasury");
        }
        new_treasury.require_auth();

        let mut info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.treasury = new_treasury;
        env.storage()
            .persistent()
            .set(&DataKey::Company(company_id), &info);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation(company_id));
    }
}

#[cfg(test)]
mod tests;
