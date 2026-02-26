#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol};

/// Company registration data
#[contracttype]
#[derive(Clone, Debug)]
pub struct Company {
    pub id: Symbol,
    pub admin: Address,
    pub treasury: Address,
    pub employee_count: u32,
    pub is_active: bool,
}

/// Employee data with private salary commitment
#[contracttype]
#[derive(Clone, Debug)]
pub struct Employee {
    pub address: Address,
    pub company_id: Symbol,
    pub salary_commitment: BytesN<32>, // Poseidon hash commitment
    pub is_active: bool,
    pub last_payment_timestamp: u64,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Company(Symbol),
    Employee(Address),
    CompanyEmployees(Symbol),
}

#[contract]
pub struct PayrollRegistry;

#[contractimpl]
impl PayrollRegistry {
    /// Register a new company
    pub fn register_company(
        env: Env,
        company_id: Symbol,
        admin: Address,
        treasury: Address,
    ) -> Company {
        // Require admin authorization
        admin.require_auth();

        // Ensure company doesn't already exist
        let key = DataKey::Company(company_id.clone());
        if env.storage().persistent().has(&key) {
            panic!("Company already exists");
        }

        let company = Company {
            id: company_id.clone(),
            admin,
            treasury,
            employee_count: 0,
            is_active: true,
        };

        env.storage().persistent().set(&key, &company);

        company
    }

    /// Add an employee with a salary commitment
    pub fn add_employee(
        env: Env,
        company_id: Symbol,
        employee_address: Address,
        salary_commitment: BytesN<32>,
    ) -> Employee {
        // Get company and verify admin
        let company_key = DataKey::Company(company_id.clone());
        let mut company: Company = env
            .storage()
            .persistent()
            .get(&company_key)
            .expect("Company not found");

        company.admin.require_auth();

        // Create employee record
        let employee = Employee {
            address: employee_address.clone(),
            company_id: company_id.clone(),
            salary_commitment,
            is_active: true,
            last_payment_timestamp: 0,
        };

        // Store employee
        let employee_key = DataKey::Employee(employee_address.clone());
        env.storage().persistent().set(&employee_key, &employee);

        // Update company employee count
        company.employee_count += 1;
        env.storage().persistent().set(&company_key, &company);

        employee
    }

    /// Update salary commitment (for raises, adjustments)
    pub fn update_salary_commitment(
        env: Env,
        company_id: Symbol,
        employee_address: Address,
        new_commitment: BytesN<32>,
    ) {
        // Verify admin authorization
        let company_key = DataKey::Company(company_id.clone());
        let company: Company = env
            .storage()
            .persistent()
            .get(&company_key)
            .expect("Company not found");

        company.admin.require_auth();

        // Update employee salary commitment
        let employee_key = DataKey::Employee(employee_address);
        let mut employee: Employee = env
            .storage()
            .persistent()
            .get(&employee_key)
            .expect("Employee not found");

        employee.salary_commitment = new_commitment;
        env.storage().persistent().set(&employee_key, &employee);
    }

    /// Get company details
    pub fn get_company(env: Env, company_id: Symbol) -> Company {
        let key = DataKey::Company(company_id);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Company not found")
    }

    /// Get employee details
    pub fn get_employee(env: Env, employee_address: Address) -> Employee {
        let key = DataKey::Employee(employee_address);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Employee not found")
    }

    /// Deactivate an employee
    pub fn deactivate_employee(env: Env, company_id: Symbol, employee_address: Address) {
        let company_key = DataKey::Company(company_id.clone());
        let mut company: Company = env
            .storage()
            .persistent()
            .get(&company_key)
            .expect("Company not found");

        company.admin.require_auth();

        let employee_key = DataKey::Employee(employee_address);
        let mut employee: Employee = env
            .storage()
            .persistent()
            .get(&employee_key)
            .expect("Employee not found");

        employee.is_active = false;
        company.employee_count = company.employee_count.saturating_sub(1);

        env.storage().persistent().set(&employee_key, &employee);
        env.storage().persistent().set(&company_key, &company);
    }

    /// Update last payment timestamp (called by payment executor)
    pub fn record_payment(env: Env, employee_address: Address, timestamp: u64) {
        let employee_key = DataKey::Employee(employee_address);
        let mut employee: Employee = env
            .storage()
            .persistent()
            .get(&employee_key)
            .expect("Employee not found");

        employee.last_payment_timestamp = timestamp;
        env.storage().persistent().set(&employee_key, &employee);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_register_company() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PayrollRegistry);
        let client = PayrollRegistryClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = Symbol::new(&env, "ACME");

        let company = client.register_company(&company_id, &admin, &treasury);

        assert_eq!(company.id, company_id);
        assert_eq!(company.admin, admin);
        assert_eq!(company.employee_count, 0);
        assert!(company.is_active);
    }

    #[test]
    fn test_add_employee() {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PayrollRegistry);
        let client = PayrollRegistryClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let company_id = Symbol::new(&env, "ACME");
        let employee_addr = Address::generate(&env);
        client.register_company(&company_id, &admin, &treasury);
        let commitment = BytesN::from_array(&env, &[0u8; 32]);
        let employee = client.add_employee(&company_id, &employee_addr, &commitment);

        assert_eq!(employee.address, employee_addr);
        assert_eq!(employee.company_id, company_id);
        assert!(employee.is_active);
    }
}
