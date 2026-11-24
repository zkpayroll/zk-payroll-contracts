use payroll::PayrollClient;
use salary_commitment::SalaryCommitmentContractClient;
use soroban_sdk::{testutils::Address as _, xdr::ToXdr, Address, BytesN, Env};

/// Register a synthetic active employee so preparation reaches the intended checks.
pub fn active_employee(env: &Env, payroll: &PayrollClient) -> Address {
    let employee = Address::generate(env);
    let commitment: BytesN<32> = env.crypto().sha256(&employee.clone().to_xdr(env)).into();
    let commitment_client =
        SalaryCommitmentContractClient::new(env, &payroll.get_addresses().commitment);
    commitment_client.store_commitment(&employee, &commitment);
    employee
}
