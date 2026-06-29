#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token as soroban_token, Address, BytesN,
    Env, Symbol, Vec,
};

use pause_manager::PauseManagerClient;
use proof_verifier::ProofVerifierClient;
use salary_commitment::SalaryCommitmentContractClient;

const MAX_BATCH: u32 = 50;

#[contract]
pub struct Payroll;

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub admin: Address,
    pub token: Address,
    pub verifier: Address,
    pub commitment: Address,
    pub treasury: Address,
    pub treasury_owner: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRun {
    pub run_id: u64,
    pub executed_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
}

#[contracttype]
pub enum DataKey {
    Addresses,
    PauseManager,
    PayrollRun(u64),
    TreasuryOwner,
    RunCounter,
}

#[contractimpl]
impl Payroll {
    pub fn initialize(
        e: Env,
        admin: Address,
        token: Address,
        verifier: Address,
        commitment: Address,
        treasury: Address,
        treasury_owner: Address,
    ) {
        let key = DataKey::Addresses;
        if e.storage().persistent().has(&key) {
            panic!("Already initialized")
        }
        let addrs = ContractAddresses {
            admin,
            token,
            verifier,
            commitment,
            treasury,
            treasury_owner: treasury_owner.clone(),
        };
        e.storage().persistent().set(&key, &addrs);
        e.storage()
            .persistent()
            .set(&DataKey::TreasuryOwner, &treasury_owner);
        e.storage().persistent().set(&DataKey::RunCounter, &0u64);
    }

    pub fn set_pause_manager(e: Env, pause_manager: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.admin.require_auth();
        e.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    pub fn deposit(e: Env, from: Address, amount: i128) {
        if amount <= 0 {
            panic!("Deposit amount must be positive");
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let treasury_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

        from.require_auth();
        treasury_owner.require_auth();

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        token_client.transfer(&from, &addrs.treasury, &amount);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "deposit"),
            ),
            (from, amount),
        );
    }

    fn derive_run_id(e: &Env) -> u64 {
        let counter: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::RunCounter)
            .unwrap_or(0);

        let run_id = counter + 1;
        e.storage()
            .persistent()
            .set(&DataKey::RunCounter, &run_id);

        run_id
    }

    pub fn get_payroll_run(e: Env, run_id: u64) -> PayrollRun {
        e.storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found")
    }

    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
    ) -> u64 {
        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        let mut total: i128 = 0;
        for i in 0..count {
            total += amounts.get(i).unwrap();
        }
        if total != expected_total_spend {
            panic!(
                "Expected spend mismatch: authorised {} but batch totals {}",
                expected_total_spend, total
            );
        }

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        if e.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = e
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(&e, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }

        addrs.admin.require_auth();

        let run_id = Self::derive_run_id(&e);

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);
        let token_client = soroban_token::Client::new(&e, &addrs.token);

        for i in 0..count {
            let proof = proofs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            let mut public_inputs = Vec::new(&e);
            public_inputs.push_back(commitment.clone());
            public_inputs.push_back(nullifier.clone());
            public_inputs.push_back(recipient_hash.clone());

            let ok = verifier.verify_payment_proof(&proof, &public_inputs);
            if !ok {
                panic!("Invalid payment proof for employee {}", i);
            }

            commitment_client.record_nullifier(&nullifier);

            token_client.transfer(&addrs.treasury, &employee, &amount);

            e.events().publish(
                (
                    symbol_short!("payroll"),
                    Symbol::new(&e, "payment_executed"),
                ),
                (employee.clone(), amount),
            );
        }

        let run = PayrollRun {
            run_id,
            executed_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: expected_total_spend,
            employee_count: count,
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "run_executed"),
            ),
            (run_id, expected_total_spend),
        );

        run_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::{Token, TokenClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use proof_verifier::{ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, IntoVal};

    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    fn mock_vk(env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: BytesN::from_array(env, &[0u8; 64]),
            beta: BytesN::from_array(env, &[0u8; 128]),
            gamma: BytesN::from_array(env, &[0u8; 128]),
            delta: BytesN::from_array(env, &[0u8; 128]),
            ic: Vec::from_array(
                env,
                [
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                    BytesN::from_array(env, &[0u8; 64]),
                ],
            ),
        }
    }

    #[test]
    fn test_payroll_run_id_derivation() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let commitment_admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let _token_client = TokenClient::new(&env, &token_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury, &treasury_owner);

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(&env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

        let mut proofs = Vec::new(&env);
        proofs.push_back(mock_proof(&env));
        let mut amounts = Vec::new(&env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        let run_id_1 = payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &1000);
        assert_eq!(run_id_1, 1);

        let run_1 = payroll_client.get_payroll_run(run_id_1);
        assert_eq!(run_1.run_id, 1);
        assert_eq!(run_1.total_amount, 1000);
        assert_eq!(run_1.employee_count, 1);
    }

    #[test]
    fn benchmark_50_batch_validations() {
        let env = Env::default();
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
        let commitment_admin = Address::generate(&env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury, &treasury_owner);

        commitment_client.set_payroll_operator(&payroll_id);

        token_client.mint(&treasury, &10_000i128);

        let mut proofs = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        let mut employees = Vec::new(&env);

        for i in 0..50u32 {
            let p = mock_proof(&env);
            proofs.push_back(p);
            amounts.push_back(100i128 + i as i128);
            let emp = Address::generate(&env);
            commitment_client.store_commitment(&emp, &BytesN::from_array(&env, &[0u8; 32]));
            employees.push_back(emp);
        }

        let expected_total_spend: i128 = 6225;

        let run_id = payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &expected_total_spend);
        assert!(run_id > 0);
    }

    fn setup_simple_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        let verifier_admin = Address::generate(env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        let commitment_admin = Address::generate(env);
        commitment_client.init_commitment_admin(&commitment_admin);

        let token_id = env.register_contract(None, Token);
        let _token_client = TokenClient::new(env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(env, &payroll_id);

        let treasury = Address::generate(env);
        let admin = Address::generate(env);
        let treasury_owner = Address::generate(env);
        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury, &treasury_owner);

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

        (payroll_client, admin, treasury, treasury_owner, employee)
    }

    fn single_payment_batch(
        env: &Env,
        employee: &Address,
        amount: i128,
    ) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(amount);
        let mut employees = Vec::new(env);
        employees.push_back(employee.clone());
        (proofs, amounts, employees)
    }

    #[test]
    fn test_set_pause_manager_stores_address() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) = setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);

        pm_client.pause();
        let (proofs, amounts, employees) = single_payment_batch(&env, &_employee, 1000);
        let result = payroll_client.try_batch_process_payroll(&proofs, &amounts, &employees, &1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_paused_payroll_rejects_batch_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) = setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(&proofs, &amounts, &employees, &1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpaused_payroll_resumes_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) = setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(&proofs, &amounts, &employees, &1000);
        assert!(result.is_err());

        pm_client.unpause();

        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(&proofs2, &amounts2, &employees2, &1000);
    }

    #[test]
    fn test_payroll_works_without_pause_manager() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) = setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &1000);
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_set_pause_manager_rejects_unauthorized() {
        let env = Env::default();
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        let verifier_admin = Address::generate(&env);
        verifier_client.init_verifier_admin(&verifier_admin);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let token_id = env.register_contract(None, Token);
        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &payroll_id,
                fn_name: "initialize",
                args: (
                    admin.clone(),
                    token_id.clone(),
                    verifier_id.clone(),
                    commitment_id.clone(),
                    treasury.clone(),
                    treasury_owner.clone(),
                )
                    .into_val(&env),
                sub_invokes: &[],
            },
        }]);
        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury, &treasury_owner);

        let pm_id = env.register_contract(None, PauseManager);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &payroll_id,
                fn_name: "set_pause_manager",
                args: (pm_id.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        payroll_client.set_pause_manager(&pm_id);
    }
}
