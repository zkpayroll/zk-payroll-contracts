#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token as soroban_token, Address, BytesN, Env, Symbol, Vec,
};

use proof_verifier::{Groth16Proof, ProofVerifierClient};
use salary_commitment::SalaryCommitmentContractClient;

const MAX_BATCH: u32 = 50; // Conservative default; adjust if benchmarking shows higher safe limit

#[contract]
pub struct Payroll;

#[contracttype]
#[derive(Clone, Debug)]
pub struct ContractAddresses {
    pub token: Address,
    pub verifier: Address,
    pub commitment: Address,
    pub treasury: Address,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::Token;
    use proof_verifier::{Groth16Proof, ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn mock_proof(env: &Env) -> Groth16Proof {
        Groth16Proof {
            a: BytesN::from_array(env, &[0u8; 64]),
            b: BytesN::from_array(env, &[0u8; 128]),
            c: BytesN::from_array(env, &[0u8; 64]),
        }
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
    fn benchmark_50_batch_validations() {
        let env = Env::default();

        // register dependent contracts
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.initialize(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);

        let token_id = env.register_contract(None, Token);

        // register payroll contract
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        // initialize payroll with addresses and a dummy treasury
        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury);

        // prepare 50 proofs/amounts/employees
        let mut proofs = Vec::new(&env);
        let mut amounts = Vec::new(&env);
        let mut employees = Vec::new(&env);

        for i in 0..50u32 {
            let p = mock_proof(&env);
            proofs.push_back(p);
            amounts.push_back(100i128 + i as i128);
            let emp = Address::generate(&env);
            // store a dummy commitment for each employee so get_commitment succeeds
            commitment_client.store_commitment(&emp, &BytesN::from_array(&env, &[0u8; 32]));
            employees.push_back(emp);
        }

        // Execute batch - should succeed with MAX_BATCH == 50
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees);
    }
}

#[contracttype]
pub enum DataKey {
    Addresses,
}

#[contractimpl]
impl Payroll {
    /// Initialize with admin, token contract, verifier, commitment contracts and treasury address
    pub fn initialize(
        e: Env,
        _admin: Address,
        token: Address,
        verifier: Address,
        commitment: Address,
        treasury: Address,
    ) {
        let key = DataKey::Addresses;
        if e.storage().persistent().has(&key) {
            panic!("Already initialized")
        }
        let addrs = ContractAddresses {
            token,
            verifier,
            commitment,
            treasury,
        };
        e.storage().persistent().set(&key, &addrs);
    }

    pub fn deposit(_e: Env, _from: Address, _amount: i128) {
        // Deposit placeholder
    }

    /// Batch process payroll: verify each proof and transfer the token amount
    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<Groth16Proof>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
    ) {
        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        // Enforce conservative max batch size to avoid hitting Soroban instruction limit
        assert!(count <= MAX_BATCH, "Batch too large");

        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);
        let token_client = soroban_token::Client::new(&e, &addrs.token);

        for i in 0..count as u32 {
            let proof = proofs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            // Retrieve stored commitment for employee
            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            // Placeholder nullifier and recipient hash for now; in production these come from the prover/public inputs
            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            // Verify the proof for this payment
            let ok =
                verifier.verify_payment_proof(&proof, &commitment, &nullifier, &recipient_hash);
            if !ok {
                panic!("Invalid payment proof for employee {}", i);
            }

            // Record nullifier to prevent double payment
            commitment_client.record_nullifier(&nullifier);

            // Execute token transfer from treasury -> employee
            token_client.transfer(&addrs.treasury, &employee, &amount);
        }
    }
}
