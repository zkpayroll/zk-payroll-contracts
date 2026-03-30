#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token as soroban_token, Address, BytesN,
    Env, Symbol, Vec,
};

use proof_verifier::ProofVerifierClient;
use salary_commitment::SalaryCommitmentContractClient;

const MAX_BATCH: u32 = 50; // Conservative default; adjust if benchmarking shows higher safe limit

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
        admin: Address,
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
            admin,
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

    /// Batch process payroll: verify each proof and execute token transfers.
    ///
    /// Only the registered admin may trigger payroll execution.
    ///
    /// # Parameters
    /// - `expected_total_spend`: The total amount the HR Admin authorises for this batch.
    ///   Must equal the sum of all individual `amounts`. This makes the admin's spending
    ///   intent explicit and prevents a malicious or accidental amount substitution attack
    ///   where individual line items are altered after admin approval.
    ///
    /// # Atomicity & Nullifier Safety (AC-1)
    /// The nullifier for each employee is recorded **before** the token transfer is
    /// attempted.  Soroban executes the entire transaction atomically: if the token
    /// transfer panics (e.g. insufficient treasury balance), the runtime rolls back
    /// every state change made in that invocation — including the nullifier recording.
    /// The nullifier is therefore never durably saved unless the corresponding transfer
    /// succeeds.
    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
    ) {
        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        // Enforce conservative max batch size to avoid hitting Soroban instruction limit
        assert!(count <= MAX_BATCH, "Batch too large");

        // ── AC-2: Explicit spend authorisation ───────────────────────────────
        // Sum up every individual payment and verify it matches the amount the
        // admin declared upfront.  This check happens before any state changes so
        // a mismatch is caught instantly at no cost.
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

        // Only the registered admin may trigger payroll execution
        addrs.admin.require_auth();

        let verifier = ProofVerifierClient::new(&e, &addrs.verifier);
        let commitment_client = SalaryCommitmentContractClient::new(&e, &addrs.commitment);
        let token_client = soroban_token::Client::new(&e, &addrs.token);

        for i in 0..count {
            let proof = proofs.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            let employee = employees.get(i).unwrap();

            // ── FLOW STEP 1: Retrieve commitment ─────────────────────────────
            // Panics with "Commitment not found" if the employee is not enrolled.
            let commitment_struct = commitment_client.get_commitment(&employee);
            let commitment = commitment_struct.commitment;

            // Derive a unique nullifier per (batch_index) to prevent double-payment.
            // In production these come from the prover's public inputs.
            let mut nullifier_arr = [0u8; 32];
            nullifier_arr[0] = (i % 256) as u8;
            nullifier_arr[1] = (i / 256) as u8;
            let nullifier = BytesN::from_array(&e, &nullifier_arr);
            let recipient_hash = BytesN::from_array(&e, &[0u8; 32]);

            // Verify the Groth16 proof for this payment
            let mut public_inputs = Vec::new(&e);
            public_inputs.push_back(commitment.clone());
            public_inputs.push_back(nullifier.clone());
            public_inputs.push_back(recipient_hash.clone());

            // ── FLOW STEP 2: Groth16 proof verification ───────────────────────
            let ok = verifier.verify_payment_proof(&proof, &public_inputs);
            if !ok {
                panic!("Invalid payment proof for employee {}", i);
            }

            // ── FLOW STEP 3: Record nullifier (effect before interaction) ─────
            // Panics with "Nullifier already used" on a replay attempt.
            // Because this comes before the token transfer, Soroban's atomic
            // rollback guarantees the nullifier is discarded if the transfer fails.
            commitment_client.record_nullifier(&nullifier);

            // ── FLOW STEP 4: Token transfer ───────────────────────────────────
            // A panic here (e.g. insufficient treasury balance) causes Soroban to
            // roll back the entire transaction, including the nullifier recorded above.
            token_client.transfer(&addrs.treasury, &employee, &amount);

            // ── FLOW STEP 5: Emit event for off-chain indexers ────────────────
            e.events().publish(
                (
                    symbol_short!("payroll"),
                    Symbol::new(&e, "payment_executed"),
                ),
                (employee.clone(), amount),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::token::{Token, TokenClient};
    use proof_verifier::{ProofVerifier, VerificationKey};
    use salary_commitment::SalaryCommitmentContract;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

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
    fn benchmark_50_batch_validations() {
        let env = Env::default();
        env.mock_all_auths(); // required: batch_process_payroll enforces admin.require_auth()

        // register dependent contracts
        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
        verifier_client.initialize_verifier(&mock_vk(&env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);

        let token_id = env.register_contract(None, Token);
        let token_client = TokenClient::new(&env, &token_id);

        // register payroll contract
        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        // initialize payroll with addresses and a dummy treasury
        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        payroll_client.initialize(&admin, &token_id, &verifier_id, &commitment_id, &treasury);

        // amounts are 100..149; total = sum(100..=149) = 6225
        token_client.mint(&treasury, &10_000i128);

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

        // amounts are 100..149; total = sum(100..=149) = 5000 + (49*50/2) = 6225
        let expected_total_spend: i128 = 6225;

        // Execute batch - should succeed with MAX_BATCH == 50
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &expected_total_spend);
    }
}
