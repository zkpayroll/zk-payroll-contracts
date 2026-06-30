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

/// Reconciliation status for completed payroll runs.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationStatus {
    Unreconciled,
    Reconciled,
    Failed,
}

/// A completed payroll run record.
///
/// `draft_hash` is the SHA-256 / Poseidon hash of the off-chain payroll
/// preparation artifact submitted by the client (#102). Storing it on-chain
/// gives auditors a stable reference to tie the execution back to the
/// reviewed draft.
///
/// `nonce` is a caller-supplied, company-scoped uniqueness token (#103).
/// Once used it can never be reused, preventing accidental duplicate runs.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRun {
    pub run_id: u64,
    pub executed_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
    /// Off-chain draft hash bound at execution time (issue #102).
    pub draft_hash: BytesN<32>,
    /// Caller-supplied run nonce (issue #103). Unique per contract lifetime.
    pub nonce: BytesN<32>,
    pub reconciliation_status: ReconciliationStatus,
}

/// Pending emergency withdrawal request (issue #104).
///
/// Withdrawal requires two separate authorised actions:
/// 1. `request_emergency_withdrawal` — called by the `treasury_owner`.
/// 2. `approve_emergency_withdrawal` — called by the `admin`.
///
/// This two-step design ensures neither role can unilaterally drain funds.
#[contracttype]
#[derive(Clone, Debug)]
pub struct EmergencyWithdrawalRequest {
    pub amount: i128,
    pub recipient: Address,
    pub requested_at: u64,
    pub approved: bool,
}

#[contracttype]
pub enum DataKey {
    Addresses,
    PauseManager,
    PayrollRun(u64),
    TreasuryOwner,
    RunCounter,
    /// Marks a run nonce as consumed. Value is the run_id that used it (#103).
    RunNonce(BytesN<32>),
    /// Pre-committed draft hash bound before execution (#102).
    DraftCommitment(BytesN<32>),
    /// Pending emergency withdrawal request (#104).
    EmergencyRequest,
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
            (symbol_short!("payroll"), Symbol::new(&e, "deposit")),
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
        e.storage().persistent().set(&DataKey::RunCounter, &run_id);

        run_id
    }

    pub fn get_payroll_run(e: Env, run_id: u64) -> PayrollRun {
        e.storage()
            .persistent()
            .get(&DataKey::PayrollRun(run_id))
            .expect("Run not found")
    }

    /// Pre-commit an off-chain draft hash so it can be bound to a future run.
    ///
    /// Clients compute `draft_hash` over the payroll preparation artifact
    /// (employee list, amounts, period metadata) before submitting the batch.
    /// Calling this function registers the hash on-chain so that
    /// `batch_process_payroll` can verify it has not been tampered with.
    ///
    /// Only the admin may pre-commit a draft. The commitment is one-time-use:
    /// once consumed by a successful `batch_process_payroll` call it is removed
    /// from storage (issue #102).
    pub fn commit_draft(e: Env, admin: Address, draft_hash: BytesN<32>) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let key = DataKey::DraftCommitment(draft_hash.clone());
        if e.storage().persistent().has(&key) {
            panic!("Draft already committed");
        }
        e.storage().persistent().set(&key, &true);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_committed")),
            draft_hash,
        );
    }

    /// Request an emergency treasury withdrawal (step 1 of 2 — issue #104).
    ///
    /// Only the `treasury_owner` may submit a request. A pending request is
    /// stored on-chain and must be separately approved by the `admin` via
    /// `approve_emergency_withdrawal`. At most one pending request may exist at
    /// any time.
    pub fn request_emergency_withdrawal(
        e: Env,
        treasury_owner: Address,
        amount: i128,
        recipient: Address,
    ) {
        if amount <= 0 {
            panic!("Amount must be positive");
        }
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if treasury_owner != stored_owner {
            panic!("Unauthorized: caller is not treasury owner");
        }
        treasury_owner.require_auth();

        if e.storage().persistent().has(&DataKey::EmergencyRequest) {
            panic!("A pending emergency request already exists");
        }

        let request = EmergencyWithdrawalRequest {
            amount,
            recipient: recipient.clone(),
            requested_at: e.ledger().timestamp(),
            approved: false,
        };
        e.storage()
            .persistent()
            .set(&DataKey::EmergencyRequest, &request);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_requested")),
            (amount, recipient),
        );
    }

    /// Approve and execute a pending emergency withdrawal (step 2 of 2 — issue #104).
    ///
    /// Only the `admin` may approve. On approval the treasury funds are
    /// transferred to the recipient specified in the request and the pending
    /// request is cleared from storage, ensuring it cannot be replayed.
    pub fn approve_emergency_withdrawal(e: Env, admin: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let request: EmergencyWithdrawalRequest = e
            .storage()
            .persistent()
            .get(&DataKey::EmergencyRequest)
            .expect("No pending emergency request");

        // Clear before transfer (checks-effects-interactions).
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        let token_client = soroban_token::Client::new(&e, &addrs.token);
        token_client.transfer(&addrs.treasury, &request.recipient, &request.amount);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_approved")),
            (request.amount, request.recipient),
        );
    }

    /// Cancel a pending emergency withdrawal request.
    ///
    /// Either the `treasury_owner` or the `admin` may cancel. Cancellation
    /// removes the pending request without transferring any funds.
    pub fn cancel_emergency_withdrawal(e: Env, caller: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

        let is_admin = caller == addrs.admin;
        let is_owner = caller == stored_owner;
        if !is_admin && !is_owner {
            panic!("Unauthorized: only admin or treasury owner may cancel");
        }
        caller.require_auth();

        if !e.storage().persistent().has(&DataKey::EmergencyRequest) {
            panic!("No pending emergency request to cancel");
        }
        e.storage().persistent().remove(&DataKey::EmergencyRequest);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "emrg_cancelled")),
            caller,
        );
    }

    /// Returns the pending emergency withdrawal request, if any.
    pub fn get_emergency_request(e: Env) -> Option<EmergencyWithdrawalRequest> {
        e.storage().persistent().get(&DataKey::EmergencyRequest)
    }

    pub fn batch_process_payroll(
        e: Env,
        proofs: Vec<BytesN<256>>,
        amounts: Vec<i128>,
        employees: Vec<Address>,
        expected_total_spend: i128,
        nonce: BytesN<32>,
        draft_hash: Option<BytesN<32>>,
    ) -> u64 {
        let count = proofs.len();

        if amounts.len() != count || employees.len() != count {
            panic!("Array length mismatch");
        }

        assert!(count <= MAX_BATCH, "Batch too large");

        // #103 — reject duplicate run nonces before any other work.
        let nonce_key = DataKey::RunNonce(nonce.clone());
        if e.storage().persistent().has(&nonce_key) {
            panic!("Duplicate run nonce: this payroll batch has already been submitted");
        }

        // #102 — if a draft hash is supplied, verify a pre-commitment exists.
        let resolved_draft_hash: BytesN<32> = if let Some(ref dh) = draft_hash {
            let commit_key = DataKey::DraftCommitment(dh.clone());
            if !e.storage().persistent().has(&commit_key) {
                panic!("Draft hash not pre-committed: call commit_draft first");
            }
            // Consume the commitment — one run per pre-committed draft.
            e.storage().persistent().remove(&commit_key);
            dh.clone()
        } else {
            BytesN::from_array(&e, &[0u8; 32])
        };

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

        // #103 — mark nonce as consumed (store run_id for auditability).
        e.storage().persistent().set(&nonce_key, &run_id);

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
            // topics : ("payroll", "payment_executed")
            // data   : (employee, amount)
        }

        let run = PayrollRun {
            run_id,
            executed_at: e.ledger().timestamp(),
            admin: addrs.admin.clone(),
            total_amount: expected_total_spend,
            employee_count: count,
            draft_hash: resolved_draft_hash,
            nonce: nonce.clone(),
            reconciliation_status: ReconciliationStatus::Unreconciled,
        };
        e.storage()
            .persistent()
            .set(&DataKey::PayrollRun(run_id), &run);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "run_executed")),
            (run_id, expected_total_spend),
        );

        run_id
    }

    /// Update the reconciliation status of a completed payroll run.
    ///
    /// Only the `admin` may update the reconciliation status.
    /// Emits a `reconciliation_updated` event.
    pub fn update_reconciliation_status(
        e: Env,
        admin: Address,
        run_id: u64,
        status: ReconciliationStatus,
    ) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let run_key = DataKey::PayrollRun(run_id);
        let mut run: PayrollRun = e
            .storage()
            .persistent()
            .get(&run_key)
            .expect("Run not found");

        run.reconciliation_status = status;
        e.storage().persistent().set(&run_key, &run);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "reconciliation_updated"),
            ),
            (run_id, status),
        );
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

    /// Generates a unique 32-byte nonce from a counter seed for tests.
    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
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
        let token_client = TokenClient::new(&env, &token_id);

        let treasury = Address::generate(&env);
        let admin = Address::generate(&env);
        let treasury_owner = Address::generate(&env);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(&env, &payroll_id);

        token_client.mint(&treasury, &1_000_000i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

        commitment_client.set_payroll_operator(&payroll_id);

        let employee = Address::generate(&env);
        commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0u8; 32]));

        let mut proofs = Vec::new(&env);
        proofs.push_back(mock_proof(&env));
        let mut amounts = Vec::new(&env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(&env);
        employees.push_back(employee.clone());

        let run_id_1 = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 1),
            &None,
        );
        assert_eq!(run_id_1, 1);

        let run_1 = payroll_client.get_payroll_run(&run_id_1);
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

        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

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

        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &expected_total_spend,
            &test_nonce(&env, 2),
            &None,
        );
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
        let token_client = TokenClient::new(env, &token_id);

        let payroll_id = env.register_contract(None, Payroll);
        let payroll_client = PayrollClient::new(env, &payroll_id);

        let treasury = Address::generate(env);
        let admin = Address::generate(env);
        let treasury_owner = Address::generate(env);
        // Mint enough tokens so transfer calls in tests succeed.
        token_client.mint(&treasury, &1_000_000i128);
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

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
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);

        pm_client.pause();
        let (proofs, amounts, employees) = single_payment_batch(&env, &_employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 3),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_paused_payroll_rejects_batch_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 4),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unpaused_payroll_resumes_processing() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        payroll_client.set_pause_manager(&pm_id);
        pm_client.pause();

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 5),
            &None,
        );
        assert!(result.is_err());

        pm_client.unpause();

        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &test_nonce(&env, 6),
            &None,
        );
    }

    #[test]
    fn test_payroll_works_without_pause_manager() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 7),
            &None,
        );
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
        payroll_client.initialize(
            &admin,
            &token_id,
            &verifier_id,
            &commitment_id,
            &treasury,
            &treasury_owner,
        );

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

    // ── Issue #103: per-payroll run nonce uniqueness ───────────────────────────

    #[test]
    fn test_duplicate_nonce_is_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 10);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);

        // Second call with the same nonce must fail.
        let (proofs2, amounts2, employees2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000,
            &nonce,
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_distinct_nonces_allow_multiple_runs() {
        // Each call to setup_simple_payroll registers fresh contract instances
        // (new commitment contract, new employee) so nullifiers never collide.
        let env = Env::default();

        let (client1, _a1, _t1, _to1, emp1) = setup_simple_payroll(&env);
        let (p1, a1, e1) = single_payment_batch(&env, &emp1, 500);
        let id1 = client1.batch_process_payroll(&p1, &a1, &e1, &500, &test_nonce(&env, 11), &None);

        let (client2, _a2, _t2, _to2, emp2) = setup_simple_payroll(&env);
        let (p2, a2, e2) = single_payment_batch(&env, &emp2, 500);
        let id2 = client2.batch_process_payroll(&p2, &a2, &e2, &500, &test_nonce(&env, 12), &None);

        assert!(id1 > 0);
        assert!(id2 > 0);
    }

    #[test]
    fn test_nonce_is_stored_in_payroll_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let nonce = test_nonce(&env, 13);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client
            .batch_process_payroll(&proofs, &amounts, &employees, &1000, &nonce, &None);
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.nonce, nonce);
    }

    // ── Issue #102: draft hash binding ────────────────────────────────────────

    #[test]
    fn test_draft_hash_binding_accepted_when_pre_committed() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let draft_hash = BytesN::from_array(&env, &[0xabu8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 20),
            &Some(draft_hash.clone()),
        );
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.draft_hash, draft_hash);
    }

    #[test]
    fn test_draft_hash_rejected_without_pre_commitment() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let unknown_hash = BytesN::from_array(&env, &[0xcdu8; 32]);
        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 21),
            &Some(unknown_hash),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_draft_commitment_is_consumed_after_use() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let draft_hash = BytesN::from_array(&env, &[0xefu8; 32]);
        payroll_client.commit_draft(&admin, &draft_hash);

        let (p1, a1, e1) = single_payment_batch(&env, &employee, 1000);
        payroll_client.batch_process_payroll(
            &p1,
            &a1,
            &e1,
            &1000,
            &test_nonce(&env, 22),
            &Some(draft_hash.clone()),
        );

        // Second use of the same draft hash must fail (already consumed).
        let (p2, a2, e2) = single_payment_batch(&env, &employee, 1000);
        let result = payroll_client.try_batch_process_payroll(
            &p2,
            &a2,
            &e2,
            &1000,
            &test_nonce(&env, 23),
            &Some(draft_hash),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_runs_without_draft_hash() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 24),
            &None,
        );
        assert!(run_id > 0);
    }

    // ── Issue #104: emergency withdrawal workflow ─────────────────────────────

    #[test]
    fn test_emergency_request_then_approve() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &500i128, &recipient);

        let req = payroll_client
            .get_emergency_request()
            .expect("request should exist");
        assert_eq!(req.amount, 500i128);
        assert_eq!(req.recipient, recipient);
        assert!(!req.approved);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not treasury owner")]
    fn test_emergency_request_rejects_non_treasury_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&attacker, &500i128, &recipient);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_emergency_approve_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &100i128, &recipient);

        let attacker = Address::generate(&env);
        payroll_client.approve_emergency_withdrawal(&attacker);
    }

    #[test]
    #[should_panic(expected = "No pending emergency request")]
    fn test_approve_without_request_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);
        payroll_client.approve_emergency_withdrawal(&admin);
    }

    #[test]
    fn test_cancel_emergency_withdrawal_by_admin() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);

        payroll_client.cancel_emergency_withdrawal(&admin);
        assert!(payroll_client.get_emergency_request().is_none());
    }

    #[test]
    fn test_cancel_emergency_withdrawal_by_treasury_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);

        payroll_client.cancel_emergency_withdrawal(&treasury_owner);
        assert!(payroll_client.get_emergency_request().is_none());
    }

    #[test]
    #[should_panic(expected = "A pending emergency request already exists")]
    fn test_duplicate_emergency_request_rejected() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let recipient = Address::generate(&env);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &100i128, &recipient);
        payroll_client.request_emergency_withdrawal(&treasury_owner, &200i128, &recipient);
    }

    // ── Issue #134: reconciliation status tracking ─────────────────────────────

    #[test]
    fn test_new_run_is_unreconciled() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 30),
            &None,
        );

        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(
            run.reconciliation_status,
            ReconciliationStatus::Unreconciled
        );
    }

    #[test]
    fn test_admin_can_update_reconciliation_status() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 31),
            &None,
        );

        // Update to Reconciled
        payroll_client.update_reconciliation_status(
            &admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.reconciliation_status, ReconciliationStatus::Reconciled);

        // Update to Failed
        payroll_client.update_reconciliation_status(&admin, &run_id, &ReconciliationStatus::Failed);
        let run = payroll_client.get_payroll_run(&run_id);
        assert_eq!(run.reconciliation_status, ReconciliationStatus::Failed);
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_non_admin_cannot_update_reconciliation_status() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) =
            setup_simple_payroll(&env);

        let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 1000);
        let run_id = payroll_client.batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000,
            &test_nonce(&env, 32),
            &None,
        );

        let non_admin = Address::generate(&env);
        payroll_client.update_reconciliation_status(
            &non_admin,
            &run_id,
            &ReconciliationStatus::Reconciled,
        );
    }

    #[test]
    #[should_panic(expected = "Run not found")]
    fn test_update_status_for_invalid_run_panics() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        payroll_client.update_reconciliation_status(
            &admin,
            &999u64,
            &ReconciliationStatus::Reconciled,
        );
    }
}
