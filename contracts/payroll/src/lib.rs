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

// ── Issue #89: payroll amendment flow ────────────────────────────────────────

/// Lifecycle state of a payroll run draft.
///
/// Only `Pending` drafts may be amended. `Finalized` drafts are immutable
/// and serve as the canonical audit record.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RunDraftState {
    Pending = 0,
    Finalized = 1,
}

/// An unfinalized payroll run draft that can be corrected before execution.
///
/// Admins create a draft, optionally amend it one or more times, then
/// finalize it. Once finalized the record is immutable and every amendment
/// is reflected in `amendment_count` for auditability.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PayrollRunDraft {
    pub draft_id: u64,
    pub created_at: u64,
    pub admin: Address,
    pub total_amount: i128,
    pub employee_count: u32,
    pub period_label: Symbol,
    pub state: RunDraftState,
    pub amendment_count: u32,
}

// ── Issue #91: privileged-role rotation ──────────────────────────────────────

/// Pending two-step role-rotation request.
///
/// The current holder proposes a successor; the successor must explicitly
/// accept. Neither party can unilaterally complete the transfer, and the
/// proposal can be cancelled by the current holder at any time before
/// acceptance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingRotation {
    pub new_holder: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Addresses,
    PauseManager,
    PayrollRun(u64),
    TreasuryOwner,
    RunCounter,
    /// Draft run storage for the amendment flow (issue #89).
    RunDraft(u64),
    /// Auto-increment counter for draft IDs (issue #89).
    RunDraftCounter,
    /// Pending admin rotation proposal (issue #91).
    PendingAdminRotation,
    /// Pending treasury-owner rotation proposal (issue #91).
    PendingTreasuryRotation,
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

    // ── Issue #89: payroll amendment flow ────────────────────────────────────

    /// Create a correctable payroll run draft.
    ///
    /// Returns the new `draft_id`. The draft starts in `Pending` state and
    /// can be amended via `amend_run_draft` before being locked with
    /// `finalize_run_draft`.
    pub fn create_run_draft(
        e: Env,
        admin: Address,
        total_amount: i128,
        employee_count: u32,
        period_label: Symbol,
    ) -> u64 {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        if total_amount <= 0 {
            panic!("total_amount must be positive");
        }

        let counter: u64 = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraftCounter)
            .unwrap_or(0);
        let draft_id = counter + 1;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraftCounter, &draft_id);

        let draft = PayrollRunDraft {
            draft_id,
            created_at: e.ledger().timestamp(),
            admin: admin.clone(),
            total_amount,
            employee_count,
            period_label: period_label.clone(),
            state: RunDraftState::Pending,
            amendment_count: 0,
        };
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_created")),
            (draft_id, admin, period_label),
        );

        draft_id
    }

    /// Amend a `Pending` payroll run draft before finalization.
    ///
    /// Only the admin may amend. Finalized drafts are rejected so audit
    /// trails remain unambiguous.
    pub fn amend_run_draft(
        e: Env,
        admin: Address,
        draft_id: u64,
        new_total_amount: i128,
        new_employee_count: u32,
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

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if draft.state != RunDraftState::Pending {
            panic!("Only pending drafts can be amended");
        }
        if new_total_amount <= 0 {
            panic!("total_amount must be positive");
        }

        draft.total_amount = new_total_amount;
        draft.employee_count = new_employee_count;
        draft.amendment_count += 1;

        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_amended")),
            (draft_id, new_total_amount, draft.amendment_count),
        );
    }

    /// Finalize a `Pending` draft, making it permanently immutable.
    ///
    /// After finalization no further amendments are possible. The finalized
    /// draft serves as the canonical audit record for the run.
    pub fn finalize_run_draft(e: Env, admin: Address, draft_id: u64) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if admin != addrs.admin {
            panic!("Unauthorized");
        }
        admin.require_auth();

        let mut draft: PayrollRunDraft = e
            .storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found");

        if draft.state != RunDraftState::Pending {
            panic!("Draft is already finalized");
        }

        draft.state = RunDraftState::Finalized;
        e.storage()
            .persistent()
            .set(&DataKey::RunDraft(draft_id), &draft);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "draft_finalized")),
            (draft_id, draft.total_amount, draft.amendment_count),
        );
    }

    /// Retrieve a payroll run draft by ID.
    pub fn get_run_draft(e: Env, draft_id: u64) -> PayrollRunDraft {
        e.storage()
            .persistent()
            .get(&DataKey::RunDraft(draft_id))
            .expect("Draft not found")
    }

    // ── Issue #91: privileged-role rotation ──────────────────────────────────

    /// Propose a new admin (step 1 of 2).
    ///
    /// Only the current admin can propose a successor. The proposal is stored
    /// on-chain and must be accepted by the new admin via `accept_admin_rotation`.
    pub fn propose_admin_rotation(e: Env, current_admin: Address, new_admin: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized: caller is not the current admin");
        }
        current_admin.require_auth();

        if e.storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation)
        {
            panic!("A pending admin rotation already exists");
        }

        let proposal = PendingRotation {
            new_holder: new_admin.clone(),
            proposed_by: current_admin.clone(),
            proposed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingAdminRotation, &proposal);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "admin_proposed")),
            (current_admin, new_admin),
        );
    }

    /// Accept an admin rotation proposal (step 2 of 2).
    ///
    /// Only the proposed new admin can accept. On acceptance the admin in
    /// `ContractAddresses` is updated and the proposal is cleared.
    pub fn accept_admin_rotation(e: Env, new_admin: Address) {
        let proposal: PendingRotation = e
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation)
            .expect("No pending admin rotation");

        if new_admin != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed admin");
        }
        new_admin.require_auth();

        let mut addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");

        let old_admin = addrs.admin.clone();
        addrs.admin = new_admin.clone();
        e.storage().persistent().set(&DataKey::Addresses, &addrs);
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "admin_rotated")),
            (old_admin, new_admin),
        );
    }

    /// Cancel a pending admin rotation proposal.
    ///
    /// Only the current admin (who submitted the proposal) may cancel.
    pub fn cancel_admin_rotation(e: Env, current_admin: Address) {
        let addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        if current_admin != addrs.admin {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !e
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation)
        {
            panic!("No pending admin rotation to cancel");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        e.events().publish(
            (symbol_short!("payroll"), Symbol::new(&e, "admin_rot_cancel")),
            current_admin,
        );
    }

    /// Propose a new treasury owner (step 1 of 2).
    pub fn propose_treasury_rotation(e: Env, current_owner: Address, new_owner: Address) {
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if current_owner != stored_owner {
            panic!("Unauthorized: caller is not the current treasury owner");
        }
        current_owner.require_auth();

        if e.storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation)
        {
            panic!("A pending treasury rotation already exists");
        }

        let proposal = PendingRotation {
            new_holder: new_owner.clone(),
            proposed_by: current_owner.clone(),
            proposed_at: e.ledger().timestamp(),
        };
        e.storage()
            .persistent()
            .set(&DataKey::PendingTreasuryRotation, &proposal);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treasury_proposed"),
            ),
            (current_owner, new_owner),
        );
    }

    /// Accept a treasury-owner rotation (step 2 of 2).
    pub fn accept_treasury_rotation(e: Env, new_owner: Address) {
        let proposal: PendingRotation = e
            .storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation)
            .expect("No pending treasury rotation");

        if new_owner != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed treasury owner");
        }
        new_owner.require_auth();

        let old_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");

        e.storage()
            .persistent()
            .set(&DataKey::TreasuryOwner, &new_owner);

        let mut addrs: ContractAddresses = e
            .storage()
            .persistent()
            .get(&DataKey::Addresses)
            .expect("Not initialized");
        addrs.treasury_owner = new_owner.clone();
        e.storage().persistent().set(&DataKey::Addresses, &addrs);

        e.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treasury_rotated"),
            ),
            (old_owner, new_owner),
        );
    }

    /// Cancel a pending treasury-owner rotation.
    pub fn cancel_treasury_rotation(e: Env, current_owner: Address) {
        let stored_owner: Address = e
            .storage()
            .persistent()
            .get(&DataKey::TreasuryOwner)
            .expect("Treasury owner not set");
        if current_owner != stored_owner {
            panic!("Unauthorized");
        }
        current_owner.require_auth();

        if !e
            .storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation)
        {
            panic!("No pending treasury rotation to cancel");
        }
        e.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation);

        e.events().publish(
            (
                symbol_short!("payroll"),
                Symbol::new(&e, "treas_rot_cancel"),
            ),
            current_owner,
        );
    }

    /// Return the pending admin rotation proposal, if any.
    pub fn get_pending_admin_rotation(e: Env) -> Option<PendingRotation> {
        e.storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation)
    }

    /// Return the pending treasury-owner rotation proposal, if any.
    pub fn get_pending_treasury_rotation(e: Env) -> Option<PendingRotation> {
        e.storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation)
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

    // ── Issue #89: payroll amendment flow ────────────────────────────────────

    #[test]
    fn test_create_run_draft_returns_incremental_id() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let label = Symbol::new(&env, "Q1_2025");
        let id1 = payroll_client.create_run_draft(&admin, &5_000i128, &10u32, &label);
        let id2 = payroll_client.create_run_draft(&admin, &3_000i128, &5u32, &label);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn test_create_run_draft_starts_pending() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id = payroll_client.create_run_draft(
            &admin,
            &10_000i128,
            &20u32,
            &Symbol::new(&env, "JAN"),
        );
        let draft = payroll_client.get_run_draft(&id);

        assert_eq!(draft.state, RunDraftState::Pending);
        assert_eq!(draft.total_amount, 10_000i128);
        assert_eq!(draft.employee_count, 20u32);
        assert_eq!(draft.amendment_count, 0u32);
    }

    #[test]
    fn test_amend_run_draft_updates_fields_and_increments_count() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id = payroll_client.create_run_draft(
            &admin,
            &10_000i128,
            &20u32,
            &Symbol::new(&env, "FEB"),
        );
        payroll_client.amend_run_draft(&admin, &id, &12_000i128, &22u32);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.total_amount, 12_000i128);
        assert_eq!(draft.employee_count, 22u32);
        assert_eq!(draft.amendment_count, 1u32);
        assert_eq!(draft.state, RunDraftState::Pending);
    }

    #[test]
    fn test_finalize_run_draft_makes_it_immutable() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id = payroll_client.create_run_draft(
            &admin,
            &8_000i128,
            &15u32,
            &Symbol::new(&env, "MAR"),
        );
        payroll_client.finalize_run_draft(&admin, &id);

        let draft = payroll_client.get_run_draft(&id);
        assert_eq!(draft.state, RunDraftState::Finalized);
    }

    #[test]
    fn test_amend_finalized_draft_is_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let id = payroll_client.create_run_draft(
            &admin,
            &5_000i128,
            &10u32,
            &Symbol::new(&env, "APR"),
        );
        payroll_client.finalize_run_draft(&admin, &id);

        let result = payroll_client.try_amend_run_draft(&admin, &id, &9_000i128, &18u32);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Unauthorized")]
    fn test_create_run_draft_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        payroll_client.create_run_draft(
            &attacker,
            &1_000i128,
            &1u32,
            &Symbol::new(&env, "MAY"),
        );
    }

    // ── Issue #91: admin/treasury rotation ───────────────────────────────────

    #[test]
    fn test_admin_rotation_full_flow() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let proposal = payroll_client
            .get_pending_admin_rotation()
            .expect("proposal should exist");
        assert_eq!(proposal.new_holder, new_admin);
        assert_eq!(proposal.proposed_by, admin);

        payroll_client.accept_admin_rotation(&new_admin);

        assert!(payroll_client.get_pending_admin_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the current admin")]
    fn test_propose_admin_rotation_rejects_non_admin() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&attacker, &new_admin);
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the proposed admin")]
    fn test_accept_admin_rotation_rejects_wrong_address() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let impostor = Address::generate(&env);
        payroll_client.accept_admin_rotation(&impostor);
    }

    #[test]
    fn test_cancel_admin_rotation() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);
        payroll_client.cancel_admin_rotation(&admin);

        assert!(payroll_client.get_pending_admin_rotation().is_none());
    }

    #[test]
    fn test_treasury_rotation_full_flow() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&treasury_owner, &new_owner);

        let proposal = payroll_client
            .get_pending_treasury_rotation()
            .expect("proposal should exist");
        assert_eq!(proposal.new_holder, new_owner);

        payroll_client.accept_treasury_rotation(&new_owner);
        assert!(payroll_client.get_pending_treasury_rotation().is_none());
    }

    #[test]
    #[should_panic(expected = "Unauthorized: caller is not the current treasury owner")]
    fn test_propose_treasury_rotation_rejects_non_owner() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let attacker = Address::generate(&env);
        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&attacker, &new_owner);
    }

    #[test]
    #[should_panic(expected = "A pending admin rotation already exists")]
    fn test_duplicate_admin_rotation_proposal_rejected() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, _employee) =
            setup_simple_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);
        payroll_client.propose_admin_rotation(&admin, &new_admin);
    }
}
