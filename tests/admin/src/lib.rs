//! # Admin Configuration Lock Tests (issue #253)
//!
//! Verifies that unsafe admin configuration changes are rejected while a
//! payroll run is prepared but not yet resolved, and that they become
//! available again once every pending run has been cancelled.
//!
//! Locked while a run is active: `accept_admin_rotation`,
//! `accept_treasury_rotation`, `set_asset_allowed`, `set_company_state`.
//!
//! Deliberately left unlocked (escape hatches / inert steps):
//! `propose_admin_rotation`, `cancel_admin_rotation`, `set_pause_manager`,
//! `cancel_payroll_run` itself.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p admin_config_lock_tests
//! ```

#[cfg(test)]
mod tests {
    use payroll::{CompanyState, Payroll, PayrollClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
    use token::{Token, TokenClient};

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

    fn mock_proof(env: &Env) -> BytesN<256> {
        BytesN::from_array(env, &[0u8; 256])
    }

    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
    }

    /// Sets up a fully wired payroll contract with one registered employee.
    /// Returns (payroll_client, admin, treasury, treasury_owner, employee).
    fn setup(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
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

    fn prepare_a_run(
        env: &Env,
        payroll_client: &PayrollClient,
        employee: &Address,
        seed: u8,
    ) -> u64 {
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(env);
        employees.push_back(employee.clone());

        payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(env, seed),
            &None,
        )
    }

    // ── has_active_payroll_run reflects pending state ─────────────────────────

    #[test]
    fn test_has_active_payroll_run_toggles_with_prepare_and_cancel() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        assert!(!payroll_client.has_active_payroll_run());

        let run_id = prepare_a_run(&env, &payroll_client, &employee, 1);
        assert!(payroll_client.has_active_payroll_run());

        payroll_client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "test"));
        assert!(!payroll_client.has_active_payroll_run());
    }

    #[test]
    fn test_config_lock_persists_until_all_pending_runs_resolved() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        let run_a = prepare_a_run(&env, &payroll_client, &employee, 1);
        let run_b = prepare_a_run(&env, &payroll_client, &employee, 2);
        assert!(payroll_client.has_active_payroll_run());

        // Resolving only one of two pending runs must keep the lock engaged.
        payroll_client.cancel_payroll_run(&admin, &run_a, &Symbol::new(&env, "test"));
        assert!(payroll_client.has_active_payroll_run());

        let new_asset = Address::generate(&env);
        let result = payroll_client.try_set_asset_allowed(&new_asset, &true);
        assert!(result.is_err(), "lock must still be engaged");

        // Resolving the second (last) pending run releases the lock.
        payroll_client.cancel_payroll_run(&admin, &run_b, &Symbol::new(&env, "test"));
        assert!(!payroll_client.has_active_payroll_run());
        payroll_client.set_asset_allowed(&new_asset, &true);
    }

    // ── accept_admin_rotation ──────────────────────────────────────────────────

    #[test]
    fn test_accept_admin_rotation_blocked_while_run_pending() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let result = payroll_client.try_accept_admin_rotation(&new_admin);
        assert!(
            result.is_err(),
            "accept must be locked while a run is pending"
        );
    }

    #[test]
    fn test_accept_admin_rotation_succeeds_after_run_cancelled() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let run_id = prepare_a_run(&env, &payroll_client, &employee, 1);
        payroll_client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "test"));

        payroll_client.accept_admin_rotation(&new_admin);
        assert!(payroll_client.get_pending_admin_rotation().is_none());
    }

    /// Proposing a rotation is inert (nothing mutates until accepted), so it
    /// must remain available even while a run is pending.
    #[test]
    fn test_propose_admin_rotation_not_blocked_by_active_run() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);
        assert!(payroll_client.get_pending_admin_rotation().is_some());
    }

    // ── accept_treasury_rotation ───────────────────────────────────────────────

    #[test]
    fn test_accept_treasury_rotation_blocked_while_run_pending() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, treasury_owner, employee) = setup(&env);

        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&treasury_owner, &new_owner);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let result = payroll_client.try_accept_treasury_rotation(&new_owner);
        assert!(
            result.is_err(),
            "accept must be locked while a run is pending"
        );
    }

    #[test]
    fn test_accept_treasury_rotation_succeeds_after_run_cancelled() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, treasury_owner, employee) = setup(&env);

        let new_owner = Address::generate(&env);
        payroll_client.propose_treasury_rotation(&treasury_owner, &new_owner);

        let run_id = prepare_a_run(&env, &payroll_client, &employee, 1);
        payroll_client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "test"));

        payroll_client.accept_treasury_rotation(&new_owner);
        assert!(payroll_client.get_pending_treasury_rotation().is_none());
    }

    // ── set_asset_allowed ──────────────────────────────────────────────────────

    #[test]
    fn test_set_asset_allowed_blocked_while_run_pending() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) = setup(&env);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let new_asset = Address::generate(&env);
        let result = payroll_client.try_set_asset_allowed(&new_asset, &true);
        assert!(
            result.is_err(),
            "asset allowlist changes must be locked while a run is pending"
        );
    }

    #[test]
    fn test_set_asset_allowed_works_with_no_pending_runs() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, _employee) = setup(&env);

        let new_asset = Address::generate(&env);
        payroll_client.set_asset_allowed(&new_asset, &true);
        assert!(payroll_client.is_asset_allowed(&new_asset));
    }

    // ── set_company_state ──────────────────────────────────────────────────────

    #[test]
    fn test_set_company_state_blocked_while_run_pending() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let result = payroll_client.try_set_company_state(&admin, &CompanyState::Paused);
        assert!(
            result.is_err(),
            "company state changes must be locked while a run is pending"
        );
    }

    #[test]
    fn test_set_company_state_succeeds_after_run_cancelled() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        let run_id = prepare_a_run(&env, &payroll_client, &employee, 1);
        payroll_client.cancel_payroll_run(&admin, &run_id, &Symbol::new(&env, "test"));

        payroll_client.set_company_state(&admin, &CompanyState::Paused);
        assert_eq!(payroll_client.get_company_state(), CompanyState::Paused);
    }

    // ── Escape hatches remain available during an active run ─────────────────

    /// Pausing the whole system must always remain available as an emergency
    /// stop, even while a run is pending and other config is locked.
    #[test]
    fn test_set_pause_manager_not_blocked_by_active_run() {
        let env = Env::default();
        let (payroll_client, _admin, _treasury, _treasury_owner, employee) = setup(&env);

        prepare_a_run(&env, &payroll_client, &employee, 1);

        let pm_id = env.register_contract(None, pause_manager::PauseManager);
        let pm_client = pause_manager::PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        // Must not panic.
        payroll_client.set_pause_manager(&pm_id);
    }

    /// Cancelling a pending run is the mechanism that releases the lock, so
    /// it must never be blocked by the lock itself.
    #[test]
    fn test_cancel_payroll_run_always_available_while_locked() {
        let env = Env::default();
        let (payroll_client, admin, _treasury, _treasury_owner, employee) = setup(&env);

        let run_a = prepare_a_run(&env, &payroll_client, &employee, 1);
        let run_b = prepare_a_run(&env, &payroll_client, &employee, 2);

        payroll_client.cancel_payroll_run(&admin, &run_a, &Symbol::new(&env, "test"));
        payroll_client.cancel_payroll_run(&admin, &run_b, &Symbol::new(&env, "test"));
        assert!(!payroll_client.has_active_payroll_run());
    }
}
