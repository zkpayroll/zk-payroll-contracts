//! # Company Lifecycle State Execution Gate Tests (issue #147 / #253)
//!
//! `CompanyState` (`Active` / `Paused` / `Archived` / `Incomplete`) is meant
//! to gate whether a company's payroll can execute at all: per
//! `docs/architecture/company-lifecycle-states-106.md`, "payroll execution
//! is only permitted when the state is `Active`". These tests cover that
//! gate as wired into `prepare_payroll_run` and `batch_process_payroll`, and
//! confirm the default (no state ever set) preserves existing Active
//! behavior for deployments that predate this field.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p company_state_gate_tests
//! ```

#[cfg(test)]
mod tests {
    use payroll::{CompanyState, Payroll, PayrollClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, BytesN, Env, Vec};
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
    /// Returns (payroll_client, admin, employee).
    fn setup(env: &Env) -> (PayrollClient<'_>, Address, Address) {
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

        (payroll_client, admin, employee)
    }

    fn single_batch(env: &Env, employee: &Address) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
        let mut proofs = Vec::new(env);
        proofs.push_back(mock_proof(env));
        let mut amounts = Vec::new(env);
        amounts.push_back(1000i128);
        let mut employees = Vec::new(env);
        employees.push_back(employee.clone());
        (proofs, amounts, employees)
    }

    #[test]
    fn test_default_company_state_is_active() {
        let env = Env::default();
        let (payroll_client, _admin, _employee) = setup(&env);

        assert_eq!(payroll_client.get_company_state(), CompanyState::Active);
    }

    // ── prepare_payroll_run gated by company state ────────────────────────────

    #[test]
    fn test_prepare_payroll_run_succeeds_by_default() {
        let env = Env::default();
        let (payroll_client, _admin, employee) = setup(&env);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let run_id = payroll_client.prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 1),
            &None,
        );
        assert!(run_id > 0);
    }

    #[test]
    fn test_prepare_payroll_run_rejected_when_paused() {
        let env = Env::default();
        let (payroll_client, admin, employee) = setup(&env);
        payroll_client.set_company_state(&admin, &CompanyState::Paused);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let result = payroll_client.try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 2),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_payroll_run_rejected_when_archived() {
        let env = Env::default();
        let (payroll_client, admin, employee) = setup(&env);
        payroll_client.set_company_state(&admin, &CompanyState::Archived);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let result = payroll_client.try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 3),
            &None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_payroll_run_rejected_when_incomplete() {
        let env = Env::default();
        let (payroll_client, admin, employee) = setup(&env);
        payroll_client.set_company_state(&admin, &CompanyState::Incomplete);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let result = payroll_client.try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 4),
            &None,
        );
        assert!(result.is_err());
    }

    // ── batch_process_payroll gated by company state ──────────────────────────

    #[test]
    fn test_batch_process_payroll_rejected_when_paused() {
        let env = Env::default();
        let (payroll_client, admin, employee) = setup(&env);
        payroll_client.set_company_state(&admin, &CompanyState::Paused);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let result = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 5),
            &None,
        );
        assert!(result.is_err());
    }

    /// Round trip: pausing blocks execution, and restoring Active resumes it
    /// — the gate must not be a one-way trip.
    #[test]
    fn test_batch_process_payroll_resumes_after_returning_to_active() {
        let env = Env::default();
        let (payroll_client, admin, employee) = setup(&env);
        payroll_client.set_company_state(&admin, &CompanyState::Paused);

        let (proofs, amounts, employees) = single_batch(&env, &employee);
        let blocked = payroll_client.try_batch_process_payroll(
            &proofs,
            &amounts,
            &employees,
            &1000i128,
            &test_nonce(&env, 6),
            &None,
        );
        assert!(blocked.is_err());

        payroll_client.set_company_state(&admin, &CompanyState::Active);

        let (proofs2, amounts2, employees2) = single_batch(&env, &employee);
        let run_id = payroll_client.batch_process_payroll(
            &proofs2,
            &amounts2,
            &employees2,
            &1000i128,
            &test_nonce(&env, 7),
            &None,
        );
        assert!(run_id > 0);
    }

    // ── Access control ──────────────────────────────────────────────────────

    #[test]
    fn test_non_admin_cannot_set_company_state() {
        let env = Env::default();
        let (payroll_client, _admin, _employee) = setup(&env);

        let attacker = Address::generate(&env);
        let result = payroll_client.try_set_company_state(&attacker, &CompanyState::Archived);
        assert!(result.is_err());
    }
}
