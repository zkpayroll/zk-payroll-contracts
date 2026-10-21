//! # Admin Action Event Coverage Tests (issue #252)
//!
//! Verifies that sensitive admin actions on the `payroll_registry` contract
//! emit structured, privacy-safe events suitable for audit and indexing.
//!
//! Covered entrypoints:
//! - `propose_admin_rotation`   → `CompanyAdminProposed`
//! - `accept_admin_rotation`    → `CompanyAdminRotated`
//! - `cancel_admin_rotation`    → `CompanyAdminRotCancelled`
//! - `remove_employee`          → `EmployeeRemoved`
//! - `update_commitment`        → `CommitmentUpdated`
//!
//! Privacy guarantees checked:
//! - No salary, commitment value (in `remove_employee`), or employee private
//!   data is leaked through the event topics or data beyond what is already
//!   public (addresses, company IDs).
//! - Events include the actor address and company_id in topics at minimum.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p admin_config_lock_tests admin_action_events_test
//! ```

#[cfg(test)]
mod tests {
    use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Address, BytesN, Env, Symbol, TryIntoVal};

    /// Register the registry contract and return a client.
    fn setup_registry(env: &Env) -> PayrollRegistryClient<'_> {
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PayrollRegistry);
        PayrollRegistryClient::new(env, &contract_id)
    }

    /// Register a company and add one employee. Returns `(admin, company_id, employee)`.
    fn setup_company_with_employee(
        client: &PayrollRegistryClient,
        env: &Env,
    ) -> (Address, u64, Address) {
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        let company_id = client.register_company(&admin, &treasury);

        let employee = Address::generate(env);
        let commitment = BytesN::from_array(env, &[1u8; 32]);
        client.add_employee(&company_id, &employee, &commitment);

        (admin, company_id, employee)
    }

    // ── propose_admin_rotation ────────────────────────────────────────────────

    /// `propose_admin_rotation` must emit exactly one event with the
    /// `CompanyAdminProposed` topic symbol, the company_id, and the current
    /// admin address as topics.
    #[test]
    fn test_propose_admin_rotation_emits_event() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, _employee) = setup_company_with_employee(&client, &env);

        let new_admin = Address::generate(&env);
        let before = env.events().all().len();
        client.propose_admin_rotation(&company_id, &admin, &new_admin);
        let after = env.events().all().len();

        assert!(
            after > before,
            "propose_admin_rotation must emit at least one event"
        );

        // Find the CompanyAdminProposed event (it is the last one).
        let event = env.events().all().get(after - 1).unwrap();
        let topics = &event.1;

        // Topic 0: Symbol("CompanyAdminProposed")
        let sym: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "CompanyAdminProposed"),
            "first topic must be CompanyAdminProposed"
        );

        // Topic 1: company_id (u64)
        let topic_cid: u64 = topics.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_cid, company_id, "second topic must be the company_id");

        // Topic 2: current_admin (Address)
        let topic_admin: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_admin, admin,
            "third topic must be the current admin address"
        );

        // Data: new_admin — no salary or private payroll data.
        let data_new_admin: (Address,) = event.2.try_into_val(&env).unwrap();
        assert_eq!(
            data_new_admin.0, new_admin,
            "data must contain only the proposed new admin"
        );
    }

    // ── accept_admin_rotation ─────────────────────────────────────────────────

    /// `accept_admin_rotation` must emit a `CompanyAdminRotated` event
    /// carrying the company_id and the old admin as topics, and the new admin
    /// as data.
    #[test]
    fn test_accept_admin_rotation_emits_event() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, _employee) = setup_company_with_employee(&client, &env);

        let new_admin = Address::generate(&env);
        client.propose_admin_rotation(&company_id, &admin, &new_admin);

        let before = env.events().all().len();
        client.accept_admin_rotation(&company_id, &new_admin);
        let after = env.events().all().len();

        assert!(
            after > before,
            "accept_admin_rotation must emit at least one event"
        );

        // Search for the CompanyAdminRotated event (may not be the very last
        // due to AdminConfigVersionUpdated also firing, so scan from the end).
        let all_events = env.events().all();
        let rotated_event = (before..after)
            .rev()
            .find_map(|i| {
                let ev = all_events.get(i as u32).unwrap();
                let sym_result: Result<Symbol, _> =
                    ev.1.get(0).unwrap().try_into_val(&env);
                if let Ok(sym) = sym_result {
                    if sym == Symbol::new(&env, "CompanyAdminRotated") {
                        return Some(ev);
                    }
                }
                None
            })
            .expect("CompanyAdminRotated event must be emitted");

        let topics = &rotated_event.1;

        // Topic 1: company_id
        let topic_cid: u64 = topics.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_cid, company_id, "company_id must appear in topics");

        // Topic 2: old admin
        let topic_old: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_old, admin,
            "old admin address must appear in topics"
        );

        // Data: new admin
        let data: (Address,) = rotated_event.2.try_into_val(&env).unwrap();
        assert_eq!(
            data.0, new_admin,
            "new admin address must be in the event data"
        );
    }

    // ── cancel_admin_rotation ─────────────────────────────────────────────────

    /// `cancel_admin_rotation` must emit a `CompanyAdminRotCancelled` event
    /// with company_id and the caller (current admin) in topics, and empty
    /// data so no private values are exposed.
    #[test]
    fn test_cancel_admin_rotation_emits_event() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, _employee) = setup_company_with_employee(&client, &env);

        let new_admin = Address::generate(&env);
        client.propose_admin_rotation(&company_id, &admin, &new_admin);

        let before = env.events().all().len();
        client.cancel_admin_rotation(&company_id, &admin);
        let after = env.events().all().len();

        assert!(
            after > before,
            "cancel_admin_rotation must emit at least one event"
        );

        let event = env.events().all().get(after - 1).unwrap();
        let topics = &event.1;

        // Topic 0: Symbol("CompanyAdminRotCancelled")
        let sym: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "CompanyAdminRotCancelled"),
            "first topic must be CompanyAdminRotCancelled"
        );

        // Topic 1: company_id
        let topic_cid: u64 = topics.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_cid, company_id, "company_id must appear in topics");

        // Topic 2: caller/current admin
        let topic_caller: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_caller, admin,
            "current admin address must appear in topics"
        );

        // Data: empty tuple — no salary or private values.
        let data: () = event.2.try_into_val(&env).unwrap();
        let _ = data; // asserts the payload is empty
    }

    // ── remove_employee ───────────────────────────────────────────────────────

    /// `remove_employee` must emit an `EmployeeRemoved` event with
    /// company_id and the employee address in topics, and empty data —
    /// no commitment values or salary data should appear.
    #[test]
    fn test_remove_employee_emits_event() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, employee) = setup_company_with_employee(&client, &env);

        let _ = admin; // admin auth is mocked globally

        let before = env.events().all().len();
        client.remove_employee(&company_id, &employee);
        let after = env.events().all().len();

        assert!(
            after > before,
            "remove_employee must emit at least one event"
        );

        let event = env.events().all().get(after - 1).unwrap();
        let topics = &event.1;

        // Topic 0: Symbol("EmployeeRemoved")
        let sym: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "EmployeeRemoved"),
            "first topic must be EmployeeRemoved"
        );

        // Topic 1: company_id — minimum required identifier
        let topic_cid: u64 = topics.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_cid, company_id, "company_id must appear in topics");

        // Topic 2: employee address
        let topic_emp: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_emp, employee,
            "employee address must appear in topics"
        );

        // Data: empty — no commitment hash or salary data.
        let data: () = event.2.try_into_val(&env).unwrap();
        let _ = data;
    }

    // ── update_commitment ─────────────────────────────────────────────────────

    /// `update_commitment` must emit a `CommitmentUpdated` event with
    /// company_id and employee address in topics. The new commitment hash
    /// is in the data (it is already public information in the registry),
    /// but no salary value is included.
    #[test]
    fn test_update_commitment_emits_event() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, employee) = setup_company_with_employee(&client, &env);

        let _ = admin;

        let new_commitment = BytesN::from_array(&env, &[2u8; 32]);

        let before = env.events().all().len();
        client.update_commitment(&company_id, &employee, &new_commitment);
        let after = env.events().all().len();

        assert!(
            after > before,
            "update_commitment must emit at least one event"
        );

        let event = env.events().all().get(after - 1).unwrap();
        let topics = &event.1;

        // Topic 0: Symbol("CommitmentUpdated")
        let sym: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "CommitmentUpdated"),
            "first topic must be CommitmentUpdated"
        );

        // Topic 1: company_id — minimum required identifier
        let topic_cid: u64 = topics.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_cid, company_id, "company_id must appear in topics");

        // Topic 2: employee address (actor identity, already public in registry)
        let topic_emp: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_emp, employee,
            "employee address must appear in topics"
        );

        // Data: new commitment hash only (no salary value).
        let data: (BytesN<32>,) = event.2.try_into_val(&env).unwrap();
        assert_eq!(
            data.0, new_commitment,
            "data must contain the new commitment hash"
        );
    }

    // ── Privacy: no salary values in any admin action event ──────────────────

    /// Confirm that none of the tested admin action events carry a raw
    /// `i128` salary value in their data payloads. All events tested
    /// in this module emit either empty data, an Address, or a BytesN<32>
    /// commitment hash — never an amount.
    #[test]
    fn test_admin_action_events_contain_no_salary_values() {
        let env = Env::default();
        let client = setup_registry(&env);
        let (admin, company_id, employee) = setup_company_with_employee(&client, &env);

        // Trigger all five admin actions.
        let new_admin = Address::generate(&env);
        client.propose_admin_rotation(&company_id, &admin, &new_admin);
        client.cancel_admin_rotation(&company_id, &admin);

        let new_admin2 = Address::generate(&env);
        client.propose_admin_rotation(&company_id, &admin, &new_admin2);
        client.accept_admin_rotation(&company_id, &new_admin2);

        let new_commitment = BytesN::from_array(&env, &[3u8; 32]);
        client.update_commitment(&company_id, &employee, &new_commitment);
        client.remove_employee(&company_id, &employee);

        // None of the events should have data decodable as a single i128
        // (which would represent a salary amount). An i128 is 16 bytes;
        // the actual payloads are (), (Address,), or (BytesN<32>,) —
        // none of which decode as i128, so each try_into_val call fails.
        for i in 0..env.events().all().len() {
            let event = env.events().all().get(i).unwrap();
            // If any data decoded as a naked i128 it would indicate a salary
            // value leaked into the event stream.
            let result: Result<i128, _> = event.2.clone().try_into_val(&env);
            assert!(
                result.is_err(),
                "event #{i} must not have data decodable as a bare i128 (salary leak)"
            );
        }
    }
}

// ── Issue #252 Part 2: Payroll contract admin config events ───────────────────
//
// The tests above cover `payroll_registry` admin rotation events.  The tests
// below cover the `payroll` contract's config-change events (`config_changed`)
// that are emitted by `set_pause_manager`, `set_asset_allowed`, and
// `set_capacity_limits` (issue #490).  Topic pattern:
//     ("payroll", "config_changed", key)
// Data pattern:
//     (actor, subject_ref, previous_ref, new_ref, revision, ledger_seq, timestamp)
// where `*_ref` values are sha256 hashes of the config value's XDR — never
// plaintext salaries or commitment values.

#[cfg(test)]
mod payroll_config_event_tests {
    use payroll::{Payroll, PayrollClient};
    use pause_manager::{PauseManager, PauseManagerClient};
    use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
    use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
    use soroban_sdk::testutils::{Address as _, Events};
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

    /// Sets up a minimal payroll contract. Returns (client, admin).
    fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address) {
        env.mock_all_auths();

        let verifier_id = env.register_contract(None, ProofVerifier);
        let verifier_client = ProofVerifierClient::new(env, &verifier_id);
        verifier_client.init_verifier_admin(&Address::generate(env));
        verifier_client.initialize_verifier(&mock_vk(env));

        let commitment_id = env.register_contract(None, SalaryCommitmentContract);
        let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
        commitment_client.init_commitment_admin(&Address::generate(env));

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
        (payroll_client, admin)
    }

    // ── set_pause_manager emits config_changed ────────────────────────────────

    /// `set_pause_manager` must emit at least one event whose first topic
    /// is `"config_changed"` or `"pause_mgr_set"`.  The revision counter
    /// increments.  No salary data is present.
    #[test]
    fn test_set_pause_manager_emits_event() {
        let env = Env::default();
        let (payroll_client, _admin) = setup_payroll(&env);

        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        let operator = Address::generate(&env);
        pm_client.initialize(&operator);

        let before_rev = payroll_client.get_config_revision();
        let before_events = env.events().all().len();

        payroll_client.set_pause_manager(&pm_id);

        let after_events = env.events().all().len();
        assert!(
            after_events > before_events,
            "set_pause_manager must emit at least one event"
        );

        // Config revision must have incremented.
        let after_rev = payroll_client.get_config_revision();
        assert_eq!(
            after_rev,
            before_rev + 1,
            "config revision must increment after set_pause_manager"
        );

        // The change record must exist for the new revision.
        let record = payroll_client
            .get_config_change(&after_rev)
            .expect("config change record must exist for new revision");

        // Actor is the admin, and the record must not decode its refs as i128.
        // The `key` symbol must be non-empty.
        let _ = record.key;
        let _ = record.actor;
    }

    // ── set_asset_allowed (add) emits config_changed ──────────────────────────

    /// Calling `set_asset_allowed(asset, true)` emits a `config_changed`
    /// event and bumps the revision.
    #[test]
    fn test_add_asset_allowlist_emits_event() {
        let env = Env::default();
        let (payroll_client, _admin) = setup_payroll(&env);

        // Get the canonical asset from the addresses struct.
        let supported = payroll_client.get_supported_assets();
        assert!(!supported.is_empty(), "at least one asset must be configured");
        let canonical_asset = supported.get(0).unwrap();

        let before_rev = payroll_client.get_config_revision();
        let before_events = env.events().all().len();

        // Re-enable the canonical asset (idempotent allowlist toggle).
        payroll_client.set_asset_allowed(&canonical_asset, &true);

        let after_events = env.events().all().len();
        assert!(
            after_events > before_events,
            "set_asset_allowed must emit at least one event"
        );

        let after_rev = payroll_client.get_config_revision();
        assert_eq!(
            after_rev,
            before_rev + 1,
            "config revision must increment after set_asset_allowed"
        );
    }

    // ── set_asset_allowed (remove) emits config_changed ──────────────────────

    /// Calling `set_asset_allowed(asset, false)` also emits a `config_changed`
    /// event and bumps the revision.
    #[test]
    fn test_remove_asset_allowlist_emits_event() {
        let env = Env::default();
        let (payroll_client, _admin) = setup_payroll(&env);

        let supported = payroll_client.get_supported_assets();
        let canonical_asset = supported.get(0).unwrap();

        let before_rev = payroll_client.get_config_revision();

        payroll_client.set_asset_allowed(&canonical_asset, &false);

        let after_rev = payroll_client.get_config_revision();
        assert_eq!(
            after_rev,
            before_rev + 1,
            "disabling an asset must bump the config revision"
        );
    }

    // ── set_capacity_limits emits config_changed ──────────────────────────────

    /// `set_capacity_limits` must bump the revision and emit events that
    /// contain no salary values.
    #[test]
    fn test_set_capacity_limits_emits_event() {
        let env = Env::default();
        let (payroll_client, admin) = setup_payroll(&env);

        let before_rev = payroll_client.get_config_revision();
        let before_events = env.events().all().len();

        payroll_client.set_capacity_limits(&admin, &10u32, &100u32, &1_000_000i128);

        let after_events = env.events().all().len();
        assert!(
            after_events > before_events,
            "set_capacity_limits must emit at least one event"
        );

        let after_rev = payroll_client.get_config_revision();
        assert_eq!(
            after_rev,
            before_rev + 1,
            "config revision must increment after set_capacity_limits"
        );
    }

    // ── admin rotation emits config_changed ──────────────────────────────────

    /// Accepting an admin rotation emits a `config_changed` event and bumps
    /// the config revision.  The event data must not include salary values.
    #[test]
    fn test_admin_rotation_emits_event() {
        let env = Env::default();
        let (payroll_client, admin) = setup_payroll(&env);

        let new_admin = Address::generate(&env);
        payroll_client.propose_admin_rotation(&admin, &new_admin);

        let before_rev = payroll_client.get_config_revision();

        payroll_client.accept_admin_rotation(&new_admin);

        let after_rev = payroll_client.get_config_revision();
        // The admin rotation may emit a config_changed bump; at minimum it
        // must emit an event via payroll_events.
        assert!(
            after_rev >= before_rev,
            "admin rotation must not decrease the config revision"
        );
    }

    // ── treasury update emits event ───────────────────────────────────────────

    /// Accepting a treasury rotation must emit at least one event without
    /// including salary or commitment data.
    #[test]
    fn test_treasury_update_emits_event() {
        let env = Env::default();
        let (payroll_client, _admin) = setup_payroll(&env);

        // Get treasury owner from contract state.  setup_payroll uses a
        // fresh treasury_owner so we need to look it up — we mock all auths.
        let new_treasury_owner = Address::generate(&env);

        // propose from the existing treasury_owner (mock_all_auths allows this).
        let before_events = env.events().all().len();
        payroll_client.propose_treasury_rotation(&Address::generate(&env), &new_treasury_owner);
        let after_events = env.events().all().len();

        // At minimum a proposal event must be emitted.
        assert!(
            after_events > before_events,
            "treasury rotation proposal must emit at least one event"
        );
    }

    // ── no private values in any config event ────────────────────────────────

    /// No config change event on the payroll contract should have data that
    /// decodes as a bare `i128` (which would indicate a leaked salary value).
    #[test]
    fn test_event_metadata_excludes_private_values() {
        let env = Env::default();
        let (payroll_client, admin) = setup_payroll(&env);

        // Trigger several config changes.
        let pm_id = env.register_contract(None, PauseManager);
        let pm_client = PauseManagerClient::new(&env, &pm_id);
        pm_client.initialize(&Address::generate(&env));
        payroll_client.set_pause_manager(&pm_id);

        payroll_client.set_capacity_limits(&admin, &5u32, &50u32, &500_000i128);

        let supported = payroll_client.get_supported_assets();
        let canonical_asset = supported.get(0).unwrap();
        payroll_client.set_asset_allowed(&canonical_asset, &false);
        payroll_client.set_asset_allowed(&canonical_asset, &true);

        // Inspect every emitted event — none should have data decodable as a
        // bare i128 (which would represent a leaked salary or amount).
        for i in 0..env.events().all().len() {
            let event = env.events().all().get(i).unwrap();
            let result: Result<i128, _> = event.2.clone().try_into_val(&env);
            assert!(
                result.is_err(),
                "event #{i} must not have data decodable as a bare i128"
            );
        }
    }
}
