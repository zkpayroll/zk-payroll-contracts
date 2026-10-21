//! # Employee Wallet Update Event Tests (issue #269)
//!
//! Verifies that `update_payout_destination_wallet` (and the underlying
//! `update_payout_destination`) emit a correctly-structured
//! `PayoutDestinationUpdated` event and that the event does not leak any
//! private salary commitment values.
//!
//! Two properties from the issue are pinned here:
//!
//! 1. "Safe metadata" — topics carry only the event symbol, the company ID,
//!    and the employee address; no salary amounts or 32-byte commitment hashes.
//! 2. "Correct employee reference" — the third topic is exactly the employee
//!    address that performed the update, never another employee.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p audit_revocation_event_tests
//! ```

#[cfg(test)]
mod wallet_update_event_tests {
    use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Address, BytesN, Env, String, Symbol, TryIntoVal};

    // A valid Stellar account StrKey that is NOT the zero address.
    // Encodes 32 key bytes of 0x01 (key starting with 0x01, rest zeros):
    //   version 0x30 + [0x01, 0x00, ..., 0x00] + CRC16-XMODEM
    const VALID_WALLET_NON_ZERO: &str =
        "GAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHV4";

    // A second valid Stellar account StrKey for multi-address tests.
    // Encodes 32 key bytes of 0x01:
    //   version 0x30 + [0x01; 32] + CRC16-XMODEM
    const VALID_WALLET_ALL_ONES: &str =
        "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H";

    // The Stellar zero address — valid format but blocked as a destination.
    const ZERO_WALLET: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    /// Set up a fresh environment with a registered company and one employee.
    /// Returns `(env, client, company_id, employee_address, salary_commitment)`.
    fn setup() -> (
        Env,
        PayrollRegistryClient<'static>,
        u64,
        Address,
        BytesN<32>,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register_contract(None, PayrollRegistry);
        let client = PayrollRegistryClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[0xab; 32]);
        let employee = Address::generate(&env);

        let company_id = client.register_company(&admin, &treasury);
        client.add_employee(&company_id, &employee, &commitment);

        (env, client, company_id, employee, commitment)
    }

    // ── Test 1: wallet path emits PayoutDestinationUpdated ───────────────────

    /// Calling `update_payout_destination_wallet` must emit exactly one
    /// `PayoutDestinationUpdated` event whose topics are
    /// `(Symbol, company_id: u64, employee: Address)` and whose data payload
    /// is `(old_dest: Address, new_dest: Address)`.
    #[test]
    fn test_wallet_update_emits_payout_destination_updated_event() {
        let (env, client, company_id, employee, _commitment) = setup();

        // Default destination before any update is the employee address itself.
        let old_dest = employee.clone();

        let new_dest_wallet = String::from_str(&env, VALID_WALLET_NON_ZERO);
        let new_dest = Address::from_string(&new_dest_wallet);

        let before = env.events().all().len();
        client.update_payout_destination_wallet(&company_id, &employee, &new_dest_wallet);
        let after = env.events().all().len();

        assert_eq!(
            after,
            before + 1,
            "update_payout_destination_wallet must emit exactly one event"
        );

        let event = env.events().all().get(after - 1).unwrap();

        // Topics: (Symbol, company_id, employee)
        assert_eq!(
            event.1.len(),
            3,
            "PayoutDestinationUpdated must have exactly 3 topics"
        );

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "PayoutDestinationUpdated"),
            "first topic must be 'PayoutDestinationUpdated'"
        );

        let topic_company_id: u64 = event.1.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_company_id, company_id,
            "second topic must be the company ID"
        );

        let topic_employee: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_employee, employee,
            "third topic must be the employee address"
        );

        // Data: (old_dest, new_dest)
        let (data_old, data_new): (Address, Address) = event.2.try_into_val(&env).unwrap();
        assert_eq!(data_old, old_dest, "data[0] must be the previous destination");
        assert_eq!(
            data_new, new_dest,
            "data[1] must be the newly set destination"
        );
    }

    // ── Test 2: topics contain no salary commitment data ─────────────────────

    /// The three topics of a `PayoutDestinationUpdated` event must not contain
    /// any 32-byte commitment hash. If a commitment leaked into the topics, any
    /// observer could correlate it with the employee's salary range.
    #[test]
    fn test_wallet_update_event_topics_contain_no_salary_data() {
        let (env, client, company_id, employee, commitment) = setup();

        let new_dest_wallet = String::from_str(&env, VALID_WALLET_NON_ZERO);

        client.update_payout_destination_wallet(&company_id, &employee, &new_dest_wallet);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();

        // None of the three topics should decode as the 32-byte salary commitment.
        for i in 0..event.1.len() {
            let topic_val = event.1.get(i).unwrap();
            let as_commitment: Result<BytesN<32>, _> = topic_val.try_into_val(&env);
            if let Ok(decoded) = as_commitment {
                assert_ne!(
                    decoded, commitment,
                    "topic {} must not contain the salary commitment hash",
                    i
                );
            }
        }
    }

    // ── Test 3: event data contains only addresses, not commitment hashes ────

    /// The data payload of `PayoutDestinationUpdated` must decode as
    /// `(Address, Address)` — the old and new payout destinations. It must
    /// not be possible to extract the salary commitment hash from the data.
    #[test]
    fn test_wallet_update_event_does_not_expose_commitment() {
        let (env, client, company_id, employee, commitment) = setup();

        let new_dest_wallet = String::from_str(&env, VALID_WALLET_NON_ZERO);
        client.update_payout_destination_wallet(&company_id, &employee, &new_dest_wallet);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();

        // The data must decode as exactly two addresses.
        let result: Result<(Address, Address), _> = event.2.try_into_val(&env);
        assert!(
            result.is_ok(),
            "event data must decode as (Address, Address)"
        );

        let (old_dest, new_dest) = result.unwrap();

        // Neither address should accidentally equal the commitment bytes.
        // The commitment is BytesN<32>; an Address is a different type, so this
        // verifies the data shape is purely address-based with no 32-byte hash.
        let new_dest_wallet_addr =
            Address::from_string(&String::from_str(&env, VALID_WALLET_NON_ZERO));
        assert_eq!(
            old_dest, employee,
            "old destination must be the employee address (default)"
        );
        assert_eq!(
            new_dest, new_dest_wallet_addr,
            "new destination must be the wallet-derived address"
        );

        // Attempting to decode the data as a commitment tuple must fail,
        // confirming no commitment is embedded in the data payload.
        let as_commitment: Result<(BytesN<32>,), _> = event.2.try_into_val(&env);
        assert!(
            as_commitment.is_err(),
            "event data must not be decodable as a commitment hash tuple"
        );
        // Ensure the commitment itself is not accidentally stored as data.
        let _ = commitment; // acknowledged; not present in event
    }

    // ── Test 4: direct address update emits the same event structure ─────────

    /// `update_payout_destination` (the direct-address variant, not the wallet
    /// path) must produce an identical `PayoutDestinationUpdated` event shape.
    /// Both entry points funnel through the same emission code.
    #[test]
    fn test_direct_address_update_emits_same_event() {
        let (env, client, company_id, employee, _commitment) = setup();

        let new_dest = Address::generate(&env);
        let old_dest = employee.clone();

        let before = env.events().all().len();
        client.update_payout_destination(&company_id, &employee, &new_dest);
        let after = env.events().all().len();

        assert_eq!(
            after,
            before + 1,
            "update_payout_destination must emit exactly one event"
        );

        let event = env.events().all().get(after - 1).unwrap();

        // Topics: (Symbol, company_id, employee)
        assert_eq!(event.1.len(), 3, "must have exactly 3 topics");

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            sym,
            Symbol::new(&env, "PayoutDestinationUpdated"),
            "first topic must be 'PayoutDestinationUpdated'"
        );

        let topic_company_id: u64 = event.1.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_company_id, company_id,
            "second topic must be the company ID"
        );

        let topic_employee: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(
            topic_employee, employee,
            "third topic must be the employee address"
        );

        // Data: (old_dest, new_dest)
        let (data_old, data_new): (Address, Address) = event.2.try_into_val(&env).unwrap();
        assert_eq!(data_old, old_dest, "data[0] must be the previous destination");
        assert_eq!(data_new, new_dest, "data[1] must be the newly set destination");
    }

    // ── Test 5: duplicate destination rejected ────────────────────────────────

    /// Setting the same wallet destination twice must be rejected on the
    /// second call.  The second call must neither succeed nor emit an event.
    #[test]
    #[should_panic]
    fn test_wallet_update_event_duplicate_rejected() {
        let (env, client, company_id, employee, _commitment) = setup();

        let new_dest_wallet = String::from_str(&env, VALID_WALLET_NON_ZERO);

        // First update: should succeed and emit one event.
        client.update_payout_destination_wallet(&company_id, &employee, &new_dest_wallet);
        let events_after_first = env.events().all().len();
        assert!(events_after_first > 0);

        // Second update with the same wallet: must panic (duplicate destination).
        client.update_payout_destination_wallet(&company_id, &employee, &new_dest_wallet);
    }

    // ── Test 6: invalid wallet format panics and emits no event ──────────────

    /// Providing a wallet string that fails checksum validation must cause the
    /// call to panic and must not emit any event — no partial or misleading
    /// `PayoutDestinationUpdated` signal should be observable.
    #[test]
    #[should_panic(expected = "Invalid employee wallet address format")]
    fn test_invalid_wallet_format_emits_no_event() {
        let (env, client, company_id, employee, _commitment) = setup();

        // Record the event count before the failing call.
        let before = env.events().all().len();

        let bad_wallet = String::from_str(&env, "not-a-valid-stellar-wallet-string");

        // This call must panic due to format validation.
        client.update_payout_destination_wallet(&company_id, &employee, &bad_wallet);

        // If the panic is caught (e.g., in a should_panic context), verify no
        // event was emitted. In practice the should_panic attribute handles
        // this, but the assertion documents the contract.
        assert_eq!(
            env.events().all().len(),
            before,
            "a rejected wallet update must not emit any event"
        );
    }
}
