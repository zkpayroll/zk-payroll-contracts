//! # Audit Grant Revocation Event Tests (issue #284)
//!
//! Pins down the exact on-chain event schema `audit_module` emits around
//! view-key revocation, and confirms two properties the issue calls out
//! specifically:
//!
//! 1. "Revocation should be visible to auditors" — `revoke_view_key` emits a
//!    precisely-structured `AuditAccessRevoked` event on success, and a
//!    *failed* revocation attempt (wrong granter, unknown auditor) emits no
//!    event at all, so observers never see a misleading revocation signal.
//! 2. "Confirm the change does not expose private payroll values in ...
//!    events" — `ViewKeyGenerated`'s event data is checked to hold only the
//!    expiration ledger, never the raw 32-byte key material itself (which
//!    would let anyone bypass the keyed-commitment scheme without holding
//!    the actual key).
//!
//! `docs/events.md` previously claimed `AuditAccessRevoked` carries a
//! `timestamp` in its data and `ViewKeyGenerated` carries the raw
//! `key_bytes` — neither matches the actual emission code in
//! `contracts/events/src/lib.rs`. These tests assert the real schema so the
//! docs (now corrected) and the contract can't silently drift apart again.
//!
//! ## How to run
//!
//! ```bash
//! cargo test -p audit_revocation_event_tests
//! ```

#[cfg(test)]
mod tests {
    use audit_module::{AuditModule, AuditModuleClient};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Address, Env, Symbol, TryIntoVal};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AuditModule);
        (env, contract_id)
    }

    // ── AuditAccessRevoked: exact schema on success ───────────────────────────

    #[test]
    fn test_audit_access_revoked_topics_are_symbol_admin_auditor() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let admin = contract_id.clone();
        let before = env.events().all().len();
        client.revoke_view_key(&admin, &auditor);
        let after = env.events().all().len();
        assert_eq!(after, before + 1, "revocation must emit exactly one event");

        let event = env.events().all().get(after - 1).unwrap();
        assert_eq!(event.1.len(), 3, "topics must be (Symbol, admin, auditor)");

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "AuditAccessRevoked"));

        let topic_admin: Address = event.1.get(1).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_admin, admin);

        let topic_auditor: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_auditor, auditor);
    }

    /// The event carries no data payload at all — in particular no salary,
    /// commitment, or key material. Pinning this down as `()` protects
    /// against a future change accidentally attaching a sensitive value.
    #[test]
    fn test_audit_access_revoked_data_is_empty() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();
        let data: Result<(), _> = event.2.try_into_val(&env);
        assert!(data.is_ok(), "AuditAccessRevoked data must decode as empty");
    }

    // ── No event on a failed revocation attempt ───────────────────────────────

    /// An unauthorized revocation attempt must be a complete no-op,
    /// including no event — an observer watching for `AuditAccessRevoked`
    /// must never see a signal for a grant that is still fully live.
    #[test]
    fn test_failed_revoke_wrong_granter_emits_no_event() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor, &(seq + 1_000));

        let before = env.events().all().len();
        let interloper = Address::generate(&env);
        let result = client.try_revoke_view_key(&interloper, &auditor);
        assert!(result.is_err());

        let after = env.events().all().len();
        assert_eq!(
            after, before,
            "a rejected revocation must not emit any event"
        );
    }

    /// Revoking an auditor who was never granted a key must also be a
    /// silent, event-free failure.
    #[test]
    fn test_failed_revoke_unknown_auditor_emits_no_event() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let before = env.events().all().len();

        let admin = contract_id.clone();
        let result = client.try_revoke_view_key(&admin, &stranger);
        assert!(result.is_err());

        let after = env.events().all().len();
        assert_eq!(
            after, before,
            "revoking an unknown auditor must not emit any event"
        );
    }

    // ── Revocation event targets exactly the intended auditor ────────────────

    /// When two auditors hold live grants, revoking one must emit an event
    /// naming exactly that auditor — never the other one.
    #[test]
    fn test_revoked_event_names_exactly_the_targeted_auditor() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor_a = Address::generate(&env);
        let auditor_b = Address::generate(&env);
        let seq = env.ledger().sequence();
        client.generate_view_key(&auditor_a, &(seq + 1_000));
        client.generate_view_key(&auditor_b, &(seq + 1_000));

        let admin = contract_id.clone();
        client.revoke_view_key(&admin, &auditor_a);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();
        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "AuditAccessRevoked"));
        let named_auditor: Address = event.1.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(named_auditor, auditor_a);
        assert_ne!(named_auditor, auditor_b);
    }

    // ── ViewKeyGenerated: privacy of the event payload ────────────────────────

    /// The generated key material itself must never appear in the public
    /// event — only the expiration ledger. Leaking the raw key bytes would
    /// let anyone perform keyed-commitment checks without ever holding a
    /// genuine grant, defeating the point of a per-auditor view key.
    #[test]
    fn test_view_key_generated_event_data_excludes_raw_key_bytes() {
        let (env, contract_id) = setup();
        let client = AuditModuleClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let seq = env.ledger().sequence();
        let expiration = seq + 1_000;
        let key_bytes = client.generate_view_key(&auditor, &expiration);

        let event = env
            .events()
            .all()
            .get(env.events().all().len() - 1)
            .unwrap();

        let sym: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(sym, Symbol::new(&env, "ViewKeyGenerated"));

        // The data payload decodes as exactly one u32 (expiration_ledger).
        // Soroban's tuple decoding enforces exact arity — if the payload
        // also carried the 32-byte key material, this single-field decode
        // would fail (and does, if you widen the target type), so a
        // successful decode here is itself the proof that no extra field —
        // in particular no key bytes — is present.
        let data: (u32,) = event.2.try_into_val(&env).unwrap();
        assert_eq!(data.0, expiration);

        // Sanity: the key returned to the caller is still real 32-byte
        // material — it's just never published in the event.
        assert_eq!(key_bytes.len(), 32);
    }
}
