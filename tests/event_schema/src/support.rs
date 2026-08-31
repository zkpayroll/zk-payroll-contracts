//! Shared scaffolding for the event schema snapshot tests.
//!
//! Each contract event is captured twice, structurally:
//! - **topics**, compared as a whole `soroban_sdk::Vec<Val>` against the
//!   exact tuple the emitter publishes, so any reordering, insertion, or type
//!   change in the topic list fails the test immediately.
//! - **data**, decoded into the exact Rust tuple/type the emitter constructs
//!   and compared field-for-field, so a payload shape change (added/removed
//!   field, reordered field, retyped field) fails to decode or fails the
//!   `assert_eq!`.
//!
//! On top of that structural check, each event also produces an [`EventSchema`]
//! description (topic kinds + payload field names/types + a schema version)
//! that is compared against a checked-in fixture in `fixtures/events/`. The
//! fixture is what reviewers actually diff in a pull request, and what a
//! consumer team can point to as the contract for a given event. See
//! `fixtures/events/README.md` for the intentional-migration process.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use soroban_sdk::testutils::Events;
use soroban_sdk::{contract, contractimpl, Address, Env, Val, Vec as SVec};

/// A no-op contract whose only purpose is to give `as_contract` a real,
/// registered contract instance to publish events under. `payroll_events`
/// helpers are free functions, not contract entrypoints, so tests invoke
/// them directly rather than through this contract's (empty) interface.
#[contract]
pub struct EventProbe;

#[contractimpl]
impl EventProbe {}

/// One topic slot in an event's topic list.
///
/// `Symbol` topics carry a fixed `value` (the domain/action name is part of
/// the contract, so it is asserted verbatim). Topics that carry a
/// per-invocation identifier (an `Address`, a `u64` id, ...) only pin the
/// *type*, since the value is naturally dynamic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicSpec {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

pub fn sym(value: &str) -> TopicSpec {
    TopicSpec {
        ty: "Symbol".to_string(),
        value: Some(value.to_string()),
    }
}

pub fn dynamic(ty: &str) -> TopicSpec {
    TopicSpec {
        ty: ty.to_string(),
        value: None,
    }
}

/// One field in an event's data payload. Soroban events carry payload fields
/// positionally (there are no on-the-wire field names), so `name` here is
/// documentation for SDK/indexer authors, while `type` is what the snapshot
/// actually enforces via the decode step in each test.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

pub fn field(name: &str, ty: &str) -> FieldSpec {
    FieldSpec {
        name: name.to_string(),
        ty: ty.to_string(),
    }
}

/// The full schema description for one event, as recorded in a fixture file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSchema {
    pub schema_version: u32,
    pub topics: Vec<TopicSpec>,
    pub data: Vec<FieldSpec>,
}

/// Fixture files map `"<contract>.<event>"` to its [`EventSchema`]. A map
/// (rather than an ordered list) is used so that adding a new event, or
/// reordering the test functions that produce them, never causes a spurious
/// diff for events that did not change.
pub type SchemaMap = BTreeMap<String, EventSchema>;

/// A fresh, isolated `Env` plus a synthetic contract id to publish events
/// under (`payroll_events` helpers require an active contract frame).
pub fn new_env() -> (Env, Address) {
    let env = Env::default();
    let contract_id = env.register_contract(None, EventProbe);
    (env, contract_id)
}

/// Returns the most recently published event as `(contract, topics, data)`.
pub fn last_event(env: &Env) -> (Address, SVec<Val>, Val) {
    let all = env.events().all();
    let len = all.len();
    assert!(len > 0, "expected an event to have been published");
    all.get(len - 1).unwrap()
}

/// Compares the schemas observed in this test run against the checked-in
/// fixture, with a failure message that points at the migration doc instead
/// of a bare `assert_eq!`.
pub fn assert_matches_fixture(fixture_name: &str, fixture_json: &str, observed: SchemaMap) {
    let expected: SchemaMap = serde_json::from_str(fixture_json)
        .unwrap_or_else(|err| panic!("fixtures/events/{fixture_name}.json failed to parse: {err}"));
    assert_eq!(
        observed, expected,
        "\n\nEvent schema drift detected against fixtures/events/{fixture_name}.json.\n\
         If this is an intentional schema change: bump `schema_version` for the\n\
         affected event(s), update the fixture, and record the migration per\n\
         fixtures/events/README.md before merging.\n"
    );
}
