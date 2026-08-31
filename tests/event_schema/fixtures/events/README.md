# Event schema fixtures

This directory pins the wire shape of every Soroban event emitted through
`payroll_events` (`contracts/events/src/lib.rs`). Each file is a JSON map,
keyed `"<contract-domain>.<event>"`, of the topics and payload fields that
event is expected to publish:

```json
"payroll.deposit": {
  "schema_version": 1,
  "topics": [
    { "type": "Symbol", "value": "payroll" },
    { "type": "Symbol", "value": "deposit" }
  ],
  "data": [
    { "name": "from", "type": "Address" },
    { "name": "amount", "type": "i128" },
    { "name": "deposit_id", "type": "BytesN<32>" }
  ]
}
```

- `topics` are positional. A `Symbol` topic records its exact `value`
  because it *is* part of the contract (SDKs filter on it). A topic that
  carries a per-invocation identifier (`Address`, `u64`, ...) only records
  its `type`, since the value is naturally dynamic.
- `data` is also positional — Soroban events don't carry field names on the
  wire — so `name` here is documentation for the humans and tools consuming
  the event; only `type` (and field order/count) is actually enforced.
- `schema_version` is a per-event, repo-only counter. It is **not** part of
  the on-chain payload; consumers key off event name plus shape. Bump it
  whenever you deliberately change that event's topics or data, so a
  changelog entry / consumer migration is easy to find in git blame.

## How the tests use this

`tests/event_schema/src/<domain>.rs` has one `#[test]` per contract domain.
Each test:

1. Calls the real `payroll_events::emit_*` helper with fixture input values,
   inside a registered dummy contract frame.
2. Asserts the published **topics** equal the exact tuple the emitter
   constructs (`assert_eq!` on the whole `Vec<Val>` — order, count, and
   values all have to match).
3. Decodes the published **data** into the exact Rust type the emitter
   passed in and asserts it back against the input values. If a field is
   added, removed, reordered, or retyped, this decode fails (or the
   `assert_eq!` after it fails).
4. Builds an `EventSchema` description of what it just observed and
   compares the whole domain's map against the checked-in fixture here.

Any of those three checks failing means the event's shape drifted from what
this fixture says a consumer can rely on.

## Updating a fixture on an intentional change

1. Change the `emit_*` helper in `contracts/events/src/lib.rs` as needed.
2. Update (or add) the corresponding `case_*` function in
   `tests/event_schema/src/<domain>.rs` so it constructs/decodes the new
   shape — the compiler will point you at every call site and decode that
   needs updating.
3. **Bump `schema_version`** for every changed event in the fixture file.
4. Update the fixture's `topics`/`data` entries to match the new shape.
5. Run `cargo test -p event_schema_snapshots` and confirm it's green.
6. Call out the schema change (event name, old/new shape, new version) in
   the PR description so SDK/dashboard/indexer owners can update their
   parsers before this lands.

Do not bump `schema_version` for a change that only affects this
repo's tests (e.g. reordering `case_*` calls) — only for an actual change
to what gets published on-chain.

## Adding a new event

1. Add the `emit_*` helper to `contracts/events/src/lib.rs`.
2. Add a `case_*` function for it in the right `tests/event_schema/src/<domain>.rs`
   (or create a new domain module + fixture file for a new contract), following
   the existing cases as a template.
3. Add its entry to the fixture JSON with `schema_version: 1`.
4. Run `cargo test -p event_schema_snapshots`.
