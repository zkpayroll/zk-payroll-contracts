# Payroll Configuration Audit Events (#490)

Every successful change to a `payroll` contract configuration setting
publishes exactly one `config_changed` audit event. The event records **who**
made the change, **which** setting changed, **references** (hashes) to the
previous and new values, and a monotonically increasing **revision**, so
auditors can reconstruct and verify the configuration history without the
event log exposing configuration values.

The logic lives in one helper, `record_config_change` in
[`contracts/payroll/src/config_audit.rs`](../contracts/payroll/src/config_audit.rs);
the event type is `ConfigChanged` in
[`contracts/events/src/lib.rs`](../contracts/events/src/lib.rs).

## Event schema

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("config_changed")
topics[2]  Symbol   key              which setting changed (table below)
data[0]    Address  actor            authenticated address that made the change
data[1]    BytesN<32> subject_ref    sha256 of the asset / period / role holder the
                                     setting is keyed by; all zeros if not keyed
data[2]    BytesN<32> previous_ref   sha256 of the value before the change;
                                     all zeros if there was no value
data[3]    BytesN<32> new_ref        sha256 of the value after the change;
                                     all zeros if the value was removed
data[4]    u64      revision         contract-wide configuration revision after
                                     this change (1, 2, 3, ...)
data[5]    u32      ledger_sequence  env.ledger().sequence()
data[6]    u64      timestamp        env.ledger().timestamp()
```

`data` is a vector in the order above (the same shape as the tuple payloads
used by the other `payroll` events).

### Configuration keys

| `key` | Entrypoint(s) | Actor (authorized by) | Subject | Value referenced |
|-------|---------------|-----------------------|---------|------------------|
| `pause_manager` | `set_pause_manager` | admin | — | pause manager `Address` |
| `asset_allowed` | `set_asset_allowed` | admin | asset `Address` | `bool` |
| `company_state` | `set_company_state` | admin | — | `CompanyState` |
| `capacity_limits` | `set_capacity_limits` | admin | — | `CapacityLimits` |
| `settlement_window` | `set_settlement_window` | admin | period `Symbol` | `SettlementWindow` |
| `period_frozen` | `freeze_period_config` | admin | period `Symbol` | `bool` |
| `retention_policy` | `set_retention_policy` | admin | — | `RetentionPolicy` |
| `dispute_authority` | `add_dispute_authority`, `remove_dispute_authority` | admin | authority `Address` | `bool` (absent once removed) |
| `reviewer` | `add_reviewer`, `remove_reviewer` | admin | reviewer `Address` | `bool` (absent once removed) |
| `reservation_expiry` | `set_reservation_expiry_policy` | admin | asset `Address` | `ReservationExpiry` |
| `payroll_currency` | `set_payroll_currency` | admin | — | `PayrollCurrencyConfig` |
| `storage_version` | `set_storage_version` | admin | — | `StorageVersionState` |
| `admin` | `accept_admin_rotation`, `accept_admin_handover` | the **new** admin | — | admin `Address` |
| `treasury_owner` | `accept_treasury_rotation` | the **new** treasury owner | — | treasury owner `Address` |

Each actor is checked against the stored role (not just any address that
signs) and must pass `require_auth`, so the `actor` field is always the
address whose signature the change required.

Not audited, by design:

- `propose_*`, `cancel_*`, and `request_admin_handover` are inert until
  accepted; the accepting call is the audited change.
- `initialize` is one-time setup and is already covered by the
  `("payroll", "initialized")` event.
- Operational calls (`open_capacity_period`, payroll runs, drafts, disputes,
  compliance holds, archival, pruning) are not configuration changes.

## Revision

`revision` is a single contract-wide `u64` counter in persistent storage
(`DataKey::ConfigRevision`). It starts at `0` and increases by exactly one for
every audited change, across all keys. `get_config_revision()` returns the
current value. Because the counter is global, an indexer that has events
`1..=N` with no gaps and `get_config_revision() == N` knows it has not missed
any configuration change.

The events are the audit trail: the contract stores only the counter, not a
history of changes.

## No-op, failed, and rejected changes

- **No-op:** if the stored value after the call is byte-for-byte identical
  to the value before it (for example, re-adding an existing reviewer or
  setting the same capacity limits again), the setter behaves exactly as
  before, including any existing domain event. However, **no audit event is
  published and the revision is not bumped**. Settings that record a
  timestamp (`settlement_window`, `reservation_expiry`, `payroll_currency`,
  `storage_version`) change whenever that timestamp changes, so re-applying
  them in a later ledger is audited.
- **Failed calls** (unauthorized caller, missing authorization, invalid input,
  configuration lock) revert, so they publish nothing and leave the revision
  unchanged. Failure messages name the role or rule that was violated and never
  echo the submitted configuration values.

## Verifying a reference

A reference is `sha256` of the canonical XDR encoding of the `ScVal`:

```
ref = sha256( ScVal(value).to_xdr() )        // all zeros when there is no value
```

To check an event:

1. Read the setting's value at the ledger before the change (for
   `previous_ref`) or after it (for `new_ref`). The easiest source is the
   `ScVal` returned by simulating the matching getter, such as
   `get_capacity_limits`, `get_settlement_window(period)`,
   `get_reservation_expiry(asset)`, `get_retention_policy`,
   `get_payroll_currency`, `get_storage_version`, `get_treasury_owner`,
   `get_addresses().admin`, or `is_reviewer(addr)`. Alternatively, read the
   contract data ledger entry directly. For `pause_manager` and
   `dispute_authority` there is no getter that returns the stored value, so use
   the ledger entry.
2. If nothing is stored (for example, a setting that was never configured or
   a revoked reviewer), the reference is 32 zero bytes. Note that some getters
   return a default for an absent value (`get_company_state` returns `Active`,
   `is_asset_allowed` and `is_reviewer` return `false`, and
   `is_dispute_authority` returns `true` for the admin), but the reference is
   still all zeros.
3. Otherwise compute `sha256` over the value's XDR bytes and compare.
4. Check the chain: for consecutive events with the same `key` and
   `subject_ref`, `previous_ref` of the later event equals `new_ref` of the
   earlier one.

In Rust (tests or tooling):

```rust
use soroban_sdk::xdr::ToXdr;
let expected: BytesN<32> = env.crypto().sha256(&value.to_xdr(&env)).into();
```

Subjects are referenced the same way: `subject_ref = sha256(ScVal(subject).to_xdr())`.

## Privacy

Contract events are public and permanent. The audit event publishes only:

- the actor address (already public as the transaction signer),
- the setting name,
- 32-byte digests,
- the revision, ledger sequence, and timestamp.

It never publishes a configuration value in plaintext. That covers amounts
and limits (`reserved_amount`, `max_total_value`), windows and timestamps,
currency codes, asset and period identifiers, and reviewer or authority
addresses.

Configuration setters never touch salaries, per-employee amounts, employee
identities, salary commitments, blinding factors, or proofs, so none of these
can reach an audit event.

What the digests do **not** do: they are integrity references, not
encryption. Configuration values are stored in contract storage, which is
publicly readable, and a low-entropy value (a `bool`, a `CompanyState`, a
known address) can be confirmed by hashing candidate values. Some
pre-existing domain events published by the same setters (for example
`capacity_limits_set`, `asset_allowlist_updated`, `reviewer_added`) already
carry their values in plaintext. This change leaves those events unchanged
and adds no new plaintext.

## Tests

[`contracts/payroll/tests/config_audit_events.rs`](../contracts/payroll/tests/config_audit_events.rs)
covers:

- one event per setter with exact fields,
- the zero "no value" reference,
- revision increments and chaining,
- references matching `sha256` of the stored value,
- unauthorized and invalid-input changes (no event, no revision bump),
- no-op changes,
- no plaintext values in events,
- value-free error messages,
- a full payroll run after configuration changes,
- the actor's `require_auth`.

Run them with:

```bash
cargo test -p payroll --test config_audit_events
```
