# Contract Upgrade Strategy — Issue #83

Defines how ZK Payroll contract data structures and entry-points can evolve without breaking downstream consumers (SDK, dashboard, indexers). This document reduces future migration risk and aligns teams on schema upgrade assumptions.

---

## Background

The ZK Payroll system is **early-stage** and contract schemas will change. The current design assumes:

- **No storage versioning yet** — contracts are single-initialization (cannot be re-initialized).
- **Proofs are schema-versioned** — see `docs/interop/proof-schema-version-negotiation.md` for proof format evolution.
- **Data structures are not versioned** — storage layout is fixed until a new contract is deployed.

This document plans for safe evolution as requirements change (e.g., multi-currency, batch commitments, new verification schemes).

---

## Part 1: Identifying Upgrade Surfaces

The contract interfaces that **will likely change**:

### 1.1 Proof Schema

**Surface:** `contracts/proof_verifier/src/lib.rs` — `verify_payment_proof(proof, public_inputs)`

**Why it changes:** New proof circuit designs (e.g., range proofs, batch proofs, zero-knowledge range arguments).

**Change example:**
```diff
- public_inputs: [commitment, amount]
+ public_inputs: [commitment, amount, timestamp, recipient_hash]
```

**Impact:**
- ❌ Clients generating old-schema proofs will fail verification.
- ✅ Mitigated by: Proof versioning (see `docs/interop/proof-schema-version-negotiation.md`).

**Upgrade path:**
1. New circuit + new verification key deployed in **new verifier contract**.
2. Clients updated to generate new-schema proofs.
3. Payment executor points to new verifier contract.
4. Old verifier kept read-only for 30 days for audit queries.

---

### 1.2 Salary Commitment Storage

**Surface:** `contracts/salary_commitment/src/lib.rs` — `set_commitment(employee_id, commitment)`

**Current:** Stores `commitment: BytesN<32>` per employee.

**Why it might change:**
- Support batch commitments (multiple salary tiers per employee).
- Store commitment metadata (vesting schedule, deductions, currency).
- Use Poseidon hash instead of SHA-256 fallback (when CAP-0075 is available).

**Change example:**
```rust
// v1: Simple commitment
pub struct SalaryCommitment {
    value: BytesN<32>,  // hash
}

// v2: Commitment with metadata
pub struct SalaryCommitmentV2 {
    value: BytesN<32>,
    vesting_schedule: u64,  // in days
    currency_code: u32,      // e.g., "USD", "XLM"
    created_at: u64,         // timestamp
}
```

**Impact:**
- ❌ Old contracts cannot read new commitment format.
- ❌ New contracts cannot read old commitment format.
- ✅ Mitigated by: Explicit version field + separate new contract deployment.

**Upgrade path:**
1. Deploy **new salary_commitment_v2 contract** with extended schema.
2. Migrate historical commitments (off-chain tool or gradual on-chain migration).
3. Payment executor uses new contract address.
4. Old commitment contract kept read-only for audits.

---

### 1.3 Payment Executor Entry-Points

**Surface:** `contracts/payment_executor/src/lib.rs` — `process_payment()`, `execute_batch()`

**Current:** Requires proof and public inputs; no batch metadata.

**Why it might change:**
- Add `batch_id` field for audits.
- Support conditional payments (time-locked, vesting).
- Add `settlement_token` to support multi-currency payroll.

**Change example:**
```rust
// v1
pub fn process_payment(
    proof: BytesN<256>,
    public_inputs: Vec<BytesN<32>>,
) -> Result<(), PaymentError>

// v2 with settlement token
pub fn process_payment_v2(
    proof: BytesN<256>,
    public_inputs: Vec<BytesN<32>>,
    settlement_token: Address,  // NEW
) -> Result<(), PaymentError>
```

**Impact:**
- ❌ Old SDK clients calling `process_payment()` still work, but cannot use new currency feature.
- ✅ New entry-point is parallel, doesn't break old one.

**Upgrade path:**
1. Add new entry-point `process_payment_v2()` alongside existing `process_payment()`.
2. Clients can opt-in to new feature; old clients unaffected.
3. Both entry-points coexist until v1 is deprecated (announce 3 releases in advance).

---

### 1.4 Registry Company / Employee Data

**Surface:** `contracts/payroll_registry/src/lib.rs` — company and employee storage.

**Current:** Minimal: `admin`, `treasury`, `created_at`.

**Why it might change:**
- Add company metadata (legal name, domain, jurisdiction).
- Add employee fields (department, cost center, tax ID).
- Support employee data versioning (historical records).

**Impact:**
- ❌ New fields cannot be queried on old contracts.
- ✅ Mitigated by: Backward-compatible extension (new optional fields).

---

## Part 2: Migration Assumptions

When a storage schema changes, what **must remain stable**?

### 2.1 Primary Keys Are Immutable

**Rule:** Once a company or employee record is created, its ID cannot change.

**Example:** Company ID `0` stays `0` forever. An employee's `(company_id, employee_id)` pair is stable.

**Why:** Downstream systems (indexers, dashboards) index by ID. Changing IDs breaks external lookups.

**Implication:** If the registry needs to change employee data, add new fields rather than renaming existing ones.

---

### 2.2 Event Structure Is Versioned

**Rule:** Events include a schema version field. If the event schema changes, the version increments.

**Example:**
```rust
pub struct PaymentMadeEvent {
    schema_version: u32,  // v1 = 1, v2 = 2
    company_id: u64,
    employee_id: u64,
    amount: u64,
    // v2 adds:
    settlement_token: Option<Address>,  // only in v2+
}
```

**Why:** Off-chain indexers subscribe to events. If the schema changes silently, indexing breaks.

**Implication:** Every event emission includes a version field. Indexers handle multiple versions.

---

### 2.3 Deprecation Requires Announcement

**Rule:** Any breaking change (removing a field, changing parameter order) requires:
1. RFC or issue discussing the change.
2. Announcement in release notes.
3. At least **3 release cycles** before removal.

**Example:** "In v0.2, the `set_commitment()` function will be deprecated. Migrate to `set_commitment_v2()` by v0.5."

**Why:** Gives SDK/dashboard teams time to migrate.

---

### 2.4 Proof Nullifiers Are Permanent

**Rule:** Once a proof's nullifier is recorded (payment executed), it is **never re-used**.

**Why:** Enables audit queries on old verifiers; prevents double-spend even across contract upgrades.

**Implication:** Nullifier storage is kept in the old payment executor indefinitely.

---

## Part 3: Documented Upgrade Surfaces

The following surfaces **are known to change** and have migration plans:

| Surface | Current Version | Next Likely Version | Risk Level |
|---------|-----------------|-------------------|-----------|
| Proof schema | v1 (2 inputs) | v2 (3+ inputs, timestamp) | High — circuit change required |
| Commitment storage | Simple (BytesN<32>) | With metadata (vesting, currency) | Medium — parallel contract |
| Executor entry-points | `process_payment()` | `process_payment_v2()` (multi-currency) | Medium — parallel entry-point |
| Registry employee data | Minimal | Extended (dept, tax ID, metadata) | Low — backward-compatible |
| Token standard | SEP-41 | SEP-41 (no change expected) | Low |
| Proof verifier VK | Groth16 BN254 | Unknown (future ZK scheme) | Very High — long-term |

---

## Part 4: Downstream Compatibility Expectations

### 4.1 For SDK Developers

**What to expect:**
- Proof schema **will change**. Monitor `docs/interop/proof-schema-version-negotiation.md` for updates.
- Commitment schema **may change**. When upgrading, read the new contract's events to understand the format.
- Payment executor **may add new entry-points**. Old entry-points remain supported for 3+ releases.

**What you can rely on:**
- Company and employee IDs are stable.
- Event schema versioning ensures compatibility.
- Deprecations are announced 3 releases in advance.

**Action items:**
- Pin your client library to a specific **proof schema version** (see `proof-schema-version-negotiation.md`).
- Subscribe to `PaymentMadeEvent` with version awareness.
- Monitor release notes for deprecation warnings.

---

### 4.2 For Dashboard Developers

**What to expect:**
- Registry fields **may be extended** (new optional columns).
- Employee data **may include new fields** (department, cost center).
- Payment history **may expose new fields** (settlement token, vesting schedule).

**What you can rely on:**
- Company ID and employee ID are immutable.
- Event schema versioning ensures new fields are announced.
- Old UI queries continue to work.

**Action items:**
- Use **nullable columns** in your database schema (assume new fields may appear).
- Test against both old and new contract versions during migration windows.
- Monitor `release_notes.md` for new event fields.

---

### 4.3 For Off-Chain Indexers

**What to expect:**
- Event schema **will be versioned**. Handle multiple versions in your indexer.
- New events **may be added**. Indexer must gracefully skip unknown event types.
- Storage layout **does not change** (no events for historical data migration).

**What you can rely on:**
- Every event includes a `schema_version` field.
- Event types are never removed (only deprecated and new types added).
- Nullifier uniqueness is preserved across contract upgrades.

**Action items:**
- Index events by `(event_type, schema_version)`.
- Use a schema registry to map versions to fields.
- Implement tests for event version upgrades.

---

## Part 5: Upgrade Procedure

When rolling out a contract upgrade:

### 5.1 Pre-Upgrade

1. **Write an RFC** — Document the change, why it's needed, impact on SDK/dashboard, timeline.
2. **Announce in release notes** (pre-release) — "Deprecation: `set_commitment()` will be replaced by `set_commitment_v2()` in v0.5."
3. **Deploy to testnet** — New contract runs in parallel with old one.
4. **Test migration** — Verify old clients still work, new clients can use new features.
5. **Wait 1 release cycle minimum** — Let users upgrade their code.

### 5.2 Upgrade

1. **Deploy new contract** — New version deployed to mainnet (separate contract address).
2. **Update payment executor** — Point to new verifier / commitment contract.
3. **Keep old contract read-only** — Archive for 30 days (audit queries).
4. **Update documentation** — Point clients to migration guide.

### 5.3 Post-Upgrade

1. **Monitor logs** — Watch for failed transactions (old client trying to use new contract).
2. **Support period** — Answer migration questions for 1 release cycle.
3. **Archive old contract** — After 30 days, mark as deprecated in docs.

---

## Part 6: High-Risk Migration Areas

The following areas pose the **highest risk** if not handled carefully:

| Area | Risk | Mitigation |
|------|------|-----------|
| **Proof schema** | Breaking change + circuit change | Version negotiation + parallel verifiers |
| **Nullifier format** | If changed, enables double-spend | Nullifiers are immutable; new format uses new contract |
| **Treasury address** | If corrupted, payroll halts | Admin controls treasury; pause manager stops payments |
| **Commitment privacy** | If leaked, salaries exposed | Commitments never stored plaintext; audits use view keys |
| **Token contract address** | If wrong, payments go to wrong recipient | Immutable at init; deployment checklist catches errors |

---

## Part 7: SDK and Dashboard Migration Checklist

When a new contract version is released:

- [ ] Read the release notes and identify breaking changes.
- [ ] For proof schema changes: check `docs/interop/proof-schema-version-negotiation.md`.
- [ ] For commitment changes: read the new contract's Rustdocs.
- [ ] For executor changes: update client calls to use `_v2` entry-points if needed.
- [ ] Run integration tests against testnet new version.
- [ ] Update your UI / client library version pin.
- [ ] Deploy to your staging environment.
- [ ] Test end-to-end payroll flow.
- [ ] Notify your users of the upgrade timeline.

---

## Related Resources

- [Proof Schema Version Negotiation](docs/interop/proof-schema-version-negotiation.md) — How to version proof formats.
- [Contributor Module Checklist](docs/contributor-module-checklist.md) — Per-contract upgrade responsibilities.
- [Incident Response Playbook](docs/incident-response-playbook.md) — What to do if a migration breaks.
- [Release Checklist](docs/v0-readiness-checklist.md) — Pre-release validation.
