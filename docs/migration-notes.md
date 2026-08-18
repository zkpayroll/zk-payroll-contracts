# Contract Version Migration Notes

> **Issue:** [#223](https://github.com/zkpayroll/zk-payroll-contracts/issues/223)
>
> **Purpose:** Explain how each contract version transition should be performed
> safely, which storage keys are affected by each change, and how to preserve
> payroll history and admin access throughout an upgrade.
>
> **Related docs:**
> - [upgrades.md](upgrades.md) — Migration test framework, state-version rules,
>   and checklist for adding migration coverage.
> - [interop/contract-upgrade-strategy.md](interop/contract-upgrade-strategy.md)
>   — Upgrade surfaces, downstream compatibility expectations, and deprecation
>   policy.
> - [deployment-verification.md](deployment-verification.md) — Post-upgrade
>   verification checklist.

---

## Table of Contents

1. [How to Read This Document](#1-how-to-read-this-document)
2. [Current Version Baseline (v1)](#2-current-version-baseline-v1)
3. [Migration: v1 → v2 Guidance](#3-migration-v1--v2-guidance)
   - [payment_executor](#31-payment_executor)
   - [payroll_registry](#32-payroll_registry)
   - [salary_commitment](#33-salary_commitment)
   - [payroll](#34-payroll)
   - [proof_verifier](#35-proof_verifier)
   - [audit_module](#36-audit_module)
4. [Cross-Cutting Migration Rules](#4-cross-cutting-migration-rules)
5. [Step-by-Step Upgrade Runbook](#5-step-by-step-upgrade-runbook)
6. [Payroll History Preservation](#6-payroll-history-preservation)
7. [Admin Access Preservation](#7-admin-access-preservation)
8. [Rollback Procedure](#8-rollback-procedure)
9. [Version Compatibility Matrix](#9-version-compatibility-matrix)

---

## 1. How to Read This Document

Each contract section follows the same structure:

- **What changed** — the storage keys or struct fields that differ between versions.
- **Migration handler** — the function or procedure that transforms old-format
  storage into new-format storage.
- **Invariants** — assertions that must hold before and after migration.
- **Risk level** — Low / Medium / High, based on blast radius if migration fails.

> **Rule of thumb:** if a migration section is empty ("no action required"),
> the contract uses only append-safe changes and existing storage deserializes
> unchanged. When in doubt, run `cargo test -p migration_tests` and confirm
> all `mg_*` tests pass before and after deployment.

---

## 2. Current Version Baseline (v1)

All contracts are currently at storage version **1**. The table below is the
authoritative baseline; update it whenever a contract's `StorageVersion` is
bumped.

| Contract | Storage Version | Versioning Mechanism | First Deployed |
|---|---|---|---|
| `payment_executor` | **1** | Explicit `DataKey::StorageVersion` (`u32`) | v0.1 |
| `payroll_registry` | **1** (implicit) | No explicit version key; implicit via WASM hash | v0.1 |
| `salary_commitment` | **1** (implicit) | No explicit version key; `SalaryCommitment.version` tracks per-record revision | v0.1 |
| `payroll` | **1** (implicit) | No explicit version key | v0.1 |
| `proof_verifier` | **1** (implicit) | No explicit version key | v0.1 |
| `audit_module` | **1** (implicit) | No explicit version key | v0.1 |

**What "implicit" means:** contracts without an explicit `StorageVersion` key
have no on-chain signal of their schema generation. Before introducing a
breaking storage change in any of these contracts, add an explicit version key
first (see §3.2 – §3.6 for per-contract guidance).

---

## 3. Migration: v1 → v2 Guidance

### 3.1 `payment_executor`

**Risk level:** Medium

#### What changed (v1 → v2, anticipated)

`payment_executor` is the only contract that already stores an explicit
`DataKey::StorageVersion`. Any breaking schema change here must:

1. Read the current version with `get_storage_version()` and gate migration
   logic on version `== 1`.
2. Bump `StorageVersion` to `2` in the same transaction as the migration.

**Currently tracked storage keys (v1):**

| Key | Type | Notes |
|---|---|---|
| `Addresses` | `ContractAddresses` | Immutable after init — do not migrate |
| `Payment(Address, u32)` | `PaymentRecord` | Append-only; never delete |
| `Nullifier(BytesN<32>)` | `bool` | Permanent — see §4.3 |
| `TotalPaid(u64)` | `i128` | Running sum; must survive migration |
| `ExecutorAdmin` | `Address` | Admin access — see §7 |
| `PauseManager` | `Address` | Optional; preserve if set |
| `Period(u64, u32)` | `PayrollPeriod` | Periods must remain readable |
| `PeriodSequence(u64)` | `u32` | Sequence counter; must continue incrementing |
| `AllowedAsset(Address)` | `bool` | Allowlist; preserve all entries |
| `StorageVersion` | `u32` | Must be bumped to `2` during migration |

**Migration handler pattern:**

```rust
pub fn migrate_v1_to_v2(env: &Env) {
    // 1. Guard: only run once
    let version: u32 = env.storage().persistent()
        .get(&DataKey::StorageVersion)
        .unwrap_or(1);
    assert_eq!(version, 1, "migrate_v1_to_v2: expected version 1");

    // 2. Perform data transforms here
    //    e.g., read old-format PayrollPeriod, write new-format PayrollPeriodV2

    // 3. Bump version last (atomic commit)
    env.storage().persistent().set(&DataKey::StorageVersion, &2u32);
}
```

**Invariants to assert post-migration:**

- `get_storage_version()` returns `2`.
- All `Period(company_id, period_id)` records deserialize without panic.
- `is_paid(employee, period)` returns `true` for all pre-migration payments.
- Nullifiers present before migration are still detected by `is_nullifier_used`.
- `get_total_paid(company_id)` returns the same sum as before migration.

---

### 3.2 `payroll_registry`

**Risk level:** High (company IDs and employee keys are the primary stable
identifiers used across the entire system)

#### Adding an explicit StorageVersion

`payroll_registry` has no explicit version key today. Before any breaking
change, add one during initialization:

```rust
// In initialize() or first call that touches persistent storage:
if !env.storage().persistent().has(&DataKey::StorageVersion) {
    env.storage().persistent().set(&DataKey::StorageVersion, &1u32);
}
```

Then append `StorageVersion` to the `DataKey` enum **at the end**:

```rust
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    CompanySequence,
    EmpStatus(u64, Address),
    PendingAdminRotation(u64),
    PendingTreasuryRotation(u64),
    CompanyAdmin(Address),
    PauseManager,
    StorageVersion,  // NEW — must be appended, never inserted mid-enum
}
```

#### Payroll history preservation

The `Company(u64)` and `Employee(u64, Address)` keys are the root anchors for
all historical payroll data. **These keys must never be renamed, reordered, or
removed.** Downstream systems index by company ID and employee address. Any
corruption here breaks reconciliation, audit, and SDK queries.

**Safe changes (no migration needed):**

- Adding new optional fields (`Option<T>`) to `CompanyInfo` — XDR evolution
  fills missing fields with `None` on read.
- Adding a new `DataKey` variant appended to the end of the enum.
- Adding new company metadata fields with a default value of `0` or empty.

**Breaking changes (migration required):**

- Renaming fields inside `CompanyInfo` or `EmployeeStatus`.
- Removing any field from `CompanyInfo`.
- Adding a required (non-`Option`) field to `CompanyInfo`.
- Changing the type of an existing field.

**Migration handler pattern for `CompanyInfo` extension:**

```rust
// Example: adding a `jurisdiction: Option<String>` field to CompanyInfo v2
pub fn migrate_registry_v1_to_v2(env: &Env) {
    // Iterate is not available on Soroban persistent storage.
    // Migration must be driven externally (list all company IDs from a
    // run counter or off-chain index), then for each company_id:
    //   1. Read the old CompanyInfoV1
    //   2. Write a new CompanyInfoV2 under the same key
    //   3. Bump StorageVersion
}
```

> **Note on iteration:** Soroban persistent storage does not support key
> iteration. If migration requires transforming every company record, the
> contract must accept a `company_ids: Vec<u64>` argument supplied by the
> admin, or use an off-chain tool to enumerate IDs and call a migration
> entry-point per record.

**Invariants post-migration:**

- `get_company(company_id)` returns a valid record for every pre-migration company.
- `is_eligible(company_id, employee)` returns the correct status for all employees.
- `CompanySequence` counter reflects the correct next company ID.
- `CompanyAdmin(address)` reverse-lookup still resolves to the correct company.
- Pending admin/treasury rotation proposals survive (keys preserved).

---

### 3.3 `salary_commitment`

**Risk level:** High (commitment data is the privacy anchor; any corruption
leaks salary information indirectly via invalid proof verification)

#### Per-record versioning vs. contract-level versioning

`salary_commitment` uses a per-record `version: u32` field inside
`SalaryCommitment` (not a contract-level `StorageVersion`). This tracks how
many times a single employee's commitment has been rotated.

**Key rule:** a migration must never reset `SalaryCommitment.version` to `1`.
It must use `existing.version + 1` when writing a transformed record.

#### Commitment history preservation

The `CommitmentHistory(Address, u32)` key stores an archived snapshot every
time `update_commitment` is called. History is append-only and must not be
deleted or overwritten during migration.

**Safe changes:**

- Adding new `Option<T>` fields to `SalaryCommitment`.
- Adding new `DataKey` variants.
- Adding new `CommitmentSnapshot` fields.

**Breaking changes (migration required):**

- Removing or renaming fields in `SalaryCommitment`.
- Changing `BytesN<32>` commitment to a different type.
- Changing the `CommitmentHistory` indexing scheme.

**Migration handler pattern:**

```rust
pub fn migrate_commitment_v1_to_v2(env: &Env, employees: Vec<Address>) {
    // For each employee address (supplied by admin):
    for employee in employees.iter() {
        if let Some(old) = env.storage().persistent()
            .get::<_, SalaryCommitmentV1>(&DataKey::Commitment(employee.clone()))
        {
            let new = SalaryCommitmentV2 {
                commitment: old.commitment,
                created_at: old.created_at,
                updated_at: old.updated_at,
                version: old.version,  // PRESERVE: never reset to 1
                revoked: old.revoked,
                new_field: None,       // safe default for new optional field
            };
            env.storage().persistent()
                .set(&DataKey::Commitment(employee.clone()), &new);
        }
    }
}
```

**Invariants post-migration:**

- `has_commitment(employee)` returns `true` for all pre-migration employees.
- `get_commitment(employee).version` equals the pre-migration version (not `1`).
- `get_commitment_history(employee)` returns all pre-migration snapshots.
- `is_nullifier_used(nullifier)` returns `true` for all pre-migration nullifiers.
- `is_commitment_locked(employee)` reflects the same lock state as before migration.
- Employee reference ID reverse lookups (`get_employee_by_reference_id`) still resolve.

---

### 3.4 `payroll`

**Risk level:** High (payroll runs are the primary historical record; corruption
breaks reconciliation and audit)

#### Adding an explicit StorageVersion

Like `payroll_registry`, the `payroll` contract has no explicit version key.
Append `StorageVersion` to its `DataKey` enum **before** introducing any
breaking change.

#### Payroll run preservation

`PayrollRun` records are written once and must be readable indefinitely.
`PayrollDataKey::PayrollRun(run_id)` keys are immutable after creation.

The `RunCounter` key must survive migration with its current value — it is the
basis for assigning the next run ID.

**Do not modify:**

- `RunNonce(BytesN<32>)` — consumed nonces prevent duplicate payroll runs;
  clearing them enables replay attacks.
- `DepositNonce(BytesN<32>)` — same reason.
- `DraftCommitment(BytesN<32>)` — clearing this enables re-submission of
  already-committed drafts.
- `EmergencyRequest` — pending emergency withdrawal requests must survive.

**Safe changes:**

- Adding `Option<T>` fields to `PayrollRun`.
- Adding new `DataKey` variants appended at the end.

**Breaking changes (migration required):**

- Adding required (non-`Option`) fields to `PayrollRun`.
- Changing `ReconciliationStatus` discriminant values.
- Renaming or removing fields in `PayrollRun` or `PendingPayrollRun`.

**Invariants post-migration:**

- `get_payroll_run(run_id)` returns a valid record for every pre-migration run.
- All three `ReconciliationStatus` variants (`Reconciled`, `Unreconciled`,
  `Failed`) deserialize correctly from historical records.
- `RunCounter` equals the highest run ID written before migration.
- Pending admin/treasury rotation proposals survive.
- `EmergencyRequest` survives with `amount` and `recipient` intact.

---

### 3.5 `proof_verifier`

**Risk level:** Very High (verifier key changes invalidate all existing proofs;
circuit changes require coordinated SDK and contract upgrades)

#### Upgrade approach: deploy a new contract, not a storage migration

Proof verifier upgrades are fundamentally different from storage schema
migrations. The verification key (`VerificationKey`) is circuit-specific; a new
circuit requires a new key, and old proofs generated for the old circuit will
fail under the new key.

**The safe upgrade path is always:**

1. Deploy a **new `proof_verifier` contract** with the new verification key.
2. Update `payment_executor`'s `ContractAddresses.verifier` to point at the new
   contract. Because `ContractAddresses` is stored via `DataKey::Addresses` in
   `payment_executor`, and `initialize()` cannot be called again after init,
   this requires redeploying `payment_executor` as well (see
   [deployment-verification.md §6](deployment-verification.md) for the
   re-wiring procedure).
3. Keep the old verifier contract alive (read-only, no further payments) for at
   least **30 days** to support audit queries against historical proofs.

**No storage migration is needed for `proof_verifier` itself.** The verification
key is written once during `initialize_verifier()` and is not mutated.

**Invariants to check after wiring new verifier:**

- New verifier's `get_verification_key()` returns the expected `VerificationKey`
  with `ic.len() == (public_input_count + 1)`.
- New `payment_executor` calls `verify()` on the new verifier (confirm via
  `ContractAddresses.verifier` in executor storage).
- Old verifier remains callable for `get_verification_key()` audit queries.

---

### 3.6 `audit_module`

**Risk level:** Low–Medium (audit view keys enable compliance; losing them breaks
auditor access but not payroll execution)

#### View key storage

Audit view keys are stored under an internal `DataKey` that is private to the
`audit_module` crate. They are set up through the contract's client API
(`audit_client.generate_view_key()`), not via direct storage writes.

**Safe changes:**

- Adding fields to the `ViewKeyRecord` struct with `Option<T>` defaults.
- Adding new `DataKey` variants.

**Breaking changes (migration required):**

- Changing the `AuditScope` enum discriminant values.
- Removing fields from `ViewKeyRecord`.
- Changing the key scheme for `AuditorKey(Address)`.

**If view key storage changes:** provide a migration entry-point that accepts a
list of `(auditor_address, view_key_record)` pairs and re-writes them under the
new key format. The audit admin must supply the list (from an off-chain index
of `ViewKeyGranted` events).

**Invariants post-migration:**

- `verify_access(auditor)` returns `true` for all pre-migration auditors.
- `get_view_key(auditor)` returns a valid `ViewKeyRecord` for each auditor.
- New view keys can be generated after migration.

---

## 4. Cross-Cutting Migration Rules

These rules apply to every contract upgrade without exception.

### 4.1 DataKey Enum Variants Are Append-Only

New `DataKey` variants must always be **appended** to the end of the enum.
Inserting a new variant in the middle shifts all subsequent discriminant values,
corrupting every storage read that uses any key after the insertion point.

```rust
// ✅ Safe: append at end
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    // ... existing variants ...
    NewFeature(u64),  // appended — does not change existing discriminants
}

// ❌ Unsafe: mid-enum insertion
pub enum DataKey {
    Company(u64),
    NewFeature(u64),  // inserted — shifts Employee and all following keys
    Employee(u64, Address),
}
```

### 4.2 Struct Fields Must Not Be Removed or Reordered

Soroban XDR encodes struct fields positionally. Removing a field or changing the
order of fields changes the byte layout, causing deserialization panics on
records written under the old format.

| Change type | Safe? | Action required |
|---|---|---|
| Add `Option<T>` field at end | Yes | None — defaults to `None` on old records |
| Add `u32`/`u64` field at end | Yes | None — defaults to `0` on old records |
| Remove a field | No | New key variant + migration |
| Reorder fields | No | New key variant + migration |
| Change field type | No | New key variant + migration |
| Add required (non-`Option`) field | No | New key variant + migration |

### 4.3 Nullifiers Are Permanent

`Nullifier(BytesN<32>)` keys in both `salary_commitment` and `payment_executor`
must never be cleared, zeroed, or deleted during migration. These are the
double-spend protection mechanism for the entire system. Clearing any nullifier
allows a previously-used proof to be replayed.

### 4.4 Version Bump Is the Last Write

When a migration function writes new-format data and bumps `StorageVersion`,
the version increment must be the **last storage write** in the migration
transaction. This ensures that if the transaction fails partway through, the
version is not prematurely marked as migrated.

### 4.5 Nonces and Draft Commitments Are Permanent

`RunNonce`, `DepositNonce`, and `DraftCommitment` keys in the `payroll` contract
are consumed-state flags. Clearing them creates replay vulnerabilities equivalent
to clearing nullifiers. Do not touch them during migration.

### 4.6 Run Migration Tests Before Deploying

Every migration must be accompanied by a test in
`tests/migrations/src/migration_tests.rs` that:

1. Sets up full v1 state using `MigrationContext::write_full_v1_state()`.
2. Simulates the upgrade with `simulate_upgrade_v2()`.
3. Runs the migration handler.
4. Asserts all required invariants.

See [upgrades.md §4](upgrades.md#4-adding-migration-coverage) for the
step-by-step guide.

---

## 5. Step-by-Step Upgrade Runbook

Use this runbook for every contract upgrade that touches storage.

### Step 1: Pre-Migration Preparation

- [ ] Identify which contracts are affected and whether the change is
  append-safe or requires a migration handler.
- [ ] If the affected contract has no `StorageVersion` key, add one and deploy
  it as a non-breaking preparatory upgrade first.
- [ ] Write the migration handler (see §3.x for the relevant contract).
- [ ] Add migration test coverage (see [upgrades.md §4](upgrades.md#4-adding-migration-coverage)).
- [ ] Run `cargo test -p migration_tests` locally — all tests must pass.
- [ ] Announce the upgrade with at least **3 release cycles** notice if any
  external API surface changes (entry-point signatures, event schemas, proof
  format). See
  [interop/contract-upgrade-strategy.md §2.3](interop/contract-upgrade-strategy.md).

### Step 2: Testnet Dry Run

- [ ] Deploy the new WASM to testnet.
- [ ] Set up representative v1 state on testnet (companies, employees, payroll
  runs, nullifiers).
- [ ] Call the migration entry-point on testnet.
- [ ] Verify invariants using the `deployment-verification.md` checklist.
- [ ] Confirm payroll execution still works end-to-end on testnet.

### Step 3: Pause Before Mainnet Upgrade

- [ ] Trigger the pause manager on all affected contracts so no new writes land
  during the upgrade window:

```bash
# Pause payment_executor
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network mainnet -- set_pause_manager --pause_manager $PAUSE_MANAGER_ID
```

- [ ] Confirm no pending payroll runs are in `PendingRun` state (drain the
  queue before pausing).

### Step 4: Deploy New WASM

In Soroban, upgrading a contract preserves existing storage. The new WASM is
uploaded and linked to the same contract address.

```bash
# Build optimized WASM
cargo build --target wasm32-unknown-unknown --release

# Upload new WASM (returns a wasm_hash)
stellar contract upload \
  --wasm target/wasm32-unknown-unknown/release/<contract>.wasm \
  --source $SOURCE --network mainnet

# Upgrade the contract to the new WASM
stellar contract upgrade \
  --id $CONTRACT_ID \
  --wasm-hash <NEW_WASM_HASH> \
  --source $SOURCE --network mainnet
```

### Step 5: Run Migration Entry-Point

```bash
stellar contract invoke --id $CONTRACT_ID --source $SOURCE --network mainnet -- migrate_v1_to_v2
```

Confirm the transaction succeeds and `StorageVersion` is now `2`:

```bash
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network mainnet -- get_storage_version
# Expected: 2
```

### Step 6: Verify Invariants

Run the [deployment-verification.md](deployment-verification.md) smoke test
checklist. Specifically confirm:

- [ ] Company and employee records are readable.
- [ ] Nullifiers from before the upgrade are still detected.
- [ ] Payroll history reads correctly (sample a few run IDs).
- [ ] Admin access works (admin-gated function call succeeds).
- [ ] A new payroll run can be created and executed.

### Step 7: Unpause

```bash
stellar contract invoke --id $PAUSE_MANAGER_ID --source $SOURCE --network mainnet -- unpause
```

---

## 6. Payroll History Preservation

Payroll history is stored across three contracts. Each has different
preservation guarantees.

### `payroll` — Run records

`PayrollRun` records are written once and never modified after finalization.
They are keyed by `PayrollDataKey::PayrollRun(run_id)`, where `run_id` is a
monotonically increasing `u64` from `RunCounter`.

**To preserve during migration:**
- Never delete or overwrite `PayrollRun(run_id)` keys.
- Ensure `RunCounter` survives with its current value.
- If `PayrollRun` struct fields are extended, use `Option<T>` so historical
  records deserialize without error.

### `payment_executor` — Payment records and period records

`Payment(employee, period)` records are the on-chain proof of each individual
payment. `Period(company_id, period_id)` records track payroll cycles.

**To preserve during migration:**
- Never delete `Payment` or `Period` keys.
- Preserve `PeriodSequence(company_id)` counters so new periods are numbered
  correctly.
- Preserve `TotalPaid(company_id)` accumulators.

### `salary_commitment` — Commitment history

`CommitmentHistory(employee, index)` snapshots are written every time a
commitment is rotated. They are the only on-chain record of a salary change.

**To preserve during migration:**
- Never delete `CommitmentHistory` entries.
- Preserve the history index counter embedded inside each `SalaryCommitment`
  (the `version` field tracks how many rotations have occurred).

---

## 7. Admin Access Preservation

Admin keys control critical operations: registering companies, changing
treasury addresses, granting audit access, and pausing the system. Loss of
admin access can halt payroll permanently.

### Key admin storage locations

| Contract | Admin key | Storage key |
|---|---|---|
| `payment_executor` | Executor admin | `DataKey::ExecutorAdmin` |
| `salary_commitment` | HR admin | `DataKey::Admin` |
| `salary_commitment` | Payroll operator | `DataKey::PayrollOperator` |
| `payroll` | Payroll admin | `DataKey::Addresses` (stored inside `PayrollContractAddresses`) |
| `payroll_registry` | Per-company admin | `DataKey::CompanyAdmin(Address)` |
| `payroll` | Treasury owner | `DataKey::TreasuryOwner` |

### Pending rotation proposals

If an admin rotation is in-flight at migration time (i.e., a proposal has been
made but not accepted), the pending rotation record must survive:

| Contract | Pending rotation key |
|---|---|
| `payroll` | `DataKey::PendingAdminRotation`, `DataKey::PendingTreasuryRotation` |
| `payroll_registry` | `DataKey::PendingAdminRotation(company_id)`, `DataKey::PendingTreasuryRotation(company_id)` |
| `salary_commitment` | `DataKey::PendingAdminRotation` |

**Migration rule:** do not touch any `PendingAdminRotation` or
`PendingTreasuryRotation` key. Accept or reject pending proposals **before**
migrating if the rotation proposal structure itself is changing format.

### Emergency withdrawal requests

`DataKey::EmergencyRequest` in the `payroll` contract must survive migration
with `amount`, `recipient`, `requested_at`, and `approved` intact. An
interrupted emergency request that disappears after migration creates an
unrecoverable state.

---

## 8. Rollback Procedure

If an invariant fails after migration, stop immediately and do not unpause.

### Scenario A: Migration entry-point panicked

The `StorageVersion` was not bumped (last write rule, §4.4). Existing storage
is unchanged. Re-examine the migration handler, fix the bug, and re-run.

### Scenario B: Version was bumped but some records are corrupted

1. If still within the upgrade window and the old WASM is available,
   re-upload the old WASM and upgrade the contract back to it.
2. Soroban storage is not rolled back automatically — if records were written
   under the new format but the old WASM cannot read them, a new recovery
   migration is needed.
3. Open an incident following [incident-response-playbook.md](incident-response-playbook.md).

### Scenario C: Admin key is inaccessible post-migration

If the admin key was stored in a struct that was migrated incorrectly:

1. Use the pause manager to halt payments immediately.
2. Reconstruct the admin address from event logs (`CompanyRegistered`,
   `CommitmentUpdated`, etc.) or off-chain records.
3. Deploy a recovery contract entry-point (requires governance approval) to
   restore the admin key.

### Scenario D: Nullifiers were cleared

This is a critical security incident. Pause immediately. Reconstruct the
nullifier set from `PayrollProcessed` events (topics include `nullifier` in
the event data) and re-write them via a recovery entry-point.

---

## 9. Version Compatibility Matrix

This table tracks which contract versions are compatible with each other.
Update it whenever a version is bumped.

| `payment_executor` | `payroll_registry` | `salary_commitment` | `payroll` | `proof_verifier` | `audit_module` | Compatible |
|---|---|---|---|---|---|---|
| v1 | v1 | v1 | v1 | v1 | v1 | ✅ Yes (current) |
| v2 | v1 | v1 | v1 | v1 | v1 | ⚠️ Only if v2 adds no new cross-contract calls |
| v1 | v1 | v2 | v1 | v1 | v1 | ⚠️ Only if v2 SalaryCommitment is backward-compatible |
| v1 | v1 | v1 | v1 | v2 | v1 | ❌ Requires executor re-wired to new verifier |

**Legend:**
- ✅ **Yes** — all contracts can be deployed together without a migration handler.
- ⚠️ **Conditional** — compatible under stated conditions; verify before deploying.
- ❌ **Incompatible** — must follow the upgrade runbook in §5.
