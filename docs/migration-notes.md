# Contract Version Migration Notes

> **Issue:** [#223](https://github.com/zkpayroll/zk-payroll-contracts/issues/223)
>
> **Purpose:** Explain how each contract version transition should be performed
> safely, which storage keys are affected by each change, and how to preserve
> payroll history and admin access throughout an upgrade.
>
> **Related docs:**
> - [upgraades.md](upgrades.md) — Migration test framework, state-version rules,
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
have no on-chain signal of their schema generation. Before introducing a breaking
storage change in any of these contracts, add an explicit version key
first (see ç3.2 – §3.6 for per-contract guidance).

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
        .unwrap_or_else(1);
    assert_eq(version, 1, "migrate_v1_to_v2: expected version 1");

    // 2. Perform data transforms here
    //    e.g., read old-format PayrollPeriod, write new-format PayrollPeriodV2

    // 3. Bump version last (atomic commit)
    env.storage().persistent().set(&DataKey::StorageVersion, &`u32);
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

The `Company(u64)` and `Employee(u64, Address)`keys are the root anchors for
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
> leaks salary information indirectly via invalid proof verification)

#### Per-record versioning vs. contract-level versioning

`salary_commitment` uses a per-record `version: u32` field inside
`SalaryCommitment` (not a contract-level `StorageVersion`). This tracks how
many times a single employee's commitment has been rotated.

**Key rule:** a migration must never reset `SalaryCommitment.version` to `1`.
It must use `existing.version + 1` when writing a transformed record.

#### Commitment history preservation

The `CommitmentHistory(Address, u32)`key stores an archived snapshot every
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
                .set(&DataKey::Commitment(employee.clone()), &n);
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

PayrollRun` records are written once and must be readable indefinitely.
`PayrollDataKey::PayrollRun(run_id)` keys are immutable after creation.

The `RunCounter` key must survive migration with its current value — it is the
basis for assigning the next run ID.

**Do not modify:**

- `RunNonce(BytesN<32>)` — consumed nonces prevent duplicate payroll runs;
  clearing them enables replay attacks.
- `DepositNonce(BytesN<32>)` — same reason.
- `DraftContract` — draft payroll contracts must remain readable and
  executable across the upgrade.

**Safe changes:**

- Adding new optional fields to `PayrollRun`.
- Adding new `PayrollDataKey` variants appended to the end.
- Adding new event emissions.

**Breaking changes (migration required):**

- Renaming or removing fields in `PayrollRun`.
- Changing the type of `run_id` or any identifier field.
- Changing the `RunCounter` key name or type.

**Migration handler pattern:**

```rust
pub fn migrate_payroll_v1_to_v2(env : &Env, run_ids: Vec<u64>) {
    // 1. Guard: only run once
    let version: u32 = env.storage().persistent()
        .get(&PayrollDataKey::StorageVersion)
        .unwrap_or_else(1);
    assert_eq(version, 1, "migrate_payroll_v1_to_v2: expected version 1");

    // 2. Transform each run record in place (run_ids supplied by admin)
    for run_id in run_ids.iter() {
        if let Some(old) = env.storage().persistent()
            .get::<_, PayrollRunV1>(&PayrollDataKey::PayrollRun(run_id))
        {
            let new = PayrollRunV2 {
                id: old.id,
                company_id: old.company_id,
                total_amount: old.total_amount,
                payment_count: old.payment_count,
                created_at: old.created_at,
                status: old.status,
                new_field: None,
            };
            env.storage().persistent()
                .set(&PayrollDataKey::PayrollRun(run_id), &new);
        }
    }

    // 3. Bump version last (atomic commit)
    env.storage().persistent().set(&PayrollDataKey::StorageVersion, &`u32);
}
```

**Invariants post-migration:**

- All `PayrollRun(run_id)` records deserialize without panic.
- `RunCounter` returns the same value as before migration.
- `RunNonce` and `DepositNonce` entries present before migration are still
  detected as consumed.
- Draft payroll contracts remain readable and executable.

---

### 3.5 `proof_verifier`

**Risk level:** Medium (verifier changes affect all payroll executions)

#### Adding an explicit StorageVersion

`proof_verifier` has no explicit version key today. Append `StorageVersion` to
its `DataKey` enum **before** introducing any breaking change.

**Safe changes:**

- Adding new verification keys appended to the enum.
- Adding new optional configuration fields.

**Breaking changes (migration required):**

- Changing the verification key schema or hash algorithm.
- Removing or renaming existing keys.

**Invariants post-migration:**

- All pre-migration verification keys remain readable.
- Verification results for pre-migration proofs are unchanged.

---

### 3.6 `audit_module`

**Risk level:** Low (audit records are append-only and not used in consensus)

#### Adding an explicit StorageVersion

`audit_module` has no explicit version key today. Append `StorageVersion` to
its `DataKey` enum **before** introducing any breaking change.

**Safe changes:**

- Adding new audit event types.
- Adding new optional fields to audit records.

**Breaking changes (migration required):**

- Renaming or removing fields in audit records.
- Changing the audit event indexing scheme.

**Invariants post-migration:**

- All pre-migration audit records remain readable.
- Audit queries return the same results as before migration.

---

## 4. Cross-Cutting Migration Rules

### 4.1 Atomicity

Migration must be atomic: either all storage transforms and the version bump
succeed, or none do. Never leave the contract in a partially-migrated state.

### 4.2 Idempotency

Migration handlers must be idempotent: calling them twice must not corrupt
data. Guard on the current version before applying any transform.

### 4.3 Nullifier Permanence

Nullifiers are permanent. Never delete or clear a nullifier during migration.
Clearing a nullifier enables double-spending of the same payroll period.

### 4.4 Admin Key Preservation

Admin keys (`ExecutorAdmin`, `CompanyAdmin`, `PauseManager`) must be
preserved across migration. If an admin key is lost, the contract becomes
neigh unmanageable.

### 4.5 Version Bump Order

Always bump the version key **last**, after all data transforms have
succeeded. This ensures that a failed migration can be retried because the
version still reflects the old schema.

---

## 5. Step-by-Step Upgrade Runbook

1. **Pre-flight checks**: run `cargo test -p migration_tests` and confirm
   all `mg_*` tests pass.
2. **Snapshot state**: export all persistent keys off-chain for rollback.
3. **Deploy new WASM**: upload the new contract bytecode.
4. **Run migration**: invoke the migration entry-point with the required
   arguments (e.g., `company_ids`, `run_ids`, `employees`).
5. **Verify invariants**: assert all post-migration invariants for the
   affected contract.
6. **Update docs**: bump the version in the baseline table (§2) and add a
   migration section if one does not exist.
7. **Monitor**: watch for failed deserialization or unexpected panics in
   the first hours after upgrade.

---

## 6. Payroll History Preservation

Payroll history is the primary audit trail. The following keys are append-only
and must never be deleted, renamed, or reordered:

- `Payment(Address, u32)` — payment records.
- `Period(u64, u32)` — payroll periods.
- `PayrollRun(run_id)` — payroll run records.
- `CommitmentHistory(Address, u32)` — commitment snapshots.
- `AuditRecord(u64)` — audit records.

Any migration that touches these keys must preserve the existing values and
append new data without overwriting historical entries.

---

## 7. Admin Access Preservation

Admin access is crucial for contract management. The following keys must be
preserved across all migrations:

- `ExecutorAdmin` (`payment_executor`) — admin address.
- `CompanyAdmin(Address)` (`payroll_registry`) — reverse lookup.
- `PauseManager` — pause control address.
- `PendingAdminRotation(u64)` — pending admin rotation proposals.
- `PendingTreasuryRotation(u64)` — pending treasury rotation proposals.

If an admin key is lost during migration, the contract becomes neigh
unmanageable. Always verify admin keys post-migration before considering the
upgrade complete.

---

## 8. Rollback Procedure

If a migration fails or an invariant is violated:

1. **Stop the contract**: use the pause mechanism if available.
2. **Restore the previous WASM**: redeploy the last known-good bytecode.
3. **Restore state**: if the migration modified storage, restore from the
   off-chain snapshot taken in step 2 of the runbook.
4. **Verify**: confirm all invariants for the restored version.
5. **Post-mortem**: document the failure and add a regression test before
   retrying the migration.

---

## 9. Version Compatibility Matrix

The matrix below describes which contract versions can interoperate with
downstream consumers.

| Contract | Storage Version | Compatible SDK Versions | Notes |
|---|---|---|---|
| `payment_executor` | 1 | SDK >= 0.1 | Baseline version |
| `payment_executor` | 2 | SDK >= 0.2 | Requires migration from v1 |
| `payroll_registry` | 1 | SDK >= 0.1 | Baseline version |
| `salary_commitment` | 1 | SDK >= 0.1 | Baseline version |
| `payroll` | 1 | SDK >= 0.1 | Baseline version |
| `proof_verifier` | 1 | SDK >= 0.1 | Baseline version |
| `audit_module` | 1 | SDK >= 0.1 | Baseline version |

> **Note:** Update this matrix whenever a contract's storage version is
> bumped or a new SDK release is published.
