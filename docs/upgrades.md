# Contract Migration & Upgrade Guide

This document covers the contract migration test framework, upgrade assumptions,
state-version rules, and the required steps for adding migration coverage when
contract storage changes.

---

## Table of Contents

1. [Migration Test Framework](#1-migration-test-framework)
2. [Upgrade Assumptions](#2-upgrade-assumptions)
3. [State Version Rules](#3-state-version-rules)
4. [Adding Migration Coverage](#4-adding-migration-coverage)
5. [Migration Test Checklist](#5-migration-test-checklist)
6. [Supported Storage Keys](#6-supported-storage-keys)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Migration Test Framework

### Overview

The migration test framework (in `tests/migrations/`) validates that stored
contract data remains compatible across schema upgrades. It simulates the
full upgrade lifecycle:

1. **Deploy v1 contracts** — All contracts deployed with current WASM.
2. **Write v1 state** — Populate storage with representative data
   (companies, employees, payroll runs, audit permissions, etc.).
3. **Simulate upgrade** — Re-deploy contracts (simulating WASM upgrade)
   while preserving existing storage.
4. **Run migration** — Execute v1→v2 migration adapters.
5. **Assert invariants** — Verify all historical state remains readable,
   active flows continue, and unsupported versions fail safely.

### Framework Components

| Module | Path | Purpose |
|--------|------|---------|
| `state_fixtures` | `tests/migrations/src/state_fixtures.rs` | Fixture constructors for all v1 data types |
| `migration_helpers` | `tests/migrations/src/migration_helpers.rs` | `MigrationContext`, setup, upgrade simulation, and assertions |
| `migration_tests` | `tests/migrations/src/migration_tests.rs` | All test cases (positive and negative) |

### How to Run

```bash
# Run all migration tests
cargo test -p migration_tests

# Run a specific test
cargo test -p migration_tests mg_10

# Run negative tests only
cargo test -p migration_tests mg_neg_
```

### Test Naming Convention

- `mg_*` — Core migration tests (positive): historical record preservation,
  active flow continuation, invariant checks.
- `mg_neg_*` — Negative tests: unsupported versions, malformed state,
  missing records, duplicate nonces.

---

## 2. Upgrade Assumptions

These are the invariants that must hold across any contract upgrade:

### 2.1 Primary Keys Are Immutable

Company IDs and employee addresses are the primary keys. They must never
change. Once a company or employee record is created, its ID is stable
forever.

**Why:** Downstream systems (indexers, dashboards, SDKs) index by ID.
Changing IDs breaks external lookups.

### 2.2 Storage Keys Are Append-Only

New `DataKey` variants must be appended (not inserted) to the enum. Adding
at the end preserves existing discriminant values. Inserting mid-enum
would shift all subsequent discriminants and corrupt existing storage.

**Example:**
```rust
// ✅ Correct: append new variants
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    // ... existing variants ...
    PayrollSchedule(u64),  // NEW — appended at end
}

// ❌ Wrong: inserting mid-enum breaks existing discriminants
pub enum DataKey {
    Company(u64),
    PayrollSchedule(u64),  // NEW — inserted here: SHIFTS Employee discriminant
    Employee(u64, Address),  // DISCRIMINANT CHANGED — data corruption
    // ...
}
```

### 2.3 Nullifiers Are Permanent

Once a proof nullifier is recorded, it must never be deleted or modified.
This is the double-spend protection guarantee.

**Migration rule:** No migration function may clear, reset, or modify
nullifier storage. Nullifier checks must continue to work after upgrade.

### 2.4 Storage Backward Compatibility

Adding new fields to existing structs is safe (Soroban XDR evolution
handles this). Removing or reordering fields is **not safe** and requires
a new key variant.

**Safe changes:**
- Adding `Option<T>` fields (default to `None` in old records)
- Adding `u32` / `u64` fields (default to `0` in old records)
- Adding new `DataKey` variants

**Breaking changes (require migration):**
- Removing fields from a struct
- Reordering struct fields
- Changing a field's type
- Adding required fields (without `Option` or default)

### 2.5 Event Structure Is Not Tested by Migration Framework

Event schemas may change independently of storage. See
`docs/interop/contract-upgrade-strategy.md` for event versioning rules.

---

## 3. State Version Rules

### 3.1 Storage Version Tag

Each contract that may undergo schema evolution should store a
`StorageVersion` tag (typically `u32`). The version is:

- **Set to 1** upon contract initialization.
- **Incremented** when a breaking schema change is introduced.
- **Read by migration functions** to determine if a migration is needed.

### 3.2 Current Version Table

| Contract | Storage Version | Status |
|----------|----------------|--------|
| `payment_executor` | 1 | Initial |
| `payroll` | 1 (implicit) | Initial |
| `payroll_registry` | 1 (implicit) | Initial |
| `salary_commitment` | 1 (implicit) | Initial |
| `proof_verifier` | 1 (implicit) | Initial |
| `audit_module` | 1 (implicit) | Initial |

### 3.3 Upgrade Procedure

When introducing a breaking storage change:

1. **Bump version**: Increment the `StorageVersion` in the new WASM.
2. **Write migration handler**: Create `migrate_v1_to_v2()` that reads old
   keys and writes new ones.
3. **Add fixture**: Add a v1 fixture constructor in `state_fixtures.rs`.
4. **Add test**: Write a test in `migration_tests.rs` that:
   - Loads v1 state
   - Simulates upgrade
   - Runs migration
   - Asserts post-migration correctness
5. **Document**: Update this file's version table.

---

## 4. Adding Migration Coverage

When a contract storage schema changes, follow these steps to add
migration test coverage:

### Step 1: Add Fixture Constructor

In `tests/migrations/src/state_fixtures.rs`, add a `write_v1_*_fixture`
function that writes the old-format data directly to storage.

```rust
pub fn write_v1_new_feature_fixture(
    env: &Env,
    contract_id: &Address,
    param1: Address,
    param2: u64,
) -> SomeFixture {
    let fixture = SomeFixture { /* v1 fields */ };
    env.as_contract(contract_id, || {
        env.storage().persistent().set(
            &SomeDataKey::SomeKey(param2),
            &fixture,
        );
    });
    fixture
}
```

### Step 2: Enable Fixture in MigrationContext

In `tests/migrations/src/migration_helpers.rs`, update:

1. **`write_full_v1_state()`** — Call your new fixture constructor to
   populate state during setup.
2. **`assert_post_migration_invariants()`** — Add assertions that the
   new state survived migration.

### Step 3: Write Migration Handler

If the upgrade requires active data transformation, add a `migrate_v1_to_v2()`
function and call it from `run_migration_v1_to_v2()`.

```rust
pub fn migrate_v1_to_v2(env: &Env, ctx: &MigrationContext) {
    // Read old-format keys
    // Transform data
    // Write new-format keys
    // Optionally verify
}
```

### Step 4: Add Test Cases

In `tests/migrations/src/migration_tests.rs`, add:

```rust
/// MG-XX: Description of what this test validates.
#[test]
fn mg_xx_new_feature_survives_migration() {
    let env = Env::default();
    let ctx = setup_and_migrate(&env);

    // Assertions
}
```

### Step 5: Run Tests

```bash
cargo test -p migration_tests
```

---

## 5. Migration Test Checklist

- [ ] All v1 state is populated before upgrade simulation
- [ ] Historical records are readable after migration:
  - Payroll runs (reconciled, unreconciled, failed)
  - Employee records (active, inactive, incomplete)
  - Company records (admin, treasury)
  - Audit view keys
  - Nullifiers
  - Commitment history
- [ ] Active flows continue after migration:
  - New employee registration
  - New payroll execution
  - New commitment creation/update
  - New audit key generation
  - New period creation
- [ ] Unsupported state versions fail safely
- [ ] Malformed state produces deserialization errors (not silent corruption)
- [ ] Duplicate nonce detection still works
- [ ] Pending rotations survive migration
- [ ] Emergency withdrawal requests survive migration

---

## 6. Supported Storage Keys

### `payroll_registry` DataKey Variants

| Variant | Type | Key |
|---------|------|-----|
| `Company(u64)` | Persistent | Company ID → CompanyInfo |
| `Employee(u64, Address)` | Persistent | (Company ID, Employee) → BytesN<32> |
| `CompanySequence` | Persistent | Counter |
| `EmpStatus(u64, Address)` | Persistent | (Company ID, Employee) → EmployeeStatus |
| `PendingAdminRotation(u64)` | Persistent | Company ID → PendingCompanyRotation |
| `PendingTreasuryRotation(u64)` | Persistent | Company ID → PendingCompanyRotation |
| `CompanyAdmin(Address)` | Persistent | Admin → Company ID |
| `PauseManager` | Persistent | Address |

### `salary_commitment` DataKey Variants

| Variant | Type | Key |
|---------|------|-----|
| `Commitment(Address)` | Persistent | Employee → SalaryCommitment |
| `Nullifier(BytesN<32>)` | Persistent | Nullifier → PaymentNullifier |
| `Admin` | Persistent | Address |
| `PayrollOperator` | Persistent | Address |
| `CommitmentHistory(Address, u32)` | Persistent | (Employee, index) → CommitmentSnapshot |
| `CommitmentLock(Address)` | Persistent | Employee → bool |
| `EmployeeReferenceId(Address)` | Persistent | Employee → String |
| `ReferenceIdIndex(String)` | Persistent | Ref ID → Employee |
| `PauseManager` | Persistent | Address |
| `PendingAdminRotation` | Persistent | PendingRotation |

### `payroll` DataKey Variants

| Variant | Type | Key |
|---------|------|-----|
| `Addresses` | Persistent | ContractAddresses |
| `PauseManager` | Persistent | Address |
| `PayrollRun(u64)` | Persistent | Run ID → PayrollRun |
| `PendingRun(u64)` | Persistent | Run ID → PendingPayrollRun |
| `TreasuryOwner` | Persistent | Address |
| `RunCounter` | Persistent | u64 |
| `RunDraft(u64)` | Persistent | Draft ID → PayrollRunDraft |
| `RunDraftCounter` | Persistent | u64 |
| `PendingAdminRotation` | Persistent | PendingRotation |
| `PendingTreasuryRotation` | Persistent | PendingRotation |
| `RunNonce(BytesN<32>)` | Persistent | Nonce → u64 (run_id) |
| `DepositNonce(BytesN<32>)` | Persistent | Nonce → bool |
| `DraftCommitment(BytesN<32>)` | Persistent | Hash → bool |
| `EmergencyRequest` | Persistent | EmergencyWithdrawalRequest |

### `payment_executor` DataKey Variants

| Variant | Type | Key |
|---------|------|-----|
| `Addresses` | Persistent | ContractAddresses |
| `Payment(Address, u32)` | Persistent | (Employee, Period) → PaymentRecord |
| `Nullifier(BytesN<32>)` | Persistent | Nullifier → bool |
| `TotalPaid(u64)` | Persistent | Company ID → i128 |
| `ExecutorAdmin` | Persistent | Address |
| `PauseManager` | Persistent | Address |
| `Period(u64, u32)` | Persistent | (Company ID, Period ID) → PayrollPeriod |
| `PeriodSequence(u64)` | Persistent | Company ID → u32 |
| `AllowedAsset(Address)` | Persistent | Token → bool |
| `StorageVersion` | Persistent | u32 |

---

## 7. Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Test panics with "Company not found" | Key variant discriminant changed | Ensure new DataKey variants are appended, not inserted |
| Nullifiers not detected post-upgrade | Nullifier storage was cleared | Migration must not touch nullifier keys |
| Employee status reset to Incomplete | EmpStatus key was not preserved | Verify DataKey::EmpStatus is not removed or changed |
| Commitment version reset to 1 | Migration re-initialized commitment | Update must use existing.version + 1, not 1 |
| Deserialization error on existing record | Struct fields changed incompatibly | Use new DataKey variant for new struct format |
| Malformed state produces Ok | No deserialization validation on read | Add `try_get_*` fallback or assert deserialization fails |
