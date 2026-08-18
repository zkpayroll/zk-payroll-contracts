# Storage Key Versioning Strategy & Migration Plan

This document specifies the storage key versioning strategy and migration guidelines for the ZK Payroll smart contracts. Storage key stability and versioning are essential for maintaining backward compatibility across WASM contract upgrades and long-term historical records.

---

## 1. Storage Key Schema Principles

1. **Prefix Namespace Separation**:
   - Each contract defines an explicit `DataKey` enum to namespace persistent keys.
   - Key collisions between logical namespaces (e.g. employee records, periods, nullifiers) are prevented by distinct enum variants.

2. **Schema Versioning Tag (`StorageVersion`)**:
   - Contracts store a dedicated `DataKey::StorageVersion -> u32` persistent entry initialized upon contract instantiation (e.g., version `1`).
   - When introducing structural or breaking changes to storage models in future WASM upgrades, the schema version counter is incremented.

3. **Additive Schema Modifications**:
   - Structural field additions to existing structs should use `Option<T>` or default fallbacks (`unwrap_or`) when reading existing storage.
   - Existing key variants must not be repurposed for incompatible data types.

---

## 2. Storage Key Mapping Reference

| Contract | DataKey Variant | Storage Type | Data Structure | Version Introduced |
|----------|-----------------|--------------|----------------|--------------------|
| `payment_executor` | `Addresses` | Persistent | `ContractAddresses` | V1 |
| `payment_executor` | `Payment(Address, u32)` | Persistent | `PaymentRecord` | V1 |
| `payment_executor` | `Nullifier(BytesN<32>)` | Persistent | `bool` | V1 |
| `payment_executor` | `AllowedAsset(Address)` | Persistent | `bool` | V1 (#175) |
| `payment_executor` | `StorageVersion` | Persistent | `u32` | V1 (#174) |
| `payroll` | `PayrollRun(u64)` | Persistent | `PayrollRun` | V1 |
| `payroll` | `PendingRun(u64)` | Persistent | `PendingRun` | V1 |
| `payroll` | `RunNonce(BytesN<32>)` | Persistent | `u64` | V1 |
| `payroll_registry` | `Company(u64)` | Persistent | `CompanyInfo` | V1 |
| `payroll_registry` | `Employee(u64, Address)` | Persistent | `BytesN<32>` | V1 |
| `payroll_registry` | `EmpStatus(u64, Address)` | Persistent | `EmployeeStatus` | V1 |
| `audit_module` | `AuditorKey(Address)` | Persistent | `ViewKeyRecord` | V1 |

---

## 3. Migration Guidelines & Upgrade Procedure

1. **Pre-Upgrade Storage Inspection**:
   - Read `get_storage_version()`. If current version matches contract WASM version, no storage migration script is required.

2. **Sequential Version Upgrades**:
   - If version `V_current < V_target`, execute forward migration handlers sequentially (`V1 -> V2 -> V3`).

3. **Non-Destructive Storage Migration**:
   - Migration functions must preserve historical nullifier, payment record, and commitment data.
   - Sibling records (e.g. employee records under a company) must remain independent during record updates or deletions.

---

## 4. Test Verification

Storage key versioning and upgrade compatibility are verified in automated test suites:
- `up08_storage_key_versioning_and_migration` in `contracts/integration_tests/src/upgrade_simulation.rs`
- Unit tests `test_storage_version_returns_version_1` in `contracts/payment_executor/src/lib.rs`
