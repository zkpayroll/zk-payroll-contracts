# ZK Payroll — SDK Interface Specification

> **Canonical contract interface reference for SDK clients.**
> Target platform: Soroban (Stellar) smart contracts — Rust → WASM.
> Circuit backend: Groth16 over BN254.

---

## Table of Contents

1. [Identifiers & Addresses](#1-identifiers--addresses)
2. [Entrypoints by Contract](#2-entrypoints-by-contract)
   - [2.1 PayrollRegistry](#21-payrollregistry)
   - [2.2 SalaryCommitment](#22-salarycommitment)
   - [2.3 ProofVerifier](#23-proofverifier)
   - [2.4 PaymentExecutor](#24-paymentexecutor)
   - [2.5 Payroll (high-level batch)](#25-payroll-high-level-batch)
   - [2.6 AuditModule](#26-auditmodule)
   - [2.7 PauseManager](#27-pausemanager)
   - [2.8 Token (mock / SEP-41)](#28-token-mock--sep-41)
3. [Data Structures](#3-data-structures)
4. [Serialization Rules](#4-serialization-rules)
   - [4.1 Addresses](#41-addresses)
   - [4.2 Identifiers](#42-identifiers)
   - [4.3 Commitment Data](#43-commitment-data)
   - [4.4 Proof Data](#44-proof-data)
   - [4.5 Nullifiers](#45-nullifiers)
   - [4.6 Amount Encoding](#46-amount-encoding)
5. [Events](#5-events)
6. [Error Reference](#6-error-reference)
7. [Compatibility & Versioning](#7-compatibility--versioning)

---

## 1. Identifiers & Addresses

### Soroban Address (`Address`)

| Property       | Value                                                               |
|----------------|---------------------------------------------------------------------|
| **Encoding**   | Stellar StrKey (e.g. `G...` for Ed25519, `C...` for contract)      |
| **SDK format** | 32-byte public key (Ed25519) or 32-byte contract hash + 1-byte type|
| **Conversion** | `stellar-strkey` crate for encode/decode; `stellar-xdr` for binary  |

Addresses are the native Soroban `Address` type. SDKs should use the Stellar SDK's
`Address` type when available, or the equivalent `stellar-strkey` library.

### Company ID (`u64`)

- **Type**: `u64` (unsigned 64-bit integer)
- **Allocation**: Sequential, auto-incremented (starting at `0`)
- **Encoding in XDR**: `Uint64` (8 bytes big-endian)
- **Uniqueness**: Global — company IDs are not scoped per contract

### Employee Identifier

Employees are identified by their Soroban `Address` (Ed25519 public key).

### Period ID (`u32`)

- **Type**: `u32` (unsigned 32-bit integer)
- **Allocation**: Sequential per company (starting at `1`)
- **Scoping**: Period IDs are scoped within a company — `(company_id, period_id)` forms the composite key

### Symbol (for audit queries)

Company identifiers in the AuditModule use Soroban `Symbol` (max 32 bytes UTF-8).

---

## 2. Entrypoints by Contract

### 2.1 PayrollRegistry

**Source**: `contracts/payroll_registry/src/lib.rs`
**Contract ID**: deployed as `payroll_registry.wasm`

#### `register_company`

| Field     | Type      | Description                                       |
|-----------|-----------|---------------------------------------------------|
| `admin`   | `Address` | Company admin (must sign)                          |
| `treasury`| `Address` | Payment source address for token transfers         |
| **Returns** | `u64`   | Newly assigned company ID                          |

**Behavior**:
- Requires `admin.require_auth()` — the caller must be the admin address.
- Company IDs are allocated sequentially starting from `0`.
- Returns the assigned company ID.

**Errors**: None (always succeeds).

---

#### `add_employee`

| Field       | Type        | Description                              |
|-------------|-------------|------------------------------------------|
| `company_id`| `u64`       | Target company                           |
| `employee`  | `Address`   | Employee Ed25519 public key              |
| `commitment`| `BytesN<32>`| Poseidon(salary, blinding) — 32 bytes    |
| **Returns** | `()`        | void                                     |

**Behavior**:
- Loads `CompanyInfo` for `company_id`; panics with `"Company not found"` if missing.
- Calls `info.admin.require_auth()`.
- Stores `commitment` under `(company_id, employee)`.

**Errors**:
- `panic!("Company not found")` — company does not exist

---

#### `remove_employee`

| Field       | Type      | Description         |
|-------------|-----------|---------------------|
| `company_id`| `u64`     | Target company      |
| `employee`  | `Address` | Employee to remove  |
| **Returns** | `()`      | void                |

**Behavior**:
- Loads `CompanyInfo`; panics if missing.
- Requires admin auth.
- Hard-deletes the employee record.

**Errors**:
- `panic!("Company not found")`

---

#### `update_commitment`

| Field          | Type        | Description                          |
|----------------|-------------|--------------------------------------|
| `company_id`   | `u64`       | Target company                       |
| `employee`     | `Address`   | Employee whose commitment to update  |
| `new_commitment`| `BytesN<32>`| New Poseidon commitment              |
| **Returns**    | `()`        | void                                 |

**Behavior**:
- Loads `CompanyInfo`; panics if missing.
- Requires admin auth.
- Checks employee exists via `storage().has()`; panics `"Employee not found"` if absent.
- Overwrites commitment in storage.

**Errors**:
- `panic!("Company not found")`
- `panic!("Employee not found")`

---

#### `get_company`

| Field       | Type  | Description    |
|-------------|-------|----------------|
| `company_id`| `u64` | Target company |
| **Returns** | `CompanyInfo` | See [CompanyInfo](#companyinfo) |

**Behavior**: Read-only. Returns `CompanyInfo { admin: Address, treasury: Address }`.

**Errors**: `panic!("Company not found")`

---

#### `get_commitment`

| Field       | Type        | Description    |
|-------------|-------------|----------------|
| `company_id`| `u64`       | Target company |
| `employee`  | `Address`   | Employee       |
| **Returns** | `BytesN<32>` | Stored commitment (32 bytes) |

**Behavior**: Read-only. Returns the raw commitment bytes stored for the employee.

**Errors**: `panic!("Employee not found")`

---

### 2.2 SalaryCommitment

**Source**: `contracts/salary_commitment/src/lib.rs`
**Contract ID**: deployed as `salary_commitment.wasm`

> 15 public entrypoints: init, admin, operator, store, update, rotate, status, history, get, has, nullifier (record + check), compute, verify.

#### `init_commitment_admin`

| Field   | Type      | Description               |
|---------|-----------|---------------------------|
| `admin` | `Address` | HR admin for this contract |
| **Returns** | `()`  | void                      |

**Behavior**: One-time initialization. Sets the HR admin address that authorizes all commitment writes.

**Errors**: `panic!("Already initialized")`

---

#### `set_payroll_operator`

| Field      | Type      | Description                           |
|------------|-----------|---------------------------------------|
| `operator` | `Address` | Address delegated to record nullifiers |
| **Returns** | `()`     | void                                  |

**Behavior**: Only callable by the HR admin. Allows a separate address (typically the Payroll contract) to call `record_nullifier`.

**Errors**: `panic!("Not initialized")` — if admin not yet set.

---

#### `get_commitment_admin`

| Field | Type | Description |
|-------|------|-------------|
| **Returns** | `Address` | The stored HR admin address |

**Behavior**: Read-only.

**Errors**: `panic!("Not initialized")`

---

#### `get_payroll_operator`

| Field | Type | Description |
|-------|------|-------------|
| **Returns** | `Option<Address>` | `Some(operator)` or `None` |

**Behavior**: Read-only. Returns `None` if no operator has been set.

**Errors**: None.

---

#### `store_commitment`

| Field       | Type        | Description                              |
|-------------|-------------|------------------------------------------|
| `employee`  | `Address`   | Employee address                         |
| `commitment`| `BytesN<32>`| Poseidon(salary, blinding) — 32 bytes    |
| **Returns** | `SalaryCommitment` | See [SalaryCommitment](#salarycommitment) |

**Behavior**:
- Requires HR admin auth.
- Creates a new `SalaryCommitment` with `version = 1`, `revoked = false`, timestamps set to current ledger time.
- Emits `(Symbol("CommitmentUpdated"), employee_Address) → (commitment,)` event.

**Errors**:
- `panic!("Not initialized")` — admin not set

---

#### `update_commitment`

| Field          | Type        | Description                          |
|----------------|-------------|--------------------------------------|
| `employee`     | `Address`   | Employee address                     |
| `new_commitment`| `BytesN<32>`| New Poseidon commitment              |
| **Returns**    | `SalaryCommitment` | Updated commitment record     |

**Behavior**:
- Requires HR admin auth.
- Archives the current commitment to `CommitmentHistory`.
- Creates new record with incremented `version`, `revoked = false`.
- Emits `(Symbol("CommitmentUpdated"), employee) → (new_commitment,)` event.

**Errors**:
- `panic!("Commitment not found")` — no existing commitment for employee
- `panic!("Not initialized")`

---

#### `rotate_commitment`

| Field          | Type        | Description                          |
|----------------|-------------|--------------------------------------|
| `employee`     | `Address`   | Employee address                     |
| `new_commitment`| `BytesN<32>`| New Poseidon commitment              |
| **Returns**    | `SalaryCommitment` | New active commitment         |

**Behavior**:
- Archives the current commitment to history.
- Marks the existing record as `revoked = true` (cannot be used in future proofs).
- Stores the new commitment as active via `store_commitment`.
- Emits `(Symbol("CommitmentRotated"), employee) → (old_commitment, new_commitment)` event.

**Errors**:
- `panic!("Commitment not found")`
- `panic!("Not initialized")`

---

#### `is_commitment_active`

| Field      | Type      | Description    |
|------------|-----------|----------------|
| `employee` | `Address` | Employee       |
| **Returns**| `bool`    | `true` if active and not revoked |

**Behavior**: Read-only. Returns `false` if no commitment exists or the existing one has `revoked = true`.

**Errors**: None.

---

#### `get_commitment_history`

| Field      | Type      | Description    |
|------------|-----------|----------------|
| `employee` | `Address` | Employee       |
| **Returns**| `Vec<CommitmentSnapshot>` | Ordered history |

**Behavior**: Returns archived snapshots in order (oldest first). Empty vec if no rotations have occurred.

**Errors**: None.

---

#### `get_commitment`

| Field      | Type      | Description |
|------------|-----------|-------------|
| `employee` | `Address` | Employee    |
| **Returns**| `SalaryCommitment` | Active commitment record |

**Behavior**: Read-only.

**Errors**: `panic!("Commitment not found")`

---

#### `has_commitment`

| Field      | Type      | Description |
|------------|-----------|-------------|
| `employee` | `Address` | Employee    |
| **Returns**| `bool`    | Whether a commitment record exists |

**Behavior**: Read-only. Returns `false` if no commitment has ever been stored.

**Errors**: None.

---

#### `record_nullifier`

| Field       | Type        | Description              |
|-------------|-------------|--------------------------|
| `nullifier` | `BytesN<32>`| Unique proof nullifier   |
| **Returns** | `()`        | void                     |

**Behavior**:
- Requires HR admin OR payroll operator auth.
- Checks nullifier hasn't been used; panics if already recorded.
- Stores `PaymentNullifier { nullifier, used_at: current_timestamp }`.

**Errors**:
- `panic!("Nullifier already used")`
- `panic!("Not initialized")`

---

#### `is_nullifier_used`

| Field       | Type        | Description              |
|-------------|-------------|--------------------------|
| `nullifier` | `BytesN<32>`| Nullifier bytes          |
| **Returns** | `bool`      | Whether nullifier exists |

**Behavior**: Read-only.

**Errors**: None.

---

#### `compute_commitment`

| Field            | Type        | Description                     |
|------------------|-------------|---------------------------------|
| `salary`         | `u64`       | Salary amount                   |
| `blinding_factor`| `BytesN<32>`| 32-byte blinding factor         |
| **Returns**      | `BytesN<32>`| SHA-256(salary ‖ blinding) hash |

**Behavior**:
- Encodes `salary` as 8 bytes little-endian.
- Concatenates with 32-byte blinding factor.
- Returns SHA-256 hash.
- **Note**: Current on-chain implementation uses SHA-256. Production will migrate to Poseidon when Soroban host functions support it (CAP-0075).

**Errors**: None.

---

#### `verify_commitment`

| Field            | Type        | Description                |
|------------------|-------------|----------------------------|
| `employee`       | `Address`   | Employee                   |
| `claimed_salary` | `u64`       | Claimed salary amount      |
| `blinding_factor`| `BytesN<32>`| Blinding factor            |
| **Returns**      | `bool`      | `true` if commitment matches AND active |

**Behavior**: Retrieves stored commitment, recomputes hash from claimed salary + blinding, and checks equality AND that the stored commitment is not revoked.

**Errors**: `panic!("Commitment not found")`

---

### 2.3 ProofVerifier

**Source**: `contracts/proof_verifier/src/lib.rs`
**Contract ID**: deployed as `proof_verifier.wasm`

#### `init_verifier_admin`

| Field   | Type      | Description   |
|---------|-----------|---------------|
| `admin` | `Address` | Verifier admin |
| **Returns** | `()`  | void          |

**Behavior**: One-time initialization.

**Errors**: `panic!("Already initialized")`

---

#### `get_verifier_admin`

| Field | Type | Description |
|-------|------|-------------|
| **Returns** | `Address` | Stored admin address |

**Errors**: `panic!("Not initialized")`

---

#### `initialize_verifier`

| Field | Type              | Description              |
|-------|-------------------|--------------------------|
| `vk`  | `VerificationKey` | Groth16 verification key |
| **Returns** | `()`       | void                     |

**Behavior**: One-time setup. Requires admin auth. Stores the verification key.

**Errors**:
- `panic!("Not initialized")`
- `panic!("Verifier already initialized")`

---

#### `get_verification_key`

| Field | Type | Description |
|-------|------|-------------|
| **Returns** | `VerificationKey` | Stored VK |

**Errors**: `panic!("Verifier not initialized")`

---

#### `verify`

| Field           | Type                  | Description                      |
|-----------------|-----------------------|----------------------------------|
| `proof`         | `Groth16Proof`        | Structured proof with A, B, C    |
| `public_inputs` | `Vec<BytesN<32>>`     | Public inputs (commitment, amount, etc.) |
| **Returns**     | `bool`                | `true` if proof is valid         |

**Behavior**: Packs `Groth16Proof` into 256-byte buffer then delegates to `verify_payment_proof`. See [4.4 Proof Data](#44-proof-data) for serialization layout.

**Errors**: None (returns `false` on any verification failure).

---

#### `verify_payment_proof`

| Field           | Type                  | Description                      |
|-----------------|-----------------------|----------------------------------|
| `proof`         | `BytesN<256>`         | Flat 256-byte packed proof       |
| `public_inputs` | `Vec<BytesN<32>>`     | Public inputs (32 bytes each)    |
| **Returns**     | `bool`                | `true` if proof is valid         |

**Behavior**:
- Loads stored VK.
- Checks `public_inputs.len() + 1 == vk.ic.len()` — returns `false` if mismatch.
- Delegates to Groth16 pairing check.
- **⚠️ Current implementation**: `simulated_verify_groth16` always returns `true`. Production must replace with real BN254 pairing verification.

**Errors**: None (returns `false` on any failure).

---

### 2.4 PaymentExecutor

**Source**: `contracts/payment_executor/src/lib.rs`
**Contract ID**: deployed as `payment_executor.wasm`

> 11 public entrypoints: initialize, admin, pause-manager, period lifecycle (create/close/get), payment (single/batch), payment query (get/is_paid), total.

#### `initialize`

| Field       | Type              | Description                             |
|-------------|-------------------|-----------------------------------------|
| `addresses` | `ContractAddresses` | Addresses of registry, commitment, verifier, token contracts |
| **Returns** | `()`              | void                                    |

**Behavior**: One-time initialization. Stores dependent contract addresses.

**Errors**: `panic!("Already initialized")`

---

#### `set_executor_admin`

| Field   | Type      | Description            |
|---------|-----------|------------------------|
| `admin` | `Address` | Executor-level admin   |
| **Returns** | `()`  | void                   |

**Behavior**: One-time, protected by caller auth.

**Errors**: `panic!("Executor admin already set")`

---

#### `set_pause_manager`

| Field          | Type      | Description               |
|----------------|-----------|---------------------------|
| `pause_manager`| `Address` | PauseManager contract     |
| **Returns**    | `()`      | void                      |

**Behavior**: Only executor admin may call.

**Errors**: `panic!("Executor admin not set")`

---

#### `create_period`

| Field       | Type   | Description    |
|-------------|--------|----------------|
| `company_id`| `u64`  | Target company |
| **Returns** | `Result<PayrollPeriod, PaymentError>` | Created period or error |

**Behavior**:
- Loads registry, requires company admin auth.
- Period IDs are sequential per company (starting at `1`).
- Only one period per company can be open at a time — but check is implicit (duplicate ID returns `PeriodAlreadyExists`).
- Emits `(Symbol("PeriodCreated"), company_id) → (period_id,)` event.

**Errors**:
- `Err(PaymentError::PeriodAlreadyExists)` — if the next sequential ID somehow already exists (race condition guard)

---

#### `close_period`

| Field       | Type    | Description     |
|-------------|---------|-----------------|
| `company_id`| `u64`   | Target company  |
| `period_id` | `u32`   | Period to close |
| **Returns** | `Result<PayrollPeriod, PaymentError>` | Closed period |

**Behavior**:
- Requires company admin auth.
- Sets `closed = true`, records `end_ledger`.
- Emits `(Symbol("PeriodClosed"), company_id) → (period_id,)` event.

**Errors**:
- `Err(PaymentError::PeriodNotFound)`
- `Err(PaymentError::PeriodClosed)` — period already closed

---

#### `get_period`

| Field       | Type    | Description     |
|-------------|---------|-----------------|
| `company_id`| `u64`   | Target company  |
| `period_id` | `u32`   | Period ID       |
| **Returns** | `Option<PayrollPeriod>` | Period or `None` |

**Behavior**: Read-only.

**Errors**: None.

---

#### `execute_payment`

| Field       | Type          | Description                        |
|-------------|---------------|------------------------------------|
| `company_id`| `u64`         | Target company                     |
| `employee`  | `Address`     | Employee receiving payment         |
| `amount`    | `i128`        | Payment amount (in token units)    |
| `proof_a`   | `BytesN<64>`  | Groth16 proof A (G1 point)        |
| `proof_b`   | `BytesN<128>` | Groth16 proof B (G2 point)        |
| `proof_c`   | `BytesN<64>`  | Groth16 proof C (G1 point)        |
| `nullifier` | `BytesN<32>`  | Unique payment nullifier           |
| `period`    | `u32`         | Payroll period ID                  |
| **Returns** | `Result<PaymentRecord, PaymentError>` | Payment record or error |

**Behavior** (in order):
1. **Pause check**: If `PauseManager` is configured, checks `is_paused()`; panics `"Payroll is paused"` if paused.
2. **Period validation**: Period must exist and be open (`!closed`).
3. **Nullifier check**: Reject if nullifier `ProofAlreadyUsed`.
4. **Double-payment check**: Reject if employee already paid in this period (`AlreadyPaid`).
5. **Commitment retrieval**: Fetches commitment from `SalaryCommitment` contract.
6. **Company info**: Fetches company metadata from `PayrollRegistry`.
7. **Admin auth**: Requires company `admin.require_auth()`.
8. **Proof verification**: Constructs public inputs as `[commitment, amount_as_public_input]`, calls `ProofVerifier.verify()`.
9. **Token transfer**: `token.transfer(company.treasury, employee, amount)`.
10. **State recording**: Stores payment record, marks nullifier used, increments total paid + period payment count.
11. **Event**: Emits `(Symbol("PayrollProcessed"), company_id) → (employee, amount, period)`.

**Errors**:
- `Err(PaymentError::PeriodNotFound)` — period does not exist
- `Err(PaymentError::PeriodClosed)` — period is closed
- `Err(PaymentError::ProofAlreadyUsed)` — nullifier already recorded
- `Err(PaymentError::AlreadyPaid)` — employee already paid in this period
- `panic!("Invalid payment proof")` — Groth16 verification failed
- `panic!("Payroll is paused")` — pause manager is active and paused
- `panic!("Company not found")` — registry lookup failure (propagated)

---

#### `execute_batch_payroll`

| Field        | Type                  | Description                              |
|--------------|-----------------------|------------------------------------------|
| `company_id` | `u64`                 | Target company                           |
| `employees`  | `Vec<Address>`        | Employee addresses                       |
| `amounts`    | `Vec<i128>`           | Payment amounts (same length)            |
| `proofs_a`   | `Vec<BytesN<64>>`     | G1 proof A components                    |
| `proofs_b`   | `Vec<BytesN<128>>`    | G2 proof B components                    |
| `proofs_c`   | `Vec<BytesN<64>>`     | G1 proof C components                    |
| `nullifiers` | `Vec<BytesN<32>>`     | Unique nullifiers per payment            |
| `period`     | `u32`                 | Payroll period ID                        |
| **Returns**  | `Result<Vec<PaymentRecord>, PaymentError>` | All payment records or first error |

**Behavior**:
- All input vectors must have identical length; returns `Err(ArrayLengthMismatch)` otherwise.
- Iterates sequentially, calling `execute_payment` for each employee.
- First failure aborts the entire batch.

---

#### `get_payment`

| Field      | Type      | Description              |
|------------|-----------|--------------------------|
| `employee` | `Address` | Employee address         |
| `period`   | `u32`     | Payroll period ID        |
| **Returns**| `PaymentRecord` | Stored payment record |

**Errors**: `panic!("Payment not found")`

---

#### `is_paid`

| Field      | Type      | Description              |
|------------|-----------|--------------------------|
| `employee` | `Address` | Employee address         |
| `period`   | `u32`     | Payroll period ID        |
| **Returns**| `bool`    | Whether payment exists   |

**Errors**: None.

---

#### `get_total_paid`

| Field       | Type  | Description                  |
|-------------|-------|------------------------------|
| `company_id`| `u64` | Target company               |
| **Returns** | `i128`| Cumulative amount paid       |

**Errors**: None (returns `0` for unknown companies).

---

### 2.5 Payroll (high-level batch)

**Source**: `contracts/payroll/src/lib.rs`
**Contract ID**: deployed as `payroll.wasm`

#### `initialize`

| Field        | Type      | Description            |
|--------------|-----------|------------------------|
| `admin`      | `Address` | Payroll admin          |
| `token`      | `Address` | Token contract address |
| `verifier`   | `Address` | ProofVerifier address  |
| `commitment` | `Address` | SalaryCommitment addr  |
| `treasury`   | `Address` | Treasury address       |
| **Returns**  | `()`      | void                   |

**Errors**: `panic!("Already initialized")`

---

#### `set_pause_manager`

| Field          | Type      | Description                   |
|----------------|-----------|-------------------------------|
| `pause_manager`| `Address` | PauseManager contract address |
| **Returns**    | `()`      | void                          |

**Errors**: `panic!("Not initialized")` then admin auth failure.

---

#### `deposit`

| Field    | Type      | Description   |
|----------|-----------|---------------|
| `_from`  | `Address` | (unused)      |
| `_amount`| `i128`    | (unused)      |
| **Returns** | `()`   | void          |

**Behavior**: Placeholder — no-op in current implementation.

---

#### `batch_process_payroll`

| Field                 | Type               | Description                              |
|-----------------------|--------------------|------------------------------------------|
| `proofs`              | `Vec<BytesN<256>>` | Flat 256-byte packed proofs              |
| `amounts`             | `Vec<i128>`        | Payment amounts                           |
| `employees`           | `Vec<Address>`     | Employee addresses                        |
| `expected_total_spend`| `i128`             | Admin-declared total (must equal sum)     |
| **Returns**           | `()`               | void                                      |

**Behavior** (in order):
1. **Length check**: `proofs.len() == amounts.len() == employees.len()`. Panics `"Array length mismatch"` on failure.
2. **Batch size limit**: `proofs.len() <= 50` (constant `MAX_BATCH`). Panics `"Batch too large"`.
3. **Spend authorization**: Sums all amounts, compares to `expected_total_spend`. Panics on mismatch.
4. **Pause check**: If PauseManager configured, checks `is_paused()`; panics `"Payroll is paused"` if paused.
5. **Admin auth**: Calls `addrs.admin.require_auth()`.
6. **Per-employee loop**:
   a. Retrieve commitment from `SalaryCommitment` contract. Panics `"Commitment not found"` if missing.
   b. Construct public inputs: `[commitment, nullifier, recipient_hash]`.
   c. Verify proof via `ProofVerifier.verify_payment_proof()`. Panics `"Invalid payment proof"` on failure.
   d. Record nullifier via `SalaryCommitment.record_nullifier()`. Panics `"Nullifier already used"` on replay.
   e. Transfer tokens: `token.transfer(treasury, employee, amount)`.
   f. Emit event: `(symbol_short!("payroll"), Symbol("payment_executed")) → (employee, amount)`.

**⚠️ Note**: The nullifier is derived deterministically from the batch index (`[index_lsb, index_msb, 0, ..., 0]`), not from the proof itself. Production must use a proper cryptographic nullifier.

**Errors** (all `panic!`, not `Result`):
- `panic!("Array length mismatch")`
- `panic!("Batch too large")`
- `panic!("Expected spend mismatch: authorised X but batch totals Y")`
- `panic!("Payroll is paused")`
- `panic!("Invalid payment proof for employee N")`
- `panic!("Nullifier already used")`
- `panic!("Commitment not found")`

---

### 2.6 AuditModule

**Source**: `contracts/audit_module/src/lib.rs`
**Contract ID**: deployed as `audit_module.wasm`

#### `generate_view_key`

| Field               | Type      | Description              |
|---------------------|-----------|--------------------------|
| `auditor`           | `Address` | Auditor address          |
| `expiration_ledger` | `u32`     | Expiration ledger seq    |
| **Returns**         | `BytesN<32>` | SHA-256 derived view key |

**Errors**: None.

---

#### `verify_access`

| Field     | Type      | Description    |
|-----------|-----------|----------------|
| `auditor` | `Address` | Auditor        |
| **Returns**| `bool`   | Key exists and not expired |

**Errors**: None.

---

#### `revoke_view_key`

| Field     | Type                        | Description    |
|-----------|-----------------------------|----------------|
| `admin`   | `Address`                   | Key granter    |
| `auditor` | `Address`                   | Auditor        |
| **Returns**| `Result<(), AuditError>`   | void or error  |

**Errors**:
- `Err(AuditError::KeyNotFound)`
- `Err(AuditError::NotKeyGranter)` — caller is not the granter

---

#### `get_view_key`

| Field     | Type                          | Description    |
|-----------|-------------------------------|----------------|
| `auditor` | `Address`                     | Auditor        |
| **Returns**| `Result<ViewKeyRecord, AuditError>` | Record or error |

**Errors**: `Err(AuditError::KeyNotFound)`

---

#### `verify_commitment_with_key`

| Field              | Type                          | Description                        |
|--------------------|-------------------------------|------------------------------------|
| `auditor`          | `Address`                     | Auditor                            |
| `stored_commitment`| `BytesN<32>`                  | Commitment from employee           |
| `claimed_amount`   | `i128`                        | Claimed salary amount              |
| `blinding_factor`  | `BytesN<32>`                  | Blinding factor                    |
| `scope`            | `AuditScope`                  | Access scope                       |
| **Returns**        | `Result<bool, AuditError>`    | Match result or error              |

**Behavior**: Computes keyed commitments and compares. Records audit log entry.

**Errors**:
- `Err(AuditError::KeyNotFound)`
- `Err(AuditError::KeyExpired)`
- `Err(AuditError::InsufficientScope)` — scope is `AggregateOnly`
- `Err(AuditError::CommitmentMismatch)` — hash does not match

---

#### `verify_commitment_with_view_key`

| Field              | Type                          | Description                        |
|--------------------|-------------------------------|------------------------------------|
| `auditor`          | `Address`                     | Auditor                            |
| `supplied_key`     | `BytesN<32>`                  | The purported view key             |
| `stored_commitment`| `BytesN<32>`                  | Commitment from employee           |
| `claimed_amount`   | `i128`                        | Claimed salary amount              |
| `blinding_factor`  | `BytesN<32>`                  | Blinding factor                    |
| `scope`            | `AuditScope`                  | Access scope                       |
| **Returns**        | `Result<bool, AuditError>`    | Match result or error              |

**Errors**: Same as `verify_commitment_with_key` plus:
- `Err(AuditError::InvalidViewKey)` — supplied key does not match stored key

---

#### `generate_aggregate_report`

| Field         | Type                          | Description    |
|---------------|-------------------------------|----------------|
| `auditor`     | `Address`                     | Auditor        |
| `company_id`  | `Symbol`                      | Company symbol |
| `period_start`| `u64`                         | Start timestamp|
| `period_end`  | `u64`                         | End timestamp  |
| **Returns**    | `Result<AuditReport, AuditError>` | Report or error |

**Errors**:
- `Err(AuditError::KeyNotFound)`
- `Err(AuditError::KeyExpired)`

---

#### Query methods

| Method             | Parameters                         | Returns              |
|--------------------|------------------------------------|----------------------|
| `query_by_company` | `company_id: Symbol`               | `AuditQueryResult`   |
| `query_by_employee`| `company_id: Symbol, employee: Address` | `AuditQueryResult` |
| `query_by_period`  | `company_id: Symbol, period_start: u64, period_end: u64` | `AuditQueryResult` |
| `get_audit_log_count` | `company_id: Symbol`           | `u32`                |

All query methods are read-only with no errors.

**⚠️ Known limitation**: The internal `record_audit_log` helper hardcodes `company_id = Symbol("default")` regardless of the company being queried. This means `query_by_company`, `query_by_employee`, and `query_by_period` all return the same audit log entries regardless of the `company_id` argument. This will be addressed in a future release to scope audit logs per-company.

---

### 2.7 PauseManager

**Source**: `contracts/pause_manager/src/lib.rs`
**Contract ID**: deployed as `pause_manager.wasm`

| Method         | Parameters      | Returns   | Access Control        |
|----------------|-----------------|-----------|-----------------------|
| `initialize`   | `operator: Address` | `()`   | None (one-time)       |
| `pause`        | —               | `()`      | `require_auth(operator)` |
| `unpause`      | —               | `()`      | `require_auth(operator)` |
| `is_paused`    | —               | `bool`    | Public                |
| `set_operator` | `new_operator: Address` | `()` | `require_auth(operator)` |

**Errors**:
- `panic!("Already initialized")` — `initialize` called twice
- `panic!("Not initialized")` — `pause`/`unpause`/`set_operator` before `initialize`

---

### 2.8 Token (mock / SEP-41)

**Source**: `contracts/token/src/lib.rs`

**⚠️ Note**: This is a minimal mock token for testing. Production deployments replace this with a real SEP-41 token (e.g., Stellar native asset or soroban-token-contract).

| Method     | Parameters                              | Returns | Notes                      |
|------------|-----------------------------------------|---------|----------------------------|
| `initialize` | `_admin: Address, _decimal: u32, _name: String, _symbol: String` | `()` | No-op mock       |
| `mint`     | `to: Address, amount: i128`             | `()`    | Increases balance          |
| `balance`  | `id: Address`                           | `i128`  | Returns stored balance     |
| `transfer` | `from: Address, to: Address, amount: i128` | `()` | Transfers; panics on insufficient balance |

---

## 3. Data Structures

### `CompanyInfo`

| Field      | Type      | Description                   |
|------------|-----------|-------------------------------|
| `admin`    | `Address` | Company admin (auth key)      |
| `treasury` | `Address` | Token source address          |

**Storage**: Keyed by `DataKey::Company(u64)` in persistent storage.

---

### `SalaryCommitment`

| Field        | Type        | Description                           |
|--------------|-------------|---------------------------------------|
| `commitment` | `BytesN<32>`| Poseidon(salary, blinding_factor)     |
| `created_at` | `u64`       | Ledger timestamp at creation          |
| `updated_at` | `u64`       | Ledger timestamp at last update       |
| `version`    | `u32`       | Monotonically increasing version      |
| `revoked`    | `bool`      | Whether commitment has been rotated   |

**Storage**: Keyed by `DataKey::Commitment(Address)`.

---

### `CommitmentSnapshot`

| Field        | Type        | Description                  |
|--------------|-------------|------------------------------|
| `commitment` | `BytesN<32>`| Previously active commitment |
| `version`    | `u32`       | Version at time of rotation  |
| `rotated_at` | `u64`       | Timestamp of rotation        |

**Storage**: Keyed by `DataKey::CommitmentHistory(Address, u32)`.

---

### `PaymentNullifier`

| Field       | Type        | Description              |
|-------------|-------------|--------------------------|
| `nullifier` | `BytesN<32>`| Unique nullifier bytes   |
| `used_at`   | `u64`       | Ledger timestamp         |

**Storage**: Keyed by `DataKey::Nullifier(BytesN<32>)`.

---

### `PaymentRecord`

| Field        | Type        | Description                      |
|--------------|-------------|----------------------------------|
| `company_id` | `u64`       | Company ID                       |
| `employee`   | `Address`   | Employee recipient               |
| `proof_hash` | `BytesN<32>`| Nullifier (used as proof hash)   |
| `timestamp`  | `u64`       | Ledger timestamp of payment      |
| `period`     | `u32`       | Payroll period ID                |

**Storage**: Keyed by `DataKey::Payment(Address, u32)`.

---

### `PayrollPeriod`

| Field           | Type   | Description                         |
|-----------------|--------|-------------------------------------|
| `period_id`     | `u32`  | Sequential period ID (per company)  |
| `company_id`    | `u64`  | Company ID                          |
| `start_ledger`  | `u32`  | Ledger sequence when opened         |
| `end_ledger`    | `u32`  | Ledger sequence when closed (0=open)|
| `created_at`    | `u64`  | Unix timestamp at creation          |
| `closed`        | `bool` | Whether period is closed            |
| `payment_count` | `u32`  | Number of payments in this period   |

**Storage**: Keyed by `DataKey::Period(u64, u32)`.

---

### `Groth16Proof`

| Field | Type          | Description                    |
|-------|---------------|--------------------------------|
| `a`   | `BytesN<64>`  | G1 point π_A (x ‖ y)          |
| `b`   | `BytesN<128>` | G2 point π_B (x0 ‖ x1 ‖ y0 ‖ y1) |
| `c`   | `BytesN<64>`  | G1 point π_C (x ‖ y)          |

**Flat encoding** (256 bytes):

```
offset 0..64:   a (G1)
offset 64..192: b (G2)
offset 192..256: c (G1)
```

---

### `VerificationKey`

| Field   | Type                | Description                     |
|---------|---------------------|---------------------------------|
| `alpha` | `BytesN<64>`        | G1 point α                      |
| `beta`  | `BytesN<128>`       | G2 point β                      |
| `gamma` | `BytesN<128>`       | G2 point γ                      |
| `delta` | `BytesN<128>`       | G2 point δ                      |
| `ic`    | `Vec<BytesN<64>>`   | G1 elements for public inputs   |

**Note**: `ic.len()` must equal `public_inputs.len() + 1` for verification to succeed.

---

### `ContractAddresses` (PaymentExecutor)

| Field        | Type      | Description                     |
|--------------|-----------|---------------------------------|
| `registry`   | `Address` | PayrollRegistry contract        |
| `commitment` | `Address` | SalaryCommitment contract       |
| `verifier`   | `Address` | ProofVerifier contract          |
| `token`      | `Address` | Token contract                  |

---

### `ContractAddresses` (Payroll)

| Field        | Type      | Description               |
|--------------|-----------|---------------------------|
| `admin`      | `Address` | Payroll contract admin    |
| `token`      | `Address` | Token contract            |
| `verifier`   | `Address` | ProofVerifier contract    |
| `commitment` | `Address` | SalaryCommitment contract |
| `treasury`   | `Address` | Treasury address          |

---

### Audit Types

#### `ViewKeyRecord`

| Field              | Type        | Description                |
|--------------------|-------------|----------------------------|
| `key_bytes`        | `BytesN<32>`| Derived view key           |
| `expiration_ledger`| `u32`       | Expiration ledger sequence |
| `granted_by`       | `Address`   | Admin who granted the key  |

#### `AuditScope`

| Variant         | Value | Description                     |
|-----------------|-------|---------------------------------|
| `FullCompany`   | `0`   | Full access to company data     |
| `TimeRange`     | `1`   | Access within a time range      |
| `EmployeeList`  | `2`   | Access to specific employees    |
| `AggregateOnly` | `3`   | Aggregate statistics only       |

#### `AuditLogEntry`

| Field        | Type        | Description            |
|--------------|-------------|------------------------|
| `auditor`    | `Address`   | Auditor address        |
| `company_id` | `Symbol`    | Company symbol         |
| `scope`      | `AuditScope`| Access scope used      |
| `timestamp`  | `u64`       | Ledger timestamp       |
| `matched`    | `bool`      | Verification result    |

#### `AuditReport`

| Field           | Type     | Description     |
|-----------------|----------|-----------------|
| `company_id`    | `Symbol` | Company symbol  |
| `total_employees`| `u32`   | Employee count  |
| `total_paid`    | `i128`   | Total paid      |
| `period_start`  | `u64`    | Period start    |
| `period_end`    | `u64`    | Period end      |
| `verified`      | `bool`   | Verification    |

#### `AuditQueryResult`

| Field     | Type               | Description   |
|-----------|--------------------|---------------|
| `entries` | `Vec<AuditLogEntry>`| Matching logs |

---

## 4. Serialization Rules

### 4.1 Addresses

| Aspect          | Rule                                              |
|-----------------|---------------------------------------------------|
| **On-chain**    | Soroban `Address` (20 bytes for `AccountId`, 32+1 for contract) |
| **String**      | Stellar StrKey format: `G...` (Ed25519), `C...` (Contract) |
| **SDK**         | Use `stellar-strkey` for encode/verify            |
| **Binary**      | 32-byte Ed25519 public key for accounts           |

### 4.2 Identifiers

| Identifier    | Type   | Wire Encoding | Endianness | Range       |
|---------------|--------|---------------|------------|-------------|
| Company ID    | `u64`  | XDR `Uint64`  | Big-endian | `0` to `2^64-1` |
| Period ID     | `u32`  | XDR `Uint32`  | Big-endian | `1` to `2^32-1` |
| Ledger seq    | `u32`  | XDR `Uint32`  | Big-endian | Stellar ledger range |
| Timestamp     | `u64`  | XDR `Uint64`  | Big-endian | Unix epoch seconds |

### 4.3 Commitment Data

#### Encoding

Commitments are exactly **32 bytes** (`BytesN<32>` in Soroban, `[u8; 32]` in Rust).

#### Computation (on-chain, via `compute_commitment`)

```
preimage = salary.to_le_bytes() ++ blinding_factor[0..32]
output   = SHA-256(preimage)
```

Where:
- `salary` is a `u64` encoded as 8 bytes little-endian
- `blinding_factor` is 32 bytes

#### Computation (off-chain CLI, via `poseidon_commitment`)

```
input_1 = Fr(salary)            // BN254 scalar from u64
input_2 = Fr(blinding_factor)   // BN254 scalar from LE bytes
output  = Poseidon([input_1, input_2])  // circomlib-compatible width-3 sponge
```

**Notes**:
- Off-chain uses Poseidon for Circom compatibility.
- On-chain currently uses SHA-256 as a placeholder.
- **Migration**: When Soroban CAP-0075 lands, on-chain will switch to Poseidon to match circuit.

#### Serialization format for SDK

```
BytesN<32> — 32 raw bytes
```

- **Wire format**: XDR `BytesN<32>` (32-byte opaque)
- **Hex string**: 64 lowercase hex characters (e.g., `a1b2c3...`)
- **Conversion**: Use `stellar-xdr` for XDR; standard hex encoding for display

### 4.4 Proof Data

#### `Groth16Proof` structure

| Field | Size    | Content                                                    |
|-------|---------|------------------------------------------------------------|
| `a`   | 64 bytes| G1 point: `x[32] ‖ y[32]` — big-endian field elements      |
| `b`   | 128 bytes| G2 point: `x0[32] ‖ x1[32] ‖ y0[32] ‖ y1[32]` — BE     |
| `c`   | 64 bytes| G1 point: `x[32] ‖ y[32]` — big-endian field elements      |

#### Flat 256-byte encoding

```
offset 0..64:     G1 π_A (a.x, a.y)
offset 64..192:   G2 π_B (b.x0, b.x1, b.y0, b.y1)
offset 192..256:  G1 π_C (c.x, c.y)
```

Used by `ProofVerifier.verify_payment_proof(proof: BytesN<256>, ...)`.

#### Field element encoding

| Aspect        | Rule                                                       |
|---------------|------------------------------------------------------------|
| **Size**      | Exactly 32 bytes per BN254 scalar field element            |
| **Endianness**| Big-endian (matching EVM/ethers convention)                 |
| **Range**     | Must be < BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617 |
| **Zero-pad**  | Left-padded with zeros to 32 bytes                         |
| **Hex**       | 64 lowercase hex characters per element                   |

#### `proof_bytes.json` format (integration test helper)

```json
{
  "pi_a":              "<128 hex chars>",
  "pi_b":              "<256 hex chars>",
  "pi_c":              "<128 hex chars>",
  "salary_commitment": "<64 hex chars>",
  "payment_nullifier":  "<64 hex chars>",
  "recipient_hash":    "<64 hex chars>"
}
```

#### Public inputs layout

**PaymentExecutor**: `[commitment, amount]`
- `commitment`: `BytesN<32>` — employee's salary commitment
- `amount`: `BytesN<32>` — 16-byte big-endian amount in upper 16 bytes of 32-byte field element

**Payroll (batch)**: `[commitment, nullifier, recipient_hash]`
- `commitment`: `BytesN<32>` — employee's salary commitment
- `nullifier`: `BytesN<32>` — derived from batch index (production should use proof-derived value)
- `recipient_hash`: `BytesN<32>` — reserved (currently `[0u8; 32]`)

---

### 4.5 Nullifiers

| Aspect        | Rule                                           |
|---------------|-------------------------------------------------|
| **Type**      | `BytesN<32>` (exactly 32 bytes)               |
| **Uniqueness**| MUST be globally unique per payment            |
| **Replay guard**| PaymentExecutor checks `DataKey::Nullifier(BytesN<32>)` |
| **Construction** | Off-chain: derived from proof public inputs. On-chain batch: derived from batch index (⚠️ temporary). |

### 4.6 Amount Encoding

When an `i128` amount is converted to a public input (`BytesN<32>`) in PaymentExecutor:

```
if amount < 0 → panic!("Amount must be non-negative")
let bytes[0..16] = 0x00 * 16
let bytes[16..32] = amount.to_be_bytes()
return bytes as BytesN<32>
```

This places the amount in the **upper 16 bytes** (big-endian) of a 32-byte field element, with the lower 16 bytes zeroed.

---

## 5. Events

All events are published via `env.events().publish(topic, payload)`.

| Contract           | Event Topic                                        | Payload                                         |
|--------------------|----------------------------------------------------|-------------------------------------------------|
| `SalaryCommitment` | `(Symbol("CommitmentUpdated"), employee: Address)` | `(commitment: BytesN<32>,)`                    |
| `SalaryCommitment` | `(Symbol("CommitmentRotated"), employee: Address)` | `(old: BytesN<32>, new: BytesN<32>)`           |
| `PaymentExecutor`  | `(Symbol("PeriodCreated"), company_id: u64)`       | `(period_id: u32,)`                            |
| `PaymentExecutor`  | `(Symbol("PeriodClosed"), company_id: u64)`        | `(period_id: u32,)`                            |
| `PaymentExecutor`  | `(Symbol("PayrollProcessed"), company_id: u64)`    | `(employee: Address, amount: i128, period: u32)` |
| `Payroll`          | `(symbol_short!("payroll"), Symbol("payment_executed"))` | `(employee: Address, amount: i128)`       |
| `PauseManager`     | `(Symbol("PauseManager"), Symbol("paused"))`       | `()`                                            |
| `PauseManager`     | `(Symbol("PauseManager"), Symbol("unpaused"))`     | `()`                                            |
| `AuditModule`      | `(Symbol("AuditSuccessful"), auditor: Address)`    | `(scope: AuditScope, keyed_commitment: BytesN<32>)` |
| `AuditModule`      | `(Symbol("AggregateAuditGenerated"), auditor: Address)` | `(company_id: Symbol, period_start: u64, period_end: u64)` |

---

## 6. Error Reference

### Contract Panics (String-based)

| Contract       | Panic Message                        | Trigger                                  |
|----------------|--------------------------------------|------------------------------------------|
| PayrollRegistry| `"Company not found"`               | Unknown `company_id`                     |
| PayrollRegistry| `"Employee not found"`              | Unknown employee in company              |
| SalaryCommitment| `"Already initialized"`            | Duplicate `init_commitment_admin`        |
| SalaryCommitment| `"Not initialized"`                | Admin not set before admin-gated call    |
| SalaryCommitment| `"Commitment not found"`           | `get_commitment` for unregistered employee|
| SalaryCommitment| `"Nullifier already used"`         | Duplicate nullifier                      |
| ProofVerifier  | `"Already initialized"`             | Duplicate `init_verifier_admin`          |
| ProofVerifier  | `"Not initialized"`                 | Admin not set                            |
| ProofVerifier  | `"Verifier already initialized"`    | Duplicate `initialize_verifier`          |
| ProofVerifier  | `"Verifier not initialized"`        | VK not set before verification           |
| PaymentExecutor| `"Already initialized"`             | Duplicate `initialize`                   |
| PaymentExecutor| `"Executor admin already set"`      | Duplicate `set_executor_admin`           |
| PaymentExecutor| `"Executor admin not set"`          | `set_pause_manager` before admin set     |
| PaymentExecutor| `"Payroll is paused"`               | PauseManager active and paused           |
| PaymentExecutor| `"Invalid payment proof"`           | Groth16 verification failed              |
| PaymentExecutor| `"Payment not found"`               | `get_payment` for unknown (employee, period)|
| PaymentExecutor| `"Amount must be non-negative"`     | Negative amount in `execute_payment`     |
| Payroll        | `"Already initialized"`             | Duplicate `initialize`                   |
| Payroll        | `"Not initialized"`                 | `set_pause_manager` before init          |
| Payroll        | `"Array length mismatch"`           | Mismatched proof/amount/employee arrays  |
| Payroll        | `"Batch too large"`                 | >50 employees in batch                   |
| Payroll        | `"Expected spend mismatch: ..."`    | Sum of amounts ≠ expected_total_spend    |
| Payroll        | `"Payroll is paused"`               | PauseManager active and paused           |
| Payroll        | `"Invalid payment proof for employee N"` | Individual proof verification failed |
| Payroll        | `"Nullifier already used"`          | Nullifier replay detected (propagated)   |
| Payroll        | `"Commitment not found"`            | Missing employee commitment (propagated) |
| PauseManager   | `"Already initialized"`             | Duplicate `initialize`                   |
| PauseManager   | `"Not initialized"`                 | `pause`/`unpause` before init            |
| Token          | `"Mint amount must be non-negative"`| Negative mint amount                     |
| Token          | `"Insufficient balance"`            | Insufficient funds for transfer          |

### Typed Errors (`PaymentError`)

| Variant               | Code | Description                                     |
|-----------------------|------|-------------------------------------------------|
| `ProofAlreadyUsed`    | 1    | Nullifier already on-chain (replay prevention)  |
| `ArrayLengthMismatch` | 2    | Batch input vectors have different lengths      |
| `AlreadyPaid`         | 3    | Employee already paid in this period            |
| `PeriodNotFound`      | 4    | No period exists for (company, period_id)       |
| `PeriodClosed`        | 5    | Period is closed; no new payments allowed       |
| `PeriodAlreadyExists` | 6    | Duplicate period creation attempt               |

### Typed Errors (`AuditError`)

| Variant              | Code | Description                                    |
|----------------------|------|------------------------------------------------|
| `KeyNotFound`        | 1    | No view key stored for auditor                 |
| `WrongAuditor`       | 2    | Caller is not the designated auditor           |
| `KeyExpired`         | 3    | `ledger_sequence > expiration_ledger`          |
| `NotKeyGranter`      | 4    | Caller is not the admin that granted the key   |
| `InsufficientScope`  | 5    | Scope insufficient for requested operation     |
| `CommitmentMismatch` | 6    | Hash does not match stored commitment          |
| `InvalidViewKey`     | 7    | Supplied key does not match stored record      |

---

## 7. Compatibility & Versioning

### 7.1 Backward Compatibility Guarantees

| Component               | Guarantee Level | Notes                                         |
|-------------------------|-----------------|-----------------------------------------------|
| **Entrypoint signatures** | Stable v0.1   | Names, parameters, and types are locked. New params added as optional trailing args only. |
| **Data structures**      | Stable v0.1    | Field layout (names, types, order) fixed. New field appended to end only. |
| **Event topics**         | Stable v0.1    | Topic pattern and payload shape guaranteed. New events added with new topic symbols. |
| **Error messages**       | Unstable       | `panic!("...")` strings may change. Use typed `PaymentError`/`AuditError` codes for stable error handling. |
| **Storage layout**       | Internal       | `DataKey` enum variants may be added but existing keys (`Company`, `Employee`, etc.) will not be removed or reinterpreted. |

### 7.2 Breaking Changes Policy

A change is **breaking** if it requires SDK modifications to maintain correctness:

1. **Removing or renaming an entrypoint** — breaking (major version bump).
2. **Changing parameter types or order** — breaking.
3. **Changing return types** — breaking.
4. **Changing event topic or payload** — breaking.
5. **Adding a required parameter** — breaking (new overloaded entrypoint the SDK must call conditionally).
6. **Adding an optional parameter** — non-breaking if old call pattern still works.
7. **Adding a new entrypoint** — non-breaking (SDK can ignore).
8. **Changing panic message strings** — non-breaking (SDKs should not parse panic strings).
9. **Switching SHA-256 → Poseidon** — source-compatible for SDK callers (both produce `BytesN<32>`). Off-chain commitment generators must update algorithm.
10. **Replacing simulated Groth16 with real verification** — interface-compatible; SDK sees same `bool` return.

### 7.3 Known Migration Points

| Feature                          | Current State               | Target State                  | Expected Impact               |
|----------------------------------|------------------------------|-------------------------------|-------------------------------|
| On-chain commitment hash         | SHA-256                      | Poseidon (CAP-0075)           | Commitment byte size same; SDK generators must switch algorithm |
| Proof verification               | `simulated_verify_groth16` (always `true`) | Real BN254 pairing checks     | SDK proofs must now pass real verification |
| Payroll nullifier derivation     | Batch-index-based            | Cryptographic proof-derived   | SDKs must send proper nullifier |
| SalaryCommitment `compute_commitment` | SHA-256                    | Poseidon host function        | Same interface, different output bytes |
| Token (mock)                     | Placeholder `Token`          | SEP-41 token contract         | Same transfer interface       |

### 7.4 SDK Implementation Guidance

1. **Always use typed error codes** (`PaymentError`, `AuditError`) for error handling, never parse panic strings.
2. **Always use `try_` prefixed methods** (e.g., `try_execute_payment`) for fallible calls that return `Result`. The non-`try` variants panic on error.
3. **Validate proof byte lengths** client-side before submission: A = 64, B = 128, C = 64, flat proof = 256.
4. **For batch operations**, ensure all input vectors have identical lengths.
5. **Monitor events** for `PayrollProcessed` and `CommitmentUpdated` for off-chain indexing.
6. **Pre-allocate company IDs** with `register_company` before adding employees.

---

## Appendix A: Off-chain Commitment Generation (CLI)

For SDK implementations that generate commitments off-chain:

```
blinding = OsRng(64 bytes) % BN254_R    → 32-byte LE field element
commitment = Poseidon(
    Fr(salary),
    Fr(blinding)
)                                       → 32-byte LE field element
```

- **Blinding factor**: 64 bytes from CSPRNG, reduced modulo BN254 scalar field prime.
- **Field encoding**: Little-endian canonical representation (arkworks convention).
- **Hash**: Width-3 Poseidon sponge, circomlib-compatible parameters.
- **Output**: 32 bytes little-endian.

## Appendix B: Cross-Contract Call Graph

```
Payroll.batch_process_payroll()
  ├── SalaryCommitment.get_commitment(employee)      → commitment_bytes
  ├── ProofVerifier.verify_payment_proof(proof, inputs) → bool
  ├── SalaryCommitment.record_nullifier(nullifier)    → void
  └── Token.transfer(treasury, employee, amount)      → void

PaymentExecutor.execute_payment()
  ├── PayrollRegistry.get_company(company_id)          → CompanyInfo
  ├── SalaryCommitment.get_commitment(employee)        → SalaryCommitment
  ├── ProofVerifier.verify(proof, inputs)              → bool
  └── Token.transfer(treasury, employee, amount)       → void
```
