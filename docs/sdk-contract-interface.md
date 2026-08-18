# SDK Contract Interface Guide

High-level reference for SDK consumers covering the four core payroll flows:
company setup, employee onboarding, payroll execution, and audit access.

> **For the complete entrypoint-by-entrypoint reference**, see
> [SDK Interface Spec](sdk-interface-spec.md).
> For payload serialization details, see [Payload Examples](payload-examples.md).
> For terminology, see [Glossary](glossary.md).

---

## Table of Contents

1. [Flow 1: Company Setup](#flow-1-company-setup)
2. [Flow 2: Employee Onboarding](#flow-2-employee-onboarding)
3. [Flow 3: Payroll Execution](#flow-3-payroll-execution)
4. [Flow 4: Audit Access](#flow-4-audit-access)
5. [Supporting Flows](#supporting-flows)
6. [Cross-Contract Call Graph](#cross-contract-call-graph)

---

## Flow 1: Company Setup

Register a company and configure its treasury so payroll can be funded.

### Contracts involved

| Contract | Role |
|----------|------|
| `payroll_registry` | Stores company metadata (admin, treasury) |
| `payroll` | High-level batch facade; holds deposited tokens |

### Step 1 — Register the company

**Entrypoint:** `PayrollRegistry::register_company`

| Input | Type | Description |
|-------|------|-------------|
| `admin` | `Address` | Company admin (must sign the transaction) |
| `treasury` | `Address` | Address that holds payroll funds (SEP-41 token) |
| **Returns** | `u64` | Auto-assigned company ID |

**Sample payload:**

```json
{
  "admin": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "treasury": "GBC3H...TREASURY_ADDRESS..."
}
```

### Step 2 — Initialize the payroll facade

**Entrypoint:** `Payroll::initialize`

Links the payroll facade to the deployed contracts.

| Input | Type | Description |
|-------|------|-------------|
| `admin` | `Address` | Payroll admin (typically same as company admin) |
| `token` | `Address` | SEP-41 token contract address |
| `verifier` | `Address` | `proof_verifier` contract address |
| `commitment` | `Address` | `salary_commitment` contract address |
| `treasury` | `Address` | Treasury contract address holding funds |
| `treasury_owner` | `Address` | Authorized treasury owner |

**Sample payload:**

```json
{
  "admin": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "token": "CAS3...TOKEN_ADDRESS...",
  "verifier": "CAZX...VERIFIER_ADDRESS...",
  "commitment": "CALM...COMMITMENT_ADDRESS...",
  "treasury": "GBCT...TREASURY_ADDRESS...",
  "treasury_owner": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S..."
}
```

### Step 3 — Deposit funds into treasury

**Entrypoint:** `Payroll::deposit`

| Input | Type | Description |
|-------|------|-------------|
| `from` | `Address` | Token holder (must sign) |
| `amount` | `i128` | Deposit amount (must be positive) |

**Sample payload:**

```json
{
  "from": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "amount": 1000000
}
```

**Events emitted:** `Deposit` (topics: `admin`, `amount`)

### Step 4 (optional) — Set a pause manager

**Entrypoint:** `Payroll::set_pause_manager`

| Input | Type | Description |
|-------|------|-------------|
| `pause_manager` | `Address` | Contract or address authorized to pause/unpause payroll |

---

## Flow 2: Employee Onboarding

Register an employee with a private salary commitment.

### Contracts involved

| Contract | Role |
|----------|------|
| `payroll_registry` | Stores employee record and commitment reference |
| `salary_commitment` | Stores the on-chain ZK commitment (`Poseidon(salary, blinding)`) |

### Prerequisites

- A company is registered (see Flow 1).
- The `salary_commitment` contract is initialized with `init_commitment_admin`.
- The SDK has generated a commitment off-chain: `commitment = Poseidon(salary, blinding_factor)`.

### Step 1 — Store the commitment on-chain

**Entrypoint:** `SalaryCommitmentContract::store_commitment`

| Input | Type | Description |
|-------|------|-------------|
| `employee` | `Address` | Employee Ed25519 public key |
| `commitment` | `BytesN<32>` | Poseidon hash commitment |
| **Returns** | `SalaryCommitment` | Created commitment record |

**Sample payload:**

```json
{
  "employee": "GA2C5QQZAOWTJJFFAQ44XQR5A2RIV5C2P4XQ...",
  "commitment": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}
```

### Step 2 — Register the employee in the payroll registry

**Entrypoint:** `PayrollRegistry::add_employee`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID from registration |
| `employee` | `Address` | Employee address (must match Step 1) |
| `commitment` | `BytesN<32>` | Same commitment hash stored in Step 1 |

**Sample payload:**

```json
{
  "company_id": 0,
  "employee": "GA2C5QQZAOWTJJFFAQ44XQR5A2RIV5C2P4XQ...",
  "commitment": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}
```

### Step 3 — Activate the employee

**Entrypoint:** `PayrollRegistry::set_employee_status`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID |
| `employee` | `Address` | Employee address |
| `status` | `EmployeeStatus` | Set to `Active` |

**Employee statuses:**

| Value | Meaning |
|-------|---------|
| `Active` (0) | Eligible for payroll payments |
| `Inactive` (1) | Temporarily ineligible |
| `Incomplete` (2) | Default; onboarding not finished |

### Updating commitments

When salary changes, use one of:

| Entrypoint | When to use |
|------------|-------------|
| `SalaryCommitmentContract::update_commitment` | Routine salary change; archives old version |
| `SalaryCommitmentContract::rotate_commitment` | Security rotation; marks old commitment as revoked |
| `PayrollRegistry::update_commitment` | Convenience wrapper that updates both registry and commitment contracts |

---

## Flow 3: Payroll Execution

Process payments for employees in a payroll run.

### Contracts involved

| Contract | Role |
|----------|------|
| `payroll` | High-level batch facade (recommended for SDK consumers) |
| `payment_executor` | Low-level single/batch payment execution |
| `proof_verifier` | Verifies Groth16 proofs |
| `salary_commitment` | Records nullifiers to prevent double-spend |

### Two execution paths

| Path | Contract | Best for |
|------|----------|----------|
| **Batch** (recommended) | `Payroll` | Multi-employee runs in a single transaction |
| **Single** | `PaymentExecutor` | One-off payments or custom orchestration |

### Path A — Batch execution via Payroll facade

#### Step 1 (optional) — Create and finalize a run draft

Drafts let you correct totals before committing on-chain.

| Entrypoint | Description |
|------------|-------------|
| `Payroll::create_run_draft` | Create a `Pending` draft with expected totals |
| `Payroll::amend_run_draft` | Correct amounts/employee count before finalizing |
| `Payroll::finalize_run_draft` | Lock the draft (immutable) |

**Sample: `create_run_draft`**

```json
{
  "admin": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "total_amount": 11500,
  "employee_count": 2,
  "period_label": "2025-W03"
}
```

**Returns:** `draft_id` (`u64`)

#### Step 2 — Execute the batch

**Entrypoint:** `Payroll::batch_process_payroll`

| Input | Type | Description |
|-------|------|-------------|
| `proofs` | `Vec<BytesN<256>>` | Packed Groth16 proofs (one per employee) |
| `amounts` | `Vec<i128>` | Payment amounts (private; for total validation) |
| `employees` | `Vec<Address>` | Employee addresses |
| `expected_total_spend` | `i128` | Sum of amounts; must match actual treasury outflow |
| `nonce` | `BytesN<32>` | Unique nonce for this run (prevents replay) |
| `draft_hash` | `Option<BytesN<32>>` | Optional pre-committed draft hash |
| **Returns** | `u64` | Run ID for tracking |

**Sample payload:**

```json
{
  "proofs": ["0x...", "..."],
  "amounts": [5000, 6500],
  "employees": [
    "GA2C5QQZAOWTJJFFAQ44XQR5A2RIV5C2P4XQ...",
    "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S..."
  ],
  "expected_total_spend": 11500,
  "nonce": "0xdeadbeef00000000000000000000000000000000000000000000000000000000",
  "draft_hash": null
}
```

**What happens on-chain:**

1. Nonce uniqueness is checked (replay protection).
2. If `draft_hash` is provided, it must match a pre-committed draft.
3. For each employee, the proof is verified against the stored commitment.
4. Nullifiers are recorded in `salary_commitment` (prevents double-spend).
5. Tokens are transferred from treasury to each employee.
6. A run ID is returned.

#### Step 3 — Record reconciliation status

**Entrypoint:** `Payroll::update_reconciliation_status`

| Input | Type | Description |
|-------|------|-------------|
| `admin` | `Address` | Company admin |
| `run_id` | `u64` | Completed run ID |
| `status` | `ReconciliationStatus` | `Reconciled`, `Unreconciled`, or `Failed` |

### Path B — Single payment via PaymentExecutor

#### Step 1 — Create a payroll period

**Entrypoint:** `PaymentExecutor::create_period`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID |
| **Returns** | `PayrollPeriod` | Period record with sequential `period_id` |

Only one open period per company at a time.

#### Step 2 — Execute payment

**Entrypoint:** `PaymentExecutor::execute_payment`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID |
| `employee` | `Address` | Employee address |
| `amount` | `i128` | Payment amount |
| `proof_a` | `BytesN<64>` | Groth16 proof component A |
| `proof_b` | `BytesN<128>` | Groth16 proof component B |
| `proof_c` | `BytesN<64>` | Groth16 proof component C |
| `nullifier` | `BytesN<32>` | Unique nullifier for this proof |
| `period` | `u32` | Period ID |
| **Returns** | `PaymentRecord` | Payment record |

**Sample payload:**

```json
{
  "company_id": 0,
  "employee": "GA2C5QQZAOWTJJFFAQ44XQR5A2RIV5C2P4XQ...",
  "amount": 5000,
  "proof_a": "0x...",
  "proof_b": "0x...",
  "proof_c": "0x...",
  "nullifier": "0x...",
  "period": 1
}
```

**Safety checks enforced:**

| Check | Error |
|-------|-------|
| System not paused | Panics if pause manager reports paused |
| Period exists and is open | `PeriodNotFound` / `PeriodClosed` |
| Proof not expired (max 7 days) | `ProofExpired` |
| Nullifier not previously used | `ProofAlreadyUsed` |
| No duplicate payment for this period | `AlreadyPaid` |
| Proof verified by `proof_verifier` | Panics on invalid proof |

#### Step 3 — Close the period

**Entrypoint:** `PaymentExecutor::close_period`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID |
| `period_id` | `u32` | Period to close |

No further payments are allowed in a closed period.

### Batch variant (PaymentExecutor)

**Entrypoint:** `PaymentExecutor::execute_batch_payroll`

Same as `execute_payment` but accepts arrays. All arrays must have equal length.

```json
{
  "company_id": 0,
  "employees": ["GA2C5...", "GB7TA..."],
  "amounts": [5000, 6500],
  "proofs_a": ["0x...", "0x..."],
  "proofs_b": ["0x...", "0x..."],
  "proofs_c": ["0x...", "0x..."],
  "nullifiers": ["0x...", "0x..."],
  "period": 1
}
```

---

## Flow 4: Audit Access

Grant an auditor time-bounded access to verify salary commitments.

### Contract involved

| Contract | Role |
|----------|------|
| `audit_module` | Manages view keys, commitment verification, and audit logs |

### Step 1 — Grant a view key

**Entrypoint:** `AuditModule::generate_view_key`

| Input | Type | Description |
|-------|------|-------------|
| `auditor` | `Address` | Auditor's public key |
| `expiration_ledger` | `u32` | Ledger sequence at which access expires |
| **Returns** | `BytesN<32>` | The view key |

**Sample payload:**

```json
{
  "auditor": "GCNP...AUDITOR_ADDRESS...",
  "expiration_ledger": 500000
}
```

### Step 2 — Auditor verifies a commitment

Two entrypoints are available depending on whether the auditor supplies the key explicitly:

| Entrypoint | Description |
|------------|-------------|
| `AuditModule::verify_commitment_with_key` | Key derived internally from stored record |
| `AuditModule::verify_commitment_with_view_key` | Auditor supplies the key explicitly |

**`verify_commitment_with_key` inputs:**

| Input | Type | Description |
|-------|------|-------------|
| `auditor` | `Address` | Auditor address |
| `stored_commitment` | `BytesN<32>` | The commitment to verify |
| `claimed_amount` | `i128` | Claimed salary amount |
| `blinding_factor` | `BytesN<32>` | Blinding factor used in commitment |
| `scope` | `AuditScope` | `FullCompany`, `TimeRange`, `EmployeeList`, or `AggregateOnly` |
| **Returns** | `Result<bool, AuditError>` | `Ok(true)` if commitment matches |

**Sample payload:**

```json
{
  "auditor": "GCNP...AUDITOR_ADDRESS...",
  "stored_commitment": "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "claimed_amount": 5000,
  "blinding_factor": "0x...",
  "scope": "FullCompany"
}
```

**Audit scopes:**

| Value | Meaning |
|-------|---------|
| `FullCompany` (0) | Full company audit |
| `TimeRange` (1) | Audit within a specific time window |
| `EmployeeList` (2) | Audit specific employees |
| `AggregateOnly` (3) | Aggregated stats only (no per-commitment verification) |

### Step 3 — Generate an aggregate report

**Entrypoint:** `AuditModule::generate_aggregate_report`

| Input | Type | Description |
|-------|------|-------------|
| `auditor` | `Address` | Auditor address (must have valid key) |
| `company_id` | `Symbol` | Company identifier |
| `period_start` | `u64` | Period start timestamp |
| `period_end` | `u64` | Period end timestamp |
| **Returns** | `AuditReport` | Aggregate report |

**Returns:**

```json
{
  "company_id": "my_company",
  "total_employees": 0,
  "total_paid": 0,
  "period_start": 1700000000,
  "period_end": 1700086400,
  "verified": true
}
```

> Note: `total_employees` and `total_paid` are currently stubbed to `0`.
> Implementations should query `PaymentExecutor` for real aggregates.

### Step 4 — Export a compliance summary

**Entrypoint:** `AuditModule::export_audit_summary`

| Input | Type | Description |
|-------|------|-------------|
| `auditor` | `Address` | Auditor address |
| `company_id` | `Symbol` | Company identifier |
| `period_start` | `u64` | Period start |
| `period_end` | `u64` | Period end |
| **Returns** | `AuditMetadataSummary` | Compliance-ready summary |

**Returns:**

```json
{
  "company_id": "my_company",
  "period_start": 1700000000,
  "period_end": 1700086400,
  "total_audit_entries": 5,
  "verification_pass_count": 4,
  "verification_fail_count": 1,
  "exported_at": 1700090000,
  "exported_by": "GCNP...AUDITOR_ADDRESS..."
}
```

This never includes salary values — only counts and pass/fail status.

### Step 5 (optional) — Revoke access

**Entrypoint:** `AuditModule::revoke_view_key`

| Input | Type | Description |
|-------|------|-------------|
| `admin` | `Address` | Admin who originally granted the key |
| `auditor` | `Address` | Auditor to revoke |

### Querying audit logs

| Entrypoint | Description |
|------------|-------------|
| `AuditModule::query_by_company` | All entries for a company |
| `AuditModule::query_by_employee` | Entries for a specific employee |
| `AuditModule::query_by_period` | Entries within a time range |
| `AuditModule::get_audit_log_count` | Total entry count for a company |

---

## Supporting Flows

### Admin rotation (two-step)

Both `PayrollRegistry` and `Payroll` support admin rotation via a propose/accept pattern:

| Step | PayrollRegistry | Payroll |
|------|----------------|---------|
| Propose | `propose_admin_rotation(company_id, current_admin, new_admin)` | `propose_admin_rotation(current_admin, new_admin)` |
| Accept | `accept_admin_rotation(company_id, new_admin)` | `accept_admin_rotation(new_admin)` |
| Cancel | `cancel_admin_rotation(company_id, current_admin)` | `cancel_admin_rotation(current_admin)` |

### Treasury owner rotation (two-step)

| Step | Payroll |
|------|---------|
| Propose | `propose_treasury_rotation(current_owner, new_owner)` |
| Accept | `accept_treasury_rotation(new_owner)` |
| Cancel | `cancel_treasury_rotation(current_owner)` |

### Emergency withdrawal (two-step, admin + treasury owner)

| Step | Entrypoint | Description |
|------|------------|-------------|
| 1 | `Payroll::request_emergency_withdrawal` | Treasury owner requests withdrawal |
| 2 | `Payroll::approve_emergency_withdrawal` | Admin approves and executes |
| Cancel | `Payroll::cancel_emergency_withdrawal` | Either party cancels |

### Commitment utilities

| Entrypoint | Description |
|------------|-------------|
| `SalaryCommitmentContract::compute_commitment` | Compute `SHA-256(salary, blinding_factor)` off-chain |
| `SalaryCommitmentContract::verify_commitment` | Verify a claimed salary against stored commitment |
| `SalaryCommitmentContract::is_commitment_active` | Check if commitment is valid (not revoked) |
| `SalaryCommitmentContract::has_commitment` | Check if employee has any commitment |

---

## Cross-Contract Call Graph

For SDK consumers, the primary call paths are:

```
SDK
├── PayrollRegistry::register_company
├── PayrollRegistry::add_employee
├── PayrollRegistry::set_employee_status
├── SalaryCommitmentContract::store_commitment
│
├── Payroll::batch_process_payroll          (recommended)
│   ├── ProofVerifier::verify_payment_proof   (per employee)
│   ├── SalaryCommitmentContract::record_nullifier (per employee)
│   └── Token::transfer                        (per employee)
│
├── PaymentExecutor::execute_payment       (single payment)
│   ├── ProofVerifier::verify
│   ├── SalaryCommitmentContract::record_nullifier
│   └── Token::transfer
│
└── AuditModule::generate_view_key
    ├── AuditModule::verify_commitment_with_key
    ├── AuditModule::generate_aggregate_report
    └── AuditModule::export_audit_summary
```

---

## Further Reference

| Document | Contents |
|----------|----------|
| [SDK Interface Spec](sdk-interface-spec.md) | Complete entrypoint signatures, data structures, serialization rules, events, and error codes |
| [Payload Examples](payload-examples.md) | Concrete JSON payload and event shapes |
| [Glossary](glossary.md) | Definitions of all domain terms |
| [Events](events.md) | Event schema reference |
| [Deployment Guide](deployment.md) | Step-by-step contract deployment |
