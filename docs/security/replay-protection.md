# Payroll Execution Idempotency & Replay Protection

## Overview

The ZK Payroll system implements multi-layered protection against duplicate
payroll execution and replay attacks. This document describes each layer,
how they interact, and what integrators (SDK, dashboard, automation scripts)
need to know for safe retry behaviour.

---

## Protection Layers

| Layer | Scope | Mechanism | Error Signal |
|-------|-------|-----------|-------------|
| **Per-proof nullifier** | `payment_executor` single payment | Nullifier key prevents same proof being used twice | `PaymentError::ProofAlreadyUsed` |
| **Per-employee period guard** | `payment_executor` single payment | `Payment(employee, period)` key prevents double-payment in same period | `PaymentError::AlreadyPaid` |
| **Batch-level nonce** | `payroll.batch_process_payroll` | Caller-supplied 32-byte nonce consumed on first use | `"Duplicate run nonce"` panic |
| **Payload fingerprint** | `payroll.batch_process_payroll` | SHA-256 fingerprint of full batch payload stored alongside nonce | `"Conflicting replay"` panic |
| **Batch execution identity** | `payment_executor.execute_batch_payroll` | SHA-256 fingerprint of batch parameters checked before execution | `PaymentError::ExecutionAlreadyCompleted` |

---

## Canonical Execution Identity

Each payroll execution is identified by a **canonical execution identity**
composed of:

| Field | Source | Purpose |
|-------|--------|---------|
| `company_id` | Caller parameter | Scopes identity to a single company |
| `nonce` | Caller-supplied 32-byte value | Uniqueness token (must be unique per contract lifetime) |
| `batch_fingerprint` | Computed on-chain SHA-256 | Encodes the full batch payload (employees, amounts, proofs) |
| `expected_total_spend` | Caller parameter | Validates batch amount integrity |
| `period` (payment_executor) | Caller parameter | Scopes to a specific payroll period |

### Fingerprint Computation

The batch fingerprint is a **SHA-256 hash** of:

```
SHA-256(
    expected_total_spend (16 bytes BE)  +
    for each employee i:
      employee_address (32 bytes XDR)  +
      amount (16 bytes BE)            +
      proof_hash (first 32 bytes)
)
```

> **Determinism guarantee**: Two batches with identical parameters always
> produce the same fingerprint. Any change to employees, amounts, proofs,
> or total spend produces a different fingerprint.

---

## Safe Retry vs. Malicious Replay

The system distinguishes three scenarios when a nonce is resubmitted:

| Scenario | Nonce state | Fingerprint match | Behaviour |
|----------|-------------|-------------------|-----------|
| **Safe retry** | Already consumed | ✅ Matches | Return existing `run_id` (no re-execution) |
| **Conflicting replay** | Already consumed | ❌ Differs | Panic: `"Conflicting replay detected"` |
| **Fresh submission** | Not consumed | N/A | Execute normally |

### Safe Retry Flow

```
Client                                Contract
  │                                       │
  ├── batch_process_payroll(nonce=X) ────► Execute, store fingerprint
  │                                       │
  │  (network timeout, tx succeeded)      │
  │                                       │
  ├── batch_process_payroll(nonce=X) ────► Fingerprint matches →
  │   (same payload)                       Return existing run_id
  │                                       │
```

### Conflicting Replay Detection

```
Client                                Contract
  │                                       │
  ├── batch_process_payroll(nonce=X) ────► Execute, store fingerprint
  │   (employees: [Alice], amount: 5000)  │
  │                                       │
  ├── batch_process_payroll(nonce=X) ────► Fingerprint differs →
  │   (employees: [Bob], amount: 3000)     PANIC: "Conflicting replay"
  │                                       │
```

---

## What Integrators Must Do

### Choosing a Nonce

- The nonce **MUST be unique per contract instance** (not just per company).
- Generate it as: `SHA-256(company_id ‖ payroll_period ‖ client_timestamp ‖ random_entropy)`.
- Never reuse a nonce across different payroll batches.
- Store the nonce + payload hash locally so you can safely retry.

### Handling Errors

| Error / Panic Message | Cause | Recovery |
|-----------------------|-------|----------|
| `"Conflicting replay detected"` | Same nonce, different payload | **Do NOT retry** — investigate off-chain |
| Idempotent retry | Same nonce, same payload | Returns existing `run_id` — treat as success |
| `ProofAlreadyUsed` / `AlreadyPaid` | Individual payment replay detected | Generate fresh proofs for new runs |
| `"Amount must be positive"` | Invalid amount | Fix input data |
| `"Array length mismatch"` | Mismatched arrays | Fix input data |

### Retry Strategy

1. **Before retrying**, check if the nonce has been consumed (read `RunNonce`).
2. If consumed, verify the stored fingerprint matches your payload:
   - ✅ If match → idempotent success, no action needed.
   - ❌ If mismatch → **do NOT retry**, investigate.
3. If nonce is **not** consumed, retry with the **exact same payload**.
4. Use exponential backoff (start with 1s, max 30s).

---

## Cross-Company Collision Safety

The execution identity is implicitly scoped per-company through:

- **Company-specific nonce selection**: Client generates nonces that include
  `company_id` in the hash entropy.
- **Contract isolation**: Each payroll contract instance serves one treasury
  and admin.
- **Period isolation**: `payment_executor` periods are scoped per `company_id`.

A nonce collision across companies is prevented because:
- The nonce is stored keyed to `RunNonce(BytesN<32>)` — same 32-byte value
  on different contract instances is independent.
- The batch fingerprint includes `employees` (different addresses across
  companies → different fingerprint).

---

## Storage Key Design

```
DataKey::RunNonce(BytesN<32>)
  → u64 (run_id)
  Used to detect nonce reuse.

DataKey::NonceFingerprint(BytesN<32>)
  → BytesN<32> (SHA-256 batch fingerprint)
  Stored alongside RunNonce for idempotent retry detection.

DataKey::BatchExecution(BytesN<32>)
  → bool (executed = true)
  Tracks batch execution identity in payment_executor.

DataKey::BatchExecutionRecords(BytesN<32>)
  → Vec<PaymentRecord>
  Cached execution results for idempotent returns.
```

---

## Event Signals

| Event | When | Data |
|-------|------|------|
| `BatchExecuted` | Batch execution completed in `payment_executor` | `(fingerprint, period)` |

---

## Testing Checklist

Integrators should verify their client-side retry logic against these scenarios:

- [ ] Retry after confirmed success returns same `run_id` (idempotent).
- [ ] Retry after timeout (tx actually succeeded) returns same `run_id`.
- [ ] Retry with modified payload (different amount) is rejected.
- [ ] Retry with different employees is rejected as conflicting replay.
- [ ] Cross-company nonce collision does not cause issues (separate contract instances).
- [ ] `prepare_payroll_run` followed by retry returns existing `run_id`.
- [ ] Batch execution identity prevents re-execution in `payment_executor`.
