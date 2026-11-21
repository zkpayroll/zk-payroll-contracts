# Payout Batch Retry Invariants

This document specifies the invariants that govern payout batch retry behavior in the payment_executor contract. These invariants ensure that retries are safe, idempotent, and recover gracefully from failures.

## Overview

Payout batch retries in the payment_executor are governed by three core mechanisms:

1. **Settlement Receipt Mechanism** (`execute_batch_with_receipt`): Provides idempotency for the entire batch via a globally-unique receipt ID.
2. **Per-Employee Nullifier Mechanism**: Prevents double-payment within and across periods via zero-knowledge proof nullifiers.
3. **Per-Employee AlreadyPaid Flag**: Prevents duplicate payment attempts within a single period.

## Core Invariants

### R-1: Settlement Receipt Idempotency

**Statement:** A settlement receipt ID is consumed at most once across the entire contract lifetime. Any `execute_batch_with_receipt` call with an already-consumed receipt ID is rejected with `SettlementReceiptAlreadyUsed` without modifying contract state.

**Mechanism:**
- Receipt presence is checked **before** any state mutation.
- The receipt is recorded **only after** the entire batch succeeds.
- If any payment in the batch fails, the receipt remains unconsumed, allowing the caller to retry with corrected data.

**Privacy:** Receipt IDs are opaque 32-byte identifiers stored on-chain but never emitted in events or exposed in error messages. No employee addresses or salary amounts are associated with receipt records.

**Use Case:** Callers use receipt IDs as idempotency keys for retry safety across RPC network failures, timeouts, and replays.

---

### R-2: Nullifier Global Uniqueness

**Statement:** Each zero-knowledge proof nullifier is consumed at most once globally. Any payment attempt with a nullifier that has already been used is rejected with `ProofAlreadyUsed`.

**Scope:** Nullifiers are global across:
- All employees
- All companies  
- All periods

**Consequence:** Cross-period replays of the same proof are prevented. If a nullifier was used in period 1, submitting it again in period 2 will fail.

**Retry Pattern:** Retries must use fresh proofs with new nullifiers, not replay the same proof.

---

### R-3: Per-Employee Per-Period Uniqueness

**Statement:** Each (employee, period) pair can receive at most one successful payment. Any attempt to pay the same employee twice in the same period is rejected with `AlreadyPaid`.

**Key Point:** This invariant is **independent** of the nullifier. Even with a fresh nullifier and fresh proof, paying the same employee a second time in the same period fails.

**Consequence:**
- `is_paid(employee, period)` transitions from `false` → `true` exactly once per period.
- If a first payment succeeds, subsequent payment attempts (regardless of proof) fail.
- If a first payment fails, the `is_paid` flag is not set, and a retry is allowed.

**Retry Pattern:** If a payment for (emp, period) fails before the `is_paid` flag is set, retry with a fresh proof. If the flag is already set, either:
1. Confirm the original payment succeeded (query `get_payment(emp, period)`)
2. Or wait for a new period and pay the employee there.

---

### R-4: Batch-Level Atomicity Boundary

**Statement:** Batch payment is **not atomic**. If employee *k* in a batch of *n* employees fails:
- Employees 1 to *k-1* are permanently paid.
- Employees *k* to *n* are not processed.
- The batch can be retried for the remaining employees in the same or a new period (subject to R-3).

**Consequence:** Callers must handle partial batch failures by:
1. Querying which employees were paid (via `get_payment` or `is_paid`).
2. Retrying only the unpaid employees.

**Note on Idempotency:** When using `execute_batch_with_receipt`:
- If the batch partially fails, the receipt is left unconsumed.
- The caller can retry the entire batch with the same receipt (successful payments will fail with `AlreadyPaid`, unpaid employees will be retried).
- Alternatively, submit a corrected batch with only the unpaid employees and a fresh receipt.

---

### R-5: Closed Period Barrier

**Statement:** A payment to a closed period is rejected with `PeriodClosed`, regardless of employee or proof state. The total paid and all previously-recorded payment records remain unchanged.

**Consequence:**
- Once a period is closed, no payments can be added.
- Callers must open a new period to retry.

---

### R-6: Batch Array Length Pre-Validation

**Statement:** If the batch arrays (employees, amounts, proofs_a, proofs_b, proofs_c, nullifiers) have mismatched lengths, the function returns `ArrayLengthMismatch` **before any state is mutated**.

**Consequence:** A failed array-length check does not consume receipts or nullifiers, allowing the caller to retry with corrected arrays.

---

### R-7: Total Paid Monotonicity on Retry

**Statement:** `get_total_paid(company_id)` is monotonically non-decreasing. A failed payment attempt (including retries that fail) does not decrease the total.

**Consequence:**
- Retrying a failed payment cannot reduce the company's reported total.
- If a retry succeeds, the total increases by the payment amount.
- If a retry fails (e.g., with `AlreadyPaid` or `ProofAlreadyUsed`), the total is unchanged.

---

## Retry Patterns

### Pattern 1: Network Retry with Receipt (Recommended)

Use `execute_batch_with_receipt` with a unique receipt ID that the caller generates and stores durably.

```
Retry Attempt N:
  → Call execute_batch_with_receipt(company, employees, amounts, proofs, ..., receipt_id)
  
  Case A: Success
    ✓ Receipt is consumed; batch fully processed
    
  Case B: Partial failure at employee k (e.g., insufficient balance)
    ✗ Receipt remains unconsumed
    → Inspect which employees were paid (query is_paid for each)
    → Either:
       i.  Retry with corrected data (e.g., lower amounts) and same receipt_id
       ii. Retry with only unpaid employees and fresh receipt_id
    
  Case C: Full failure (e.g., array length mismatch, batch too large)
    ✗ Receipt remains unconsumed
    ✗ No state changed
    → Fix the issue and retry with same receipt_id
    
  Case D: RPC timeout / no response
    → Caller retries with same receipt_id
    → If receipt was already consumed on chain, retry rejected with SettlementReceiptAlreadyUsed
    → Query is_settlement_receipt_used(receipt_id) to confirm
```

### Pattern 2: Cross-Period Retry

If a payment attempt fails within a period and retry fails again:

```
Period 1:
  → execute_payment(emp, amount, proof_a, proof_b, proof_c, nullifier)
  → Fails with ProofAlreadyUsed or insufficient balance

Period 2 (after closing period 1):
  → create_period(company_id)
  → execute_payment(emp, amount, proof_b, proof_b_new, proof_c_new, nullifier_new)
  → Succeeds (fresh period, fresh proof, new nullifier)
```

### Pattern 3: Individual Payment Retry vs. Batch Retry

- **Individual Payment Retry:** If `execute_payment` fails, retry with a fresh proof (new nullifier).
- **Batch Retry:** If `execute_batch_payroll` partially fails at index k, query `is_paid` for each employee to identify unpaid ones, then retry only those.

---

## Failure Modes and Recovery

| Failure | Error Code | Retry Strategy |
|---------|-----------|-----------------|
| Same nullifier reused | `ProofAlreadyUsed` | Use a fresh proof with a new nullifier |
| Same employee in same period | `AlreadyPaid` | Move to a new period and pay with a fresh proof |
| Batch too large | `BatchTooLarge` | Reduce batch size or split across calls |
| Array length mismatch | `ArrayLengthMismatch` | Fix array lengths; no state was mutated |
| Period is closed | `PeriodClosed` | Open a new period |
| Receipt already used | `SettlementReceiptAlreadyUsed` | Query `is_settlement_receipt_used` to confirm success; no retry needed |
| Insufficient balance | (payment fails) | Ensure treasury has sufficient balance; retry with fresh proof |

---

## Privacy Considerations

- Receipt IDs are **never** emitted in events.
- Error messages do **not** expose employee addresses, salaries, or company IDs.
- All retry state (receipts, nullifiers, payment flags) is stored on-chain but isolated from public event streams.

This preserves privacy for employees and salary information throughout all retry scenarios.

---

## Testing Strategy

Retry invariants are tested across three test suites:

1. **invariant_tests.rs** (I-9): AlreadyPaid retry does not alter running total.
2. **recovery_tests.rs** (test_partial_batch_failure_*): Partial batch failures and per-employee retry.
3. **security_tests.rs** (test_retry_*): Cross-period retries, idempotency, and nullifier replay prevention.

Each invariant is exercised with success, failure, and boundary cases to confirm contract behavior is predictable and safe.

---

## References

- Issue #551: Settlement receipt mechanism for idempotent batch payroll execution
- Issue #136: Retry safety and nullifier uniqueness across periods
- Issue #510: Batch size limits and error handling
