# Settlement Receipt Replay Protection

This document defines the invariants for settlement receipt replay handling in
`contracts/payment_executor` (`execute_batch_with_receipt`,
`is_settlement_receipt_used`, `DataKey::SettlementReceipt`).

## Purpose

Settlement receipts provide an idempotency handle for batch payroll settlement so
clients can safely retry after RPC/network uncertainty without duplicating
payouts.

## Invariants

1. **Global uniqueness**
   - A `receipt_id` (`BytesN<32>`) is single-use across the entire contract.
   - Uniqueness is not scoped to company, period, employee set, or amount.
   - Any reuse returns `PaymentError::SettlementReceiptAlreadyUsed (17)`.

2. **Check-before-effects**
   - The duplicate-receipt guard runs before any payment side effects.
   - A rejected replay attempt must not mutate balances, payment records,
     period counters, totals, or other receipt markers.

3. **Commit-on-success only**
   - The receipt marker is persisted only after the batch completes
     successfully.
   - If the batch fails (validation error, funding failure, proof/nullifier
     rejection, etc.), the receipt remains unused so a corrected retry with the
     same `receipt_id` is allowed.

4. **Composable with other replay guards**
   - Receipt replay protection is independent of proof-nullifier replay checks
     and per-employee-per-period payment checks.
   - A request must satisfy all applicable guards to succeed.

5. **Privacy-preserving failures**
   - Receipt IDs are treated as opaque identifiers and are never emitted in
     events.
   - Error paths must not leak salary amounts, employee identities, or other
     sensitive payroll data.

## Operational guidance

- Reuse the same `receipt_id` only when retrying the *same intended settlement*
  after an uncertain or failed attempt.
- Use a new `receipt_id` for any genuinely new settlement.
- On `SettlementReceiptAlreadyUsed`, treat the prior attempt as already
  processed and reconcile using existing payment/period state rather than
  resubmitting.
