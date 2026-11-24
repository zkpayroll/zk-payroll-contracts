# Settlement Receipt Replay Invariants

This document records the replay behavior of `execute_batch_with_receipt` in `contracts/payment_executor/src/lib.rs`. It complements `RETRY_INVARIANTS.md` with a focused statement of the receipt guarantees.

## R1: A receipt is globally single-use

A receipt id is an opaque 32-byte value. The first successful call records it under `DataKey::SettlementReceipt`. Any later call with the same value is rejected with `PaymentError::SettlementReceiptAlreadyUsed`, regardless of company, period, employee set, or amounts. The guard runs before any state mutation.

**Enforcement point:** `execute_batch_with_receipt`.

## R2: Failed calls do not consume a receipt

If a batch fails validation or an individual payment fails, the receipt is not recorded. The same receipt id can be reused for a corrected retry. A successful batch consumes the receipt only after all payment records have been produced.

**Enforcement point:** `execute_batch_with_receipt`, after `execute_batch_payroll` returns successfully.

## R3: Receipt state is observable without exposing data

`is_settlement_receipt_used` returns only a boolean. Receipt ids are never emitted in events, and the rejection error is a stable integer with no salary, employee, or proof data.

**Enforcement point:** `is_settlement_receipt_used`.

## R4: Receipt ids are opaque

All-zero and otherwise arbitrary receipt ids are treated like any other identifier. The contract does not derive meaning from their contents, so callers remain responsible for choosing collision-resistant values.

**Enforcement point:** `execute_batch_with_receipt`.

## Test coverage

- `contracts/payment_executor/tests/settlement_receipt_uniqueness.rs`: first use, duplicate rejection, global uniqueness across companies and periods, failed-batch retry, zero-id opacity, and pre-validation failure.
- `contracts/payment_executor/tests/retry_invariant_tests.rs`: idempotency and partial-failure retry behavior.
