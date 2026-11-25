# Settlement Window

`settlement_window` enforces payroll period timing windows and settlement safety guards.

## Settlement Receipt Ownership and Replay Safety (#882, #1001)

Settlement receipts are opaque `BytesN<32>` identifiers. They are used as idempotency/replay guards for settlement flows that must not be applied twice. Each consumed receipt is bound to one `(company_id, period_id)` pair, and `close_period` requires a receipt with that exact scope.

### Invariants

- **One-time consumption**: a receipt ID can be consumed at most once.
- **Period ownership**: a consumed receipt can close only the company and period to which it was bound.
- **Replay rejection is safe**: replay attempts return `SettlementError::SettlementReceiptReplay` and perform no state mutation.
- **Ownership mismatch is safe**: missing or differently scoped receipts return `SettlementError::SettlementReceiptOwnershipMismatch`; the period remains unchanged.
- **No sensitive data**: receipt storage contains an opaque marker and non-sensitive company/period scope only; no employee addresses, salary amounts, or proof payloads are stored.
- **Admin-gated consumption**: only the configured admin may consume receipts, consistent with other settlement administrative actions.
- **Pause-aware**: receipt consumption respects pause state (`require_not_paused`).

### Public API

- `consume_settlement_receipt(env, company_id: u64, period_id: u32, receipt_id: BytesN<32>) -> Result<(), SettlementError>`
  - First call: marks receipt consumed.
  - Replay: returns `SettlementReceiptReplay`.
- `close_period(env, company_id: u64, period_id: u32, receipt_id: BytesN<32>) -> Result<SettlementPeriod, SettlementError>`
  - Closes only when the consumed receipt is bound to the supplied company and period.
- `is_settlement_receipt_consumed(env, receipt_id: BytesN<32>) -> bool`
  - Read-only replay check.

### Error

- `SettlementReceiptReplay = 12`
  - Meaning: the receipt was already consumed.
  - Caller guidance: treat as already-settled/idempotent replay; do not resubmit settlement side effects for the same receipt.
- `SettlementReceiptOwnershipMismatch = 13`
  - Meaning: the receipt is not consumed for the company and period being closed.
  - Caller guidance: verify the non-sensitive company/period association and consume the correct receipt before retrying.
