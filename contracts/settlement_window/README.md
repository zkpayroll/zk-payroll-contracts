# Settlement Window

`settlement_window` enforces payroll period timing windows and settlement safety guards.

## Settlement receipt replay safety (#1001)

Settlement receipts are opaque `BytesN<32>` identifiers. They are used as idempotency/replay guards for settlement flows that must not be applied twice.

### Invariants

- **One-time consumption**: a receipt ID can be consumed at most once.
- **Replay rejection is safe**: replay attempts return `SettlementError::SettlementReceiptReplay` and perform no state mutation.
- **No sensitive data**: receipt storage contains only an opaque receipt marker; no employee addresses, salary amounts, or proof payloads are stored.
- **Admin-gated consumption**: only the configured admin may consume receipts, consistent with other settlement administrative actions.
- **Pause-aware**: receipt consumption respects pause state (`require_not_paused`).

### Public API

- `consume_settlement_receipt(env, receipt_id: BytesN<32>) -> Result<(), SettlementError>`
  - First call: marks receipt consumed.
  - Replay: returns `SettlementReceiptReplay`.
- `is_settlement_receipt_consumed(env, receipt_id: BytesN<32>) -> bool`
  - Read-only replay check.

### Error

- `SettlementReceiptReplay = 12`
  - Meaning: the receipt was already consumed.
  - Caller guidance: treat as already-settled/idempotent replay; do not resubmit settlement side effects for the same receipt.
