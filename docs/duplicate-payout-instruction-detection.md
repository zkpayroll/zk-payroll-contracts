# Duplicate Payout Instruction Detection

The payroll contract now detects and rejects duplicate payout instructions within
a payroll period. A *payout instruction* is an on-chain record directing the
contract to transfer a specific amount to a specific employee within a period.
Without this detection, submitting the same instruction twice — whether through
a client retry, a race between operator sessions, or a crafted replay — could
pay an employee twice for the same period.

## How it works

The contract tracks every `(period_id, instruction_id)` pair seen within a
period. The first submission for a pair succeeds and is recorded; a subsequent
submission of the same pair is rejected before any transfer is attempted. Only
the composite key is persisted — no salary amount, employee identity, or proof
material is retained. Dedup records are written to persistent storage so they
survive ledger eviction windows and cannot be cleared by a contract upgrade.

## Entry points

### `record_payment_instruction(period_id, instruction_id) -> Result<(), PaymentError>`

Records a payout instruction as seen, or rejects it if it was already seen.

- `Ok(())` on first sighting; the pair is recorded in persistent storage.
- `Err(PaymentError::EmployeeAlreadyPaid)` on a duplicate, without modifying
  storage.
- Requires the payroll admin's authorization.

### `is_payment_instruction_duplicate(period_id, instruction_id) -> bool`

Read-only preflight check. Returns `true` if `(period_id, instruction_id)` has
already been recorded, without modifying storage. Intended for dashboards and
SDKs to check before submitting a payout.

## Error reference

| Contract | Code | Variant | Suggested client message |
|----------|------|---------|--------------------------|
| `payroll` | `303` | `EmployeeAlreadyPaid` | "This payout instruction was already processed for this period. Do not resubmit the same instruction." |

## Integration with batch execution

`record_or_reject_duplicate` is invoked inside `batch_process_payroll` and
`batch_process_with_expiry` for every instruction in the batch, keyed by
`(run_id, instruction_index)`. This prevents a payout instruction from being
processed more than once within the same run.

## QA coverage

`contracts/payroll/tests/payment_instruction_dedup.rs`:

| Test | Coverage |
|------|----------|
| `record_payment_instruction_success_path` | success — fresh pair records and is visible as duplicate |
| `record_payment_instruction_duplicate_is_rejected` | failure — same pair rejected on re-submission |
| `same_instruction_id_different_period_is_not_duplicate` | edge — same instruction_id in a different period is accepted |

```bash
cargo test -p payroll --test payment_instruction_dedup
```

## Privacy

Only the composite `(period_id, instruction_id)` key is written to storage.
No salary amounts, employee addresses, commitments, or proof material are
retained or surfaced by this module, keeping error paths and stored state
privacy-safe.
