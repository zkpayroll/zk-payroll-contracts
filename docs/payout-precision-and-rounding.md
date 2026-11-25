# Payout Amount Precision and Rounding (#1085)

Payroll amounts are signed `i128` integer base units. Two mistakes can change
how much an employee receives without any obvious failure:

1. **Aggregation drift** — a batch total accumulated with unchecked addition
   can wrap, so an understated `expected_total_spend` appears to match the
   submitted amounts.
2. **Rounding drift** — a payout derived from a pro-rata share
   (`gross * numerator / denominator`) truncates on integer division. Without
   an explicit rounding mode and tolerance, the loss is invisible to callers.

## Execution-path guard

`prepare_payroll_run`, `batch_process_payroll`, `batch_process_with_expiry`,
and `batch_process_payroll_bounded` now aggregate amounts through
`payout_precision::require_precise_batch_total`. Every amount must be strictly
positive, the running total must be representable as `i128`, and the total must
equal the authorised spend. Failures are static panic messages: they never
include amounts, employee addresses, or salary data.

`dry_run_batch_process_payroll` reports an unrepresentable total as the stable
reason code `PayoutTotalOverflow` (24) alongside its other blockers.

## Pro-rata rounding preflight

`check_payout_precision(gross, numerator, denominator, decimals, tolerance_bps,
rounding_mode)` is read-only. It:

- rejects non-positive gross amounts, invalid shares (negative numerator, zero
  denominator, or numerator above denominator), tolerances above 10,000 bps,
  and precisions above 18 decimals;
- computes `gross * numerator` and each rounding step with checked arithmetic;
- applies `Floor` (truncate) or `HalfUp` (nearest, ties up) explicitly;
- reports `rounding_delta = rounded_amount * denominator - gross * numerator`
  and the absolute drift in basis points, so callers can reconcile the exact
  share:
  `rounded_amount * denominator - rounding_delta == gross * numerator`;
- rejects drift above `tolerance_bps`.

`validate_payout_batch(amounts, expected_total_spend)` is a read-only batch
preflight. It confirms positivity, exact summation, and agreement with the
authorised spend without writing state or moving funds.

## Privacy

`PayoutPrecisionError` codes carry no values. The `payout_precision_validated`
event contains only `(run_id, pinned_decimals, timestamp)` — no payout amounts,
salaries, employees, or proof material.

## Error codes

| Code | Meaning |
|------|---------|
| 8700 | `NonPositiveAmount` — gross or payout amount is zero or negative. |
| 8701 | `InvalidDecimals` — precision is above 18 decimals. |
| 8702 | `InvalidShare` — malformed pro-rata numerator/denominator. |
| 8703 | `InvalidTolerance` — tolerance is above 100% (10,000 bps). |
| 8704 | `ArithmeticOverflow` — scaling, rounding, or aggregation is unrepresentable. |
| 8705 | `RoundingDriftExceedsTolerance` — rounding loss exceeds the configured limit. |
| 8706 | `ExpectedSpendMismatch` — checked batch total differs from the authorised spend. |
