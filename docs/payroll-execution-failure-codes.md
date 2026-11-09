# Payroll Execution Failure Codes

This reference documents every payroll execution failure code in `contracts/shared_errors` (`PaymentError` range `300..=321`) and the corresponding contract-local execution errors in `contracts/payment_executor` (`1..=20`).

## Privacy Guarantee

All failure codes are deterministic `u32` discriminants. Error returns never include employee wallet addresses, Poseidon salary commitments, blinding factors, or individual salary amounts.

## Shared `PaymentError` Taxonomy (`300..=321`)

| Code | Variant | Retryable | Cause | Operator / Integrator Remediation |
|------|---------|-----------|-------|-----------------------------------|
| `300` | `PeriodNotFound` | No | Target payroll period does not exist for the company. | Create the payroll period via `create_period` or verify the `period` ID. |
| `301` | `PeriodClosed` | Yes | Target payroll period is closed and accepts no new disbursements. | Reopen the period with `reopen_period` or create the next sequential period. |
| `302` | `PeriodAlreadyExists` | No | An open payroll period already exists for the company. | Close the active period before opening a new one, or submit against the active period. |
| `303` | `EmployeeAlreadyPaid` | No | Target recipient has already been settled in the specified period. | Skip the already-settled entry when retrying a partially completed batch. |
| `304` | `InvalidPaymentAmount` | No | Payout amount is non-positive or fails asset decimal normalization. | Ensure the amount is non-negative and normalized to the configured asset decimals. |
| `305` | `EmployeeNotFound` | No | Recipient record is not registered or is incomplete for the company. | Onboard the recipient and store their commitment before executing payroll. |
| `306` | `CompanyNotFound` | No | Company identifier is not registered in the payroll registry. | Register the company in `payroll_registry` and use the returned `company_id`. |
| `307` | `CommitmentLocked` | Yes | Salary commitment is locked by an active audit or compliance hold. | Release the audit/compliance hold or wait for lock resolution before retrying. |
| `308` | `EmptyBatch` | No | Batch payroll submission contains zero payment entries. | Include at least one valid payment instruction in the batch call. |
| `309` | `ArrayLengthMismatch` | No | Batch input vectors (`employees`, `amounts`, `proofs_a/b/c`, `nullifiers`) have mismatched lengths. | Ensure all batch input vectors have identical length. |
| `310` | `SettlementWindowNotYetOpen` | Yes | Current ledger timestamp precedes the period execution window. | Wait until the ledger timestamp reaches `execute_at`, then retry. |
| `311` | `SettlementWindowClosed` | No | Current ledger timestamp is past the period execution/grace window. | Open a new settlement window for the next cycle or extend before expiry. |
| `312` | `InvalidSettlementWindowConfig` | No | Settlement window timestamps are not monotonically ordered. | Supply timestamps satisfying `open_at <= execute_at <= grace_until <= close_at`. |
| `313` | `SettlementWindowOverlap` | No | Proposed settlement window overlaps an existing non-cancelled company period. | Schedule the new period at or after the previous period's `close_at` boundary. |
| `314` | `WithholdingConfigMissing` | Yes | Company withholding configuration has not been set prior to payment execution. | Configure company withholding parameters via `set_withholding_config` first. |
| `315` | `InvalidWithholdingRate` | No | Combined tax and social withholding rates exceed `10,000` basis points (`100%`). | Set `income_tax_bps + social_tax_bps <= 10_000`. |
| `316` | `NetAmountBelowMinimum` | No | Net payout after withholding deductions is below the configured floor. | Adjust `min_net_per_payment` or verify the payment amount meets the net floor. |
| `317` | `GrossAmountExceedsCap` | No | Gross payout exceeds the configured per-payment maximum cap. | Split the disbursement across periods or raise `max_gross_per_payment`. |
| `318` | `SettlementReceiptAlreadyUsed` | No | Settlement receipt identifier was already consumed by a completed batch. | Treat the prior batch as settled or generate a fresh `receipt_id` for a new batch. |
| `319` | `BatchTooLarge` | No | Batch size exceeds the company or contract maximum batch size limit. | Chunk the batch into smaller slices at or below `get_max_batch_size`. |
| `320` | `PeriodAlreadyOpen` | No | Cannot reopen a payroll period that is already open. | Proceed with payment execution directly; no reopen call is needed. |
| `321` | `PayoutTotalOverflow` | No | Aggregate batch payout or cumulative company total exceeded `i128::MAX`. | Split the batch or rotate company accounting before exceeding `i128::MAX`. |

## Programmatic Inspection

Integrators and SDKs can inspect any numeric code in `300..=321` via `shared_errors::describe_payment_failure_code(code)` or `shared_errors::PaymentError::from_code(code)`.
