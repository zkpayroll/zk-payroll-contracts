# Treasury Accounting Assumptions & Invariants

This document outlines the core assumptions and invariants surrounding the treasury balance accounting in the ZK Payroll Contracts, specifically within the `payroll` contract.

## Core Invariants

1. **Treasury Token Balance**: The actual on-chain token balance of the treasury address must exactly equal the initial balance plus all successful deposits minus all successful payroll executions.
   
   `Token.balance(treasury) = initial_balance + sum(deposits) - sum(batch_process_payroll)`

2. **Depositor Balance Accumulation**: The `get_treasury_balance(depositor)` mapping exclusively tracks the sum of all successful deposits made by that specific depositor. It does not decrement upon payroll execution. It serves as an append-only accounting ledger for auditability.

   `get_treasury_balance(depositor) = sum(deposits by depositor)`

3. **Failed Operations**: Operations that fail or revert (e.g., due to invalid proofs, mismatched amounts, unauthorized access, or zero amounts) must have zero side effects on the treasury token balance and the depositor balance ledger.

4. **Non-Execution State Transitions**: Lifecycle operations that do not execute token transfers (such as `prepare_payroll_run`, `cancel_payroll_run`, and `update_reconciliation_status`) must not affect the treasury token balance or the depositor balance ledger.

## State Transitions & Accounting Effects

### Deposits (`deposit`)
- **Accounting Effect**: Increases the underlying token balance of the treasury by transferring tokens from the depositor.
- **Ledger Effect**: Increases the `CompanyBalance` (read via `get_treasury_balance`) for the caller by the exact deposit amount.
- **Failures**: Reverts if the amount is zero/negative or if the nonce was already used. No partial balances are stored.

### Payroll Execution (`batch_process_payroll`)
- **Accounting Effect**: Decreases the underlying token balance of the treasury by the `expected_total_spend`, transferring tokens to the specified employees.
- **Ledger Effect**: None. `get_treasury_balance` is unchanged.
- **Failures**: If the treasury lacks sufficient funds, or any proof is invalid, or any commitment is missing, the entire transaction reverts. Funds are not removed from the treasury.

### Cancellation (`cancel_payroll_run`)
- **Accounting Effect**: None. Pending runs do not reserve funds in the token contract.
- **Ledger Effect**: None. The `PendingPayrollRun` is deleted, and the run state becomes `Cancelled`. The treasury balances remain entirely unchanged.

### Settlement (`update_reconciliation_status`)
- **Accounting Effect**: None.
- **Ledger Effect**: None. Settlement simply marks the `PayrollRun` state as `Completed` (or `ReconciliationRequired`/`Failed`) for off-chain accounting and compliance tracking.

### Finalization (`finalize_payroll_run`)
- **Accounting Effect**: None. Finalizes a pending run into a completed `PayrollRun` record for auditability without executing payments.

## Security Assumptions

- **One-Way Execution Funding**: The payroll contract acts as a one-way bridge out of the treasury. It cannot pull funds from the treasury for any purpose other than authorized batch processing or emergency withdrawals.
- **Balance Insufficiency Protection**: The contract explicitly verifies `treasury_balance >= expected_total_spend` before attempting sequential transfers. This prevents partial execution where some employees are paid and others fail due to a dry treasury.
- **Nonce Uniqueness**: Both deposits and payroll runs rely on one-time-use nonces (`DepositNonce`, `RunNonce`) to prevent double-spending and replay attacks.
