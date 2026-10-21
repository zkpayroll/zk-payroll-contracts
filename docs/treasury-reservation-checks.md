# Treasury Balance Reservation Checks (#699)

`prepare_payroll_run` refuses to reserve more treasury funds than the balance
left after pending-run locks and the configured retained-balance buffer.

## Why

Preparing a run locks its total (`LockedPayrollFunds`) so that an emergency
withdrawal cannot spend money a pending run is counting on. Before this check
the lock was recorded without asking whether the treasury could cover it. Two
runs prepared back to back could together lock more than the treasury holds,
and the shortfall only surfaced later, when `finalize_payroll_run` tried to
transfer the money and failed.

The treasury is an ordinary account, so the check cannot prevent every
shortfall (see [Limits](#limits)), but it stops the contract from creating one
itself.

## Rule

A run of `expected_total_spend` may be prepared only when

```
expected_total_spend <= max(treasury_balance - locked_funds - buffer, 0)
```

where `treasury_balance` is the canonical token's balance at the treasury
address, `locked_funds` is what other pending runs already hold
(`get_locked_funds`), and `buffer` is the minimum retained amount configured
with `set_treasury_balance_buffer` (zero until configured). This is the rule
`check_funding_source_readiness` applies to a hypothetical spend, so a readiness
check that says "ready" and a `prepare_payroll_run` that follows it agree.

| Case | Behaviour |
|------|-----------|
| Amount fits after locks and buffer | Run is prepared and its total is locked. |
| Amount equals the reservable balance | Allowed (the boundary is inclusive); only the configured buffer remains. |
| Amount is one unit over the reservable balance | Rejected. |
| Other pending runs hold funds | Only the balance they leave free counts. |
| A run is cancelled, expires, or is finalized | Its lock is released or consumed, as before; the next run is checked against the new balance. |
| Treasury holds less than locks and buffer | Nothing is available; every run is rejected until it is funded or a run is cancelled. |

## Order of operations in `prepare_payroll_run`

1. Execution-initiator authorization, company state, storage version.
2. Batch shape: non-empty, matching lengths, size cap, duplicate nonce,
   draft pre-commitment, duplicate employees, positive amounts, total equals
   `expected_total_spend`.
3. Nonce monotonicity and the asset allowlist.
4. **Treasury reservation and buffer check (#699/#712)** — rejects before any state is written.
5. Capacity limits, settlement window, run id, nonce consumption, the pending
   run record, and the funds lock.

A rejected run writes nothing: the nonce is not consumed, no capacity is
recorded, and `get_locked_funds` is unchanged, so the caller can resubmit the
same nonce with a smaller batch once the treasury is funded.

## Errors

| Message | Meaning and recovery |
|---------|----------------------|
| `"Insufficient available treasury balance: run needs {amount} but only {available} is reservable after the {buffer} buffer ({locked} of {balance} is locked for pending payroll); fund the treasury, reduce the buffer, or cancel a pending run"` | The run does not fit. Deposit to the treasury, reduce the buffer, cancel a pending run to release its lock, or shrink the batch. `available` is never negative. |
| `"Treasury token unavailable: cannot confirm the balance to reserve against"` | The token contract did not answer a balance query. Retry; if it persists, check the configured asset. |
| `"Reservation amount must be positive"` | Defensive; `prepare_payroll_run` already rejects non-positive amounts first. |

## Code

The decision is pure and lives in `contracts/payroll/src/treasury_reservation.rs`:

| Item | Purpose |
|------|---------|
| `check_reservation_with_buffer(total_balance, reserved, buffer, amount)` | Returns the balances after the reservation, or a `ReservationIssue`. |
| `unreserved_balance(total_balance, reserved)` | `total - reserved`, never negative. |
| `ReservationIssue` | `NonPositiveAmount`, `InsufficientUnreserved { available }`, with stable `as_str()` codes. |
| `ReservationOutcome` | Available before, reserved after, and available after. |

Reading the balance and raising the panic stay in `Payroll`
(`require_reservable_treasury_balance`). The buffer is configured by the admin
with `set_treasury_balance_buffer`; see
[Treasury Balance Buffer Enforcement](./treasury-balance-buffer.md).

## Limits

- The treasury is an external account. If something outside payroll moves money
  out of it after a run is prepared, the lock can exceed the balance again. The
  check only governs what payroll itself reserves; `get_safe_treasury_summary`
  and `check_funding_source_readiness` show the current position.
- Only `prepare_payroll_run` reserves funds. The direct execution entrypoints
  (`batch_process_payroll`, `batch_process_with_expiry`,
  `batch_process_payroll_bounded`) still do not consult locked funds, but each
  payout checks that the configured buffer remains in the treasury.

## Privacy

Only aggregate token amounts are read and reported. No employee identity,
salary row, commitment, or proof material is involved.

## Verification

- `cargo test -p payroll --test treasury_reservation_checks` — integration
  tests: a run within the balance reserves its total, exact-boundary success,
  one unit over rejected with the figures in the message, reservations
  accumulating across pending runs, cancelling and finalizing releasing the
  lock, a treasury drawn below its locked funds, a rejected run leaving no
  trace (nonce reusable, lock unchanged), and agreement with
  `check_funding_source_readiness`.
- `cargo test -p payroll --test treasury_balance_buffer` — default-zero
  compatibility, buffer-boundary reservations and readiness, failed-run
  retryability, direct-payout and emergency-withdrawal enforcement, and
  negative configuration.
- Unit tests in `treasury_reservation.rs` pin the arithmetic, including the
  inclusive boundary, a treasury below its locked funds, and extreme values.
