# Treasury Balance Buffer Enforcement (#712)

Payroll can retain a configured minimum token balance in its treasury. This
buffer protects operational liquidity from being consumed by payroll runs or
withdrawals.

## Configuration

The contract admin sets the minimum retained balance with
`set_treasury_balance_buffer(admin, minimum_balance)`. The value is denominated
in the canonical payout token's smallest unit, must be non-negative, and can
only be changed when no prepared payroll run is active. Until configured, the
buffer is `0`, preserving existing deployments' behavior.

`get_treasury_balance_buffer()` returns the configured value. Setting a new
buffer is recorded by the configuration audit ledger under the
`treasury_balance_buffer` key; the amount itself is not emitted in plaintext.

## Enforcement

Payroll reserves and readiness checks use the balance left after subtracting
both pending-run locks and the buffer:

```text
reservable = max(treasury_balance - locked_payroll_funds - buffer, 0)
```

Direct payroll payout entrypoints check the live token balance before transfer
and reject any payout that would leave less than the buffer. Bounded batches
apply the check to each chunk so partial progress cannot spend the retained
minimum. Emergency withdrawals use the same available-balance calculation at
request and approval time.

`get_available_treasury_balance`, `get_safe_treasury_summary`, and
`check_funding_source_readiness` report capacity after both payroll locks and
the configured buffer. The buffer is aggregate-only and does not expose
employee, salary, or proof data.

The treasury remains an external token account: transfers made outside payroll
can reduce its balance below the configured buffer. Payroll blocks further
outflows until the treasury is replenished or the admin lowers the buffer.

## Errors and recovery

- `Treasury balance buffer would be breached` means the requested direct payout
  would leave less than the configured minimum. Fund the treasury or lower the
  buffer.
- `Insufficient available treasury balance` on a reservation means that the
  pending-run locks and buffer leave insufficient capacity. Fund the treasury,
  reduce the requested run, release a pending reservation, or lower the buffer.
