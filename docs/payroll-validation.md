# Payroll validation APIs

These read-only entrypoints support contract/SDK preflight checks. They emit
no events, write no storage, and need no authorization. They do not register
pay groups or change payroll execution/settlement state. Callers must use
authoritative records when preparing validation inputs.

## Pay-group effective dates (#783)

`validate_pay_group_dates(proposed, existing)` validates an opaque group
reference and its Unix timestamp interval. Starts may be the current ledger
timestamp or at most 365 days in the future, matching payroll policy dates.
An end of zero is unbounded; otherwise the end must be strictly after the
start. Intervals are half-open: a group is active at its start and expired
at its end. Adjacent intervals are allowed; overlapping intervals for the
same group are rejected. At most 50 existing intervals may be supplied.

`check_pay_group_effective(period)` checks whether the group is effective now.
The existing-history argument must contain the group's complete relevant
history; the contract has no existing pay-group registry to authenticate it.
Scheduling validation does not itself authorize a payout.

Errors are stable contract errors: `7830` invalid group reference, `7831`
invalid interval, `7832` start in past, `7833` start beyond the scheduling
horizon, `7834` overlapping interval, `7835` history too large, `7836` not
yet effective, and `7837` expired. Timestamp arithmetic is overflow-safe.
