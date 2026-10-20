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

## Payout confirmation reconciliation (#784)

`reconcile_payout_confirmations(run_id, expected, confirmations)` returns the
expected, confirmed, pending, and failed counts and a `ReconciliationStatus`.
Payouts are matched by opaque `payout_ref`, independently of receipt order.
Run IDs, asset addresses, beneficiary references, and amount references must
match exactly. Both input vectors are limited to 50 records, and duplicate or
unknown payout IDs are errors. A confirmed payout requires a nonzero transaction
reference and a confirmation timestamp in `(0, current_ledger_timestamp]`.
One transaction may legitimately confirm several distinct payouts.

Missing receipts count as pending. Pending/failed receipts must not carry a
confirmation timestamp. Any failed receipt yields `Failed`; otherwise any
pending payout yields `Unreconciled`; only a completely confirmed set yields
`Reconciled`. Empty expectation lists cannot reconcile successfully.

This is evidence consistency checking, not independent verification that a
transfer occurred. Callers must authenticate receipts and expected payouts.
The report does not update a run or call `update_reconciliation_status`.
Only hashes/references are supplied, never plaintext salary amounts.

Errors: `7840` invalid/mismatched run, `7841` empty expectations, `7842` input
too large, `7843` invalid reference, `7844` duplicate payout, `7845` unknown
payout, `7846` mismatched payout details, and `7847` invalid confirmation time.
