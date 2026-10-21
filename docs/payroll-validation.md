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

## Configuration-ledger export consistency (#785)

`validate_ledger_export(first_revision, last_revision, entries)` validates a
complete inclusive revision range of 1–50 entries exported by the existing
`get_config_ledger` API. The contract reads the canonical page itself; the
exporter cannot supply the expected records. Every field of every entry must
match storage, including actor, key, subject/value references, revision,
ledger sequence, and timestamp. Missing, extra, duplicate, reordered, or
tampered entries are rejected. Revision zero and reversed ranges are invalid.
Historical pages remain valid when new revisions are appended.

Success returns bounds, count, and a deterministic SHA-256 integrity hash of
the domain separator `zkpayroll_ledger_export_v1`, the contract address, range
bounds, and canonical XDR entries. This binds the digest to one contract.
No additional export records or plaintext configuration values are stored.
An unavailable canonical record fails closed; restore archived state before
retrying. Empty exports cannot be reported as successfully reconciled ranges.

Errors: `7850` invalid range, `7851` page too large, `7852` entry-count mismatch,
`7853` nonconsecutive revisions, `7854` unavailable canonical entries, and
`7855` an exported entry differs from storage.

## Beneficiary verification status (#786)

`check_beneficiary_status(beneficiary, verification)` accepts only a matching
`Verified` record with a nonzero evidence reference, a nonzero verification
timestamp at or before the ledger time, and an unexpired validity interval.
Pending, rejected, revoked, missing, or mismatched records fail with distinct
errors. Expiry is exclusive: a record is expired at `expires_at`. Zero expiry
means indefinite validity; a finite expiry must follow `verified_at`.

The record is not mutated when it expires. Only an evidence hash is accepted;
identity documents and their contents must remain off-chain. This preflight
checks a supplied record's status and dates, not an issuer's signature or
identity evidence. The existing contract has no beneficiary-verification
registry. Integrators must fetch/authenticate the record from their verifier
before calling this check and enforce a successful result in their payout
workflow. This API does not add a new mandatory gate to legacy payroll calls.

Errors: `7860` missing record, `7861` beneficiary mismatch, `7862` pending,
`7863` rejected, `7864` revoked, `7865` missing evidence, `7866` invalid dates,
and `7867` expired. These checks cannot issue verification decisions.

## Integration and tests

The public validation traits and Soroban types are exported by the payroll
crate, and the methods are part of the `Payroll` contract interface. All new
methods are read-only; no storage migration or new authorization role is
required. Call the date/status checks before the integrating flow commits any
state or transfers funds. Authenticate off-chain records separately.

Inline Rust tests cover success, rejection, and boundary cases for every API.
Run `cargo test -p payroll --lib` for the module tests, and the normal workspace
format, clippy, and test checks before merging. These additions do not require
changes to the ZK circuits or trusted setup.
