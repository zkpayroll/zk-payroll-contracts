# Payroll Responsibility Delegation Audit (#714)

An on-chain, append-only record of every time responsibility for a pending
payroll run is handed from one admin to another.

## Why

A pending run has one responsible party, its admin. `transfer_pending_run_admin`
lets the current admin hand that responsibility to another address. The run
keeps only the current admin, and the handover used to leave only an event. Once
the run was finalized, cancelled, or expired, nothing on chain said who had been
responsible for it along the way, and an auditor had to rebuild the chain of
custody from an indexer.

Each handover now appends a record to the run's audit trail. The trail outlives
the pending run, can be paged, and can be verified.

## What is recorded

A `DelegationRecord` per handover:

| Field | Meaning |
|-------|---------|
| `run_id` | The run. |
| `sequence` | 1-based position in the run's trail. |
| `delegator` | The admin who handed responsibility over and authorized the call. |
| `delegate` | The admin who took responsibility. |
| `delegated_at` | Ledger timestamp of the handover. |
| `ledger_sequence` | Ledger sequence of the handover. |

The first record's `delegator` is the run's admin as prepared, so the chain of
custody is complete from the first handover without recording anything when the
run is prepared. A run that was never handed over has an empty trail.

## Rules

| Case | Behaviour |
|------|-----------|
| Handover by the run's admin | Recorded, then takes effect (unchanged authorization and checks). |
| Handover rejected (not the admin, to oneself, unknown run, paused, disputed) | Nothing is recorded. |
| Handing the run back to an earlier admin | A new record; earlier records are never rewritten. |
| Run finalized, cancelled, or expired | The trail stays. |
| More than `MAX_DELEGATIONS_PER_RUN` (100) handovers | Rejected: finalize or cancel the run instead. This is the one new limit. |

Records are written once and never changed or removed by the contract.

## Contract surface

| Entrypoint | Purpose |
|------------|---------|
| `get_run_delegation_count(run_id)` | Number of handovers recorded. |
| `get_run_delegation(run_id, sequence)` | One record by its 1-based sequence, or `None`. |
| `get_run_delegation_audit(run_id, after_sequence, limit)` | A page of records, oldest first: those with `sequence > after_sequence`, at most `limit`, never more than `MAX_DELEGATION_AUDIT_PAGE` (50). Start with `after_sequence = 0`, then pass the last sequence received. |
| `verify_run_delegation_audit(run_id)` | Checks the trail still adds up and returns a `DelegationAuditVerdict`. |

All four are read-only and need no authorization.

### Verification

`verify_run_delegation_audit` checks, in order, and reports the first problem
with the sequence it was found at (`issue_at`):

| `DelegationAuditIssue` | Meaning |
|------------------------|---------|
| `SequenceGap` | A record is missing or out of order; sequences must run 1, 2, 3... |
| `SelfDelegation` | A record hands responsibility from an address to itself. |
| `BrokenChain` | A handover does not start from the previous handover's delegate. |
| `CurrentHolderMismatch` | The run is pending and the last delegate is not its current admin. |
| `NoIssue` | The trail is consistent. |

`DelegationAuditVerdict` also carries `entries`, `consistent`, `run_pending`, and
`current_holder`: the run's admin while it is pending, otherwise the last
delegate (`None` if it was never handed over).

## Events

`transfer_pending_run_admin` keeps publishing its existing event unchanged and
adds one:

| Topics | Data |
|--------|------|
| `("payroll", "run_admin_transferred")` | `(run_id, delegator, delegate)` (unchanged) |
| `("payroll", "delegation_recorded")` | `(run_id, sequence, delegator, delegate, delegated_at)` |

## Code

`contracts/payroll/src/delegation_audit.rs` holds the record types, the
bounded append, paging, and the pure `verify_records` check. Storage uses a
dedicated `DelegationAuditKey` enum (`Count(run_id)` and `Entry(run_id,
sequence)`), leaving the existing `DataKey` layout untouched (that enum is
already past the Soroban 50-case spec ceiling). Each record is its own entry,
so a handover writes two small entries however long the trail is.

## Scope

This audits the handover of a pending run's admin, the one place payroll
responsibility is handed between addresses today. Changes to reviewers, the
admin, the treasury owner, and other configuration are already audited by
[Configuration Audit Events](./config-audit-events.md).

## Privacy

Only addresses, sequence numbers, and ledger times are stored and emitted. No
salary amount, employee identity, commitment, or proof material is read or
surfaced.

## Verification

- `cargo test -p payroll --test run_delegation_audit` — integration tests: an
  untouched run has an empty consistent trail, a handover records who, to whom
  and when, ordered chains verify, handing back appends, the trail survives
  cancellation, rejected handovers write nothing, runs have independent trails,
  paging by last sequence and the page ceiling, the 100-handover ceiling and
  its message, the event pair, and verification catching a broken chain, a
  missing record, a trail ending elsewhere than the pending admin, and a
  self-handover.
- Unit tests in `delegation_audit.rs` cover `verify_records`, the ceiling, the
  page clamp, and the stable issue codes.
