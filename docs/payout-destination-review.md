# Payout Destination Change Review (#610)

`payroll_registry` lets an employee redirect their payroll to a different
address. Issue #486 added that direct update. Issue #610 adds a **review**
path so that a destination change can be held for company-admin sign-off
before any salary is redirected.

This document describes the review lifecycle, the guarantees it provides, and
its interaction with the direct update flow.

## Why a review

The direct flow (`update_payout_destination`) is self-authorized: whoever
controls the employee account can change the payout destination at any time,
and the next payroll run pays the new address. That is the intended behaviour
for a legitimate employee who changed wallets, but it is also exactly the
shape of a compromised or coerced account.

The review flow separates *proposing* a change from *applying* it. The employee
proposes; the company admin decides. Until the admin approves, the payout
destination on file is untouched, so the worst case of a hijacked employee
account is a pending review that the admin can reject — not a redirected
payroll.

## Lifecycle

```
                 propose_payout_dest_change
                            |
                            v
  (none) ------------> [Pending] -------- review(approve=true)  ----> [Approved]
                          |  |                                        destination applied
                          |  | review(approve=false) ----> [Rejected]   (unchanged)
                          |  |
                          |  +------ cancel_payout_dest_change --> [Cancelled]
                          |                                           (unchanged)
                          |
                    next propose
                    overwrites the
                    resolved record
```

`get_payout_dest_review(company_id, employee)` returns the current record, or
`None` if the employee has never proposed a change.

### States

`DestinationReviewStatus` is a `#[contracttype]` with explicit ordinals so
off-chain clients can persist and pattern-match on it across upgrades:

| State | Meaning | Payout destination |
| --- | --- | --- |
| `Pending` | Proposed by the employee, awaiting an admin decision. | unchanged |
| `Approved` | Admin approved; the new destination has been written. | **new destination** |
| `Rejected` | Admin rejected the change. | unchanged |
| `Cancelled` | The proposing employee withdrew the change. | unchanged |

Only one review record is kept per `(company_id, employee)`. A new proposal
overwrites a resolved record; a second proposal while a review is `Pending` is
rejected, so an employee cannot stack competing destinations.

## Fields

`PayoutDestinationReview` carries only review lifecycle data:

| Field | Meaning |
|-------|---------|
| `company_id` | Company the employee is registered under. |
| `employee` | Employee who proposed the change. |
| `new_destination` | Destination being proposed. |
| `current_destination` | Destination on file at proposal time. |
| `proposed_at` | Ledger timestamp of the proposal. |
| `status` | Current `DestinationReviewStatus`. |
| `resolved_at` | Ledger timestamp of the decision or cancellation (`0` while pending). |
| `resolved_by` | Company admin that decided (`None` while pending or on cancellation). |

`current_destination` is a **snapshot** taken when the change is proposed, not a
live lookup. Payout destinations default to the employee address when no
explicit destination is stored, so an absent record and a record equal to the
employee address mean the same thing.

No salary values, Poseidon commitments, or payment history appear in the
record or in its events.

## Events

| Event | Topics | Data | Emitted by |
| --- | --- | --- | --- |
| `PayoutDestinationChangeProposed` | symbol, `company_id`, `employee` | *(empty)* | `propose_payout_dest_change` |
| `PayoutDestinationChangeReviewed` | symbol, `company_id`, `employee` | `approve: bool` | `review_payout_dest_change` |
| `PayoutDestinationChangeCancelled` | symbol, `company_id`, `employee` | *(empty)* | `cancel_payout_dest_change` |
| `PayoutDestinationUpdated` | symbol, `company_id`, `employee` | `(current, new)` | `update_payout_destination` **and** an approved `review_payout_dest_change` |

An approval emits two events: the review decision, then the destination update.
Indexers that already consume `PayoutDestinationUpdated` (from the #486 direct
flow) observe the same shape for an approved review, so they do not need to be
changed — but they will see an approved review as a destination change even
though no `PayoutDestinationChangeReviewed` existed before #610.

## Validation

The review path enforces exactly the same destination rules as the direct
update flow, so the two paths cannot drift apart:

| Condition | Panic |
| --- | --- |
| Employee is not registered under the company | `Employee not found` |
| `new_destination` equals the destination on file | `Destination address is already on file` |
| `new_destination` is the zero address | `Cannot set zero address as payout destination` |
| A review for the employee is already `Pending` | `A payout destination change is already under review` |
| No review exists for the employee | `No payout destination change under review` |
| The review is already resolved | `Payout destination change is not pending review` |
| Review path caller is not the company admin | `Unauthorized: caller is not the company admin` |
| The company admin is revoked | `Company admin is revoked` |
| The contract is paused | `Contract is paused` |

Authorization:

- `propose_payout_dest_change` and `cancel_payout_dest_change` require
  `require_auth` from the **employee**. An outsider cannot propose or withdraw
  a change on someone else's behalf.
- `review_payout_dest_change` takes the deciding `admin` address explicitly and
  requires it to equal the company's current admin, then calls
  `admin.require_auth()`. Passing an address is not enough — the signature is
  still required.

Every entrypoint calls `require_not_paused` first, so a paused registry cannot
enter or advance the review lifecycle.

## Relationship to `update_payout_destination`

The direct update path from #486 is unchanged and still available. The review
flow is **additive and opt-in**: a company that wants two-person control over
payout redirects routes its employees through `propose_payout_dest_change`,
while a company that does not can keep using `update_payout_destination`.

Because the direct path is not gated on there being no `Pending` review, a
`Pending` review does not block a subsequent direct update. An indexer that
treats a `Pending` review as "the destination is pinned" must therefore also
watch `PayoutDestinationUpdated`, which is emitted by both paths.

## Operator guidance

- Show the pending review (proposed destination and the destination currently on
  file) to the admin before they decide, so an approval is an informed decision
  rather than a single click.
- `get_payout_dest_review` is read-only and privacy-safe, so an operations UI
  can poll it without a transaction and without exposing payroll values.
- A `Rejected` or `Cancelled` record is retained rather than deleted, which
  gives a short audit trail of how often changes were proposed and refused.
