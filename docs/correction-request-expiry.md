# Correction Request Expiry (#622)

A **correction request** is a `Pending` payroll run draft that can still be
corrected through `amend_run_draft` (#89). This documents the opt-in expiry
policy that lets an employer stop an idle correction request from staying
correctable forever, and the permissionless path that retires it.

This documents the on-chain behaviour in `contracts/payroll/src/lib.rs` and
`contracts/payroll/src/correction_request_expiry.rs`.

## Motivation

A pending draft holds the period's single pending-draft slot (#398) and can be
amended indefinitely. A draft an operator created and then abandoned:

- blocks `create_run_draft` for its period (the duplicate guard rejects a new
  draft until the old one leaves `Pending`), forcing an admin-only
  `expire_run_draft`/`cancel_run_draft` to recover; and
- can be corrected weeks later against a payroll roster, treasury balance, or
  asset allowlist that has since drifted.

Expiry turns "open for correction" from an unbounded state into a bounded one.

## Expiry Policy

Expiry is **opt-in** and backward compatible:

| Operation | Who | Effect |
|-----------|-----|--------|
| `set_correction_request_expiry(admin, max_age_seconds)` | Admin | Enables/updates the policy. `0` clears it (restores unrestricted corrections). |
| `get_correction_request_expiry()` | Anyone | Returns `Option<CorrectionRequestExpiryPolicy>` (`None` = disabled). |
| `is_correction_request_expired(draft_id)` | Anyone | `true` when the draft is `Pending` and idle past the window. |
| `expire_correction_request(caller, draft_id)` | Anyone | Retires a *lapsed* request; moves the draft to `Expired` and frees its period. |

- While no policy is configured, `amend_run_draft` behaves exactly as it did
  before this feature: no policy is read, no clock is consulted, every amendment
  is accepted.
- `set_correction_request_expiry` follows the other payroll configuration gates:
  admin-only, blocked while paused, and blocked while a payroll run is in
  progress (#253).
- Unlike run expiration (#474), clearing the policy is always allowed — a draft
  reserves no treasury funds, so a lapsed request can never hold funds hostage.

## Semantics

`max_age_seconds` is an **inactivity** window measured from the draft's
`updated_at` timestamp, which every accepted amendment refreshes:

- a request that is being actively corrected never lapses;
- only a request left untouched for longer than the window does.

The window is half-open: a request expires only once
`now > updated_at + max_age_seconds`, so a request exactly on the boundary is
still correctable. The comparison uses saturating arithmetic, so an extreme
timestamp can never wrap into the past and expire every request.

## Lifecycle

```
create_run_draft                 (window elapses idle)      expire_correction_request
      │                                  │                              │
      ▼                                  ▼                              ▼
  Pending ──────────► amend_run_draft    Pending ─── rejected ───►  Expired (terminal)
      ▲                    │  (refreshes updated_at)                     │
      └── amend accepted ──┘                                            └── period slot freed
                                                                           for a fresh draft
```

1. **Inside the window** — nothing changes: the draft can be amended normally,
   and each accepted amendment resets the inactivity clock.
2. **Past the window** — `amend_run_draft` rejects the correction with a panic
   naming the recovery path. The rejection writes no state, so the draft and the
   period's #577 correction usage counters are untouched.
3. **Retirement** — permissionless: *any* caller may submit it once the request
   has lapsed. The draft moves to the terminal `Expired` state, the period's
   pending-draft slot (#398) is cleared, and `draft_expired` is emitted.
   Retirement is terminal, so a second attempt fails.
4. **Operator escape hatches** — raise or clear the policy
   (`set_correction_request_expiry`) to make a lapsed request correctable again,
   or let anyone call `expire_correction_request` and create a fresh draft.

## What Is Enforced, and What Is Not

This feature deliberately gates the **correction** path only:

- `amend_run_draft` refuses to correct a lapsed request.
- `finalize_run_draft` and `submit_run_draft` are **not** gated. The correction
  right is what expires — a draft that was never corrected can still be finalized
  and executed exactly as before. Keeping the payroll execution path untouched
  avoids any risk of blocking legitimate runs, which is the higher-severity
  failure mode. An integrator that wants a lapsed draft to be unusable should
  call `expire_correction_request`.

## Privacy

The policy stores only the age bound, who configured it, and when. The expiry
check reads timestamps and the draft state; it reads no salary amount, employee
identity, or proof material. The retirement event carries only the draft id and
the caller, matching `draft_expired`.

## Edge Cases

| Situation | Result |
|-----------|--------|
| No policy configured | `is_correction_request_expired` is `false`; corrections unrestricted |
| Exactly on the boundary | Not expired (half-open window) |
| Unknown draft id | `is_correction_request_expired` is `false` |
| Non-`Pending` draft | `is_correction_request_expired` is `false`; cannot be retired again |
| `expire_correction_request` on a live request | Panics; request stays `Pending` |
| `expire_correction_request` with expiry disabled | Panics |
| Policy raised after a lapse | Request becomes correctable again |
| Amendment rejected by the expiry gate | No draft state and no #577 usage counters written |

## Testing

Focused coverage lives in `contracts/payroll/tests/correction_request_expiry.rs`
(18 tests): policy lifecycle, non-admin rejection, boundary semantics, rejection
after the window, clock refresh on amendment, permissionless retirement, slot
release, terminal/idempotent retirement, and interaction with the #577
correction-authorization budget.

```bash
cargo test -p payroll --test correction_request_expiry
```
