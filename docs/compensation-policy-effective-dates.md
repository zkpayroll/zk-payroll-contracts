# Compensation Policy Effective-Date Validation

A *compensation policy* binds a company's hashed compensation schedule to the
ledger timestamp it takes effect at. This document describes the rules
`payroll_registry` enforces on that timestamp, why each rule exists, and how an
integrator resolves the policy that governs a given payroll run.

- **Contract:** `contracts/payroll_registry/src/lib.rs`
- **Entrypoints:** `schedule_compensation_policy`, `check_policy_effective_date`,
  `require_valid_effective_date`, `get_compensation_policy`,
  `get_compensation_policy_schedule`, `get_compensation_policy_at`,
  `is_compensation_policy_effective`
- **Event:** [`CompensationPolicyScheduled`](./events.md#compensationpolicyscheduled--payroll_registry)

---

## Why the effective date needs validating

Compensation is the one payroll input where a wrong timestamp is silently
durable. A salary commitment is a hash: swapping it is visible as a commitment
rotation. An effective date is not — a policy dated in the past, or dated twice,
produces no error at read time, only an explanation of *why* a run paid under a
schedule nobody intended.

Three failure modes are worth refusing at write time:

| Failure | Consequence if accepted |
|---------|-------------------------|
| Effective date behind the ledger clock | Retroactively restates the schedule earlier payroll runs were executed under. Off-chain amounts already proven against the old schedule no longer match. |
| Two policies with the same effective date | "Which policy is in force?" stops having one answer, and the resolver has to pick a tie-break rule that was never agreed with the operator. |
| Effective date decades out | A mistyped timestamp (milliseconds submitted as seconds, a `u64` overflow, a spreadsheet serial) parks the company on a schedule that cannot be corrected, because every later date is *also* out of the horizon. |

The contract therefore enforces:

1. **No silent backdating.** `effective_at` may not be more than
   `COMPENSATION_POLICY_PAST_SKEW_SECONDS` (300s) behind the ledger clock.
2. **Bounded horizon.** `effective_at` may not exceed
   `MAX_COMPENSATION_POLICY_HORIZON_SECONDS` (one year) ahead of it.
3. **Strictly increasing schedule.** `effective_at` must be strictly greater
   than the effective date of the newest policy already scheduled for the
   company.

Rules are evaluated in that order, so a caller is told about the rule they most
likely broke first — a date that is both in the past and behind the schedule is
reported as `InThePast`.

---

## Privacy: the policy carries a commitment, not an amount

`policy_commitment` is a Poseidon hash of the off-chain schedule. No salary
amount, pay rate, or band is ever stored in contract state, put in an event, or
used as a proof public input. This is the same discipline employee salary
commitments follow, and the same rule
[`docs/architecture/001-privacy-audit-tradeoffs.md`](./architecture/001-privacy-audit-tradeoffs.md)
states: *no salary data is ever emitted in events or stored in plaintext
on-chain*.

An all-zero commitment is rejected: that is the uninitialised slot, not a hashed
schedule, and accepting it would let a company record a policy that binds
nothing.

---

## Scheduling a policy

**Entrypoint:** `PayrollRegistry::schedule_compensation_policy`

| Input | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Company ID |
| `admin` | `Address` | Must equal the registered company admin |
| `policy_commitment` | `BytesN<32>` | Poseidon hash of the compensation schedule; must not be all zero |
| `effective_at` | `u64` | Ledger timestamp from which the policy applies (inclusive) |

Returns the stored `CompensationPolicy`:

| Field | Type | Description |
|-------|------|-------------|
| `company_id` | `u64` | Owning company |
| `policy_commitment` | `BytesN<32>` | Hashed schedule |
| `effective_at` | `u64` | Ledger timestamp the policy applies from |
| `created_at` | `u64` | Ledger timestamp it was scheduled at |
| `created_by` | `Address` | Company admin that scheduled it |

Order of operations inside the call, and why it matters:

1. **Pause check** — a paused registry schedules nothing.
2. **Company lookup** — an unknown `company_id` fails with `"Company not found"`.
3. **Admin identity, then `require_auth`** — the identity check runs *before*
   authorisation so the effective-date errors cannot be used as an oracle for
   reading a company's schedule.
4. **Commitment check** — rejects an all-zero commitment.
5. **Effective-date validation** — rules 1–3 above.
6. **Write** — the policy under `(company_id, effective_at)`, and the effective
   date appended to the company's ascending schedule.
7. **Event** — `CompensationPolicyScheduled`.

Nothing is written and no event is emitted when any step fails.

### Why a past date is tolerated by 300 seconds

The effective date is chosen off-chain and submitted by the HR admin, so it can
legitimately trail the network clock by consensus skew. Refusing a date one
second behind the ledger would make a correct submission fail for a reason the
admin cannot see or fix. 300 seconds matches the approval-clock-skew bound the
`payroll` contract already applies to reviewer approval timestamps
(`MAX_APPROVAL_CLOCK_SKEW_SECONDS`, `contracts/payroll/src/lib.rs:402`), so the
two contracts treat "recently generated off-chain input" the same way. Dates
further behind than the tolerance are treated as genuinely backdating attempts.

---

## Preflight: checking before you submit

Two read-only entrypoints let a client or another contract evaluate a proposed
date without changing anything.

**`PayrollRegistry::check_policy_effective_date`**

| Output | Type | Description |
|--------|------|-------------|
| `effective_at` | `u64` | The date that was evaluated |
| `ledger_now` | `u64` | Ledger clock the verdict was taken at |
| `latest_scheduled_effective_at` | `Option<u64>` | Effective date of the newest scheduled policy, if any |
| `issue` | `CompensationPolicyEffectiveDateIssue` | The single rule that decides the verdict |
| `valid` | `bool` | Always agrees with `issue == None` |

The `issue` field takes one of four values:

| `CompensationPolicyEffectiveDateIssue` | Meaning | Remediation |
|---------------------------------------|---------|-------------|
| `None` (0) | Acceptable | — |
| `InThePast` (1) | More than the skew tolerance behind the ledger clock | Schedule at or after the current ledger timestamp |
| `BeyondSchedulingHorizon` (2) | More than one year ahead | Check for a seconds/milliseconds mix-up |
| `NotAfterScheduledPolicy` (3) | Not strictly after the newest scheduled policy | Use a later timestamp than `latest_scheduled_effective_at` |

**`PayrollRegistry::require_valid_effective_date`** enforces the same rules and
panics instead of returning a verdict, for use as a guard:

```
Compensation policy effective date is invalid for company 0: effective date is
in the past; schedule it at or after the current ledger timestamp (requested
1600000000, ledger now 1700000000)
```

```
Compensation policy effective date is invalid for company 0: effective date is
not after the latest scheduled policy; use a strictly later timestamp (requested
1700001000, latest scheduled 1700001000)
```

Both entrypoints take no `admin` argument and emit no events — they are safe to
call from simulation, a dashboard preflight, or another contract.

---

## Resolving the policy in force

Because effective dates in a company's schedule are strictly increasing, exactly
one policy is in force at any timestamp: the scheduled policy with the greatest
effective date `<= at_timestamp`.

| Question | Entrypoint |
|----------|-----------|
| What policy covered payroll at time `t`? | `get_compensation_policy_at(company_id, t)` |
| Was any policy in force at time `t`? | `is_compensation_policy_effective(company_id, t)` |
| What is the full schedule? | `get_compensation_policy_schedule(company_id)` — ascending, earliest first |
| What is scheduled for exactly this date? | `get_compensation_policy(company_id, effective_at)` |

`get_compensation_policy_at` returns `None` when `at_timestamp` precedes the
company's first policy. That is a real answer, not an error: no policy covered
that point in time, and the caller should not treat a missing policy as "use the
current one".

---

## Storage

| Key | Value | Notes |
|-----|-------|-------|
| `DataKey::CompensationPolicy(u64, u64)` | `CompensationPolicy` | Keyed by `(company_id, effective_at)` |
| `DataKey::CompensationPolicySchedule(u64)` | `Vec<u64>` | Ascending effective dates; also the "latest scheduled date" the validator reads |

The schedule vector doubles as the ordering invariant and the resolution index,
so no second copy of the ordering can drift out of step with the policies
themselves. Adding these two variants keeps the registry `DataKey` union well
under the 50-variant Soroban contract-spec ceiling.

---

## Related

| Reference | Path |
|-----------|------|
| Registry contract | `contracts/payroll_registry/src/lib.rs` |
| Focused tests | `contracts/payroll_registry/tests/compensation_policy_effective_dates.rs` |
| Error recovery table | [docs/errors.md](./errors.md) |
| SDK walkthrough | [docs/sdk-contract-interface.md](./sdk-contract-interface.md) |
| Event reference | [docs/events.md](./events.md) |
