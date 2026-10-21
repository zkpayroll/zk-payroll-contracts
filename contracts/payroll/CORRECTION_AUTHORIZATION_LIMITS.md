# Payroll Correction Authorization Limits

## Overview

Correction authorization limits let an employer cap how much correction activity a single
payroll period can absorb before someone deliberately revisits the policy.

A **correction** is an amendment to a pending payroll run draft, applied through
`amend_run_draft`. Corrections move money, so an unbounded flow of them is hard to review
after the fact. This feature adds an optional, admin-configured ceiling that is enforced
before the amendment is written.

Limits are **opt-in**. Until an employer configures them, `amend_run_draft` behaves exactly
as it did before this feature existed: no counter is read, no storage is written, and no
correction is rejected.

## Why This Matters

- **Guardrails**: a compromised or misconfigured client cannot quietly drain a period through
  an unlimited number of amendments.
- **Actionable feedback**: a correction that would breach a ceiling is rejected up front with
  a message naming the ceiling, before any partial state is written.
- **Privacy**: counters are aggregate numbers only. No salary amount, employee identity, or
  proof material is stored, surfaced, or included in an error message.

## Configuration

### Setting limits

Only the registered payroll admin may set limits. The contract must not be paused, and no
payroll run may be in progress.

```rust
// Cap a period at 3 corrections, a cumulative 500_000 of correction movement,
// and 40 corrected employees.
payroll.set_correction_auth_limits(&admin, &3u32, &500_000i128, &40u32);

// A ceiling of 0 disables that individual check.
payroll.set_correction_auth_limits(&admin, &0u32, &500_000i128, &0u32);

// All-zero ceilings store an ineffective policy: enforcement and counting stop.
payroll.set_correction_auth_limits(&admin, &0u32, &0i128, &0u32);
```

A negative `max_total_delta` is rejected, since no correction could ever satisfy it.

Setting limits publishes a `corr_limits_set` event carrying the actor and the three
ceilings — configuration values only, never payroll data.

### Querying limits

```rust
let limits = payroll.get_correction_auth_limits();
match limits {
    Some(l) => {
        println!("max corrections/period: {}", l.max_corrections_per_period);
        println!("max total delta:         {}", l.max_total_delta);
        println!("max employees corrected: {}", l.max_employees_corrected);
    }
    None => println!("corrections are unrestricted"),
}
```

### Querying usage

```rust
let usage = payroll.get_correction_usage(&period);
println!("corrections: {}", usage.correction_count);
println!("total delta: {}", usage.total_delta);
println!("employees:   {}", usage.employees_corrected);
```

Usage is scoped per payroll period and reported as zeroed counters when the period has no
recorded corrections.

## The three ceilings

| Ceiling | Stored as | Counts | Disabled by |
| --- | --- | --- | --- |
| `max_corrections_per_period` | `u32` | amendments applied to drafts in the period | `0` |
| `max_total_delta` | `i128` | cumulative **absolute** change in draft total amount | `0` |
| `max_employees_corrected` | `u32` | cumulative employee count carried by corrected drafts | `0` |

`max_total_delta` consumes budget for the **magnitude** of a change, so raising a draft total
from 1,000 to 1,100 and lowering it from 1,000 to 900 both consume 100. This is deliberate:
the ceiling bounds how much correction movement a period can contain, in either direction.

## Enforcement semantics

`amend_run_draft` evaluates the ceilings in this order and rejects on the first breach:

1. correction count,
2. corrected-employee budget,
3. correction amount budget.

A rejected correction:

- panics **before** any state is written, so the draft's `total_amount`, `employee_count` and
  `amendment_count` are untouched;
- consumes **no** budget, so a failed attempt does not bring the period closer to its ceiling.

A successful correction increments `correction_count`, adds the change magnitude to
`total_delta`, and adds the amended employee count to `employees_corrected`.

Because counters are written only when an *effective* policy is configured, contracts that
never use this feature pay no storage cost.

## Interaction with period freeze

Correction limits are evaluated after the existing period-freeze guard (#471/#484). A frozen
period is still rejected for that reason first; limits are an additional, independent check.

## Tests

`contracts/payroll/tests/correction_authorization_limits.rs` covers:

- amendments are unrestricted while no policy is configured;
- a configured policy is readable and a later call replaces it wholesale;
- each ceiling independently rejects the correction that would exceed it;
- usage accumulates across corrections and is scoped per period;
- a rejected correction consumes no budget and leaves the draft unchanged;
- all-zero ceilings disable enforcement without losing readability;
- non-admin callers and negative ceilings are rejected;
- clearing a policy restores unrestricted amendments.
