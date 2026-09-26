# Payroll Period Freeze Guard (#471)

Once a payroll period has been finalized, its payroll data must not be
silently editable. This document describes the freeze guard in
`contracts/payroll/src/lib.rs` — what it blocks, what deliberately stays
available, and how authorized corrections work.

## Overview

A period can be frozen in two ways:

1. **Automatically** — `submit_run_draft` freezes the period (with reason
   `finalized`) at the moment the draft is converted into an executable
   payroll run.
2. **Manually** — the admin calls `freeze_payroll_period` with an explicit
   reason (e.g. `manual`), freezing the period without submitting a run.

The freeze state is stored per period label under
`DataKey::PeriodFreeze(period_label)` as a `PeriodFreeze` record:

| Field | Meaning |
|-------|---------|
| `period_label` | The frozen period's label (matches the draft `period_label`) |
| `frozen_by` | Address that applied the freeze |
| `frozen_at` | Ledger timestamp when the freeze was applied |
| `reason` | Short operator label (`finalized` for auto-freeze, or admin-supplied) |
| `runs_count` | Executed runs bound to this period when the freeze was applied |

The record is deliberately minimal: **no salary values, commitments, or
employee lists** are ever stored in or emitted with the freeze state.

## Blocked entrypoints

While a period is frozen, these entrypoints panic with
`"Payroll period is frozen: it has been finalized and can no longer be edited"`
for that period:

| Entrypoint | Why it is blocked |
|------------|-------------------|
| `create_run_draft` | No new payroll work may be created against a finalized period. |
| `amend_run_draft` | Frozen figures cannot be changed. |
| `set_run_draft_description` | Draft metadata cannot be edited. |
| `finalize_run_draft` | Drafts cannot be locked in for submission. |
| `submit_run_draft` | No executable run may be submitted into a frozen period. |

## Deliberately still available (escape hatches)

| Entrypoint | Why it stays available |
|------------|------------------------|
| `cancel_run_draft` / `expire_run_draft` | These remove pending work instead of adding or changing it — an operator must always be able to clean up an orphaned draft on a frozen period. |
| `unfreeze_payroll_period` | The authorized correction valve; see below. |
| `freeze_payroll_period` | Freezing an already-frozen period is rejected (`"Payroll period is already frozen"`), but the freeze state itself must remain inspectable and the error actionable. |
| `get_period_freeze` / `is_period_frozen` | Read-only queries; clients should use these to disable edit affordances proactively. |

## Authorized correction flow

Freezes are reversible by design, but only through an explicit admin action:

```
freeze  ──▶  (edits blocked)  ──▶  unfreeze  ──▶  (edits possible again)
```

1. Admin checks `is_period_frozen(period_label)`.
2. Admin calls `unfreeze_payroll_period(period_label)` — this emits
   `period_unfrozen` and is the **sole** path back to editing.
3. The correction is performed (e.g. a new draft is created).
4. The period is re-frozen by the normal flow (auto-freeze on
   `submit_run_draft`, or a manual `freeze_payroll_period`).

Every transition is captured as an event, so the full freeze history of a
period is recoverable from the event log alone. Treat unfreezing as an
exceptional, audited action — not a routine rollback button.

## Event surface

| Event | Emitted when | Payload |
|-------|--------------|---------|
| `payroll / period_frozen` | Freeze applied (manual or auto) | `(period_label: Symbol, frozen_by: Address, reason: Symbol)` |
| `payroll / period_unfrozen` | Freeze lifted by admin | `(period_label: Symbol, unfrozen_by: Address)` |

The event schemas are pinned by snapshot tests in
`tests/event_schema/` and fixtures in `tests/event_schema/fixtures/events/payroll.json`.

## Interaction with the duplicate-period guard (#398)

The #398 guard blocks a second *pending* draft for the same period and
records the active draft id under `DataKey::ActiveDraftForPeriod`. Terminal
draft transitions (`submit`, `cancel`, `expire`) now clear that slot
(previously a stale entry could block later drafts for the period — relevant
exactly in the unfreeze-and-correct flow described above).

## QA coverage

`contracts/payroll/tests/period_freeze_guard.rs` covers:

- Manual freeze/unfreeze round trip with state assertions.
- Event emission for both freeze and unfreeze (topics + payload).
- Blocking of all five edit entrypoints on a frozen period (panic-message
  assertions).
- Auto-freeze on `submit_run_draft` (reason `finalized`) and its enforcement.
- Escape hatches: cancel and expire of a pending draft remain possible while
  frozen.
- Validation and authorization: double freeze, unfreeze-without-freeze,
  non-admin freeze/unfreeze, empty period label / reason.
- Privacy: the freeze record and event payloads carry no salary or employee
  data.
