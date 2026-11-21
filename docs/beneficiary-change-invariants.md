# Beneficiary change invariants

This page documents what must stay true when a payee's bindings change. The tests that hold each
rule in place are in `contracts/salary_commitment/src/beneficiary_change_tests.rs`.

## What "beneficiary" means here

There is no separate beneficiary contract. The payee of a payroll entry is the **employee
address** in `salary_commitment`, and three bindings hang off it:

| Binding | Set by | Changed by |
|---|---|---|
| Salary commitment (`SalaryCommitment`) | `store_commitment` | `update_commitment`, `rotate_commitment`, `rotate_approved_commitment` |
| External reference id (HR system id) | `set_employee_reference_id` | `set_employee_reference_id` again |
| Authority over both (the commitment admin) | `init_commitment_admin` | `propose_admin_rotation` + `accept_admin_rotation` |

(`payroll` also exposes `check_beneficiary_status`, a read-only verification preflight. It changes
nothing and is described in `payroll-validation.md`.)

## Invariants

### B1. A commitment value belongs to one employee, for ever

A value that has ever been bound, active or retired, can never be bound again, to the same
employee or another. `CommitmentIndex` is set on first use and never cleared. This keeps a settled
payroll record matchable to the commitment it used.

### B2. Only the commitment admin changes a binding

`store_commitment`, `update_commitment`, `rotate_commitment`, `rotate_approved_commitment`,
`lock_commitment_updates`, `unlock_commitment_updates` and `set_employee_reference_id` all require
the admin's authorisation. The employee, the payroll operator and a stranger cannot call them. After
a handover the previous admin loses all of them.

### B3. A commitment is stored once, then changed through its history

`store_commitment` panics if the employee already has a commitment. Without that rule a second
store would reset `version` to 1 and replace the live record without archiving it. Every later
change goes through update or rotate, which archive the outgoing value and raise the version by
one (saturating at `u32::MAX`).

### B4. A rejected change leaves no trace

A change refused for any reason (lock, duplicate value, zero value, unknown employee, missing
authorisation, pause) must not move the version, add a history entry, or reserve the value it
tried to use.

### B5. A reference id points at one employee

Ids are compared after normalisation (trimmed, upper-cased), so `emp1`, ` EMP1 ` and `EMP1` are the
same id. A held id cannot be claimed by another employee. When an employee moves to a new id, the
old id is freed and only that one. Two employees cannot swap ids directly, because each id is held
by the other at the time; they swap through a free id.

### B6. Admin handover is two-step and does not touch bindings

A handover needs a proposal from the current admin and an acceptance from the proposed address.
Only one proposal can be pending. A cancelled proposal cannot be accepted, and an accepted one
cannot be accepted twice. A handover changes who has authority and nothing else: commitments,
history, locks and reference ids are unchanged.

## Known gaps

- `rotate_commitment` sets `created_at` to the rotation time, while `update_commitment` keeps the
  original `created_at`. The two disagree on what `created_at` means; this page does not change
  either.
- There is no way to unset a reference id. An employee can only move to another id.
