# Employer Role Change Invariants

> Closes #952.

This document is the authoritative reference for all invariants that the
`access_control` module enforces during employer role transitions.  Every
invariant listed here is tested in
[`contracts/access_control/tests/employer_role_adversarial.rs`](tests/employer_role_adversarial.rs)
and the role-change regression suite in
[`contracts/access_control/tests/employer_role_regression.rs`](tests/employer_role_regression.rs).
It is tracked by the stable error codes in
[`EmployerRoleError`](src/lib.rs#EmployerRoleError) (codes 800–807).

---

## 1. Terminology

| Term | Meaning |
|---|---|
| **Company** | A logical entity registered in the registry, identified by an auto-incremented `u64` company ID. |
| **Employer** | The `Address` currently authorized to act on behalf of a company via employer-only entrypoints. |
| **Role record** | The on-chain `EmployerRoleRecord` stored at `DataKey::EmployerRole(company_id)`. |
| **Pending transfer** | An in-flight two-step handoff stored at `DataKey::PendingEmployerTransfer(company_id)`. |
| **Revoked** | A boolean flag on the role record indicating the employer authorization has been lifted. |

---

## 2. Role Registration Invariants

### INV-REG-1  One role record per company

A company may have at most one `EmployerRoleRecord`.  `register_employer` panics
with `EmployerRoleError::AlreadyActive` (807) if a record already exists for the
given company ID.

### INV-REG-2  Registered role starts active

A freshly registered employer record always has `revoked = false`.  The
`last_changed_at` field is set to the current ledger timestamp at registration
time.

---

## 3. Role Enforcement Invariants

### INV-ENF-1  Only the active employer may act

`require_active_employer` enforces that the caller equals `EmployerRoleRecord::employer`
and that `revoked == false`.  Callers that differ from the registered employer
receive `EmployerRoleError::UnauthorizedEmployer` (801).  A revoked employer
receives `EmployerRoleError::EmployerRevoked` (805) regardless of address match.

### INV-ENF-2  Authorization is always demanded

Every enforcement path calls `caller.require_auth()` only after the identity and
revocation checks pass.  An attacker who supplies the correct employer address but
cannot produce a valid Soroban host authorization is still rejected.

### INV-ENF-3  Absent role record is not treated as authorization

`require_active_employer` and `is_active_employer` both return a failure result
(panic or `false` respectively) when the role record is absent.  An absent record
is never treated as an implicit grant.

---

## 4. Role Transfer Invariants

### INV-TRF-1  Only one pending transfer at a time

`propose_employer_role_transfer` panics with `EmployerRoleError::PendingTransferExists`
(802) if a pending transfer already exists for the company.  The existing transfer
must be accepted or cancelled before a new one can be proposed.

### INV-TRF-2  Current employer must initiate the transfer

Only the current active employer (matching `EmployerRoleRecord::employer` and with
`revoked == false`) may propose a transfer.  Any other caller receives
`EmployerRoleError::UnauthorizedEmployer` (801).

### INV-TRF-3  Self-transfer is rejected

The incoming address must differ from the current employer.  Proposing a transfer
to oneself panics with `EmployerRoleError::SelfTransferNotAllowed` (806).

### INV-TRF-4  Only the named incoming address may accept

`accept_employer_role_transfer` checks that the accepting address equals
`PendingRoleTransfer::incoming`.  Any mismatch panics with
`EmployerRoleError::InvalidTransferTarget` (804).

### INV-TRF-5  Revoked employer cannot initiate a transfer

A revoked employer is fully blocked: `propose_employer_role_transfer` panics
with `EmployerRoleError::EmployerRevoked` (805) before checking any other
condition.

### INV-TRF-6  Acceptance is blocked while role is revoked

If the role is revoked after a transfer has been proposed but before acceptance,
`accept_employer_role_transfer` panics with `EmployerRoleError::EmployerRevoked`
(805).  The pending transfer record is left intact (not silently cleared).

### INV-TRF-7  Accepted transfer updates the role record atomically

On acceptance the role record and pending transfer key are updated in the same
storage write sequence.  After `accept_employer_role_transfer` returns
successfully:

* `EmployerRoleRecord::employer` equals the new employer address.
* `EmployerRoleRecord::last_changed_at` equals the current ledger timestamp.
* `EmployerRoleRecord::revoked` is `false`.
* The `DataKey::PendingEmployerTransfer(company_id)` key is absent.

### INV-TRF-8  Only the current employer may cancel

`cancel_employer_role_transfer` requires that the cancelling caller is the
current employer (the one who proposed).  An unauthorized canceller receives
`EmployerRoleError::UnauthorizedEmployer` (801).

---

## 5. Revocation Invariants

### INV-REV-1  Revocation is idempotent-safe (error on double revoke)

Calling `revoke_employer_role` on an already-revoked employer panics with
`EmployerRoleError::EmployerRevoked` (805).  Double-revocation is never a
silent no-op; callers must check state before acting.

### INV-REV-2  Only the current employer may self-revoke

Revocation requires the same `UnauthorizedEmployer` check as all other
employer-gated actions.  A third party cannot revoke another company's
employer.

### INV-REV-3  Revocation does not delete history

`revoke_employer_role` sets `revoked = true` and updates `last_changed_at`.
The employer address stored in the record is preserved for audit purposes.
Historical payroll data is completely unaffected.

### INV-REV-4  Revocation blocks all employer-gated operations

After revocation `require_active_employer` will always panic with
`EmployerRoleError::EmployerRevoked` (805) for the affected company,
regardless of the caller address.

---

## 6. Privacy Invariants

### INV-PRI-1  Error messages are free of private payroll data

No variant of `EmployerRoleError`, no event payload, and no preflight return
value carries salary amounts, employee addresses, commitment hashes, or
individual payment records.  All error messages are safe to log and display
to operators without filtering.

### INV-PRI-2  Read helpers expose only role-lifecycle data

`get_employer_role` returns only `{ employer, revoked, last_changed_at }`.
`get_pending_transfer` returns only `{ incoming, initiated_by, proposed_at }`.
Neither function returns any payroll, salary, or employee data.

---

## 7. Event Invariants

| Event symbol | Topics | Data |
|---|---|---|
| `employer_role_registered` | `(symbol, company_id)` | `(employer, timestamp)` |
| `employer_role_transfer_proposed` | `(symbol, company_id)` | `(current_employer, incoming, timestamp)` |
| `employer_role_transfer_accepted` | `(symbol, company_id)` | `(old_employer, new_employer, timestamp)` |
| `employer_role_transfer_cancelled` | `(symbol, company_id)` | `(employer, timestamp)` |
| `employer_role_revoked` | `(symbol, company_id)` | `(employer, timestamp)` |

**INV-EVT-1** — An event is emitted if and only if the corresponding state
transition succeeds.  Failed calls never emit partial events.

**INV-EVT-2** — No event payload includes salary values, employee identifiers,
commitment hashes, or payment amounts.

---

## 8. Error Code Registry

| Code | Variant | Meaning |
|---|---|---|
| 800 | `CompanyNotFound` | No role record exists for the given company ID. |
| 801 | `UnauthorizedEmployer` | Caller is not the registered employer. |
| 802 | `PendingTransferExists` | A transfer proposal is already open. |
| 803 | `NoPendingTransfer` | No transfer proposal to accept or cancel. |
| 804 | `InvalidTransferTarget` | Accepting address ≠ proposal target. |
| 805 | `EmployerRevoked` | Employer role has been revoked. |
| 806 | `SelfTransferNotAllowed` | Transfer target equals current employer. |
| 807 | `AlreadyActive` | Role already exists; re-registration is not allowed. |

Codes 800–899 are reserved for employer-role / access-control errors and must
not be used by other modules.
