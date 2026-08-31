# Contract Event Schema Reference

Structured events emitted by the ZK Payroll contract suite. This is the
authoritative schema reference for SDK, indexer, dashboard, and compliance
contributors.

- **Naming convention:** `PascalCase` event names emitted as `Symbol` topics.
  The legacy `payroll` contract uses an older two-symbol convention
  (`("payroll", "<verb>")`).
- **Topic/data layout:** Every event is a `(topics, data)` tuple on Soroban.
  Topics always carry the event name and **primary identifiers** so that
  filters can subscribe without parsing the data payload.
- **Privacy boundary:** No event in this suite emits a raw salary value.
  Commitments and keyed-commitment hashes are safe to publish; plaintext
  amounts are NOT.

> **Tip:** Pair this reference with:
> - [monitoring/event-taxonomy.md](./monitoring/event-taxonomy.md) ? the
>   canonical category taxonomy (`ONB`, `FND`, `EXE`, `AUD`, `SEC`).
> - [monitoring/event-severity-mappings.md](./monitoring/event-severity-mappings.md)
>   ? severity levels and alert routing guidance.
> - [payload-examples.md](./payload-examples.md) ? sample XDR payloads.

---

## Common Conventions

| Concept | Convention |
|---------|------------|
| `topics[0]` | `Symbol` event name (e.g. `"CompanyRegistered"`) |
| `topics[1..]` | Primary identifiers (`company_id`, `employee`, `auditor`, ?) |
| `data` | Payload tuple in declaration order |
| Empty data | Serialised as `()` (Rust unit) |
| Amount fields | `i128` raw token units ? divide by token decimals before display |
| Timestamps | `u64` Unix seconds from `env.ledger().timestamp()` |
| Ledger fields | `u32` from `env.ledger().sequence()` |
| Identifiers | `company_id` is `u64` (registry) or `Symbol` (audit / batch facade ? see notes) |

**Topic format ? modern contracts**

```
topics = ( Symbol("<EventName>"), <primary_id_1>, <primary_id_2>, ... )
data   = ( <payload_field_1>, <payload_field_2>, ... )
```

**Topic format ? `pause_manager`** (legacy two-symbol convention)

```
topics = ( Symbol("PauseManager"), Symbol("<verb>") )
data   = ( <payload> ) | ()
```

**Topic format ? legacy `payroll` batch facade** (older contract path)

```
topics = ( Symbol("payroll"), Symbol("<verb>") )
data   = ( <payload> )
```

---

## Domain Index

| Domain | Section | Primary contract(s) |
|--------|---------|--------------------|
| Employee lifecycle & onboarding | [? Employee Events](#employee-events) | `payroll_registry`, `salary_commitment` |
| Payroll execution & proof | [? Payroll Events](#payroll-events) | `payment_executor`, `payroll` (legacy) |
| Treasury administration | [? Treasury Events](#treasury-events) | `payroll_registry`, `pause_manager` |
| Audit & compliance | [? Audit Events](#audit-events) | `audit_module` |
| ZK proof verification | [? Proof Events](#proof-events) | `proof_verifier` (cross-contract effects) |

---

## Employee Events

These events track the lifecycle of employees and their commitment state.
HR UIs, identity providers, and roster indexers subscribe to them.

### `EmployeeAdded` ? `payroll_registry`

Emitted when a new employee and their Poseidon commitment are registered
under a company. Initial status defaults to `Active`.

```
topics[0]  Symbol("EmployeeAdded")
topics[1]  u64   company_id
topics[2]  Address employee
data       (BytesN<32> commitment,)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` (routine onboarding) | HR UIs, indexers, employee directories |

---

### `EmployeeRemoved` ? `payroll_registry`

Emitted when an employee record is permanently deleted from the registry.

```
topics[0]  Symbol("EmployeeRemoved")
topics[1]  u64   company_id
topics[2]  Address employee
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` (destructive) | HR UIs, access-review tools, retention-archival pipelines (see [retention-archival-policy.md](./compliance/retention-archival-policy.md)) |

---

### `EmployeeDeactivated` ? `payroll_registry`

Emitted when a registered employee is marked `Inactive` via
`set_employee_status`. Deactivated employees remain in storage but are not
eligible for payroll execution until reactivated.

```
topics[0]  Symbol("EmployeeDeactivated")
topics[1]  u64   company_id
topics[2]  Address employee
data       (EmployeeStatus previous_status, EmployeeStatus new_status, u32 ledger_sequence, u64 timestamp)
```

| Field | Meaning |
|-------|---------|
| `previous_status` | Status observed before the update. |
| `new_status` | Always `EmployeeStatus::Inactive`. |
| `ledger_sequence` | Ledger sequence at which the lifecycle change was recorded. |
| `timestamp` | Ledger timestamp for ordering history views. |

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` | HR UIs, payroll eligibility caches, audit-log indexers |

---

### `EmployeeReactivated` ? `payroll_registry`

Emitted when a registered employee is marked `Active` via
`set_employee_status`. Reactivated employees become eligible for payroll
execution once other client-side checks pass.

```
topics[0]  Symbol("EmployeeReactivated")
topics[1]  u64   company_id
topics[2]  Address employee
data       (EmployeeStatus previous_status, EmployeeStatus new_status, u32 ledger_sequence, u64 timestamp)
```

| Field | Meaning |
|-------|---------|
| `previous_status` | Status observed before the update. |
| `new_status` | Always `EmployeeStatus::Active`. |
| `ledger_sequence` | Ledger sequence at which the lifecycle change was recorded. |
| `timestamp` | Ledger timestamp for ordering history views. |

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` | HR UIs, payroll eligibility caches, audit-log indexers |

---

### `EmployeeStatusUpdated` ? `payroll_registry`

Emitted when a registered employee is moved to `Incomplete`. This state is
used when required registration data is missing and should be treated as
ineligible until corrected.

```
topics[0]  Symbol("EmployeeStatusUpdated")
topics[1]  u64   company_id
topics[2]  Address employee
data       (EmployeeStatus previous_status, EmployeeStatus new_status, u32 ledger_sequence, u64 timestamp)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | HR UIs, roster validation jobs |

---

### `CommitmentUpdated` ? `salary_commitment`

Emitted when a new commitment is stored (`store_commitment`) or an existing
one is updated (`update_commitment`). The same event name is also emitted
from `payroll_registry.update_commitment` with `(company_id, employee)` as
the topic tuple ? indexers MUST subscribe by contract address to
disambiguate.

**From `salary_commitment`:**
```
topics[0]  Symbol("CommitmentUpdated")
topics[1]  Address employee
data       (BytesN<32> commitment,)
```

**From `payroll_registry`:**
```
topics[0]  Symbol("CommitmentUpdated")
topics[1]  u64   company_id
topics[2]  Address employee
data       (BytesN<32> new_commitment,)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | Roster caches, salary-history builders, indexers |

> ?? A `CommitmentUpdated` followed by a `CommitmentRotated` in the same
> transaction indicates the old commitment has been invalidated.

---

### `CommitmentRotated` ? `salary_commitment`

Emitted when an existing commitment is **explicitly rotated** (old value
revoked, new value stored). Indexers that cache commitments MUST replace
their cached value on receipt of this event.

```
topics[0]  Symbol("CommitmentRotated")
topics[1]  Address employee
data       (BytesN<32> old_commitment, BytesN<32> new_commitment)
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` (authoritative invalidation signal) | Indexers, salary-history rebuilders, audit trails |

---

### `CommitmentLocked` ? `salary_commitment`

Emitted when an employee's commitment is locked to prevent silent updates
during a finalized payroll draft or audited payroll run. After this event,
`update_commitment` and `rotate_commitment` will panic until unlocked.

```
topics[0]  Symbol("CommitmentLocked")
topics[1]  Address employee
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` (routine during payroll finalisation; treat as integrity signal ? any unaccompanied unlock should be investigated) | HR UIs, compliance reviewers, monitoring |

---

### `CommitmentUnlocked` ? `salary_commitment`

Emitted when an employee's commitment lock is cleared by the admin. Should
only follow a previously observed `CommitmentLocked` for the same employee.

```
topics[0]  Symbol("CommitmentUnlocked")
topics[1]  Address employee
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` | HR UIs, monitoring (verify it was preceded by an authorised lock) |

---

### `ReferenceIdSet` ? `salary_commitment`

Emitted when an external HR-system reference ID (e.g. `"EMP12345"`) is bound
to an employee address. IDs are non-sensitive metadata only ? never include
salary or bank information.

```
topics[0]  Symbol("ReferenceIdSet")
topics[1]  Address employee
data       (String reference_id,)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | HR-system bridges, identity providers, integration indexers |

---

### `AdminRotationProposed` ? `salary_commitment`

Step 1 of the two-step HR-admin rotation. Signals a pending change of the
HR admin address. Must be followed by `AdminRotationAccepted` (rotates the
admin) or `AdminRotationCancelled` (reverts).

```
topics[0]  Symbol("AdminRotationProposed")
topics[1]  Address current_admin
data       (Address new_admin,)
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` | Security dashboards, pending-change monitors |

---

### `AdminRotationAccepted` ? `salary_commitment`

Step 2 of the rotation: the proposed admin has accepted and now holds the
HR-admin role.

```
topics[0]  Symbol("AdminRotationAccepted")
topics[1]  Address new_admin
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `HIGH` (privileged handoff) | Security dashboards, key-management tools |

---

### `AdminRotationCancelled` ? `salary_commitment`

The current admin cancelled a pending rotation before acceptance. The
admin set did NOT change.

```
topics[0]  Symbol("AdminRotationCancelled")
topics[1]  Address current_admin
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | Security dashboards (expected if not accepted within timeout) |

---

## Payroll Events

These events cover payroll periods, individual payment execution, and the
proof-verified settlement step. Reconciliation tools, payment dashboards,
and indexers MUST subscribe to this domain.

### `PeriodCreated` ? `payment_executor`

Emitted when a new payroll period is opened for a company. Periods are
monotonically numbered per company. A new period cannot be opened while a
prior one is still open.

```
topics[0]  Symbol("PeriodCreated")
topics[1]  u64   company_id
data       (u32 period_id,)
```

| Severity | Consumers |
|----------|-----------|
| `INFO` (expected lifecycle) | Indexers, payroll schedulers, dashboards |

---

### `PeriodClosed` ? `payment_executor`

Emitted when a payroll period is closed. No further payments can be made
against the period after this event.

```
topics[0]  Symbol("PeriodClosed")
topics[1]  u64   company_id
data       (u32 period_id,)
```

| Severity | Consumers |
|----------|-----------|
| `INFO` (expected lifecycle) | Indexers, reconciliation tools (use to finalise per-period totals) |

---

### `PayrollProcessed` ? `payment_executor`

Emitted after a successful private payment execution via the period-aware
payment path. The included `amount` is a plaintext value (the off-chain
prover has already disclosed it to the contract). Indexers can trust this
event only after the same transaction's `proof_verifier.verify` succeeded.

```
topics[0]  Symbol("PayrollProcessed")
topics[1]  u64   company_id
data       (Address employee, i128 amount, u32 period_id)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` (high-volume success) | Reconciliation tools, payment dashboards, per-company & per-period aggregators |

> ?? Distinguish from the legacy `payment_executed` event (? Legacy Batch
> Events): `PayrollProcessed` carries `company_id` in `topics[1]` and
> `period_id` in `data[2]`.

---

### Legacy Batch Events ? `payroll` (batch facade)

The older `payroll` contract uses a two-symbol topic convention. Treat it
as a separate emission source, but normalise records into a common schema
keyed on `(company_id, employee, period, amount, ledger_sequence)`.

#### `payroll / payment_executed`

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("payment_executed")
data       (Address employee, i128 amount)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | Reconciliation tools, legacy dashboards |

#### `payroll / run_executed`

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("run_executed")
data       (u64 run_id, i128 total_amount)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | Run-aggregators (track `run_id` sequence for gap detection) |

### Payroll lifecycle ordering

For the cross-call payroll lifecycle, consumers should process the legacy
`payroll` topics in this order:

1. `run_prepared` - a pending run was created.
2. `run_approved` - an authorized reviewer recorded approval.
3. `payment_executed` - an individual payment completed.
4. `run_executed` - the execution batch completed.
5. `reconciliation_updated` with `Reconciled` - settlement completed.

The preparation and execution calls allocate separate run IDs in the current
API. Consumers must use the event payload run ID when correlating records and
must not infer correlation from event position alone. Event-ordering tests
assert topics only; they do not log or export payroll amounts, commitments, or
employee addresses. A failed or unauthorized approval reverts and emits no
`run_approved` event.


#### `payroll / draft_updated`

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("draft_updated")
data       (u64 draft_id, Symbol period_label, i128 total_amount, u32 employee_count, u32 amendment_count)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | SDKs, dashboards, draft-review indexers |
#### `payroll / deposit`

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("deposit")
data       (Address from, i128 amount)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` (treasury deposits) | Funding dashboards, treasury monitors |

> ?? The legacy `payroll` contract emits additional event types beyond the
> three enumerated above (for example `draft_amended`, run lifecycle and
> submission events). This document only covers the high-priority, externally
> documented topics. To enumerate the full surface, subscribe by contract
> address and inspect topics at runtime, or read
> `contracts/payroll/src/lib.rs` / `libmain.rs` directly.

---

## Treasury Events

Events describing company onboarding and privileged-role administration
that affect treasury behavior (admin/treasury rotation, pause control).

### `CompanyRegistered` ? `payroll_registry`

Emitted when a new company is registered. Carries the initial admin and
treasury addresses used for subsequent payment execution.

```
topics[0]  Symbol("CompanyRegistered")
topics[1]  u64   company_id
data       (Address admin, Address treasury)
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` (new tenant onboarding) | Onboarding analytics, tenant indexers, billing |

---

### Privileged-Role Rotation Events (cross-contract cross-reference)

The two-step rotation pattern is implemented in two contracts and emits the
canonical topic names listed under [? Employee Events](#employee-events) for
`salary_commitment`, and under [`pause_manager` events](#pausemanager--paused--pausemanager) below for `pause_manager`. Subscribe **by contract address** to
distinguish:

| Contract | Event topic | Section |
|----------|-------------|---------|
| `salary_commitment` | `AdminRotationProposed` / `Accepted` / `Cancelled` | [? Employee Events](#employee-events) |
| `pause_manager` | `PauseManager / op_proposed` / `op_rotated` / `op_cancelled` | [? pause_manager events](#pausemanager--paused--pausemanager) |

> ?? `payroll_registry` exposes `propose_*_rotation` / `accept_*_rotation` /
> `cancel_*_rotation` storage functions for company-level admin and treasury
> roles but **does not emit rotation events**. Off-chain monitors tracking
> privileged changes at the company level must poll registry storage or
> rely on companion indexers rather than subscribe to events.

---

### `PauseManager / paused` ? `pause_manager`

Emitted when the system is paused. All payroll execution halts immediately
until unpaused. Treat as `CRITICAL`.

```
topics[0]  Symbol("PauseManager")
topics[1]  Symbol("paused")
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `CRITICAL` (page on-call) | All operations, incident-response runbooks (see [incident-response-playbook.md](./incident-response-playbook.md)) |

---

### `PauseManager / unpaused` ? `pause_manager`

Emitted when the system resumes. Operators MUST verify the root cause of the
preceding `paused` event before treating this as routine.

```
topics[0]  Symbol("PauseManager")
topics[1]  Symbol("unpaused")
data       ()
```

| Severity | Consumers |
|----------|-----------|
| `HIGH` | All operations, incident-response runbooks |

---

## Audit Events

Compliance-grade events from `audit_module`. They carry only metadata ?
salary values are NEVER emitted, consistent with the privacy boundary.

### `ViewKeyGenerated` ? `audit_module`

Emitted when a view key is generated for an auditor. Includes the raw key
bytes (auditor-address-bound) and the ledger at which the key expires.

```
topics[0]  Symbol("ViewKeyGenerated")
topics[1]  Address auditor
data       (BytesN<32> key_bytes, u32 expiration_ledger)
```

| Severity | Consumers |
|----------|-----------|
| `MEDIUM` (privileged credential issued) | Audit dashboards, key-lifecycle trackers, SOC logs |

---

### `ViewKeyRevoked` ? `audit_module` (historical)

> ?? The canonical source only emits `AuditAccessRevoked` (see below). The
> name `ViewKeyRevoked` does not appear in the current `master` emission
> surface ? it is documented here only so that older indexers / external
> tooling can recognise it if they encounter it from legacy deployments.
> **Treat `AuditAccessRevoked` as the authoritative event.**

---

### `AuditAccessRevoked` ? `audit_module`

Emitted when a view key is revoked before its expiration. Carries the
revoking admin, the affected auditor, and the ledger timestamp at which
the revocation occurred.

```
topics[0]  Symbol("AuditAccessRevoked")
topics[1]  Address admin       // the admin that originally granted the key
topics[2]  Address auditor     // the auditor losing access
data       (u64 timestamp,)    // env.ledger().timestamp() at revocation
```

| Severity | Consumers |
|----------|-----------|
| `HIGH` (privileged credential destroyed) | Compliance reviewers, security dashboards, audit trails |

---

### `AuditSuccessful` ? `audit_module`

Emitted when an auditor's commitment verification passes. The second data
field is a **keyed** commitment (`SHA-256(view_key ? commitment)`) ? not the
raw salary commitment, so it is safe to publish for off-chain auditing.

```
topics[0]  Symbol("AuditSuccessful")
topics[1]  Address auditor
data       (AuditScope scope, BytesN<32> keyed_stored)
```

`AuditScope` serialises as a `u32` discriminant:

| Value | Scope |
|-------|-------|
| `0`   | `FullCompany` |
| `1`   | `TimeRange` |
| `2`   | `EmployeeList` |
| `3`   | `AggregateOnly` |

| Severity | Consumers |
|----------|-----------|
| `INFO` (routine compliance check) | Compliance dashboards, audit-trace builders |

---

### `AggregateAuditGenerated` ? `audit_module`

Emitted when an aggregate compliance report is generated for a company and
period. No individual salary data is included.

```
topics[0]  Symbol("AggregateAuditGenerated")
topics[1]  Address auditor
data       (Symbol company_id, u64 period_start, u64 period_end)
```

> ?? `company_id` here is the audit-module `Symbol` form (string-coerced
> identifier), which differs from the `u64` integer ID used by
> `payroll_registry` and `payment_executor`.

| Severity | Consumers |
|----------|-----------|
| `INFO` | Compliance dashboards, period-aggregators |

---

### `AuditSummaryExported` ? `audit_module`

Emitted when an exportable metadata summary is produced for external
compliance tooling (issue #93). The summary includes only verification
counts and metadata ? never salary values.

```
topics[0]  Symbol("AuditSummaryExported")
topics[1]  Address auditor
data       (Symbol company_id, u64 period_start, u64 period_end, u32 total_entries)
```

| Severity | Consumers |
|----------|-----------|
| `LOW` | External compliance integrations, evidence-collectors |

---

## Proof Events

`proof_verifier` is a storage-only contract; it does not emit events directly.
However, `payment_executor.execute_payment` integrates proof verification
into the settlement path, and the **success or failure** of a payment is the
public signal that a Groth16 proof was or was not verified.

> A failed proof verification causes a Soroban transaction reversion
> (`"Invalid payment proof"`); it does NOT emit an explicit event. Off-chain
> monitors must listen for failed transactions and read the diagnostic
> string from the host envelope.

### Proof success ? `PayrollProcessed`

Every `PayrollProcessed` event (? Payroll Events) is also an implicit
**proof-verification success**: the contract only emits it after
`proof_verifier.verify` returned `true` and the asset allowlist passed.

**Cross-domain signal contract:**

| Proof result | On-chain signal | Consumer guidance |
|--------------|-----------------|-------------------|
| Success | `PayrollProcessed` event in same tx | Indexers may treat as authoritative proof-acceptance |
| Failure (`CommitmentMismatch`, malformed proof, etc.) | Transaction reverts with host diagnostic | Detect via failed-tx monitoring; see [event-severity-mappings.md](./monitoring/event-severity-mappings.md) Exceptional Conditions |
| Stale proof (`ProofExpired`, > 7 days) | `PaymentError::ProofExpired` reversion | Detect via failed-tx monitoring; ? Operational Impact |
| Replay attempt | `PaymentError::ProofAlreadyUsed` reversion | `CRITICAL` alert (see [alert-rules.md](./monitoring/alert-rules.md) ? 2) |
| Payment in closed period | `PaymentError::PeriodClosed` reversion | `MEDIUM` alert (see [alert-rules.md](./monitoring/alert-rules.md) ? 6) |

| Severity | Consumers |
|----------|-----------|
| See `PayrollProcessed` for success | See `PayrollProcessed` |

---

## Consumer Matrix

Quick-reference: which consumer types should subscribe to which domain.

| Consumer | Employee | Payroll | Treasury | Audit | Proof |
|----------|:--------:|:-------:|:--------:|:-----:|:-----:|
| HR/Employee UI | ? | ? | ? | ? | ? |
| Payroll operator UI | ? | ? | ? | ? | ? |
| Payment indexer | ? | ? | ? | ? | ? |
| Reconciliation tool | ? | ? | ? | ? | ? |
| Treasury dashboard | ? | ? | ? | ? | ? |
| Compliance dashboard | ? | ? | ? | ? | ? |
| Audit-trace builder | ? | ? | ? | ? | ? |
| Incident-response alerts | ? (locks) | ? | ? (pause) | ? (revokes) | ? (failed-tx) |
| External compliance export | ? | ? | ? | ? | ? |
| Identity provider / HR-system bridge | ? (`ReferenceIdSet`) | ? | ? | ? | ? |

---

## Indexer Integration Notes

- Subscribe **by contract address and topic discriminant** ? multiple
  contracts emit events that overlap by name (e.g. `CommitmentUpdated` is
  emitted by both `salary_commitment` and `payroll_registry`).
- Decode topics and data using `ScVal` (`Symbol`, `Address`, `u32`, `u64`,
  `i128`, `BytesN<N>`, tuples). The Stellar SDK's `EventFilter` is the
  recommended subscription mechanism.
- `i128` amount fields are **raw token units** ? divide by the token's
  decimal precision before storing or displaying.
- The two payment paths (`payment_executor` and legacy `payroll`) use
  different topic layouts ? normalise records to a common schema keyed on
  `(company_id, employee, period, amount, ledger_sequence)` to avoid
  double-counting.
- `company_id` is a `u64` integer in `payroll_registry` / `payment_executor`,
  but a `Symbol` string identifier in `audit_module`. Convert both to a
  stable off-chain UUID namespace when correlating across domains.
- Failed proof verifications do NOT emit an event ? monitor host-level
  transaction failures and parse reversion diagnostics instead.

---

## Compatibility & Versioning

- This document covers the v0 event surface emitted by `master`. Older
  deployments may emit the legacy `payment_executed` and `ViewKeyRevoked`
  names ? see [interop/proof-schema-version-negotiation.md](./interop/proof-schema-version-negotiation.md)
  for the negotiation protocol used when older and newer clients coexist.
- New events MUST be added here AND in [event-taxonomy.md](./monitoring/event-taxonomy.md)
  AND [event-severity-mappings.md](./monitoring/event-severity-mappings.md)
  before a release ships.
- Renaming an event is a **breaking change** ? use topic aliases during
  deprecation windows, and document the migration window in release notes.

---

## Quick Schema Tables (one-page crib sheet)

### Topics-only (no data)

| Event | Contract | topics |
|-------|----------|--------|
| `EmployeeRemoved` | `payroll_registry` | `("EmployeeRemoved", u64 company_id, Address employee)` |
| `CommitmentLocked` | `salary_commitment` | `("CommitmentLocked", Address employee)` |
| `CommitmentUnlocked` | `salary_commitment` | `("CommitmentUnlocked", Address employee)` |
| `AdminRotationAccepted` | `salary_commitment` | `("AdminRotationAccepted", Address new_admin)` |
| `AdminRotationCancelled` | `salary_commitment` | `("AdminRotationCancelled", Address current_admin)` |
| `PauseManager / paused` | `pause_manager` | `("PauseManager", "paused")` |
| `PauseManager / unpaused` | `pause_manager` | `("PauseManager", "unpaused")` |

### Tuples by topic shape

| Event | Contract | topics | data |
|-------|----------|--------|------|
| `EmployeeAdded` | `payroll_registry` | `(company_id, employee)` | `(commitment,)` |
| `CommitmentUpdated` | `salary_commitment` | `(employee)` | `(commitment,)` |
| `CommitmentUpdated` | `payroll_registry` | `(company_id, employee)` | `(new_commitment,)` |
| `CommitmentRotated` | `salary_commitment` | `(employee)` | `(old, new)` |
| `ReferenceIdSet` | `salary_commitment` | `(employee)` | `(reference_id,)` |
| `AdminRotationProposed` | `salary_commitment` | `(current_admin)` | `(new_admin,)` |
| `CompanyRegistered` | `payroll_registry` | `(company_id)` | `(admin, treasury)` |
| `PeriodCreated` | `payment_executor` | `(company_id)` | `(period_id,)` |
| `PeriodClosed` | `payment_executor` | `(company_id)` | `(period_id,)` |
| `PayrollProcessed` | `payment_executor` | `(company_id)` | `(employee, amount, period_id)` |
| `ViewKeyGenerated` | `audit_module` | `(auditor)` | `(key_bytes, expiration_ledger)` |
| `AuditAccessRevoked` | `audit_module` | `(admin, auditor)` | `(timestamp,)` |
| `AuditSuccessful` | `audit_module` | `(auditor)` | `(scope, keyed_stored)` |
| `AggregateAuditGenerated` | `audit_module` | `(auditor)` | `(company_id, period_start, period_end)` |
| `AuditSummaryExported` | `audit_module` | `(auditor)` | `(company_id, period_start, period_end, total)` |
| `PauseManager / op_proposed` | `pause_manager` | `("PauseManager", "op_proposed")` | `(current_operator, new_operator)` |
| `PauseManager / op_rotated` | `pause_manager` | `("PauseManager", "op_rotated")` | `Address new_operator` *(bare Address ? single-value data)* |
| `PauseManager / op_cancelled` | `pause_manager` | `("PauseManager", "op_cancelled")` | `Address current_operator` *(bare Address ? single-value data)* |

---

## Related Resources

| Reference | Path |
|-----------|------|
| Event taxonomy (canonical categories) | [docs/monitoring/event-taxonomy.md](./monitoring/event-taxonomy.md) |
| Event severity mappings | [docs/monitoring/event-severity-mappings.md](./monitoring/event-severity-mappings.md) |
| Alert rules | [docs/monitoring/alert-rules.md](./monitoring/alert-rules.md) |
| Payload examples | [docs/payload-examples.md](./payload-examples.md) |
| SLA operational targets | [docs/SLA_OPERATIONAL_TARGETS.md](./SLA_OPERATIONAL_TARGETS.md) |
| Health metrics | [docs/monitoring/health-metrics-observability.md](./monitoring/health-metrics-observability.md) |
| `payroll_registry` contract | `contracts/payroll_registry/src/lib.rs` |
| `salary_commitment` contract | `contracts/salary_commitment/src/lib.rs` |
| `payment_executor` contract | `contracts/payment_executor/src/lib.rs` |
| `audit_module` contract | `contracts/audit_module/src/lib.rs` |
| `pause_manager` contract | `contracts/pause_manager/src/lib.rs` |
| `proof_verifier` contract | `contracts/proof_verifier/src/lib.rs` |
| Legacy `payroll` contract | `contracts/payroll/src/lib.rs` |
