# Retention and Audit-Grant Expiry Invariants

This document pins the behavior added for issues #969, #970, #975, and #977.
It is written for operators and indexers who need to know exactly when a
grant is active and when a retention window may change.

## 1. Audit-grant expiry (issues #969, #970)

### 1.1 Boundary convention

A view-key grant is active while:

```
ledger.sequence() <= expiration_ledger
```

It is expired starting at `expiration_ledger + 1`. The boundary is **inclusive**
of the expiration ledger. The same rule is used by `verify_access`,
`is_grant_active`, and the internal grant validator used by the data-access
paths. A delegated grant additionally requires its parent grant to be active,
its scope to be contained in the parent's `max_scope`, and its expiration not
to exceed either the parent's `max_expiration_ledger` or the parent's own
expiration.

### 1.2 Expired grants are immutable

Once a grant is expired, lifecycle mutations are rejected with `KeyExpired`:

- `refresh_view_key` may not extend an expired grant.
- `set_delegation_policy` and its alias `approve_delegation` may not change an
  expired grant's delegation settings.
- `extend_delegated_access` may not revive an expired delegate or an expired
  parent.

The only supported revival is a fresh `generate_view_key` call, which replaces
the record with an explicitly scoped new grant and emits a fresh
`ViewKeyGenerated` event. This keeps expiry meaningful: an attacker who obtains
an old grant cannot silently extend it.

### 1.3 Event behavior

A rejected mutation returns `KeyExpired` and, because Soroban rolls back failed
invocations, emits no visible event. Successful lifecycle changes emit the same
privacy-safe events as before (expiration ledger and addresses only; no salary
data, employee addresses, or commitment bytes).

## 2. Retention-window updates (issues #975, #977)

### 2.1 Two separate policy domains

There are two independent retention domains. They do not share storage:

| Domain | Contract | Entry point | Scope |
|--------|----------|-------------|-------|
| Global payroll policy | `payroll` | `set_retention_policy` | Whole payroll instance |
| Per-company override | `retention_manager` | `set_retention_override` | One `(company_id, RecordType)` |

The invariants below govern the **per-company override** in `retention_manager`.
The global `payroll` policy remains a separate domain and is not modified by
this work.

### 2.2 Monotonic effective window

Let `default(type)` be the built-in window for a record type and `current` be
the effective window (`current = override` when present, otherwise
`default(type)`).

- A non-zero `window_secs` must **strictly extend** `current`. A value less than
  or equal to `current` is rejected with `RetentionWindowShortened` (code 7).
- `window_secs == 0` clears the override, restoring `default(type)`. This is
  permitted only while `default(type) >= current`. In practice that means an
  override can be cleared only when retention has not been extended beyond the
  default.
- Every successful update emits a distinct `retention_override_set` event with
  `(company_id, record_type, previous_window_secs, new_window_secs)`. This is a
  separate schema from `retention_policy_set`; indexers must not confuse them.

### 2.3 Registration-time freeze

A `RetentionRecord` captures `eligible_after = registered_at + window` at
registration time. Changing an override never rewrites existing records. A
policy update therefore affects only records registered after the update.
Operators needing longer retention for existing records must not rely on an
override change; the records keep their original `eligible_after`.

### 2.4 Overflow handling

`eligible_after` uses `saturating_add`. An extreme timestamp or override cannot
panic; it saturates to `u64::MAX`, which means the record is retained
effectively forever.

### 2.5 Privacy

No event or error payload in this work carries a salary amount, employee
address, commitment, or record identifier beyond the opaque numeric IDs already
present in the retention API. New error variants are unit-only.
