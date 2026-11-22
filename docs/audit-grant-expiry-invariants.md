# Auditor Grant Expiry Invariants

This document records the invariants that govern the lifecycle of an
`audit_module` auditor grant from expiry through retention and pruning. The
rules are enforced by `audit_module` and are covered by the focused suites
`audit_grant_expiry_safe_errors` and `audit_grant_expiry_adversarial`.

All ledger comparisons use the ledger **sequence**, not the timestamp. No
employee name, salary amount, or commitment value is exposed by any error or
event described here.

## State model

A grant has an `expiration_ledger` and an optional retention window chosen by
the administrator at prune time (`retention_ledgers`). Its lifecycle stage is
one of `Granted`, `Active`, `Revoked`, or `Pruned`.

Let `now` be the current ledger sequence, `exp` the grant's expiration ledger,
and `ret` the administrator-supplied retention window.

| Phase | Condition | `check_grant_expiry` | `prune_expired_view_key` |
|-------|-----------|----------------------|--------------------------|
| Active | `now <= exp` | `GrantNotExpired (22)` | `GrantNotExpired (22)` |
| Retained | `exp < now < exp + ret` | `GrantNotYetPrunable (23)` | `GrantNotYetPrunable (23)` |
| Prunable | `now >= exp + ret` | `Ok(())` | Removes the grant |

The expiration ledger is inclusive: a grant is still valid at `now == exp`.
The retention window is inclusive at its far edge: pruning succeeds exactly at
`now == exp + ret`.

`exp + ret` uses `saturating_add`. An overflowing retention can therefore never
wrap around and make a live grant appear prunable.

## Invariants

1. **Diagnostic and mutation agree.** `check_grant_expiry` and
   `prune_expired_view_key` apply identical phase predicates. A successful
   diagnostic always means the subsequent prune is allowed by expiry rules
   (authorization and pause state still apply).
2. **Diagnostics are pure.** `check_grant_expiry` is permissionless, read-only,
   and emits no events. A client may call it repeatedly while retrying an
   operation without changing state.
3. **Rejection is non-destructive.** Every rejected prune leaves the view-key
   record, its `key_bytes`, its expiration, its scope, and its lifecycle stage
   byte-for-byte unchanged. A failed prune never emits a prune event.
4. **Grantor-only pruning.** Only the address recorded as `granted_by` may
   prune a grant. Other administrators receive `NotKeyGranter (4)` even when
   the grant is prunable, and even with a valid signature of their own.
5. **Expiry is not a workaround for authorization.** A wrong grantor cannot
   shorten the grace period by choosing a different `retention_ledgers` value.
   The retention window is applied uniformly to the stored expiration.
6. **Renewal beats retention.** `refresh_view_key` may be called during the
   retention window by the grantor. It rotates `key_bytes`, sets a strictly
   later expiration, and returns the grant to the Active phase. A prune that
   was previously allowed by an older retention calculation is then rejected
   with `GrantNotExpired`.
7. **Cascade removal is atomic.** Pruning a parent removes every delegate key
   reachable from it, recursively, in the same invocation. No orphan delegate
   retains audit access after its parent is pruned.
8. **Isolation between auditors.** Expiry and pruning of one auditor's grant
   never alter another auditor's grant, key material, expiration, or lifecycle
   stage.
9. **Terminal states are final.** Pruning an already-pruned grant, or pruning a
   grant that was explicitly revoked, returns `KeyNotFound (1)`. There is no
   path that revives a pruned key.
10. **Pause dominates.** When a pause manager is configured and paused,
    pruning is rejected before any storage is read or written, regardless of
    the grant's phase.
11. **Privacy-safe errors.** `GrantNotExpired`, `GrantNotYetPrunable`, and
    `KeyNotFound` messages are fixed strings. They never include auditor
    identifiers, employee data, salary amounts, or commitments. `KeyExpired
    (3)` remains reserved for operations that genuinely require a fresh grant
    (verification and delegation), not for pruning gating.
12. **Exact expiration boundary (#890).** A grant is valid on its expiration
    ledger itself (`now == exp`) and expired from `exp + 1`, on every read
    path (`verify_access`, `is_grant_active`, `check_grant_expiry`) and for
    delegates, whose access also ends at the parent's `exp + 1`.
13. **No dead-on-arrival grants (#890).** `generate_view_key` and
    `delegate_view_key` reject `expiration_ledger < now` with
    `ExpirationInPast (24)`; `expiration_ledger == now` is accepted and valid
    for the current ledger only. Covered by `auditor_grant_exact_boundary`.

## Client guidance

- Call `check_grant_expiry(auditor, retention_ledgers)` before showing a prune
  control. Show "grant still active", "waiting for retention" or "ready to
  prune" based on the typed error, not on a client-side ledger guess.
- Do not auto-retry a prune after `GrantNotExpired` or `GrantNotYetPrunable`.
  The operator must renew the grant or wait for the retention window.
- Treat `NotKeyGranter` as a configuration problem, not a transient failure.
  The correct grantor address is the only valid signer.

## Related documents

- [Errors](./errors.md#audit-access)
- [Error taxonomy](./error-taxonomy.md#audit-access-200-299)
