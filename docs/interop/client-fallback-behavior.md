# Client Fallback Behavior for Older Contract Interfaces — Issue #97

Explains how SDK and dashboard clients should behave when they encounter a
contract version newer than they were built against, and what the supported
and unsupported downgrade paths are.

---

## Background

ZK Payroll contracts evolve across three independent axes:

1. **Proof schema** — the public input count and proof byte layout (governed by
   [proof-schema-version-negotiation.md](./proof-schema-version-negotiation.md)).
2. **Contract interface** — entry-point signatures and `#[contracttype]` struct
   shapes.
3. **Event shape** — topic and data fields emitted by contracts.

A deployed production environment may temporarily run a contract version that is
ahead of the client SDK or dashboard. This document defines what clients should
do in that scenario and which combinations are safe to operate.

---

## Compatibility Model

### Principle: No Silent Degradation

Clients MUST surface interface mismatches as distinct, actionable errors rather
than silently succeeding with incorrect behaviour. The following hard rules apply:

1. **Proof schema mismatches are hard rejections.** The `proof_verifier` contract
   returns `false` immediately when the public input count does not match the
   stored VK. Clients must not retry with the same inputs — they must regenerate
   the proof against the correct VK. See
   [proof-schema-version-negotiation.md](./proof-schema-version-negotiation.md).

2. **Entry-point signature changes are hard rejections.** Soroban encodes
   arguments as XDR. Sending the wrong number or type of arguments causes a
   transaction failure at the host level — there is no partial acceptance.

3. **Event schema additions are backward compatible.** Contracts may add new
   event fields to the `data` payload without breaking consumers that only
   read earlier fields. However, consumers MUST NOT assume a specific data
   length — iterate defensively.

4. **Event topic renames are breaking.** If an event topic `Symbol` changes,
   existing subscribers will stop receiving it. The taxonomy in
   [event-taxonomy.md](../monitoring/event-taxonomy.md) is the stable contract;
   deviations will be announced with a migration notice.

---

## Supported Fallback Scenarios

These scenarios are safe to operate and have defined handling paths.

### S1 — Old client, same proof schema, new non-breaking entry-point fields

**Situation:** The contract adds optional metadata to an existing entry-point
response struct (e.g., a new field on `PayrollRun`) but the core signature is
unchanged.

**Fallback:** The Soroban SDK deserialises known fields and ignores unknown
trailing fields in `#[contracttype]` structs. The old client can continue
operating. No action required.

**Risk:** Low. Verify by checking the PR that introduced the new field; it should
be appended to the struct and not inserted at a non-trailing position.

---

### S2 — Old client, new proof schema deployed on testnet only

**Situation:** A new verifier contract with a different VK (e.g., `ic.len()` changed)
is deployed on testnet while production still runs the old VK.

**Fallback:**
1. Read `vk.ic.len()` from the testnet verifier before generating any proofs.
2. Use that value to configure the circuit and proof generation tooling.
3. Do not submit testnet proofs to mainnet and vice versa — they will be rejected.
4. See the [Client Integration Checklist](./proof-schema-version-negotiation.md#client-integration-checklist)
   in the proof schema doc.

**Risk:** Low if network environments are kept separate. The verifier hard-rejects
mismatched inputs with no state change.

---

### S3 — Dashboard consuming stale event topics

**Situation:** A dashboard subscribed to `"PayrollProcessed"` events from
`payment_executor` does not yet handle the newer `"payment_executed"` topic
from the `payroll` facade (or vice versa), resulting in incomplete display.

**Fallback:**
1. Subscribe to both topic patterns during any transition window.
2. Normalise both event shapes to the common schema defined in
   [event-taxonomy.md](../monitoring/event-taxonomy.md#naming-inconsistencies-known).
3. The known naming inconsistency between the two payment paths is documented —
   see the "Naming Inconsistencies" section in the event taxonomy doc.

**Risk:** Low — duplicate events are not emitted; the two topics come from
different contracts. Missing one path means incomplete data, not corrupted data.

---

### S4 — Old client, pause manager added post-deployment

**Situation:** A client does not know the `pause_manager` address (it was set
after the client was configured) and submits a batch while the system is paused.

**Fallback:**
1. The `payroll` and `payment_executor` contracts panic with `"Payroll is paused"`
   when a pause manager is set and `is_paused()` returns `true`.
2. Clients should catch this panic (it surfaces as a failed transaction) and
   surface it as a distinct `PayrollPausedError` rather than a generic failure.
3. Clients should call `pause_manager.is_paused()` before each batch submission
   as a pre-flight check. The pause manager address should be discoverable via
   the operator's configuration endpoint.

**Risk:** Medium — a client unaware of the pause state will generate failed
transactions that consume fees. Build the pre-flight check.

---

## Unsupported Downgrade Paths

The following scenarios are explicitly unsupported. Clients or operators attempting
these paths will encounter hard failures that cannot be resolved without engineering
intervention.

| Scenario | Why it is unsupported | Recommended action |
|----------|-----------------------|-------------------|
| **Submitting v0 proofs (3 public inputs) to a v1 verifier** | VK `ic.len()` mismatch; `verify_payment_proof` returns `false` immediately | Regenerate proofs against the v1 circuit; see proof schema doc |
| **Calling `initialize_verifier` a second time on an existing verifier** | Contract panics with `"Verifier already initialized"` | Deploy a new `proof_verifier` instance; no in-place re-init |
| **Calling `initialize` on `payroll` or `payment_executor` a second time** | Contracts panic with `"Already initialized"` | Contracts are single-init; a new deployment is required for address changes |
| **Routing payments to a period that has been closed** | `payment_executor` returns `PaymentError::PeriodClosed (5)` | Open a new period; closed periods are immutable |
| **Reading a `PayrollRun` by a run_id that was never written** | `payroll` panics with `"Run not found"` | Run IDs are contiguous starting at 1; query `RunCounter` to find the valid range |
| **Using a revoked salary commitment for proof generation** | `salary_commitment.is_commitment_active()` returns `false`; on-chain proof will fail | Fetch the current active commitment via `get_commitment` before generating proofs |
| **Submitting a proof with an already-used nullifier** | `payment_executor` returns `PaymentError::ProofAlreadyUsed (1)` or `salary_commitment` panics with `"Nullifier already used"` | Generate a fresh proof with a new nullifier; do not reuse nullifiers |

---

## Migration Planning Guide

When a new contract interface or proof schema version is being rolled out, client
teams should plan their upgrade using the following steps.

### Before the upgrade window

1. Read the PR or release notes to identify which of the three axes changed
   (proof schema, contract interface, event shape).
2. If proof schema changed: follow the
   [Upgrade Procedure](./proof-schema-version-negotiation.md#upgrade-procedure) in
   the proof schema doc.
3. If contract interface changed: test the new entry-point signatures against
   the testnet deployment before the production cutover.
4. If event shape changed: update indexer consumers to handle both old and new
   shapes during the transition window; remove old handling after cutover.

### During the upgrade window

- Expect brief unavailability if a `pause` is issued during the upgrade.
- Subscribe to `PauseManager/paused` and `PauseManager/unpaused` events to track
  the upgrade window automatically.
- Do not submit new payroll batches until `PauseManager/unpaused` is received.

### After the upgrade

- Confirm the new contract addresses from the deployment manifest.
- Run the [Client Integration Checklist](./proof-schema-version-negotiation.md#client-integration-checklist)
  against the new verifier address.
- Monitor for 3 consecutive successful payroll runs before reducing alert
  sensitivity to pre-upgrade levels.

---

## Error Code Reference

Clients should map contract error codes to user-facing messages. Known error
codes across the payment path:

| Contract | Error code | Enum variant | Recommended client message |
|----------|-----------|--------------|---------------------------|
| `payment_executor` | `1` | `ProofAlreadyUsed` | "This payment proof has already been used. Generate a new proof." |
| `payment_executor` | `2` | `ArrayLengthMismatch` | "Batch input arrays have mismatched lengths. Check serialisation." |
| `payment_executor` | `3` | `AlreadyPaid` | "This employee has already been paid for this period." |
| `payment_executor` | `4` | `PeriodNotFound` | "Payroll period does not exist. Create a period before submitting payments." |
| `payment_executor` | `5` | `PeriodClosed` | "Payroll period is closed. Open a new period." |
| `payment_executor` | `6` | `PeriodAlreadyExists` | "A period already exists for this company. Close it before creating a new one." |
| `audit_module` | `1` | `KeyNotFound` | "No view key found for this auditor." |
| `audit_module` | `2` | `WrongAuditor` | "Caller is not the designated auditor for this key." |
| `audit_module` | `3` | `KeyExpired` | "Auditor view key has expired. Request a new key." |
| `audit_module` | `4` | `NotKeyGranter` | "Caller did not grant this key and cannot revoke it." |
| `audit_module` | `5` | `InsufficientScope` | "View key scope does not permit this operation." |
| `audit_module` | `6` | `CommitmentMismatch` | "Claimed salary does not match the stored commitment." |
| `audit_module` | `7` | `InvalidViewKey` | "Supplied view key material is incorrect." |

---

## Related Resources

| Reference | Path |
|-----------|------|
| Proof schema version negotiation | [docs/interop/proof-schema-version-negotiation.md](./proof-schema-version-negotiation.md) |
| Event taxonomy | [docs/monitoring/event-taxonomy.md](../monitoring/event-taxonomy.md) |
| Event severity mappings | [docs/monitoring/event-severity-mappings.md](../monitoring/event-severity-mappings.md) |
| Preflight deployment checklist | [docs/ops/preflight-deployment-checklist.md](../ops/preflight-deployment-checklist.md) |
| Rollback checklist | [docs/ops/rollback-checklist.md](../ops/rollback-checklist.md) |
| SLA operational targets | [docs/SLA_OPERATIONAL_TARGETS.md](../SLA_OPERATIONAL_TARGETS.md) |
| Payload examples | [docs/payload-examples.md](../payload-examples.md) |

---

*Closes Issue [#97](https://github.com/zkpayroll/zk-payroll-contracts/issues/97)*
