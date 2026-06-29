# Deployment Rollback Checklist — Issue #98

Use this checklist when a contract deployment or upgrade needs to be reverted.
It applies to both testnet rehearsals and production incidents. Every item must
be checked by the operator before marking the rollback complete.

---

## Rollback Triggers

Initiate a rollback when any of the following conditions are confirmed:

| Trigger | Description |
|---------|-------------|
| **Smoke test failure** | Any post-deployment smoke test in the preflight checklist fails on a live network |
| **Proof verification regression** | `verify_payment_proof` returns `false` for proofs that passed on the previous deployment |
| **Auth bypass detected** | A state-mutating entry-point accepts a call that should have been rejected |
| **Nullifier storage fault** | Replay protection fails or a nullifier is written to `Temporary` instead of `Persistent` storage |
| **Pause manager unresponsive** | `is_paused()` returns an unexpected value or the operator key cannot reach the contract |
| **Treasury misconfiguration** | Post-deployment treasury address or treasury owner does not match the deployment manifest |
| **Circuit / VK mismatch** | The deployed verification key does not match the checksum recorded during the trusted setup ceremony |
| **Critical error rate** | Any single operation exceeds a 5% error rate within 30 minutes of deployment |

---

## Prerequisites Before Starting Rollback

- [ ] **Pause payroll immediately** — call `pause` on the `pause_manager` contract before any
  rollback action to stop new payments while the environment is inconsistent.
  ```bash
  stellar contract invoke --id <PAUSE_MGR_ADDR> -- pause
  stellar contract invoke --id <PAUSE_MGR_ADDR> -- is_paused
  # Expected: true
  ```

- [ ] **Previous contract addresses available** — confirm the old contract addresses were
  recorded in the deployment manifest before the upgrade. If unavailable, check git history
  and deployment logs before proceeding.

- [ ] **Operator key accessible** — the on-call operator holds the pause manager operator key
  and the relevant contract admin keys. Verify signing device is responsive.

- [ ] **Incident lead assigned** — at least one person owns the rollback timeline. See the
  [Incident Response Playbook](../incident-response-playbook.md) for role definitions.

- [ ] **Affected scope documented** — note which contract(s) were upgraded, the block/ledger
  at which the upgrade was applied, and whether any state was written to the new contract
  before the rollback was triggered.

---

## Rollback Steps

### Step 1 — Contain

1. Pause the affected contract(s) via `pause_manager`.
2. Notify the on-call team using the internal alert template in the
   [Incident Response Playbook](../incident-response-playbook.md#communication-templates).
3. Capture the failed deployment's contract addresses and ledger range.

### Step 2 — Restore Contract Pointers

Route traffic back to the previous contract version by updating the address
references in any contracts that depend on the upgraded one.

The dependency chain is (see deployment order in [preflight checklist](./preflight-deployment-checklist.md)):

```
payroll / payment_executor
  └── proof_verifier   (ContractAddresses.verifier)
  └── salary_commitment (ContractAddresses.commitment)
  └── token            (ContractAddresses.token)
  └── payroll_registry (ContractAddresses.registry)
```

For each affected dependency:

- [ ] Confirm the old contract address is live and responding:
  ```bash
  stellar contract invoke --id <OLD_CONTRACT_ADDR> -- get_verifier_admin
  # or equivalent read-only call for that contract
  ```
- [ ] If the upgraded contract exposed a setter to update addresses (e.g.,
  `set_executor_admin`, `set_pause_manager`), call it with the old address.
  If no setter exists, a new deployment of the *caller* contract pointing to
  the old dependency address may be required.
- [ ] Record each restored address in the rollback manifest.

### Step 3 — Verify Rollback State

- [ ] **Verifier admin readable on old contract**:
  ```bash
  stellar contract invoke --id <OLD_VERIFIER_ADDR> -- get_verifier_admin
  ```
  Expected: returns the intended admin address.

- [ ] **Proof acceptance restored** — submit a known-good test proof against
  the old verifier on testnet and confirm it returns `true`.

- [ ] **Commitment lookup works** — call `get_commitment` on the old
  `salary_commitment` address for a known employee and confirm it returns the
  expected value.

- [ ] **Nullifier set intact** — if the new contract wrote any nullifiers before
  rollback, verify those nullifiers are also present in the old contract or
  document them as requiring manual reconciliation.

- [ ] **Pause manager still points to the correct contracts** — re-run the
  `is_paused()` check and confirm the pause manager operator key can unpause.

### Step 4 — State Validation After Rollback

Salary commitments and nullifiers are stored in `Persistent` storage and are
not automatically migrated between contract versions. Validate:

| Item | Validation |
|------|------------|
| Commitments | All employee commitments from before the failed upgrade are accessible on the old contract address |
| Nullifiers | Any nullifiers written during the failed deployment window are identified; if written to the new (now-abandoned) contract, they must be recorded off-chain to prevent accidental reuse |
| Payment records | `PaymentRecord` entries written during the failed window are audited; any duplicate payment risk is flagged to the Incident Lead |
| Run counter | The payroll run counter (`RunCounter` in `payroll` contract) reflects the expected value; no phantom run IDs were committed |

- [ ] State validation items above confirmed.
- [ ] Rollback manifest updated with any orphaned state entries.

### Step 5 — Unpause and Monitor

- [ ] Unpause the contract once state validation passes:
  ```bash
  stellar contract invoke --id <PAUSE_MGR_ADDR> -- unpause
  stellar contract invoke --id <PAUSE_MGR_ADDR> -- is_paused
  # Expected: false
  ```
- [ ] Submit one monitored payroll batch (testnet) or a small representative
  batch (production) and confirm it completes without error.
- [ ] Monitor for 3 consecutive successful batches before declaring the
  rollback closed.

---

## Post-Rollback

- [ ] **Root cause documented** — open a follow-up issue describing what went
  wrong with the failed upgrade and what must change before re-attempting.
- [ ] **Deployment manifest archived** — save the failed deployment's contract
  addresses and the rollback manifest in `docs/post-incident/` using the
  filename format `YYYY-MM-DD-rollback-<short-slug>.md`.
- [ ] **Preflight checklist updated** — if a gap in the preflight checklist
  allowed the bad deployment through, update
  [docs/ops/preflight-deployment-checklist.md](./preflight-deployment-checklist.md).
- [ ] **Incident report filed** — for any production rollback, a written
  post-incident review is required within 7 days (see the Incident Response
  Playbook for the template).

---

## Unsupported Rollback Paths

The following scenarios cannot be handled by this checklist alone and require
engineering escalation:

| Scenario | Reason |
|----------|--------|
| Nullifiers written to new contract only | Persistent storage is not migrated; manual reconciliation is required to avoid replay gaps |
| Treasury drained before rollback | On-chain transfers are irreversible; requires out-of-band remediation |
| Verifier VK overwritten | `initialize_verifier` panics on a second call; a fresh contract deploy is required — re-initialization on the same address is not possible |
| Run counter rolled back | The run counter is monotonic by design; rewinding it would create run ID collisions |
| Commitment history corrupted | Archived `CommitmentSnapshot` entries are append-only; corrupted history requires off-chain audit support |

---

## Related Resources

| Reference | Path |
|-----------|------|
| Preflight deployment checklist | [docs/ops/preflight-deployment-checklist.md](./preflight-deployment-checklist.md) |
| Incident response playbook | [docs/incident-response-playbook.md](../incident-response-playbook.md) |
| Proof schema version negotiation | [docs/interop/proof-schema-version-negotiation.md](../interop/proof-schema-version-negotiation.md) |
| SLA operational targets | [docs/SLA_OPERATIONAL_TARGETS.md](../SLA_OPERATIONAL_TARGETS.md) |
| Pause manager contract | `contracts/pause_manager/src/lib.rs` |
| Payment executor security tests | `contracts/payment_executor/tests/security_tests.rs` |

---

*Closes Issue [#98](https://github.com/zkpayroll/zk-payroll-contracts/issues/98)*
