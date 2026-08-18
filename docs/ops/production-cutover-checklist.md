# Production-like Environment Cutover Checklist

Use this checklist when moving from testnet workflows to a production-like
Stellar/Soroban environment. The goal is to make contract, SDK, dashboard, and
operations readiness visible before any irreversible deployment step begins.

This guide is intentionally cross-repo: keep a single release thread or issue as
the source of truth, and link the readiness issues for every dependent surface
before scheduling the cutover.

## 1. Cutover ownership and scope

- [ ] **Cutover owner named** — one accountable operator owns the schedule,
  go/no-go decision, and rollback decision.
- [ ] **Environment target recorded** — document the target network, RPC URL,
  Horizon URL, network passphrase, protocol version, and ledger retention
  assumptions.
- [ ] **Change window approved** — confirm the deployment window, freeze period,
  expected user impact, and the latest rollback decision time with maintainers.
- [ ] **Cross-repo contacts identified** — list contract, SDK, dashboard,
  monitoring, support, and communications owners in the release thread.
- [ ] **Release channel selected** — confirm where status updates, go/no-go
  acknowledgements, incident notices, and closeout notes will be posted.

## 2. Prerequisites

- [ ] **Preflight checklist complete** — finish the standard deployment checks
  in [preflight-deployment-checklist.md](./preflight-deployment-checklist.md)
  before starting cutover work.
- [ ] **Rollback checklist reviewed** — confirm every rollback owner understands
  [rollback-checklist.md](./rollback-checklist.md) and has the required keys and
  access.
- [ ] **Incident response roles assigned** — name the incident lead,
  communications lead, and technical leads from the
  [incident response playbook](../incident-response-playbook.md).
- [ ] **WASM size checks clean** — run the WASM size regression workflow or the
  local commands in
  [wasm-size-regression-thresholds.md](../testing/wasm-size-regression-thresholds.md).
- [ ] **Release artifacts pinned** — record Git commit SHA, contract WASM hashes,
  verification key hash, SDK package version, dashboard build identifier, and
  feature flag set.
- [ ] **Deployment manifest prepared** — pre-create the manifest that will hold
  old and new contract IDs, artifact checksums, initialization arguments,
  operator addresses, ledger numbers, and validation evidence.
- [ ] **Secrets available through approved stores** — no raw admin, deployer, or
  treasury secrets should be copied into chat, issue comments, or local env
  files.

## 3. Dependency readiness

Track each dependency with an owner, status, and link to the readiness issue or
PR. Do not cut over while a critical dependency is unresolved. Replace every
`TBD` with a concrete issue, PR, release, or runbook link before go/no-go.

| Surface | Required readiness signal | Owner | Link |
|---------|---------------------------|-------|------|
| Contracts | Deployment manifest reviewed, checksums captured, and initialization arguments approved | Contracts | TBD |
| SDK | Contract IDs, network passphrase, RPC config, proof schema, and package version released | SDK | [Proof schema negotiation](../interop/proof-schema-version-negotiation.md) |
| Dashboard | Feature flags, API base URLs, wallet/network labels, and production-like config validated | Dashboard | TBD |
| Reconciliation/indexer | Event ingestion, payment status mapping, and replay/retry behavior validated | Data/Ops | [Reconciliation status](../interop/reconciliation-status.md) |
| Monitoring | Event taxonomy and severity mappings loaded into alerting | Ops | [Event taxonomy](../monitoring/event-taxonomy.md), [severity mappings](../monitoring/event-severity-mappings.md) |
| Support | Incident, rollback, and customer-facing communication templates ready | Support | [Incident response playbook](../incident-response-playbook.md) |
| Operations | SLA targets, on-call coverage, and escalation path confirmed | Ops | [SLA operational targets](../SLA_OPERATIONAL_TARGETS.md) |

### Readiness issue template

Use this minimal structure for each linked readiness issue:

```md
## Readiness signal
- Owner:
- Repository/surface:
- Required version or commit:
- Validation evidence:
- Rollback owner:
- Open risks:
- Go/no-go status: Pending / Ready / Blocked
```

## 4. Validation plan

Complete validation in testnet or staging first, then repeat the smoke-test
subset after production-like cutover.

- [ ] **Dry run completed** — rehearse deployment order in a staging or testnet
  environment using the same commands planned for cutover.
- [ ] **Contract initialization validated** — confirm every initialized contract
  returns expected admin, operator, token, verifier, registry, commitment, and
  pause-manager addresses.
- [ ] **End-to-end payroll path tested** — run a representative payroll flow from
  SDK/dashboard entry point through contract invocation and reconciliation.
- [ ] **Proof compatibility checked** — submit at least one known-good proof and
  one intentionally invalid proof to confirm verifier and SDK behavior match the
  target proof schema.
- [ ] **Dashboard configuration checked** — verify the dashboard shows the target
  network, does not expose testnet labels or contract IDs, and can display the
  post-cutover payroll status.
- [ ] **Monitoring smoke test complete** — emit or observe representative events
  and verify severity mappings reach the expected alert channel.
- [ ] **Access review complete** — verify only approved operators can deploy,
  initialize, pause, unpause, or rotate operational keys.
- [ ] **Evidence captured** — attach command output, transaction hashes, ledger
  numbers, screenshots where useful, and owner sign-offs to the release thread.

## 5. Go/no-go gate

Before go/no-go, the cutover owner posts a summary containing:

- Target environment and change window.
- Exact contract commit SHA and artifact checksums.
- SDK and dashboard versions that point at the new environment.
- Deployment manifest link, including old and new contract IDs where applicable.
- Open risks, mitigations, abort criteria, and explicit rollback trigger
  thresholds.
- Confirmation from every dependency owner in the readiness table.

Proceed only after contract, SDK, dashboard, monitoring, support, and operations
owners acknowledge the summary in the release thread. If any critical owner is
unavailable, postpone the cutover instead of treating silence as approval.

## 6. Cutover execution

- [ ] **Freeze confirmed** — pause non-essential merges and deployments across
  dependent repos for the cutover window.
- [ ] **Final config diff reviewed** — compare the production-like environment
  config against the last successful testnet config and explicitly approve all
  differences.
- [ ] **Deploy in documented order** — follow the order in the preflight
  checklist and record each contract address immediately.
- [ ] **Publish environment manifest** — share contract IDs, network passphrase,
  RPC URL, Horizon URL, artifact hashes, and ledger numbers with SDK/dashboard
  owners through approved channels.
- [ ] **Flip dependent config** — SDK and dashboard owners update environment
  config only after the manifest is published and checked.
- [ ] **Run post-cutover smoke tests** — repeat the validation plan against the
  production-like environment and capture evidence in the release thread.
- [ ] **Monitor the stabilization window** — keep owners online until the agreed
  number of successful payroll flows, event ingestions, and dashboard refreshes
  complete.

## 7. Rollback and abort criteria

Abort or roll back if any of the following occur:

- Contract deployment or initialization produces an unexpected address, admin,
  operator, token, verifier, registry, commitment, or pause-manager
  configuration.
- WASM artifact hashes do not match the approved release manifest.
- SDK/dashboard smoke tests cannot complete against the deployed contracts.
- Proof verification accepts an invalid proof or rejects a known-good proof.
- Reconciliation/indexer state diverges from contract events or cannot process
  new payment events within the agreed SLA.
- Monitoring fails to surface critical events in the expected alert channel.
- A key, secret, or privileged role is exposed to an unapproved location.
- The rollback decision time is reached before validation is complete.

When rollback is triggered, stop new cutover actions, announce the decision in
the release thread, and execute [rollback-checklist.md](./rollback-checklist.md).
Record any state written during the failed window so reconciliation owners can
prevent duplicate payroll runs or replay gaps.

## 8. Communication and closeout

- [ ] **Status updates posted** — post start, deploy-complete, validation,
  rollback-if-needed, and closeout updates to the agreed release channel.
- [ ] **Dependent teams notified** — explicitly notify SDK, dashboard,
  monitoring, support, and operations owners when the manifest is published,
  config is flipped, validation passes, or rollback starts.
- [ ] **Known issues documented** — capture deferred fixes, owner, severity,
  customer impact, and follow-up issue links before ending the cutover window.
- [ ] **Runbook updates filed** — open PRs for any checklist step that was wrong,
  missing, or ambiguous.
- [ ] **Final decision recorded** — mark the cutover as completed, rolled back,
  or aborted with timestamp, operator signature, manifest link, and validation
  evidence.
