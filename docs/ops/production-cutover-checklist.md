# Production-like Environment Cutover Checklist

Use this checklist when moving from testnet workflows to a production-like
Stellar/Soroban environment. The goal is to make contract, SDK, dashboard, and
operations readiness visible before any irreversible deployment step begins.

## 1. Cutover ownership and scope

- [ ] **Cutover owner named** — one accountable operator owns the schedule,
  go/no-go decision, and rollback decision.
- [ ] **Environment target recorded** — document the target network, RPC URL,
  Horizon URL, network passphrase, and expected protocol version.
- [ ] **Change window approved** — confirm the deployment window, freeze period,
  and expected user impact with maintainers.
- [ ] **Cross-repo contacts identified** — list contract, SDK, dashboard, and
  support owners in the release thread.

## 2. Prerequisites

- [ ] **Preflight checklist complete** — finish the standard deployment checks
  in `docs/ops/preflight-deployment-checklist.md` before starting cutover work.
- [ ] **Rollback checklist reviewed** — confirm every rollback owner understands
  `docs/ops/rollback-checklist.md` and has the required keys and access.
- [ ] **WASM size checks clean** — run the WASM size regression workflow or the
  local commands in `docs/testing/wasm-size-regression-thresholds.md`.
- [ ] **Release artifacts pinned** — record Git commit SHA, contract WASM hashes,
  verification key hash, SDK package version, and dashboard build identifier.
- [ ] **Secrets available through approved stores** — no raw admin, deployer, or
  treasury secrets should be copied into chat, issue comments, or local env files.

## 3. Dependency readiness

Track each dependency with an owner, status, and link to the readiness issue or
PR. Do not cut over while a critical dependency is unresolved.

| Surface | Required readiness signal | Owner | Link |
|---------|---------------------------|-------|------|
| Contracts | Deployment manifest reviewed and checksums captured | Contracts | TBD |
| SDK | Contract IDs, network passphrase, and RPC config released | SDK | TBD |
| Dashboard | Feature flags and production-like config validated | Dashboard | TBD |
| Monitoring | Event taxonomy and severity mappings loaded | Ops | `docs/monitoring/event-taxonomy.md` |
| Support | Incident and rollback communication templates ready | Support | `docs/incident-response-playbook.md` |

## 4. Validation plan

- [ ] **Dry run completed** — rehearse deployment order in a staging or testnet
  environment using the same commands planned for cutover.
- [ ] **Contract initialization validated** — confirm every initialized contract
  returns expected admin, operator, token, verifier, and pause-manager addresses.
- [ ] **End-to-end payroll path tested** — run a representative payroll flow from
  SDK/dashboard entry point through contract invocation and reconciliation.
- [ ] **Monitoring smoke test complete** — emit or observe representative events
  and verify severity mappings reach the expected alert channel.
- [ ] **Access review complete** — verify only approved operators can deploy,
  initialize, pause, unpause, or rotate operational keys.

## 5. Go/no-go gate

Before go/no-go, the cutover owner posts a summary containing:

- Target environment and change window.
- Exact contract commit SHA and artifact checksums.
- SDK and dashboard versions that point at the new environment.
- Open risks, mitigations, and explicit rollback trigger thresholds.
- Confirmation from every dependency owner in the readiness table.

Proceed only after contract, SDK, dashboard, and operations owners acknowledge the
summary in the release thread.

## 6. Cutover execution

- [ ] **Freeze confirmed** — pause non-essential merges and deployments across
  dependent repos for the cutover window.
- [ ] **Deploy in documented order** — follow the order in the preflight
  checklist and record each contract address immediately.
- [ ] **Publish environment manifest** — share contract IDs, network passphrase,
  RPC URL, and artifact hashes with SDK/dashboard owners through approved
  channels.
- [ ] **Flip dependent config** — SDK and dashboard owners update environment
  config only after the manifest is published and checked.
- [ ] **Run post-cutover smoke tests** — repeat the validation plan against the
  production-like environment and capture evidence in the release thread.

## 7. Rollback and abort criteria

Abort or roll back if any of the following occur:

- Contract deployment or initialization produces an unexpected address, admin, or
  verifier configuration.
- WASM artifact hashes do not match the approved release manifest.
- SDK/dashboard smoke tests cannot complete against the deployed contracts.
- Monitoring fails to surface critical events in the expected alert channel.
- A key, secret, or privileged role is exposed to an unapproved location.

When rollback is triggered, stop new cutover actions, announce the decision in
the release thread, and execute `docs/ops/rollback-checklist.md`.

## 8. Communication and closeout

- [ ] **Status updates posted** — post start, deploy-complete, validation, and
  closeout updates to the agreed release channel.
- [ ] **Known issues documented** — capture deferred fixes, owner, severity, and
  follow-up issue links before ending the cutover window.
- [ ] **Runbook updates filed** — open PRs for any checklist step that was wrong,
  missing, or ambiguous.
- [ ] **Final decision recorded** — mark the cutover as completed, rolled back,
  or aborted with timestamp and operator signature.
