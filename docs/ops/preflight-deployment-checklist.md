# Preflight Deployment Checklist — Issue #112

Run this checklist before any release action begins. Each item must be
checked off by the operator performing the deployment. The checklist is
suitable for rehearsals and production releases alike.

---

## 1. Network Configuration

- [ ] **Target network confirmed** — verify `stellar contract deploy` will
  target the intended network (`testnet` / `mainnet`). Run:
  ```bash
  stellar network ls
  ```
  Confirm the active network matches the release target.

- [ ] **RPC endpoint reachable** — ping the Horizon / RPC endpoint:
  ```bash
  curl -s <HORIZON_URL>/health | grep '"status":"good"'
  ```
  Expected: `"status":"good"`. Abort if unreachable.

- [ ] **Network passphrase matches** — confirm the passphrase in your
  Stellar CLI config matches the deployment target:
  - Testnet: `Test SDF Network ; September 2015`
  - Mainnet: `Public Global Stellar Network ; September 2015`

- [ ] **Protocol version checked** — confirm the network is running the
  protocol version required by the contracts (Protocol 21+):
  ```bash
  curl -s <HORIZON_URL> | jq '.core_supported_protocol_version'
  ```

---

## 2. Identity & Key Management

- [ ] **Deployer key loaded** — confirm the deployer keypair is available:
  ```bash
  stellar keys ls
  ```
  The deployment key must appear in the list.

- [ ] **Deployer account funded** — verify the deployer account has
  sufficient XLM for deployment fees:
  ```bash
  stellar account balance --source <DEPLOYER_KEY>
  ```
  Minimum recommended: 10 XLM above estimated fee total.

- [ ] **Admin key is separate from deployer key** — the contract admin
  address must not be the same as the deployment key to limit blast radius
  on key compromise.

- [ ] **Hardware wallet / HSM confirmation** (if applicable) — confirm the
  signing device is connected and responding before beginning deployment.

- [ ] **No key material in environment variables** — verify that no raw
  secret keys are set in shell env:
  ```bash
  env | grep -iE 'SECRET|PRIVATE|MNEMONIC|SEED'
  ```
  Expected: no output. Keys must be managed via Stellar CLI key store only.

---

## 3. Secret & Configuration Assumptions

- [ ] **Contract admin addresses recorded** — document the intended admin
  `Address` for each contract before deployment. These cannot be changed
  post-initialisation.

- [ ] **Treasury address confirmed** — the treasury `Address` that will
  hold payroll funds is correct and owned by the expected keypair.

- [ ] **Verifier VK artefacts present** — confirm `verification_key.json`
  is present and was generated from the correct `.zkey` file:
  ```bash
  ls -lh circuits/verification_key.json
  ```
  The file must exist and match the expected SHA-256 checksum recorded
  during the trusted setup ceremony.

- [ ] **Token contract address confirmed** — the SEP-41 token contract
  address to be used in `payment_executor` / `payroll` is correct for the
  target network.

- [ ] **No testnet addresses in mainnet config** — grep config files for
  known testnet contract IDs and confirm zero matches against mainnet deploy
  parameters.

---

## 4. Build Verification

- [ ] **Clean build passes** — run from workspace root:
  ```bash
  cargo build --target wasm32-unknown-unknown --release
  ```
  Expected: zero errors, zero warnings (treat warnings as errors in release).

- [ ] **Unit tests pass**:
  ```bash
  cargo test -p payroll_registry -p salary_commitment -p proof_verifier -p audit_module
  ```
  Expected: all tests pass, zero failures.

- [ ] **WASM artefacts present** — confirm WASM files exist for all five
  core contracts:
  ```bash
  ls target/wasm32-unknown-unknown/release/*.wasm
  ```
  Expected: `payroll_registry.wasm`, `salary_commitment.wasm`,
  `proof_verifier.wasm`, `payment_executor.wasm`, `audit_module.wasm`.

- [ ] **WASM sizes within limits** — Soroban enforces a contract size limit.
  Confirm each WASM is under 64 KB:
  ```bash
  wc -c target/wasm32-unknown-unknown/release/*.wasm
  ```

---

## 5. Deployment Order

Contracts must be deployed and initialised in this exact order due to
cross-contract address dependencies:

1. `token` (or confirm existing token contract address)
2. `proof_verifier` → call `init_verifier_admin`, then `initialize_verifier`
3. `salary_commitment` → call `init_commitment_admin`
4. `payroll_registry` (stateless init; no explicit init call required)
5. `pause_manager` → call `initialize`
6. `payment_executor` → call `initialize` with addresses from steps 1–4,
   then `set_executor_admin`, then `set_pause_manager`
7. `payroll` → call `initialize`, then `set_pause_manager`
8. `salary_commitment` → call `set_payroll_operator` with `payroll` contract address
9. `audit_module` (standalone; no cross-contract init dependency)

- [ ] Deployment order checklist above followed exactly.
- [ ] Each contract address captured immediately after deployment and
  recorded in the deployment manifest before proceeding to the next step.

---

## 6. Post-Deployment Smoke Tests

- [ ] **Verifier admin readable**:
  ```bash
  stellar contract invoke --id <VERIFIER_ADDR> -- get_verifier_admin
  ```
  Expected: returns the intended admin address.

- [ ] **Commitment admin readable**:
  ```bash
  stellar contract invoke --id <COMMITMENT_ADDR> -- get_commitment_admin
  ```
  Expected: returns the intended admin address.

- [ ] **Pause manager not paused**:
  ```bash
  stellar contract invoke --id <PAUSE_MGR_ADDR> -- is_paused
  ```
  Expected: `false`.

- [ ] **Register a test company** (testnet only — do not run on mainnet):
  ```bash
  stellar contract invoke --id <REGISTRY_ADDR> -- register_company \
    --admin <ADMIN_ADDR> --treasury <TREASURY_ADDR>
  ```
  Expected: returns `0` (first company ID).

---

## 7. Rollback Plan

- [ ] **Previous contract addresses recorded** — if upgrading, the old
  contract addresses are saved so traffic can be routed back if needed.
- [ ] **Pause manager accessible** — the on-call operator has the pause
  manager operator key and can call `pause` within 5 minutes if a critical
  issue is detected post-deployment.
- [ ] **Incident runbook link shared** — the team knows where the incident
  runbook is located before deployment begins.

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Operator | | | |
| Reviewer | | | |

> All items must be checked before the first `stellar contract deploy`
> command is executed in the release environment.
