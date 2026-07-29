# Deployment Verification Checklist

> **Purpose:** A step-by-step checklist an operator runs **immediately after
> deploying the ZK Payroll contract suite** to confirm every contract is
> live, correctly initialized, wired to its dependencies, pointed at the
> intended network, and behaving end-to-end before any real payroll is
> processed.
>
> **When to run it:** After each fresh deployment (testnet or mainnet), after
> redeploying any single contract, and as a pre-cutover gate before handing a
> deployment to production. Work top to bottom — do not skip to the Smoke
> Tests before the initialization and wiring checks pass. If any step fails,
> jump to [Rollback Procedure](#6-rollback-procedure).
>
> Related docs: [deployment.md](deployment.md),
> [ops/preflight-deployment-checklist.md](ops/preflight-deployment-checklist.md),
> [ops/production-cutover-checklist.md](ops/production-cutover-checklist.md),
> [ops/rollback-checklist.md](ops/rollback-checklist.md).

All commands use the unified **`stellar`** CLI (the `soroban` CLI is
equivalent — `soroban contract …` accepts the same subcommands where noted).
Replace every `<ALL_CAPS>` placeholder with your real value before running.

The five contracts and their release WASM artifacts:

| Contract | Struct | WASM artifact |
|----------|--------|---------------|
| `payroll_registry` | `PayrollRegistry` | `payroll_registry.wasm` |
| `salary_commitment` | `SalaryCommitmentContract` | `salary_commitment.wasm` |
| `proof_verifier` | `ProofVerifier` | `proof_verifier.wasm` |
| `payment_executor` | `PaymentExecutor` | `payment_executor.wasm` |
| `audit_module` | `AuditModule` | `audit_module.wasm` |

---

## 1. Pre-Deployment

### Required tools and versions

Confirm each tool meets the minimum version from the project [README](../README.md):

- [ ] Rust `1.74+` — `rustc --version`
- [ ] Soroban CLI `v21+` — `soroban --version`
- [ ] Stellar CLI `v21+` — `stellar --version`
- [ ] Node.js `18+` (required by snarkjs / circom WASM output) — `node --version`
- [ ] Circom `2.1+` — `circom --version`
- [ ] `wasm32-unknown-unknown` target installed — `rustup target list --installed | grep wasm32-unknown-unknown`

### Environment variables

Set the following before deploying so the commands below are copy-pasteable.
These names follow the convention already used in
[deployment.md](deployment.md) and [scripts/demo.sh](../scripts/demo.sh):

- [ ] `NETWORK` — target network name (`testnet` or `mainnet`)

```bash
export NETWORK=testnet
```

- [ ] `SOURCE` — the identity/keypair name used to sign deploy + init txns

```bash
export SOURCE=admin
```

- [ ] Contract-ID variables, exported as each contract is deployed:

```bash
export TOKEN_ID=<TOKEN_CONTRACT_ID> REGISTRY_ID=<REGISTRY_CONTRACT_ID> COMMITMENT_ID=<COMMITMENT_CONTRACT_ID> VERIFIER_ID=<VERIFIER_CONTRACT_ID> EXECUTOR_ID=<EXECUTOR_CONTRACT_ID> AUDIT_ID=<AUDIT_CONTRACT_ID>
```

### Network config verification

- [ ] The target network is registered in the CLI with the correct RPC URL and passphrase.

Add / verify **testnet** (values from [deployment.md](deployment.md)):

```bash
stellar network add testnet --rpc-url https://soroban-testnet.stellar.org:443 --network-passphrase "Test SDF Network ; September 2015"
```

Add / verify **mainnet** (public network passphrase is fixed; supply your own RPC provider URL):

```bash
stellar network add mainnet --rpc-url <MAINNET_RPC_URL> --network-passphrase "Public Global Stellar Network ; September 2015"
```

- [ ] List configured networks and confirm the passphrase matches the intended environment:

```bash
stellar network ls
```

- [ ] **Guard rail:** confirm you are NOT accidentally pointed at mainnet for a test deploy (and vice-versa):

```bash
echo "Deploying to: $NETWORK"
```

### Wallet / keypair checks

- [ ] The signing identity exists locally:

```bash
stellar keys ls
```

- [ ] Print the public address that will own/admin the deployment and confirm it is the intended key:

```bash
stellar keys address $SOURCE
```

- [ ] The signing account is funded with sufficient XLM for deploy + init fees. On testnet, fund via friendbot:

```bash
stellar keys fund $SOURCE --network $NETWORK
```

- [ ] (Mainnet) Confirm the account balance is non-zero and adequate by inspecting the account on-chain:

```bash
stellar keys address $SOURCE
```

---

## 2. Contract Deployment Verification

Run these for **each of the five contracts**. Repeat the block substituting the
matching contract-ID variable (`$REGISTRY_ID`, `$COMMITMENT_ID`,
`$VERIFIER_ID`, `$EXECUTOR_ID`, `$AUDIT_ID`).

### 2.1 Confirm the contract was deployed

`stellar contract fetch` downloads the deployed WASM; a non-empty response
confirms code exists at that contract ID.

- [ ] `payroll_registry` deployed:

```bash
stellar contract fetch --id $REGISTRY_ID --network $NETWORK --out-file /tmp/fetched_registry.wasm
```

- [ ] `salary_commitment` deployed:

```bash
stellar contract fetch --id $COMMITMENT_ID --network $NETWORK --out-file /tmp/fetched_commitment.wasm
```

- [ ] `proof_verifier` deployed:

```bash
stellar contract fetch --id $VERIFIER_ID --network $NETWORK --out-file /tmp/fetched_verifier.wasm
```

- [ ] `payment_executor` deployed:

```bash
stellar contract fetch --id $EXECUTOR_ID --network $NETWORK --out-file /tmp/fetched_executor.wasm
```

- [ ] `audit_module` deployed:

```bash
stellar contract fetch --id $AUDIT_ID --network $NETWORK --out-file /tmp/fetched_audit.wasm
```

**Expected output:** each command writes a `.wasm` file with no error. A
`Contract not found` / non-zero exit means the deploy did not land — go to
[Rollback Procedure](#6-rollback-procedure).

### 2.2 Verify the contract ID matches what was deployed

- [ ] Confirm the fetched WASM matches the locally built artifact (byte-identical hash) for each contract. Example for the registry:

```bash
cmp /tmp/fetched_registry.wasm target/wasm32-unknown-unknown/release/payroll_registry.wasm
```

**Expected output:** no output and exit code `0` (files are identical). Any
`differ` line means the deployed code is not the build you expected.

- [ ] The contract ID you recorded matches the one you are invoking (inspect the interface — a valid deployed contract lists its functions):

```bash
stellar contract info interface --id $REGISTRY_ID --network $NETWORK
```

**Expected output:** the function list for the contract (e.g. `register_company`,
`add_employee`, `get_company` for the registry).

### 2.3 Expected initialization state after deploy

Each contract has a distinct init contract. Confirm the post-init state:

- [ ] **`payroll_registry`** — has no global init entrypoint; state begins empty
  and the company counter starts at `0`. First `register_company` returns
  company ID `0`. (Optional) a pause manager can be wired via
  `set_pause_manager(admin, pause_manager)`.
- [ ] **`salary_commitment`** — `init_commitment_admin(admin)` has been called
  exactly once (a second call panics with `Already initialized`). Confirm via
  `get_commitment_admin` (see §3).
- [ ] **`proof_verifier`** — `init_verifier_admin(admin)` **and**
  `initialize_verifier(vk)` have both been called (each panics with
  `Already initialized` / `Verifier already initialized` on a second call).
  Confirm via `get_verifier_admin` and `get_verification_key` (see §3 / §4).
- [ ] **`payment_executor`** — `initialize(addresses)` has been called (panics
  `Already initialized` on repeat) and `set_executor_admin(admin)` has been
  set (panics `Executor admin already set` on repeat). Confirm storage schema
  version and the initial allowed asset:

```bash
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network $NETWORK -- get_storage_version
```

**Expected output:** `1`

```bash
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network $NETWORK -- is_asset_allowed --asset $TOKEN_ID
```

**Expected output:** `true` (the token passed into `initialize` is
auto-allowlisted).

- [ ] **`audit_module`** — has no admin-init entrypoint; the view-key granter is
  the contract's own address. State begins empty (`get_audit_log_count`
  returns `0`). (Optional) wire a pause manager via
  `set_pause_manager(admin, pause_manager)`.

---

## 3. Admin Role Verification

### 3.1 `salary_commitment` admin (HR admin)

- [ ] Confirm the stored HR admin address matches `<ADMIN_ADDRESS>`:

```bash
stellar contract invoke --id $COMMITMENT_ID --source $SOURCE --network $NETWORK -- get_commitment_admin
```

**Expected output:** `"<ADMIN_ADDRESS>"`

- [ ] (If a payroll operator was delegated) confirm it is the intended address:

```bash
stellar contract invoke --id $COMMITMENT_ID --source $SOURCE --network $NETWORK -- get_payroll_operator
```

**Expected output:** `"<OPERATOR_ADDRESS>"` or `null` if none was set.

### 3.2 `proof_verifier` admin

- [ ] Confirm the verifier admin matches `<ADMIN_ADDRESS>`:

```bash
stellar contract invoke --id $VERIFIER_ID --source $SOURCE --network $NETWORK -- get_verifier_admin
```

**Expected output:** `"<ADMIN_ADDRESS>"`

### 3.3 `payment_executor` admin

`payment_executor` stores an `ExecutorAdmin` but exposes **no getter** for it.
Verify indirectly:

- [ ] Confirm an admin-gated call succeeds only for the real admin — re-setting
  an allowlist flag as `$SOURCE` should succeed if `$SOURCE` is the executor
  admin, and fail with an authorization error otherwise:

```bash
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network $NETWORK -- set_asset_allowed --asset $TOKEN_ID --allowed true
```

**Expected output:** succeeds (returns no value) when `$SOURCE` is the executor
admin; an authorization/`require_auth` error confirms `$SOURCE` is not admin.

### 3.4 `payroll_registry` per-company admin + treasury

The registry has no global admin — admin and treasury are stored **per company**
in `CompanyInfo`. After registering a company:

- [ ] Confirm the company admin and treasury are set correctly:

```bash
stellar contract invoke --id $REGISTRY_ID --source $SOURCE --network $NETWORK -- get_company --company_id <COMPANY_ID>
```

**Expected output:** a JSON object `{"admin":"<ADMIN_ADDRESS>","treasury":"<TREASURY_ADDRESS>"}`
— confirm both fields match the intended addresses.

### 3.5 `audit_module` granter

- [ ] Note: `audit_module` stores no admin address; generated view keys record
  `granted_by = <the audit_module contract address>`. There is no admin query
  to run here. Confirm instead there are no unexpected pre-existing keys/logs:

```bash
stellar contract invoke --id $AUDIT_ID --source $SOURCE --network $NETWORK -- get_audit_log_count --company_id default
```

**Expected output:** `0` on a fresh deploy.

---

## 4. Network Config Verification

### 4.1 Correct network (testnet vs mainnet)

- [ ] Confirm the passphrase configured for `$NETWORK` is the one you intend:

```bash
stellar network ls
```

**Expected output:** for testnet the entry must map to
`Test SDF Network ; September 2015`; for mainnet,
`Public Global Stellar Network ; September 2015`. A mismatch means contracts
were (or will be) deployed to the wrong network.

- [ ] Confirm each recorded contract ID actually resolves on `$NETWORK` (repeat the §2.1 `fetch` for at least one contract) — an ID that resolves on testnet but not mainnet is a strong signal of a wrong-network deploy.

### 4.2 ZK verifier key loaded on `proof_verifier`

- [ ] Confirm the Groth16 verification key is loaded and readable:

```bash
stellar contract invoke --id $VERIFIER_ID --source $SOURCE --network $NETWORK -- get_verification_key
```

**Expected output:** a JSON `VerificationKey` object with non-empty `alpha`,
`beta`, `gamma`, `delta`, and an `ic` array. The `ic` length must equal
`(number of public inputs) + 1`. For the payroll payment circuit there are 2
public inputs (commitment + amount), so `ic` must contain **3** elements. A
`Verifier not initialized` panic means `initialize_verifier` was never called
— redeploy/reinitialize the verifier (see §6).

### 4.3 RPC endpoint sanity check

- [ ] Confirm the RPC endpoint for `$NETWORK` is healthy and reachable before running smoke tests:

```bash
curl -s -X POST <MAINNET_RPC_URL_OR_https://soroban-testnet.stellar.org:443> -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
```

**Expected output:** JSON containing `"status":"healthy"`.

---

## 5. Smoke Tests

Run this sequence after deployment to prove the system is live end-to-end. Use
throwaway test identities. Export helper values as you go.

- [ ] **Prepare test identities** (admin already exists as `$SOURCE`):

```bash
stellar keys generate test_treasury --network $NETWORK && stellar keys generate test_employee --network $NETWORK
```

**Expected output:** two keypairs generated (and funded via friendbot on testnet).

- [ ] **Register a test company:**

```bash
stellar contract invoke --id $REGISTRY_ID --source $SOURCE --network $NETWORK -- register_company --admin $(stellar keys address $SOURCE) --treasury $(stellar keys address test_treasury)
```

**Expected output:** a `u64` company ID (e.g. `0` on a fresh registry). Record
it: `export COMPANY_ID=<COMPANY_ID>`. Emits a `CompanyRegistered` event
(topics: `"CompanyRegistered"`, `company_id`; data: `admin`, `treasury`).

- [ ] **Store a dummy commitment in `salary_commitment`** (32-byte hex; the HR admin must sign):

```bash
stellar contract invoke --id $COMMITMENT_ID --source $SOURCE --network $NETWORK -- store_commitment --employee $(stellar keys address test_employee) --commitment 0101010101010101010101010101010101010101010101010101010101010101
```

**Expected output:** a `SalaryCommitment` object with `version: 1`,
`revoked: false`. Emits a `CommitmentUpdated` event (topics:
`"CommitmentUpdated"`, `employee`; data: `commitment`).

- [ ] **Add the test employee to the registry with the same commitment:**

```bash
stellar contract invoke --id $REGISTRY_ID --source $SOURCE --network $NETWORK -- add_employee --company_id $COMPANY_ID --employee $(stellar keys address test_employee) --commitment 0101010101010101010101010101010101010101010101010101010101010101
```

**Expected output:** no return value; succeeds. Emits an `EmployeeAdded` event
(topics: `"EmployeeAdded"`, `company_id`, `employee`; data: `commitment`). The
employee's status defaults to `Active`.

- [ ] **Verify the employee exists in the registry:**

```bash
stellar contract invoke --id $REGISTRY_ID --source $SOURCE --network $NETWORK -- get_commitment --company_id $COMPANY_ID --employee $(stellar keys address test_employee)
```

**Expected output:** the 32-byte commitment hex you stored
(`0101…01`). A `Employee not found` panic means the add failed.

- [ ] **Confirm eligibility (status is `Active`):**

```bash
stellar contract invoke --id $REGISTRY_ID --source $SOURCE --network $NETWORK -- is_eligible --company_id $COMPANY_ID --employee $(stellar keys address test_employee)
```

**Expected output:** `true`

- [ ] **Check that `proof_verifier` responds to a verification call.** First confirm the key is present (see §4.2), then submit a well-formed proof + the required 2 public inputs:

```bash
stellar contract invoke --id $VERIFIER_ID --source $SOURCE --network $NETWORK -- verify --proof '{"a":"<PROOF_A_64B_HEX>","b":"<PROOF_B_128B_HEX>","c":"<PROOF_C_64B_HEX>"}' --public_inputs '["<COMMITMENT_32B_HEX>","<AMOUNT_32B_HEX>"]'
```

**Expected output:** `true`. **Note:** proof verification is currently
*simulated* (`simulated_verify_groth16` returns `true` for any structurally
valid input whose `public_inputs.len() + 1 == vk.ic.len()`). A mismatched
public-input count returns `false`; a `Verifier not initialized` panic means
the VK was never loaded. This confirms the contract is reachable and the VK is
wired — it is not a cryptographic soundness check.

- [ ] **Confirm events are emitted correctly.** Fetch recent contract events and confirm the topics from the steps above appear:

```bash
stellar events --network $NETWORK --start-ledger <RECENT_LEDGER> --id $REGISTRY_ID
```

**Expected output:** event entries whose topics include `CompanyRegistered` and
`EmployeeAdded` for `$REGISTRY_ID`. Repeat with `--id $COMMITMENT_ID` to see
`CommitmentUpdated`. (Use a `--start-ledger` a few ledgers before your smoke
run; `stellar events` requires a start ledger within the RPC's retention
window.)

- [ ] **(Optional) Full payment path.** If you want to prove `payment_executor`
  end-to-end, open a period (`create_period --company_id $COMPANY_ID`), fund the
  treasury with the payment token, then call `execute_payment` and confirm a
  `PayrollProcessed` event and balance movement. This is beyond a basic smoke
  test — see [sdk-contract-interface.md](sdk-contract-interface.md) Flow 3.

---

## 6. Rollback Procedure

If verification fails at any step, stop and remediate before proceeding to real
payroll. See [ops/rollback-checklist.md](ops/rollback-checklist.md) for the full
production procedure.

### If verification fails

- [ ] **Do not process real payroll.** Halt the cutover immediately.
- [ ] **Pause the affected contracts** (if a pause manager is wired) so no
  writes can land while you investigate:

```bash
stellar contract invoke --id $EXECUTOR_ID --source $SOURCE --network $NETWORK -- set_pause_manager --pause_manager <PAUSE_MANAGER_ID>
```

  Then trigger the pause on the pause manager itself (see the pause manager's
  own interface). The registry, salary_commitment, and audit_module each also
  expose `set_pause_manager` for the same purpose.
- [ ] **Capture diagnostics:** record the failing command, the contract ID,
  and the full error/panic message for the incident log (see
  [incident-response-playbook.md](incident-response-playbook.md)).
- [ ] **Identify scope:** determine whether the failure is a bad contract ID, a
  missing init call, a wrong-network deploy, or an unwired dependency address.

### Redeploy a single contract without affecting the others

Because contracts reference each other by stored address, you can replace one
contract and re-wire only the references that point at it.

- [ ] **Rebuild** the affected contract:

```bash
stellar contract build
```

- [ ] **Redeploy only that contract** (example: proof_verifier) and capture the new ID:

```bash
stellar contract deploy --wasm target/wasm32-unknown-unknown/release/proof_verifier.wasm --source $SOURCE --network $NETWORK
```

- [ ] **Re-run that contract's init** on the new ID (example: verifier):

```bash
stellar contract invoke --id <NEW_VERIFIER_ID> --source $SOURCE --network $NETWORK -- init_verifier_admin --admin <ADMIN_ADDRESS>
```

```bash
stellar contract invoke --id <NEW_VERIFIER_ID> --source $SOURCE --network $NETWORK -- initialize_verifier --vk '<VERIFICATION_KEY_JSON>'
```

- [ ] **Re-wire dependents.** `payment_executor` stores dependency addresses in
  its `initialize(addresses)` struct (`registry`, `commitment`, `verifier`,
  `token`). If you redeployed a dependency **after** `payment_executor` was
  initialized, `initialize` cannot be called again (`Already initialized`). In
  that case the executor must itself be redeployed and re-initialized pointing
  at the new dependency ID:

```bash
stellar contract deploy --wasm target/wasm32-unknown-unknown/release/payment_executor.wasm --source $SOURCE --network $NETWORK
```

```bash
stellar contract invoke --id <NEW_EXECUTOR_ID> --source $SOURCE --network $NETWORK -- initialize --addresses '{"registry":"<REGISTRY_ID>","commitment":"<COMMITMENT_ID>","verifier":"<NEW_VERIFIER_ID>","token":"<TOKEN_ID>"}'
```

```bash
stellar contract invoke --id <NEW_EXECUTOR_ID> --source $SOURCE --network $NETWORK -- set_executor_admin --admin <ADMIN_ADDRESS>
```

- [ ] **Update recorded contract IDs** (env vars, deployment manifest, SDK
  config) to the new IDs so downstream consumers point at the redeployed
  contract.
- [ ] **Re-run Sections 2–5 of this checklist** against the redeployed
  contract(s) before resuming cutover.
- [ ] Note: `payroll_registry` company/employee state and `salary_commitment`
  commitments are **not** migrated automatically on redeploy — redeploying
  those contracts starts from empty storage. Only redeploy stateful contracts
  if you accept losing on-chain state or have a migration plan.
