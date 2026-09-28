# Contracts Workspace

This directory contains every Soroban WASM contract in the ZK Payroll suite, plus
shared crates (`events`, `shared_errors`) and integration tests. Use this guide
when setting up a local environment, running contract tests, or preparing a
testnet/mainnet deployment.

## Contract crates

| Crate | Purpose |
|-------|---------|
| `payroll_registry` | Company registration and employee roster |
| `salary_commitment` | Poseidon salary commitments and nullifiers |
| `proof_verifier` | On-chain Groth16 verification |
| `payment_executor` | Private payment execution with withholding validation |
| `payroll` | Payroll run lifecycle and treasury |
| `pause_manager` | Global pause / unpause control |
| `audit_module` | Compliance and selective disclosure |
| `events` | Shared `emit_*` helpers for stable event shapes |
| `integration_tests` | Cross-contract end-to-end tests |

Build all WASM artifacts from the repository root:

```bash
stellar contract build
```

---

## Environment variables

Soroban contracts themselves do **not** read process environment variables at
runtime — configuration is passed through contract initialization and storage.
The variables below are used by **local tooling, shell scripts, and CI** when
building, testing, and deploying.

### Deployment and CLI operations

Set these in your shell before running deploy, invoke, or verification commands.
Names follow [docs/deployment.md](../docs/deployment.md),
[docs/deployment-verification.md](../docs/deployment-verification.md), and
[scripts/demo.sh](../scripts/demo.sh).

| Variable | Required | Example | Purpose |
|----------|----------|---------|---------|
| `NETWORK` | Yes (deploy/invoke) | `testnet` | Target Stellar network name registered in the CLI |
| `SOURCE` | Yes (deploy/invoke) | `admin` | Local signing identity name (`stellar keys ls`) |
| `TOKEN_ID` | After token deploy | `C…` | Soroban token contract ID |
| `REGISTRY_ID` | After registry deploy | `C…` | `payroll_registry` contract ID |
| `COMMITMENT_ID` | After commitment deploy | `C…` | `salary_commitment` contract ID |
| `VERIFIER_ID` | After verifier deploy | `C…` | `proof_verifier` contract ID |
| `PAUSE_ID` | After pause manager deploy | `C…` | `pause_manager` contract ID |
| `EXECUTOR_ID` | After executor deploy | `C…` | `payment_executor` contract ID |
| `PAYROLL_ID` | After payroll deploy | `C…` | `payroll` contract ID |
| `AUDIT_ID` | After audit deploy | `C…` | `audit_module` contract ID |
| `COMPANY_ID` | After company registration | `0` | Numeric company ID returned by `register_company` |

Minimal export example:

```bash
export NETWORK=testnet
export SOURCE=admin
export REGISTRY_ID=<REGISTRY_CONTRACT_ID>
export COMMITMENT_ID=<COMMITMENT_CONTRACT_ID>
export COMPANY_ID=0
```

Confirm you are on the intended network before sending transactions:

```bash
echo "Deploying to: $NETWORK"
stellar network ls
```

### Local development and testing

| Variable | Required | Example | Purpose |
|----------|----------|---------|---------|
| `RUST_BACKTRACE` | No | `1` | Print full Rust backtraces when a test panics or traps |
| `CARGO_MANIFEST_DIR` | No (set by Cargo) | — | Cargo sets this automatically; integration proof helpers use it to locate `circuits/generate_proof.js` |

Enable backtraces when debugging contract panics:

```bash
# Linux / macOS
export RUST_BACKTRACE=1
cargo test -p payroll_registry

# Windows PowerShell
$env:RUST_BACKTRACE = "1"
cargo test -p payroll_registry
```

### Demo script (`scripts/demo.sh`)

The demo script generates and exports key material for a testnet walkthrough.
These are **not** required for normal `cargo test` runs.

| Variable | Set by | Purpose |
|----------|--------|---------|
| `ADMIN_SECRET` / `ADMIN_PUBLIC` | `demo.sh` | Admin signing key and address |
| `EMPLOYEE_SECRET` / `EMPLOYEE_PUBLIC` | `demo.sh` | Demo employee key and address |
| `TREASURY_SECRET` / `TREASURY_PUBLIC` | `demo.sh` | Treasury funding key and address |

---

## Local test setup expectations

### Prerequisites

| Requirement | Verify with |
|-------------|---------------|
| Rust 1.74+ with `wasm32-unknown-unknown` | `rustup target add wasm32-unknown-unknown` |
| Stellar / Soroban CLI v21+ | `stellar --version` |
| Node.js 18+ (optional) | `node --version` |

Node.js is **optional** for most unit tests. Integration tests that call
`circuits/generate_proof.js` skip gracefully when Node.js is missing.

### Build WASM before integration tests

Integration tests load compiled `.wasm` files from `target/wasm32-unknown-unknown/release/`.
If those artifacts are missing, tests fail with a “no such file” error.

```bash
stellar contract build
cargo test --workspace
```

### Test tiers

| Tier | Command | What it covers |
|------|---------|----------------|
| Unit / contract | `cargo test -p payroll_registry` | In-memory Soroban host, mocked auth |
| Event schema snapshots | `cargo test -p event_schema_snapshots` | Stable event topic/payload shapes |
| Workspace | `cargo test --workspace` | All crates including migration and access-control suites |

Most contract unit tests call `env.mock_all_auths()` — they do **not** require
exported contract IDs or network access.

### ZK proof tests

Dynamic proof generation tests (`contracts/integration_tests`) need:

1. Node.js on `PATH`
2. `circuits/generate_proof.js` present at the workspace root
3. Optional: completed Circom/snarkjs trusted setup (see [CONTRIBUTING.md](../CONTRIBUTING.md#zk-trusted-setup-ptau))

When prerequisites are missing, those tests emit a stderr warning and skip rather
than failing CI.

---

## Privacy: do not put secrets in environment variables

Never export the following into shell history, CI logs, or `.env` files checked
into git:

- Raw salary amounts or blinding factors
- Private signing keys or mnemonics (use `stellar keys` identities instead)
- Groth16 proving keys or ptau ceremony artifacts with contributor entropy

On-chain events and commitments expose **Poseidon hashes only** — salary values
are not recoverable from environment configuration or emitted event payloads.

---

## Verification checklist (manual QA)

Use these steps to confirm your local setup without running the full workspace
test suite.

### Success path

1. `rustup target add wasm32-unknown-unknown`
2. `stellar contract build` completes without errors
3. `cargo test -p payroll_registry` passes
4. (Optional) `export RUST_BACKTRACE=1` then re-run a failing test for detail

### Failure path

1. Remove WASM artifacts: `cargo clean`
2. Run `cargo test -p integration_tests` **without** rebuilding
3. **Expected:** tests fail with missing `.wasm` file errors
4. **Fix:** run `stellar contract build` and retry

### Edge case — optional Node.js toolchain

1. Ensure `node` is **not** on `PATH` (or rename temporarily)
2. Run integration proof helper tests
3. **Expected:** tests skip with a warning about Node.js; other tests still pass

---

## Withholding configuration (`payment_executor` — issue #538)

Every company must have a `WithholdingConfig` set before payments can be executed.
This ensures clear operational states and prevents silent no-op payroll flows.

### Overview

`WithholdingConfig` stores per-company tax deduction rates and recipient addresses.
Rates are expressed in **basis points** (bps): `10 000 bps = 100 %`.
Sensitive salary values are never stored in the config — only rate parameters and
recipient wallet addresses.

### Setting up withholding (executor admin only)

```bash
stellar contract invoke \
  --id "$EXECUTOR_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- set_withholding_config \
    --company_id 0 \
    --income_tax_bps 1000 \
    --social_tax_bps 500 \
    --income_tax_recipient "$TAX_AUTHORITY_ADDR" \
    --social_tax_recipient "$SOCIAL_FUND_ADDR" \
    --max_gross_per_payment 0 \
    --min_net_per_payment 0
```

| Field | Description |
|-------|-------------|
| `income_tax_bps` | Income-tax rate in bps (e.g. `1000` = 10 %). |
| `social_tax_bps` | Social/statutory-tax rate in bps (e.g. `500` = 5 %). |
| `income_tax_recipient` | Wallet address that receives withheld income tax. |
| `social_tax_recipient` | Wallet address that receives withheld social tax. |
| `max_gross_per_payment` | Per-payment gross cap (0 = no cap). |
| `min_net_per_payment` | Per-payment net floor; rejected if net falls below this (0 = no floor). |

The combined `income_tax_bps + social_tax_bps` must not exceed `10 000`; an
`InvalidWithholdingRate` error is returned otherwise.

### How payments are split

When `execute_payment` runs, the gross `amount` from the ZK proof is split on-chain:

```
net_amount   = gross_amount - income_tax - social_tax
income_tax   = gross_amount × income_tax_bps / 10 000
social_tax   = gross_amount × social_tax_bps / 10 000
```

Three token transfers are issued from the company treasury:
1. `net_amount` → employee
2. `income_tax` → `income_tax_recipient` (skipped when zero)
3. `social_tax` → `social_tax_recipient` (skipped when zero)

### Error reference

| Error | Code | Meaning |
|-------|------|---------|
| `WithholdingConfigMissing` | 13 | No config set for this company. |
| `InvalidWithholdingRate` | 14 | Combined bps > 10 000 or negative cap/floor. |
| `NetAmountBelowMinimum` | 15 | Net after deductions < `min_net_per_payment`. |
| `GrossAmountExceedsCap` | 16 | Gross amount > `max_gross_per_payment`. |

---

## Payout batch size limits (issue #510)

`execute_batch_payroll` enforces a configurable per-company ceiling on the
number of employees in a single batch. This prevents oversized payroll
submissions from exhausting on-chain resources and causing unintended
cost spikes.

### Hard cap

The contract always enforces a hard ceiling of **100 employees per batch**
(`MAX_PAYOUT_BATCH_SIZE`). This cap applies even when no per-company policy
has been configured. It cannot be raised via any admin call.

### Per-company policy

The executor admin can set a tighter limit per company:

```bash
stellar contract invoke \
  --id "$EXECUTOR_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- set_max_batch_size \
    --company_id 0 \
    --max_size 25
```

Read the current effective limit back:

```bash
stellar contract invoke \
  --id "$EXECUTOR_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- get_max_batch_size \
    --company_id 0
```

| Field | Description |
|-------|-------------|
| `company_id` | Numeric company ID (returned by `register_company`). |
| `max_size` | Maximum employees per batch (1–100 inclusive). |

### Behaviour

- When no policy is configured the effective limit is the hard cap (100).
- `max_size = 0` is rejected; `max_size > 100` is rejected.
- Limits are scoped per company; changing one company's limit does not
  affect another.
- Batches that exceed the limit are rejected immediately with
  `PaymentError::BatchTooLarge` (error code 18). The error carries no
  employee addresses or salary amounts, keeping failure paths privacy-safe.
- `execute_batch_payroll_with_receipt` enforces the same limit as
  `execute_batch_payroll`.

### Error reference

| Error | Code | Meaning |
|-------|------|---------|
| `BatchTooLarge` | 18 | Employee count exceeds the configured or default batch size limit. |

---

## Related guides

| Guide | When to use it |
|-------|----------------|
| [tests/README.md](tests/README.md) | Common test panics and HostError debugging |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Full contributor setup, pre-commit hooks, ZK ceremony |
| [docs/troubleshooting-soroban-build.md](../docs/troubleshooting-soroban-build.md) | Build and optimize failures |
| [docs/deployment-verification.md](../docs/deployment-verification.md) | Post-deploy smoke tests using `$NETWORK` / `$SOURCE` |
