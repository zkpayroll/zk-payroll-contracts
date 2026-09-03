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
| `payment_executor` | Private payment execution |
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

## Related guides

| Guide | When to use it |
|-------|----------------|
| [tests/README.md](tests/README.md) | Common test panics and HostError debugging |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Full contributor setup, pre-commit hooks, ZK ceremony |
| [docs/troubleshooting-soroban-build.md](../docs/troubleshooting-soroban-build.md) | Build and optimize failures |
| [docs/deployment-verification.md](../docs/deployment-verification.md) | Post-deploy smoke tests using `$NETWORK` / `$SOURCE` |
