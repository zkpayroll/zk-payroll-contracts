# Local Setup and Test Troubleshooting

This guide provides solutions for common issues encountered when setting up the local environment and running tests for ZK Payroll contracts.

## 1. Environment Setup Issues

### Missing `wasm32-unknown-unknown` Target
**Error:** `error[E0463]: can't find crate for std` or similar when running `cargo test` or `stellar contract build`.
**Solution:** Ensure the WASM target is installed for your active Rust toolchain.
```bash
rustup target add wasm32-unknown-unknown
```

### Soroban CLI Version Mismatch
**Error:** Unrecognized commands or unexpected test behavior when invoking contracts.
**Solution:** Verify your Soroban/Stellar CLI version is v21+.
```bash
stellar --version
```
If outdated, upgrade it via cargo:
```bash
cargo install --locked stellar-cli
```

## 2. Common Test Failures

### Missing WASM Fixtures (`no such file`)
**Error:** Integration tests fail because they cannot load a `.wasm` file (e.g., `target/wasm32-unknown-unknown/release/payroll_registry.wasm`).
**Why it happens:** Our integration tests load the compiled WebAssembly binaries of the contracts. If you haven't built them yet, the tests will fail.
**Solution:** Always build the contracts before running integration tests.
```bash
stellar contract build
cargo test
```

### HostError or Contract Panics
**Error:** A test fails with `HostError` or `Status(WasmVm)`.
**Why it happens:** Soroban traps on any Rust `panic!()` or failed `.unwrap()`. The backtrace in WASM is often opaque.
**Solution:**
1. Run tests with the environment variable `RUST_BACKTRACE=1` to get more detailed Rust backtraces.
2. Look for `unwrap()`, `expect()`, or out-of-bounds array access in the contract code. Replace them with proper error handling (`Result<T, Error>`).

### Out of Resources (CPU/Memory/Gas)
**Error:** `CpuLimitExceeded`, `MemLimitExceeded`, or test runner hanging.
**Solution:**
- The default Soroban environment in tests has resource limits mimicking the testnet.
- Check for unbounded loops or overly large data structures (e.g., large `Vec` instead of `Map`).
- If you legitimately need more resources for a test, consider modifying the budget in the test environment (e.g., `env.budget().reset_unlimited()`).

## 3. ZK Proof Setup Failures

### `snarkjs` or Circuit Verification Fails in Tests
**Error:** `Not enough values for input signal` or proof verification fails locally.
**Solution:**
- Ensure you have correctly downloaded the Phase 1 `ptau` file and completed the Phase 2 trusted setup.
- If you modified `payment.circom` or any other circuit, you **must** rerun the Phase 2 setup. The existing `.zkey` and `.wasm` witness generator will be invalidated.
- See the [ZK Trusted Setup](../../CONTRIBUTING.md#zk-trusted-setup-ptau) section in `CONTRIBUTING.md` for the exact regeneration commands.

## Getting More Help
If you encounter an issue not listed here, check our more comprehensive [Soroban Build Troubleshooting](../../docs/troubleshooting-soroban-build.md) guide or ask for help in the `#soroban-dev` channel on the Stellar Discord.
