# Soroban Build & Optimize Troubleshooting Guide

This guide covers the most common local failures when building, optimizing, and deploying ZK Payroll contracts with the Soroban/Stellar toolchain. If you hit something not listed here, open an issue and we will add it.

---

## Quick Diagnostics

Run this sequence first to isolate the failure layer:

```bash
# 1. Confirm toolchain versions
rustup show
stellar --version
cargo --version

# 2. Check the wasm32 target is installed
rustup target list --installed | grep wasm32

# 3. Try a clean build
cargo clean
stellar contract build
```

---

## Build Failures

### `error[E0463]: can't find crate for std` (missing wasm32 target)

**Symptom:** Rust reports it cannot find `std` when building for `wasm32-unknown-unknown`.

**Fix:**
```bash
rustup target add wasm32-unknown-unknown
```

If the target is already installed but the error persists, the active toolchain may not match the project's `rust-toolchain.toml`. Check with:
```bash
rustup show active-toolchain
```
Then install the target against that specific toolchain:
```bash
rustup target add wasm32-unknown-unknown --toolchain <toolchain-version>
```

---

### `stellar contract build` produces no `.wasm` output

**Symptom:** The command exits 0 but `target/wasm32-unknown-unknown/release/` is empty or missing the expected `.wasm` file.

**Possible causes and fixes:**

1. **Wrong working directory.** Run the command from the workspace root (`zk-payroll-contracts/`), not from inside a contract subdirectory.
2. **Crate is not a `cdylib`.** Each contract's `Cargo.toml` must declare:
   ```toml
   [lib]
   crate-type = ["cdylib", "rlib"]
   ```
   The `cdylib` type is required for WASM output.
3. **Contract not in workspace members.** Check the root `Cargo.toml` and confirm the contract path is listed under `[workspace] members`.

---

### `error: linker 'lld' not found` or `LLVM error`

**Symptom:** Build fails with a linker or LLVM toolchain error on Windows.

**Fix:** Install the MSVC build tools and ensure the correct Rust target triple is being used:
```bash
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
rustup target add wasm32-unknown-unknown
```

---

### `error: package ... is not a member of the workspace`

**Symptom:** `cargo build` or `stellar contract build` reports a package is not a workspace member.

**Fix:** Open the root `Cargo.toml` and verify all contract paths are listed:
```toml
[workspace]
members = [
  "contracts/payroll_registry",
  "contracts/salary_commitment",
  "contracts/proof_verifier",
  "contracts/payment_executor",
  "contracts/audit_module",
  "contracts/pause_manager",
  "contracts/token",
  "cli",
]
```

---

### Compilation succeeds but contract panics at runtime

**Symptom:** Unit tests pass, but an invocation on testnet or in integration tests panics.

**Likely cause:** A `panic!()` or `.unwrap()` call in contract code. Soroban traps on any `panic!`.

**Fix:** Replace panics with explicit Soroban errors:
```rust
// Bad
let val = storage.get(&key).unwrap();

// Good
let val = storage.get(&key).ok_or(Error::NotFound)?;
```

Refer to the [Code Standards](../CONTRIBUTING.md#code-standards) section in CONTRIBUTING for the no-panics rule.

---

## Optimize Step Failures

### `stellar contract optimize` not found / unrecognized subcommand

**Symptom:** `stellar contract optimize` exits with "unrecognized subcommand".

**Fix:** Ensure Stellar CLI is at v21+:
```bash
stellar --version
```
If outdated, reinstall:
```bash
cargo install --locked stellar-cli --features opt
```
The `--features opt` flag enables the `wasm-opt` integration.

---

### `wasm-opt` binary not found

**Symptom:** Optimize step reports it cannot find `wasm-opt`.

**Fix:** Install `binaryen` which ships `wasm-opt`:
```bash
# macOS
brew install binaryen

# Windows (via Scoop)
scoop install binaryen

# Linux (Debian/Ubuntu)
apt-get install binaryen
```

Or install via `cargo`:
```bash
cargo install wasm-opt
```

---

### Optimized WASM is larger than the original

**Symptom:** The `.optimized.wasm` file is bigger than the unoptimized version.

**Explanation:** This can happen when `wasm-opt` inlines aggressively with `O3`. The Stellar CLI defaults to `Os` (optimize for size), so this is uncommon. If you ran `wasm-opt` manually with a different flag, switch to:
```bash
wasm-opt -Os --strip-debug -o output.wasm input.wasm
```

---

### WASM exceeds Soroban contract size limit

**Symptom:** Deployment fails with a contract size error. The Soroban limit is currently ~256 KB for the optimized binary.

**Fixes:**
1. Run the optimize step if you have not already: `stellar contract optimize --wasm <file>.wasm`
2. Audit `Cargo.toml` dependencies — pull in only what is needed.
3. Add to the root `Cargo.toml`:
   ```toml
   [profile.release]
   opt-level = "z"       # optimize for size
   lto = true            # link-time optimization
   codegen-units = 1     # smaller binary, slower build
   strip = true          # strip symbols
   ```
4. Avoid `std` features where possible; prefer `no_std`-compatible crates.

---

## CLI Failures

### `stellar contract invoke` returns `Error: host invocation failed`

**Symptom:** An invocation against testnet or localnet returns a vague host error.

**Diagnostic steps:**
```bash
# Add --verbose for XDR-level detail
stellar contract invoke \
  --id <contract-id> \
  --source <identity> \
  --network testnet \
  --verbose \
  -- <function> <args>

# Decode raw XDR result if returned
stellar xdr decode --type TransactionResult --xdr <base64-xdr>
```

Common root causes:
- Calling a function that requires auth without `--source` set to the authorized account.
- Passing arguments in the wrong XDR type (e.g., passing a string where a `u64` is expected).
- Contract storage entry has expired — bump TTL or redeploy.

---

### `Error: account not found` on testnet

**Symptom:** Stellar CLI cannot find the account used as `--source`.

**Fix:** Fund the account on testnet using Friendbot:
```bash
stellar keys generate alice --network testnet
stellar keys address alice
# Then fund:
curl "https://friendbot.stellar.org?addr=$(stellar keys address alice)"
```

---

### `cargo test` fails with `no such file` for WASM fixtures

**Symptom:** Integration tests or security tests fail because they cannot load a `.wasm` file.

**Fix:** Build contracts before running tests:
```bash
stellar contract build
cargo test
```

Or update your test setup to call `stellar contract build` as a pre-test step. The integration test helpers in `contracts/integration_tests/src/proof_helper.rs` expect binaries to be present in `target/wasm32-unknown-unknown/release/`.

---

### Pre-commit hook blocks commit with `cargo fmt` error

**Symptom:** `git commit` is aborted with a formatting error.

**Fix:**
```bash
cargo fmt
git add -u
git commit -m "your message"
```

Do not use `--no-verify` unless it is a genuine emergency — CI will catch it anyway.

---

## Circom / snarkjs Build Failures

### `circom` not found

**Symptom:** Pre-commit hook warns "circom not installed" or CI fails at circuit compilation.

**Fix:** Install Circom following the [official guide](https://docs.circom.io/getting-started/installation/). For local development, the pre-commit hook will skip the Circom check gracefully if `circom` is absent, but CI will still enforce it.

---

### `snarkjs` proof generation fails with `Not enough values for input signal`

**Symptom:** `generate_witness.js` exits with a signal count mismatch.

**Fix:** Verify your `test_input.json` matches the public/private signal declarations in `circuits/payment.circom`. Any change to circuit signals requires regenerating the witness template.

---

### `zkey verify` fails after circuit modification

**Symptom:** `snarkjs zkey verify` reports the `.r1cs` and `.zkey` do not match.

**Explanation:** Any change to circuit constraints invalidates the Phase 2 zkey. A new trusted setup is required.

**Fix:** Follow the full [ZK Trusted Setup](../CONTRIBUTING.md#zk-trusted-setup-ptau) steps from Phase 2 onward.

---

## Getting Help

- [Stellar Discord](https://discord.gg/stellar) — `#soroban-dev` channel
- [Soroban Docs](https://soroban.stellar.org/docs)
- [Circom Docs](https://docs.circom.io)
- Open an issue on this repository with the label `devex` or `bug`

---

*Last updated: Issue [#118](https://github.com/zkpayroll/zk-payroll-contracts/issues/118)*
