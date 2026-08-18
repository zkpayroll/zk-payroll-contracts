# Fuzz Testing

This directory contains fuzz tests for proof validation, single payments, and batch payments in the zk-payroll contracts.

Fuzzing is implemented using `cargo-fuzz` (libFuzzer).

## Prerequisites

1. **Rust Nightly**: `cargo-fuzz` requires a nightly Rust compiler.
   ```bash
   rustup toolchain install nightly
   ```

2. **cargo-fuzz**: Install the `cargo-fuzz` CLI tool.
   ```bash
   cargo install cargo-fuzz
   ```

3. **C/C++ Compiler**: A modern compiler (such as `clang` or `gcc` on Linux/macOS, or MSVC on Windows) is needed for compiling sanitizer instrumentation. Note: libFuzzer has native support on Unix-like environments; running on Windows might require WSL2 or MSVC LLVM tools.

## Running the Fuzzer

To run the proof and payment validation fuzzer, execute:

```bash
# Navigate to the workspace root or the fuzz directory, then run:
cargo +nightly fuzz run fuzz_proof_validation
```

This will run the fuzzer continuously until a crash/bug (such as an unexpected panic or failed invariant assertion) is found or it is manually stopped (Ctrl+C).

## Reproducing Findings Locally

If the fuzzer finds a bug, it will save the offending input payload to a file under `fuzz/artifacts/fuzz_proof_validation/crash-XXXXXXXXXXXX`.

To reproduce the failure locally and debug:

```bash
cargo +nightly fuzz run fuzz_proof_validation fuzz/artifacts/fuzz_proof_validation/crash-XXXXXXXXXXXX
```

You can run this with `RUST_BACKTRACE=1` to print the backtrace of the crash:

```bash
$env:RUST_BACKTRACE=1   # On Windows PowerShell
# OR
export RUST_BACKTRACE=1 # On Linux/macOS

cargo +nightly fuzz run fuzz_proof_validation fuzz/artifacts/fuzz_proof_validation/crash-XXXXXXXXXXXX
```

## CI/CD Integration Guidance

Since fuzz testing runs indefinitely, running continuous fuzzing directly in PR check pipelines can be slow and expensive. Below are the recommended approaches for CI integration:

### Option A: Regression testing (Recommended for PRs)
Execute the fuzz target with a time limit (e.g., 60 seconds) or run only existing regression inputs (artifacts) on every pull request.

To run with a time limit of 1 minute in CI:
```bash
cargo +nightly fuzz run fuzz_proof_validation -- -max_total_time=60
```

To run with zero new fuzz inputs (just runs existing corpus/regression files):
```bash
cargo +nightly fuzz run fuzz_proof_validation -- -runs=0
```

### Option B: Nightly Scheduled Fuzzing
Set up a scheduled GitHub Action that runs the fuzzer for a longer duration (e.g., 10 minutes or 1 hour) every night:

```yaml
name: Nightly Fuzz Testing

on:
  schedule:
    - cron: '0 2 * * *' # Every night at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust Nightly
        uses: dtolnay/rust-toolchain@nightly

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Run Fuzzer
        run: |
          cd fuzz
          cargo +nightly fuzz run fuzz_proof_validation -- -max_total_time=600
```
