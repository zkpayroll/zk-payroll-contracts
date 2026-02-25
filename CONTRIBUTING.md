# Contributing to ZK Payroll Contracts

Thank you for your interest in contributing! This project is part of the **Stellar Wave Program**
and implements a highly-secure, privacy-preserving payroll protocol on Stellar/Soroban using
zero-knowledge proofs. The cryptographic assumptions in this codebase (Poseidon hash, Groth16
verifying keys) are load-bearing — please follow this guide carefully.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [License](#license)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Setup](#environment-setup)
  - [ZK Trusted Setup (ptau)](#zk-trusted-setup-ptau)
- [How to Contribute](#how-to-contribute)
  - [Finding an Issue](#finding-an-issue)
  - [Development Workflow](#development-workflow)
  - [Code Standards](#code-standards)
- [Issue Labels](#issue-labels)
- [Areas of Contribution](#areas-of-contribution)
- [Getting Help](#getting-help)

---

## Code of Conduct

- Be respectful and inclusive.
- No spam or low-effort contributions.
- Quality over quantity.

---

## License

ZK Payroll Contracts is dual-licensed under **MIT OR Apache-2.0**. By contributing, you agree
that your contributions will be dual-licensed under these terms. See [LICENSE](LICENSE),
[LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE) for details.

---

## Getting Started

### Prerequisites

| Tool | Minimum Version | Install |
|------|-----------------|---------|
| Rust | 1.74 | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Soroban CLI | 21.0 | See [Soroban setup docs](https://soroban.stellar.org/docs/getting-started/setup) |
| Stellar CLI | 21.0 | See [Stellar CLI docs](https://developers.stellar.org/docs/tools/stellar-cli) |
| Node.js | 18+ | Required for snarkjs |
| snarkjs | 0.7+ | `npm install -g snarkjs` |
| Circom | 2.1+ | See [Circom install guide](https://docs.circom.io/getting-started/installation/) |

### Environment Setup

```bash
# Clone the repository
git clone https://github.com/zkpayroll/zk-payroll-contracts.git
cd zk-payroll-contracts

# Install Rust wasm target
rustup target add wasm32-unknown-unknown

# Build all contracts
cargo build

# Run tests
cargo test

# Build for Soroban (WASM)
stellar contract build
```

---

### ZK Trusted Setup (ptau)

This project uses **Groth16** proofs, which require a two-phase trusted setup:

- **Phase 1** — Powers of Tau (ptau): a universal ceremony independent of any specific circuit.
- **Phase 2** — Circuit-specific setup: derived from Phase 1 for each Circom circuit.

> **Security note:** Never use ptau files from untrusted sources. The Phase 1 ceremony's
> security depends on at least one honest participant. We use the Hermez `powersOfTau28_hez_final`
> ceremony artifacts which had thousands of contributors.

#### Step 1 — Download Phase 1 ptau File

Download the appropriate Powers of Tau file based on the circuit's constraint count.
The `payment.circom` circuit currently requires fewer than 2^20 constraints.

```bash
# Create a directory for ceremony artifacts (excluded from git via .gitignore)
mkdir -p ptau

# Download the Hermez Phase 1 ceremony file (2^20 constraints, ~1.8 GB)
# Source: https://hermez.s3-eu-west-1.amazonaws.com/
wget -O ptau/powersOfTau28_hez_final_20.ptau \
  https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau

# Verify the file integrity (compare against published checksums)
b2sum ptau/powersOfTau28_hez_final_20.ptau
# Expected: 55c77ce8 (see https://github.com/iden3/snarkjs#7-prepare-phase-2)
```

> For smaller circuits (<= 2^16 constraints) you may use `powersOfTau28_hez_final_16.ptau`
> to save disk space and speed up the setup. Check the constraint count first:
> `circom circuits/payment.circom --r1cs && snarkjs r1cs info payment.r1cs`

#### Step 2 — Compile the Circuit

```bash
# Compile the Circom circuit
circom circuits/payment.circom \
  --r1cs \
  --wasm \
  --sym \
  --output build/circuits/

# Inspect constraint count and public signals
snarkjs r1cs info build/circuits/payment.r1cs
snarkjs r1cs print build/circuits/payment.r1cs build/circuits/payment.sym
```

#### Step 3 — Phase 2 Setup (Circuit-Specific)

```bash
# Start Phase 2 from the Phase 1 ptau file
snarkjs groth16 setup \
  build/circuits/payment.r1cs \
  ptau/powersOfTau28_hez_final_20.ptau \
  build/circuits/payment_0000.zkey

# Contribute to Phase 2 ceremony (adds your randomness)
# In production, multiple parties should each contribute
snarkjs zkey contribute \
  build/circuits/payment_0000.zkey \
  build/circuits/payment_0001.zkey \
  --name="Contributor 1" \
  -v

# Apply a random beacon for final finalization
snarkjs zkey beacon \
  build/circuits/payment_0001.zkey \
  build/circuits/payment_final.zkey \
  <random-beacon-hex-string> \
  10 \
  -n="Final Beacon"

# Verify the final zkey
snarkjs zkey verify \
  build/circuits/payment.r1cs \
  ptau/powersOfTau28_hez_final_20.ptau \
  build/circuits/payment_final.zkey

# Export the verifying key (used by the on-chain verifier)
snarkjs zkey export verificationkey \
  build/circuits/payment_final.zkey \
  build/circuits/verification_key.json
```

#### Step 4 — Generate and Verify a Test Proof

```bash
# Generate witness from test inputs
node build/circuits/payment_js/generate_witness.js \
  build/circuits/payment_js/payment.wasm \
  circuits/test_input.json \
  build/circuits/witness.wtns

# Generate Groth16 proof
snarkjs groth16 prove \
  build/circuits/payment_final.zkey \
  build/circuits/witness.wtns \
  build/circuits/proof.json \
  build/circuits/public.json

# Verify the proof locally
snarkjs groth16 verify \
  build/circuits/verification_key.json \
  build/circuits/public.json \
  build/circuits/proof.json
```

> **When is a new trusted setup required?**
> Any change to a circuit's constraints (adding/removing signals, modifying constraints)
> requires a new Phase 2 setup with the updated `.r1cs`. Phase 1 ptau can be reused
> as long as the constraint count stays within the supported range.

---

## How to Contribute

### Finding an Issue

1. Browse issues labeled [`stellar-wave`](https://github.com/zkpayroll/zk-payroll-contracts/labels/stellar-wave) or [`good first issue`](https://github.com/zkpayroll/zk-payroll-contracts/labels/good%20first%20issue).
2. Comment on the issue to express interest.
3. **Wait for assignment** before starting work — parallel efforts on the same issue create merge conflicts and wasted effort.

### Development Workflow

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/zk-payroll-contracts.git
cd zk-payroll-contracts

# 2. Create a feature branch from main
git checkout -b feature/your-feature-name

# 3. Make your changes, then verify
cargo fmt --check              # formatting
cargo clippy -- -D warnings    # linting
cargo test                     # all tests
cargo audit                    # dependency security audit

# 4. Build WASM contracts
stellar contract build

# 5. Commit with a descriptive message
git commit -m "feat(payment_executor): add batch payment entry-point"

# 6. Push and open a PR against main
git push origin feature/your-feature-name
```

All PRs require:
- At least **1 reviewer approval**
- All **CI status checks** to pass (build, test, lint, audit)

### Code Standards

| Area | Standard |
|------|----------|
| Formatting | `cargo fmt` (enforced in CI) |
| Linting | `cargo clippy -- -D warnings` (enforced in CI) |
| Tests | Every new public function must have at least one unit test |
| Commit messages | [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, etc.) |
| No panics | Use `Result` / Soroban error enums instead of `unwrap()` or `panic!()` |
| Authorization | All state-mutating entry-points must call `env.require_auth()` |
| Secrets | Never commit private keys, blinding factors, or ptau artifacts |

---

## Issue Labels

| Label | Description | Points |
|-------|-------------|--------|
| `good first issue` | Great for newcomers | 100 |
| `medium` | Standard complexity | 150 |
| `high` | Complex implementation | 200 |
| `stellar-wave` | Eligible for Stellar Wave rewards | — |
| `zk-circuits` | Circom circuit changes | — |
| `smart-contracts` | Soroban/Rust contract changes | — |
| `state-rent` | Issues affecting Stellar state rent / storage | — |
| `audit-module` | Selective disclosure / compliance module | — |
| `bug` | Something isn't working | — |
| `enhancement` | New feature or improvement | — |
| `security` | Security-sensitive changes | — |

---

## Areas of Contribution

### Smart Contracts (Rust / Soroban)
- Implement missing contract entry-points
- Add test coverage
- Optimize resource usage (CPU, memory, ledger entries)
- Security reviews

### ZK Circuits (Circom / snarkjs)
- Circuit development and optimization
- Proof generation tooling
- New circuit designs (range proofs, batch proofs)

### Documentation
- Code documentation and inline comments
- Tutorial creation
- Architecture diagrams

### Testing
- Integration tests
- Fuzzing with `cargo-fuzz`
- End-to-end proof generation and verification tests

---

## Getting Help

- Join [Stellar Discord](https://discord.gg/stellar) — `#soroban-dev` channel
- Check [Soroban Docs](https://soroban.stellar.org/docs)
- Check [Circom Docs](https://docs.circom.io)
- Ask questions in issue comments — we respond to all good-faith questions
