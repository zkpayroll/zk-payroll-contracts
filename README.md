# ZK Payroll Contracts

Privacy-first payroll smart contracts for Stellar/Soroban using zero-knowledge proofs.

## Overview

ZK Payroll Contracts enable companies to process payroll on-chain while keeping salary amounts private. Using Stellar's Protocol X-Ray ZK primitives (BN254, Poseidon), employers can prove payments were made without revealing exact amounts.

## Features

- **Private Salary Commitments** — Salary amounts stored as ZK commitments
- **Proof-Based Payments** — Verify payments without exposing values
- **Batch Payroll** — Process multiple employees in single transaction
- **Compliance Ready** — Selective disclosure for audits via view keys
- **On-Chain Verification** — Groth16 proof verification on Soroban

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ZK Payroll System                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   Payroll   │    │   Salary    │    │    Proof    │ │
│  │  Registry   │───▶│ Commitment  │───▶│  Verifier   │ │
│  └─────────────┘    └─────────────┘    └─────────────┘ │
│         │                  │                  │        │
│         ▼                  ▼                  ▼        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │  Employee   │    │   Payment   │    │   Audit     │ │
│  │  Registry   │    │   Executor  │    │   Module    │ │
│  └─────────────┘    └─────────────┘    └─────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Contracts

| Contract | Description |
|----------|-------------|
| `payroll_registry` | Company registration, employee management |
| `salary_commitment` | ZK commitment storage and updates |
| `proof_verifier` | Groth16 proof verification using BN254 |
| `payment_executor` | Private payment execution |
| `audit_module` | Selective disclosure for compliance |

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| [Rust](https://rustup.rs/) | 1.74+ | Contract development and testing |
| [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup) | v21+ | Contract deployment |
| [Stellar CLI](https://developers.stellar.org/docs/tools/stellar-cli) | v21+ | Network interaction |
| [Node.js](https://nodejs.org/) | 18+ | Required by snarkjs and circom WASM output |
| [Circom](https://docs.circom.io/getting-started/installation/) | 2.1+ | ZK circuit compilation |

## Installation

```bash
# Clone the repository
git clone https://github.com/zkpayroll/zk-payroll-contracts.git
cd zk-payroll-contracts

# Install dependencies
cargo build

# Run tests
cargo test
```

## Quick Start

### 1. Build Contracts

```bash
stellar contract build
```

### 2. Deploy to Testnet

```bash
# Deploy payroll registry
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/payroll_registry.wasm \
  --network testnet \
  --source alice
```

### 3. Initialize Company

```rust
// Register a company
payroll_registry.register_company(
    company_id,
    admin_address,
    treasury_address
);
```

## Usage

### Register Employee with Private Salary

```rust
// Create salary commitment (off-chain)
let commitment = poseidon_hash(salary_amount, blinding_factor);

// Register employee with commitment
payroll_registry.add_employee(
    company_id,
    employee_address,
    salary_commitment
);
```

### Process Private Payroll

```rust
// Generate proof (off-chain)
let proof = generate_payment_proof(
    salary_amount,
    blinding_factor,
    recipient
);

// Execute payment with proof
payment_executor.process_payment(
    company_id,
    employee_address,
    proof
);
```

### Compliance Audit

```rust
// Generate view key for auditor
let view_key = audit_module.generate_view_key(
    company_id,
    auditor_address,
    time_range
);

// Auditor verifies with selective disclosure
audit_module.verify_with_view_key(view_key, proof);
```

## Project Structure

```
zk-payroll-contracts/
├── contracts/
│   ├── payroll_registry/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── company.rs
│   │   │   └── employee.rs
│   │   └── Cargo.toml
│   ├── salary_commitment/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   └── commitment.rs
│   │   └── Cargo.toml
│   ├── proof_verifier/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── groth16.rs
│   │   │   └── bn254.rs
│   │   └── Cargo.toml
│   ├── payment_executor/
│   │   └── ...
│   └── audit_module/
│       └── ...
├── circuits/
│   ├── payment.circom
│   └── range_proof.circom
├── scripts/
│   ├── deploy.sh
│   └── generate_proof.sh
├── tests/
│   └── integration_tests.rs
├── Cargo.toml
└── README.md
```

## Cryptographic Primitives

This project leverages Stellar's Protocol X-Ray (Protocol 25) primitives:

- **BN254** — Elliptic curve for Groth16 proof verification
- **Poseidon** — ZK-friendly hash function for commitments
- **Groth16** — Succinct proof system for payment verification

## Security

- All salary amounts are stored as Poseidon hash commitments
- Payments verified via Groth16 proofs without revealing amounts
- View keys enable selective disclosure for compliance
- No salary data exposed on public ledger

## Roadmap

- [x] Core contract architecture
- [ ] Payroll registry implementation
- [ ] Salary commitment contract
- [ ] Groth16 verifier integration
- [ ] Payment executor
- [ ] Audit module with view keys
- [ ] Batch payment optimization
- [ ] Multi-currency support

## Events

See [docs/events.md](docs/events.md) for the full event schema reference and
consumption expectations.


## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Good First Issues

Check out issues labeled `good-first-issue` and `stellar-wave` for contribution opportunities.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Stellar Development Foundation](https://stellar.org) — Protocol X-Ray ZK primitives
- [Nethermind](https://nethermind.io) — ZK tooling collaboration
