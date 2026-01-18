# Contributing to ZK Payroll Contracts

Thank you for your interest in contributing! This project is part of the **Stellar Wave Program**.

## Getting Started

### Prerequisites

- Rust 1.74+
- Soroban CLI v21+
- Basic understanding of ZK proofs (helpful but not required)

### Setup

```bash
git clone https://github.com/your-org/zk-payroll-contracts.git
cd zk-payroll-contracts
cargo build
cargo test
```

## How to Contribute

### 1. Find an Issue

- Look for issues labeled `stellar-wave` or `good-first-issue`
- Comment on the issue to express interest
- Wait for assignment before starting work

### 2. Development Workflow

```bash
# Create a branch
git checkout -b feature/your-feature-name

# Make changes
# ...

# Run tests
cargo test

# Build contracts
stellar contract build

# Submit PR
```

### 3. Code Standards

- Follow Rust best practices
- Add tests for new functionality
- Update documentation as needed
- Use meaningful commit messages

## Issue Labels

| Label | Description | Points |
|-------|-------------|--------|
| `good-first-issue` | Great for newcomers | 100 |
| `medium` | Standard complexity | 150 |
| `high` | Complex implementation | 200 |
| `stellar-wave` | Eligible for Wave rewards | - |

## Areas of Contribution

### Smart Contracts (Rust)
- Implement missing contract functions
- Add test coverage
- Optimize gas usage
- Security improvements

### ZK Circuits
- Circom circuit development
- Proof generation optimization
- New circuit designs

### Documentation
- Code documentation
- Tutorial creation
- Architecture diagrams

### Testing
- Integration tests
- Fuzzing
- Security audits

## Getting Help

- Join [Stellar Discord](https://discord.gg/stellar)
- Check [Soroban Docs](https://soroban.stellar.org/docs)
- Ask questions in issue comments

## Code of Conduct

- Be respectful and inclusive
- No spam or low-effort contributions
- Quality over quantity

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
