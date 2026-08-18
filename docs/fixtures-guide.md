# Fixture Datasets for Local Testing — Issue #81

This guide provides reusable fixture data for contributors testing ZK Payroll contracts locally, ensuring consistent test data across SDK and dashboard development.

## Overview

Fixtures provide deterministic, well-known test data (companies, employees, payroll periods, proofs) that reduce setup friction and align contract assumptions across teams.

## Available Fixtures

### Companies

| ID | Name | Admin | Treasury | Status |
|---|---|---|---|---|
| `0` | **Acme Corp** | `GACME...` | `TACME...` | Active |
| `1` | **TechStart Inc** | `GTECH...` | `TTECH...` | Active |
| `2` | **GlobalPay Ltd** | `GGPAY...` | `TGPAY...` | Onboarded (3 employees) |

### Employees (Company ID 0 - Acme Corp)

| Name | Address | Salary | Blinding | Commitment |
|---|---|---|---|---|
| **Alice** | `GALICE...` | 5000 XLM | `123` | `0xabcd...` |
| **Bob** | `GBOB...` | 3500 XLM | `456` | `0xdef0...` |
| **Carol** | `GCAROL...` | 7200 XLM | `789` | `0x1234...` |

### Employees (Company ID 2 - GlobalPay Ltd)

| Name | Address | Salary | Blinding | Commitment |
|---|---|---|---|---|
| **David** | `GDAVID...` | 4500 XLM | `111` | `0x5555...` |
| **Emma** | `GEMMA...` | 6000 XLM | `222` | `0x6666...` |
| **Frank** | `GFRANK...` | 5500 XLM | `333` | `0x7777...` |

### Payroll Periods

| Company | Period | Start Date | End Date | Status |
|---|---|---|---|---|
| Acme Corp | Q1 2024 | 2024-01-01 | 2024-03-31 | Closed |
| Acme Corp | Q2 2024 | 2024-04-01 | 2024-06-30 | Active |
| GlobalPay Ltd | Feb 2024 | 2024-02-01 | 2024-02-29 | Closed |

## How to Use Fixtures

### 1. In Unit Tests

Use the `fixtures` module to load test data directly:

```rust
#[cfg(test)]
mod tests {
    use payroll::fixtures;

    #[test]
    fn test_with_alice() {
        let alice = fixtures::employee::ALICE;
        assert_eq!(alice.salary, 5000u64);
        assert_eq!(alice.name, "Alice");
    }
}
```

### 2. In Integration Tests

Load fixture companies and employees:

```rust
#[test]
fn test_full_payroll_run() {
    let env = Env::default();
    let acme = fixtures::company::ACME_CORP;
    let alice = fixtures::employee::ALICE;
    
    // Register company
    registry.register_company(&acme.admin, &acme.treasury);
    
    // Enrol employee with fixture commitment
    registry.add_employee(0, &alice.address, &alice.commitment);
}
```

### 3. Dashboard / SDK Development

Reference fixture metadata in external integrations:

```typescript
// JavaScript / TypeScript
import { fixtures } from '@zkpayroll/fixtures';

const alice = fixtures.employees.ALICE;
const commitment = new Uint8Array(alice.commitment);
```

### 4. Local Demo Setup

Use the `setup_with_fixtures()` helper to initialize a full demo:

```rust
let demo = fixtures::setup_with_fixtures(&env);
// Automatically deploys all contracts + registers 3 companies + enrols 6 employees
// Ready for immediate testing
```

## Fixture Determinism

All fixtures are **deterministic** and **reproducible**:

- Addresses are derived from known seeds (not random).
- Salary commitments use `Poseidon_Hash(salary, blinding_factor)`.
- Blinding factors are intentionally simple for manual verification.
- Payroll periods use fixed, well-known dates (no relative dates).

This ensures:
- ✅ Contributors can verify calculations by hand.
- ✅ SDK and dashboard teams align on data assumptions.
- ✅ CI and local tests produce identical results.
- ✅ Proofs generated against fixtures are reproducible.

## Extending Fixtures

To add a new fixture:

1. **Define the data structure** in `fixtures/data.rs`:
   ```rust
   pub const NEW_COMPANY: CompanyFixture = CompanyFixture {
       id: 3,
       name: "My Company",
       admin: Address::...,
       treasury: Address::...,
   };
   ```

2. **Document it** in the fixture registry above.

3. **Add a test** in `fixtures/mod.rs`:
   ```rust
   #[test]
   fn test_new_company_loads() {
       let company = fixtures::company::NEW_COMPANY;
       assert_eq!(company.name, "My Company");
   }
   ```

4. **Update this guide** with the new fixture metadata.

## Proof Fixtures

Mock proofs are provided for testing without proof generation:

```rust
use fixtures::proof;

let mock_proof = proof::VALID_PAYMENT_PROOF_FOR_ALICE;
// Already represents a payment of 5000 XLM from Alice
```

> **Note:** These proofs are mock (all-zero) and exist **only for local testing**.
> They will fail on a real Groth16 verifier. For end-to-end testing, use
> `contracts/integration_tests/proof_helper.rs` to generate real proofs.

## Compatibility Across Teams

### For SDK Developers

- Use `fixtures::employee::ALICE.commitment` to pre-populate SDK test wallets.
- Expect salary amounts and blinding factors to match the values in this guide.

### For Dashboard Developers

- Query fixture companies via the registry contract to populate UI screens.
- Use fixture employee addresses for test transactions.
- Assume all fixtures are **already registered and onboarded**.

### For Contract Developers

- Reference fixture addresses in security tests (e.g., re-entrancy).
- Use fixture commitments to validate proof verification.
- See `docs/fixtures-guide.md` before writing new test scenarios.

## Fixture Decay Policy

Fixtures remain stable and backward-compatible. However:

- **Breaking changes** (adding required new fields, renaming) require an issue + RFC.
- **New fixtures** can be added without breaking existing ones.
- **Removed fixtures** will be announced 2 releases in advance.

## Implementation Details

Fixtures are implemented in:

- `contracts/integration_tests/src/fixtures/` — Rust implementations for contract testing.
- `fixtures/typescript/` — TypeScript bindings for SDK and dashboard.

## Related Resources

- [Contributor Module Checklist](docs/contributor-module-checklist.md) — Fixtures used in per-contract testing.
- [E2E Integration Tests](contracts/integration_tests/src/lib.rs) — Full protocol flow using fixtures.
- [SDK Interface Spec](docs/sdk-interface-spec.md) — Client API aligned to fixture assumptions.
