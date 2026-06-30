# Payload Examples

This document provides concrete JSON payload examples for downstream clients (SDKs and dashboards) interacting with the ZK Payroll contracts. These samples reduce ambiguity in serialization and event consumption.

## Entrypoint Payloads

These represent the arguments passed to Soroban contract invocations. Depending on the SDK (e.g., `soroban-cli` or JS SDK), arguments might be passed as JSON arrays or objects. The examples below show the logical JSON representations of the arguments.

### `SalaryCommitmentContract::store_commitment`

Stores a new salary commitment for an employee.

```json
{
  "employee": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "commitment": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}
```
*(Note: `BytesN<32>` is often represented as a hex string in higher-level SDKs.)*

### `PaymentExecutor::execute_payment`

Executes a single payroll payment.

```json
{
  "company_id": 1,
  "employee": "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  "amount": 5000,
  "proof_a": "0x...",
  "proof_b": "0x...",
  "proof_c": "0x...",
  "nullifier": "0x...",
  "period": 1
}
```

### `PaymentExecutor::execute_batch_payroll`

Executes a batch payroll payment.

```json
{
  "company_id": 1,
  "employees": [
    "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
    "GA2C5QQZAOWTJJFFAQ44XQR5A2RIV5C2P4XQ..."
  ],
  "amounts": [5000, 6500],
  "proofs_a": ["0x...", "0x..."],
  "proofs_b": ["0x...", "0x..."],
  "proofs_c": ["0x...", "0x..."],
  "nullifiers": ["0x...", "0x..."],
  "period": 1
}
```

## Event Payloads

These represent the event data emitted by the contracts and indexed by downstream consumers.

### `CommitmentUpdated` Event

**Topics:**
1. `"CommitmentUpdated"` (Symbol)
2. `employee` (Address)

**Data:**
```json
[
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" 
]
```
*(Tuple containing the new commitment `BytesN<32>`)*

### `PayrollProcessed` Event

**Topics:**
1. `"PayrollProcessed"` (Symbol)
2. `company_id` (u64)

**Data:**
```json
[
  "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6UJWEHLVDJLSB3C0S...",
  5000,
  1
]
```
*(Tuple containing `employee` (Address), `amount` (i128), and `period` (u32))*

### `PeriodCreated` Event

**Topics:**
1. `"PeriodCreated"` (Symbol)
2. `company_id` (u64)

**Data:**
```json
[
  2
]
```
*(Tuple containing `next_id` (u32))*

## Evolving Samples with the API

To maintain consistency as the contract API evolves:
1. Always update this document alongside any pull request that modifies `#[contracttype]` structs, entrypoint signatures, or `env.events().publish()` calls.
2. Ensure that integration tests output or validate against these exact JSON structures where possible.
3. If new data types are introduced (e.g., nested structs), add a representative sample here with all fields fully populated.
