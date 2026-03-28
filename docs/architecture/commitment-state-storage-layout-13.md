# Issue #13: State Management and Storage Layout for Commitments

## Goal
Define a Soroban storage layout for Poseidon salary commitments that minimizes rent and avoids transaction size failures.

## Decision Summary
- Use individualized keys: `DataKey::Commitment(company_id, employee_address)`.
- Do not store all employee commitments in one `Vec` under a company key.
- Bump TTL on write paths and payment execution paths; do not rely on an on-chain cron (Soroban has no native scheduler).

## Storage Options Evaluated

### Option A: Single vector per company
- Key: `DataKey::CompanyCommitments(company_id)`
- Value: `Vec<(Address, BytesN<32>)>`

Operational impact:
- Read/update one employee requires reading and writing the entire company vector.
- Lookup/update is effectively `O(n)` on-chain for finding an employee inside the vector.
- A single large read/write can exceed Soroban host read/write limits.

### Option B: Individual mapping keys (recommended)
- Key: `DataKey::Commitment(company_id, employee_address)`
- Value: `CommitmentRecord { commitment: BytesN<32>, created_at: u64, updated_at: u64, version: u32 }`

Operational impact:
- One employee lookup/update touches one key/value pair.
- Lookup/update is `O(1)` by exact key.
- Avoids loading unrelated employees into one transaction.

## Byte Overhead Comparison (Estimate)

Assumptions for rough sizing:
- `Address` payload: ~32 bytes (plus XDR/SCVal envelope overhead)
- `BytesN<32>` commitment: 32 bytes
- `CommitmentRecord` payload: `32 + 8 + 8 + 4 = 52` bytes (without envelope overhead)
- Soroban per-op read/write budget is constrained enough that very large single entries fail long before 10k employees.

### Estimated entry sizes
- Vector entry `(Address, BytesN<32>)`: ~80-96 bytes effective serialized footprint per employee.
- Mapping entry `DataKey::Commitment(company_id, employee) -> CommitmentRecord`: ~120-160 bytes per employee when key+value envelopes are included.

### Estimated 10,000 employee footprint
- Single vector value only: ~800 KB to ~960 KB in one value.
- Mapping total across all entries: ~1.2 MB to ~1.6 MB aggregate, but split across 10,000 independent keys.

Key conclusion:
- Mapping may have slightly higher aggregate ledger bytes due to per-key overhead, but it is the only practical model for Soroban execution limits.
- Single-vector design fails transaction read/write constraints for large companies.

## Why Mapping Wins Despite Extra Per-Key Overhead
- Prevents catastrophic single-key bloat.
- Enables incremental updates (one employee at a time).
- Enables predictable gas and rent behavior per operation.
- Supports scalable payroll processing and auditing patterns.

## TTL Strategy

### Recommended policy
1. Bump TTL when a commitment is created or updated.
2. Bump TTL when a payment references that commitment (payment execution path).
3. Bump TTL when a nullifier is written/checked in payment flow.
4. Optional off-chain keeper can periodically refresh active companies in batches; do not require cron semantics in contract.

### Why not cron-only
- Soroban contracts do not have native cron execution.
- A cron-only strategy risks expiry for rarely updated but still valid commitments.
- TTL refresh should occur naturally on business actions (updates and payments).

### Suggested TTL constants (example)
- `TARGET_TTL = 180 days`
- `RENEW_THRESHOLD = 30 days`
- With ~5s ledgers:
  - `TARGET_TTL_LEDGERS = 3,110,400`
  - `RENEW_THRESHOLD_LEDGERS = 518,400`

Usage pattern:
- On each relevant operation:
  - `persistent.extend_ttl(&key, RENEW_THRESHOLD_LEDGERS, TARGET_TTL_LEDGERS)`

## Proposed DataKey Layout

```rust
pub enum DataKey {
    Company(u64),
    Commitment(u64, Address),
    Nullifier(BytesN<32>),
    NextCompanyId,
}
```

## Acceptance Criteria Mapping
- Data Key Design benchmarked: vector vs mapping tradeoff documented with size estimates and operational complexity.
- Required conclusion: individualized mappings are required for `O(1)` lookups and to avoid massive single-entry state bloat.
- TTL strategy defined: refresh on payment/update flows, optional off-chain keeper batching.
- Markdown deliverable completed.
