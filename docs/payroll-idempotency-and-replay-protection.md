# Payroll Execution Idempotency and Replay Protection

This document describes how the ZK Payroll contract prevents duplicate payroll execution,
protects against malicious replays, and ensures safe retry semantics for SDKs and dashboards.

## Problem Statement

Without proper idempotency controls, payroll execution risks:

1. **Duplicate Execution**: Retrying a transaction after temporary failure could create two payments
2. **Replay Attacks**: An attacker could reuse a previously valid payload on new periods or companies
3. **Malicious Modification**: An attacker could modify a payload (e.g., changing the recipient)
   and submit it claiming it was an "old" execution
4. **Cross-Context Confusion**: Payloads could be reused across different companies, periods, or assets

## Solution: Execution Identity and Deterministic Hashing

The contract uses a **canonical execution identity** that uniquely identifies a single logical
payroll run. This identity is deterministic: the same inputs always produce the same identity.

### Execution Identity Components

```rust
struct PayrollExecutionIdentity {
    company_id: u64,              // Ensures no cross-company reuse
    payroll_period: Symbol,       // Ensures no cross-period reuse (e.g., "2024-08")
    batch_commitment_hash: BytesN<32>,  // Hash of all employee commitments
    asset: Address,               // Ensures no cross-asset reuse
    treasury_account: Address,    // Ensures correct treasury receives funds
    nonce: BytesN<32>,           // Caller-supplied unique token (client-side UUID)
}
```

Each component serves a critical role:

| Component | Purpose | Prevents |
|-----------|---------|----------|
| `company_id` | Identifies employer | Cross-company payload reuse |
| `payroll_period` | Time window for payments | Cross-period replay (e.g., paying Jan bonus in Feb) |
| `batch_commitment_hash` | All employee salaries | Modifying which employees are included |
| `asset` | Token/currency for payment | Switching assets (e.g., USD to another token) |
| `treasury_account` | Destination for funds | Misdirecting payments to attacker's account |
| `nonce` | Unique execution token | Generic duplicate prevention |

## Execution Flow

### First Execution

```
1. SDK generates execution identity (company, period, batch, asset, treasury, nonce)
2. SDK computes identity_hash = SHA256(identity)
3. SDK computes payload_hash = SHA256(all execution parameters including amounts)
4. SDK submits to contract: {identity, payload_hash, total_amount, employee_count}
5. Contract checks: identity_hash not in ExecutionRecord store
6. Contract checks: nonce not in NonceIndex store
7. Contract creates: ExecutionRecord(identity, payload_hash, executed_at, ...)
8. Contract stores: ExecutionRecord[identity_hash] → record
9. Contract stores: NonceIndex[nonce] → identity_hash
10. Contract executes: transfer funds, create payment records
11. Contract emits: "execution_registered" event
12. SDK receives: run_id, timestamp, total_paid
```

### Retry with Identical Payload (Safe)

```
1. SDK resubmits with identical identity and payload_hash
2. Contract computes: identity_hash (same as before)
3. Contract checks: ExecutionRecord[identity_hash] exists
4. Contract verifies: stored payload_hash == provided payload_hash ✓
5. Contract returns: cached ExecutionRecord (no state change)
6. SDK detects: run_id same as original (idempotent result)
```

### Replay with Modified Payload (Malicious)

```
1. Attacker resubmits with SAME identity but DIFFERENT payload_hash
   (e.g., changed treasury address or employee amounts)
2. Contract computes: identity_hash (same as original)
3. Contract checks: ExecutionRecord[identity_hash] exists
4. Contract verifies: stored payload_hash != provided payload_hash ✗
5. Contract rejects: ConflictingPayloadData error
6. Attacker gains nothing (original execution is immutable)
```

### New Execution with Reused Nonce (Rejected)

```
1. Attacker attempts new execution with identical nonce but different identity
   (e.g., different company_id or period)
2. Contract checks: NonceIndex[nonce] exists
3. Contract retrieves: stored_identity_hash ≠ new identity_hash
4. Contract rejects: NonceAlreadyUsed error
5. Attacker cannot create new executions with old nonces
```

### Genuine New Execution with New Nonce (Allowed)

```
1. SDK submits new payroll with new nonce
2. Contract checks: identity_hash not in ExecutionRecord ✓
3. Contract checks: nonce not in NonceIndex ✓
4. Contract creates: new ExecutionRecord
5. Execution proceeds normally
```

## Error Codes and Retry Guidance

| Error | Meaning | Retryable? | SDK Action |
|-------|---------|-----------|-----------|
| `NonceAlreadyUsed` (600) | Nonce consumed with different identity | No | Generate new nonce |
| `PayrollAlreadyExecuted` (601) | Same identity executed previously | No | Verify prior execution, or use new nonce |
| `ConflictingPayloadData` (603) | Payload changed after original submission | No | Resubmit with original payload |
| `ExecutionIdentityMismatch` (604) | Stored vs provided identity doesn't match | No | Verify identity parameters |
| `AuthorizationExpired` (605) | Authorization (signature, seq) invalid | No | Regenerate authorization |
| Other errors | Various | Depends | See [error-taxonomy.md](./error-taxonomy.md) |

## SDK Implementation Checklist

### Pre-Execution

- [ ] Generate 32-byte cryptographically secure nonce (UUID or random bytes)
- [ ] Collect all execution parameters: company, period, batch hash, asset, treasury
- [ ] Verify execution identity matches drafted payroll
- [ ] Compute payload hash: `SHA256(company || period || batch || asset || treasury || nonce || amounts || employee_data)`
- [ ] Store nonce and payload_hash in draft record (for audit trail)

### Submission

- [ ] Call `contract.execute_payroll(execution_identity, payload_hash, total_amount, employee_count)`
- [ ] If `ConflictingPayloadData` error: Do NOT retry. Investigate payload discrepancy.
- [ ] If `NonceAlreadyUsed` error: Do NOT retry. Generate new nonce and resubmit.
- [ ] If temporary error (timeout, network): Retry with same nonce and payload_hash.

### Post-Execution

- [ ] Log execution: `{run_id, nonce, payload_hash, execution_timestamp, total_amount}`
- [ ] For audit: Store nonce alongside all related records
- [ ] For reconciliation: Compare returned `total_amount` to expected amount

### Idempotency Testing

- [ ] Test retry immediately after submission → same result
- [ ] Test retry after state change → same result (cached)
- [ ] Test modified payload with same nonce → ConflictingPayloadData error
- [ ] Test nonce reuse with different company → NonceAlreadyUsed error
- [ ] Test network timeout and recovery → correct idempotent behavior

## Payload Hash Computation (Reference Implementation)

```rust
use sha2::{Sha256, Digest};

fn compute_payroll_payload_hash(
    company_id: u64,
    payroll_period: &str,
    batch_commitment_hash: &[u8; 32],
    asset: &Address,
    treasury: &Address,
    nonce: &[u8; 32],
    total_amount: i128,
    employee_payments: &[EmployeePayment],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Core identity parameters
    hasher.update(&company_id.to_be_bytes());
    hasher.update(payroll_period.as_bytes());
    hasher.update(batch_commitment_hash);
    hasher.update(asset.as_bytes());
    hasher.update(treasury.as_bytes());
    hasher.update(nonce);

    // Payment details
    hasher.update(&total_amount.to_be_bytes());
    hasher.update(&(employee_payments.len() as u32).to_be_bytes());

    // Individual employee payments (in canonical order)
    for payment in employee_payments.iter() {
        hasher.update(payment.employee.as_bytes());
        hasher.update(&payment.amount.to_be_bytes());
        hasher.update(&payment.proof_hash);
    }

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
```

**Important**: Use the same hash function and canonical ordering in both SDK and contract
to ensure hashes match. Document hash algorithm in error messages for SDK debugging.

## Nonce Generation (Reference Implementation)

```rust
use rand::Rng;

fn generate_payroll_nonce() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce);
    nonce
}

// Never do this:
// ❌ static_counter += 1  // Reuses nonces after restart
// ❌ derive nonce from timestamp  // Collides under high load
// ❌ use low-entropy nonce  // Guessable
```

## Execution Record Retention

The contract retains `ExecutionRecord` entries indefinitely (or per configuration):

- **Auditing**: Auditors can verify historical payroll execution by checking the record
- **Reconciliation**: SDKs can verify prior executions by querying execution records
- **Dispute Resolution**: If a duplicate execution is claimed, the stored record proves the original

For **archive and compliance**, contract maintainers can implement:
- Periodic snapshot of execution records to external storage
- Compression of old records (e.g., keep hash only, not full record)
- Legal retention period enforcement

## Cross-Contract Coordination

If using multiple contracts (payroll, audit, treasury):

1. **Shared Nonce Validation**: All contracts validate nonce against the same index
2. **Identical Identity Hashing**: All contracts hash execution identity identically
3. **Abort on Conflict**: Any contract rejecting execution blocks the entire run

Example: If `payment_executor` accepts but `audit_module` rejects the same execution identity,
the run is considered failed and must be resubmitted with a new nonce.

## Limitations and Future Work

### Current Limitations

1. **Storage Growth**: ExecutionRecord entries grow with each payroll. Consider archival policies.
2. **Nonce Management**: SDKs must track nonces. Lost nonce tracking can lead to re-execution attempts.
3. **Payload Hash Computation**: SDKs must compute hashes identically to contract. Versioning required.

### Future Enhancements

1. **Execution Record Pruning**: Automated cleanup of very old records (>1 year)
2. **Nonce Expiration**: Nonces that are unused for N ledgers could be re-released
3. **Execution Proof Format**: Standardized receipt format (run_id, nonce, hash, timestamp)

## Debugging Guide

**Issue**: "ConflictingPayloadData on retry"
- Cause: Payload changed between submissions
- Debug: Compare SHA256(identity || amounts || employees) before and after state change
- Fix: Submit with original payload, or use new nonce if payload genuinely differs

**Issue**: "NonceAlreadyUsed with different execution"
- Cause: Nonce reused across different payroll runs
- Debug: Log all nonce usage per company. Check for restart/recovery scenarios.
- Fix: Generate new nonce per execution. Never reuse.

**Issue**: "ExecutionIdentityMismatch"
- Cause: Contract stored vs. SDK provided identity differ
- Debug: Verify company_id, period, batch_hash, asset, treasury all match
- Fix: Ensure execution identity matches original draft exactly

## Related Documents

- [Error Taxonomy](./error-taxonomy.md) — Complete error reference
- [SDK Contract Interface](./sdk-contract-interface.md) — Execute payroll endpoint specification
- [Payroll State Machine](./payroll-state-machine.md) — Lifecycle of payroll runs
- [Reconciliation States](./reconciliation-states.md) — After-execution reconciliation
