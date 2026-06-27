# ADR-001: Privacy and Audit Trade-offs in ZK Payroll

## Status

Accepted

## Context

ZK Payroll Contracts aim to process payroll on-chain while keeping individual salary amounts private. This creates inherent tension between:

1. **Privacy** — Employees' salary amounts must not be publicly visible
2. **Auditability** — Companies must demonstrate compliance to regulators and auditors
3. **Operational Simplicity** — The system must remain usable for HR teams and developers

Traditional payroll systems expose all salary data publicly. Fully private systems prevent any verification. We must find a middle ground.

## Decision

We adopt a **selective disclosure architecture** that balances these concerns:

### Privacy Model

- Salary amounts stored as **Poseidon hash commitments**: `commitment = Poseidon(salary, blinding_factor)`
- Commitments stored in `payroll_registry` under `DataKey::Employee(company_id, employee_address)`
- Public inputs to ZK proofs include only the commitment hash and payment amount, not the salary directly
- No salary data is ever emitted in events or stored in plaintext on-chain

**Implementation**: `payroll_registry/src/lib.rs:94-104` stores commitments, `salary_commitment/src/lib.rs:96-102` retrieves them.

### Audit Model

- **View keys** enable selective disclosure without compromising permanent privacy
- Four audit scopes defined in `audit_module/src/lib.rs:57-66`:
  - `FullCompany` — Unrestricted read on all payroll data
  - `TimeRange` — Read within a specific time range only
  - `EmployeeList` — Verify individual commitments for named employees
  - `AggregateOnly` — Aggregate totals only, no per-employee data
- View keys expire by ledger sequence (`audit_module/src/lib.rs:153-162`)
- Auditors verify commitments by recomputing with their view key (`audit_module/src/lib.rs:294-321`)

### Key Trade-offs

| Concern | Decision | Rationale |
|---------|----------|-----------|
| Privacy vs. Audit | Privacy is default; audit is opt-in via view keys | Protects employees while enabling compliance |
| Transparency | Payment amount emitted in events (`payment_executor/src/lib.rs:163-171`) | Enables accounting/tracking without revealing salary |
| Blinding factor | Must be managed off-chain; commitment can be verified with blinding | Required for zero-knowledge; creates key custody burden |
| Scope enforcement | Enforced at contract level, not just policy | Prevents accidental data exposure |
| Nullifier storage | Stored publicly to prevent double-payment | Minor metadata leak; necessary for security |

## Consequences

### Positive

- Individual salaries remain private by default
- Regulators can verify payroll without accessing all salary data
- HR can generate time-bound audit reports
- Employees control their own blinding factors (can prove salary ownership off-chain)

### Negative

- Off-chain key management required for blinding factors
- View key generation adds operational step for companies
- Audit logs show when audits occur (metadata leak)
- Proof generation overhead for each payment

### Neutral

- Payment amounts are visible in `PayrollProcessed` events (not salary, but observable spending)
- Commitment updates are publicly visible (`EmployeeAdded`, `CommitmentUpdated` events)

## Related Contracts

| Contract | Privacy Role | Audit Role |
|----------|--------------|------------|
| `payroll_registry` | Stores commitments | Employees registered with commitments |
| `salary_commitment` | Computes/verifies commitments | Commitment source for auditors |
| `proof_verifier` | Verifies payment proofs | N/A |
| `payment_executor` | Uses commitments in proof verification | Emits payment events |
| `audit_module` | N/A | View key management and selective disclosure |

## Future Considerations

- **Issue #20**: Public inputs to ZK proofs must include on-chain commitment
- **Issue #28**: Batch payment optimization may affect nullifier checking
- **CAP-0075**: Native Poseidon host functions will replace SHA256 stand-ins
- **Token emission**: Consider if payment amounts should be hidden in events

## References

- See `docs/events.md` for event schema that enables off-chain indexing
- See `docs/architecture/commitment-state-storage-layout-13.md` for storage layout rationale