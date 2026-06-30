# Contract Event Reference

Structured events emitted by the ZK Payroll contract suite. All events use
PascalCase names and snake_case data fields. Topics carry the event name and
primary identifiers; data carries the event payload.

## Common Conventions

- **Topics[0]** — `Symbol` event name (e.g. `"CompanyRegistered"`)
- **Topics[1..]** — Primary identifiers (`company_id`, `employee`, `auditor`, ...)
- **Data** — Payload values in declaration order
- **Empty data** — Represented as `()` in Rust (no payload)

## payroll_registry

### CompanyRegistered

Emitted when a new company is registered.

```
topics[0]  Symbol("CompanyRegistered")
topics[1]  u64 company_id
data       (Address admin, Address treasury)
```

### EmployeeAdded

Emitted when an employee commitment is stored under a company.

```
topics[0]  Symbol("EmployeeAdded")
topics[1]  u64 company_id
topics[2]  Address employee
data       (BytesN<32> commitment,)
```

### EmployeeRemoved

Emitted when an employee record is permanently removed.

```
topics[0]  Symbol("EmployeeRemoved")
topics[1]  u64 company_id
topics[2]  Address employee
data       ()
```

### CommitmentUpdated

Emitted when an employee's active commitment is replaced in the registry.

```
topics[0]  Symbol("CommitmentUpdated")
topics[1]  u64 company_id
topics[2]  Address employee
data       (BytesN<32> new_commitment,)
```

## salary_commitment

### CommitmentUpdated

Emitted when a salary commitment is stored or updated.

```
topics[0]  Symbol("CommitmentUpdated")
topics[1]  Address employee
data       (BytesN<32> commitment,)
```

## payment_executor

### PayrollProcessed

Emitted after a successful private payment execution.

```
topics[0]  Symbol("PayrollProcessed")
topics[1]  u64 company_id
data       (Address employee, i128 amount, u32 period)
```

## audit_module

### ViewKeyGenerated

Emitted when a view key is generated for an auditor.

```
topics[0]  Symbol("ViewKeyGenerated")
topics[1]  Address auditor
data       (BytesN<32> key_bytes, u32 expiration_ledger)
```

### ViewKeyRevoked

Emitted when a view key is revoked before expiry.

```
topics[0]  Symbol("ViewKeyRevoked")
topics[1]  Address auditor
data       ()
```

### AuditSuccessful

Emitted when a commitment verification succeeds.

```
topics[0]  Symbol("AuditSuccessful")
topics[1]  Address auditor
data       (AuditScope scope, BytesN<32> keyed_stored)
```

### AggregateAuditGenerated

Emitted when an aggregate audit report is generated.

```
topics[0]  Symbol("AggregateAuditGenerated")
topics[1]  Address auditor
data       (Symbol company_id, u64 period_start, u64 period_end)
```

## payroll (legacy)

### payment_executed

Emitted per employee in a batch payroll run.

```
topics[0]  Symbol("payroll")
topics[1]  Symbol("payment_executed")
data       (Address employee, i128 amount)
```

## Consumption Expectations

- **Indexers** should filter by `topics[0]` for the event name and
  `topics[1]` for the primary identifier (company, employee, or auditor).
- **Dashboards** can reconstruct payment history by joining `PayrollProcessed`
  events with off-chain employee metadata.
- **Audit tooling** should listen for `ViewKeyGenerated` and `ViewKeyRevoked`
  to track key lifecycle, and `AuditSuccessful` for compliance logs.
- **Analytics** can track onboarding velocity via `CompanyRegistered` and
  `EmployeeAdded` rates.
