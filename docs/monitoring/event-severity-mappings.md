# Contract Event Severity Mappings — Issue #110

Defines how contract-emitted events map to severity levels in operational
dashboards. Teams should ingest these via a Stellar horizon event stream or
a custom indexer and apply the levels below to drive alert routing and triage.

---

## Severity Scale

| Level | Label | Dashboard colour | Action |
|-------|-------|-----------------|--------|
| 0 | `INFO` | Grey / blue | Log only |
| 1 | `LOW` | Green | No immediate action |
| 2 | `MEDIUM` | Yellow | Investigate within 1 hour |
| 3 | `HIGH` | Orange | Investigate within 15 minutes |
| 4 | `CRITICAL` | Red | Page on-call immediately |

---

## Event Inventory

### `salary_commitment` contract

| Event topic | Data | Severity | Rationale |
|-------------|------|----------|-----------|
| `CommitmentUpdated` | `(employee: Address, commitment: BytesN<32>)` | `LOW` | Normal employee onboarding / salary change |
| `CommitmentRotated` | `(employee: Address, old: BytesN<32>, new: BytesN<32>)` | `MEDIUM` | Proactive commitment rotation; confirm it was authorised |

### `payment_executor` contract

| Event topic | Data | Severity | Rationale |
|-------------|------|----------|-----------|
| `PeriodCreated` | `(company_id: u64, period_id: u32)` | `INFO` | Expected payroll cycle open |
| `PeriodClosed` | `(company_id: u64, period_id: u32)` | `INFO` | Expected payroll cycle close |
| `PayrollProcessed` | `(company_id: u64, employee: Address, amount: i128, period: u32)` | `LOW` | Successful individual payment |

### `payroll` (batch facade) contract

| Event topic | Data | Severity | Rationale |
|-------------|------|----------|-----------|
| `payroll / payment_executed` | `(employee: Address, amount: i128)` | `LOW` | Normal batch payment leg |

### `audit_module` contract

| Event topic | Data | Severity | Rationale |
|-------------|------|----------|-----------|
| `AuditSuccessful` | `(auditor: Address, scope: AuditScope, commitment: BytesN<32>)` | `INFO` | Routine compliance check |
| `AggregateAuditGenerated` | `(auditor: Address, company_id: Symbol, period_start: u64, period_end: u64)` | `INFO` | Aggregate report generated |

### `pause_manager` contract

| Event topic | Data | Severity | Rationale |
|-------------|------|----------|-----------|
| `PauseManager / paused` | `()` | `CRITICAL` | All payroll activity halted — requires immediate investigation |
| `PauseManager / unpaused` | `()` | `HIGH` | Payroll resuming — verify pause root-cause was resolved |

---

## Exceptional / Alert Conditions

These are **inferred** from the absence of expected events or from contract
error codes returned by failed transactions. Dashboards should also monitor
failed transaction results, not just emitted events.

| Condition | Detection | Severity | Response |
|-----------|-----------|----------|----------|
| Double-spend attempt | Transaction fails with `ProofAlreadyUsed` (error 1) | `CRITICAL` | Investigate potential replay attack immediately |
| Payment to unregistered employee | Transaction fails with `Commitment not found` panic | `HIGH` | Verify employee onboarding pipeline |
| Payroll in closed period | Transaction fails with `PeriodClosed` (error 5) | `MEDIUM` | Check scheduler / client sending payments to wrong period |
| Array mismatch in batch | Transaction fails with `ArrayLengthMismatch` (error 2) | `MEDIUM` | Client-side serialisation bug |
| Expired auditor view key | Transaction fails with `KeyExpired` (audit error 3) | `LOW` | Auditor key needs renewal |
| Unauthorised admin action | `require_auth` fails | `HIGH` | Potential key compromise; audit access logs |

---

## Dashboard Groupings

Operational dashboards should group events into three panels:

### Panel 1 — Payroll Flow (normal operations)
Events: `PeriodCreated`, `PeriodClosed`, `PayrollProcessed`, `payment_executed`
Threshold alerts:
- No `PayrollProcessed` events within an expected payroll window → `MEDIUM`
- Payment volume drops >50% vs rolling 7-day average → `MEDIUM`

### Panel 2 — Commitment Lifecycle
Events: `CommitmentUpdated`, `CommitmentRotated`
Threshold alerts:
- Bulk commitment rotations (>10 in 5 minutes) outside a known migration window → `HIGH`

### Panel 3 — Security & Operations
Events: `PauseManager/paused`, `PauseManager/unpaused`
Failed-tx conditions: `ProofAlreadyUsed`, `require_auth` failures
Threshold alerts:
- Any `paused` event → `CRITICAL` (page on-call)
- >3 `ProofAlreadyUsed` errors in 10 minutes → `CRITICAL`
- >5 `require_auth` failures in 10 minutes → `HIGH`

---

## Integration Notes

- Event topics in Soroban are XDR-encoded `ScVal`; use the Stellar SDK's
  `EventFilter` to subscribe by contract address and topic discriminant.
- `amount` in `PayrollProcessed` is the raw `i128` token unit; divide by
  the token's decimal precision before displaying in dashboards.
- `AuditScope` is serialised as a `u32` discriminant: 0=FullCompany,
  1=TimeRange, 2=EmployeeList, 3=AggregateOnly.
- Pair this document with `docs/architecture/commitment-state-storage-layout-13.md`
  for full observability context.
