# ZK Payroll Contracts: Retention and Archival Policy

**Issue**: #79 - [Compliance] Define retention and archival rules for audit-related payroll records

## Overview

This document defines the retention expectations for audit-related payroll records stored on-chain and off-chain. Compliance consumers need predictable retention expectations to satisfy regulatory requirements and audit workflows.

## Record Classification

### Permanent Records (No Expiration)

The following records MUST be retained indefinitely:

1. **Payroll Run Executions** (`PayrollRun` records in the contract)
   - `run_id`: Unique run identifier
   - `executed_at`: Timestamp of execution
   - `admin`: Address of authorizing admin
   - `total_amount`: Total payout for the run
   - `employee_count`: Number of employees paid
   - `draft_hash`: Hash of the off-chain preparation artifact (#102)
   - `nonce`: Run-unique nonce for idempotency (#103)
   - `reconciliation_status`: Final reconciliation outcome

   **Justification**: These records form the immutable ledger of payroll history. They are typically required for 3-7 years under most payroll regulations (SOX, GDPR, labor law).

2. **Payment Records** (`PaymentRecord` in `payment_executor`)
   - `company_id`: Company identifier
   - `employee`: Employee address
   - `proof_hash`: Hash of the ZK proof used
   - `timestamp`: When the payment executed
   - `period`: The period ID

   **Justification**: Individual payment records are audit evidence for payroll compliance, tax reporting, and employee disputes.

3. **Salary Commitments** (on commitment contract)
   - Employee salary commitments (as hashed values, not plaintext)
   - Nullifier tracking to prevent duplicate payments

   **Justification**: Commitment hashes tie proofs to verified amounts without exposing plaintext salaries.

4. **Period Metadata** (`PayrollPeriod` records)
   - `period_id`, `company_id`, `start_ledger`, `end_ledger`, `created_at`
   - `closed` status and `payment_count`

   **Justification**: Period metadata provides temporal context for audit queries without leaking salary amounts.

### Archival Records (Queryable, Optional Compression)

The following records are queryable but MAY be archived after regulatory hold periods:

1. **Emergency Withdrawal Requests** (once completed)
   - Can be moved to archive after 1 year if not under dispute
   - Retain proof of authorization and execution

2. **Draft Commitments** (pending runs)
   - Kept only while run is in pending state
   - Automatically removed on finalization or cancellation
   - Never archived (temporary by design)

3. **Reconciliation Status Updates**
   - Queryable for 3-7 years (depending on jurisdiction)
   - May be archived after regulatory hold period

### Temporary Records (Ephemeral, No Archival)

1. **Pending Payroll Runs** (`PendingPayrollRun` in payroll contract)
   - Automatically removed upon finalization or cancellation
   - No need to archive; they are transient operational state

2. **Session/Authentication State**
   - Not stored on-chain
   - Managed off-chain; not subject to archival rules

## Retention Timeline

| Record Type | Queryable Duration | Archival Trigger | Archive Duration | Destruction Policy |
|-------------|-------------------|------------------|------------------|--------------------|
| Completed Payroll Runs | Indefinite | Optional after 7 years | No fixed end | Legal hold may apply |
| Payment Records | Indefinite | Optional after 7 years | No fixed end | Legal hold may apply |
| Salary Commitments | Indefinite | N/A | N/A | Permanent on-chain |
| Period Metadata | Indefinite | Optional after 5 years | No fixed end | Legal hold may apply |
| Emergency Withdrawal Requests | 3-7 years | After regulatory hold | 1+ years | As per jurisdiction |
| Reconciliation Updates | 3-7 years | After regulatory hold | 1+ years | As per jurisdiction |
| Pending Runs | Duration of run | N/A | N/A | Auto-cleanup on finalization |

## Storage Implications

### On-Chain Storage

On-chain records (Soroban persistent storage) are immutable and retained by the ledger permanently. No archival or deletion is possible without breaking the chain of custody.

**Cost Impact**: 
- Each `PayrollRun` record occupies ~200 bytes in persistent storage
- Each `PaymentRecord` occupies ~120 bytes
- Large payroll batches (50+ employees) generate significant storage growth
- Estimated growth: ~10KB per 50-employee payroll batch

**Mitigation**:
- Batch payments to reduce transaction overhead
- Use period-based queries to avoid scanning all history
- Consider ledger archival snapshots (off-chain, optional)

### Off-Chain Storage

Off-chain records (audit artifacts, proof logs, compliance dashboards) may be archived to cold storage after retention periods:

1. **Proof Log Archive** (after 7 years):
   - Compress proof verification logs to archive storage
   - Retain metadata index for recovery
   - Implement retention workflow (e.g., S3 Glacier)

2. **Draft Artifact Archive** (after regulatory hold):
   - Archive SHA-256 hashes of original payroll preparation artifacts
   - Can be deleted if no active disputes

3. **Compliance Reports** (as per jurisdiction):
   - Archive audit trail summaries
   - Retain summary statistics permanently

## Regulatory Context

- **SOX (Sarbanes-Oxley)**: Payroll records require 3-7 year retention (varies by jurisdiction)
- **GDPR**: Personal data (including salary) must be deleted when no longer needed, with exceptions for legal obligations
- **Labor Law**: Most jurisdictions require 3-4 year payroll record retention
- **Tax Law**: IRS/equivalent bodies typically require 3-6 year retention

**Note**: This policy provides conservative defaults. Each company MUST verify requirements for their specific jurisdiction and update their retention practices accordingly.

## Compliance Evidence

The following queries MUST remain available for audit purposes:

1. **Run-level Evidence**:
   ```
   Get all runs for a company within a date range
   Get detailed execution history for a specific run
   Verify nonce uniqueness (no duplicate submissions)
   ```

2. **Payment-level Evidence**:
   ```
   Get all payments to a specific employee within a period
   Verify proof usage (nullifier checks)
   Validate period-to-payment mapping
   ```

3. **Reconciliation Evidence**:
   ```
   Get reconciliation status for a run
   Trace status changes with timestamps
   Verify admin authorization for each update
   ```

## Implementation Checklist

- [ ] All `PayrollRun` records are queryable indefinitely
- [ ] All `PaymentRecord` records are queryable indefinitely
- [ ] Pending runs are automatically cleaned up on finalization/cancellation
- [ ] Draft commitments are consumed (removed) after use
- [ ] Reconciliation status updates include timestamps and admin address
- [ ] Emergency withdrawal records include authorization proof
- [ ] Off-chain audit logs include proof verification results
- [ ] Archive policy is documented in SDK client libraries
- [ ] Legal review confirms compliance with target jurisdictions

## Future Enhancements

1. **Granular Deletion** (Issue #86): Allow selective deletion of personal data (employee address mappings) for GDPR compliance, while retaining anonymized execution history.

2. **Encryption at Rest** (Issue #87): Support encrypted storage for sensitive fields (employee address) in archival systems.

3. **Archive Snapshot API** (Issue #88): Provide off-chain APIs to export archival-ready snapshots for compliance dashboards.

4. **Retention Reporting** (Issue #89): Automated reports showing what data is available for audit queries and when archival deadlines approach.

---

**Last Updated**: June 2026  
**Document Owner**: Compliance Team  
**Next Review**: June 2027
