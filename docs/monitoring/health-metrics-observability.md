# ZK Payroll Contracts: Health Metrics and On-Chain Observability

**Issue**: #82 - [Monitoring] Define contract health metrics and on-chain observability signals

## Overview

This document defines the key metrics and observability signals required to monitor ZK Payroll contract behavior in live environments. Operators need predictable, event-derived metrics to identify failed executions, pauses, proof anomalies, and operational issues before they escalate.

## Core Observability Principles

1. **Event-Driven Metrics**: All signals are derived from on-chain events published by the contracts
2. **Non-Leaking**: Metrics never expose plaintext salary amounts or sensitive proof data
3. **Real-Time**: Events are published synchronously during execution (no delayed reporting)
4. **Auditable**: All metrics can be traced back to specific transactions and roles
5. **Dashboard-Ready**: Metrics are structured for easy ingestion by monitoring dashboards (Grafana, Datadog, etc.)

## Events and Signals

### Payroll Contract Events

#### `run_prepared` (Issue #75)
**Emitted**: When a payroll run is prepared (pending finalization)
```
Event: ("payroll", "run_prepared")
Data: (run_id: u64, total_amount: i128)
```
**Signals**:
- Operator intent to execute payroll
- Budget reservation (total_amount indicates planned spend)
- Nonce consumption (prevents duplicate runs)

**Alert Triggers**:
- `run_prepared` without corresponding `run_executed` or `run_cancelled` after 24 hours = stalled preparation
- `run_prepared` but actual amount != declared amount = validation mismatch

#### `run_executed` (Existing)
**Emitted**: When a payroll run completes execution
```
Event: ("payroll", "run_executed")
Data: (run_id: u64, total_amount: i128)
```
**Signals**:
- Payroll execution completed
- Treasury debit confirmed
- Employee count processed (derived from amount)

**Alert Triggers**:
- `run_executed` but no payment events published = proof failures
- `run_executed` with `total_amount` spike > 2 sigma from rolling average = anomaly
- `run_executed` but reconciliation_status = Failed within 30 minutes = post-execution detection of issues

#### `run_cancelled` (Issue #75)
**Emitted**: When a pending payroll run is cancelled
```
Event: ("payroll", "run_cancelled")
Data: (run_id: u64, total_amount: i128)
```
**Signals**:
- Operator halted a prepared run
- Budget reservation released
- Reason implicit (may be paired with off-chain reason logs)

**Alert Triggers**:
- Multiple `run_cancelled` events from same admin within 1 hour = possible misconfiguration
- `run_cancelled` for high-value runs (> threshold) = operational review needed

#### `deposit` (Existing)
**Emitted**: When tokens are deposited to treasury
```
Event: ("payroll", "deposit")
Data: (from: Address, amount: i128)
```
**Signals**:
- Treasury replenishment
- Account funding events

**Alert Triggers**:
- Deposit but insufficient balance before execution = treasury underprovisioning
- Large single deposit = possible fund movement outside normal patterns

#### `reconciliation_updated` (Existing)
**Emitted**: When reconciliation status changes for a completed run
```
Event: ("payroll", "reconciliation_updated")
Data: (run_id: u64, status: ReconciliationStatus)
```
**Signals**:
- Audit status of completed run
- Post-execution validation outcome

**Alert Triggers**:
- `reconciliation_updated` with Failed status = execution validation failed
- Reconciliation status update delayed > 7 days after execution = slow audit cycle

#### Emergency Withdrawal Events (Issue #104, Existing)
- `emrg_requested`: Withdrawal request created
- `emrg_approved`: Withdrawal request approved and executed
- `emrg_cancelled`: Withdrawal request cancelled

**Alert Triggers**:
- Emergency withdrawal during normal business hours = unexpected treasury action
- Multiple emergency withdrawals in 24 hours = possible compromise

### Payment Executor Events

#### `PeriodCreated` (Existing)
**Emitted**: When a new payroll period is opened
```
Event: ("PeriodCreated", company_id)
Data: (period_id: u32)
```
**Signals**:
- Start of new payroll cycle
- Period initialization

**Alert Triggers**:
- Multiple periods open simultaneously (should be sequential) = state machine violation
- Period creation without subsequent payments > 48 hours = unused period

#### `PeriodClosed` (Existing)
**Emitted**: When a payroll period is closed to new payments
```
Event: ("PeriodClosed", company_id)
Data: (period_id: u32)
```
**Signals**:
- End of payroll cycle
- Finalization point for that period

**Alert Triggers**:
- Period closed with 0 payments = empty period (configuration issue)
- Period closed without preceding open = state violation

#### `PayrollProcessed` (Existing)
**Emitted**: When a payment is executed
```
Event: ("PayrollProcessed", company_id)
Data: (employee: Address, amount: i128, period: u32)
```
**Signals**:
- Individual payment confirmation
- Per-employee execution status

**Alert Triggers**:
- Payment to same employee in same period = duplicate execution
- Payment amount = 0 = invalid execution
- Payment amount spike for employee = possible data error

### Pause Manager Events (Existing)

#### `pause` / `unpause`
**Signals**:
- System-wide execution pause
- Emergency stop activation

**Alert Triggers**:
- System paused > 2 hours = operational incident ongoing
- Unpause without corresponding pause = state corruption

## Health Metrics Dashboard

### Real-Time Metrics

| Metric | Source | Calculation | Normal Range | Alert Threshold |
|--------|--------|-------------|--------------|-----------------|
| Active Periods | `PeriodCreated` - `PeriodClosed` | Count of open periods | 0-2 | > 2 |
| Payments Per Period | `PayrollProcessed` events | Sum per period | 10-1000 | > 1000 (batch size) or < 5 |
| Treasury Balance | Token contract | Real-time balance | Varies | < 10% of avg run size |
| Avg Payment Latency | Event timestamps | `PayrollProcessed` - `PeriodCreated` | < 5 seconds | > 30 seconds |
| Proof Expiration Rate | `PaymentError::ProofExpired` counts | Failed proofs / total attempts | < 0.1% | > 1% |

### Batch-Level Metrics

| Metric | Source | Calculation | Normal Range | Alert Threshold |
|--------|--------|-------------|--------------|-----------------|
| Run Success Rate | `run_executed` / (`run_prepared` + `run_cancelled`) | % runs that execute | 90-100% | < 90% |
| Reconciliation Lag | `reconciliation_updated` timestamp - `run_executed` timestamp | Hours until audit complete | 0-72 | > 168 (7 days) |
| Nonce Collision Rate | `Duplicate run nonce` errors | Collision attempts / total attempts | 0 | > 0 (any collision is anomalous) |
| Proof Verification Success Rate | Valid proofs / total proof submissions | % proofs passing verification | 95-100% | < 95% |

### Operational Metrics

| Metric | Source | Calculation | Normal Range | Alert Threshold |
|--------|--------|-------------|--------------|-----------------|
| System Pause Duration | `pause` → `unpause` events | Total paused time per day | 0 hours | > 1 hour |
| Admin Actions Per Day | All events with admin authorization | Count of authorized operations | 5-50 | > 100 (suspicious activity) |
| Emergency Withdrawal Frequency | `emrg_requested` events | Requests per month | < 2 | > 1 per week |
| Draft Commitment Reuse | `commit_draft` → `commit_draft` (same hash) | Unexpected resubmissions | 0 | > 0 |

## Observability Checklist

### Event Publishing
- [ ] All contract functions publish relevant events
- [ ] Events include sufficient context (IDs, amounts, timestamps, addresses)
- [ ] Sensitive data (plaintext salaries) is never included in events
- [ ] Event names follow consistent naming convention

### Metric Derivation
- [ ] All metrics can be computed from event streams
- [ ] Metrics are time-windowed appropriately (real-time, hourly, daily)
- [ ] Metric calculations handle edge cases (empty periods, zero amounts)
- [ ] Metrics support aggregation across multiple companies

### Alerting
- [ ] Each metric has defined alert thresholds
- [ ] Alerts include contextual information (company_id, run_id, timestamp)
- [ ] False positive rate is minimized (thresholds are data-driven, not arbitrary)
- [ ] Alert escalation procedures are documented

### Dashboard Integration
- [ ] Grafana/Datadog dashboards pull from event logs
- [ ] Dashboards display all core metrics and trends
- [ ] Dashboards support filtering by company, time range, metric
- [ ] Dashboard SLOs are documented (e.g., 99.5% uptime)

## Anomaly Detection Patterns

### Pattern: Proof Expiration Spikes
**Symptoms**:
- `ProofExpired` error rate suddenly rises above 1%
- Multiple failures for same company within short time window

**Root Causes**:
- Off-chain proof generation is delayed (SDK regression, slow circuit)
- On-chain period creation has regressed (period is unexpectedly old)
- Clock skew between off-chain and on-chain systems

**Response**:
1. Check off-chain proof generation latency
2. Verify on-chain period creation timestamps
3. Compare local time with network time
4. If persistent, pause affected company and investigate proof pipeline

### Pattern: Reconciliation Delays
**Symptoms**:
- Runs execute but reconciliation status not updated > 24 hours

**Root Causes**:
- Audit service is offline or slow
- Admin has forgotten to call `update_reconciliation_status`
- Data inconsistency requires manual review

**Response**:
1. Verify audit service connectivity
2. Check for any Failed reconciliation attempts
3. Reach out to admin team for manual status update

### Pattern: Nonce Collision Attempts
**Symptoms**:
- `Duplicate run nonce` error appears in logs

**Root Causes**:
- Off-chain system resubmitting the same run (idempotency issue)
- Attacker attempting to replay a known nonce
- State synchronization issue between systems

**Response**:
1. Verify resubmission is intentional (client retry logic)
2. If repeated, investigate for replay attack
3. Consider increasing nonce entropy

### Pattern: Treasury Depletion
**Symptoms**:
- Treasury balance drops below 10% of average run size

**Root Causes**:
- Large payroll run unexpected
- Deposit mechanism failed
- Unexpected emergency withdrawal

**Response**:
1. Verify upcoming payroll runs are scheduled
2. Check deposit transaction status
3. Review emergency withdrawal requests
4. Alert treasury owner to rebalance funds

## SDK Consumer Guidance

### Integration Steps
1. Subscribe to all contract events via Soroban event subscription API
2. Aggregate events into time-windowed buckets (real-time, hourly, daily)
3. Compute metrics from aggregated events
4. Push metrics to monitoring backend (Prometheus, Datadog, Cloudwatch)
5. Set up alerts based on thresholds defined in this document

### Example: Computing Run Success Rate
```pseudo
// Aggregate events over 24-hour window
prepared_count = count(run_prepared events in window)
cancelled_count = count(run_cancelled events in window)
executed_count = count(run_executed events in window)

success_rate = executed_count / (prepared_count - cancelled_count + executed_count)

if success_rate < 0.90:
    alert("Run success rate dropped below 90%", {success_rate, window})
```

### Example: Detecting Proof Expiration Spike
```pseudo
// Count proof expiration errors in rolling 1-hour window
expiration_errors = count(PaymentError::ProofExpired in last 1h)
total_attempts = count(execute_payment calls in last 1h)

expiration_rate = expiration_errors / total_attempts

if expiration_rate > 0.01:  // > 1%
    alert("Proof expiration rate spike", {
        rate: expiration_rate,
        error_count: expiration_errors,
        window: "1h"
    })
```

## Future Enhancements

1. **Ledger-Indexed Metrics** (Issue #90): Support querying historical metrics by ledger sequence for regulatory compliance.

2. **Custom Alert Rules** (Issue #91): Allow operators to define custom alert rules per company (e.g., "alert if run > $500K").

3. **Event Filtering API** (Issue #92): Expose filtered event queries (e.g., "all PayrollProcessed events for company X in period Y").

4. **Metrics Retention Policy** (Issue #93): Define how long to retain metric aggregates (e.g., 2 years of daily aggregates).

---

**Last Updated**: June 2026  
**Document Owner**: DevOps / SRE Team  
**Next Review**: June 2027
