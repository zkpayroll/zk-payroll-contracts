# Recommended Alert Rules for ZK Payroll Operations

This document defines recommended alert thresholds and rules for monitoring the most critical operational failures in payroll execution, proof verification, and audit workflows.

Pair with [event-severity-mappings.md](./event-severity-mappings.md) for severity classifications.

---

## Alert Rules by Category

### 1. Pause Events (CRITICAL Priority)

**Alert Name**: `PauseManager/paused`  
**Severity**: CRITICAL  
**Response Time**: Immediate (page on-call)

**Rule**:
```
IF any PauseManager/paused event emitted
THEN trigger CRITICAL alert
```

**Rationale**: A pause halts all payroll activity. This is an emergency event indicating either:
- An operator detected a security issue and triggered pause manually
- An automated circuit breaker detected anomalous behavior
- A bug or exploit was discovered in production

**Action on Alert**:
1. Incident lead contacts contract owner within 2 minutes
2. Investigate root cause: review preceding transactions, check for proof replay or unauthorized mutations
3. Assess if pause scope is sufficient or if additional contracts need halting
4. Prepare customer communication before unpausing

**Recovery**:
- Do not unpause until root cause is confirmed fixed
- Verify fix on testnet first
- Unpause only after incident lead approval

---

### 2. Proof Replay / Double-Spend (CRITICAL Priority)

**Alert Name**: `PaymentError/ProofAlreadyUsed`  
**Severity**: CRITICAL  
**Threshold**: Any single occurrence OR >3 within 10 minutes

**Rule**:
```
IF transaction fails with error code 1 (ProofAlreadyUsed)
THEN trigger CRITICAL alert
AND aggregate >3 occurrences in 10 min window
THEN trigger higher-escalation alert
```

**Rationale**: 
- **Single occurrence**: Could indicate operator testing or a single adversarial submission — still needs investigation
- **Multiple within 10 min**: Signals either systematic replay attack or a nullifier storage bug

**Detection**: Monitor failed transaction results from `payment_executor.execute_payment`

**Action on Alert**:
1. Immediately review transaction hashes and sender addresses
2. Check for pattern (same proof, different periods? same employee/company combinations?)
3. If patterns suggest systematic attack, pause the system manually
4. If patterns suggest nullifier storage bug, escalate to ZK engineer

**Operational Impact**: Duplicate payments may have already been executed. Financial reconciliation is required.

---

### 3. Unauthorized Admin/Revocation Attempts (HIGH Priority)

**Alert Name**: `require_auth failure` (payment_executor, audit_module)  
**Severity**: HIGH  
**Threshold**: >5 failures within 10 minutes

**Rule**:
```
IF transaction fails with require_auth panic
AND originating from admin/auth-required entrypoint
THEN log as security event
IF >5 such failures in rolling 10-min window
THEN trigger HIGH alert
```

**Rationale**: 
- A small number of failed auth attempts can happen (user testing wrong key, stale client credentials)
- >5 in 10 minutes suggests either compromised key or active exploitation attempt

**Affected Entrypoints**:
- `payment_executor.execute_payment` (requires valid proof signature)
- `audit_module.revoke_view_key` (requires authorized admin/revocation role)
- `payroll_registry.add_employee` (requires company admin)

**Action on Alert**:
1. Identify the actor (public key / address attempting calls)
2. Check if actor is known (employee, auditor, admin)
3. If unknown: potential key compromise — recommend password/key rotation
4. Review preceding successful authentications from that actor to establish baseline
5. Audit: did unauthorized revocation succeed? (check audit_module logs)

**Recovery**:
- If key is compromised, rotate credentials and re-issue view keys
- If revocation was unauthorized, restore access via new view key issuance

---

### 4. Commitment Verification Failures (HIGH Priority)

**Alert Name**: `PaymentError/CommitmentNotFound` OR `PaymentError/InvalidCommitment`  
**Severity**: HIGH  
**Threshold**: >10 within 1 hour

**Rule**:
```
IF transaction fails with CommitmentNotFound or InvalidCommitment
AND employee exists in payroll_registry (confirm via on-chain query)
THEN log as mismatch event
IF >10 mismatches in 1-hour rolling window
THEN trigger HIGH alert
```

**Rationale**: 
- **Single mismatch**: Likely operator error (paying an employee in wrong company) or data sync lag
- **>10 within 1 hour**: Indicates either:
  - Client library bug sending wrong commitment
  - Commitment rotation not propagated to all callers
  - Deliberate mismatched payment attempt

**Detection**: Monitor failed transaction results from `payment_executor.execute_payment`

**Action on Alert**:
1. Check if commitment rotations occurred in the preceding 30 minutes (check `salary_commitment` events)
2. Compare client-submitted commitments against on-chain values
3. Verify that CLI and SDK clients are running the same version (version mismatch could cause drift)
4. Check if payroll batch was generated from stale employee roster

**Recovery**:
- If rotation caused mismatch, notify operator to re-run batch with current commitments
- If version mismatch, update clients
- If data sync issue, resync employee roster from authoritative source

---

### 5. Proof Verification Failures (MEDIUM Priority)

**Alert Name**: `ProofVerifier/VerificationFailed`  
**Severity**: MEDIUM  
**Threshold**: Any single occurrence during production payroll

**Rule**:
```
IF transaction fails during proof verification (proof_verifier contract panics)
AND within known payroll window (e.g., 9-5 business hours)
THEN trigger MEDIUM alert
```

**Rationale**:
- During testing/development: proof generation may be broken, is expected
- During production payroll: signals either:
  - Proof generation pipeline produces invalid proofs
  - Verification key was corrupted or rotated unexpectedly
  - Prover and verifier are misaligned (zkey vs verification key mismatch)

**Detection**: Monitor failed transaction results from `proof_verifier.verify_proof`

**Action on Alert**:
1. Check if verification key was recently updated (check `ProofVerifier` events)
2. Verify that prover (off-chain) is using the correct zkey matching on-chain verification key
3. Regenerate a test proof locally and verify it passes on-chain
4. Check circuit constraint logs for any recent changes

**Recovery**:
- If zkey/verification key mismatch, redeploy contracts with matched pair
- If prover bug, fix and regenerate proofs
- If verification key corrupted, revert to previous version and investigate

---

### 6. Payroll Period Anomalies (MEDIUM Priority)

**Alert Name**: `PeriodClosed/PaymentAttempted`  
**Severity**: MEDIUM  
**Threshold**: >3 within 1 hour

**Rule**:
```
IF transaction fails with PeriodClosed error
AND period exists and is confirmed closed
AND >3 such failures in 1-hour window
THEN trigger MEDIUM alert
```

**Rationale**: 
- **Single occurrence**: Operator submitted batch to wrong period, user error
- **>3 within 1 hour**: Indicates either:
  - Scheduler bug sending batches to closed periods
  - Time drift between operator clock and blockchain clock
  - Stale period state cached in client

**Detection**: Monitor failed transaction results from `payment_executor.execute_payment`

**Action on Alert**:
1. Confirm which period is closed (query `payment_executor.get_period_status`)
2. Check scheduler logs / client timestamps to see if operator is using stale period ID
3. Verify operator clock is synchronized (NTP check)
4. Check if there's a natural period boundary that was crossed unexpectedly

**Recovery**:
- If scheduler bug: fix and re-run for correct period
- If time drift: resync operator clock
- If stale cache: clear client cache and retry

---

### 7. View Key Expiration / Audit Access Denial (LOW Priority)

**Alert Name**: `audit_module/KeyExpired`  
**Severity**: LOW  
**Threshold**: Informational; aggregate for reporting

**Rule**:
```
IF audit_module.verify_access returns false for known auditor
AND view key exists but is past expiration_ledger
THEN log as expected expiration
IF >5 expired keys per day (unusual high rate)
THEN trigger LOW alert (possible key rotation issue)
```

**Rationale**: 
- Key expiration is expected behavior; auditors must request new keys periodically
- High expiration rate could indicate issue with key issuance process

**Detection**: Monitor `audit_module` state queries

**Action on Alert** (only if high rate):
1. Review audit workflow: how often are keys being issued?
2. Check if key lifetime is configured too short
3. Verify audit scheduling — if audits happen more frequently than key lifetime, reconfigure

**Recovery**:
- Issue new view key to auditor
- Consider adjusting key lifetime to align with audit frequency

---

### 8. Batch Payment Gaps (MEDIUM Priority)

**Alert Name**: `PayrollRun/GapDetected`  
**Severity**: MEDIUM  
**Threshold**: Any gap in run IDs > 1

**Rule**:
```
IF run_id sequence has gap (e.g., run_id 100, then run_id 102)
THEN trigger MEDIUM alert
```

**Rationale**: Run IDs are contiguous and monotonically increasing. A gap indicates:
- A batch transaction failed and was not retried
- A batch was cancelled without completing
- A bug in run ID allocation

**Detection**: Indexer tracking `run_executed` events should monitor run_id sequence

**Action on Alert**:
1. Query failed transaction history around the gap timestamp
2. Check if there's a corresponding failed `batch_process_payroll` transaction
3. Verify if gap was intentional (operator cancelled batch)
4. Reconcile missing run against expected payroll roster

**Recovery**:
- If transaction failed: retry the batch for missing period
- If intentional cancellation: update payroll schedule and skip that batch
- If bug: investigate run ID allocation logic

---

## Alert Dashboard Configuration

### High-Frequency Alerts (Page on-call)
- `PauseManager/paused` (any occurrence)
- `ProofAlreadyUsed` (any occurrence or >3 in 10 min)

### Medium-Frequency Alerts (Ticket to ops team)
- `require_auth` failures (>5 in 10 min)
- `CommitmentNotFound` (>10 in 1 hour)
- `ProofVerificationFailed` (during payroll hours)
- `PeriodClosed` errors (>3 in 1 hour)
- Batch run ID gaps

### Low-Frequency Alerts (Logged, aggregated for reporting)
- `KeyExpired` (>5 per day)
- Commitment rotation spikes (>10 in 5 min outside migration window)

---

## Integration Checklist

- [ ] Indexer subscribes to contract event stream and failed transaction results
- [ ] Alert rules are configured in monitoring tool (Prometheus, Grafana, DataDog, etc.)
- [ ] On-call rotation is aware of alert meanings and escalation paths
- [ ] Incident response playbook is linked from alert runbooks
- [ ] Alert thresholds are reviewed quarterly
- [ ] Anomaly detection is baselined against rolling 7-day history for seasonal patterns

---

## Related Documents

- [Event Taxonomy](./event-taxonomy.md) — Event naming and structure
- [Event Severity Mappings](./event-severity-mappings.md) — Severity classification reference
- [Incident Response Playbook](../incident-response-playbook.md) — Response procedures for each incident type

