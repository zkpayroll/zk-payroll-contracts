# SLA-Style Operational Targets for ZK Payroll

This document defines target expectations for execution speed, failure rates, and operational recovery for the ZK Payroll system. These targets guide readiness assessment and incident severity classification.

## Scope

This document covers:

- **Payroll execution latency** — Time from batch initiation to transaction confirmation
- **Proof verification latency** — Groth16 verification time per payment
- **Failure rates** — Expected panic/rejection rates for valid operations
- **Recovery procedures** — Steps to restore operation after incidents

## Payroll Execution Latency

### Target Metrics

| Metric | Target | Warning Threshold | Critical Threshold |
|--------|--------|-------------------|-------------------|
| **Batch initialization to first proof** | <100ms | >150ms | >250ms |
| **Per-payment proof verification** | <50ms | >75ms | >150ms |
| **Per-payment token transfer** | <200ms | >350ms | >500ms |
| **Full batch (50 payments)** | <20s | >30s | >45s |
| **Transaction confirmation (Soroban)** | <5s | >8s | >15s |

### Observable Signals

- **Ledger latency** — Monitor `e.ledger().timestamp()` deltas between batch start and end
- **RPC call durations** — Track token client transfer call times
- **Proof verification logs** — Measure verifier contract invocation times
- **Soroban transaction metrics** — Use Stellar RPC's `getTransaction` API to observe block latency

### Assumptions & Limitations

- Targets assume **testnet** or **non-congested mainnet**. Higher latencies expected during network congestion.
- Proof verification time depends on circuit complexity (current: BN254, moderate size). Larger circuits may exceed targets.
- Token transfer times vary with contract complexity; these assume standard Stellar token contracts.
- Early-stage measurement; targets refined as production data accumulates.

## Failure Rates

### Expected Failure Rates (Valid Operations)

| Operation | Target Failure Rate | Acceptable Range |
|-----------|-------------------|------------------|
| **Valid proof verification** | 0% | 0% (hard failure) |
| **Valid commitment lookup** | <0.1% (missing employee) | <1% (operational error) |
| **Valid token transfer** | <0.5% (insufficient balance) | <2% (operational error) |
| **Treasury ownership check** | <0.1% (auth failure) | <1% (configuration error) |

### Common Failure Modes (with mitigations)

#### 1. Invalid Commitment (Panic: "Commitment not found")

**Cause:** Employee not enrolled in salary commitment contract.
**Mitigation:** Pre-flight check: verify all employees in batch have stored commitments before submission.
**Recovery:** Add missing employee, retry batch.
**Target:** <0.1% (catch in pre-flight).

#### 2. Insufficient Treasury Balance (Panic: "Insufficient balance")

**Cause:** Total transfer amount exceeds treasury balance.
**Mitigation:** Pre-flight check: verify treasury has at least `expected_total_spend + 100 tokens` buffer.
**Recovery:** Deposit additional funds, retry batch.
**Target:** <0.5% (operational discipline).

#### 3. Invalid Proof (Panic: "Invalid payment proof")

**Cause:** Proof verification failed; likely malformed proof or circuit mismatch.
**Mitigation:** Verify proofs are generated with current circuit and serialized correctly.
**Recovery:** Regenerate proof, retry.
**Target:** <0.01% (development environment; 0% in production).

#### 4. Run ID Collision (should not occur)

**Cause:** Two batches derive the same run ID.
**Mitigation:** Run IDs are monotonically incremented; collisions prevented by counter design.
**Recovery:** None needed; counter ensures uniqueness.
**Target:** 0% (deterministic guarantee).

#### 5. Pause Manager Activation

**Cause:** Payroll has been paused for maintenance.
**Mitigation:** Check `is_paused()` before submitting batch; subscribe to pause/unpause events.
**Recovery:** Wait for unpause, retry.
**Target:** <1% (administrative action, not operational error).

## Operational Recovery SLA

### Incident Categories & Response Times

| Severity | Description | Acknowledgment | Fix Target | Escalation |
|----------|---|---|---|---|
| **Critical** | Zero payroll throughput; system unusable | <15 min | <4 hours | On-call engineer + team lead |
| **High** | Payroll slow (>2x target); partial failures <10% | <30 min | <8 hours | On-call engineer + tech lead |
| **Medium** | Elevated latency; <5% failure rate | <1 hour | <24 hours | Team lead |
| **Low** | Documentation gap; future-facing issue | <24 hours | <1 week | Product manager |

### Common Recovery Procedures

#### A. Pause & Investigate

```
1. Admin calls `set_pause_manager()` to pause payroll
2. Collect logs: ledger timestamps, RPC latencies, proof verification times
3. Check treasury balance and employee commitments
4. Identify root cause (e.g., network congestion, balance issue, missing employee)
```

#### B. Hot-Fix: Deposit Funds

```
1. If treasury balance insufficient:
   - Source tokens from backup treasury
   - Call `deposit(backup_address, amount)` with dual authorization
   - Verify new balance >= expected_total_spend
```

#### C. Regenerate & Retry

```
1. If proof verification fails:
   - Regenerate proof off-chain with current circuit
   - Verify serialization matches contract expectations
   - Retry batch_process_payroll() with fresh proofs
```

#### D. Add Missing Employee

```
1. If commitment not found:
   - Call salary_commitment.store_commitment(employee, commitment_hash)
   - Verify commitment is now retrievable
   - Retry batch
```

#### E. Unpause & Resume

```
1. Once root cause fixed:
   - Pause manager calls `unpause()`
   - Verify next batch processes successfully
   - Monitor latency for 3 batches before declaring incident closed
```

## Monitoring & Alerting

### Recommended Metrics

1. **Batch execution time** (per batch)
   - Alert if >30s (warning) or >45s (critical)

2. **Per-payment latency** (histogram)
   - Alert if p50 >75ms or p95 >150ms

3. **Failure rate** (daily)
   - Alert if any operation >1% failure rate

4. **Treasury balance** (continuous)
   - Alert if <2 days of expected payroll spend

5. **Run ID counter** (monotonic check)
   - Alert if counter ever decreases (indicates data corruption)

6. **Proof verification failures** (rate)
   - Alert if valid proofs fail verification

### Off-Chain Indexer

Subscribe to contract events:

- `payroll:payment_executed(employee, amount)` — Track individual payments
- `payroll:run_executed(run_id, total_amount)` — Track batch completion
- `payroll:deposit(from, amount)` — Track treasury deposits

Use run_id for reconciliation: run records are immutable and queryable by ID.

## Revision History

| Date | Version | Notes |
|------|---------|-------|
| 2026-06-28 | 1.0 | Initial targets based on testnet observations |

## Future Refinements

- **Mainnet targets** — Lower latencies expected post-launch; revise after 1000+ live batches
- **Circuit optimization** — Projected 2-3x speedup with circuit compression
- **Batch size scaling** — Current MAX_BATCH=50; may increase to 100+ with optimization
- **Auto-pause thresholds** — Define auto-pause conditions (e.g., >3 consecutive failures)

---

**Owners:** Operations Team, ZK Payroll Eng  
**Last Updated:** 2026-06-28  
**Next Review:** 2026-09-28 (or after 100 mainnet batches)
