# Contract Error Taxonomy

This document defines the deterministic error taxonomy for ZK Payroll contracts.
All contract errors are assigned stable numeric identifiers grouped by category,
enabling SDK clients to reliably distinguish failure modes and determine retry behavior.

## Error ID Ranges

| Range | Category | Purpose |
|-------|----------|---------|
| 1-99 | Authorization | Access control and role validation |
| 100-199 | Proof Verification | Cryptographic proof validation |
| 200-299 | Audit Access | Audit permissions and scope |
| 300-399 | Payment Execution | Payment processing and state |
| 400-499 | Treasury | Fund availability and asset management |
| 500-599 | Payroll State | Lifecycle and state machine |
| 600-699 | Replay Protection | Idempotency and duplicate detection |
| 700-799 | Storage | Initialization and versioning |

## Error Categories

### Authorization (1-99)

Authorization errors indicate that the caller lacks proper permission or that a
role-based constraint was violated.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 1 | UnauthorizedAdmin | Caller is not the company admin | No | Require admin to sign |
| 2 | UnauthorizedTreasuryOwner | Caller is not the treasury owner | No | Require treasury owner to sign |
| 3 | UnauthorizedAuditor | Caller is not an authorized auditor | No | Request auditor grant |
| 4 | UnauthorizedRotationTarget | Caller is not the rotation target | No | Require target address to sign |
| 5 | UnauthorizedReviewer | Caller is not an authorized reviewer | No | Register as reviewer first |
| 6 | AuthorizationFailed | Host `require_auth` failed | No | Verify signer and transaction |
| 7 | UnauthorizedHandoverTarget | Caller is not handover recipient | No | Require pending admin to accept |

**SDK Guidance**: For any authorization error, do not retry with the same signer.
Instead, request the correct authorized party (admin, treasury owner, auditor, etc.)
to sign the transaction.

### Proof Verification (100-199)

Proof errors indicate that a ZK proof or cryptographic commitment failed verification.
These are non-retryable with the same proof data.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 100 | InvalidProofFormat | Proof bytes are malformed | No | Regenerate proof from source |
| 101 | ProofVerificationFailed | Groth16 verification failed | No | Rebuild proof with correct schema |
| 102 | CommitmentMismatch | Salary + blinding ≠ stored commitment | No | Regenerate with correct source data |
| 103 | ProofExpired | Proof timestamp outside freshness window | Yes | Generate fresh proof |
| 104 | InvalidPublicInputs | Proof public inputs malformed | No | Rebuild proof schema |
| 105 | VerifyingKeyMismatch | Verifying key does not match proof | No | Verify proof schema version |
| 106 | InvalidNullifier | Nullifier is malformed or invalid | No | Regenerate with valid nullifier |

**SDK Guidance**: Proof generation is deterministic given source payroll data. If a
proof fails verification, regenerate from source rather than retrying the same proof.
For `ProofExpired` (103), generate a new proof within the freshness window.

### Audit Access (200-299)

Audit errors relate to auditor permissions, view keys, and audit scope constraints.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 200 | ViewKeyNotFound | No view key granted to auditor | No | Admin must grant key |
| 201 | InvalidViewKey | Provided key does not match stored key | No | Load correct key material |
| 202 | ViewKeyExpired | View key expired by ledger sequence | Yes | Request key renewal |
| 203 | InsufficientAuditScope | Auditor scope too narrow | No | Request broader scope or narrow query |
| 204 | UnauthorizedChallengeParticipant | Auditor cannot challenge this payload | No | Verify auditor grant and scope |
| 205 | ChallengeNotFound | Challenge ID does not exist | No | Verify challenge ID |
| 206 | ChallengeExpired | Challenge deadline has passed | No | Create new challenge |
| 207 | ChallengeAlreadyResolved | Challenge already has a response | No | Load existing response |
| 208 | InvalidChallenge | Challenge is malformed or out of scope | No | Verify challenge data |
| 209 | InvalidResponseTimestamp | Response outside acceptance window | No | Verify timestamp and retry |

**SDK Guidance**: Most audit errors are non-retryable and indicate insufficient
permissions or stale state. `ViewKeyExpired` (202) is retryable after requesting
renewal from the admin.

### Payment Execution (300-399)

Payment errors occur during payment processing and employee payment state transitions.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 300 | PeriodNotFound | Payroll period does not exist | Yes | Create period first |
| 301 | PeriodClosed | Period is closed | No | Open new period |
| 302 | PeriodAlreadyExists | Period already exists | No | Load existing period |
| 303 | EmployeeAlreadyPaid | Employee already paid this period | No | Mark reconciled |
| 304 | InvalidPaymentAmount | Amount invalid or exceeds limits | No | Validate and correct |
| 305 | EmployeeNotFound | Employee record missing | Yes | Onboard employee first |
| 306 | CompanyNotFound | Company record missing | Yes | Register company first |
| 307 | CommitmentLocked | Commitment locked by audit hold | Yes | Wait for lock release |
| 308 | EmptyBatch | Batch is empty | No | Add employees to batch |
| 309 | ArrayLengthMismatch | Array lengths do not match | No | Validate batch arrays |

**SDK Guidance**: Retryable payment errors (`PeriodNotFound`, `EmployeeNotFound`,
`CommitmentLocked`) indicate incomplete setup or temporary locks. Non-retryable
errors require corrected input or new workflow.

### Treasury (400-499)

Treasury errors relate to fund availability and asset management.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 400 | InsufficientTreasuryBalance | Insufficient funds for transfer | Yes | Fund treasury and retry |
| 401 | AssetNotAllowed | Asset not in allowed list | No | Select allowed asset |
| 402 | WithdrawalRequestPending | Withdrawal already pending | No | Complete/cancel existing request |
| 403 | WithdrawalRequestNotFound | No pending request exists | No | Create withdrawal request first |
| 404 | TreasuryLocked | Treasury locked or unavailable | Yes | Wait and retry |
| 405 | InsufficientUnreservedBalance | Reserved funds too high | Yes | Wait or release reservations |
| 406 | InvalidAssetConfiguration | Asset config invalid | No | Update configuration |

**SDK Guidance**: `InsufficientTreasuryBalance` (400) is retryable after funding.
Most other treasury errors require administrative action or configuration change.

### Payroll State (500-599)

State errors relate to payroll lifecycle and state machine transitions.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 500 | PayrollRunNotFound | Run does not exist | Yes | Verify run ID |
| 501 | PendingRunNotFound | Pending run does not exist | Yes | Query pending runs |
| 502 | DraftNotFound | Draft does not exist | Yes | Query available drafts |
| 503 | InvalidPayrollState | State invalid for this operation | No | Check state and follow state machine |
| 504 | DraftLocked | Draft is finalized | No | Create new draft |
| 505 | InvalidCompanyState | Company paused or archived | Yes | Wait for state change |
| 506 | InvalidEmployeeStatus | Employee status invalid | No | Update employee status |
| 507 | EmployeeIneligible | Employee does not qualify | No | Correct status/commitment |
| 508 | ComplianceHoldActive | Compliance hold blocks operation | Yes | Wait for hold release |

**SDK Guidance**: Many state errors are retryable after state changes (company
becoming active, hold release, etc.). Always check and follow the payroll state
machine before transitioning.

### Replay Protection (600-699)

Replay errors prevent duplicate execution and protect against nonce reuse.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 600 | NonceAlreadyUsed | Nonce has been consumed | No | Generate new nonce |
| 601 | PayrollAlreadyExecuted | Execution identity already used | No | Verify prior execution or use new nonce |
| 602 | NullifierAlreadyUsed | Proof nullifier consumed | No | Generate new proof with new nullifier |
| 603 | ConflictingPayloadData | Payload changed since original | No | Submit with original payload or new nonce |
| 604 | ExecutionIdentityMismatch | Stored vs provided identity differs | No | Verify payload matches stored record |
| 605 | AuthorizationExpired | Authorization (signature, seq) invalid | No | Regenerate authorization |
| 606 | InvalidPayloadContext | Cross-company/asset reuse detected | No | Verify company and asset match |

**SDK Guidance**: Replay errors are never retryable with the same nonce or proof.
They indicate a prior successful execution. If a duplicate is intentional, generate
a new nonce and resubmit.

### Storage (700-799)

Storage errors relate to initialization and version compatibility.

| Code | Name | Cause | Retryable | SDK Action |
|------|------|-------|-----------|-----------|
| 700 | NotInitialized | Contract not initialized | Yes | Call initialize() first |
| 701 | AlreadyInitialized | Contract already initialized | No | Use existing instance |
| 702 | StorageVersionMismatch | Storage schema incompatible | No | Migrate or redeploy |
| 703 | StorageCorruption | Storage record invalid | No | Report and contact support |
| 704 | MigrationFailed | Upgrade migration failed | No | Investigate and recover manually |

**SDK Guidance**: Storage errors indicate contract initialization or upgrade issues.
`NotInitialized` is retryable after calling the initialize function.

## Retry Decision Tree

```
Is this a proof or cryptographic error (100-199)?
  → Yes: Non-retryable (except ProofExpired = retry with fresh proof)
  → No: Next

Is this an authorization error (1-99)?
  → Yes: Non-retryable (wrong signer)
  → No: Next

Is this a replay error (600-699)?
  → Yes: Non-retryable (would duplicate execution)
  → No: Next

Is this specific code marked retryable above?
  → Yes: Retryable (fund treasury, create period, wait for state change, etc.)
  → No: Non-retryable
```

## SDK Mapping Guidelines

For SDK clients implementing contract error handling:

1. **Define error handlers by category**: Group errors by their range (1-99 = auth,
   100-199 = proof, etc.) rather than individual codes.

2. **Implement category-level retry logic**: Authorization errors → different signer.
   Proof errors → regenerate. State errors → check and wait. Replay errors → new nonce.

3. **Log error context**: Store error codes, error messages, contract names, and
   method names together for debugging.

4. **Expose error categories to UI**: Show users actionable messages based on the
   error category, not raw error codes.

5. **Test error path coverage**: Verify that your SDK correctly handles each error
   code and category via integration tests.

## Backward Compatibility

Error codes are stable and append-only:
- New errors will have previously unused IDs
- Existing error codes will never be reused or renamed
- Error category ranges are reserved and will not overlap
- Contracts may sunset old errors but will document deprecation

This ensures SDKs built against older contracts continue to work with newer versions.

## Related Documents

- [Error Handling in SDK](./interop/error-handling-sdk.md) — SDK implementation examples
- [Contract Interface](./sdk-contract-interface.md) — Complete endpoint error reference
- [Proof Schema Versioning](./interop/proof-schema-version-negotiation.md) — Proof error details
