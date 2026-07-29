# Contract Error Cases

This guide maps common ZK Payroll contract failures to likely causes and
client recovery guidance for SDK, dashboard, and indexer contributors.

## How to Classify Failures

| Class | Meaning | Client behavior |
|-------|---------|-----------------|
| Retryable | The same user intent may succeed after waiting, refreshing state, funding an account, or resubmitting with fresh inputs. | Show an actionable message and preserve the user's draft. |
| Non-retryable | The request violates contract invariants, authorization, or proof semantics. | Stop automatic retries; require a corrected input, different signer, or new workflow. |

Soroban host authorization failures and explicit `panic!` messages are surfaced
as invocation failures. `#[contracterror]` values are returned as typed errors
where the contract exposes `Result<_, Error>`.

## Company Setup and Administration

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `payroll_registry.register_company` | `"Company already registered"` | The admin address already owns a company record. | Non-retryable with the same admin | Load the existing company ID for that admin or use a different admin address. |
| `payroll_registry.*` | `"Payroll is paused"` | A configured `pause_manager` has paused payroll operations. | Retryable after unpause | Disable submit buttons, subscribe to pause events, and retry only after `is_paused()` is false. |
| `payroll_registry.*` | `"Company not found"` | Unknown `company_id` or stale dashboard cache. | Retryable after state refresh | Refresh registry state and validate the company ID before resubmitting. |
| Rotation entrypoints | `"Unauthorized: caller is not the company admin"` or host `authorized` failure | Wrong signer or wrong `current_admin` argument. | Non-retryable until signer changes | Prompt the registered admin to sign or fetch current company metadata. |
| Rotation entrypoints | Pending rotation already exists / no pending rotation | The UI attempted a duplicate, stale, or out-of-order rotation step. | Retryable after refresh | Refresh pending rotation state and render the correct next action. |

## Employee Onboarding and Lifecycle

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `payroll_registry.add_employee` | `"Company not found"` | Employee is being added under a missing company. | Retryable after state refresh | Re-query company setup and require company creation first. |
| `payroll_registry.add_employee`, `remove_employee`, `update_commitment`, `set_employee_status` | Host `authorized` failure | The transaction is not signed by the company's admin. | Non-retryable until signer changes | Ask the company admin to reconnect/sign; do not retry with the treasury or employee signer. |
| `payroll_registry.update_commitment`, `set_employee_status`, `get_commitment` | `"Employee not found"` | Unknown or deleted employee record. | Retryable after roster refresh | Refresh the roster, then onboard the employee before updating status or commitment. |
| `salary_commitment.update_commitment` / `rotate_commitment` | `"Commitment is locked..."` | A payroll draft or audit lock prevents changing the salary commitment. | Retryable after unlock | Show the lock reason and wait for an admin unlock or payroll finalization rollback. |
| `salary_commitment.set_reference_id` | Invalid or duplicate reference ID | Empty/oversized HR reference or reference already assigned. | Non-retryable until corrected | Validate length and uniqueness client-side before submission. |

## Payroll Execution and Periods

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `payment_executor.process_payment` | `PaymentError::PeriodNotFound (4)` | Payment submitted before creating the period. | Retryable after creating period | Create or select a valid period, then regenerate/sign the payment request. |
| `payment_executor.create_period` | `PaymentError::PeriodAlreadyExists (6)` | The company already has the requested period. | Non-retryable | Load the existing period and continue with payment submission. |
| `payment_executor.close_period` / `process_payment` | `PaymentError::PeriodClosed (5)` | Attempted to pay into a closed period. | Non-retryable for that period | Open a new period or select the active period. |
| `payment_executor.process_payment` | `PaymentError::AlreadyPaid (3)` | Employee already received a payment for that period. | Non-retryable | Mark the payroll item reconciled; investigate only if the UI expected an unpaid status. |
| Batch payment entrypoints | `PaymentError::ArrayLengthMismatch (2)` or `"Array length mismatch"` | Employees, amounts, proofs, or other batch arrays have different lengths. | Non-retryable until corrected | Validate all array lengths before invoking the contract. |
| `payroll.process_payroll` / `payment_executor.process_payment` | `"Amount must be positive"` / `"Amount must be non-negative"` | Invalid payment or deposit amount. | Non-retryable until corrected | Enforce token-unit amount validation in forms and SDK builders. |
| `payroll` draft flows | Draft missing, duplicate nonce, or hash not pre-committed | UI skipped the commit step or reused a finalized run nonce. | Non-retryable for same nonce/hash | Restart the draft flow with a new nonce and pre-commit the expected hash. |

## Treasury and Token Checks

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `token.transfer` | `"Insufficient balance"` | Treasury does not hold enough token balance. | Retryable after funding | Show funding instructions and retry after the treasury balance updates. |
| Treasury withdrawal / emergency flows | `"Unauthorized: caller is not treasury owner"` | Wrong signer is approving treasury movement. | Non-retryable until signer changes | Require the configured treasury owner to sign. |
| Emergency request flows | Pending request already exists / no pending request | Duplicate, stale, or out-of-order emergency action. | Retryable after refresh | Refresh treasury request state before showing approve/cancel controls. |
| Asset allow-list check | `"Asset not allowed"` | Payment asset is not configured for payroll. | Non-retryable until configuration changes | Select an allowed asset or ask an admin to update deployment/configuration. |

## Audit Access

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `audit_module` | `AuditError::KeyNotFound (1)` | Auditor has no granted view key. | Non-retryable until granted | Ask an admin to grant a view key. |
| `audit_module` | `AuditError::WrongAuditor (2)` / `InvalidViewKey (7)` | The caller or supplied key material does not match the grant. | Non-retryable until corrected | Re-authenticate the auditor and load the correct key material. |
| `audit_module` | `AuditError::KeyExpired (3)` | The view key expired by ledger sequence. | Retryable after renewal | Request a fresh grant; do not retry the old key. |
| `audit_module` | `AuditError::InsufficientScope (5)` | Auditor scope does not cover the requested report or employee. | Non-retryable until scope changes | Request broader scope or narrow the query. |
| `audit_module` | `AuditError::CommitmentMismatch (6)` | Claimed salary/blinding pair does not match stored commitment. | Non-retryable for same proof data | Regenerate the disclosure package from source payroll data. |

## Proof Verification and Replay Protection

| Contract / entrypoint | Error case | Likely cause | Retry? | Recommended recovery |
|-----------------------|------------|--------------|--------|----------------------|
| `payment_executor.process_payment` | `PaymentError::ProofAlreadyUsed (1)` | Proof/nullifier was already consumed. | Non-retryable for same nullifier | Generate a fresh proof with a new nullifier; never auto-retry the same proof. |
| `payment_executor.process_payment` | `PaymentError::ProofExpired (7)` | Proof timestamp is outside the accepted freshness window. | Retryable with a new proof | Regenerate proof inputs for the current period/timestamp. |
| `payment_executor.process_payment` | `"Invalid payment proof"` | Verifier rejected proof bytes or public inputs. | Non-retryable until proof regenerated | Rebuild the proof using the expected schema and public input ordering. |
| `proof_verifier.verify_payment_proof` | Returns `false` | Proof schema, verifying key, or public input count mismatch. | Non-retryable for the same proof | Negotiate the proof schema version and regenerate the proof. See [Proof Schema Version Negotiation](./interop/proof-schema-version-negotiation.md). |
| `salary_commitment.mark_nullifier_used` | `"Nullifier already used"` | Replay attempt or duplicate payment submission. | Non-retryable for same nullifier | Treat as duplicate; reconcile against the original payment event. |

## SDK Mapping Notes

- Prefer typed errors where available (`PaymentError`, `AuditError`) and map
  panics by exact message only as a compatibility fallback.
- Treat proof replay, duplicate payroll period, already-paid, authorization,
  and invalid proof failures as non-retryable for the same payload.
- Treat paused contracts, missing/stale state, expired audit keys, expired
  proofs, and insufficient treasury funds as retryable only after a specific
  recovery action.
- Related client guidance: [SDK Contract Interface](./sdk-contract-interface.md),
  [Client Fallback Behavior](./interop/client-fallback-behavior.md), and
  [Proof Schema Version Negotiation](./interop/proof-schema-version-negotiation.md).
