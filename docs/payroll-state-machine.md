# Payroll Run State Machine

Issue #159 defines the canonical payroll run lifecycle that contracts, SDKs, and
dashboards must mirror. The contract source of truth is
`PayrollRunState` in `contracts/payroll/src/lib.rs`; the machine-readable mirror
is `fixtures/state-machine/payroll-run-state-machine.json`.

## Canonical States

| State | Contract variant | Terminal | Retryable | Semantics |
| --- | --- | --- | --- | --- |
| `draft` | `Draft` | No | No | Payroll inputs are still being assembled off-chain. |
| `validating` | `Validating` | No | No | Payroll inputs are being checked before proof work begins. |
| `proof_pending` | `ProofPending` | No | No | Required ZK proof or verification artifacts are being produced. |
| `ready_to_submit` | `ReadyToSubmit` | No | No | All validation artifacts are present and the run is ready for submission. |
| `submitted` | `Submitted` | No | No | The run has been prepared on-chain and is waiting to be executed or cancelled. |
| `confirming` | `Confirming` | No | No | Execution has been submitted and clients should wait for final confirmation. |
| `completed` | `Completed` | Yes | No | Payroll completed and reconciliation is final. |
| `failed` | `Failed` | No | Yes | The run failed before a terminal outcome and may be retried or cancelled. |
| `cancelled` | `Cancelled` | Yes | No | The run was intentionally stopped and cannot be reopened. |
| `reconciliation_required` | `ReconciliationRequired` | No | No | Payments executed, but reconciliation still needs review or finalization. |
| `expired` | `Expired` | Yes | No | The prepared run was never finalized within its expiry window (#474); its funds reservation was released and nothing was executed. |

`completed`, `cancelled`, and `expired` are immutable terminal states. `failed`
is the only retryable state. `reconciliation_required` is reviewable, but
clients should not show it as a retry action by default because the next step is
reconciliation or operator review.

## Allowed Transitions

| From | To | Initiator | User-visible meaning |
| --- | --- | --- | --- |
| `draft` | `validating` | Payroll operator or automation | Start validating a draft run. |
| `draft` | `cancelled` | Payroll operator | Stop a run before validation. |
| `validating` | `proof_pending` | Validation service | Inputs passed validation and proof work can start. |
| `validating` | `failed` | Validation service | Validation failed and the run can be retried. |
| `validating` | `cancelled` | Payroll operator | Stop a run during validation. |
| `proof_pending` | `ready_to_submit` | Proof service | Required proof artifacts are ready. |
| `proof_pending` | `failed` | Proof service | Proof generation or verification failed. |
| `proof_pending` | `cancelled` | Payroll operator | Stop a run while proofs are pending. |
| `ready_to_submit` | `submitted` | Payroll operator or submitter | Submit the prepared payroll run on-chain. |
| `ready_to_submit` | `failed` | Submitter or automation | Submission preparation failed. |
| `ready_to_submit` | `cancelled` | Payroll operator | Stop a run before on-chain submission. |
| `submitted` | `confirming` | Contract, submitter, or indexer | Execution has been sent and confirmation is pending. |
| `submitted` | `failed` | Contract, submitter, or indexer | Submission failed before confirmation. |
| `submitted` | `cancelled` | Admin | Cancel a prepared run before execution. |
| `submitted` | `expired` | Any observer or automation | Retire a prepared run that aged past the configured expiry window before finalization (#474). |
| `confirming` | `completed` | Contract or reconciliation operator | Execution and reconciliation are final. |
| `confirming` | `failed` | Contract or reconciliation operator | Confirmation failed before a terminal success. |
| `confirming` | `reconciliation_required` | Contract or reconciliation operator | Execution happened, but reconciliation must be completed. |
| `failed` | `validating` | Payroll operator or automation | Retry from validation. |
| `failed` | `proof_pending` | Payroll operator or automation | Retry from proof generation when inputs remain valid. |
| `failed` | `cancelled` | Payroll operator | Stop a failed run instead of retrying. |
| `reconciliation_required` | `completed` | Reconciliation operator | Reconciliation succeeded and the run is final. |
| `reconciliation_required` | `failed` | Reconciliation operator | Reconciliation failed and the run requires retry handling. |

All other transitions are forbidden. In particular, clients and integrations
must reject direct jumps such as `draft -> completed`, reverse transitions
such as `submitted -> draft`, and any transition out of `completed`, `cancelled`, or
`expired`.

## Contract Entry Points

The payroll contract records canonical state for the on-chain lifecycle:

| Entry point | State effect |
| --- | --- |
| `prepare_payroll_run` | Stores `submitted` for the new pending run. |
| `cancel_payroll_run` | Stores `cancelled` and removes the pending run. |
| `expire_payroll_run` | Stores `expired`, removes the pending run, and releases its funds reservation (#474). |
| `batch_process_payroll` | Stores `reconciliation_required` after execution. |
| `update_reconciliation_status(Reconciled)` | Stores `completed`. |
| `update_reconciliation_status(Unreconciled)` | Keeps or stores `reconciliation_required`. |
| `update_reconciliation_status(Failed)` | Stores retryable `failed`. |
| `transition_payroll_run_state` | Admin-only conformance hook that rejects forbidden transitions. |
| `get_payroll_run_state` | Reads the canonical state for a run ID. |

The contract exposes `is_payroll_state_transition_allowed`,
`is_payroll_state_terminal`, and `is_payroll_state_retryable` so tests and
off-chain mirrors can assert the same semantics without duplicating rules.

### Run Expiration (#474)

Prepared-but-unfinalized runs can expire so stale batches cannot be settled
long after their preconditions (treasury balance, asset allowlist, roster)
stopped holding:

- Expiration is **opt-in**. The admin sets a maximum pending age via
  `set_run_expiration_policy`; without a policy, behavior is unchanged.
- While the policy is active, `finalize_payroll_run` rejects runs older than
  the window ("Run has expired…") and `expire_payroll_run` moves them to the
  terminal `expired` state.
- Expiry is **permissionless** — any observer may submit it — so idle funds
  reservations (#343) and the #253 configuration lock cannot be held hostage
  by an unresponsive operator.
- Expiry executes nothing: no token transfer, no salary row, no exposure of
  amounts. A redacted `ExpiredRunRecord` and a `run_expired` event
  `(run_id, expired_by)` are all that remain. The run nonce stays burned.

See [Payroll Run Expiration](./run-expiration.md) for the full workflow,
SDK guidance, and error recovery.

### Failed Bounded Payout Retry

Bounded payroll payout checkpoints can be inspected with
`is_failed_payout_retry_eligible`, passing the original employer, batch root,
asset, execution nonce, and expected payment count. The view returns only a
Boolean. It returns `true` only for a failed checkpoint that has remaining
payments; completed checkpoints and checkpoints at or beyond the payment count
are not retryable.

When eligible, the admin calls `resume_failed_payout_retry` with the same
checkpoint identity and the persisted checkpoint index. Then the operator
retries `batch_process_payroll_bounded` with the original batch inputs and
nonce. Execution resumes at the saved index so previously completed payouts
are not repeated. A failed checkpoint cannot be resumed through the regular
bounded payout call without this explicit eligibility and resume step. If the
eligibility view returns `false`, refresh the checkpoint and reconcile the
original payout outcome before creating any new payout attempt.

The eligibility result, error text, and resume event contain no employee or
salary values. Keep the original proofs and payout inputs in the authorized
payroll workflow; do not include them in user-facing errors or operational
logs.

## Payroll Submission Sequence Validation

Before a prepared run may be submitted, the contract enforces a monotonic submission
sequence per employer. This guardrail prevents a stale or out-of-order submission
from being accepted after a newer run has already been prepared for the same
employer.

- Each accepted submission advances the employer's submission sequence by one.
- A submission whose sequence is not exactly the next expected value is rejected
  with a non-sensitive error that identifies only the run and the expected sequence.
- Rejected submissions do not consume a sequence number and do not move the run
  out of `submitted`.

The sequence check is exposed through the contract entry points below and can be
asserted off-chain without duplicating the rules:

| Entry point | State effect |
| --- | --- |
| `submit_payroll_run` | Validates the employer's expected submission sequence and advances it on success. |
| `get_submission_sequence` | Reads the next expected submission sequence for an employer. |

The error surfaced to clients is deliberately redacted: it contains only the
run identifier and the expected sequence number. No employee identifiers, salary
amounts, bank details, or salary commitments are included in the error, events,
telemetry, or contract state.

## Contract Period Transition Consistency

Payroll runs carry a contract period (a start and end timestamp) that defines
the salary interval being settled. To keep the canonical state machine and the
contract period mutually consistent, the contract validates the period on every
state transition that moves a run forward.

- A contract period must have a start that is strictly before its end.
- The period must not be in the future relative to the transition timestamp.
- The period must not be older than the configured maximum contract period age.
- Transitions that do not move the run forward (e.g. cancellation or failure)
  do not revalidate the period, so a run can always be stopped even if its
  period has since become invalid.

Errors are actionable and redacted: they name the run and the field that failed
validation (for example `invalid_contract_period` or `contract_period_expired`)
without exposing employee identifiers, salary amounts, or bank details.

| Entry point | Period consistency effect |
| --- | --- |
| `set_contract_period_policy` | Admin-only configuration of the maximum contract period age. |
| `validate_contract_period` | Read-only check that returns an actionable error when the period is invalid for the given transition timestamp. |
| `transition_payroll_run_state` | Rejects forward transitions whose contract period is invalid. |
| `prepare_payroll_run` | Validates the contract period before storing `submitted`. |

The contract exposes `is_contract_period_valid` so tests and off-chain mirrors
can assert the same consistency rules without duplicating them.

## Future Additions

When adding or renaming a state, update all of the following in the same pull
request:

1. `PayrollRunState` and the internal transition table in `contracts/payroll/src/lib.rs`.
2. Positive and negative contract tests for the new transition behavior.
3. `fixtures/state-machine/payroll-run-state-machine.json` for SDK/dashboard conformance.
4. This document, including initiators, terminal/retryable metadata, and user-visible meaning.

Never add a transition out of a terminal state without first changing the
terminal-state definition and adding tests that prove existing terminal behavior
is intentionally replaced.

---

## Payroll Draft Lifecycle State Machine (`RunDraftState`)

In addition to the run state machine, `RunDraftState` in `contracts/payroll/src/lib.rs` tracks off-chain payroll preparation drafts before submission.

### Draft States

| State | Contract variant | Terminal | Semantics |
| --- | --- | --- | --- |
| `pending` | `Pending` | No | Draft is created or amended and open for corrections. |
| `finalized` | `Finalized` | No | Draft is locked for review; no further amendments allowed. |
| `submitted` | `Submitted` | Yes | Draft has been submitted for execution. |
| `cancelled` | `Cancelled` | Yes | Draft was cancelled before submission. |
| `expired` | `Expired` | Yes | Draft expired before submission. |

### Allowed Draft Transitions

| From | To | Initiator | User-visible meaning |
| --- | --- | --- | --- |
| `pending` | `finalized` | Admin | Finalize draft for review. |
| `pending` | `submitted` | Admin | Submit draft directly for processing. |
| `pending` | `cancelled` | Admin | Cancel draft. |
| `pending` | `expired` | Admin / Automation | Expire stale draft. |
| `finalized` | `submitted` | Admin | Submit finalized draft for processing. |
| `finalized` | `cancelled` | Admin | Cancel finalized draft. |
| `finalized` | `expired` | Admin / Automation | Expire finalized draft. |

`Submitted`, `Cancelled`, and `Expired` are terminal draft states. Transitions out of terminal states are forbidden.

### Draft Contract Entry Points

| Entry point | State effect |
| --- | --- |
| `create_run_draft` | Creates a new draft in `Pending` state. |
| `amend_run_draft` | Updates `total_amount` and `employee_count` for `Pending` draft. |
| `finalize_run_draft` | Transitions `Pending` draft to `Finalized`. |
| `submit_run_draft` | Transitions `Pending` or `Finalized` draft to `Submitted`. |
| `cancel_run_draft` | Transitions `Pending` or `Finalized` draft to `Cancelled`. |
| `expire_run_draft` | Transitions `Pending` or `Finalized` draft to `Expired`. |
