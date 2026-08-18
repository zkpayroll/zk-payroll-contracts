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

`completed` and `cancelled` are immutable terminal states. `failed` is the only
retryable state. `reconciliation_required` is reviewable, but clients should not
show it as a retry action by default because the next step is reconciliation or
operator review.

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
| `confirming` | `completed` | Contract or reconciliation operator | Execution and reconciliation are final. |
| `confirming` | `failed` | Contract or reconciliation operator | Confirmation failed before a terminal success. |
| `confirming` | `reconciliation_required` | Contract or reconciliation operator | Execution happened, but reconciliation must be completed. |
| `failed` | `validating` | Payroll operator or automation | Retry from validation. |
| `failed` | `proof_pending` | Payroll operator or automation | Retry from proof generation when inputs remain valid. |
| `failed` | `cancelled` | Payroll operator | Stop a failed run instead of retrying. |
| `reconciliation_required` | `completed` | Reconciliation operator | Reconciliation succeeded and the run is final. |
| `reconciliation_required` | `failed` | Reconciliation operator | Reconciliation failed and the run requires retry handling. |

All other transitions are forbidden. In particular, clients and integrations
must reject direct jumps such as `draft -> completed`, reverse transitions such
as `submitted -> draft`, and any transition out of `completed` or `cancelled`.

## Contract Entry Points

The payroll contract records canonical state for the on-chain lifecycle:

| Entry point | State effect |
| --- | --- |
| `prepare_payroll_run` | Stores `submitted` for the new pending run. |
| `cancel_payroll_run` | Stores `cancelled` and removes the pending run. |
| `batch_process_payroll` | Stores `reconciliation_required` after execution. |
| `update_reconciliation_status(Reconciled)` | Stores `completed`. |
| `update_reconciliation_status(Unreconciled)` | Keeps or stores `reconciliation_required`. |
| `update_reconciliation_status(Failed)` | Stores retryable `failed`. |
| `transition_payroll_run_state` | Admin-only conformance hook that rejects forbidden transitions. |
| `get_payroll_run_state` | Reads the canonical state for a run ID. |

The contract exposes `is_payroll_state_transition_allowed`,
`is_payroll_state_terminal`, and `is_payroll_state_retryable` so tests and
off-chain mirrors can assert the same semantics without duplicating rules.

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
