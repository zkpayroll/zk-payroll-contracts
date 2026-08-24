# Settlement State Machine

Issue #254 documents the canonical settlement lifecycle that the payroll
contract, SDKs, and dashboards must mirror. The contract source of truth is
`PayrollRunState` in `contracts/payroll/src/lib.rs`; the transition rules are
enforced by `is_allowed_payroll_state_transition_internal` and exposed for
operations through `transition_payroll_run_state`. The machine-readable mirror
is `fixtures/state-machine/settlement-state-machine.json`.

## Settlement Phases

The issue describes settlement in five high-level phases; they map onto the
concrete `PayrollRunState` variants below.

| Settlement phase (issue #254) | `PayrollRunState` | Terminal | Retryable | Meaning |
| --- | --- | --- | --- | --- |
| `pending` | `Submitted` | No | No | Run prepared, awaiting settlement/confirmation. |
| `executing` | `Confirming` | No | No | Settlement/confirmation in progress. |
| `settled` | `Completed` | Yes | No | Settlement finalized; immutable. |
| `failed` | `Failed` | No | Yes | Settlement failed; the only retryable state. |
| `cancelled` | `Cancelled` | Yes | No | Run cancelled; immutable. |

The full concrete state set also includes the pre-settlement drafting stages
(`Draft`, `Validating`, `ProofPending`, `ReadyToSubmit`) and the
`ReconciliationRequired` review stage that `Confirming` may enter before
`Completed`.

## Allowed Transitions

| From | To | Settlement meaning |
| --- | --- | --- |
| `Draft` | `Validating` | Begin validating a draft run. |
| `Draft` | `Cancelled` | Cancel a run before validation. |
| `Validating` | `ProofPending` | Inputs passed validation; proof work can start. |
| `Validating` | `Failed` | Validation failed; the run can be retried. |
| `Validating` | `Cancelled` | Cancel a run during validation. |
| `ProofPending` | `ReadyToSubmit` | Proof artifacts ready. |
| `ProofPending` | `Failed` | Proof generation/verification failed. |
| `ProofPending` | `Cancelled` | Cancel a run while proofs are pending. |
| `ReadyToSubmit` | `Submitted` | Submit the prepared run on-chain (`pending`). |
| `ReadyToSubmit` | `Failed` | Submission preparation failed. |
| `ReadyToSubmit` | `Cancelled` | Cancel a run before on-chain submission. |
| `Submitted` (`pending`) | `Confirming` (`executing`) | Begin settlement. |
| `Submitted` (`pending`) | `Failed` | Submission failed before confirmation. |
| `Submitted` (`pending`) | `Cancelled` | Cancel a prepared run before settlement. |
| `Confirming` (`executing`) | `Completed` (`settled`) | Settlement finalized. |
| `Confirming` (`executing`) | `Failed` | Settlement failed; retryable. |
| `Confirming` (`executing`) | `ReconciliationRequired` | Executed; must be reconciled before settlement closes. |
| `Failed` | `Validating` | Retry from validation. |
| `Failed` | `ProofPending` | Retry from proof generation when inputs remain valid. |
| `Failed` | `Cancelled` | Cancel a failed run. |
| `ReconciliationRequired` | `Completed` (`settled`) | Reconciliation complete; settlement closes. |
| `ReconciliationRequired` | `Failed` | Reconciliation failed; retryable. |

## Blocked Transitions

| Operation | Outcome |
| --- | --- |
| Any transition into `Draft` | Rejected — `Draft` is only an initial state. |
| `Completed` (`settled`) → anything | Rejected — terminal/immutable (settlement cannot be replayed). |
| `Cancelled` → anything | Rejected — terminal/immutable. |
| Non-adjacent transitions (e.g. `Submitted` → `Completed`) | Rejected — the canonical matrix only allows single-step moves. |
| Transition without the company admin's authorization | Rejected (`require_auth` fails). |

## Reference Implementation Tests

The behaviour on this page is pinned by the integration suite in
`tests/settlement/`:

| Suite | Coverage |
| --- | --- |
| `settlement_transitions.rs` | Full 10 × 10 transition matrix matches the documented rules; every valid transition is applied on-chain; invalid transitions panic with `Invalid payroll state transition`; `settled`/`cancelled` reject all further moves; only `failed` is retryable; non-admin transitions are rejected. |

Run them with:

```bash
cargo test -p settlement_state_tests
```

## Relationship to Reconciliation

Settlement finalization (`Confirming` → `Completed`) is driven by
`update_reconciliation_status`, which maps `Reconciled` → `Completed`,
`Unreconciled` → `ReconciliationRequired`, and `Failed` → `Failed`. The same
function enforces the *settlement completion is final* guard (issue #244): once
a run is `Completed` any further reconciliation update is rejected, preventing
double settlement.
