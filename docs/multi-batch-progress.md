# Multi-Batch Execution Progress Tracking (#643)

An opt-in, contract-layer aggregate view over a sequence of bounded payroll
batches.

## Why

Large payroll runs execute as a sequence of `batch_process_payroll_bounded`
calls (at most 50 payments each). Each call leaves an isolated
`BatchCheckpoint` keyed by `(employer, batch_root, asset, nonce)`. Operators
had no single record of how far the *whole* execution had progressed: how many
batches and payments were planned, how many had completed, and whether the
execution was still running, finished, or had failed.

This tracker groups those batches under one opaque `execution_id` and exposes
a privacy-safe aggregate (`MultiBatchExecutionProgress`) that dashboards, SDKs,
and indexers can poll without reassembling per-batch checkpoints.

## Safest integration point

The tracker is standalone and additive:

- New storage lives under a dedicated `MultiBatchKey::MultiBatchProgress`
  enum, leaving the existing `DataKey` layout untouched (that enum is already
  past the Soroban 50-case spec ceiling, the same reason `VarianceKey` and
  `ApprovalKey` exist).
- No existing entrypoint was modified. `BatchCheckpoint`,
  `BatchResumePlan`, `batch_process_payroll_bounded`, and the resume/recovery
  flows behave exactly as before. Enabling the tracker cannot regress prepared
  runs, checkpoints, or bounded execution.
- Pure validation lives in `contracts/payroll/src/multi_batch_progress.rs`
  (side-effect free, unit-tested); authorization, storage, and events live in
  `Payroll` in `contracts/payroll/src/lib.rs`.

## Rules

Plans are bounded so ledger entries, events, and polling loops stay small:

| Case | Behaviour |
|------|-----------|
| `total_batches` | Must be `1..=50` (`MAX_MULTI_BATCH_BATCHES`). |
| `total_payments` | Must be `1..=2500` (`MAX_MULTI_BATCH_PAYMENTS`). |
| `total_payments < total_batches` | Rejected (each batch holds at least one payment). |
| `execution_id` all-zero | Rejected (`Digest cannot be all-zero bytes`). |
| Duplicate `execution_id` | Rejected (`Multi-batch execution already exists`). |

Progress records use absolute cursors (not deltas) and are validated in a
fixed order before any state is written:

1. Terminal check (`Completed` / `Failed` reject).
2. Bounds (`completed_batches <= total_batches`,
   `processed_payments <= total_payments`).
3. Monotonicity (new cursors `>=` stored cursors).
4. Forward progress (at least one cursor strictly increases).

Reaching both planned totals flips the tracker to `Completed` automatically.
`mark_multi_batch_failed` moves `InProgress -> Failed` and preserves the
cursors so operators see how far the execution got. Terminal records are
immutable.

## Contract surface

| Entrypoint | Purpose |
|------------|---------|
| `begin_multi_batch_execution(admin, execution_id, total_batches, total_payments)` | Admin-only validated open; starts at `(0, 0)` in `InProgress`. |
| `record_multi_batch_progress(admin, execution_id, completed_batches, processed_payments)` | Admin-only monotonic advance; auto-completes on both totals. |
| `mark_multi_batch_failed(admin, execution_id)` | Admin-only `InProgress -> Failed` transition. |
| `get_multi_batch_progress(execution_id)` | Read-only aggregate view; no auth, no state change. |
| `is_multi_batch_complete(execution_id)` | Read-only completion poll; `false` when unknown, in-progress, or failed. |

Supporting types in `contracts/payroll/src/multi_batch_progress.rs`:

| Type | Purpose |
|------|---------|
| `MultiBatchExecutionProgress` | Stored aggregate (opaque id + counts + status + timestamps + updater). |
| `MultiBatchStatus` | `InProgress (0)`, `Completed (1)`, `Failed (2)` — stable ordinals. |
| `MultiBatchProgressIssue` | Structured failure reason with stable `as_str()` codes. |
| `MAX_MULTI_BATCH_BATCHES` | `50`. |
| `MAX_MULTI_BATCH_PAYMENTS` | `2500`. |

Storage uses `MultiBatchKey::MultiBatchProgress(BytesN<32>)`.

## Errors

All messages name the one thing the caller must change:

- `"Multi-batch total batches must be between 1 and 50"` — replan with a
  value in range.
- `"Multi-batch total payments must be between 1 and 2500"` — replan with a
  value in range.
- `"Multi-batch total payments cannot be less than total batches"` — raise
  `total_payments` or lower `total_batches`.
- `"Multi-batch execution already exists"` — reuse the existing tracker or
  pick a fresh `execution_id`.
- `"Multi-batch execution not found: call begin_multi_batch_execution first"`
  — open the tracker before recording.
- `"Multi-batch completed batches exceed planned total"` /
  `"Multi-batch processed payments exceed planned total"` — resubmit within
  the planned totals.
- `"Multi-batch progress regression: new progress is behind stored progress"`
  — resubmit with cursors at or ahead of the stored values.
- `"Multi-batch progress must move forward: no new batches or payments recorded"`
  — advance at least one cursor.
- `"Multi-batch execution is already terminal"` — start a new execution;
  terminal records are immutable.
- `"Unauthorized"` / pause errors — standard admin and pause gates.

## Events

Legacy `("payroll", <verb>)` convention, carrying only the opaque id, counts,
and timestamps — never employee identities or salary breakdowns:

| Topics | Data |
|--------|------|
| `("payroll", "multi_batch_started")` | `(execution_id, total_batches, total_payments, timestamp)` |
| `("payroll", "multi_batch_progress")` | `(execution_id, completed_batches, processed_payments, timestamp)` |
| `("payroll", "multi_batch_completed")` | `(execution_id, completed_batches, processed_payments, timestamp)` |
| `("payroll", "multi_batch_failed")` | `(execution_id, completed_batches, processed_payments, timestamp)` |

## Privacy

Only the opaque execution identifier and aggregate counts are stored, checked,
and emitted. No per-employee salary, identity, commitment, or proof material
is read or surfaced, consistent with the checkpoint (`BatchCheckpoint`) and
resume-plan (`BatchResumePlan`) features.

## Verification

- `cargo test -p payroll --test multi_batch_progress` — 12 focused
  integration tests (open at zero, incremental advance with auto-complete,
  failure preserves cursors, non-admin rejection, duplicate rejection, total
  validation, over-total / regression / no-op rejection, terminal
  immutability, unknown-id handling, single-batch edge, max-cap boundary,
  split-completion edge).
- Unit tests in `multi_batch_progress.rs` pin the pure validation
  (valid plans, empty/over-cap, payments-below-batches, monotonic accept,
  terminal-first, over-total precedence, regression/no-op, saturating
  remainders, stable issue codes).
- Regression: `cargo test -p payroll --test bounded_batch` and
  `cargo test -p payroll --test payroll_variance_threshold` still pass.
