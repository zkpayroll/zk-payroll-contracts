# Archived Payroll Run Queries

This document covers the archived-run query interface: how to archive a run, the
supported query parameters, the shape of returned records, expected downstream usage
patterns, and the boundary between archived and active access paths.

## Overview

Payroll runs accumulate over time. For long-term reporting and audit workflows, the
contract supports explicitly marking completed runs as **archived**. Archived runs remain
readable via a dedicated, read-only query path that is fully isolated from the active
operational flow: querying an archived run cannot trigger execution, state transitions,
or treasury mutations.

## Archiving a run

Only the admin may archive a run.

```
archive_payroll_run(admin: Address, run_id: u64)
```

**Prerequisites**:
- The caller must be the current `admin`.
- The `run_id` must correspond to an existing `PayrollRun` record
  (i.e., `batch_process_payroll` completed successfully for that ID).
- The run must not already be archived (double-archiving panics).

**Effect**: A boolean flag is stored under `DataKey::ArchivedRun(run_id)`. The underlying
`PayrollRun` record is not modified. The original `get_payroll_run` path continues to
work for the same `run_id`.

**Event emitted**: `("payroll", "run_archived")` with `run_id: u64`.

## Querying archived runs

### `get_archived_run(run_id: u64) → PayrollRun`

Returns the full `PayrollRun` record for an archived run. Panics with `"Run is not
archived"` if the run exists but has not been archived. This deliberate panic keeps the
archived and active access paths clearly separated: code that calls `get_archived_run`
can rely on the returned record always being archived.

### `is_run_archived(run_id: u64) → bool`

Non-panicking check. Returns `true` if the run has been marked as archived, `false`
otherwise (including for run IDs that do not exist).

### Supported query parameters

The current contract exposes per-run lookups only. There is no range query or
server-side filtering by date range or reconciliation status. Off-chain indexers should:

1. Listen for `("payroll", "run_archived")` events to build an index of archived run IDs.
2. Call `get_archived_run(run_id)` for each ID in the index when reporting data is needed.

Range queries and pagination are planned for a future SDK layer on top of this interface.

## Returned record shape

`get_archived_run` returns a `PayrollRun` struct:

| Field | Type | Description |
|---|---|---|
| `run_id` | `u64` | Auto-incremented run identifier. |
| `executed_at` | `u64` | Ledger timestamp at execution (seconds). |
| `admin` | `Address` | Admin that executed the run. |
| `total_amount` | `i128` | Total tokens disbursed across all employees. |
| `employee_count` | `u32` | Number of employees paid in this batch. |
| `draft_hash` | `BytesN<32>` | Off-chain payroll draft hash (zeroed if not supplied). |
| `nonce` | `BytesN<32>` | Caller-supplied run nonce; unique per contract lifetime. |
| `reconciliation_status` | `ReconciliationStatus` | `Unreconciled`, `Reconciled`, or `Failed`. |
| `metadata_hash` | `BytesN<32>` | Pre-committed metadata hash (zeroed if not supplied). |

See [payroll-run-identifiers.md](./payroll-run-identifiers.md) for the semantics of
`run_id` and `nonce`. See [reconciliation-states.md](./reconciliation-states.md) for the
meaning of `reconciliation_status`.

## Boundary between archived and active access paths

| Scenario | Correct function |
|---|---|
| Fetching a run to update its reconciliation status | `get_payroll_run(run_id)` |
| Fetching a run for a reporting or audit dashboard | `get_archived_run(run_id)` |
| Checking whether a run is in the archive | `is_run_archived(run_id)` |
| Iterating all historical runs | Off-chain: index `run_archived` events, then call `get_archived_run` per ID. |

The two paths share the same underlying storage record but differ in access semantics:
`get_archived_run` enforces the archived precondition, preventing code paths that intend
to operate only on historical data from accidentally touching active runs.

## Unsupported operations

The following operations are explicitly rejected on archived runs:

| Attempted operation | Result |
|---|---|
| `archive_payroll_run` on an already-archived run | Panics: `"Run is already archived"` |
| Calling `batch_process_payroll` with an already-used `run_id` | Not applicable; run IDs are read-only after creation. |
| Modifying `reconciliation_status` of an archived run | Permitted — `update_reconciliation_status` does not check archive status. |

## Cross-references

- Issue [#146](https://github.com/zkpayroll/zk-payroll-contracts/issues/146): this
  feature's implementation issue.
- See [payroll-run-identifiers.md](./payroll-run-identifiers.md) for run ID semantics.
- See [reconciliation-states.md](./reconciliation-states.md) for the `reconciliation_status`
  field returned in archived run records.
