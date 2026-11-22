# Contract Event Registry

Canonical reference for the Soroban events emitted by this repository. It lists
the supported topic tuples and positional payloads for every event pinned by
`tests/event_schema/fixtures/events/*.json`. The fixtures remain the
machine-readable source of truth; this document is the human-readable index.

All events below are currently pinned to `schema_version: 1`. The version is a
repository-only counter and is **not** emitted on-chain. Bump it in the fixture
and update this registry whenever a topic or payload shape changes.

## Conventions

- `topics` are positional. Static `Symbol` values are exact filter keys;
  `*<Type>` marks a dynamic per-invocation topic whose value is not fixed.
- `data` is positional. Field names are documentation only; Soroban carries
  typed values in declaration order, not names.
- Consumers should filter by the exact topic tuple and decode data using the
  listed types in order. Do not infer field names from the wire.
- `BytesN<32>` values are hashes, commitments, nullifiers, or IDs;
  `Address` values are account/contract identifiers; `i128` amounts are raw
  token units.

## `registry.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `registry.CompanyRegistered` | `CompanyRegistered:Symbol → *:u64` | `admin:Address, treasury:Address` |
| `registry.EmployeeAdded` | `EmployeeAdded:Symbol → *:u64 → *:Address` | `commitment:BytesN<32>` |
| `registry.EmployeeRemoved` | `EmployeeRemoved:Symbol → *:u64 → *:Address` | `(none)` |
| `registry.CommitmentUpdated` | `CommitmentUpdated:Symbol → *:u64 → *:Address` | `new_commitment:BytesN<32>` |
| `registry.EmployeeStatusChanged` | `EmployeeStatusChanged:Symbol → *:u64 → *:Address` | `previous_status:Symbol, new_status:Symbol` |
| `registry.RegistryPauseMgrSet` | `RegistryPauseMgrSet:Symbol` | `pause_manager:Address` |
| `registry.CompanyAdminProposed` | `CompanyAdminProposed:Symbol → *:u64 → *:Address` | `new_admin:Address` |
| `registry.CompanyAdminRotated` | `CompanyAdminRotated:Symbol → *:u64 → *:Address` | `new_admin:Address` |
| `registry.CompanyAdminRotCancelled` | `CompanyAdminRotCancelled:Symbol → *:u64 → *:Address` | `(none)` |
| `registry.CompanyTreasProposed` | `CompanyTreasProposed:Symbol → *:u64 → *:Address` | `new_treasury:Address` |
| `registry.CompanyTreasRotated` | `CompanyTreasRotated:Symbol → *:u64 → *:Address` | `new_treasury:Address` |
| `registry.CompanyTreasRotCancelled` | `CompanyTreasRotCancelled:Symbol → *:u64 → *:Address` | `(none)` |

## `employer_onboarding.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `onboarding.CommitmentUpdated` | `CommitmentUpdated:Symbol → *:Address` | `commitment:BytesN<32>` |
| `onboarding.CompanyRegistered` | `CompanyRegistered:Symbol → *:u64` | `admin:Address, treasury:Address` |
| `onboarding.EmployeeAdded` | `EmployeeAdded:Symbol → *:u64 → *:Address` | `commitment:BytesN<32>` |
| `onboarding.ReferenceIdSet` | `ReferenceIdSet:Symbol → *:Address` | `reference_id:String` |

## `payroll.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `payroll.admin_proposed` | `payroll:Symbol → admin_proposed:Symbol` | `current_admin:Address, new_admin:Address` |
| `payroll.admin_rot_cancel` | `payroll:Symbol → admin_rot_cancel:Symbol` | `caller:Address` |
| `payroll.admin_rotated` | `payroll:Symbol → admin_rotated:Symbol` | `old_admin:Address, new_admin:Address` |
| `payroll.asset_allowlist_updated` | `payroll:Symbol → asset_allowlist_updated:Symbol` | `asset:Address, allowed:bool` |
| `payroll.changes_requested` | `payroll:Symbol → changes_requested:Symbol` | `run_id:u64, reviewer:Address, reason:Symbol` |
| `payroll.deposit` | `payroll:Symbol → deposit:Symbol` | `from:Address, amount:i128, deposit_id:BytesN<32>` |
| `payroll.draft_amended` | `payroll:Symbol → draft_amended:Symbol` | `draft_id:u64, new_total:i128, amendment_count:u32` |
| `payroll.draft_cancelled` | `payroll:Symbol → draft_cancelled:Symbol` | `draft_id:u64, admin:Address` |
| `payroll.draft_committed` | `payroll:Symbol → draft_committed:Symbol` | `draft_hash:BytesN<32>` |
| `payroll.draft_created` | `payroll:Symbol → draft_created:Symbol` | `draft_id:u64, admin:Address, period_label:Symbol` |
| `payroll.draft_expired` | `payroll:Symbol → draft_expired:Symbol` | `draft_id:u64, admin:Address` |
| `payroll.draft_finalized` | `payroll:Symbol → draft_finalized:Symbol` | `draft_id:u64, total:i128, amendment_count:u32` |
| `payroll.draft_submitted` | `payroll:Symbol → draft_submitted:Symbol` | `draft_id:u64, admin:Address` |
| `payroll.emrg_approved` | `payroll:Symbol → emrg_approved:Symbol` | `amount:i128, recipient:Address` |
| `payroll.emrg_cancelled` | `payroll:Symbol → emrg_cancelled:Symbol` | `caller:Address` |
| `payroll.emrg_requested` | `payroll:Symbol → emrg_requested:Symbol` | `amount:i128, recipient:Address` |
| `payroll.initialized` | `payroll:Symbol → initialized:Symbol` | `admin:Address, token:Address, verifier:Address, commitment:Address, treasury:Address, treasury_owner:Address` |
| `payroll.meta_bound` | `payroll:Symbol → meta_bound:Symbol` | `run_id:u64, metadata_hash:BytesN<32>` |
| `payroll.meta_committed` | `payroll:Symbol → meta_committed:Symbol` | `metadata_hash:BytesN<32>` |
| `payroll.pause_mgr_set` | `payroll:Symbol → pause_mgr_set:Symbol` | `pause_manager:Address` |
| `payroll.payment_executed` | `payroll:Symbol → payment_executed:Symbol` | `employee:Address, amount:i128` |
| `payroll.payroll_upload_completed` | `payroll:Symbol → payroll_upload_completed:Symbol` | `upload_id:BytesN<32>, batch_root:BytesN<32>, uploaded_chunks:u32, total_chunks:u32` |
| `payroll.payroll_upload_failed` | `payroll:Symbol → payroll_upload_failed:Symbol` | `upload_id:BytesN<32>, batch_root:BytesN<32>, uploaded_chunks:u32, total_chunks:u32` |
| `payroll.payroll_upload_progress` | `payroll:Symbol → payroll_upload_progress:Symbol` | `upload_id:BytesN<32>, batch_root:BytesN<32>, uploaded_chunks:u32, total_chunks:u32` |
| `payroll.payroll_upload_resumed` | `payroll:Symbol → payroll_upload_resumed:Symbol` | `upload_id:BytesN<32>, batch_root:BytesN<32>, uploaded_chunks:u32, total_chunks:u32` |
| `payroll.payroll_upload_started` | `payroll:Symbol → payroll_upload_started:Symbol` | `upload_id:BytesN<32>, batch_root:BytesN<32>, total_chunks:u32` |
| `payroll.period_frozen` | `payroll:Symbol → period_frozen:Symbol` | `period_label:Symbol, frozen_by:Address, reason:Symbol` |
| `payroll.period_unfrozen` | `payroll:Symbol → period_unfrozen:Symbol` | `period_label:Symbol, unfrozen_by:Address` |
| `payroll.reconciliation_updated` | `payroll:Symbol → reconciliation_updated:Symbol` | `run_id:u64, status:Symbol` |
| `payroll.reservation_created` | `payroll:Symbol → reservation_created:Symbol` | `asset:Address, reserved_amount:i128, expires_at:u64` |
| `payroll.reviewer_added` | `payroll:Symbol → reviewer_added:Symbol` | `reviewer:Address` |
| `payroll.reviewer_removed` | `payroll:Symbol → reviewer_removed:Symbol` | `reviewer:Address` |
| `payroll.run_approval_superseded` | `payroll:Symbol → run_approval_superseded:Symbol` | `run_id:u64, previous_reviewer:Address, new_reviewer:Address` |
| `payroll.run_approval_withdrawn` | `payroll:Symbol → run_approval_withdrawn:Symbol` | `run_id:u64, reviewer:Address, reason:Symbol` |
| `payroll.run_approved` | `payroll:Symbol → run_approved:Symbol` | `run_id:u64, reviewer:Address` |
| `payroll.run_cancelled` | `payroll:Symbol → run_cancelled:Symbol` | `run_id:u64, cancelled_by:Address` |
| `payroll.run_executed` | `payroll:Symbol → run_executed:Symbol` | `run_id:u64, total_spend:i128` |
| `payroll.run_expired` | `payroll:Symbol → run_expired:Symbol` | `run_id:u64, expired_by:Address` |
| `payroll.run_prepared` | `payroll:Symbol → run_prepared:Symbol` | `run_id:u64, total_spend:i128` |
| `payroll.run_rejected` | `payroll:Symbol → run_rejected:Symbol` | `run_id:u64, reviewer:Address, reason:Symbol` |
| `payroll.treas_rot_cancel` | `payroll:Symbol → treas_rot_cancel:Symbol` | `caller:Address` |
| `payroll.treasury_balance_snapshot` | `payroll:Symbol → treasury_balance_snapshot:Symbol → *:Address` | `total_balance:i128, available_balance:i128, reserved_balance:i128, blocked_balance:i128, observed_at:u64, trigger:Symbol` |
| `payroll.treasury_proposed` | `payroll:Symbol → treasury_proposed:Symbol` | `current_owner:Address, new_owner:Address` |
| `payroll.treasury_rotated` | `payroll:Symbol → treasury_rotated:Symbol` | `old_owner:Address, new_owner:Address` |

## `payment_executor.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `payment_executor.AssetAllowedChanged` | `AssetAllowedChanged:Symbol` | `asset:Address, allowed:bool` |
| `payment_executor.ExecutorAdminSet` | `ExecutorAdminSet:Symbol` | `admin:Address` |
| `payment_executor.ExecutorInitialized` | `ExecutorInitialized:Symbol` | `registry:Address, token:Address` |
| `payment_executor.ExecutorPauseMgrSet` | `ExecutorPauseMgrSet:Symbol` | `pause_manager:Address` |
| `payment_executor.PayrollProcessed` | `PayrollProcessed:Symbol → *:u64` | `employee:Address, amount:i128, period:u32` |
| `payment_executor.PeriodClosed` | `PeriodClosed:Symbol → *:u64` | `period_id:u32` |
| `payment_executor.PeriodCreated` | `PeriodCreated:Symbol → *:u64` | `period_id:u32` |
| `payment_executor.PeriodReopened` | `PeriodReopened:Symbol → *:u64` | `period_id:u32` |

## `salary_commitment.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `salary_commitment.AdminRotationAccepted` | `AdminRotationAccepted:Symbol → *:Address` | `(none)` |
| `salary_commitment.AdminRotationCancelled` | `AdminRotationCancelled:Symbol → *:Address` | `(none)` |
| `salary_commitment.AdminRotationProposed` | `AdminRotationProposed:Symbol → *:Address` | `new_admin:Address` |
| `salary_commitment.ApprovedCommitmentRotated` | `ApprovedCommitmentRotated:Symbol → *:Address` | `old_commitment:BytesN<32>, new_commitment:BytesN<32>` |
| `salary_commitment.CommitPauseMgrSet` | `CommitPauseMgrSet:Symbol` | `pause_manager:Address` |
| `salary_commitment.CommitmentLocked` | `CommitmentLocked:Symbol → *:Address` | `(none)` |
| `salary_commitment.CommitmentRotated` | `CommitmentRotated:Symbol → *:Address` | `old_commitment:BytesN<32>, new_commitment:BytesN<32>` |
| `salary_commitment.CommitmentUnlocked` | `CommitmentUnlocked:Symbol → *:Address` | `(none)` |
| `salary_commitment.CommitmentUpdated` | `CommitmentUpdated:Symbol → *:Address` | `commitment:BytesN<32>` |
| `salary_commitment.NullifierRecorded` | `NullifierRecorded:Symbol` | `nullifier:BytesN<32>` |
| `salary_commitment.PayrollOperatorSet` | `PayrollOperatorSet:Symbol` | `operator:Address` |
| `salary_commitment.ReferenceIdSet` | `ReferenceIdSet:Symbol → *:Address` | `reference_id:String` |

## `audit_module.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `audit_module.AggregateAuditGenerated` | `AggregateAuditGenerated:Symbol → *:Address` | `company_id:Symbol, period_start:u64, period_end:u64` |
| `audit_module.AuditAccessRevoked` | `AuditAccessRevoked:Symbol → *:Address → *:Address` | `(none)` |
| `audit_module.AuditPauseMgrSet` | `AuditPauseMgrSet:Symbol` | `pause_manager:Address` |
| `audit_module.AuditSuccessful` | `AuditSuccessful:Symbol → *:Address` | `scope:Symbol` |
| `audit_module.AuditSummaryExported` | `AuditSummaryExported:Symbol → *:Address` | `company_id:Symbol, period_start:u64, period_end:u64, total:u32` |
| `audit_module.ViewKeyGenerated` | `ViewKeyGenerated:Symbol → *:Address` | `expiration_ledger:u32` |

## `pause_manager.json`

| Event | Topics | Payload (schema v1) |
|---|---|---|
| `pause_manager.initialized` | `PauseManager:Symbol → initialized:Symbol` | `operator:Address` |
| `pause_manager.op_cancelled` | `PauseManager:Symbol → op_cancelled:Symbol` | `current:Address` |
| `pause_manager.op_proposed` | `PauseManager:Symbol → op_proposed:Symbol` | `current:Address, new_op:Address` |
| `pause_manager.op_rotated` | `PauseManager:Symbol → op_rotated:Symbol` | `new_op:Address` |
| `pause_manager.paused` | `PauseManager:Symbol → paused:Symbol` | `(none)` |
| `pause_manager.unpaused` | `PauseManager:Symbol → unpaused:Symbol` | `(none)` |

## Compatibility and changes

1. Add the emitter to `contracts/events/src/lib.rs`.
2. Add a `case_*` scenario to the matching module in `tests/event_schema/src/`.
3. Add or update the fixture entry with an explicit `schema_version`.
4. Update this registry and call out old/new shapes in the PR description.
5. Run `cargo test -p event_schema_snapshots`.

A new event starts at version 1. Any topic or data change is a breaking
consumer change and requires a version bump; test-only refactors do not.
