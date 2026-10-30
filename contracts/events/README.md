# Contract Event Topics and Payload Documentation

This document describes the structured event emission schema implemented across the `zk-payroll` contract suite.

## Event Schema Structure

Every state-changing entrypoint publishes events via Soroban's event bus using a consistent tuple structure:
- **Topics** (Indexed): `(contract_domain, event_name, [entity_id])`
- **Data** (Payload): Typed tuple of event data parameters.

## Core Event Categories

### 1. Payroll Events (`payroll`)

| Topic Symbol | Data Payload | Description |
| :--- | :--- | :--- |
| `run_prepared` | `(run_id: u64, total_spend: i128)` | Emitted when a batch payroll run is prepared |
| `run_approved` | `(run_id: u64, reviewer: Address)` | Emitted when a reviewer approves a run |
| `run_approval_withdrawn` | `(run_id: u64, reviewer: Address, reason: Symbol)` | Emitted when an approval is withdrawn |
| `run_approval_superseded` | `(run_id: u64, previous_reviewer: Address, new_reviewer: Address)` | Emitted when reviewer rotation supersedes approval |
| `run_rejected` | `(run_id: u64, reviewer: Address, reason: Symbol)` | Emitted when a payroll run is rejected |
| `changes_requested` | `(run_id: u64, reviewer: Address, reason: Symbol)` | Emitted when changes are requested on a run |
| `run_executed` | `(run_id: u64, total_spend: i128)` | Emitted when a run is executed on-chain |
| `run_cancelled` | `(run_id: u64, cancelled_by: Address)` | Emitted when a pending run is cancelled by an authorized admin |
| `run_expired` | `(run_id: u64, expired_by: Address)` | Emitted when an unexecuted run expires past TTL |
| `payment_executed` | `(employee: Address, amount: i128)` | Emitted for each individual payout execution |
| `deposit` | `(from: Address, amount: i128, deposit_id: BytesN<32>)` | Emitted when funds are deposited to treasury |
| `draft_created` | `(draft_id: u64, creator: Address, total_amount: i128)` | Emitted when a payroll draft is created |
| `draft_committed` | `(draft_hash: BytesN<32>)` | Emitted when a draft hash is committed |
| `draft_amended` | `(draft_id: u64, new_total: i128, amendment_count: u32)` | Emitted when a draft is updated |
| `draft_cancelled` | `(draft_id: u64, admin: Address)` | Emitted when a draft is cancelled |

### 2. Administrative & Governance Events

| Topic Symbol | Data Payload | Description |
| :--- | :--- | :--- |
| `admin_proposed` | `(current_admin: Address, new_admin: Address)` | Two-step admin proposal initiated |
| `admin_rotated` | `(old_admin: Address, new_admin: Address)` | Admin rotation completed |
| `admin_rot_cancel` | `(caller: Address)` | Pending admin rotation cancelled |
| `treasury_proposed` | `(current_owner: Address, new_owner: Address)` | Treasury owner rotation proposed |
| `treasury_rotated` | `(old_owner: Address, new_owner: Address)` | Treasury owner rotation completed |
| `treas_rot_cancel` | `(caller: Address)` | Pending treasury rotation cancelled |
| `reviewer_added` | `(reviewer: Address)` | Authorized reviewer added |
| `reviewer_removed` | `(reviewer: Address)` | Reviewer removed |
| `asset_allowlist_updated` | `(asset: Address, allowed: bool)` | Asset allowlist configuration updated |
| `reservation_created` | `(asset: Address, reserved_amount: i128, expires_at: u64)` | Treasury fund reservation created |

## Privacy and Data Minimization

Payloads are deliberately designed to protect sensitive employee details:
- Individual salary amounts are only emitted via ephemeral payment execution events, never logged in permanent contract headers.
- Cancelled runs record only the cancelling administrative authority and identifier, avoiding exposure of drafted financial aggregates.
