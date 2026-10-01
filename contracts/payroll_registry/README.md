# payroll_registry Architecture Interface

This document defines the canonical interface and storage model for the
`payroll_registry` contract.

## Entrypoints

| Method | Parameters | Returns | Access Control |
| --- | --- | --- | --- |
| `register_company` | `admin: Address`, `treasury: Address` | `u64` | None |
| `add_employee` | `company_id: u64`, `employee: Address`, `commitment: BytesN<32>` | `()` | `require_auth(admin)` |
| `remove_employee` | `company_id: u64`, `employee: Address` | `()` | `require_auth(admin)` |
| `update_commitment` | `company_id: u64`, `employee: Address`, `new_commitment: BytesN<32>` | `()` | `require_auth(admin)` |
| `set_employee_status` | `company_id: u64`, `employee: Address`, `status: EmployeeStatus` | `()` | `require_auth(admin)` |
| `update_payout_destination` | `company_id: u64`, `employee: Address`, `new_destination: Address` | `()` | `require_auth(employee)` |
| `propose_payout_dest_change` | `company_id: u64`, `employee: Address`, `new_destination: Address` | `()` | `require_auth(employee)` |
| `review_payout_dest_change` | `company_id: u64`, `employee: Address`, `admin: Address`, `approve: bool` | `()` | `require_auth(admin)` |
| `cancel_payout_dest_change` | `company_id: u64`, `employee: Address` | `()` | `require_auth(employee)` |
| `get_payout_dest_review` | `company_id: u64`, `employee: Address` | `Option<PayoutDestinationReview>` | None |

## Rust Interface Definitions

The contract interface is defined by the Rust trait:

- `PayrollRegistryTrait`
  - `fn register_company(env: Env, admin: Address, treasury: Address) -> u64`
  - `fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>)`
  - `fn remove_employee(env: Env, company_id: u64, employee: Address)`
  - `fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>)`
  - `fn set_employee_status(env: Env, company_id: u64, employee: Address, status: EmployeeStatus)`
  - `fn update_payout_destination(env: Env, company_id: u64, employee: Address, new_destination: Address)`
  - `fn propose_payout_dest_change(env: Env, company_id: u64, employee: Address, new_destination: Address)`
  - `fn review_payout_dest_change(env: Env, company_id: u64, employee: Address, admin: Address, approve: bool)`
  - `fn cancel_payout_dest_change(env: Env, company_id: u64, employee: Address)`
  - `fn get_payout_dest_review(env: Env, company_id: u64, employee: Address) -> Option<PayoutDestinationReview>`

## Storage Types and Keys

Storage is implemented using `DataKey`:

- `DataKey::Company(u64)` maps to `CompanyInfo { admin: Address, treasury: Address }`
- `DataKey::Employee(u64, Address)` maps to `BytesN<32>` (active Poseidon commitment)
- `DataKey::PayoutDestination(u64, Address)` maps to `Address` (unset means the
  destination defaults to the employee address)
- `DataKey::DestinationReview(u64, Address)` maps to `PayoutDestinationReview`
  (issue #610; the most recent review for the employee)

The `CompanyInfo` struct definition in Rust:

- `pub struct CompanyInfo { pub admin: Address, pub treasury: Address }`

The payout destination review types (issue #610):

- `pub enum DestinationReviewStatus { Pending = 0, Approved = 1, Rejected = 2, Cancelled = 3 }`
- `pub struct PayoutDestinationReview { company_id: u64, employee: Address, new_destination: Address, current_destination: Address, proposed_at: u64, status: DestinationReviewStatus, resolved_at: u64, resolved_by: Option<Address> }`

## Payout Destination Change Review (issue #610)

`update_payout_destination` applies a destination change immediately. The review
flow adds a second pair of eyes before the destination is actually redirected,
so a compromised or coerced employee account cannot silently divert payroll:

1. `propose_payout_dest_change` — the employee records a `Pending` review
   holding the proposed destination and a snapshot of the destination currently
   on file. The payout destination is **not** changed.
2. `review_payout_dest_change` — the company admin approves or rejects. On
   approval the new destination is written and the existing
   `PayoutDestinationUpdated` event is emitted, so indexers see the same event
   shape as a direct update.
3. `cancel_payout_dest_change` — the proposing employee may withdraw a pending
   change at any time.

**Validation** (identical to the direct flow, so the two paths cannot diverge):

| Condition | Panic |
| --- | --- |
| Employee is not registered under the company | `Employee not found` |
| `new_destination` equals the destination on file | `Destination address is already on file` |
| `new_destination` is the zero address | `Cannot set zero address as payout destination` |
| A review for the employee is already `Pending` | `A payout destination change is already under review` |
| Review does not exist for the employee | `No payout destination change under review` |
| Review is already resolved | `Payout destination change is not pending review` |
| Caller is not the company admin (review path) | `Unauthorized: caller is not the company admin` |
| Company admin is revoked | `Company admin is revoked` |
| Contract is paused | `Contract is paused` |

`get_payout_dest_review` is read-only and returns the lifecycle record only — no
salary values, commitments, or payment history. `current_destination` defaults
to the employee address when no explicit destination has been stored, matching
`get_payout_destination`.

## Notes

- Company IDs are allocated sequentially and persisted with `DataKey::CompanySequence`.
- Duplicate company registration for the same admin address is rejected with `"Company already registered"`.
- Admin-gated methods load `CompanyInfo` via `DataKey::Company(company_id)` and call
  `info.admin.require_auth()` before mutating employee state.

## Emitted Events

| Event | Trigger |
|-------|---------|
| `CompanyRegistered` | `register_company` |
| `EmployeeAdded` | `add_employee` |
| `EmployeeRemoved` | `remove_employee` |
| `CommitmentUpdated` | `update_commitment` |
| `EmployeeActivated` | `set_employee_status(..., EmployeeStatus::Active)` |
| `EmployeeSuspended` | `set_employee_status(..., EmployeeStatus::Suspended)` |
| `EmployeeOffboarded` | `set_employee_status(..., EmployeeStatus::Offboarded)` |
| `EmployeeReactivated` | `set_employee_status(..., EmployeeStatus::Active)` |
| `EmployeeStatusUpdated` | `set_employee_status(..., EmployeeStatus::Incomplete)` |
| `PayoutDestinationUpdated` | `update_payout_destination` and an approved `review_payout_dest_change` |
| `PayoutDestinationChangeProposed` | `propose_payout_dest_change` |
| `PayoutDestinationChangeReviewed` | `review_payout_dest_change` (data: `approve: bool`) |
| `PayoutDestinationChangeCancelled` | `cancel_payout_dest_change` |

