# ZK Payroll Contracts

Privacy-first payroll smart contracts for Stellar/Soroban using zero-knowledge proofs.

## Overview

ZK Payroll Contracts enable companies to process payroll on-chain while keeping salary amounts private. Using Stellar's Protocol X-Ray ZK primitives (BN254, Poseidon), employers can prove payments were made without revealing exact amounts.

## Features

- **Private Salary Commitments** — Salary amounts stored as ZK commitments
- **Proof-Based Payments** — Verify payments without exposing values
- **Employee Identifier Normalization** — Canonical trimming, ASCII uppercasing, and validation for safe HR reference lookups and collision prevention
- **Commitment Rotation Controls** — Approved (locked) salary commitments can be rotated in place after a payroll settles, without invalidating the settled record and without an unlock window
- **Batch Payroll** — Process multiple employees in single transaction
- **Period Freeze Guard** — Finalized payroll periods are locked against further edits, with an admin-controlled unfreeze path for authorized corrections
- **Run Expiration** — Prepared-but-unfinalized payroll runs can expire after a configurable window, releasing reserved funds and stopping stale submissions
- **Draft Lock Owner Query** — Query the lock holder for finalized drafts without exposing private employee counts or amounts
- **Execution Initiator Authorization** — Every payroll preparation/execution path validates that its initiator is the registered admin, with a read-only preflight for SDKs and dashboards
- **Duplicate Execution Guard** — Payroll runs cannot be executed twice; a second execution attempt fails with an actionable error without exposing salary or employee values
- **Compliance Ready** — Selective disclosure for audits via view keys
- **On-Chain Verification** — Groth16 proof verification on Soroban

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ZK Payroll System                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   Payroll   │    │   Salary    │    │    Proof    │ │
│  │  Registry   │───▶│ Commitment  │───▶│  Verifier   │ │
│  └─────────────┘    └─────────────┘    └─────────────┘ │
│         │                  │                  │        │
│         ▼                  ▼                  ▼        │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │  Employee   │    │   Payment   │    │   Audit     │ │
│  │  Registry   │    │   Executor  │    │   Module    │ │
│  └─────────────┘    └─────────────┘    └─────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Contracts

| Contract | Description |
|----------|-------------|
| `payroll_registry` | Company registration, employee management |
| `salary_commitment` | ZK commitment storage and updates |
| `proof_verifier` | Groth16 proof verification using BN254 |
| `payment_executor` | Private payment execution |
| `audit_module` | Selective disclosure for compliance |

> **Period lifecycle:** finalized payroll periods are protected by a freeze
> guard (#471) — see [docs/period-freeze-guard.md](docs/period-freeze-guard.md)
> for what is blocked, the escape hatches, and the authorized correction flow.
>
> **Run lifecycle:** prepared-but-unfinalized runs can expire (#474) — see
> [docs/run-expiration.md](docs/run-expiration.md) for the expiry policy, the
> permissionless expiry flow, and SDK guidance.
>
> **Commitment lifecycle:** an approved or settled commitment can be rotated
> with `rotate_approved_commitment` without dropping its lock (#520) — see
> [contracts/README.md](contracts/README.md#commitment-rotation-controls-salary_commitment--issue-520).
>
> **Duplicate execution guard:** a payroll run can only be executed once. A
> repeated execution attempt is rejected with an actionable error and never
> exposes salary, employee, or commitment values.

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|-----------------|---------|
| [Rust](https://rustup.rs/) | 1.74+ | Contract development and testing |
| [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup) | v21+ | Contract deployment |
| [Stellar CLI](https://developers.stellar.org/docs/tools/stellar-cli) | v21+ | Network interaction |
| [Node.js](https://nodejs.org/) | 18+ | Required by snarkjs and circom WASM output |
| [Circom](https://docs.circom.io/getting-started/installation/) | 2.1+ | ZK circuit compilation |

## Installation

```bash
# Clone the repository
git clone https://github.com/zkpayroll/zk-payroll-contracts.git
cd zk-payroll-contracts

# Install dependencies
cargo build

# Run tests
cargo test
```

## Quick Start

### 1. Build Contracts

```bash
stellar contract build
```

### 2. Deploy to Testnet

```bash
# Deploy payroll registry
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/payroll_registry.wasm \
  --network testnet \
  --source alice
```

### 3. Initialize Company

```rust
// Register a company
payroll_registry.register_company(
    company_id,
    admin_address,
    treasury_address
);
```

## Usage

### Versioned Admin Configuration Updates

The payroll registry now tracks configuration revisions so off-chain clients can detect changes reliably. Each company maintains a version counter that increments whenever admin or treasury configuration changes.

```rust
// Get current admin configuration version
let version = payroll_registry.get_admin_config_version(company_id);
// Returns: AdminConfigVersion { version: u64, updated_at: u64, updated_by: Address }

// The version automatically increments on admin/treasury rotations
payroll_registry.propose_admin_rotation(company_id, current_admin, new_admin);
payroll_registry.accept_admin_rotation(company_id, new_admin);
// Version now incremented to previous_version + 1
```

**Key Guarantees:**
- **Version Tracking**: Each company starts at version 1 when registered
- **Automatic Incrementing**: Version increments on admin or treasury rotation acceptance
- **Change Detection**: Off-chain clients can poll the version to detect configuration changes
- **Event Emission**: `AdminConfigVersionUpdated` events are emitted for reliable change notification
- **Backward Compatible**: Existing operations continue to work without changes

### Payroll Configuration Audit Events

Every successful configuration change on the `payroll` contract publishes one
`("payroll", "config_changed", key)` event and bumps a contract-wide revision
(#490). This covers admin and treasury-owner handoffs, pause manager, asset
allowlist, company state, capacity limits, settlement windows, period freezes,
retention policy, reviewers, dispute authorities, reservation expiry, payroll
currency, and storage version.

```rust
// data = (actor, subject_ref, previous_ref, new_ref, revision, ledger_sequence, timestamp)
payroll.set_capacity_limits(&admin, &10, &100, &1_000_000);
let revision = payroll.get_config_revision(); // 1, 2, 3, ... with no gaps
```

- **Actor:** the address whose authorization the change required (checked
  against the stored role).
- **Value references:** `sha256` of each value's canonical XDR; 32 zero bytes
  mean "no value". Consecutive changes chain (`previous_ref` = prior
  `new_ref`).
- **Privacy:** configuration values are never emitted in plaintext, and no
  salary, employee, or commitment data is involved.
- **No-op / failed changes:** no audit event and no revision bump.

See [docs/config-audit-events.md](docs/config-audit-events.md) for the schema,
key table, and how to verify a reference.

### Payroll Period Health Summary

The `payroll` contract exposes `get_period_health_summary` to provide operators and monitoring dashboards with actionable operational readiness diagnostics without leaking private employee identities or individual salary information (#552).

```rust
let summary = payroll.get_period_health_summary(&period);
// summary.status: PeriodHealthStatus (Healthy, Warning, Blocked)
// summary.reason: PeriodHealthReason (Normal, PreOpen, GracePeriod, WindowClosed, ContractPaused, PeriodFrozen, ...)
// summary.can_execute: bool
// summary.is_frozen: bool
// summary.is_paused: bool
// summary.window_status: Option<SettlementWindowStatus>
// summary.capacity_configured: bool
// summary.batch_count: u32
// summary.employee_count: u32
// summary.capacity_exceeded: bool
```

- **Operational Health**: Classifies periods into `Healthy` (ready for execution), `Warning` (grace period, frozen configuration), or `Blocked` (paused, closed window, capacity exhausted).
- **Actionable Diagnostics**: Clear, typed reason codes indicate exact blockers or operational alerts (e.g., `PreOpen`, `ContractPaused`, `BatchCapacityExceeded`).
- **Privacy Guarantees**: Plaintext salaries, employee commitments, and individual recipient rows are never exposed.

### Register Employee with Private Salary

```rust
// Create salary commitment (off-chain)
let commitment = poseidon_hash(salary_amount, blinding_factor);

// Register employee with commitment
payroll_registry.add_employee(
    company_id,
    employee_address,
    salary_commitment
);
```

### Employer Access Revocation

An authorized company admin may revoke the company's employer/admin authorization without deleting the company record or historical payroll state. Revocation marks the company as revoked in the canonical registry state, removes the active employer mapping, and blocks subsequent employer-only actions such as employee onboarding, employee status updates, and payroll-period setup for that company.

Existing payroll history remains intact; only the employer authorization is lifted. A revoked employer cannot call employer-only entrypoints until the canonical role state is restored through the repository's existing admin/rotation flows.

### Approval Withdrawal and Supersession

Payroll run approvals recorded by authorized reviewers are fully auditable
through their full lifecycle (#522). A reviewer who granted the active
approval may withdraw it with a mandatory, non-empty reason; the stored review
transitions to a `Withdrawn` decision so expiry validation (#403) and approval
consumers no longer treat the run as approved. A different authorized reviewer
can supersede an existing approval, re-pointing the approval at themselves and
restarting the #403 expiry window. Every withdrawal and supersession emits a
privacy-safe `payroll` event (`run_approval_withdrawn` /
`run_approval_superseded`) carrying only the run id, reviewer addresses, and a
short reason symbol — never salary values or employee data.

### Process Private Payroll

```rust
// Generate proof (off-chain)
let proof = generate_payment_proof(
    salary_amount,
    blinding_factor,
    recipient
);

// Execute payment with proof
payment_executor.process_payment(
    company_id,
    employee_address,
    proof
);
```

### Payroll Approval Threshold

Employers can require a configurable number of distinct reviewers to approve a
prepared payroll run before it executes. The policy is opt-in: without it,
`finalize_payroll_run` behaves exactly as before.

```rust
// Admin: require 2 of the authorized reviewers (needs >= 2 reviewers, max 10).
payroll.set_approval_threshold(&admin, &2);

let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &total, &nonce, &None);
payroll.approve_payroll_run(&reviewer_a, &run_id);
payroll.approve_payroll_run(&reviewer_b, &run_id);

// progress.required == 2, progress.approved == 2, progress.threshold_met == true
let progress = payroll.get_approval_progress(&run_id);
payroll.finalize_payroll_run(&admin, &run_id);
```

- **Counted approvals**: one per reviewer; an approval stops counting when it
  expires (`DEFAULT_APPROVAL_EXPIRY_SECONDS`) or its reviewer is removed.
- **Objections reset the quorum**: `reject_payroll_run` and
  `request_changes_payroll_run` clear all recorded approvals for the run.
- **Withdrawal and supersession**: `withdraw_approval` removes only the
  withdrawing reviewer's approval; `supersede_approval` moves the approval to
  the superseding reviewer (who must not already have approved).
- **Direct execution is disabled** while a threshold is set:
  `batch_process_payroll*` and `batch_process_with_expiry` fail and the dry-run reports
  `ApprovalWorkflowRequired`. Use prepare → approve → finalize instead.
- **Locked during in-flight runs**: the threshold cannot be changed or cleared
  (`clear_approval_threshold`) while any run is pending.
- **Privacy**: failures report only approval counts, never amounts or employees.

See [docs/security/reviewer-authorization.md](docs/security/reviewer-authorization.md#24-payroll-approval-threshold)
for the full rules and failure messages.

### Employee Payout Destination Updates

Employees can securely manage and update their payment receiving addresses:

```rust
// Update payout destination (requires employee authorization)
payroll_registry.update_payout_destination(
    company_id,
    employee_address,
    new_destination_address
);

// Update payout destination using wallet string (validates format/checksum)
payroll_registry.update_payout_destination_wallet(
    company_id,
    employee_address,
    wallet_string
);

// Retrieve current payout destination (defaults to employee address if unset)
let destination = payroll_registry.get_payout_destination(company_id, employee_address);
```

**Key Guarantees:**
- **Authorization**: Only the employee (`employee.require_auth()`) can modify their own destination.
- **Validations**: Rejects zero-address (`GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF`), existing duplicate destination on file, or invalid Stellar wallet formatting.
- **Isolation**: Pending/in-flight payroll runs retain their original snapshot parameters, isolating existing runs from destination updates.

### Bounded Batch Payroll Processing

Process large employee pools across multiple bounded transactions:

```rust
// Process a bounded batch (up to 50 employees per batch)
let processed_count = payroll.batch_process_payroll_bounded(
    company_id,
    run_id,
    batch_size // Max 50
);
```

**Key Guarantees:**
- **Hard Cap**: Strictly limits `batch_size <= 50` to prevent gas exhaustion and block limit failures.
- **Progress Tracking**: Tracks `BatchCheckpoint` state (`processed_count` out of `total_count`). Resumption starts at `last_processed_index` without double payments.
- **Halt-on-Error**: Halts and rolls back state atomically if any single employee payment or proof fails.
- **Authorization**: Requires operator/admin authorization (`admin.require_auth()`). Rejects empty batch parameters.

For a failed bounded payout checkpoint, first call
`is_failed_payout_retry_eligible` with the original batch identity and payment
count. If it returns `true`, the admin can call `resume_failed_payout_retry`
with the saved checkpoint index, then retry the same batch with the same nonce.
Completed checkpoints and checkpoints with no remaining payments are rejected.
The eligibility check returns only a boolean and does not reveal employee or
salary values. See [Payroll Run State Machine](docs/payroll-state-machine.md)
for the recovery steps.

#### Resuming a halted batch (issue #611)

When a bounded batch halts, the checkpoint is left in the `Failed` state and
further batches for the same run are rejected with a message naming
`resume_payroll_batch`. Inspect the checkpoint before acting on it:

```rust
let plan = payroll.get_batch_resume_plan(
    company_id,
    batch_root,
    asset,
    execution_nonce,
    expected_total,
);
// plan.status      -> NotFound | Resumable | FailedRetryable | Completed
// plan.can_resume  -> true only when a partial, non-failed checkpoint exists
// plan.remaining_count
// plan.cursor_consistent
```

Then, as admin, clear the failure and continue from the recorded cursor:

```rust
payroll.resume_payroll_batch(
    admin,
    employer,
    batch_root,
    asset,
    execution_nonce,
    expected_total,
);
```

`get_batch_resume_plan` is read-only and returns aggregate progress only — no
employee addresses, amounts, or salary values. It reports `NotFound` when the
batch identity is unknown or when `expected_total` is `0` or above the 50-employee
cap, so an operator cannot use it to probe for payroll sizes outside the bounds
the contract accepts. Resuming sets the checkpoint back to `Resumed`, clears the
recorded failure, and emits `batch_checkpoint_resumed`; the next
`batch_process_payroll_bounded` call continues at the stored index without
re-paying the already processed employees. Resuming an already completed batch
panics with an actionable message rather than silently re-running payments.

### Compliance Audit

```rust
// Generate view key for auditor
let view_key = audit_module.generate_view_key(
    company_id,
    auditor_address,
    time_range
);

// Auditor verifies with selective disclosure
audit_module.verify_with_view_key(view_key, proof);
```

## Project Structure

```
zk-payroll-contracts/
├── contracts/
│   ├── payroll_registry/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── company.rs
│   │   │   └── employee.rs
│   │   └── Cargo.toml
│   ├── salary_commitment/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   └── commitment.rs
│   │   └── Cargo.toml
│   ├── proof_verifier/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── groth16.rs
│   │   │   └── bn254.rs
│   │   └── Cargo.toml
│   ├── payment_executor/
│   │   └── ...
│   └── audit_module/
│       └── ...
├── circuits/
│   ├── payment.circom
│   └── range_proof.circom
├── scripts/
│   ├── deploy.sh
│   └── generate_proof.sh
├── tests/
│   └── integration_tests.rs
├── Cargo.toml
└── README.md
```

## Cryptographic Primitives

This project leverages Stellar's Protocol X-Ray (Protocol 25) primitives:

- **BN254** — Elliptic curve for Groth16 proof verification
- **Poseidon** — ZK-friendly hash function for commitments
- **Groth16** — Succinct proof system for payment verification

## Security

- All salary amounts are stored as Poseidon hash commitments
- Payments verified via Groth16 proofs without revealing amounts
- View keys enable selective disclosure for compliance
- No salary data exposed on public ledger

## Roadmap

- [x] Core contract architecture
- [ ] Payroll registry implementation
- [ ] Salary commitment contract
- [ ] Groth16 verifier integration
- [ ] Payment executor
- [ ] Audit module with view keys
- [ ] Batch payment optimization
- [ ] Multi-currency support

## SDK Contract Interface

See [docs/sdk-contract-interface.md](docs/sdk-contract-interface.md) for a
flow-oriented guide covering company setup, employee onboarding, payroll
execution, and audit access — with sample payloads and input/output tables.

## Events

See [docs/events.md](docs/events.md) for the full event schema reference and
consumption expectations.

## Clock Boundary Testing

The contracts include comprehensive clock boundary tests to ensure timestamp-based cutoff mechanisms work correctly at exact boundaries and adjacent edge cases. These tests improve reliability of time-sensitive payroll operations:

### Boundary Test Coverage

- **Settlement Window Enforcement** (`contracts/payroll/tests/settlement_window_enforcement.rs`)
  - Exact boundary tests for `open_at`, `execution_start`, `execution_end`, and `close_at` timestamps
  - Adjacent boundary cases (one tick before/after each cutoff)
  - Mid-period and mid-grace period validations
  - Grace period cancellation and expiration at boundaries

- **Approval Expiry** (`contracts/payroll/tests/approval_expiry.rs`)
  - Exact expiry boundary validation
  - One tick before/after expiry cases
  - Custom expiry period boundaries
  - Multiple approvals with different timestamps

- **Threshold Rotation Grace Periods** (`contracts/payroll_registry/tests/threshold_rotation_boundary_tests.rs`)
  - Exact grace period boundary activation
  - Adjacent timestamp validation for rotation proposals
  - Zero grace period edge cases
  - Cancellation before/after grace period boundaries

- **Reservation Expiry** (`contracts/payroll/tests/reservation_expiry_boundary_tests.rs`)
  - Exact expiry boundary release operations
  - One tick before/after expiry validation
  - Zero and large expiry offset edge cases
  - Multiple reservations with different expiry times

### Running Boundary Tests

```bash
# Run all boundary tests
cargo test --test settlement_window_enforcement
cargo test --test approval_expiry
cargo test --test threshold_rotation_boundary_tests
cargo test --test reservation_expiry_boundary_tests
```

These boundary tests ensure that payroll cutoffs work reliably at exact timestamps and prevent edge case failures in production.

## Local Setup & Test Troubleshooting

See [contracts/README.md](contracts/README.md) for **environment variables**, local test setup expectations, and a quick manual verification checklist.

See [contracts/tests/README.md](contracts/tests/README.md) for common local setup issues, test panics, missing WASM fixture errors, and ZK proof setup troubleshooting.

## Contract Error Handling

See [docs/errors.md](docs/errors.md) for common contract failure modes,
retryability guidance, and suggested SDK/dashboard recovery messages.

## Contract Upgrades

Before activating an upgraded contract implementation, validate that the data
already on chain is still compatible. `payment_executor` exposes a read-only,
admin-gated preflight that reports schema versions and readiness flags, and
fails with a typed storage error when an activation should be blocked. The
report never includes salaries, commitments, employee addresses, or amounts.

See [docs/upgrades.md](docs/upgrades.md#34-pre-activation-compatibility-check) for
the procedure and remediation table, and
[docs/architecture/storage-key-versioning.md](docs/architecture/storage-key-versioning.md)
for the versioning strategy.

## Deployment Verification Checklist

See [docs/deployment-verification.md](docs/deployment-verification.md) for a comprehensive checklist covering contract IDs, target network configuration, ZK verifier parameters, treasury setup, admin roles, and post-deploy smoke tests.


## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Good First Issues

Check out issues labeled `good-first-issue` and `stellar-wave` for contribution opportunities.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Stellar Development Foundation](https://stellar.org) — Protocol X-Ray ZK primitives
- [Nethermind](https://nethermind.io) — ZK tooling collaboration
