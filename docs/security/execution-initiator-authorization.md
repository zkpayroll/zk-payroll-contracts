# Contract Execution Initiator Authorization (Issue #620)

## Summary

A **contract execution initiator** is the address that triggers an on-chain
payroll execution. In `contracts/payroll` those entrypoints are:

| Entrypoint | Effect |
| --- | --- |
| `prepare_payroll_run` | Validates a batch and stores a `submitted` pending run. |
| `batch_process_payroll` | Executes a batch and stores a `reconciliation_required` run. |
| `batch_process_payroll_idempotent` | Idempotent wrapper around `batch_process_payroll`. |
| `batch_process_payroll_bounded` | Checkpointed/resumable execution of a batch. |

Before this change every entrypoint performed `ContractAddresses::admin.require_auth()`
somewhere in the middle of its body — after unrelated validation (array-shape
checks, accumulator math, treasury/allowlist lookups) had already run — and the
contract offered no way for a client to ask up front whether an address would be
accepted as an initiator.

This feature centralizes that decision in one place
(`contracts/payroll/src/execution_authorization.rs`), so that:

1. every execution path shares the same authorization check,
2. an unauthorized initiator fails **fast** with an actionable error, and
3. SDKs and dashboards can **preflight** the answer without spending a transaction.

## Rules

- The only address authorized to initiate a contract execution is the payroll
  **admin** recorded by `initialize` and updated by the admin rotation/handover
  flows (`accept_admin_rotation`, `accept_admin_handover`).
- The admin address is compared against the stored address book **before**
  `require_auth()` is called, so an unauthorized caller is rejected
  deterministically instead of relying on the host signature check alone. This
  mirrors the pattern used by the reviewer and rotation entrypoints.
- The check runs before any other validation, so unauthorized callers cannot
  consume nonces, reserve funds, or probe validation behavior.
- Authorization is evaluated at call time; rotating the admin immediately moves
  initiator authority to the new admin and removes it from the previous one.
- No salary amounts, employee identities, or proof material are read, emitted,
  or returned by any of these calls.

## Contract surface

All functions live in `contracts/payroll/src/lib.rs`.

| Function | Auth | Purpose |
| --- | --- | --- |
| `get_execution_initiator()` | none | Returns the address currently authorized to initiate a contract execution (`Some(admin)`), or `None` before `initialize`. |
| `check_execution_initiator(initiator)` | none | Read-only authorization snapshot for an address: `{ initiator, authorized, role, initialized }`. |
| `is_exec_initiator_authorized(initiator)` | none | Boolean convenience wrapper for `check_execution_initiator`. |
| `validate_execution_initiator(initiator)` | `initiator` | Rejects the call unless `initiator` is the registered admin, requiring its cryptographic authorization. Use this to assert the role on-chain as a precondition of a larger flow. |

The read-only status shape (privacy-safe by construction):

```rust
pub struct ExecutionInitiatorAuthorization {
    pub initiator: Address,
    pub authorized: bool,
    pub role: ExecutionInitiatorRole, // Authorized | Unauthorized
    pub initialized: bool,
}
```

## Errors

Failures are actionable panics. The message states the cause and the required
remediation; no payroll values are included.

| Message | Cause | Remediation |
| --- | --- | --- |
| `Unauthorized contract execution initiator: only the registered payroll admin may initiate a contract execution` | The supplied/acting address is not the registered admin. | Re-sign with the admin address, or rotate the admin first. |
| `Contract not initialized: configure the payroll address book before validating an execution initiator` | The contract has not been initialized, or the address book is missing. | Call `initialize` before any execution or initiator validation. |
| `Not initialized: contract addresses must be configured before a payroll execution` | An execution entrypoint was called before `initialize`. | Call `initialize` first. |

## Integrator guidance

- Before submitting an execution, call `check_execution_initiator(me)` (or
  `is_exec_initiator_authorized(me)`) to confirm the initiator role and show
  a clear message in the UI without paying for a reverted transaction.
- `validate_execution_initiator` is useful when the authorization step must be
  recorded on-chain as a precondition of a larger workflow; it does not change
  state.
- A `false` verdict with `initialized == true` means "not the admin"; a `false`
  verdict with `initialized == false` means "the contract is not configured yet".
  These are distinct operational states and should be surfaced differently.

## Testing coverage

Focused coverage lives in
`contracts/payroll/tests/execution_initiator_authorization.rs`:

- The registered admin is reported as the authorized initiator.
- A non-admin address is reported as unauthorized (`role == Unauthorized`).
- An uninitialized contract reports `initialized == false` and `None` for the
  initiator.
- The read-only preflight succeeds with no signatures present.
- `validate_execution_initiator` accepts the admin and rejects a non-admin, and
  panics with the initialization error before `initialize`.
- `batch_process_payroll`, `batch_process_payroll_bounded`, and
  `prepare_payroll_run` all reject calls with no initiator authorization.
- Admin rotation moves initiator authority to the new admin and revokes it from
  the previous one.
