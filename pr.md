# [Security] Contract validation fixes for employee wallet format, deactivation, cancellation, and treasury asset mapping

## Summary

Resolves four critical security and validation issues: employee wallet format validation (#220), employee deactivation and payroll access revocation (#61), cancel-after-submit behavior checks (#218), and treasury asset mapping validation (#217).

## Changes

**fix(#220)** — `contracts/payroll_registry/src/lib.rs`
Added wallet format validation in `add_employee()` function. Employee addresses are now validated before being accepted into contract state to prevent invalid wallet data from causing later payroll errors.

**fix(#61)** — `contracts/payroll/src/lib.rs` and `contracts/payroll/Cargo.toml`
Integrated employee deactivation checks into payroll execution. Added `payroll_registry` dependency and implemented eligibility verification in `batch_process_payroll()` to ensure deactivated employees cannot receive payments. The existing `EmployeeStatus` enum (Active/Inactive/Incomplete) is now properly enforced during payroll runs.

**fix(#218)** — `contracts/payroll/src/lib.rs`
Enhanced `cancel_payroll_run()` with explicit validation that run is still pending. Added check to prevent cancellation of already-executed runs, ensuring proper state cleanup and preventing cancel-after-submit race conditions.

**fix(#217)** — `contracts/payment_executor/src/lib.rs`
Extended treasury asset mapping validation in `execute_payment()`. Now validates that both token contract address and treasury address are properly formatted and match expected types. Builds on existing `is_asset_allowed()` check to comprehensively validate treasury asset mappings match supported payroll assets.

## Testing

The changes integrate with existing contract infrastructure and follow established patterns:
- Employee wallet validation uses the same format checks as other address validations
- Employee deactivation leverages the existing `EmployeeStatus` infrastructure already tested in `payroll_registry`
- Cancellation checks build on existing `PendingPayrollRun` and `PayrollRun` storage patterns
- Treasury validation extends the existing `AllowedAsset` allowlist feature

```bash
cargo fmt -- --check
cargo check --all-targets
cargo test -p payroll_registry -p payment_executor -p payroll
```

## Closes

Closes #220
Closes #61
Closes #218
Closes #217

