# Payroll Import Source Validation

## Overview

Import source validation ensures that payroll batches come from authorized, known sources. This prevents accidental or malicious imports from unauthorized origins while maintaining privacy by not exposing sensitive payroll or employee data in error messages.

## Integration Points

### 1. Source Registration

Only the payroll admin can register new import sources:

```rust
payroll.register_import_source(&source_address, &source_type);
```

Supported source types:
- `0`: ExternalService — External API endpoints or services
- `1`: InternalSource — Admin-designated internal sources
- `2`: VerificationService — Batch verification services

### 2. Source Authorization Check

Check if a source is currently authorized before submitting:

```rust
let is_authorized = payroll.is_import_source_authorized(&source_address);
```

### 3. Batch Processing

Payroll batches now require a `source_address` parameter:

```rust
payroll.batch_process_payroll(
    &proofs,
    &amounts,
    &employees,
    &expected_total_spend,
    &nonce,
    &draft_hash,
    &source_address  // NEW: must be authorized
);
```

The source is validated early in the execution flow, before any other work:
- **Authorization check happens first** — unauthorized sources fail immediately
- **Error messages are privacy-safe** — no payroll or authorized source details exposed
- **Deactivated sources are rejected** — deactivated sources cannot submit new batches

### 4. Source Deactivation

Deactivate a source without removing its record:

```rust
payroll.deactivate_import_source(&source_address);
```

Deactivated sources:
- Cannot submit new payroll batches
- Historical records remain for audit purposes
- Can be re-activated by re-registering

### 5. Dry-Run Validation

The dry-run preflight now validates import sources:

```rust
let args = DryRunArgs {
    // ... other fields ...
    source_address: Some(source),
};
let report = payroll.dry_run_batch_process_payroll(&args);
```

If the source is unauthorized, the report will include `UnauthorizedImportSource` in the blockers list.

## Error Handling

### Privacy Guarantees

- **No source exposure**: Error messages never list which sources are authorized
- **No payroll data**: Errors don't include salary amounts or employee identities
- **Generic feedback**: All authorization failures use the same privacy-safe message

### Failure Modes

1. **Unregistered source** → `UnauthorizedImportSource`
2. **Deactivated source** → `UnauthorizedImportSource`
3. **No source provided** (optional field is None) → Skipped in mandatory checks

## Operational Workflow

### Initial Setup

```rust
// Admin initializes contract
payroll.initialize(...);

// Admin registers authorized sources
payroll.register_import_source(&internal_api, &1);      // InternalSource
payroll.register_import_source(&external_service, &0);  // ExternalService
```

### Normal Operation

```rust
// External service submits payroll
payroll.batch_process_payroll(
    &proofs,
    &amounts,
    &employees,
    &expected_total_spend,
    &nonce,
    &draft_hash,
    &external_service  // validated here
);
```

### Incident Response

```rust
// If source is compromised, deactivate it
payroll.deactivate_import_source(&compromised_source);

// Source can be re-registered if needed
payroll.register_import_source(&new_source, &0);
```

## Testing

Integration tests cover:
- ✓ Authorized sources accept batches
- ✓ Unauthorized sources reject batches
- ✓ Deactivated sources reject batches
- ✓ Source authorization checks work correctly
- ✓ Dry-run reports source validation failures

Run tests:
```bash
cargo test -p payroll import_source
```

## Security Considerations

1. **Early validation** — Source is checked before any proof verification or transfers
2. **No bypass paths** — All batch processing entrypoints require source validation
3. **Privacy-safe** — Error paths never expose which sources are authorized
4. **Admin-controlled** — Only the payroll admin can register or deactivate sources
5. **Audit trail** — Source records persist for compliance and forensics

## Compatibility

- Existing workflows continue working (backward compatible via optional source field)
- Dry-run reports include source validation status
- Error messages remain consistent with existing failure modes
