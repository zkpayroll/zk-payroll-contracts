# Employee Activation Prerequisites

## Overview

Employee activation prerequisite checks ensure that employees can only be activated (transitioned to `Active` status) when all necessary conditions are met. This safeguards payroll correctness and prevents activation of incomplete employee records.

## Why This Matters

Before an employee becomes eligible for payroll inclusion, the system must verify:

- **Commitment integrity**: Employee commitment is registered and valid
- **Record completeness**: All required fields are present
- **State consistency**: Employee lifecycle state is valid for activation
- **Privacy**: Errors don't expose sensitive payroll or salary data

## Employee Status Lifecycle

```
[Onboarded]
    ↓
[Active] ← Can receive payroll
    ↕
[Suspended] ← Temporarily ineligible (e.g., leave)
    ↕
[Incomplete] ← Missing prerequisites
    ↓
[Offboarded] ← Terminal state (cannot change)
```

## Activation Prerequisites

### When Transitioning to Active Status

Before an employee can be activated, the following checks run:

1. **Commitment Registration**: Employee must have a registered commitment
   - Verified via storage: `DataKey::Employee(company_id, employee)`
   - Error if missing: "Employee commitment not found: cannot activate without commitment registration"

2. **No Offboarded Status**: Cannot reactivate an offboarded employee
   - Already enforced by existing guard
   - Error: "Offboarded employee status cannot be changed"

### When NOT Validating

- **Suspending an employee**: No validation required
- **Marking Incomplete**: No validation required
- **Re-activating from Active**: No re-validation (idempotent)

## Implementation Details

### Integration Point

Validation occurs in `set_employee_status` function in `payroll_registry/src/lib.rs`:

```rust
// Guard: only validate when transitioning TO Active
if status == EmployeeStatus::Active && previous_status != EmployeeStatus::Active {
    Self::validate_activation_prereqs(&env, company_id, &employee);
}
```

### Validation Function

```rust
fn validate_activation_prereqs(env: &Env, company_id: u64, employee: &Address) {
    // Verify commitment exists and is retrievable
    if !env.storage().persistent().has(&DataKey::Employee(company_id, employee.clone())) {
        panic!("Employee commitment not found: cannot activate without commitment registration");
    }
}
```

## Usage Examples

### Example 1: Activate Already-Active Employee (Idempotent)

```rust
// First activation (happens at onboarding)
client.add_employee(&company_id, &employee, &commitment);
// Status is now Active

// Attempting to activate again is a no-op (prerequisite check skipped)
client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
// Still Active, no errors
```

### Example 2: Suspend Then Reactivate

```rust
// Employee is Active
client.set_employee_status(&company_id, &employee, &EmployeeStatus::Suspended);
// Now ineligible for payroll

// Reactivate (prerequisite validation runs and passes)
client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
// Now eligible again
```

### Example 3: Incomplete to Active

```rust
// Employee is in Incomplete state (missing prerequisites)
let status = client.get_employee_status(&company_id, &employee);
// Returns: EmployeeStatus::Incomplete

// Attempt activation (prerequisite check runs)
client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
// If commitment exists, activation succeeds
// If commitment missing, panics with actionable error
```

## Error Handling

### Privacy-Safe Errors

All error messages are designed to not expose sensitive information:

```
✅ PRIVACY-SAFE: "Employee commitment not found: cannot activate without commitment registration"

❌ EXPOSE: "Cannot activate employee 0xABC123 with commitment 0xDEF456"
❌ EXPOSE: "Employee earned $50,000 and cannot be activated yet"
❌ EXPOSE: "Employee has participated in 2 prior payroll runs"
```

### Error Messages by Scenario

| Scenario | Error Message |
|----------|---------------|
| Commitment missing | "Employee commitment not found: cannot activate without commitment registration" |
| Employee not found | "Employee not found" |
| Offboarded employee | "Offboarded employee status cannot be changed" |
| Company admin revoked | "Company admin is revoked" |
| Company paused | "System is paused" |

## Validation Rules

### When Validation Runs

- ✓ Activating from Suspended
- ✓ Activating from Incomplete
- ✓ Reactivating after suspension
- ✗ Suspending (no validation)
- ✗ Marking Incomplete (no validation)
- ✗ Re-activating when already Active (no re-validation)

### Idempotency

Setting status to `Active` when already `Active` is a no-op:

```rust
// First call: Active
client.add_employee(&company_id, &employee, &commitment);

// Second call: still Active, validation skipped, no-op
client.set_employee_status(&company_id, &employee, &EmployeeStatus::Active);
```

## State Transitions

### Valid Transitions

```
Active → Suspended (allowed, no validation)
Suspended → Active (allowed, prerequisite check runs)
Active → Incomplete (allowed, no validation)
Incomplete → Active (allowed, prerequisite check runs)
Any → Offboarded (allowed, terminal state)
```

### Invalid Transitions

```
Offboarded → [Any] (blocked, terminal state)
```

## Test Coverage

The test suite validates:

- ✓ Basic activation with commitment
- ✓ Reactivation from suspended
- ✓ Missing commitment error
- ✓ Idempotent reactivation
- ✓ Suspend-reactivate cycles
- ✓ Multiple employees independent
- ✓ Nonexistent employee rejection
- ✓ Offboarded employee rejection
- ✓ Error message privacy
- ✓ Valid status transitions
- ✓ Validation guard (only on transition)

Run tests:
```bash
cargo test -p payroll_registry employee_activation_prerequisites
```

## Compatibility

- **Backward compatible**: Existing workflows unaffected
- **Non-breaking**: Validation is additive, doesn't change behavior for valid states
- **Idempotent**: Re-activating Active employees is safe

## Integration with Payroll

### Payroll Eligibility Check

The `is_eligible` function uses employee status:

```rust
pub fn is_eligible(env: Env, company_id: u64, employee: Address) -> bool {
    Self::is_employee_active(env, company_id, employee)
}

fn is_employee_active(env: Env, company_id: u64, employee: Address) -> bool {
    let status = env.storage().persistent().get(&DataKey::EmpStatus(company_id, employee))
        .unwrap_or(EmployeeStatus::Incomplete);
    status == EmployeeStatus::Active
}
```

**Only Active employees are eligible for payroll inclusion.**

## Related Features

- **Employee Onboarding** (`add_employee`): Creates employee with Active status
- **Employee Status Management** (`set_employee_status`): Manages lifecycle transitions
- **Eligibility Check** (`is_eligible`): Determines payroll inclusion
- **Status Query** (`get_employee_status`): Reads current status

## API Reference

### `set_employee_status`

```rust
pub fn set_employee_status(
    env: Env,
    company_id: u64,
    employee: Address,
    status: EmployeeStatus,
)
```

**Behavior when setting to `Active`**:
1. Validates employee exists
2. Checks not Offboarded
3. **Validates activation prerequisites** (if transitioning to Active)
4. Updates status and emits events

**Authorization**: Requires company admin authentication

### `validate_activation_prereqs`

Internal function that checks:
- Employee commitment is registered in the registry
- Employee can be safely activated

**Called by**: `set_employee_status` when transitioning to Active

**Panics if**: Commitment is not registered

## Troubleshooting

### "Employee commitment not found: cannot activate without commitment registration"

**Cause**: Employee was created without a commitment or commitment was lost.

**Solution**:
1. Verify employee was added via `add_employee` with a commitment
2. Check commitment is still registered in the commitment contract
3. If commitment is missing, offboard the employee and re-add with new commitment

### "Employee not found"

**Cause**: Attempting to activate employee that doesn't exist in the company.

**Solution**:
1. Verify company_id is correct
2. Verify employee was added to the company
3. Check employee is not in a different company

### "Offboarded employee status cannot be changed"

**Cause**: Attempting to change status of an offboarded employee.

**Solution**:
1. Offboarded status is terminal and cannot be changed
2. If employee should be reactivated, they must be re-added via `add_employee`
3. This creates a new record with a fresh status

## Security Considerations

1. **Admin-only**: Only company admin can change employee status
2. **Prerequisite validation**: Prevents activation of incomplete records
3. **Idempotent**: Re-activation doesn't expose information
4. **Privacy**: Error messages never contain payroll details
5. **Terminal states**: Offboarded status cannot be changed once set
