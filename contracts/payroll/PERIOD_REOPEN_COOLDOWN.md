# Payroll Period Reopen Cooldown

## Overview

The period reopen cooldown prevents rapid reopening of finalized payroll periods by enforcing a minimum time gap between successive reopens. This guards against accidental or malicious repeated unfreezes that could expose finalized periods to uncontrolled edits.

## Why This Matters

Once a payroll period is finalized and frozen, reopening should be an intentional, carefully considered action. A cooldown ensures:

- **Accident prevention**: Accidental double-clicks on reopen buttons won't immediately re-expose the period
- **Audit trail clarity**: Multiple rapid reopens could indicate a compromise or misconfiguration
- **Operational safety**: Teams have time to review and validate before allowing further edits
- **Privacy**: Error messages never expose sensitive payroll details

## Configuration

### Setting Cooldown Duration

Only the payroll admin can configure cooldowns:

```rust
// Set a 1-hour (3600-second) cooldown for a period
payroll.set_period_reopen_cooldown(&admin, &period, &3600u64);

// Disable cooldown (0 = no minimum delay)
payroll.set_period_reopen_cooldown(&admin, &period, &0u64);
```

### Querying Cooldown Status

Check the current cooldown configuration for a period:

```rust
let cooldown = payroll.get_period_reopen_cooldown(&period);
match cooldown {
    Some(config) => {
        println!("Cooldown: {} seconds", config.cooldown_seconds);
        println!("Last reopen: {}", config.last_reopen_at);
    }
    None => println!("No cooldown configured"),
}
```

## Workflow

### 1. Configure Cooldown (Admin)

```rust
// After contract initialization
payroll.set_period_reopen_cooldown(&admin, &Symbol::new("2024M01"), &3600u64);
```

### 2. Period Lifecycle with Cooldown

```
[Period Created]
    ↓
[Payroll Submitted] → [Period Frozen Automatically]
    ↓
[Period Finalized] → [Admin Can Reopen]
    ↓
[First Reopen] → [Cooldown Timer Starts]
    ↓
[Wait cooldown_seconds] → [Timer Expires]
    ↓
[Can Reopen Again]
```

### 3. Attempting Reopen During Cooldown

```rust
// This will panic if cooldown is active
payroll.reopen_payroll_period(&admin, &period);
// Error: "Period reopen cooldown active: cannot reopen until X seconds have elapsed"
```

### 4. Reopen After Cooldown Expires

```rust
// After sufficient time has passed
payroll.reopen_payroll_period(&admin, &period);  // Succeeds!
```

## Operational Examples

### Example 1: Enable Conservative Cooldown

```rust
// For high-value periods, enforce 24-hour reopen cooldown
let one_day_seconds = 24 * 60 * 60;
payroll.set_period_reopen_cooldown(&admin, &period, &one_day_seconds);
```

**Effect**: Period can only be reopened once per 24 hours, providing ample time for human review between changes.

### Example 2: Disable Cooldown for Dev Environments

```rust
// During development, rapid iteration is needed
payroll.set_period_reopen_cooldown(&admin, &period, &0u64);
```

**Effect**: No minimum delay between reopens. Period behaves as if no cooldown exists.

### Example 3: Multiple Periods with Different Cooldowns

```rust
// Critical Q4 period: strict cooldown
payroll.set_period_reopen_cooldown(&admin, &Symbol::new("2024Q4"), &86400u64); // 24 hours

// Regular monthly period: moderate cooldown
payroll.set_period_reopen_cooldown(&admin, &Symbol::new("2024M03"), &3600u64);  // 1 hour
```

**Effect**: Flexibility per period based on operational needs.

## Validation Rules

### Cooldown Enforcement

- **During cooldown**: Reopen is rejected with privacy-safe error
- **After expiry**: Reopen succeeds, last_reopen_at is updated
- **Timestamp update**: Each successful reopen advances the cooldown timer
- **Period independence**: Each period has its own cooldown tracking

### Error Handling

All cooldown errors are privacy-safe:

```
❌ EXPOSE: "Cannot reopen; last reopen was at 2024-11-15T10:00:00Z"
❌ EXPOSE: "Account 0xABC123 reopened this period 3 times today"
❌ EXPOSE: "Failed reopen for period 2024M01 with 500 employees"

✅ PRIVACY-SAFE: "Period reopen cooldown active: cannot reopen until X seconds have elapsed"
```

No payroll amounts, employee counts, or detailed timing information is exposed.

## Test Coverage

The test suite validates:

- ✓ Cooldown configuration persistence
- ✓ Rapid reopen blocking
- ✓ Reopen success after cooldown expires
- ✓ Disabled cooldown (0 seconds)
- ✓ Timestamp update on reopen
- ✓ Multiple periods with independent cooldowns
- ✓ Authorization enforcement
- ✓ Exact boundary conditions
- ✓ Error message privacy

Run tests:
```bash
cargo test -p payroll period_reopen_cooldown
```

## Compatibility

- **Backward compatible**: Periods without configured cooldowns work as before
- **No changes to existing workflows**: Period freeze/unfreeze logic unchanged
- **Non-disruptive**: Cooldown is opt-in per period

## Security Considerations

1. **Admin-only**: Only the payroll admin can configure or modify cooldowns
2. **Per-period**: Cooldown is tracked independently per period label
3. **Timestamp integrity**: Uses contract ledger timestamp (tamper-proof)
4. **Overflow safe**: Uses saturating arithmetic to prevent underflow
5. **Privacy**: Error messages never expose timing details or account info

## Troubleshooting

### "Period reopen cooldown active: cannot reopen until X seconds have elapsed"

**Cause**: You're attempting to reopen a period before the cooldown has expired.

**Solution**:
1. Wait `X` more seconds
2. Or reconfigure cooldown with `set_period_reopen_cooldown(&admin, &period, &0u64)` to disable

### "Payroll period is not frozen"

**Cause**: You're attempting to reopen a period that is not currently frozen.

**Solution**: Freeze the period first with `freeze_payroll_period` or wait for automatic freeze after payroll submission.

### Want to change cooldown mid-period?

**Solution**: Simply call `set_period_reopen_cooldown` with a new value. The new duration applies immediately to future reopens.

## API Reference

### `set_period_reopen_cooldown`

```rust
pub fn set_period_reopen_cooldown(
    e: Env,
    admin: Address,
    period_label: Symbol,
    cooldown_seconds: u64,
)
```

**Parameters**:
- `admin` - Authorized admin address (must be current contract admin)
- `period_label` - Period identifier (e.g., Symbol::new("2024M01"))
- `cooldown_seconds` - Minimum seconds between reopens (0 = disabled)

**Effects**:
- Creates or updates cooldown configuration for the period
- Initializes `last_reopen_at` to 0 if first time setting

**Authorization**: Requires admin authentication

### `get_period_reopen_cooldown`

```rust
pub fn get_period_reopen_cooldown(
    e: Env,
    period_label: Symbol,
) -> Option<PeriodReopenCooldown>
```

**Returns**: Optional cooldown record with current configuration and last reopen timestamp

**Privacy**: Safe to call from any address (read-only, no payroll data exposed)

### `reopen_payroll_period`

```rust
pub fn reopen_payroll_period(
    e: Env,
    admin: Address,
    period_label: Symbol,
)
```

**Behavior**:
1. Validates period is currently frozen
2. Checks cooldown if configured
3. Blocks if cooldown active, panics with actionable error
4. Updates `last_reopen_at` on success
5. Removes freeze record (period becomes editable)

**Authorization**: Requires admin authentication

## Related Features

- **Period Freeze** (`freeze_payroll_period`): Manually freeze a period
- **Period Unfreeze** (`unfreeze_payroll_period`): Alias for reopen
- **Automatic Freeze**: Triggered when payroll is submitted for a period
- **Settlement Window**: Controls when periods are settlement-ready
