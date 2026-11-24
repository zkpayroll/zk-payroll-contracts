# Pause Manager

Administrative pause control for ZK Payroll contracts.

## Invariants (#995, #997)

- **Operator-only control**: only the configured operator may pause/unpause globally or by category. Unauthorized callers must be rejected.
- **Category isolation with safe global semantics**:
  - `pause_category(category)` affects only that category.
  - `unpause_category(category)` resumes only that category.
  - `pause()` sets all categories paused; `unpause()` clears all categories.
- **Status consistency**: `get_pause_status()` reflects per-category state; `is_paused()` is true when any category is paused.
- **Initialization safety**: contract can be initialized once; pause operations require initialization.
- **Operator rotation safety**: rotation is two-step (`propose` -> `accept`) with explicit cancellation; only current operator can propose/cancel, only proposed operator can accept.
- **No sensitive data**: pause state and events contain operational/admin metadata only; no employee or salary data.

## Categories

- `Payroll` - payroll execution/mutation flows.
- `Treasury` - treasury/funding flows.
- `Audit` - audit/reporting flows as integrated by consuming contracts.
- `Admin` - administrative/configuration flows as integrated by consuming contracts.

## Integration expectation

Consumers should consult pause state before state-changing operations. For payroll/payment execution, any active pause category should block execution with an actionable error.
