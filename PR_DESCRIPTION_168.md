# [Events] Add high-priority contract events for treasury updates (#168)

## Summary

Adds structured contract events when treasury accounts, asset allowlists, or authorization settings are updated across contracts (`payroll_registry` and `payment_executor`). This ensures indexers, dashboards, and audit log monitoring systems receive real-time updates on critical treasury mutations.

## Changes

- **`contracts/payroll_registry/src/lib.rs`**:
  - Emits `TreasuryRotationProposed` event in `propose_treasury_rotation` with topics `("TreasuryRotationProposed", company_id)` and data `(current_admin, new_treasury, timestamp)`.
  - Emits `TreasuryRotated` event in `accept_treasury_rotation` with topics `("TreasuryRotated", company_id)` and data `(old_treasury, new_treasury)`.
  - Implements `cancel_treasury_rotation` in `PayrollRegistryTrait` and `PayrollRegistry` and emits `TreasuryRotationCancelled` event with topics `("TreasuryRotationCancelled", company_id)` and data `(current_admin,)`.
- **`contracts/payroll_registry/src/tests.rs`**:
  - Added unit tests for `TreasuryRotationProposed`, `TreasuryRotated`, and `TreasuryRotationCancelled` event emissions and assertions.
- **`contracts/payment_executor/src/lib.rs`**:
  - Emits `TreasuryAssetAllowedUpdated` event in `initialize` when setting the default allowed asset token.
  - Emits `TreasuryAssetAllowedUpdated` event in `set_asset_allowed` with topics `("TreasuryAssetAllowedUpdated", asset)` and data `(allowed, timestamp)`.
  - Added unit test `test_asset_allowed_emits_events` verifying event published on `initialize` and `set_asset_allowed`.

## Closes

Closes #168
