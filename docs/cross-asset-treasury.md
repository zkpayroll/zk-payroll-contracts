# Cross-Asset Treasury Invariants

Payroll and payment-executor treasury operations use the serialized Soroban
token contract `Address` as the canonical asset identifier. The configured
`ContractAddresses.token` is the only asset that may be allowlisted, reserved,
readiness-checked, or transferred from the treasury.

An issued asset with a different issuer is represented by a different token
contract address and is therefore a different canonical asset. It cannot reuse
the treasury's reserves. Asset addresses must be compared as Soroban
`Address` values; symbols, display strings, and decimal configuration are not
asset identity.

## Deactivated assets

An admin deactivates the canonical treasury asset by calling
`set_asset_allowed(token, false)`; `set_asset_allowed(token, true)` re-enables it.
Deactivation is rejected while a payroll run is prepared but not yet resolved
(#253), so an in-flight run can never be invalidated mid-flight.

While the asset is deactivated:

- Payout paths (`prepare_payroll_run`, `batch_process_payroll`) and direct
  deposits (`deposit`) are rejected with `Asset not allowed`. Deposits are
  blocked because payouts are blocked: accepting new funds for an asset that
  cannot pay out would strand them in the treasury.
- Treasury movements and views (`add_locked_funds`, `subtract_locked_funds`,
  `get_safe_treasury_summary`) report `Asset not allowed` instead of the
  cross-asset identity error, so operators can tell a reversible configuration
  change from an asset-identity mismatch.
- `get_available_treasury_balance` reports `0`, since reserved and available
  balances are only meaningful for an active asset.
- `is_asset_deactivated(asset)` returns `true` for the explicitly deactivated
  canonical asset, `false` after it is re-enabled, and `false` for any asset
  that is not this contract's canonical treasury asset. It distinguishes
  "explicitly switched off" from "never configured", which
  `is_asset_allowed` alone cannot express.

A rejected deposit does not consume its `deposit_id`, so the same request can be
retried after reactivation. Deactivation is recorded in the configuration audit
trail like any other allowlist change, and no deactivated-asset error or event
exposes employee or salary data.
