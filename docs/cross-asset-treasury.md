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
