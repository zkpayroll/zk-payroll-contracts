Closes #58

## Changes
- Fixed `payment_executor` to read employee commitments from the dedicated `salary_commitment` contract instead of `payroll_registry`.
- Kept `payroll_registry` as the source for company metadata and admin authorization.
- Added the missing `salary_commitment` dependency to `payment_executor` so the contract builds with the new client import.

## Why
The executor already accepted a commitment contract address in its config, but it was never used. That meant the proof input was sourced from the wrong contract, which did not match the intended architecture and could lead to inconsistent payroll verification behavior.

## Testing
- I verified the code changes by inspection and updated the contract wiring accordingly.
- I could not run `cargo test` in this workspace because Rust tooling is not available on the current PATH.
