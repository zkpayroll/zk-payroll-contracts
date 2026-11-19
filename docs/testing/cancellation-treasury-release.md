# Cancellation and treasury release integration tests (#828)

The suite in `contracts/integration_tests/tests/cancellation_treasury_release.rs`
uses real Payroll, salary commitment, token, and treasury isolation contracts
in one Soroban environment. It covers the current operator workflow; it does
not add an automatic treasury release, new entrypoint, or new error code.

## Expected behavior

`prepare_payroll_run` reserves the batch total in Payroll's internal token lock.
An integration using `treasury_isolation` separately records the same aggregate
reservation with `reserve(company_id, asset, total)`.

The configured payroll admin cancels the run with
`cancel_payroll_run_with_reason` (or its `cancel_payroll_run` alias). A successful
cancellation removes the pending record, records `Cancelled`, releases exactly
that run's internal lock, and leaves its nonce permanently consumed. It does
not pay employees, change their commitments, or transfer treasury tokens.
Other pending runs and their locks remain intact.

Cancellation does **not** call `treasury_isolation`. The admin or an explicitly
delegated reserve authorizer must then call
`release_reserve(company_id, asset, total, authorizer)` separately. That call
reduces the accounting reserve for exactly the selected company and asset;
it leaves the credited balance and other companies/assets unchanged.

These are separate transactions, not an atomic operation. If release fails
after cancellation, Payroll stays cancelled and the isolation reserve stays
locked. The operator must correct the authorization or request and retry only
the release. The accounting layer tracks aggregate reserves, not run IDs; it
does not deduplicate releases per run. Integrators must reconcile a successful
release before retrying it, particularly when other runs still have reserves.

## Rejections and boundaries

| Existing failure | Operator action |
| --- | --- |
| Payroll `Unauthorized` | Use the configured payroll admin and provide its authorization. |
| Payroll `Pending run not found` | Check whether the run was already cancelled or finalized; do not cancel it again. |
| Payroll `Cannot cancel a finalized payroll run` | Reconcile the finalized record; cancellation cannot reverse it. |
| Payroll `Duplicate run nonce: this payroll batch has already been submitted` | Use a fresh, increasing nonce for a replacement run. |
| `TreasuryIsolationError::Unauthorized` (7) | Use the isolation admin or obtain delegation for this company. |
| `TreasuryIsolationError::InvalidAmount` (9) | Supply a positive aggregate release amount. |
| `TreasuryIsolationError::InsufficientReserve` (6) | Reconcile the current reservation; the release exceeds it. |

Releasing exactly the current reserve is allowed and reduces it to zero.
Zero, negative amounts, over-release by one unit, and a further positive release
after exhaustion are rejected without mutating reservations or emitting success
events. A rejected cancellation likewise leaves both reservations intact.
After both locks are cleared, a new run can reserve all the available capacity.

## Privacy and coverage

Fixtures contain only generated addresses and synthetic amounts. Cancellation
events contain the opaque run ID and cancelling admin, not the caller-supplied
reason, employee identities, individual salaries, or proof bytes. Existing
treasury lock/snapshot and release events expose aggregate token accounting;
the release event is `(company_id, asset, aggregate_amount)`. This is public
aggregate information and can still permit inference in a one-employee batch.

Tests check successful cancellation followed by release, preservation of a
second pending run and unrelated company/asset reserves, rejected cancellation,
failed release with an authorized retry, exact exhaustion/over-release, nonce
replay, missing signatures for otherwise permitted roles, finalization after
cancellation, and exact event schemas. Commitment values and token balances
must remain unchanged throughout cleanup.

Run the focused suite and existing treasury tests:

```sh
cargo test --locked -p integration_tests --test cancellation_treasury_release
cargo test --locked -p treasury_isolation
```

Repository CI also runs `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace`. Formatting and tests need the repository's supported
Rust toolchain; the integration suite does not require Node or proof generation.
