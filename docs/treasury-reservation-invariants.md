# Treasury Reservation Invariants

This document defines the invariants for treasury reservations across payroll
reservation checks and the `treasury_isolation` contract. It covers
issue #947 and supports the safe-error and adversarial coverage in #946/#948.

## Scope

- `contracts/payroll/src/treasury_reservation.rs` - pure reservation math used
  by payroll preparation and readiness checks.
- `contracts/payroll/src/lib.rs` - payroll-side reservation enforcement,
  treasury buffer checks, and funding-readiness reporting.
- `contracts/treasury_isolation/src/lib.rs` - per-company, per-asset balance,
  reserve, release, and execution accounting.

## Privacy Contract

Reservation errors, events, and docs must not expose employee identity, salary
rows, commitment hashes, proof bytes, or per-recipient payout data. Only
aggregate token amounts, company/asset identifiers, and stable error codes may
be surfaced.

## Payroll Reservation Invariants

### PR-1: Reservation amount must be positive

`check_reservation` / `check_reservation_with_buffer` reject amounts `<= 0`
with `ReservationIssue::NonPositiveAmount`.

### PR-2: Available balance is never negative

`unreserved_balance` and `reservable_balance` clamp negative intermediate
values to zero. A treasury below existing locks or buffer has zero reservable
capacity, never negative capacity.

### PR-3: Buffer and locked funds are protected

A run of `amount` may be reserved only when:

```text
amount <= max(total_balance - locked_funds - buffer, 0)
```

The boundary is inclusive: reserving exactly the reservable balance is allowed.

### PR-4: Reservation checks are pure and side-effect free

The reservation decision in `treasury_reservation.rs` has no storage reads,
writes, or token calls. Payroll callers are responsible for reading balances,
locks, and buffers and for surfacing actionable errors.

### PR-5: Failed payroll reservation leaves no trace

If `prepare_payroll_run` fails the reservation check, it must not consume the
nonce, create a pending run, or change locked funds.

### PR-6: Readiness and preparation agree

Funding readiness and payroll preparation use the same reservable-balance rule:
`total_balance - locked_funds - buffer`.

## Treasury Isolation Invariants

### TI-1: Asset registration is required before reservation

`reserve` rejects an asset with no registration record for the company with
`TreasuryIsolationError::AssetNotRegistered` before mutating state.

### TI-2: Reservations are asset-scoped

Balances and reserves are keyed by `(company_id, asset)`. A reserve or debit in
one asset cannot consume balance or reserved funds from another asset.

### TI-3: Available reserve is bounded by accounting state

For any `AssetBalance`, `0 <= reserved <= balance` and available funds are
`balance - reserved`. `reserve` rejects when `amount > available`.

### TI-4: Release cannot exceed reserved amount

`release_reserve` requires explicit authorization and rejects
`amount > reserved` with `InsufficientReserve`. Releasing exactly `reserved`
is valid and clears the reservation.

### TI-5: Execution debit preserves isolation and conservation

`execute_debit` rejects when committed and treasury assets differ
(`AssetMismatch`), when amount exceeds balance (`InsufficientBalance`), or when
amount exceeds reserved (`InsufficientReserve`). On success it decrements both
`balance` and `reserved` by the same amount.

### TI-6: Invalid amounts are rejected

All state-changing reserve/credit/release/debit operations reject `amount <= 0`
with `InvalidAmount`.

### TI-7: Invalid stored state fails closed

Readiness and mutating operations validate balance state. Negative balances,
negative reserves, or `reserved > balance` are treated as invalid and do not
report readiness.

## Safe Error Mapping

| Error | Code | Meaning | Recovery |
|---|---|---:|---|
| `NotInitialized` | 1 | Treasury isolation contract has no admin. | Initialize contract before use. |
| `AssetNotRegistered` | 2 | Company/asset registration record missing. | Register the asset for the company. |
| `AssetAlreadyRegistered` | 3 | Asset already registered for company. | Use existing registration. |
| `AssetMismatch` | 4 | Committed asset differs from treasury asset. | Execute with matching asset. |
| `InsufficientBalance` | 5 | Balance/available funds cannot cover request. | Fund treasury or reduce amount. |
| `InsufficientReserve` | 6 | Reserved funds cannot cover release/debit. | Check current reservation. |
| `Unauthorized` | 7 | Caller lacks admin/reserve authority. | Use admin or authorized reserve operator. |
| `IssuerMismatch` | 8 | Issuer collides with different asset contract. | Use canonical asset registration. |
| `InvalidAmount` | 9 | Amount is zero or negative. | Provide a positive amount. |

## Verification

- `cargo test -p treasury_isolation` - registration, reservation, release,
  debit, issuer mismatch, and adversarial reservation cases.
- `cargo test -p payroll --test treasury_reservation_checks` - payroll
  reservation boundaries and no-trace failures.
- `cargo test -p payroll --test treasury_balance_buffer` - buffer-aware
  reservations and payout/withdrawal guards.
