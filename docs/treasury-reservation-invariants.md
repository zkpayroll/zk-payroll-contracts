# Treasury Reservation Invariants

> Closes #946, #947 and #948.

This document is the authoritative reference for treasury reservations made by
the payroll contract. It records the invariants enforced by
[`contracts/payroll/src/treasury_reservation.rs`](../contracts/payroll/src/treasury_reservation.rs)
and by the reservation guard in
[`contracts/payroll/src/lib.rs`](../contracts/payroll/src/lib.rs). Every rule is
covered by the adversarial suite
[`contracts/payroll/tests/treasury_reservation_adversarial.rs`](../contracts/payroll/tests/treasury_reservation_adversarial.rs).

## 1. Terminology

| Term | Meaning |
| --- | --- |
| **Treasury** | The account that holds the canonical token for a payroll deployment. It is an ordinary Stellar account, not a contract-owned vault. |
| **Reservation (lock)** | The amount recorded under `DataKey::LockedPayrollFunds(asset)` for pending payroll runs. |
| **Buffer** | The admin-configured retained balance (`get_treasury_balance_buffer`), zero until configured. |
| **Reservable balance** | `max(treasury_balance - max(reserved, 0) - max(buffer, 0), 0)`. |
| **Safe error** | A unit-only [`TreasuryReservationError`](../contracts/payroll/src/treasury_reservation.rs) variant with a permanently assigned code and fixed message. |

## 2. Accounting invariants

### INV-ACC-1  A reservation must fit

`prepare_payroll_run` may lock `amount` only when `amount <= reservable balance`.
The same rule is used by `check_funding_source_readiness` and by the preflight
entry point `validate_treasury_reservation(asset, amount)`, so the three cannot
disagree.

### INV-ACC-2  The available balance is never negative

Both `reserved` and `buffer` are clamped to zero before subtraction, and the
result is clamped at zero. A treasury drawn below its locks reports `0`
available, never a negative figure that would permit another reservation.

### INV-ACC-3  Arithmetic cannot overflow

Calculations use `saturating_sub`. Accepting `amount` at the inclusive boundary
cannot overflow because `amount <= total_balance - reserved - buffer`.

### INV-ACC-4  Reservations are per asset

`LockedPayrollFunds` is keyed by token address. Funds reserved for one asset
cannot satisfy or offset a reservation in another asset. Cross-asset use is
rejected with `CrossAssetMismatch` (8608).

## 3. Boundary invariants

### INV-BND-1  The upper boundary is inclusive

Reserving exactly the reservable balance succeeds and leaves zero available.
One more unit fails with `InsufficientUnreserved` (8603).

### INV-BND-2  Non-positive amounts fail first

`amount <= 0` is rejected with `NonPositiveAmount` (8602) before any balance is
read. Even an uninitialized or empty treasury reports the amount error first
when the amount itself is invalid.

### INV-BND-3  Extreme values are handled deterministically

`i128::MIN`, `i128::MAX`, negative locks and negative buffers cannot inflate the
available balance or wrap it into a successful reservation.

## 4. State transition invariants

### INV-STATE-1  A failed reservation writes nothing

The reservation check runs before nonce consumption, capacity accounting, the
pending-run record and the funds lock. After a rejection the nonce is still
usable, `get_locked_funds` is unchanged and no partial run exists.

### INV-STATE-2  Releasing a reservation restores capacity

Cancelling, expiring or finalizing a run removes its lock. The next reservation
is measured against the new aggregate lock total.

### INV-STATE-3  Payouts cannot consume reserved funds

Every direct execution entry point checks the live treasury balance before a
transfer and refuses a payout that would leave less than the aggregate locks
plus the configured buffer.

### INV-STATE-4  The treasury remains externally mutable

The guard governs reservations and payouts made by payroll. An external actor
may still move funds out of the treasury account; `get_safe_treasury_summary`
and `check_funding_source_readiness` report the current position.

## 5. Error and privacy invariants

### INV-ERR-1  Stable, payload-free codes

Every reservation failure maps to a unit-only `TreasuryReservationError` variant
in the 8600–8699 range. Codes are append-only and must never be reused.

### INV-ERR-2  Messages are actionable and log-safe

Each code maps to one fixed message that names the recovery step (fund the
treasury, use the canonical asset, retry, reconcile, etc.). No message contains
a salary, employee identifier, commitment, proof, address or payment amount.

### INV-ERR-3  Detailed diagnostics stay internal

`ReservationIssue::InsufficientUnreserved { available }` carries an aggregate
figure for internal diagnostics and legacy panic text. Clients that need a
contract error use `validate_treasury_reservation` or `ReservationIssue::safe_error()`,
which discard the figure in favour of the stable code.

### INV-PRI-1  Read helpers expose aggregates only

`get_safe_treasury_summary`, `get_available_treasury_balance` and
`get_locked_funds` return token-unit totals. No employee row, salary value or
proof material is read or returned by the reservation path.

## 6. Error code registry

| Code | Variant | Meaning / recovery |
| --- | --- | --- |
| 8600 | `NotInitialized` | Contract is not initialized; initialize before reserving. |
| 8601 | `AssetNotAllowed` | Asset is not on the allowlist; use an approved asset. |
| 8602 | `NonPositiveAmount` | Amount must be positive; resubmit with a positive amount. |
| 8603 | `InsufficientUnreserved` | Locks and buffer leave too little; fund, reduce the buffer or cancel a run. |
| 8604 | `TreasuryUnavailable` | Balance query failed; retry or check the token contract. |
| 8605 | `ReservationNotFound` | No reservation for this asset; check the asset and run. |
| 8606 | `InvalidReservationState` | Stored lock state is invalid (negative); reconcile pending runs. |
| 8607 | `UnauthorizedReservationChange` | Caller may not change reservations; use the authorized operator. |
| 8608 | `CrossAssetMismatch` | Asset differs from the canonical treasury asset. |

## 7. Verification

- `treasury_reservation_adversarial.rs` exercises the pure decision at the
  inclusive boundary, with negative/extreme inputs, with multiple assets and
  through the contract preflight entry point, and checks that every safe error
  is payload-free and permanently assigned.
- `treasury_reservation_checks.rs` and `treasury_balance_buffer.rs` cover the
  end-to-end reservation, rejection, cancellation and payout-guard behaviour.
