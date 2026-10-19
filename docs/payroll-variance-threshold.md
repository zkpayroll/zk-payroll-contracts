# Payroll Variance Threshold Validation (#644)

An opt-in, contract-layer guard that rejects payroll draft amendments whose
relative move exceeds an employer-configured ceiling.

## Why

A misplaced zero or a truncated batch can silently multiply a payroll total
before finalization. The variance threshold catches that class of mistake at
write time — when the amendment is submitted — with an actionable error,
instead of letting it flow into `finalize_run_draft` and execution.

## Rules

The ceiling is configured in **basis points** (`0..=10_000`, where `10_000`
is 100%) via `set_payroll_variance_threshold`:

| Case | Behaviour |
|------|-----------|
| No threshold stored | Amendments are unrestricted (pre-existing behaviour). |
| `max_variance_bps = 0` | Only exact matches are accepted (strictest policy). |
| `0 < max <= 10_000` | Amendments whose measured variance `<= max` are accepted. |
| `max > 10_000` | Rejected at configuration time. |
| `baseline <= 0` or `proposed <= 0` | Rejected; no relative move can be computed. |

Measurement: `variance_bps = |proposed - baseline| * 10_000 / baseline`,
integer division (rounds down), saturating to `u32::MAX` on overflow.
Boundaries are inclusive: with a `1_000` bps (10%) ceiling, `1_000 -> 1_110`
(1100 bps) is rejected while `1_000 -> 1_100` (exactly 1000 bps) is accepted.
Raising and lowering are symmetric: `1_000 -> 900` is also exactly 1000 bps.

## Order of operations in `amend_run_draft`

1. Pause gate, draft-id validation, admin identity + `require_auth`.
2. Pending-state check, period-freeze guard, correction-request expiry.
3. `total_amount > 0` check.
4. **Variance check (#644)** — rejects before any state is written.
5. Correction authorization limits (#577), if configured.
6. Mutation (`total_amount`, `employee_count`, `amendment_count`,
   `updated_at`), events, correction-usage accounting.

A rejected amendment writes nothing: the draft is unchanged
(`amendment_count` not bumped) and no correction budget is consumed, so the
caller can retry with a corrected total without side effects.

## Contract surface

| Entrypoint | Purpose |
|------------|---------|
| `set_payroll_variance_threshold(admin, max_variance_bps)` | Admin-only validated write; rejects `> 10_000`. |
| `get_payroll_variance_threshold()` | Current ceiling, or `None` when unrestricted. |
| `clear_payroll_variance_threshold(admin)` | Admin-only removal; restores unrestricted amendments. |
| `check_payroll_variance(baseline, proposed)` | Read-only preflight; no auth, no state change. |
| `require_payroll_variance(baseline, proposed)` | Guard that panics with the breach and its remediation. |

Supporting types in `contracts/payroll/src/payroll_variance.rs`:

| Type | Purpose |
|------|---------|
| `PayrollVarianceConfig` | Stored ceiling (`max_variance_bps`). |
| `PayrollVarianceCheck` | Preflight verdict: inputs, ceiling, measured `variance_bps`, `within_threshold`, `threshold_configured`. |
| `PayrollVarianceIssue` | Structured failure reason with stable `as_str()` codes. |
| `MAX_VARIANCE_BPS` | `10_000` (100%). |

Storage uses a dedicated `VarianceKey::PayrollVarianceThreshold` enum, leaving
the existing `DataKey` layout untouched (that enum is already past the
Soroban 50-case spec ceiling).

## Errors

All messages name the one thing the caller must change:

- `"Variance threshold must not exceed 10000 basis points (100%)"` —
  reconfigure with a value in range.
- `"Payroll variance threshold exceeded: proposed total deviates {measured}
  bps from baseline, above the {max} bps maximum; adjust the amendment or
  raise the threshold"` — shrink the amendment or deliberately raise the
  ceiling.
- `"total_amount must be positive"` — shared with the pre-existing amount
  gate; runs before the variance math so non-positive totals never reach it.
- `"Unauthorized"` / pause errors — standard admin and pause gates.

## Events

Legacy `("payroll", <verb>)` convention, carrying only magnitudes and
timestamps — never employee identities or salary breakdowns:

| Topics | Data |
|--------|------|
| `("payroll", "variance_threshold_set")` | `(max_variance_bps: u32, timestamp: u64)` |
| `("payroll", "variance_threshold_cleared")` | `(timestamp: u64)` |
| `("payroll", "variance_threshold_violated")` | `(measured_bps: u32, max_bps: u32)` |

## Privacy

Only aggregate totals and basis-point magnitudes are stored, checked, and
emitted. No per-employee salary, identity, commitment, or proof material is
read or surfaced, consistent with the correction-authorization (#577) and
minimum-payout (#514) features.

## Verification

- `cargo test -p payroll --test payroll_variance_threshold` — 14 focused
  integration tests (unrestricted default, readable/replaceable policy,
  within-ceiling success, exact-boundary success, breach rejection without
  mutation, symmetric down-move rejection, zero-threshold strictness,
  full-range boundary, no correction-budget burn on rejection, invalid
  threshold rejection, non-admin rejection, clear restores access, preflight
  purity, direct `require_` enforcement).
- Unit tests in `payroll_variance.rs` pin the basis-point math (equality,
  rounding, zero-baseline saturation, boundary precedence, stable issue
  codes).
