# Contract Treasury Replenishment Readiness Analysis (#637)

This document specifies the treasury replenishment readiness analysis module in the `payroll` contract.

## Overview

The `treasury_replenishment_analysis` module performs comprehensive, privacy-preserving liquidity assessments for employer treasury accounts. It evaluates whether a treasury holds sufficient reserves to satisfy upcoming payroll commitments and calculates dynamic reserve buffer targets before batch disbursements execute.

## Key Metrics & Analysis

- **Committed Obligations**: Total outstanding payout liabilities (scheduled runs, pending batches).
- **Dynamic Reserve Buffer**: Configurable safety buffer calculated via basis points (`reserve_buffer_bps`) with an enforced floor (`min_reserve_amount`).
- **Target Balance**: `committed_obligations + required_reserve`.
- **Shortfall vs Headroom**:
  - `headroom`: Liquid surplus available beyond obligations and required safety buffer.
  - `shortfall`: Liquidity deficit that must be replenished before execution can proceed.
- **Recommended Replenishment**: Exact amount needed to restore treasury liquidity to optimal operating targets.

## Readiness Classifications

1. **`ReplenishmentStatus::Sufficient`**: Balance comfortably satisfies both immediate payroll commitments and reserve buffer targets.
2. **`ReplenishmentStatus::ReplenishmentRequired`**: Balance satisfies immediate obligations but falls short of reserve buffers; deficit is within approved `max_replenishment_cap`.
3. **`ReplenishmentStatus::CriticalDeficit`**: Immediate obligations cannot be met by available funds or shortfall exceeds allowable replenishment ceilings.

## Deposit Enforcement

The `validate_replenishment_deposit` function enforces deposit caps (`max_replenishment_cap`) and validates that deposits are positive, protecting contracts from errant or non-conforming transfer amounts.
