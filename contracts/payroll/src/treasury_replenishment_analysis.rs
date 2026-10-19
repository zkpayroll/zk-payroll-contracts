//! Contract treasury replenishment readiness analysis (#637)
//!
//! Provides pre-flight readiness analysis for contract treasury accounts, computing
//! committed payroll obligations, dynamic reserve buffers, liquidity headroom, and
//! actionable replenishment recommendations before disbursements occur.

#![no_std]

use soroban_sdk::{contracttype, Env};

/// Classification of treasury replenishment readiness.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ReplenishmentStatus {
    /// Treasury balance is fully sufficient to cover obligations and reserve buffer.
    Sufficient = 1,
    /// Replenishment is required to meet reserve targets, but deficit is within allowable cap.
    ReplenishmentRequired = 2,
    /// Severe deficit: treasury cannot cover immediate obligations or shortfall exceeds cap.
    CriticalDeficit = 3,
}

/// Configuration parameters governing treasury replenishment analysis.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryReplenishmentConfig {
    /// Reserve buffer in basis points (e.g. 500 = 5% of committed obligations)
    pub reserve_buffer_bps: u32,
    /// Absolute minimum reserve amount retained in treasury
    pub min_reserve_amount: i128,
    /// Maximum allowable single replenishment deposit ceiling
    pub max_replenishment_cap: i128,
}

/// Comprehensive report detailing treasury replenishment readiness.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplenishmentReadinessAnalysis {
    /// Overall readiness classification status
    pub status: ReplenishmentStatus,
    /// Current verified treasury balance
    pub current_balance: i128,
    /// Total committed payroll obligations (pending batches, scheduled disbursements)
    pub committed_obligations: i128,
    /// Calculated minimum required reserve buffer
    pub required_reserve: i128,
    /// Total target liquidity (committed obligations + required reserve)
    pub total_target_balance: i128,
    /// Liquidity shortfall below target balance (0 if balance >= target)
    pub shortfall: i128,
    /// Liquidity headroom above target balance (0 if balance < target)
    pub headroom: i128,
    /// True if current balance is at least equal to committed obligations
    pub is_execution_ready: bool,
    /// True if required replenishment does not exceed max replenishment cap
    pub is_replenishment_allowable: bool,
    /// Exact recommended deposit amount to achieve target liquidity
    pub recommended_replenishment: i128,
}

/// Error codes for treasury analysis operations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TreasuryAnalysisError {
    /// Treasury balance cannot be negative.
    NegativeBalance = 1,
    /// Committed obligations cannot be negative.
    NegativeObligations = 2,
    /// Invalid configuration parameters (e.g. negative min reserve or cap).
    InvalidConfig = 3,
    /// Deposit amount exceeds max replenishment cap.
    ExceedsReplenishmentCap = 4,
    /// Deposit amount must be positive.
    InvalidDepositAmount = 5,
}

/// Validates that configuration values are non-negative.
pub fn validate_replenishment_config(
    config: &TreasuryReplenishmentConfig,
) -> Result<(), TreasuryAnalysisError> {
    if config.min_reserve_amount < 0 || config.max_replenishment_cap < 0 {
        return Err(TreasuryAnalysisError::InvalidConfig);
    }
    Ok(())
}

/// Computes the required reserve based on basis points and floor minimum.
pub fn calculate_required_reserve(
    config: &TreasuryReplenishmentConfig,
    committed_obligations: i128,
) -> i128 {
    let bps_reserve = (committed_obligations
        .saturating_mul(config.reserve_buffer_bps as i128))
        / 10_000;

    if bps_reserve > config.min_reserve_amount {
        bps_reserve
    } else {
        config.min_reserve_amount
    }
}

/// Performs complete replenishment readiness analysis for a treasury account.
pub fn analyze_replenishment_readiness(
    config: &TreasuryReplenishmentConfig,
    current_balance: i128,
    committed_obligations: i128,
) -> Result<ReplenishmentReadinessAnalysis, TreasuryAnalysisError> {
    validate_replenishment_config(config)?;

    if current_balance < 0 {
        return Err(TreasuryAnalysisError::NegativeBalance);
    }
    if committed_obligations < 0 {
        return Err(TreasuryAnalysisError::NegativeObligations);
    }

    let required_reserve = calculate_required_reserve(config, committed_obligations);
    let total_target_balance = committed_obligations.saturating_add(required_reserve);

    let is_execution_ready = current_balance >= committed_obligations;

    let (shortfall, headroom) = if current_balance >= total_target_balance {
        (0i128, current_balance.saturating_sub(total_target_balance))
    } else {
        (total_target_balance.saturating_sub(current_balance), 0i128)
    };

    let is_replenishment_allowable = if config.max_replenishment_cap > 0 {
        shortfall <= config.max_replenishment_cap
    } else {
        true
    };

    let status = if shortfall == 0 {
        ReplenishmentStatus::Sufficient
    } else if is_execution_ready && is_replenishment_allowable {
        ReplenishmentStatus::ReplenishmentRequired
    } else {
        ReplenishmentStatus::CriticalDeficit
    };

    Ok(ReplenishmentReadinessAnalysis {
        status,
        current_balance,
        committed_obligations,
        required_reserve,
        total_target_balance,
        shortfall,
        headroom,
        is_execution_ready,
        is_replenishment_allowable,
        recommended_replenishment: shortfall,
    })
}

/// Validates a replenishment deposit against the configured replenishment cap.
pub fn validate_replenishment_deposit(
    config: &TreasuryReplenishmentConfig,
    deposit_amount: i128,
) -> Result<i128, TreasuryAnalysisError> {
    validate_replenishment_config(config)?;

    if deposit_amount <= 0 {
        return Err(TreasuryAnalysisError::InvalidDepositAmount);
    }

    if config.max_replenishment_cap > 0 && deposit_amount > config.max_replenishment_cap {
        return Err(TreasuryAnalysisError::ExceedsReplenishmentCap);
    }

    Ok(deposit_amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> TreasuryReplenishmentConfig {
        TreasuryReplenishmentConfig {
            reserve_buffer_bps: 1000, // 10%
            min_reserve_amount: 100,
            max_replenishment_cap: 50_000,
        }
    }

    #[test]
    fn test_sufficient_treasury_balance() {
        let config = sample_config();
        // obligations = 1000, required_reserve = max(100, 10% of 1000 = 100) = 100.
        // target = 1100. balance = 1500 -> Sufficient with headroom 400.
        let analysis = analyze_replenishment_readiness(&config, 1500, 1000).unwrap();

        assert_eq!(analysis.status, ReplenishmentStatus::Sufficient);
        assert_eq!(analysis.shortfall, 0);
        assert_eq!(analysis.headroom, 400);
        assert!(analysis.is_execution_ready);
        assert!(analysis.is_replenishment_allowable);
        assert_eq!(analysis.recommended_replenishment, 0);
    }

    #[test]
    fn test_replenishment_required_when_below_buffer() {
        let config = sample_config();
        // obligations = 1000, target = 1100. balance = 1050 -> covers obligations (1000)
        // but short on reserve buffer by 50.
        let analysis = analyze_replenishment_readiness(&config, 1050, 1000).unwrap();

        assert_eq!(analysis.status, ReplenishmentStatus::ReplenishmentRequired);
        assert_eq!(analysis.shortfall, 50);
        assert_eq!(analysis.headroom, 0);
        assert!(analysis.is_execution_ready);
        assert!(analysis.is_replenishment_allowable);
        assert_eq!(analysis.recommended_replenishment, 50);
    }

    #[test]
    fn test_critical_deficit_when_cannot_cover_obligations() {
        let config = sample_config();
        // obligations = 1000, balance = 800 -> cannot cover immediate payroll
        let analysis = analyze_replenishment_readiness(&config, 800, 1000).unwrap();

        assert_eq!(analysis.status, ReplenishmentStatus::CriticalDeficit);
        assert!(!analysis.is_execution_ready);
        assert_eq!(analysis.shortfall, 300); // target 1100 - 800 = 300
    }

    #[test]
    fn test_critical_deficit_when_shortfall_exceeds_cap() {
        let config = TreasuryReplenishmentConfig {
            reserve_buffer_bps: 1000,
            min_reserve_amount: 100,
            max_replenishment_cap: 1000, // low cap
        };
        // obligations = 5000, target = 5500, balance = 2000 -> shortfall = 3500 > 1000 cap
        let analysis = analyze_replenishment_readiness(&config, 2000, 5000).unwrap();

        assert_eq!(analysis.status, ReplenishmentStatus::CriticalDeficit);
        assert!(!analysis.is_replenishment_allowable);
        assert_eq!(analysis.shortfall, 3500);
    }

    #[test]
    fn test_rejects_negative_balance_or_obligations() {
        let config = sample_config();
        assert_eq!(
            analyze_replenishment_readiness(&config, -10, 100),
            Err(TreasuryAnalysisError::NegativeBalance)
        );
        assert_eq!(
            analyze_replenishment_readiness(&config, 100, -10),
            Err(TreasuryAnalysisError::NegativeObligations)
        );
    }

    #[test]
    fn test_validate_replenishment_deposit() {
        let config = sample_config();
        // Valid deposit within cap
        assert_eq!(validate_replenishment_deposit(&config, 500), Ok(500));

        // Invalid non-positive deposit
        assert_eq!(
            validate_replenishment_deposit(&config, 0),
            Err(TreasuryAnalysisError::InvalidDepositAmount)
        );
        assert_eq!(
            validate_replenishment_deposit(&config, -50),
            Err(TreasuryAnalysisError::InvalidDepositAmount)
        );

        // Exceeds cap
        assert_eq!(
            validate_replenishment_deposit(&config, 60_000),
            Err(TreasuryAnalysisError::ExceedsReplenishmentCap)
        );
    }

    #[test]
    fn test_min_reserve_floor_used_when_bps_is_lower() {
        let config = TreasuryReplenishmentConfig {
            reserve_buffer_bps: 100, // 1%
            min_reserve_amount: 500, // floor is 500
            max_replenishment_cap: 50_000,
        };
        // 1% of 1000 = 10, but floor is 500 -> required reserve = 500
        let reserve = calculate_required_reserve(&config, 1000);
        assert_eq!(reserve, 500);
    }
}
