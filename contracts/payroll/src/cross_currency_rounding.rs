//! Cross-currency payout rounding safeguards (#700)
//!
//! Provides rounding validation and precision safeguards when converting amounts
//! across foreign currency exchange rates for payroll disbursement.

#![no_std]

use soroban_sdk::contracttype;

/// Rounding direction mode applied to currency conversion calculations.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RoundingMode {
    /// Round towards zero (truncate fractional stroops).
    Floor = 0,
    /// Round to nearest unit; ties round up.
    HalfUp = 1,
    /// Round strictly away from zero (ceiling).
    Ceil = 2,
}

/// Error codes for cross-currency payout rounding safeguards.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RoundingSafeguardError {
    /// Zero or negative exchange rate.
    InvalidExchangeRate = 1,
    /// Payout amount is zero or negative.
    InvalidAmount = 2,
    /// Rounding loss or delta exceeds configured tolerance in basis points.
    RoundingDiscrepancyExceedsTolerance = 3,
    /// Arithmetic overflow in conversion scaling.
    MathOverflow = 4,
}

/// Parameters for cross-currency payout conversion.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossCurrencyConversionConfig {
    /// Exchange rate numerator (e.g. rate in source stroops per target unit)
    pub rate_numerator: i128,
    /// Exchange rate denominator (e.g. 10^7 for base 7-decimal scaling)
    pub rate_denominator: i128,
    /// Maximum allowable rounding discrepancy in basis points (e.g. 10 bps = 0.1%)
    pub max_discrepancy_bps: u32,
    /// Selected rounding mode
    pub rounding_mode: RoundingMode,
}

/// Result of a cross-currency conversion with precision safeguards.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionResult {
    /// Final converted payout amount in target currency units/stroops
    pub converted_amount: i128,
    /// Exact fraction remainder in target stroops before rounding
    pub remainder: i128,
    /// Discrepancy observed from rounding in basis points
    pub discrepancy_bps: u32,
}

/// Converts a base payout amount across currencies applying rounding safeguards.
pub fn convert_with_rounding_safeguards(
    base_amount: i128,
    config: &CrossCurrencyConversionConfig,
) -> Result<ConversionResult, RoundingSafeguardError> {
    if base_amount <= 0 {
        return Err(RoundingSafeguardError::InvalidAmount);
    }
    if config.rate_numerator <= 0 || config.rate_denominator <= 0 {
        return Err(RoundingSafeguardError::InvalidExchangeRate);
    }

    let product = match base_amount.checked_mul(config.rate_numerator) {
        Some(p) => p,
        None => return Err(RoundingSafeguardError::MathOverflow),
    };

    let quotient = product / config.rate_denominator;
    let remainder = product % config.rate_denominator;

    let converted_amount = match config.rounding_mode {
        RoundingMode::Floor => quotient,
        RoundingMode::Ceil => {
            if remainder > 0 {
                match quotient.checked_add(1) {
                    Some(q) => q,
                    None => return Err(RoundingSafeguardError::MathOverflow),
                }
            } else {
                quotient
            }
        }
        RoundingMode::HalfUp => {
            if remainder * 2 >= config.rate_denominator {
                match quotient.checked_add(1) {
                    Some(q) => q,
                    None => return Err(RoundingSafeguardError::MathOverflow),
                }
            } else {
                quotient
            }
        }
    };

    // Calculate rounding discrepancy in basis points (bps) = (remainder * 10,000) / denominator
    let discrepancy_bps: u32 = if remainder > 0 {
        let scaled_rem = match remainder.checked_mul(10_000) {
            Some(s) => s,
            None => return Err(RoundingSafeguardError::MathOverflow),
        };
        (scaled_rem / config.rate_denominator) as u32
    } else {
        0
    };

    if config.max_discrepancy_bps > 0 && discrepancy_bps > config.max_discrepancy_bps {
        return Err(RoundingSafeguardError::RoundingDiscrepancyExceedsTolerance);
    }

    Ok(ConversionResult {
        converted_amount,
        remainder,
        discrepancy_bps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion_exact_match() {
        let config = CrossCurrencyConversionConfig {
            rate_numerator: 2,
            rate_denominator: 1,
            max_discrepancy_bps: 50,
            rounding_mode: RoundingMode::Floor,
        };

        let result = convert_with_rounding_safeguards(100, &config).unwrap();
        expect_eq(result.converted_amount, 200);
        expect_eq(result.remainder, 0);
        expect_eq(result.discrepancy_bps, 0);
    }

    #[test]
    fn test_rounding_modes() {
        // 10 * 3 / 2 = 15 exact
        // 10 * 1 / 3 = 3 with remainder 1 (1/3 = 3333 bps)
        let config_floor = CrossCurrencyConversionConfig {
            rate_numerator: 1,
            rate_denominator: 3,
            max_discrepancy_bps: 5000,
            rounding_mode: RoundingMode::Floor,
        };
        let res_floor = convert_with_rounding_safeguards(10, &config_floor).unwrap();
        assert_eq!(res_floor.converted_amount, 3);

        let config_ceil = CrossCurrencyConversionConfig {
            rate_numerator: 1,
            rate_denominator: 3,
            max_discrepancy_bps: 5000,
            rounding_mode: RoundingMode::Ceil,
        };
        let res_ceil = convert_with_rounding_safeguards(10, &config_ceil).unwrap();
        assert_eq!(res_ceil.converted_amount, 4);

        let config_half_up = CrossCurrencyConversionConfig {
            rate_numerator: 1,
            rate_denominator: 3,
            max_discrepancy_bps: 5000,
            rounding_mode: RoundingMode::HalfUp,
        };
        // 1/3 is < 1/2 so half up yields 3
        let res_half_up = convert_with_rounding_safeguards(10, &config_half_up).unwrap();
        assert_eq!(res_half_up.converted_amount, 3);
    }

    #[test]
    fn test_discrepancy_exceeding_tolerance_fails() {
        let config = CrossCurrencyConversionConfig {
            rate_numerator: 1,
            rate_denominator: 3,
            max_discrepancy_bps: 10, // Max 10 bps, but 1/3 is 3333 bps
            rounding_mode: RoundingMode::Floor,
        };

        let res = convert_with_rounding_safeguards(10, &config);
        assert_eq!(
            res,
            Err(RoundingSafeguardError::RoundingDiscrepancyExceedsTolerance)
        );
    }

    #[test]
    fn test_invalid_parameters() {
        let config = CrossCurrencyConversionConfig {
            rate_numerator: 0,
            rate_denominator: 1,
            max_discrepancy_bps: 100,
            rounding_mode: RoundingMode::Floor,
        };
        assert_eq!(
            convert_with_rounding_safeguards(100, &config),
            Err(RoundingSafeguardError::InvalidExchangeRate)
        );

        let config_valid = CrossCurrencyConversionConfig {
            rate_numerator: 1,
            rate_denominator: 1,
            max_discrepancy_bps: 100,
            rounding_mode: RoundingMode::Floor,
        };
        assert_eq!(
            convert_with_rounding_safeguards(-1, &config_valid),
            Err(RoundingSafeguardError::InvalidAmount)
        );
    }

    fn expect_eq<T: core::fmt::Debug + PartialEq>(a: T, b: T) {
        assert_eq!(a, b);
    }
}
