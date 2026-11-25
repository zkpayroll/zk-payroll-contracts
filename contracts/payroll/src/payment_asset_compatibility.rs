//! Contract payment asset compatibility validation (#646).
//!
//! A payroll run can only be funded by the contract's canonical treasury
//! asset, and only while that asset is allowed and not deprecated. This
//! module turns those scattered checks into one read-only preflight with
//! typed, actionable errors, and adds an optional precision guard: the admin
//! may pin the number of decimals payroll amounts are denominated in, so a
//! token whose precision does not match is rejected before any funds move.
//!
//! The check reads only configuration and the token's public metadata. It
//! never inspects salary amounts or employee rows.

use soroban_sdk::{contracterror, contractevent, contractimpl, contracttype, token, Address, Env};

use crate::{ContractAddresses, DataKey, Payroll, PayrollArgs, PayrollClient};

/// Highest precision accepted for a pinned payment asset.
pub const MAX_PAYMENT_ASSET_DECIMALS: u32 = 18;

/// Storage key for payment asset compatibility configuration.
///
/// Kept separate from [`DataKey`], which is past the Soroban contract-spec
/// ceiling of 50 cases.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentAssetKey {
    /// Decimals payroll amounts are denominated in. Absent means unpinned.
    ExpectedDecimals,
}

/// Result of a successful payment asset compatibility check.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAssetCompatibility {
    /// Asset that was checked; always the canonical treasury asset.
    pub asset: Address,
    /// Amount the caller intends to pay in this asset.
    pub amount: i128,
    /// Decimals pinned by the admin, if any.
    pub expected_decimals: Option<u32>,
    /// Decimals reported by the token. Only read when a precision is pinned.
    pub asset_decimals: Option<u32>,
}

/// Errors returned by payment asset compatibility validation (#646).
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PaymentAssetCompatibilityError {
    /// Payroll has not been initialized, so no payment asset is configured.
    NotInitialized = 6460,
    /// The asset is not this contract's canonical treasury asset. Pay with
    /// the asset returned by `get_addresses().token`.
    ForeignAsset = 6461,
    /// The canonical asset is not allowed for payouts. Ask the admin to call
    /// `set_asset_allowed(asset, true)`.
    AssetNotAllowed = 6462,
    /// The asset is deprecated and accepts no new payroll commitments. Ask
    /// the admin to call `undeprecate_asset` or migrate the asset.
    AssetDeprecated = 6463,
    /// The payment amount must be greater than zero.
    NonPositiveAmount = 6464,
    /// The token did not answer a `decimals` query, so its precision cannot
    /// be confirmed against the pinned value.
    AssetUnreachable = 6465,
    /// The token's decimals differ from the precision pinned by the admin.
    /// Amounts would be scaled incorrectly; fix the pin or the asset.
    DecimalsMismatch = 6466,
    /// The requested precision is above [`MAX_PAYMENT_ASSET_DECIMALS`].
    InvalidDecimals = 6467,
    /// The caller is not the configured payroll admin.
    Unauthorized = 6468,
}

/// Emitted as `("payroll", "asset_precision_set")` when the admin pins or
/// clears the expected payment asset precision.
#[contractevent(topics = ["payroll", "asset_precision_set"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentAssetPrecisionSet {
    /// Newly pinned decimals, or `None` when the pin was cleared.
    pub decimals: Option<u32>,
    /// Ledger timestamp of the change.
    pub updated_at: u64,
}

fn load_addresses(e: &Env) -> Result<ContractAddresses, PaymentAssetCompatibilityError> {
    e.storage()
        .persistent()
        .get(&DataKey::Addresses)
        .ok_or(PaymentAssetCompatibilityError::NotInitialized)
}

fn require_admin(e: &Env, admin: &Address) -> Result<(), PaymentAssetCompatibilityError> {
    let addrs = load_addresses(e)?;
    if admin != &addrs.admin {
        return Err(PaymentAssetCompatibilityError::Unauthorized);
    }
    admin.require_auth();
    Ok(())
}

pub(crate) fn expected_decimals(e: &Env) -> Option<u32> {
    e.storage()
        .persistent()
        .get(&PaymentAssetKey::ExpectedDecimals)
}

/// Compare the token's reported precision against the admin's pin.
///
/// Returns the token's decimals when a pin exists, and `None` when the
/// precision is unpinned (the token is not queried in that case).
fn check_precision(
    e: &Env,
    asset: &Address,
) -> Result<Option<u32>, PaymentAssetCompatibilityError> {
    let Some(expected) = expected_decimals(e) else {
        return Ok(None);
    };
    let actual = match token::Client::new(e, asset).try_decimals() {
        Ok(Ok(decimals)) => decimals,
        _ => return Err(PaymentAssetCompatibilityError::AssetUnreachable),
    };
    if actual != expected {
        return Err(PaymentAssetCompatibilityError::DecimalsMismatch);
    }
    Ok(Some(actual))
}

/// Run every compatibility rule for `asset` and `amount`.
///
/// Rules are applied in a fixed order so the same input always yields the
/// same error: identity, allowlist, deprecation, amount, then precision.
pub fn evaluate_payment_asset_compatibility(
    e: &Env,
    asset: &Address,
    amount: i128,
) -> Result<PaymentAssetCompatibility, PaymentAssetCompatibilityError> {
    let addrs = load_addresses(e)?;
    if asset != &addrs.token {
        return Err(PaymentAssetCompatibilityError::ForeignAsset);
    }
    if !Payroll::is_asset_allowed(e.clone(), asset.clone()) {
        return Err(PaymentAssetCompatibilityError::AssetNotAllowed);
    }
    if Payroll::is_asset_deprecated(e.clone(), asset.clone()) {
        return Err(PaymentAssetCompatibilityError::AssetDeprecated);
    }
    if amount <= 0 {
        return Err(PaymentAssetCompatibilityError::NonPositiveAmount);
    }
    let asset_decimals = check_precision(e, asset)?;
    Ok(PaymentAssetCompatibility {
        asset: asset.clone(),
        amount,
        expected_decimals: expected_decimals(e),
        asset_decimals,
    })
}

/// Execution-path guard used by `prepare_payroll_run`.
///
/// Only the precision rule is enforced here; identity, allowlist, and
/// deprecation are already checked by the run preparation flow with their
/// existing messages. A no-op while no precision is pinned.
pub(crate) fn require_compatible_precision(e: &Env, asset: &Address) {
    match check_precision(e, asset) {
        Ok(_) => {}
        Err(PaymentAssetCompatibilityError::AssetUnreachable) => panic!(
            "Payment asset precision unavailable: the token did not report its decimals"
        ),
        Err(_) => panic!(
            "Payment asset precision mismatch: token decimals differ from the pinned payroll precision"
        ),
    }
}

#[contractimpl]
impl Payroll {
    /// Pin the decimals payroll amounts are denominated in (#646).
    ///
    /// Once pinned, `check_payment_asset_compat` and
    /// `prepare_payroll_run` reject a payment asset whose token reports a
    /// different precision. Admin only.
    pub fn set_payment_asset_decimals(
        e: Env,
        admin: Address,
        decimals: u32,
    ) -> Result<(), PaymentAssetCompatibilityError> {
        require_admin(&e, &admin)?;
        if decimals > MAX_PAYMENT_ASSET_DECIMALS {
            return Err(PaymentAssetCompatibilityError::InvalidDecimals);
        }
        e.storage()
            .persistent()
            .set(&PaymentAssetKey::ExpectedDecimals, &decimals);
        PaymentAssetPrecisionSet {
            decimals: Some(decimals),
            updated_at: e.ledger().timestamp(),
        }
        .publish(&e);
        Ok(())
    }

    /// Remove the pinned payment asset precision (#646). Admin only.
    pub fn clear_payment_asset_decimals(
        e: Env,
        admin: Address,
    ) -> Result<(), PaymentAssetCompatibilityError> {
        require_admin(&e, &admin)?;
        e.storage()
            .persistent()
            .remove(&PaymentAssetKey::ExpectedDecimals);
        PaymentAssetPrecisionSet {
            decimals: None,
            updated_at: e.ledger().timestamp(),
        }
        .publish(&e);
        Ok(())
    }

    /// Return the pinned payment asset precision, if any (#646).
    pub fn get_payment_asset_decimals(e: Env) -> Option<u32> {
        expected_decimals(&e)
    }

    /// Read-only preflight: can `amount` be paid in `asset` (#646)?
    ///
    /// Returns the checked configuration on success, or the first rule the
    /// asset fails as a typed [`PaymentAssetCompatibilityError`].
    pub fn check_payment_asset_compat(
        e: Env,
        asset: Address,
        amount: i128,
    ) -> Result<PaymentAssetCompatibility, PaymentAssetCompatibilityError> {
        evaluate_payment_asset_compatibility(&e, &asset, amount)
    }
}
