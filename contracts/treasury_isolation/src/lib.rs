#![no_std]

//! # Cross-Asset Treasury Isolation — Issue #317
//!
//! Guarantees that payroll batches funded in one Stellar asset cannot consume,
//! reserve, or reconcile balances from another asset.
//!
//! ## Design
//!
//! Treasury balances, per-company asset reserves, and payroll commitments are
//! all keyed by a **canonical asset identifier** — the `Address` of the token
//! contract on Stellar. The isolation contract:
//!
//!   - Maintains a per-(company, asset) balance ledger.
//!   - Rejects execution when the committed asset ≠ the treasury asset.
//!   - Prevents registering two asset entries with the same issuer address but
//!     different parameter/contract addresses (issuer-mismatch guard).
//!   - Emits asset-specific events for every reserve, release, and execution so
//!     that off-chain indexers can reconcile per-asset without ambiguity.
//!
//! No salary amounts or employee data flow through this contract — it is a
//! purely structural accounting layer.

use pause_manager::PauseManagerClient;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed errors returned by the treasury isolation contract.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TreasuryIsolationError {
    /// The contract has not been initialised.
    NotInitialized = 1,
    /// The asset is not registered for this company.
    AssetNotRegistered = 2,
    /// The asset is already registered for this company.
    AssetAlreadyRegistered = 3,
    /// Execution was attempted with an asset that differs from the committed asset.
    AssetMismatch = 4,
    /// The reserved amount exceeds the registered balance.
    InsufficientBalance = 5,
    /// Attempted to release more than is currently reserved.
    InsufficientReserve = 6,
    /// The caller is not authorised to perform this operation.
    Unauthorized = 7,
    /// An asset with the same issuer address is already registered under a
    /// different token contract address (issuer-mismatch guard).
    IssuerMismatch = 8,
    /// The amount supplied is not positive.
    InvalidAmount = 9,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Per-(company, asset) balance and reserve record.
///
/// `balance`  — total amount credited to this company for this asset.
/// `reserved` — sub-set of `balance` earmarked for in-flight payroll batches.
///
/// `available = balance - reserved` is what can be newly reserved.
/// Privacy note: this reflects token-unit accounting only; no employee or
/// salary data is stored here.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AssetBalance {
    /// Token contract address (canonical asset identifier).
    pub asset: Address,
    /// Total credited balance in raw token units.
    pub balance: i128,
    /// Amount currently reserved for in-flight payroll batches.
    pub reserved: i128,
}

/// Canonical registration record for an asset under a company.
///
/// `issuer` is stored separately from `asset` (the token contract address)
/// so we can detect issuer-mismatch collisions without a cross-contract call.
/// For native XLM, `issuer` equals the well-known XLM contract address.
#[contracttype]
#[derive(Clone, Debug)]
pub struct RegisteredAsset {
    /// Token contract address — the canonical key for asset operations.
    pub asset: Address,
    /// Issuer address associated with this asset. Used for mismatch detection.
    pub issuer: Address,
    /// Human-readable asset symbol (e.g. `"USDC"`, `"XLM"`). For indexing only.
    pub symbol: Symbol,
    /// Ledger timestamp of registration.
    pub registered_at: u64,
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Admin address for this contract.
    Admin,
    /// Optional pause manager.
    PauseManager,
    /// `AssetBalance` keyed by (company_id, asset).
    Balance(u64, Address),
    /// `RegisteredAsset` keyed by (company_id, asset).
    RegisteredAsset(u64, Address),
    /// Reverse-lookup: issuer → canonical asset address (per company).
    /// Used to enforce the issuer-mismatch invariant.
    IssuerIndex(u64, Address),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct TreasuryIsolationContract;

#[contractimpl]
impl TreasuryIsolationContract {
    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Initialise the contract. One-time call.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        payroll_events::emit_treasury_isolation_initialized(&env, admin);
    }

    /// Set or replace the pause manager. Only the admin may call.
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
    }

    // -----------------------------------------------------------------------
    // Asset registration
    // -----------------------------------------------------------------------

    /// Register an asset for a company treasury.
    ///
    /// Each company may register multiple assets (e.g. USDC and XLM), but each
    /// asset contract address may only be registered once per company. A
    /// duplicate issuer address under a different token contract address is also
    /// rejected to prevent issuer-mismatch confusion.
    pub fn register_asset(
        env: Env,
        company_id: u64,
        asset: Address,
        issuer: Address,
        symbol: Symbol,
    ) -> Result<RegisteredAsset, TreasuryIsolationError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let reg_key = DataKey::RegisteredAsset(company_id, asset.clone());
        if env.storage().persistent().has(&reg_key) {
            return Err(TreasuryIsolationError::AssetAlreadyRegistered);
        }

        // Issuer-mismatch guard: reject if another asset is already registered
        // for the same issuer under this company.
        let issuer_key = DataKey::IssuerIndex(company_id, issuer.clone());
        if let Some(existing_asset) = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&issuer_key)
        {
            if existing_asset != asset {
                return Err(TreasuryIsolationError::IssuerMismatch);
            }
        }

        let now = env.ledger().timestamp();
        let record = RegisteredAsset {
            asset: asset.clone(),
            issuer: issuer.clone(),
            symbol: symbol.clone(),
            registered_at: now,
        };

        env.storage().persistent().set(&reg_key, &record);
        env.storage().persistent().set(&issuer_key, &asset);

        // Initialise balance record at zero.
        let bal_key = DataKey::Balance(company_id, asset.clone());
        let initial = AssetBalance {
            asset: asset.clone(),
            balance: 0,
            reserved: 0,
        };
        env.storage().persistent().set(&bal_key, &initial);

        payroll_events::emit_treasury_asset_registered(&env, company_id, asset, issuer, symbol);

        Ok(record)
    }

    // -----------------------------------------------------------------------
    // Balance management
    // -----------------------------------------------------------------------

    /// Credit `amount` to the (company, asset) balance.
    ///
    /// The actual token transfer must happen externally (via the token contract).
    /// This function only records the accounting entry. Admin-only.
    pub fn credit(
        env: Env,
        company_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<AssetBalance, TreasuryIsolationError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        Self::validate_positive_amount(amount)?;

        let mut bal = Self::load_balance(&env, company_id, &asset)?;
        bal.balance += amount;
        Self::save_balance(&env, company_id, &bal);

        payroll_events::emit_treasury_credited(&env, company_id, asset, amount);

        Ok(bal)
    }

    /// Reserve `amount` from the available balance for an in-flight batch.
    ///
    /// `available = balance - reserved` must be ≥ `amount`.
    /// Asset-scoped: a USDC reserve cannot draw on an XLM balance.
    pub fn reserve(
        env: Env,
        company_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<AssetBalance, TreasuryIsolationError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        Self::validate_positive_amount(amount)?;

        let mut bal = Self::load_balance(&env, company_id, &asset)?;
        let available = bal.balance - bal.reserved;
        if available < amount {
            return Err(TreasuryIsolationError::InsufficientBalance);
        }

        bal.reserved += amount;
        Self::save_balance(&env, company_id, &bal);

        payroll_events::emit_treasury_reserved(&env, company_id, asset, amount);

        Ok(bal)
    }

    /// Release a previously reserved amount (e.g. after cancellation).
    ///
    /// Validation is strict: the asset must exist for the company and the release
    /// request cannot exceed the currently reserved amount. Releasing exactly the
    /// reserved amount is valid and clears the reservation.
    pub fn release_reserve(
        env: Env,
        company_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<AssetBalance, TreasuryIsolationError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        Self::validate_positive_amount(amount)?;

        let mut bal = Self::load_balance(&env, company_id, &asset)?;
        if bal.reserved < amount {
            return Err(TreasuryIsolationError::InsufficientReserve);
        }

        bal.reserved -= amount;
        Self::save_balance(&env, company_id, &bal);

        payroll_events::emit_treasury_reserve_released(&env, company_id, asset, amount);

        Ok(bal)
    }

    /// Debit `amount` from balance (and reserved) on successful execution.
    ///
    /// Validates that `committed_asset == treasury_asset` before proceeding —
    /// this is the cross-asset isolation check. Returns `AssetMismatch` if the
    /// assets differ.
    pub fn execute_debit(
        env: Env,
        company_id: u64,
        committed_asset: Address,
        treasury_asset: Address,
        amount: i128,
    ) -> Result<AssetBalance, TreasuryIsolationError> {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        // Core isolation invariant: the asset committed to the payroll batch
        // must exactly match the treasury asset being debited.
        if committed_asset != treasury_asset {
            return Err(TreasuryIsolationError::AssetMismatch);
        }

        Self::validate_positive_amount(amount)?;

        let mut bal = Self::load_balance(&env, company_id, &treasury_asset)?;
        if bal.balance < amount {
            return Err(TreasuryIsolationError::InsufficientBalance);
        }
        if bal.reserved < amount {
            return Err(TreasuryIsolationError::InsufficientReserve);
        }

        bal.balance -= amount;
        bal.reserved -= amount;
        Self::save_balance(&env, company_id, &bal);

        payroll_events::emit_treasury_debited(&env, company_id, treasury_asset, amount);

        Ok(bal)
    }

    // -----------------------------------------------------------------------
    // Readiness check
    // -----------------------------------------------------------------------

    /// Return whether the treasury is ready to execute a payroll batch of
    /// `required_amount` for a specific asset.
    ///
    /// "Ready" means:
    ///   1. The asset is registered for the company.
    ///   2. `balance - reserved >= required_amount`.
    pub fn is_treasury_ready(
        env: Env,
        company_id: u64,
        asset: Address,
        required_amount: i128,
    ) -> bool {
        let bal_key = DataKey::Balance(company_id, asset);
        match env
            .storage()
            .persistent()
            .get::<DataKey, AssetBalance>(&bal_key)
        {
            Some(bal) => (bal.balance - bal.reserved) >= required_amount,
            None => false,
        }
    }

    // -----------------------------------------------------------------------
    // Read-only queries
    // -----------------------------------------------------------------------

    /// Return the balance record for (company, asset), or `None`.
    pub fn get_balance(env: Env, company_id: u64, asset: Address) -> Option<AssetBalance> {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(company_id, asset))
    }

    /// Return the registered asset record for (company, asset), or `None`.
    pub fn get_registered_asset(
        env: Env,
        company_id: u64,
        asset: Address,
    ) -> Option<RegisteredAsset> {
        env.storage()
            .persistent()
            .get(&DataKey::RegisteredAsset(company_id, asset))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn validate_positive_amount(amount: i128) -> Result<(), TreasuryIsolationError> {
        if amount <= 0 {
            return Err(TreasuryIsolationError::InvalidAmount);
        }
        Ok(())
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        admin.require_auth();
    }

    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let client = PauseManagerClient::new(env, &addr);
            if client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    fn load_balance(
        env: &Env,
        company_id: u64,
        asset: &Address,
    ) -> Result<AssetBalance, TreasuryIsolationError> {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(company_id, asset.clone()))
            .ok_or(TreasuryIsolationError::AssetNotRegistered)
    }

    fn save_balance(env: &Env, company_id: u64, bal: &AssetBalance) {
        env.storage()
            .persistent()
            .set(&DataKey::Balance(company_id, bal.asset.clone()), bal);
    }
}

// ---------------------------------------------------------------------------
// Tests — Issue #317
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{symbol_short, Env};

    fn setup() -> (Env, Address, soroban_sdk::Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TreasuryIsolationContract);
        let admin = Address::generate(&env);
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        (env, contract_id, admin)
    }

    #[test]
    fn test_register_asset_and_credit() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let sym = symbol_short!("USDC");
        let company_id = 1u64;

        client.register_asset(&company_id, &asset, &issuer, &sym);
        let bal = client.credit(&company_id, &asset, &5000i128);
        assert_eq!(bal.balance, 5000);
        assert_eq!(bal.reserved, 0);
    }

    #[test]
    fn test_reserve_and_release() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let sym = symbol_short!("USDC");
        let company_id = 2u64;

        client.register_asset(&company_id, &asset, &issuer, &sym);
        client.credit(&company_id, &asset, &10_000i128);
        let after_reserve = client.reserve(&company_id, &asset, &3000i128);
        assert_eq!(after_reserve.reserved, 3000);

        let after_release = client.release_reserve(&company_id, &asset, &1000i128);
        assert_eq!(after_release.reserved, 2000);
    }

    #[test]
    fn test_release_reserve_invalid_amount_rejected() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 2u64;

        client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
        client.credit(&company_id, &asset, &10_000i128);
        client.reserve(&company_id, &asset, &500i128);

        let result = client.try_release_reserve(&company_id, &asset, &0i128);
        assert_eq!(result.unwrap_err().unwrap(), TreasuryIsolationError::InvalidAmount);

        let over_release = client.try_release_reserve(&company_id, &asset, &1_000i128);
        assert_eq!(
            over_release.unwrap_err().unwrap(),
            TreasuryIsolationError::InsufficientReserve
        );
    }

    #[test]
    fn test_release_reserve_exact_amount_clears_reservation() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 3u64;

        client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
        client.credit(&company_id, &asset, &10_000i128);
        client.reserve(&company_id, &asset, &2_500i128);

        let after_release = client.release_reserve(&company_id, &asset, &2_500i128);
        assert_eq!(after_release.reserved, 0);
    }

    #[test]
    fn test_execute_debit_asset_mismatch_rejected() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let usdc = Address::generate(&env);
        let xlm = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 3u64;

        client.register_asset(&company_id, &usdc, &issuer, &symbol_short!("USDC"));
        client.credit(&company_id, &usdc, &10_000i128);
        client.reserve(&company_id, &usdc, &5000i128);

        // Attempt to debit USDC treasury using XLM as committed_asset
        let result = client.try_execute_debit(&company_id, &xlm, &usdc, &5000i128);
        assert_eq!(
            result.unwrap_err().unwrap(),
            TreasuryIsolationError::AssetMismatch
        );
    }

    #[test]
    fn test_execute_debit_success() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let usdc = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 4u64;

        client.register_asset(&company_id, &usdc, &issuer, &symbol_short!("USDC"));
        client.credit(&company_id, &usdc, &10_000i128);
        client.reserve(&company_id, &usdc, &5000i128);

        let bal = client.execute_debit(&company_id, &usdc, &usdc, &5000i128);
        assert_eq!(bal.balance, 5000);
        assert_eq!(bal.reserved, 0);
    }

    #[test]
    fn test_issuer_mismatch_rejected() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset1 = Address::generate(&env);
        let asset2 = Address::generate(&env); // Different contract, same issuer
        let issuer = Address::generate(&env);
        let company_id = 5u64;

        client.register_asset(&company_id, &asset1, &issuer, &symbol_short!("USDC"));

        // Registering asset2 with the same issuer should fail
        let result =
            client.try_register_asset(&company_id, &asset2, &issuer, &symbol_short!("USDC"));
        assert_eq!(
            result.unwrap_err().unwrap(),
            TreasuryIsolationError::IssuerMismatch
        );
    }

    #[test]
    fn test_insufficient_balance_reserve_rejected() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 6u64;

        client.register_asset(&company_id, &asset, &issuer, &symbol_short!("XLM"));
        client.credit(&company_id, &asset, &100i128);

        let result = client.try_reserve(&company_id, &asset, &500i128);
        assert_eq!(
            result.unwrap_err().unwrap(),
            TreasuryIsolationError::InsufficientBalance
        );
    }

    #[test]
    fn test_unregistered_asset_credit_rejected() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let company_id = 7u64;

        let result = client.try_credit(&company_id, &asset, &1000i128);
        assert_eq!(
            result.unwrap_err().unwrap(),
            TreasuryIsolationError::AssetNotRegistered
        );
    }

    #[test]
    fn test_is_treasury_ready() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let asset = Address::generate(&env);
        let issuer = Address::generate(&env);
        let company_id = 8u64;

        client.register_asset(&company_id, &asset, &issuer, &symbol_short!("USDC"));
        assert!(!client.is_treasury_ready(&company_id, &asset, &1000i128));

        client.credit(&company_id, &asset, &2000i128);
        assert!(client.is_treasury_ready(&company_id, &asset, &1000i128));
        assert!(!client.is_treasury_ready(&company_id, &asset, &3000i128));
    }

    #[test]
    fn test_native_xlm_and_issued_asset_isolated() {
        let (env, contract_id, _) = setup();
        let client = TreasuryIsolationContractClient::new(&env, &contract_id);
        let xlm = Address::generate(&env);
        let usdc = Address::generate(&env);
        let xlm_issuer = Address::generate(&env);
        let usdc_issuer = Address::generate(&env);
        let company_id = 9u64;

        client.register_asset(&company_id, &xlm, &xlm_issuer, &symbol_short!("XLM"));
        client.register_asset(&company_id, &usdc, &usdc_issuer, &symbol_short!("USDC"));

        client.credit(&company_id, &xlm, &50_000i128);
        client.credit(&company_id, &usdc, &20_000i128);

        // XLM reserve should not affect USDC available
        client.reserve(&company_id, &xlm, &40_000i128);
        assert!(client.is_treasury_ready(&company_id, &usdc, &20_000i128));

        // Debit XLM using USDC committed_asset — must fail
        let result = client.try_execute_debit(&company_id, &usdc, &xlm, &1000i128);
        assert_eq!(
            result.unwrap_err().unwrap(),
            TreasuryIsolationError::AssetMismatch
        );
    }
}
