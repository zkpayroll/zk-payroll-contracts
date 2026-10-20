//! Read-only validation entrypoints. No salary values, events, or state writes.

use soroban_sdk::{contractimpl, Env, Vec};

use crate::ledger_export::{
    self, LedgerExportError, LedgerExportValidation, LedgerExportVerification,
};
use crate::pay_group_effective_date::{
    self, PayGroupDateError, PayGroupEffectivePeriod, PayGroupValidation,
};
use crate::payout_confirmation::{
    self, ExpectedPayout, PayoutConfirmation, PayoutConfirmationError,
    PayoutConfirmationValidation, PayoutReconciliation,
};
use crate::ConfigLedgerEntry;
use crate::Payroll;

#[contractimpl]
impl PayGroupValidation for Payroll {
    fn validate_pay_group_dates(
        env: Env,
        proposed: PayGroupEffectivePeriod,
        existing: Vec<PayGroupEffectivePeriod>,
    ) -> Result<(), PayGroupDateError> {
        pay_group_effective_date::validate_pay_group_dates(&env, &proposed, &existing)
    }

    fn check_pay_group_effective(
        env: Env,
        period: PayGroupEffectivePeriod,
    ) -> Result<(), PayGroupDateError> {
        pay_group_effective_date::check_pay_group_effective(&env, &period)
    }
}

#[contractimpl]
impl PayoutConfirmationValidation for Payroll {
    fn reconcile_payout_confirmations(
        env: Env,
        run_id: u64,
        expected: Vec<ExpectedPayout>,
        confirmations: Vec<PayoutConfirmation>,
    ) -> Result<PayoutReconciliation, PayoutConfirmationError> {
        payout_confirmation::reconcile_payout_confirmations(&env, run_id, &expected, &confirmations)
    }
}

#[contractimpl]
impl LedgerExportVerification for Payroll {
    fn validate_ledger_export(
        env: Env,
        first_revision: u64,
        last_revision: u64,
        entries: Vec<ConfigLedgerEntry>,
    ) -> Result<LedgerExportValidation, LedgerExportError> {
        let count = ledger_export::ledger_export_count(first_revision, last_revision)?;
        let canonical = crate::config_audit::get_config_ledger(&env, first_revision, count);
        ledger_export::validate_ledger_export(
            &env,
            first_revision,
            last_revision,
            &entries,
            &canonical,
        )
    }
}
