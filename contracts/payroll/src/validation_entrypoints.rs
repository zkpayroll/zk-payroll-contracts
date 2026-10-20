//! Read-only validation entrypoints. No salary values, events, or state writes.

use soroban_sdk::{contractimpl, Env, Vec};

use crate::pay_group_effective_date::{
    self, PayGroupDateError, PayGroupEffectivePeriod, PayGroupValidation,
};
use crate::payout_confirmation::{
    self, ExpectedPayout, PayoutConfirmation, PayoutConfirmationError,
    PayoutConfirmationValidation, PayoutReconciliation,
};
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
