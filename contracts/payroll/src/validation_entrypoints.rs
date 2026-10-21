//! Read-only validation entrypoints. No salary values, events, or state writes.

use soroban_sdk::{contractimpl, Env, Vec};

use crate::beneficiary_verification::{
    self, BeneficiaryStatusValidation, BeneficiaryVerification, BeneficiaryVerificationError,
};
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
use crate::{Payroll, PayrollArgs, PayrollClient};

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

#[contractimpl]
impl BeneficiaryStatusValidation for Payroll {
    fn check_beneficiary_status(
        env: Env,
        beneficiary: soroban_sdk::Address,
        verification: Option<BeneficiaryVerification>,
    ) -> Result<(), BeneficiaryVerificationError> {
        beneficiary_verification::check_beneficiary_status(
            &env,
            &beneficiary,
            verification.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beneficiary_verification::BeneficiaryVerificationStatus;
    use crate::payout_confirmation::PayoutConfirmationStatus;
    use crate::{DataKey, ReconciliationStatus};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        vec, Address, BytesN, Symbol,
    };

    #[test]
    fn pay_group_methods_are_available_through_the_contract_client() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let id = env.register(Payroll, ());
        let client = PayrollClient::new(&env, &id);
        let period = PayGroupEffectivePeriod {
            group_ref: BytesN::from_array(&env, &[1; 32]),
            effective_from: 100,
            effective_until: 200,
        };
        client.validate_pay_group_dates(&period, &Vec::new(&env));
        client.check_pay_group_effective(&period);
        env.ledger().with_mut(|li| li.timestamp = 200);
        assert_eq!(
            client.try_check_pay_group_effective(&period),
            Err(Ok(PayGroupDateError::Expired))
        );
    }

    #[test]
    fn payout_report_is_available_through_the_contract_client() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let id = env.register(Payroll, ());
        let client = PayrollClient::new(&env, &id);
        let payout = ExpectedPayout {
            payout_ref: BytesN::from_array(&env, &[1; 32]),
            beneficiary_ref: BytesN::from_array(&env, &[2; 32]),
            asset: Address::generate(&env),
            amount_ref: BytesN::from_array(&env, &[3; 32]),
        };
        let receipt = PayoutConfirmation {
            run_id: 1,
            payout: payout.clone(),
            status: PayoutConfirmationStatus::Confirmed,
            transaction_ref: BytesN::from_array(&env, &[4; 32]),
            confirmed_at: 100,
        };
        let report =
            client.reconcile_payout_confirmations(&1, &vec![&env, payout], &vec![&env, receipt]);
        assert_eq!(report.status, ReconciliationStatus::Reconciled);
        assert_eq!(report.confirmed_count, 1);
    }

    #[test]
    fn ledger_entrypoint_reads_the_expected_records_from_storage() {
        let env = Env::default();
        let id = env.register(Payroll, ());
        let client = PayrollClient::new(&env, &id);
        let entry = ConfigLedgerEntry {
            key: Symbol::new(&env, "capacity_limits"),
            actor: Address::generate(&env),
            subject_ref: BytesN::from_array(&env, &[1; 32]),
            previous_ref: BytesN::from_array(&env, &[2; 32]),
            new_ref: BytesN::from_array(&env, &[3; 32]),
            revision: 1,
            ledger_sequence: 100,
            timestamp: 1000,
        };
        let page = vec![&env, entry.clone()];
        assert_eq!(
            client.try_validate_ledger_export(&1, &1, &page),
            Err(Ok(LedgerExportError::CanonicalEntryMissing))
        );
        env.as_contract(&id, || {
            env.storage()
                .persistent()
                .set(&DataKey::ConfigRevision, &1_u64);
            env.storage()
                .persistent()
                .set(&DataKey::ConfigLedgerEntry(1), &entry);
        });
        let validated = client.validate_ledger_export(&1, &1, &page);
        assert_eq!(validated.entry_count, 1);
        let mut tampered = entry;
        tampered.timestamp += 1;
        assert_eq!(
            client.try_validate_ledger_export(&1, &1, &vec![&env, tampered]),
            Err(Ok(LedgerExportError::EntryMismatch))
        );
        // Appending later revisions does not invalidate a historical export.
        env.as_contract(&id, || {
            env.storage()
                .persistent()
                .set(&DataKey::ConfigRevision, &2_u64)
        });
        assert_eq!(client.validate_ledger_export(&1, &1, &page), validated);
    }

    #[test]
    fn beneficiary_status_is_checked_through_the_contract_client() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let id = env.register(Payroll, ());
        let client = PayrollClient::new(&env, &id);
        let beneficiary = Address::generate(&env);
        let record = BeneficiaryVerification {
            beneficiary: beneficiary.clone(),
            status: BeneficiaryVerificationStatus::Verified,
            evidence_ref: BytesN::from_array(&env, &[1; 32]),
            verified_at: 100,
            expires_at: 200,
        };
        client.check_beneficiary_status(&beneficiary, &Some(record));
        assert_eq!(
            client.try_check_beneficiary_status(&beneficiary, &None),
            Err(Ok(BeneficiaryVerificationError::MissingVerification))
        );
    }
}
