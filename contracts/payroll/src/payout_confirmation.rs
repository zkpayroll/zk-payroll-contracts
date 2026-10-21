//! Privacy-safe, bounded payout-confirmation reconciliation (#784).
//! Caller-supplied receipt references are not independent proof of a transfer.

use soroban_sdk::{contracterror, contracttype, Address, BytesN, Env, Map, Vec};

use crate::ReconciliationStatus;

/// Match the payroll executor's maximum batch size.
pub const MAX_PAYOUT_CONFIRMATIONS: u32 = 50;

/// Expected payout identity; amounts and beneficiaries are opaque references.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPayout {
    pub payout_ref: BytesN<32>,
    pub beneficiary_ref: BytesN<32>,
    pub asset: Address,
    pub amount_ref: BytesN<32>,
}

/// State reported by the source of payout confirmation evidence.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayoutConfirmationStatus {
    Pending,
    Confirmed,
    Failed,
}

/// One confirmation bound to a run, expected payout, and transaction reference.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutConfirmation {
    pub run_id: u64,
    pub payout: ExpectedPayout,
    pub status: PayoutConfirmationStatus,
    pub transaction_ref: BytesN<32>,
    /// Nonzero only for Confirmed, and never after the ledger timestamp.
    pub confirmed_at: u64,
}

/// Aggregate result; missing confirmations count as pending, never as paid.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutReconciliation {
    pub run_id: u64,
    pub expected_count: u32,
    pub confirmed_count: u32,
    pub pending_count: u32,
    pub failed_count: u32,
    pub status: ReconciliationStatus,
}

/// Stable reconciliation validation errors, scoped to issue #784.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayoutConfirmationError {
    InvalidRun = 7840,
    EmptyExpectedPayouts = 7841,
    TooManyPayouts = 7842,
    InvalidReference = 7843,
    DuplicatePayout = 7844,
    UnknownPayout = 7845,
    PayoutMismatch = 7846,
    InvalidConfirmationTime = 7847,
}

/// Read-only contract interface for reconciliation preflight reports.
pub trait PayoutConfirmationValidation {
    /// Match evidence to expected payouts; does not finalize settlement.
    fn reconcile_payout_confirmations(
        env: Env,
        run_id: u64,
        expected: Vec<ExpectedPayout>,
        confirmations: Vec<PayoutConfirmation>,
    ) -> Result<PayoutReconciliation, PayoutConfirmationError>;
}

/// Reconcile confirmations by opaque payout ID, independent of input order.
/// Inputs must be sourced from authoritative payment records and receipts.
pub fn reconcile_payout_confirmations(
    env: &Env,
    run_id: u64,
    expected: &Vec<ExpectedPayout>,
    confirmations: &Vec<PayoutConfirmation>,
) -> Result<PayoutReconciliation, PayoutConfirmationError> {
    if run_id == 0 {
        return Err(PayoutConfirmationError::InvalidRun);
    }
    if expected.is_empty() {
        return Err(PayoutConfirmationError::EmptyExpectedPayouts);
    }
    if expected.len() > MAX_PAYOUT_CONFIRMATIONS || confirmations.len() > MAX_PAYOUT_CONFIRMATIONS {
        return Err(PayoutConfirmationError::TooManyPayouts);
    }
    let mut payouts = Map::<BytesN<32>, ExpectedPayout>::new(env);
    for payout in expected.iter() {
        if payout.payout_ref.to_array() == [0; 32]
            || payout.beneficiary_ref.to_array() == [0; 32]
            || payout.amount_ref.to_array() == [0; 32]
        {
            return Err(PayoutConfirmationError::InvalidReference);
        }
        if payouts.contains_key(payout.payout_ref.clone()) {
            return Err(PayoutConfirmationError::DuplicatePayout);
        }
        payouts.set(payout.payout_ref.clone(), payout);
    }
    let mut seen = Map::<BytesN<32>, bool>::new(env);
    let mut confirmed_count = 0;
    let mut failed_count = 0;
    for confirmation in confirmations.iter() {
        if confirmation.run_id != run_id {
            return Err(PayoutConfirmationError::InvalidRun);
        }
        let id = confirmation.payout.payout_ref.clone();
        if seen.contains_key(id.clone()) {
            return Err(PayoutConfirmationError::DuplicatePayout);
        }
        let payout = payouts
            .get(id.clone())
            .ok_or(PayoutConfirmationError::UnknownPayout)?;
        if payout != confirmation.payout {
            return Err(PayoutConfirmationError::PayoutMismatch);
        }
        seen.set(id, true);
        match confirmation.status {
            PayoutConfirmationStatus::Confirmed => {
                if confirmation.transaction_ref.to_array() == [0; 32] {
                    return Err(PayoutConfirmationError::InvalidReference);
                }
                if confirmation.confirmed_at == 0
                    || confirmation.confirmed_at > env.ledger().timestamp()
                {
                    return Err(PayoutConfirmationError::InvalidConfirmationTime);
                }
                confirmed_count += 1;
            }
            status => {
                if confirmation.confirmed_at != 0 {
                    return Err(PayoutConfirmationError::InvalidConfirmationTime);
                }
                if status == PayoutConfirmationStatus::Failed {
                    failed_count += 1;
                }
            }
        }
    }
    let pending_count = expected.len() - confirmed_count - failed_count;
    let status = if failed_count > 0 {
        ReconciliationStatus::Failed
    } else if pending_count > 0 {
        ReconciliationStatus::Unreconciled
    } else {
        ReconciliationStatus::Reconciled
    };
    Ok(PayoutReconciliation {
        run_id,
        expected_count: expected.len(),
        confirmed_count,
        pending_count,
        failed_count,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        vec,
    };

    fn payout(env: &Env, id: u8) -> ExpectedPayout {
        ExpectedPayout {
            payout_ref: BytesN::from_array(env, &[id; 32]),
            beneficiary_ref: BytesN::from_array(env, &[2; 32]),
            asset: Address::generate(env),
            amount_ref: BytesN::from_array(env, &[3; 32]),
        }
    }
    fn confirmation(env: &Env, payout: ExpectedPayout) -> PayoutConfirmation {
        PayoutConfirmation {
            run_id: 1,
            payout,
            status: PayoutConfirmationStatus::Confirmed,
            transaction_ref: BytesN::from_array(env, &[4; 32]),
            confirmed_at: 100,
        }
    }
    #[test]
    fn confirmed_receipts_reconcile_out_of_order_and_can_share_one_transaction() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let first = payout(&env, 1);
        let second = payout(&env, 2);
        let result = reconcile_payout_confirmations(
            &env,
            1,
            &vec![&env, first.clone(), second.clone()],
            &vec![&env, confirmation(&env, second), confirmation(&env, first)],
        )
        .unwrap();
        assert_eq!(result.status, ReconciliationStatus::Reconciled);
        assert_eq!(
            (
                result.confirmed_count,
                result.pending_count,
                result.failed_count
            ),
            (2, 0, 0)
        );
    }
    #[test]
    fn missing_pending_and_failed_confirmations_are_distinguished() {
        let env = Env::default();
        let expected = payout(&env, 1);
        let inputs = vec![&env, expected.clone()];
        let report = reconcile_payout_confirmations(&env, 1, &inputs, &Vec::new(&env)).unwrap();
        assert_eq!(
            (report.pending_count, report.status),
            (1, ReconciliationStatus::Unreconciled)
        );
        let mut receipt = confirmation(&env, expected);
        receipt.confirmed_at = 0;
        receipt.status = PayoutConfirmationStatus::Pending;
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, receipt.clone()])
                .unwrap()
                .status,
            ReconciliationStatus::Unreconciled
        );
        receipt.status = PayoutConfirmationStatus::Failed;
        let report =
            reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, receipt]).unwrap();
        assert_eq!(
            (report.failed_count, report.pending_count, report.status),
            (1, 0, ReconciliationStatus::Failed)
        );
    }
    #[test]
    fn rejects_duplicates_unknown_payouts_and_cross_run_receipts() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let expected = payout(&env, 1);
        let inputs = vec![&env, expected.clone()];
        let receipt = confirmation(&env, expected.clone());
        assert_eq!(
            reconcile_payout_confirmations(
                &env,
                1,
                &vec![&env, expected.clone(), expected],
                &Vec::new(&env)
            ),
            Err(PayoutConfirmationError::DuplicatePayout)
        );
        assert_eq!(
            reconcile_payout_confirmations(
                &env,
                1,
                &inputs,
                &vec![&env, receipt.clone(), receipt.clone()]
            ),
            Err(PayoutConfirmationError::DuplicatePayout)
        );
        assert_eq!(
            reconcile_payout_confirmations(
                &env,
                1,
                &inputs,
                &vec![&env, confirmation(&env, payout(&env, 9))]
            ),
            Err(PayoutConfirmationError::UnknownPayout)
        );
        let mut wrong = receipt;
        wrong.run_id = 2;
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, wrong]),
            Err(PayoutConfirmationError::InvalidRun)
        );
    }
    #[test]
    fn binds_asset_beneficiary_and_amount_references() {
        let env = Env::default();
        let expected = payout(&env, 1);
        for field in 0..3 {
            let mut receipt = confirmation(&env, expected.clone());
            match field {
                0 => receipt.payout.asset = Address::generate(&env),
                1 => receipt.payout.beneficiary_ref = BytesN::from_array(&env, &[9; 32]),
                _ => receipt.payout.amount_ref = BytesN::from_array(&env, &[9; 32]),
            }
            assert_eq!(
                reconcile_payout_confirmations(
                    &env,
                    1,
                    &vec![&env, expected.clone()],
                    &vec![&env, receipt]
                ),
                Err(PayoutConfirmationError::PayoutMismatch)
            );
        }
    }
    #[test]
    fn validates_references_and_confirmation_timestamps() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let expected = payout(&env, 1);
        let inputs = vec![&env, expected.clone()];
        for at in [0, 101] {
            let mut receipt = confirmation(&env, expected.clone());
            receipt.confirmed_at = at;
            assert_eq!(
                reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, receipt]),
                Err(PayoutConfirmationError::InvalidConfirmationTime)
            );
        }
        let mut receipt = confirmation(&env, expected.clone());
        receipt.status = PayoutConfirmationStatus::Pending;
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, receipt]),
            Err(PayoutConfirmationError::InvalidConfirmationTime)
        );
        let mut receipt = confirmation(&env, expected);
        receipt.transaction_ref = BytesN::from_array(&env, &[0; 32]);
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &inputs, &vec![&env, receipt]),
            Err(PayoutConfirmationError::InvalidReference)
        );
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &vec![&env, payout(&env, 0)], &Vec::new(&env)),
            Err(PayoutConfirmationError::InvalidReference)
        );
    }
    #[test]
    fn rejects_zero_run_empty_expectations_and_unbounded_input() {
        let env = Env::default();
        let empty = Vec::new(&env);
        assert_eq!(
            reconcile_payout_confirmations(&env, 0, &empty, &Vec::new(&env)),
            Err(PayoutConfirmationError::InvalidRun)
        );
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &empty, &Vec::new(&env)),
            Err(PayoutConfirmationError::EmptyExpectedPayouts)
        );
        let mut too_many = Vec::new(&env);
        for _ in 0..=MAX_PAYOUT_CONFIRMATIONS {
            too_many.push_back(payout(&env, 1));
        }
        assert_eq!(
            reconcile_payout_confirmations(&env, 1, &too_many, &Vec::new(&env)),
            Err(PayoutConfirmationError::TooManyPayouts)
        );
    }
}
