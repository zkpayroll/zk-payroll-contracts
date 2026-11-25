//! Issue #1085: payout amount precision and rounding validation.
//!
//! Covers the read-only preflights, the checked aggregation used by the
//! execution path, boundary values, and the privacy-safe event emitted when a
//! batch passes validation.

mod common;

use payroll::{PayoutPrecisionError, PayoutRoundingMode, Payroll, PayrollClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    vec,
    xdr::ContractEventBody,
    Address, BytesN, Env, IntoVal, Symbol, TryFromVal, TryIntoVal, Val, Vec,
};

fn client(env: &Env) -> PayrollClient<'_> {
    let id = env.register(Payroll, ());
    PayrollClient::new(env, &id)
}

#[test]
fn exact_pro_rata_payout_is_available_through_the_client() {
    let env = Env::default();
    let payroll = client(&env);
    let assessment =
        payroll.check_payout_precision(&1_000_000, &1, &4, &7, &0, &PayoutRoundingMode::Floor);
    assert_eq!(assessment.rounded_amount, 250_000);
    assert_eq!(assessment.rounding_delta, 0);
    assert_eq!(assessment.drift_bps, 0);
    assert_eq!(assessment.decimals, 7);
}

#[test]
fn floor_and_half_up_rounding_have_explicit_drift() {
    let env = Env::default();
    let payroll = client(&env);

    let floor =
        payroll.check_payout_precision(&1_000_003, &1, &4, &7, &7_500, &PayoutRoundingMode::Floor);
    assert_eq!(floor.rounded_amount, 250_000);
    assert_eq!(floor.rounding_delta, -3);
    assert_eq!(floor.drift_bps, 7_500);

    let half_up =
        payroll.check_payout_precision(&1_001, &1, &2, &7, &5_000, &PayoutRoundingMode::HalfUp);
    assert_eq!(half_up.rounded_amount, 501);
    assert_eq!(half_up.rounding_delta, 1);
    assert_eq!(half_up.drift_bps, 5_000);
}

#[test]
fn unrepresentable_or_over_tolerance_rounding_is_rejected_without_values() {
    let env = Env::default();
    let payroll = client(&env);

    assert_eq!(
        payroll.try_check_payout_precision(
            &1_000_003,
            &1,
            &4,
            &7,
            &100,
            &PayoutRoundingMode::Floor,
        ),
        Err(Ok(PayoutPrecisionError::RoundingDriftExceedsTolerance))
    );
    assert_eq!(
        payroll.try_check_payout_precision(&0, &1, &2, &7, &0, &PayoutRoundingMode::Floor),
        Err(Ok(PayoutPrecisionError::NonPositiveAmount))
    );
    assert_eq!(
        payroll.try_check_payout_precision(&100, &1, &2, &19, &0, &PayoutRoundingMode::Floor),
        Err(Ok(PayoutPrecisionError::InvalidDecimals))
    );
    assert_eq!(
        payroll.try_check_payout_precision(&100, &2, &1, &7, &0, &PayoutRoundingMode::Floor),
        Err(Ok(PayoutPrecisionError::InvalidShare))
    );
    assert_eq!(
        payroll.try_check_payout_precision(&100, &1, &2, &7, &10_001, &PayoutRoundingMode::Floor,),
        Err(Ok(PayoutPrecisionError::InvalidTolerance))
    );
    assert_eq!(
        payroll.try_check_payout_precision(
            &i128::MAX,
            &i128::MAX,
            &i128::MAX,
            &7,
            &0,
            &PayoutRoundingMode::Floor,
        ),
        Err(Ok(PayoutPrecisionError::ArithmeticOverflow))
    );
}

#[test]
fn batch_preflight_preserves_non_round_amounts() {
    let env = Env::default();
    let payroll = client(&env);
    let amounts = vec![&env, 1_i128, 333_333_333, 999_999_937];

    let report = payroll.validate_payout_batch(&amounts, &1_333_333_271);
    assert_eq!(report.payment_count, 3);
    assert_eq!(report.total, 1_333_333_271);
    assert_eq!(report.expected_total, 1_333_333_271);
}

#[test]
fn batch_preflight_rejects_mismatch_non_positive_and_overflow() {
    let env = Env::default();
    let payroll = client(&env);

    assert_eq!(
        payroll.try_validate_payout_batch(&vec![&env, 100_i128], &101),
        Err(Ok(PayoutPrecisionError::ExpectedSpendMismatch))
    );
    assert_eq!(
        payroll.try_validate_payout_batch(&vec![&env, 100_i128, -1], &99),
        Err(Ok(PayoutPrecisionError::NonPositiveAmount))
    );
    assert_eq!(
        payroll.try_validate_payout_batch(&vec![&env, i128::MAX, 1], &i128::MAX),
        Err(Ok(PayoutPrecisionError::ArithmeticOverflow))
    );
}

#[test]
#[should_panic(expected = "Payout batch total overflow")]
fn execution_rejects_an_unrepresentable_batch_total() {
    let env = Env::default();
    let (payroll, _, _) = common::setup(&env);
    let proof = BytesN::from_array(&env, &[1; 256]);
    let proofs = Vec::from_array(&env, [proof.clone(), proof]);
    let amounts = Vec::from_array(&env, [i128::MAX, 1]);
    let employees = Vec::from_array(&env, [Address::generate(&env), Address::generate(&env)]);

    payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &i128::MAX,
        &common::nonce(&env, 1),
        &None,
    );
}

#[test]
fn passing_batch_emits_a_precision_event_without_payout_values() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let amount = amounts.get(0).unwrap();

    let run_id = payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &amount,
        &common::nonce(&env, 2),
        &None,
    );

    let name = Symbol::new(&env, "payout_precision_validated");
    let all_events = env.events().all();
    let matching = all_events.events().iter().find(|event| {
        let ContractEventBody::V0(body) = &event.body;
        let Ok(topics) = Vec::<Val>::try_from_val(&env, &body.topics) else {
            return false;
        };
        topics
            .get(1)
            .and_then(|topic| Symbol::try_from_val(&env, &topic).ok())
            == Some(name.clone())
    });
    let Some(matching) = matching else {
        panic!("payout precision event was not emitted");
    };

    let ContractEventBody::V0(body) = &matching.body;
    // Aggregate metadata only: run id, optional pinned decimals, timestamp.
    let data_val: Val = Val::try_from_val(&env, &body.data).unwrap();
    let data: (u64, Option<u32>, u64) = data_val.try_into_val(&env).unwrap();
    assert_eq!(data.0, run_id);
    assert_eq!(data.1, payroll.get_payment_asset_decimals());

    // The event must not carry the individual payout amount.
    let amount_val: Val = amount.into_val(&env);
    let amount_scval: soroban_sdk::xdr::ScVal =
        soroban_sdk::xdr::ScVal::try_from_val(&env, &amount_val).unwrap();
    assert_ne!(body.data.clone(), amount_scval);
}
