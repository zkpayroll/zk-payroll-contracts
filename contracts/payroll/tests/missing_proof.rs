mod common;

use soroban_sdk::{BytesN, Env, Vec};

#[test]
#[should_panic(expected = "Missing payroll proof: one proof is required per payment")]
fn prepare_rejects_a_missing_proof_with_an_actionable_error() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (_, amounts, employees) = common::one_payment(&env, &employee);

    payroll.prepare_payroll_run(
        &Vec::<BytesN<256>>::new(&env),
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 4),
        &None,
    );
}

#[test]
#[should_panic(expected = "Missing payroll proof: one proof is required per payment")]
fn execution_rejects_a_missing_proof_with_the_same_error() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (_, amounts, employees) = common::one_payment(&env, &employee);

    payroll.batch_process_payroll(
        &Vec::<BytesN<256>>::new(&env),
        &amounts,
        &employees,
        &100,
        &common::nonce(&env, 6),
        &None,
    );
}

#[test]
fn complete_proof_reference_set_is_accepted() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    assert!(payroll
        .try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &100,
            &common::nonce(&env, 5),
            &None,
        )
        .is_ok());
}
