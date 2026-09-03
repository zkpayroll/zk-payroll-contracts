mod common;

use soroban_sdk::Env;

#[test]
fn duplicate_batch_reference_is_rejected_without_consuming_another_reference() {
    let env = Env::default();
    let (payroll, _, employee) = common::setup(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);
    let reference = common::nonce(&env, 1);

    payroll.prepare_payroll_run(&proofs, &amounts, &employees, &100, &reference, &None);
    assert!(payroll
        .try_prepare_payroll_run(&proofs, &amounts, &employees, &100, &reference, &None)
        .is_err());

    let distinct_reference = common::nonce(&env, 2);
    assert!(payroll
        .try_prepare_payroll_run(
            &proofs,
            &amounts,
            &employees,
            &100,
            &distinct_reference,
            &None,
        )
        .is_ok());
}

#[test]
fn same_reference_is_scoped_to_the_employer_contract() {
    let env = Env::default();
    let (first, _, first_employee) = common::setup(&env);
    let (second, _, second_employee) = common::setup(&env);
    let reference = common::nonce(&env, 3);
    let (first_proofs, first_amounts, first_employees) = common::one_payment(&env, &first_employee);
    let (second_proofs, second_amounts, second_employees) =
        common::one_payment(&env, &second_employee);

    first.prepare_payroll_run(
        &first_proofs,
        &first_amounts,
        &first_employees,
        &100,
        &reference,
        &None,
    );
    assert!(second
        .try_prepare_payroll_run(
            &second_proofs,
            &second_amounts,
            &second_employees,
            &100,
            &reference,
            &None,
        )
        .is_ok());
}
