use payroll::{Payroll, PayrollClient, ReconciliationStatus};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};
use token::{Token, TokenClient};

fn setup() -> (Env, PayrollClient<'static>, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let employee = Address::generate(&env);
    let verifier = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&VerificationKey {
        alpha: BytesN::from_array(&env, &[0; 64]),
        beta: BytesN::from_array(&env, &[0; 128]),
        gamma: BytesN::from_array(&env, &[0; 128]),
        delta: BytesN::from_array(&env, &[0; 128]),
        ic: Vec::from_array(
            &env,
            [
                BytesN::from_array(&env, &[0; 64]),
                BytesN::from_array(&env, &[0; 64]),
                BytesN::from_array(&env, &[0; 64]),
                BytesN::from_array(&env, &[0; 64]),
            ],
        ),
    });

    let commitment = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment);
    commitment_client.init_commitment_admin(&admin);
    commitment_client.store_commitment(&employee, &BytesN::from_array(&env, &[0; 32]));

    let token = env.register_contract(None, Token);
    TokenClient::new(&env, &token).mint(&treasury, &10_000);
    let payroll_id = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_id);
    payroll.initialize(
        &admin,
        &token,
        &verifier,
        &commitment,
        &treasury,
        &Address::generate(&env),
    );
    commitment_client.set_payroll_operator(&payroll_id);
    let source = Address::generate(&env);
    payroll.register_import_source(&source, &0);

    (env, payroll, admin, employee, source)
}

fn settle_one(env: &Env, payroll: &PayrollClient, employee: &Address, source: &Address) -> u64 {
    let proofs = Vec::from_array(env, [BytesN::from_array(env, &[0; 256])]);
    let amounts = Vec::from_array(env, [100_i128]);
    let employees = Vec::from_array(env, [employee.clone()]);
    payroll.batch_process_payroll(
        &proofs,
        &amounts,
        &employees,
        &100_i128,
        &BytesN::from_array(env, &[7; 32]),
        &None,
        source,
    )
}

#[test]
fn authorized_reconciliation_update_records_marker() {
    let (env, payroll, admin, employee, source) = setup();
    let run_id = settle_one(&env, &payroll, &employee, &source);
    assert_eq!(payroll.get_reconciliation_marker(&run_id), None);

    let timestamp = env.ledger().timestamp();
    payroll.update_reconciliation_status(&admin, &run_id, &ReconciliationStatus::Failed);

    let marker = payroll
        .get_reconciliation_marker(&run_id)
        .expect("accepted status update records a reconciliation marker");
    assert_eq!(marker.run_id, run_id);
    assert_eq!(marker.status, ReconciliationStatus::Failed);
    assert_eq!(marker.marked_at, timestamp);
    assert_eq!(marker.marked_by, admin);
}

#[test]
fn unauthorized_update_does_not_write_marker() {
    let (env, payroll, _admin, employee, source) = setup();
    let run_id = settle_one(&env, &payroll, &employee, &source);
    let unauthorized = Address::generate(&env);

    assert!(payroll
        .try_update_reconciliation_status(&unauthorized, &run_id, &ReconciliationStatus::Failed)
        .is_err());
    assert_eq!(payroll.get_reconciliation_marker(&run_id), None);
}

#[test]
fn missing_run_has_no_reconciliation_marker() {
    let (_env, payroll, _admin, _employee, _source) = setup();
    assert_eq!(payroll.get_reconciliation_marker(&u64::MAX), None);
}
