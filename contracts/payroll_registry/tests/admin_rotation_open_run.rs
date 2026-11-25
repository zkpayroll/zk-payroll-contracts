//! Employer (company admin) role transfer while a payroll run is open (issue #898).
//!
//! A claimed payroll run identifier stands for an open period. These tests pin
//! what a two-step admin rotation does to it: the role moves atomically on
//! acceptance, the old admin loses the ability to open further runs, the
//! existing run keeps its owning company, and no payroll data is involved (the
//! index stores only the owning company id).

use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(PayrollRegistry, ());
    (env, contract_id)
}

fn run_ref(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
fn test_new_admin_can_open_runs_and_old_admin_cannot_after_acceptance() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);

    // A run is open under the original admin.
    client.claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 1));

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    // The old admin can no longer open runs; nothing was recorded.
    assert!(client
        .try_claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 2))
        .is_err());
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 2)), None);

    // The new admin can.
    client.claim_payroll_run_id(&company_id, &new_admin, &run_ref(&env, 2));
    assert_eq!(
        client.get_payroll_run_owner(&run_ref(&env, 2)),
        Some(company_id)
    );
}

#[test]
fn test_open_run_keeps_its_owning_company_across_the_transfer() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);
    client.claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 1));

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    assert_eq!(
        client.get_payroll_run_owner(&run_ref(&env, 1)),
        Some(company_id)
    );
    // The run id cannot be claimed again by either admin.
    assert!(client
        .try_claim_payroll_run_id(&company_id, &new_admin, &run_ref(&env, 1))
        .is_err());
    assert!(client
        .try_claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 1))
        .is_err());
}

#[test]
fn test_pending_rotation_does_not_move_the_role_until_accepted() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);

    // Boundary: between proposal and acceptance the old admin is still in charge.
    assert!(client
        .try_claim_payroll_run_id(&company_id, &new_admin, &run_ref(&env, 3))
        .is_err());
    client.claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 3));
    assert_eq!(client.get_company(&company_id).admin, old_admin);
}

#[test]
fn test_cancelled_rotation_leaves_the_original_admin_in_place() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);
    client.claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 1));

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    client.cancel_admin_rotation(&company_id, &old_admin);

    // The nominee cannot accept a cancelled proposal.
    assert!(client
        .try_accept_admin_rotation(&company_id, &new_admin)
        .is_err());
    assert_eq!(client.get_company(&company_id).admin, old_admin);
    client.claim_payroll_run_id(&company_id, &old_admin, &run_ref(&env, 2));
}

#[test]
fn test_old_admin_cannot_start_another_rotation_after_transfer() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    let attacker_target = Address::generate(&env);
    assert!(client
        .try_propose_admin_rotation(&company_id, &old_admin, &attacker_target)
        .is_err());
    assert_eq!(client.get_company(&company_id).admin, new_admin);
}

#[test]
fn test_rotation_does_not_touch_the_treasury_or_other_companies() {
    let (env, contract_id) = setup();
    let client = PayrollRegistryClient::new(&env, &contract_id);
    let old_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let other_admin = Address::generate(&env);
    let other_treasury = Address::generate(&env);
    let company_id = client.register_company(&old_admin, &treasury);
    let other_id = client.register_company(&other_admin, &other_treasury);
    client.claim_payroll_run_id(&other_id, &other_admin, &run_ref(&env, 9));

    client.propose_admin_rotation(&company_id, &old_admin, &new_admin);
    client.accept_admin_rotation(&company_id, &new_admin);

    assert_eq!(client.get_company(&company_id).treasury, treasury);
    assert_eq!(client.get_company(&other_id).admin, other_admin);
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 9)), Some(other_id));
}
