//! Payroll run identifier collision across employers (#887).

use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env};

fn setup() -> (Env, PayrollRegistryClient<'static>, (u64, Address), (u64, Address)) {
    let env = Env::default();
    env.mock_all_auths();
    let client = PayrollRegistryClient::new(&env, &env.register(PayrollRegistry, ()));
    let admin_a = Address::generate(&env);
    let admin_b = Address::generate(&env);
    let company_a = client.register_company(&admin_a, &Address::generate(&env));
    let company_b = client.register_company(&admin_b, &Address::generate(&env));
    (env, client, (company_a, admin_a), (company_b, admin_b))
}

fn run_ref(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
fn distinct_run_ids_are_claimed_per_employer() {
    let (env, client, (a, admin_a), (b, admin_b)) = setup();
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 1));
    client.claim_payroll_run_id(&b, &admin_b, &run_ref(&env, 2));

    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 1)), Some(a));
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 2)), Some(b));
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 3)), None);
}

#[test]
#[should_panic(expected = "Payroll run identifier collides with another employer")]
fn run_id_owned_by_another_employer_is_rejected() {
    let (env, client, (a, admin_a), (b, admin_b)) = setup();
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 7));
    client.claim_payroll_run_id(&b, &admin_b, &run_ref(&env, 7));
}

#[test]
fn collision_leaves_the_original_owner_intact() {
    let (env, client, (a, admin_a), (b, admin_b)) = setup();
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 7));
    assert!(client.try_claim_payroll_run_id(&b, &admin_b, &run_ref(&env, 7)).is_err());
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 7)), Some(a));
}

#[test]
#[should_panic(expected = "Payroll run identifier already claimed by this company")]
fn same_employer_cannot_claim_a_run_id_twice() {
    let (env, client, (a, admin_a), _) = setup();
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 9));
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 9));
}

#[test]
#[should_panic(expected = "Only company admin can claim a payroll run identifier")]
fn another_employers_admin_cannot_claim_on_its_behalf() {
    let (env, client, (a, _), (_, admin_b)) = setup();
    client.claim_payroll_run_id(&a, &admin_b, &run_ref(&env, 4));
}

#[test]
fn boundary_all_zero_and_all_ff_run_ids_are_distinct() {
    let (env, client, (a, admin_a), (b, admin_b)) = setup();
    client.claim_payroll_run_id(&a, &admin_a, &run_ref(&env, 0x00));
    client.claim_payroll_run_id(&b, &admin_b, &run_ref(&env, 0xff));
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 0x00)), Some(a));
    assert_eq!(client.get_payroll_run_owner(&run_ref(&env, 0xff)), Some(b));
}
