//! Compensation policy effective-date validation.
//!
//! A compensation policy binds a hashed schedule to the ledger timestamp it
//! takes effect at. These tests pin the rules that make "which policy governs
//! this payroll run" answerable without consulting off-chain state:
//!
//!   1. an effective date may not sit behind the ledger clock (beyond the
//!      documented skew tolerance),
//!   2. it may not exceed the scheduling horizon, so a mistyped timestamp is
//!      rejected instead of parking a company on an unusable policy,
//!   3. it must be strictly after the latest policy already scheduled, so the
//!      policy in force at any timestamp stays unique.
//!
//! They also cover the read model integrators use to resolve the policy for a
//! payroll run, and confirm that a rejected schedule writes nothing and emits
//! nothing.

use payroll_registry::{
    CompanyInfo, CompensationPolicyEffectiveDateIssue, DataKey, PayrollRegistry,
    PayrollRegistryClient, COMPENSATION_POLICY_PAST_SKEW_SECONDS,
    MAX_COMPENSATION_POLICY_HORIZON_SECONDS,
};
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{Address, BytesN, Env, Symbol, TryIntoVal};

/// Ledger clock used by most tests: far enough past zero that "in the past"
/// and "at the current ledger timestamp" are clearly distinguishable.
const T0: u64 = 1_700_000_000;

/// A registered company plus a client, with the ledger clock pinned at [`T0`].
fn setup() -> (Env, PayrollRegistryClient<'static>, Address, u64) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, PayrollRegistry);
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = client.register_company(&admin, &treasury);

    env.ledger().with_mut(|li| li.timestamp = T0);
    (env, client, admin, company_id)
}

fn commitment(env: &Env, tag: u8) -> BytesN<32> {
    BytesN::from_array(env, &[tag; 32])
}

fn set_timestamp(env: &Env, timestamp: u64) {
    env.ledger().with_mut(|li| li.timestamp = timestamp);
}

// ---------------------------------------------------------------------------
// Success paths
// ---------------------------------------------------------------------------

#[test]
fn first_policy_may_be_effective_immediately() {
    let (env, client, admin, company_id) = setup();

    let policy =
        client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 1), &T0);

    assert_eq!(policy.company_id, company_id);
    assert_eq!(policy.policy_commitment, commitment(&env, 1));
    assert_eq!(policy.effective_at, T0);
    assert_eq!(policy.created_at, T0);
    assert_eq!(policy.created_by, admin);

    // `effective_at` is inclusive, so a policy dated now is in force now.
    assert!(client.is_compensation_policy_effective(&company_id, &T0));
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &T0)
            .unwrap()
            .policy_commitment,
        commitment(&env, 1)
    );
}

#[test]
fn first_policy_may_be_dated_in_the_future_within_the_horizon() {
    let (env, client, admin, company_id) = setup();
    let effective_at = T0 + 30 * 24 * 60 * 60;

    let policy = client.schedule_compensation_policy(
        &company_id,
        &admin,
        &commitment(&env, 2),
        &effective_at,
    );

    assert_eq!(policy.effective_at, effective_at);
    // A future-dated policy is scheduled but not yet in force.
    assert!(!client.is_compensation_policy_effective(&company_id, &T0));
    assert!(client.is_compensation_policy_effective(&company_id, &effective_at));
}

#[test]
fn effective_date_within_the_skew_tolerance_is_accepted() {
    let (env, client, admin, company_id) = setup();
    // The HR admin picks the date off-chain, so it may trail the network clock
    // by the usual consensus skew.
    let effective_at = T0 - COMPENSATION_POLICY_PAST_SKEW_SECONDS;

    let policy = client.schedule_compensation_policy(
        &company_id,
        &admin,
        &commitment(&env, 3),
        &effective_at,
    );

    assert_eq!(policy.effective_at, effective_at);
}

#[test]
fn horizon_boundary_exactly_one_year_ahead_is_accepted() {
    let (env, client, admin, company_id) = setup();
    let effective_at = T0 + MAX_COMPENSATION_POLICY_HORIZON_SECONDS;

    let policy = client.schedule_compensation_policy(
        &company_id,
        &admin,
        &commitment(&env, 4),
        &effective_at,
    );

    assert_eq!(policy.effective_at, effective_at);
}

#[test]
fn a_policy_may_be_rescheduled_after_the_clock_moves_on() {
    let (env, client, admin, company_id) = setup();
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 5), &(T0 + 1_000));

    // Time passing never invalidates an already-scheduled policy.
    set_timestamp(&env, T0 + 10_000);
    let next = client.schedule_compensation_policy(
        &company_id,
        &admin,
        &commitment(&env, 6),
        &(T0 + 20_000),
    );

    assert_eq!(next.created_at, T0 + 10_000);
    assert_eq!(next.effective_at, T0 + 20_000);
}

#[test]
fn scheduling_does_not_disturb_employee_eligibility() {
    let (env, client, admin, company_id) = setup();
    let employee = Address::generate(&env);

    client.add_employee(&company_id, &employee, &commitment(&env, 7));
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 8), &T0);

    assert!(client.is_eligible(&company_id, &employee));
    assert!(client.is_compensation_policy_effective(&company_id, &T0));
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

#[test]
fn effective_date_in_the_past_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let too_late = T0 - COMPENSATION_POLICY_PAST_SKEW_SECONDS - 1;

    let check = client.check_policy_effective_date(&company_id, &too_late);

    assert!(!check.valid);
    assert_eq!(check.issue, CompensationPolicyEffectiveDateIssue::InThePast);
    assert_eq!(check.effective_at, too_late);
    assert_eq!(check.ledger_now, T0);
    assert_eq!(check.latest_scheduled_effective_at, None);

    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &commitment(&env, 9), &too_late)
        .is_err());
    assert!(client
        .get_compensation_policy(&company_id, &too_late)
        .is_none());
}

#[test]
fn effective_date_beyond_the_horizon_is_rejected() {
    let (env, client, admin, company_id) = setup();
    // A milliseconds timestamp submitted as seconds is the classic typo this
    // bound exists to catch.
    let mistyped = T0 + 1_000 * MAX_COMPENSATION_POLICY_HORIZON_SECONDS;

    let check = client.check_policy_effective_date(&company_id, &mistyped);

    assert!(!check.valid);
    assert_eq!(
        check.issue,
        CompensationPolicyEffectiveDateIssue::BeyondSchedulingHorizon
    );

    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &commitment(&env, 10), &mistyped)
        .is_err());
    assert!(client
        .get_compensation_policy(&company_id, &mistyped)
        .is_none());
}

#[test]
fn effective_date_equal_to_the_latest_scheduled_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let first = T0 + 1_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 11), &first);

    let check = client.check_policy_effective_date(&company_id, &first);

    assert!(
        !check.valid,
        "a tie would make the in-force policy ambiguous"
    );
    assert_eq!(
        check.issue,
        CompensationPolicyEffectiveDateIssue::NotAfterScheduledPolicy
    );
    assert_eq!(check.latest_scheduled_effective_at, Some(first));

    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &commitment(&env, 12), &first)
        .is_err());
}

#[test]
fn effective_date_before_the_latest_scheduled_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let first = T0 + 5_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 13), &first);

    // A later call "rewinding" the schedule would silently restate the policy
    // that earlier payroll runs were executed under.
    let rewind = T0 + 4_000;
    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &commitment(&env, 14), &rewind)
        .is_err());

    let schedule = client.get_compensation_policy_schedule(&company_id);
    assert_eq!(schedule.len(), 1);
    assert_eq!(schedule.get(0).unwrap().effective_at, first);
}

#[test]
fn the_past_rule_takes_precedence_over_the_horizon_and_ordering_rules() {
    let (env, client, admin, company_id) = setup();
    let scheduled = T0 + 10_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 15), &scheduled);

    // Far in the past: also behind the schedule, but the caller is told about
    // the clock first, since that is the rule they most likely broke.
    let check = client.check_policy_effective_date(&company_id, &0);

    assert_eq!(check.issue, CompensationPolicyEffectiveDateIssue::InThePast);
    assert_eq!(check.latest_scheduled_effective_at, Some(scheduled));
}

#[test]
fn the_horizon_bound_holds_even_with_an_existing_schedule() {
    let (env, client, admin, company_id) = setup();
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 16), &(T0 + 10_000));

    let check = client.check_policy_effective_date(
        &company_id,
        &(T0 + 2 * MAX_COMPENSATION_POLICY_HORIZON_SECONDS),
    );

    assert_eq!(
        check.issue,
        CompensationPolicyEffectiveDateIssue::BeyondSchedulingHorizon
    );
    assert_eq!(check.latest_scheduled_effective_at, Some(T0 + 10_000));
}

#[test]
fn zero_policy_commitment_is_rejected() {
    let (env, client, admin, company_id) = setup();
    let uninitialized = BytesN::from_array(&env, &[0u8; 32]);

    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &uninitialized, &T0)
        .is_err());
    assert!(client
        .get_compensation_policy_schedule(&company_id)
        .is_empty());
}

#[test]
fn scheduling_rejects_a_caller_that_is_not_the_company_admin() {
    let (env, client, _admin, company_id) = setup();
    let impostor = Address::generate(&env);

    assert!(client
        .try_schedule_compensation_policy(&company_id, &impostor, &commitment(&env, 17), &T0)
        .is_err());
    assert!(client
        .get_compensation_policy_schedule(&company_id)
        .is_empty());
}

#[test]
fn scheduling_requires_authorization() {
    // No auth mocks at all, so the host rejects the missing signature. The
    // company record is written directly to isolate the auth check, and the
    // clock is set to `T0` so `effective_at = T0` would otherwise be perfectly
    // acceptable -- leaving authorisation as the only reason to fail.
    let env = Env::default();
    let contract_id = env.register_contract(None, PayrollRegistry);
    let client = PayrollRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    env.as_contract(&contract_id, || {
        env.storage().persistent().set(
            &DataKey::Company(0),
            &CompanyInfo {
                admin: admin.clone(),
                treasury: treasury.clone(),
            },
        );
    });
    set_timestamp(&env, T0);

    assert!(client
        .try_schedule_compensation_policy(&0, &admin, &commitment(&env, 18), &T0)
        .is_err());

    // The same call succeeds once authorisation is provided, confirming
    // authorisation was what failed above and not the effective date.
    env.mock_all_auths();
    let policy = client.schedule_compensation_policy(&0, &admin, &commitment(&env, 19), &T0);
    assert_eq!(policy.effective_at, T0);
}

#[test]
fn scheduling_rejects_an_unknown_company() {
    let (env, client, admin, _company_id) = setup();

    assert!(client
        .try_schedule_compensation_policy(&99, &admin, &commitment(&env, 19), &T0)
        .is_err());
}

#[test]
#[should_panic(expected = "use a strictly later timestamp")]
fn a_conflicting_effective_date_reports_the_bar_to_beat() {
    let (env, client, admin, company_id) = setup();
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 20), &(T0 + 1_000));

    client.require_valid_effective_date(&company_id, &(T0 + 1_000));
}

#[test]
#[should_panic(expected = "effective date is in the past")]
fn a_past_effective_date_reports_its_remediation() {
    let (env, client, admin, company_id) = setup();
    let too_late = T0 - COMPENSATION_POLICY_PAST_SKEW_SECONDS - 1;

    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 21), &too_late);
}

#[test]
fn require_valid_effective_date_passes_for_an_acceptable_date() {
    let (_env, client, _admin, company_id) = setup();

    // Read-only: it authorises nothing and writes nothing.
    client.require_valid_effective_date(&company_id, &T0);
    assert!(client
        .get_compensation_policy_schedule(&company_id)
        .is_empty());
}

// ---------------------------------------------------------------------------
// Read model: resolving the policy in force for a payroll run
// ---------------------------------------------------------------------------

#[test]
fn no_policy_is_in_force_before_the_first_effective_date() {
    let (env, client, admin, company_id) = setup();
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 22), &(T0 + 1_000));

    assert!(client
        .get_compensation_policy_at(&company_id, &T0)
        .is_none());
    assert!(!client.is_compensation_policy_effective(&company_id, &T0));
    // One second before it takes effect, still nothing.
    assert!(client
        .get_compensation_policy_at(&company_id, &(T0 + 999))
        .is_none());
}

#[test]
fn a_company_without_any_policy_has_nothing_in_force() {
    let (_env, client, _admin, company_id) = setup();

    assert!(client
        .get_compensation_policy_at(&company_id, &T0)
        .is_none());
    assert!(!client.is_compensation_policy_effective(&company_id, &T0));
}

#[test]
fn the_newest_due_policy_is_the_one_in_force() {
    let (env, client, admin, company_id) = setup();
    let first = T0 + 1_000;
    let second = first + 1_000;
    let third = second + 1_000;

    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 23), &first);
    set_timestamp(&env, first);
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 24), &second);
    set_timestamp(&env, second);
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 25), &third);

    // The boundary is inclusive on the effective date and switches exactly there.
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &first)
            .unwrap()
            .policy_commitment,
        commitment(&env, 23)
    );
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &(second - 1))
            .unwrap()
            .policy_commitment,
        commitment(&env, 23),
        "the previous policy stays in force until the next one takes over"
    );
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &second)
            .unwrap()
            .policy_commitment,
        commitment(&env, 24)
    );
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &third)
            .unwrap()
            .policy_commitment,
        commitment(&env, 25)
    );
}

#[test]
fn a_policy_stays_in_force_indefinitely() {
    let (env, client, admin, company_id) = setup();
    let effective_at = T0 + 1_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 26), &effective_at);

    let far_future = effective_at + 100 * 365 * 24 * 60 * 60;
    assert!(client.is_compensation_policy_effective(&company_id, &far_future));
    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &far_future)
            .unwrap()
            .effective_at,
        effective_at
    );
}

#[test]
fn the_schedule_is_returned_in_ascending_effective_date_order() {
    let (env, client, admin, company_id) = setup();
    let first = T0 + 1_000;
    let second = first + 1_000;
    let third = second + 1_000;

    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 27), &first);
    set_timestamp(&env, first);
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 28), &second);
    set_timestamp(&env, second);
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 29), &third);

    let schedule = client.get_compensation_policy_schedule(&company_id);
    assert_eq!(schedule.len(), 3);
    assert_eq!(schedule.get(0).unwrap().effective_at, first);
    assert_eq!(schedule.get(1).unwrap().effective_at, second);
    assert_eq!(schedule.get(2).unwrap().effective_at, third);
}

#[test]
fn policies_are_scoped_per_company() {
    let (env, client, admin, company_id) = setup();
    let other_admin = Address::generate(&env);
    let other_treasury = Address::generate(&env);
    let other_company = client.register_company(&other_admin, &other_treasury);

    let mine = T0 + 1_000;
    let theirs = T0 + 2_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 30), &mine);
    client.schedule_compensation_policy(
        &other_company,
        &other_admin,
        &commitment(&env, 31),
        &theirs,
    );

    assert_eq!(
        client
            .get_compensation_policy_at(&company_id, &theirs)
            .unwrap()
            .effective_at,
        mine,
        "one company's schedule must not leak into another's"
    );
    assert_eq!(
        client
            .get_compensation_policy_at(&other_company, &theirs)
            .unwrap()
            .effective_at,
        theirs
    );

    // A date that clashes with the other company's schedule is fine here.
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 32), &(theirs + 1));
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[test]
fn scheduling_emits_one_privacy_safe_event() {
    let (env, client, admin, company_id) = setup();
    let effective_at = T0 + 1_000;
    let policy_commitment = commitment(&env, 40);

    let before = env.events().all().len();
    client.schedule_compensation_policy(&company_id, &admin, &policy_commitment, &effective_at);
    let after = env.events().all().len();

    assert_eq!(after - before, 1, "scheduling emits exactly one event");

    let event = env.events().all().get(after - 1).unwrap();
    let topic0: Symbol = event.1.get(0).unwrap().try_into_val(&env).unwrap();
    let topic_company: u64 = event.1.get(1).unwrap().try_into_val(&env).unwrap();
    assert_eq!(topic0, Symbol::new(&env, "CompensationPolicyScheduled"));
    assert_eq!(topic_company, company_id);

    let data: (BytesN<32>, u64) = event.2.try_into_val(&env).unwrap();
    assert_eq!(
        data,
        (policy_commitment, effective_at),
        "the event carries the hashed schedule and its effective date, never an amount"
    );
}

#[test]
fn a_rejected_schedule_emits_nothing() {
    let (env, client, admin, company_id) = setup();
    let effective_at = T0 + 1_000;
    client.schedule_compensation_policy(&company_id, &admin, &commitment(&env, 41), &effective_at);

    let before = env.events().all().len();
    assert!(client
        .try_schedule_compensation_policy(&company_id, &admin, &commitment(&env, 42), &effective_at)
        .is_err());

    assert_eq!(
        env.events().all().len(),
        before,
        "a rejected schedule must not emit CompensationPolicyScheduled"
    );
    assert_eq!(
        client.get_compensation_policy_schedule(&company_id).len(),
        1,
        "a rejected schedule must not extend the stored schedule"
    );
}
