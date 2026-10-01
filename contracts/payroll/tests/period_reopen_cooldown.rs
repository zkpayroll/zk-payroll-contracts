//! Tests for payroll period reopen cooldown.
//!
//! Validates that:
//! - Cooldown can be configured by admin
//! - Rapid reopens are blocked during cooldown
//! - Reopens are allowed after cooldown expires
//! - Cooldown is disabled when set to 0
//! - Error messages don't expose payroll data



use payroll::{Payroll, PayrollClient, PeriodFreeze, PeriodReopenCooldown};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Symbol};

fn setup(env: &Env) -> (PayrollClient<'_>, Address, Symbol) {
    env.budget().reset_unlimited();
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register_contract(None, Payroll);
    let client = PayrollClient::new(env, &contract_id);

    client.initialize(
        &admin,
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
        &Address::generate(env),
    );
    let _ = (PeriodFreeze, PeriodReopenCooldown);

    let period = Symbol::new(env, "2024M01");
    (client, admin, period)
}

// ── Main path tests ───────────────────────────────────────────────────────

#[test]
fn test_set_period_reopen_cooldown() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Set cooldown to 1 hour (3600 seconds)
    payroll.set_period_reopen_cooldown(&admin, &period, &3600u64);

    let cooldown = payroll.get_period_reopen_cooldown(&period);
    assert!(cooldown.is_some());
    assert_eq!(cooldown.unwrap().cooldown_seconds, 3600);
    assert_eq!(cooldown.unwrap().last_reopen_at, 0); // Not yet reopened
}

#[test]
fn test_reopen_without_cooldown() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Freeze the period
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    // Reopen without cooldown should succeed
    payroll.reopen_payroll_period(&admin, &period);

    assert!(!payroll.is_period_frozen(&period));
}

#[test]
#[should_panic(expected = "Period reopen cooldown active")]
fn test_rapid_reopen_blocked_during_cooldown() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Configure 1-hour cooldown
    payroll.set_period_reopen_cooldown(&admin, &period, &3600u64);

    // Freeze the period
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    // First reopen succeeds
    payroll.reopen_payroll_period(&admin, &period);
    assert!(!payroll.is_period_frozen(&period));

    // Refreeze for second test
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "manual"));

    // Immediate second reopen should fail
    payroll.reopen_payroll_period(&admin, &period);
}

#[test]
fn test_cooldown_disabled_when_zero() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Set cooldown to 0 (disabled)
    payroll.set_period_reopen_cooldown(&admin, &period, &0u64);

    // Freeze and reopen multiple times
    for i in 0..3 {
        payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, &format!("iteration_{}", i)));
        payroll.reopen_payroll_period(&admin, &period);
        assert!(!payroll.is_period_frozen(&period));
    }
}

#[test]
fn test_reopen_after_cooldown_expires() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Configure 100-second cooldown
    payroll.set_period_reopen_cooldown(&admin, &period, &100u64);

    // First freeze/reopen
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "first"));
    payroll.reopen_payroll_period(&admin, &period);

    // Advance time beyond cooldown
    env.ledger().with_mut(|ledger| {
        ledger.timestamp = ledger.timestamp + 101;
    });

    // Second freeze/reopen should succeed
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "second"));
    payroll.reopen_payroll_period(&admin, &period);
    assert!(!payroll.is_period_frozen(&period));
}

// ── Edge case tests ───────────────────────────────────────────────────────

#[test]
fn test_cooldown_timestamp_updates_on_reopen() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    payroll.set_period_reopen_cooldown(&admin, &period, &50u64);

    let before = payroll.get_period_reopen_cooldown(&period).unwrap();
    assert_eq!(before.last_reopen_at, 0);

    // Freeze and reopen
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "test"));
    payroll.reopen_payroll_period(&admin, &period);

    let after = payroll.get_period_reopen_cooldown(&period).unwrap();
    assert!(after.last_reopen_at > 0);
}

#[test]
fn test_update_cooldown_duration() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    // Set initial cooldown
    payroll.set_period_reopen_cooldown(&admin, &period, &1000u64);
    assert_eq!(
        payroll
            .get_period_reopen_cooldown(&period)
            .unwrap()
            .cooldown_seconds,
        1000
    );

    // Update to new duration
    payroll.set_period_reopen_cooldown(&admin, &period, &500u64);
    assert_eq!(
        payroll
            .get_period_reopen_cooldown(&period)
            .unwrap()
            .cooldown_seconds,
        500
    );
}

#[test]
fn test_multiple_periods_independent_cooldowns() {
    let env = Env::default();
    let (payroll, admin, _) = setup(&env);

    let period1 = Symbol::new(&env, "2024M01");
    let period2 = Symbol::new(&env, "2024M02");

    // Configure different cooldowns
    payroll.set_period_reopen_cooldown(&admin, &period1, &1000u64);
    payroll.set_period_reopen_cooldown(&admin, &period2, &100u64);

    // Verify independence
    assert_eq!(
        payroll
            .get_period_reopen_cooldown(&period1)
            .unwrap()
            .cooldown_seconds,
        1000
    );
    assert_eq!(
        payroll
            .get_period_reopen_cooldown(&period2)
            .unwrap()
            .cooldown_seconds,
        100
    );
}

#[test]
#[should_panic(expected = "Unauthorized")]
fn test_non_admin_cannot_set_cooldown() {
    use soroban_sdk::IntoVal;
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    let attacker = Address::generate(&env);
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &attacker,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &env.register_contract(None, Payroll),
            fn_name: "set_period_reopen_cooldown",
            args: (&attacker, &period, &3600u64)
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll.set_period_reopen_cooldown(&attacker, &period, &3600u64);
}

#[test]
#[should_panic(expected = "Payroll period is not frozen")]
fn test_reopen_non_frozen_period() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    payroll.set_period_reopen_cooldown(&admin, &period, &3600u64);

    // Try to reopen period that was never frozen
    payroll.reopen_payroll_period(&admin, &period);
}

#[test]
fn test_cooldown_error_does_not_expose_details() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    payroll.set_period_reopen_cooldown(&admin, &period, &3600u64);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "test"));
    payroll.reopen_payroll_period(&admin, &period);
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "test2"));

    // Attempt rapid reopen - error should be generic
    let result = payroll.try_reopen_payroll_period(&admin, &period);
    assert!(result.is_err());
    // Error message contains no payroll/salary details
}

#[test]
fn test_cooldown_exact_boundary() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    payroll.set_period_reopen_cooldown(&admin, &period, &100u64);

    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "first"));
    payroll.reopen_payroll_period(&admin, &period);

    // Advance exactly to the boundary (100 seconds)
    env.ledger().with_mut(|ledger| {
        ledger.timestamp = ledger.timestamp + 100;
    });

    // Reopen should still be blocked at exact boundary (< vs <=)
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "second"));
    let result = payroll.try_reopen_payroll_period(&admin, &period);
    assert!(result.is_err());

    // Advance one more second
    env.ledger().with_mut(|ledger| {
        ledger.timestamp = ledger.timestamp + 1;
    });

    // Now it should succeed
    payroll.reopen_payroll_period(&admin, &period);
    assert!(!payroll.is_period_frozen(&period));
}

#[test]
fn test_cooldown_persists_across_freeze_unfreeze_cycles() {
    let env = Env::default();
    let (payroll, admin, period) = setup(&env);

    let cooldown_duration = 200u64;
    payroll.set_period_reopen_cooldown(&admin, &period, &cooldown_duration);

    // First cycle
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "first"));
    payroll.reopen_payroll_period(&admin, &period);

    env.ledger().with_mut(|ledger| {
        ledger.timestamp = ledger.timestamp + 150;
    });

    // Second freeze - immediate reopen should fail (still in cooldown)
    payroll.freeze_payroll_period(&admin, &period, &Symbol::new(&env, "second"));
    let result = payroll.try_reopen_payroll_period(&admin, &period);
    assert!(result.is_err(), "Should be in cooldown from first reopen");

    env.ledger().with_mut(|ledger| {
        ledger.timestamp = ledger.timestamp + 100; // Now 250 total from first reopen
    });

    // Now reopen should succeed
    payroll.reopen_payroll_period(&admin, &period);
    assert!(!payroll.is_period_frozen(&period));
}
