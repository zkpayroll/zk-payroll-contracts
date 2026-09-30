/// Treasury reservation reconciliation checkpoints tests — issue #416.
///
/// # Coverage
/// | Test | Scenario |
/// |------|----------|
/// | `test_reservation_checkpoint_recording_and_reconciliation_success` | Record checkpoints across Lock, Execution, Cancellation, Expiry, Close stages without drift -> succeeds |
/// | `test_reservation_drift_detected_panics` | Reservation amount mismatch sets `is_reconciled == false` and panics on reconcile |
/// | `test_get_reservation_checkpoint_returns_none_for_unrecorded_stage` | Unrecorded stage query returns `None` |
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::{
    testutils::{Address as _, Events},
    Address, BytesN, Env, Symbol, TryFromVal, TryIntoVal, Vec,
};
use token::{Token, TokenClient};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0u8; 64]),
        beta: BytesN::from_array(env, &[0u8; 128]),
        gamma: BytesN::from_array(env, &[0u8; 128]),
        delta: BytesN::from_array(env, &[0u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

struct Ctx {
    env: Env,
    admin: Address,
    treasury: Address,
    asset: Address,
    payroll_id: Address,
}

impl Ctx {
    fn payroll(&self) -> PayrollClient<'_> {
        PayrollClient::new(&self.env, &self.payroll_id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll = PayrollClient::new(&env, &payroll_id);

    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    Ctx {
        env,
        admin,
        treasury,
        asset: token_id,
        payroll_id,
    }
}

#[test]
fn test_reservation_checkpoint_recording_and_reconciliation_success() {
    let ctx = setup();
    let run_id = 300u64;
    let reserved_amount = 15_000i128;

    // Record checkpoints for stages 1..=5 (Lock, Execution, Cancellation, Expiry, Close)
    for stage in 1..=5u32 {
        let cp = ctx.payroll().record_reservation_checkpoint(
            &run_id,
            &stage,
            &reserved_amount,
            &reserved_amount,
            &ctx.asset,
        );
        assert!(cp.is_reconciled);
        assert_eq!(cp.expected_reserved_amount, reserved_amount);
        assert_eq!(cp.actual_reserved_amount, reserved_amount);

        let retrieved = ctx
            .payroll()
            .get_reservation_checkpoint(&run_id, &stage)
            .unwrap();
        assert_eq!(retrieved, cp);

        assert!(ctx.payroll().reconcile_reservation(&run_id, &stage));
    }
}

#[test]
#[should_panic(expected = "Treasury reservation drift detected")]
fn test_reservation_drift_detected_panics() {
    let ctx = setup();
    let run_id = 301u64;
    let expected = 20_000i128;
    let actual_drifted = 18_000i128;

    // Stage 1 (Lock): expected 20_000, actual 18_000 -> drift!
    let cp = ctx.payroll().record_reservation_checkpoint(
        &run_id,
        &1u32,
        &expected,
        &actual_drifted,
        &ctx.asset,
    );
    assert!(!cp.is_reconciled);

    // Verify drift event was emitted
    let events = ctx.env.events().all();
    let drift_event = events.iter().find(|(_, topics, _)| {
        if let Some(val) = topics.get(1) {
            if let Ok(sym) = Symbol::try_from_val(&ctx.env, &val) {
                return sym == Symbol::new(&ctx.env, "reservation_drift_detected");
            }
        }
        false
    });
    assert!(drift_event.is_some());

    // Reconcile must panic
    ctx.payroll().reconcile_reservation(&run_id, &1u32);
}

#[test]
fn test_get_reservation_checkpoint_returns_none_for_unrecorded_stage() {
    let ctx = setup();
    let run_id = 302u64;

    let res = ctx.payroll().get_reservation_checkpoint(&run_id, &1u32);
    assert!(res.is_none());
}
