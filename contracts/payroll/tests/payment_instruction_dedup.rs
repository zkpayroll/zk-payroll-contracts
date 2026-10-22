#![cfg(test)]

use payroll::PayrollClient;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, Vec};

fn mock_vk(env: &Env) -> proof_verifier::VerificationKey {
    proof_verifier::VerificationKey {
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
                BytesN::from_array(env, &[0u8; 64]),
            ],
        ),
    }
}

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

struct Ctx {
    env: Env,
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

    let verifier_id = env.register_contract(None, proof_verifier::ProofVerifier);
    let verifier_client = proof_verifier::ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, salary_commitment::SalaryCommitmentContract);
    let commitment = salary_commitment::SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, token::Token);

    let payroll_id = env.register_contract(None, payroll::Payroll);
    let payroll = PayrollClient::new(&env, &payroll_id);

    payroll.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &admin,
        &admin,
    );
    commitment.set_payroll_operator(&payroll_id);

    Ctx {
        env,
        payroll_id,
    }
}

// ── Duplicate payout instruction detection ──────────────────────────────────

/// Success path: recording a fresh (period, instruction) pair succeeds and is
/// afterwards visible as a duplicate via the read-only preflight check.
#[test]
fn record_payment_instruction_success_path() {
    let ctx = setup();

    let first = ctx.payroll().try_record_payment_instruction(&1, &100).unwrap();
    assert!(first.is_ok(), "first recording of a pair must succeed");

    assert!(
        ctx.payroll().is_payment_instruction_duplicate(&1, &100),
        "recorded pair must be visible as a duplicate"
    );
    assert!(
        !ctx.payroll().is_payment_instruction_duplicate(&1, &101),
        "unrecorded pair must not be a duplicate"
    );
}

/// Failure path: re-recording the same (period, instruction) pair is rejected.
#[test]
fn record_payment_instruction_duplicate_is_rejected() {
    let ctx = setup();

    let first = ctx.payroll().try_record_payment_instruction(&1, &100);
    assert!(first.is_ok(), "first recording must succeed");

    let second = ctx.payroll().try_record_payment_instruction(&1, &100);
    assert!(second.is_err(), "duplicate pair must be rejected");
}

/// Edge case: the same instruction_id in a different period is not a duplicate.
#[test]
fn same_instruction_id_different_period_is_not_duplicate() {
    let ctx = setup();

    let first = ctx.payroll().try_record_payment_instruction(&1, &100).unwrap();
    assert!(first.is_ok(), "recording in period 1 must succeed");

    let second_period = ctx.payroll().try_record_payment_instruction(&2, &100).unwrap();
    assert!(
        second_period.is_ok(),
        "same instruction_id in a different period must be accepted"
    );
    assert!(
        !ctx.payroll().is_payment_instruction_duplicate(&2, &99),
        "unrecorded pair in period 2 must not be a duplicate"
    );
}
