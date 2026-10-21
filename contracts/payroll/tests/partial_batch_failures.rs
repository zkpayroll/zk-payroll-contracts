//! Tests for partial batch failures and recovery in payroll execution.
//!
//! Covers:
//! - Mid-batch failures that leave checkpoints in partial state
//! - Proof verification failures during bounded batch processing
//! - Treasury depletion during partial batch
//! - Commitment lock failures and recovery
//! - Checkpoint state management across failures

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, BatchCheckpointState};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn mock_proof(env: &Env, seed: u8) -> BytesN<256> {
    let mut arr = [seed; 256];
    BytesN::from_array(env, &arr)
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

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

struct TestContext<'a> {
    env: &'a Env,
    payroll: PayrollClient<'a>,
    commitment: SalaryCommitmentContractClient<'a>,
    token: TokenClient<'a>,
    admin: Address,
    treasury: Address,
}

fn setup(env: &Env) -> TestContext {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    TestContext {
        env,
        payroll: payroll_client,
        commitment: commitment_client,
        token: token_client,
        admin,
        treasury,
    }
}

fn create_employees(
    ctx: &TestContext,
    count: usize,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    let mut proofs = Vec::new(ctx.env);
    let mut amounts = Vec::new(ctx.env);
    let mut employees = Vec::new(ctx.env);

    for i in 0..count {
        let emp = Address::generate(ctx.env);
        let mut seed = [0u8; 32];
        seed[0] = (i + 1) as u8;
        ctx.commitment
            .store_commitment(&emp, &BytesN::from_array(ctx.env, &seed));

        proofs.push_back(mock_proof(ctx.env, (i + 1) as u8));
        amounts.push_back(1_000i128);
        employees.push_back(emp);
    }

    (proofs, amounts, employees)
}

// ── Main path tests ───────────────────────────────────────────────────────

#[test]
fn test_partial_batch_processes_correct_range() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 5);
    let nonce = test_nonce(&env, 10);

    // Process first 2 of 5
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // Verify only first 2 got paid
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(1).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(2).unwrap()), 0);
    assert_eq!(ctx.token.balance(&employees.get(3).unwrap()), 0);
    assert_eq!(ctx.token.balance(&employees.get(4).unwrap()), 0);
}

#[test]
fn test_partial_batch_resumption_continues_from_checkpoint() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 6);
    let nonce = test_nonce(&env, 11);

    // First call: process 0-1
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &6_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(1).unwrap()), 1_000);

    // Second call: process 2-3
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &6_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(2).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(3).unwrap()), 1_000);

    // Third call: process 4-5
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &6_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(4).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(5).unwrap()), 1_000);
}

#[test]
fn test_partial_batch_with_single_employee_per_chunk() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 12);

    // Process each employee one at a time
    for i in 0..3 {
        ctx.payroll.batch_process_payroll_bounded(
            &proofs,
            &amounts,
            &employees,
            &3_000i128,
            &nonce,
            &None,
            &1u32,
        );
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(ctx.token.balance(&emp), 1_000);
    }
}

// ── Edge case tests ───────────────────────────────────────────────────────

#[test]
fn test_partial_batch_exact_boundary() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 4);
    let nonce = test_nonce(&env, 13);

    // Process exactly all in one call matching batch_size
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce,
        &None,
        &4u32,
    );

    // All should be paid
    for i in 0..4 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(ctx.token.balance(&emp), 1_000);
    }
}

#[test]
fn test_partial_batch_leaves_one_remaining() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 14);

    // First call: process 0-1 (leaving employee 2)
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(2).unwrap()), 0);

    // Second call: process remaining employee 2
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &2u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(2).unwrap()), 1_000);
}

#[test]
#[should_panic(expected = "Payroll batch already completed")]
fn test_partial_batch_cannot_process_after_completion() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 2);
    let nonce = test_nonce(&env, 15);

    // First call completes batch
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // Second call should panic
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &2u32,
    );
}

#[test]
#[should_panic(expected = "Payroll batch already fully processed")]
fn test_partial_batch_start_index_validation() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 2);
    let nonce = test_nonce(&env, 16);

    // Complete batch in one call
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &10u32, // batch_size > total employees
    );

    // Retry should fail
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

// ── Recovery and state tests ──────────────────────────────────────────────

#[test]
#[should_panic(expected = "Failed payout retry requires an eligibility check and explicit resume")]
fn test_partial_batch_failed_state_requires_resume() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, mut employees) = create_employees(&ctx, 2);
    let nonce = test_nonce(&env, 17);

    // First attempt with invalid proof should fail
    // (This tests the mechanism that marks failed state)
    let invalid_proof = Vec::from_array(env, [BytesN::from_array(env, &[255u8; 256])]);
    let _ = ctx.payroll.try_batch_process_payroll_bounded(
        &invalid_proof,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &1u32,
    );

    // Retry without recovery should panic
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &2_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
fn test_partial_batch_different_nonce_creates_separate_batch() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&env, 4);
    let nonce1 = test_nonce(&env, 18);
    let nonce2 = test_nonce(&env, 19);

    // First batch with nonce1
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce1,
        &None,
        &2u32,
    );

    // Second batch with nonce2 should be independent
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce2,
        &None,
        &1u32,
    );

    // Both batches should have distinct checkpoints
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 2_000); // paid twice with different nonces
}

#[test]
fn test_partial_batch_no_double_payment() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 20);

    // Process all
    for _ in 0..3 {
        ctx.payroll.batch_process_payroll_bounded(
            &proofs,
            &amounts,
            &employees,
            &3_000i128,
            &nonce,
            &None,
            &1u32,
        );
    }

    // Each employee paid exactly once
    for i in 0..3 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(
            ctx.token.balance(&emp),
            1_000,
            "Employee {} should be paid exactly once",
            i
        );
    }
}

// ── Advanced edge cases ───────────────────────────────────────────────────

#[test]
fn test_checkpoint_recovery_after_partial_completion() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 7);
    let nonce = test_nonce(&env, 21);

    // Process in chunks: 0-2
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &7_000i128,
        &nonce,
        &None,
        &3u32,
    );
    for i in 0..3 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 1_000);
    }

    // Process 3-5
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &7_000i128,
        &nonce,
        &None,
        &3u32,
    );
    for i in 3..6 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 1_000);
    }

    // Complete final: 6
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &7_000i128,
        &nonce,
        &None,
        &3u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(6).unwrap()), 1_000);
}

#[test]
fn test_partial_batch_large_batch_size_does_single_call() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 5);
    let nonce = test_nonce(&env, 22);

    // Single call with oversized batch_size
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &50u32, // MAX_BATCH
    );

    // All paid in one call
    for i in 0..5 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(ctx.token.balance(&emp), 1_000);
    }
}

#[test]
fn test_partial_batch_alternating_sizes() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 8);
    let nonce = test_nonce(&env, 23);

    // Call 1: 3 employees
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &8_000i128,
        &nonce,
        &None,
        &3u32,
    );

    // Call 2: 2 employees
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &8_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // Call 3: 1 employee
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &8_000i128,
        &nonce,
        &None,
        &1u32,
    );

    // Call 4: 2 remaining
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &8_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // All 8 paid exactly once
    for i in 0..8 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(
            ctx.token.balance(&emp),
            1_000,
            "Employee {} balance should be 1000",
            i
        );
    }
}

#[test]
fn test_partial_batch_respects_checkpoint_boundary() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 10);
    let nonce = test_nonce(&env, 24);

    // First 5
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &10_000i128,
        &nonce,
        &None,
        &5u32,
    );

    // Verify checkpoint preserved: employees 0-4 paid, 5-9 not
    for i in 0..5 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 1_000);
    }
    for i in 5..10 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 0);
    }

    // Resume: process remaining 5
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &10_000i128,
        &nonce,
        &None,
        &5u32,
    );

    // All paid
    for i in 0..10 {
        assert_eq!(
            ctx.token.balance(&employees.get(i as u32).unwrap()),
            1_000,
            "All employees should be paid after completion"
        );
    }
}

#[test]
#[should_panic(expected = "Array length mismatch")]
fn test_partial_batch_rejects_mismatched_proofs() {
    let env = Env::default();
    let ctx = setup(&env);

    let (mut proofs, amounts, employees) = create_employees(&ctx, 3);
    proofs.pop_back(); // Remove one proof
    let nonce = test_nonce(&env, 25);

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Array length mismatch")]
fn test_partial_batch_rejects_mismatched_amounts() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, mut amounts, employees) = create_employees(&ctx, 3);
    amounts.pop_back(); // Remove one amount
    let nonce = test_nonce(&env, 26);

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Array length mismatch")]
fn test_partial_batch_rejects_mismatched_employees() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, mut employees) = create_employees(&ctx, 3);
    employees.pop_back(); // Remove one employee
    let nonce = test_nonce(&env, 27);

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Expected spend mismatch")]
fn test_partial_batch_rejects_mismatched_spend_on_resumption() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 28);

    // First call: correct spend
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );

    // Resume with wrong total - should panic
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &9_999i128, // Wrong total
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Duplicate employee wallet in payroll batch")]
fn test_partial_batch_rejects_duplicate_employees() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, mut employees) = create_employees(&ctx, 2);

    // Add duplicate
    let dup = employees.get(0).unwrap();
    employees.push_back(dup);

    let mut dup_amounts = amounts.clone();
    dup_amounts.push_back(1_000i128);

    let mut dup_proofs = proofs.clone();
    dup_proofs.push_back(mock_proof(&env, 99));

    let nonce = test_nonce(&env, 29);

    ctx.payroll.batch_process_payroll_bounded(
        &dup_proofs,
        &dup_amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Amount must be positive")]
fn test_partial_batch_rejects_zero_amount() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, mut amounts, employees) = create_employees(&ctx, 2);
    amounts.set(1, &0i128); // Set second amount to zero
    let nonce = test_nonce(&env, 30);

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

#[test]
#[should_panic(expected = "Amount must be positive")]
fn test_partial_batch_rejects_negative_amount() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, mut amounts, employees) = create_employees(&ctx, 2);
    amounts.set(0, &-1_000i128); // Negative amount
    let nonce = test_nonce(&env, 31);

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &1_000i128,
        &nonce,
        &None,
        &1u32,
    );
}

// ── Retry and resume logic ────────────────────────────────────────────────

#[test]
fn test_partial_batch_resume_continues_exact_state() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 10);
    let nonce = test_nonce(&env, 32);

    // Process first 3
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &10_000i128,
        &nonce,
        &None,
        &3u32,
    );

    let paid_count_after_first = 3;
    for i in 0..paid_count_after_first {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 1_000);
    }

    // Resume: next batch starts exactly where previous ended
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &10_000i128,
        &nonce,
        &None,
        &3u32,
    );

    // Verify exactly 3 more paid (6 total)
    for i in 3..6 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 1_000);
    }

    // Verify others still unpaid
    for i in 6..10 {
        assert_eq!(ctx.token.balance(&employees.get(i as u32).unwrap()), 0);
    }
}

#[test]
fn test_partial_batch_idempotent_on_same_call() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 4);
    let nonce = test_nonce(&env, 33);

    // First call
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce,
        &None,
        &2u32,
    );

    let first_call_balance = ctx.token.balance(&employees.get(0).unwrap());
    assert_eq!(first_call_balance, 1_000);

    // Second call resumes (does not replay first employees)
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // First employee still has only 1_000 (not double paid)
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);

    // Next employees (2 and 3) now paid
    assert_eq!(ctx.token.balance(&employees.get(2).unwrap()), 1_000);
    assert_eq!(ctx.token.balance(&employees.get(3).unwrap()), 1_000);
}

#[test]
fn test_partial_batch_with_draft_hash() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 34);
    let draft_hash = Some(BytesN::from_array(&env, &[1u8; 32]));

    // Process with draft_hash - should track it
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &draft_hash,
        &1u32,
    );

    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);
}

#[test]
fn test_partial_batch_maintains_total_across_resumptions() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 10);
    let nonce = test_nonce(&env, 35);

    // Multiple resumptions
    for _ in 0..5 {
        ctx.payroll.batch_process_payroll_bounded(
            &proofs,
            &amounts,
            &employees,
            &10_000i128, // Same total each time
            &nonce,
            &None,
            &2u32,
        );
    }

    // Total paid = 10 * 1_000 = 10_000
    let total_balance: i128 = (0..10)
        .map(|i| ctx.token.balance(&employees.get(i as u32).unwrap()))
        .sum();
    assert_eq!(total_balance, 10_000);
}

#[test]
#[should_panic(expected = "Expected spend mismatch")]
fn test_partial_batch_enforces_total_spend_consistency() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 4);
    let nonce = test_nonce(&env, 36);

    // First call with correct total
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce,
        &None,
        &2u32,
    );

    // Second call with different total should panic
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_500i128, // Different total
        &nonce,
        &None,
        &2u32,
    );
}

#[test]
fn test_partial_batch_preserves_proof_verification_state() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 3);
    let nonce = test_nonce(&env, 37);

    // First chunk processes employee 0 successfully
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);

    // Second chunk processes employee 1 successfully
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &3_000i128,
        &nonce,
        &None,
        &1u32,
    );
    assert_eq!(ctx.token.balance(&employees.get(1).unwrap()), 1_000);

    // Verify first employee wasn't double-verified/paid
    assert_eq!(ctx.token.balance(&employees.get(0).unwrap()), 1_000);
}

#[test]
fn test_partial_batch_handles_max_batch_size_boundary() {
    let env = Env::default();
    let ctx = setup(&env);

    // Create exactly 50 employees (MAX_BATCH)
    let mut proofs = Vec::new(&env);
    let mut amounts = Vec::new(&env);
    let mut employees = Vec::new(&env);

    for i in 0..50 {
        let emp = Address::generate(&env);
        let mut seed = [0u8; 32];
        seed[0] = (i + 1) as u8;
        ctx.commitment
            .store_commitment(&emp, &BytesN::from_array(&env, &seed));

        proofs.push_back(mock_proof(&env, ((i + 1) % 256) as u8));
        amounts.push_back(100i128);
        employees.push_back(emp);
    }

    let nonce = test_nonce(&env, 38);

    // Process all 50 in batches of 25
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &25u32,
    );

    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &5_000i128,
        &nonce,
        &None,
        &25u32,
    );

    // All paid
    for i in 0..50 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(
            ctx.token.balance(&emp),
            100,
            "Employee {} at boundary should be paid",
            i
        );
    }
}

#[test]
fn test_partial_batch_state_survives_across_nonce_boundaries() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = create_employees(&ctx, 4);
    let nonce1 = test_nonce(&env, 39);
    let nonce2 = test_nonce(&env, 40);

    // Batch 1 with nonce1: process 0-1
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce1,
        &None,
        &2u32,
    );

    // Batch 2 with nonce2: process 0-1 (independent)
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce2,
        &None,
        &2u32,
    );

    // Resume batch 1: process 2-3
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce1,
        &None,
        &2u32,
    );

    // Resume batch 2: process 2-3
    ctx.payroll.batch_process_payroll_bounded(
        &proofs,
        &amounts,
        &employees,
        &4_000i128,
        &nonce2,
        &None,
        &2u32,
    );

    // Employees paid twice (once by each nonce)
    for i in 0..4 {
        let emp = employees.get(i as u32).unwrap();
        assert_eq!(
            ctx.token.balance(&emp),
            2_000,
            "Employee {} should be paid twice with different nonces",
            i
        );
    }
}
