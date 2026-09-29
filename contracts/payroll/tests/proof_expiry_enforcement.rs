//! Payroll proof expiry enforcement tests (#346).
//!
//! `batch_process_with_expiry` verifies each payment proof through a
//! registered `proof_verifier::ProofReference` instead of a bare
//! `verify_payment_proof` call, so a reference that has expired or been
//! revoked blocks settlement even when the underlying proof bytes would
//! otherwise still pass verification.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env, Vec};

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn test_ref_id(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = 0xAB;
    arr[1] = seed;
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

struct TestCtx<'a> {
    payroll: PayrollClient<'a>,
    verifier: ProofVerifierClient<'a>,
    verifier_admin: Address,
    employee: Address,
}

fn setup(env: &Env) -> TestCtx<'_> {
    env.mock_all_auths();

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier_id);
    let verifier_admin = Address::generate(env);
    verifier_client.init_verifier_admin(&verifier_admin);
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment_id);
    let commitment_admin = Address::generate(env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(env, &token_id);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(env, &payroll_id);

    let treasury = Address::generate(env);
    let admin = Address::generate(env);
    let treasury_owner = Address::generate(env);
    token_client.mint(&treasury, &1_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0u8; 32]));

    TestCtx {
        payroll: payroll_client,
        verifier: verifier_client,
        verifier_admin,
        employee,
    }
}

fn single_payment_batch(
    env: &Env,
    employee: &Address,
    amount: i128,
) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    let mut proofs = Vec::new(env);
    proofs.push_back(mock_proof(env));
    let mut amounts = Vec::new(env);
    amounts.push_back(amount);
    let mut employees = Vec::new(env);
    employees.push_back(employee.clone());
    (proofs, amounts, employees)
}

/// A freshly registered, non-expired reference authorizes settlement.
#[test]
fn fresh_proof_reference_authorizes_settlement() {
    let env = Env::default();
    let ctx = setup(&env);

    let proof = mock_proof(&env);
    let ref_id = test_ref_id(&env, 1);
    let expires_at = env.ledger().sequence() + 1000;
    ctx.verifier
        .register_proof_reference(&ctx.verifier_admin, &ref_id, &proof, &expires_at);

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(ref_id);
    let nonce = test_nonce(&env, 1);

    let run_id = ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );

    assert!(run_id > 0);
}

/// A reference past its expiry ledger must block settlement, even though the
/// exact same proof bytes would still pass a bare `verify_payment_proof`
/// call (proven here by the batch panicking specifically at the reference
/// check, not at a generic proof-invalid message).
#[test]
#[should_panic(expected = "Invalid or expired payment proof reference")]
fn expired_proof_reference_blocks_settlement() {
    let env = Env::default();
    let ctx = setup(&env);

    let proof = mock_proof(&env);
    let ref_id = test_ref_id(&env, 2);
    let expires_at = env.ledger().sequence() + 1;
    ctx.verifier
        .register_proof_reference(&ctx.verifier_admin, &ref_id, &proof, &expires_at);

    // Advance past the expiry ledger.
    env.ledger().with_mut(|li| {
        li.sequence_number = expires_at + 1;
    });

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(ref_id);
    let nonce = test_nonce(&env, 2);

    ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );
}

/// The exact boundary ledger (sequence == expires_at_ledger) is still valid;
/// one ledger later it is not. This proves the enforcement isn't off-by-one
/// in either direction.
#[test]
fn boundary_ledger_at_expiry_is_still_valid() {
    let env = Env::default();
    let ctx = setup(&env);

    let proof = mock_proof(&env);
    let ref_id = test_ref_id(&env, 3);
    let expires_at = env.ledger().sequence() + 5;
    ctx.verifier
        .register_proof_reference(&ctx.verifier_admin, &ref_id, &proof, &expires_at);

    env.ledger().with_mut(|li| {
        li.sequence_number = expires_at; // exactly at expiry, not past it
    });

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(ref_id);
    let nonce = test_nonce(&env, 3);

    let run_id = ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );

    assert!(run_id > 0);
}

/// A revoked reference is rejected even though it has not yet reached its
/// expiry ledger.
#[test]
#[should_panic(expected = "Invalid or expired payment proof reference")]
fn revoked_reference_blocks_settlement_before_expiry() {
    let env = Env::default();
    let ctx = setup(&env);

    let proof = mock_proof(&env);
    let ref_id = test_ref_id(&env, 4);
    let expires_at = env.ledger().sequence() + 1000;
    ctx.verifier
        .register_proof_reference(&ctx.verifier_admin, &ref_id, &proof, &expires_at);
    ctx.verifier
        .revoke_proof_reference(&ctx.verifier_admin, &ref_id);

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(ref_id);
    let nonce = test_nonce(&env, 4);

    ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );
}

/// A `ref_id` that was never registered is rejected with the same
/// deterministic error as an expired one - callers get one stable failure
/// mode to handle for "this reference does not currently authorize
/// anything," regardless of the underlying reason.
#[test]
#[should_panic(expected = "Invalid or expired payment proof reference")]
fn unregistered_reference_is_rejected() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(test_ref_id(&env, 99)); // never registered
    let nonce = test_nonce(&env, 5);

    ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );
}

/// "Fresh proof replacement before payroll settlement": an employer who
/// registered a reference that has since expired (or was for the wrong
/// proof) can register a brand new reference for corrected proof bytes and
/// settle successfully with it - registration itself is the replacement
/// mechanism; there's no separate "update" call.
#[test]
fn fresh_replacement_reference_succeeds_after_original_expired() {
    let env = Env::default();
    let ctx = setup(&env);

    // Original reference: registered, then allowed to expire.
    let stale_proof = mock_proof(&env);
    let stale_ref_id = test_ref_id(&env, 6);
    let stale_expiry = env.ledger().sequence() + 1;
    ctx.verifier.register_proof_reference(
        &ctx.verifier_admin,
        &stale_ref_id,
        &stale_proof,
        &stale_expiry,
    );
    env.ledger().with_mut(|li| {
        li.sequence_number = stale_expiry + 1;
    });
    assert!(!ctx.verifier.is_proof_reference_valid(&stale_ref_id));

    // Replacement: a new ref_id registered fresh, right before settlement.
    let fresh_proof = mock_proof(&env);
    let fresh_ref_id = test_ref_id(&env, 7);
    let fresh_expiry = env.ledger().sequence() + 1000;
    ctx.verifier.register_proof_reference(
        &ctx.verifier_admin,
        &fresh_ref_id,
        &fresh_proof,
        &fresh_expiry,
    );

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let mut proof_refs = Vec::new(&env);
    proof_refs.push_back(fresh_ref_id);
    let nonce = test_nonce(&env, 6);

    let run_id = ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );

    assert!(run_id > 0);
}

/// `proofs`, `proof_refs`, `amounts`, and `employees` must all be the same
/// length - a mismatched `proof_refs` array is rejected before any proof is
/// checked.
#[test]
#[should_panic(expected = "Array length mismatch")]
fn mismatched_proof_refs_length_is_rejected() {
    let env = Env::default();
    let ctx = setup(&env);

    let (proofs, amounts, employees) = single_payment_batch(&env, &ctx.employee, 500);
    let proof_refs: Vec<BytesN<32>> = Vec::new(&env); // empty, but proofs has 1 entry
    let nonce = test_nonce(&env, 7);

    ctx.payroll.batch_process_with_expiry(
        &proofs,
        &proof_refs,
        &amounts,
        &employees,
        &500,
        &nonce,
        &None,
    );
}
