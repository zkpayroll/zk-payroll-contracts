//! Payroll approval expiry validation tests (#403).

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient, DEFAULT_APPROVAL_EXPIRY_SECONDS};
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

fn setup_payroll(env: &Env) -> (PayrollClient<'_>, Address, Address, Address, Address) {
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

    (payroll_client, admin, treasury, treasury_owner, employee)
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

#[test]
fn test_approval_validity_window() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 30);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);
    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 5;
    });

    assert!(payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

#[test]
#[should_panic(expected = "Payroll approval expired: approval record exceeds maximum allowed age")]
fn test_finalize_panics_after_approval_expiry() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 31);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 10;
    });

    payroll.finalize_payroll_run(&admin, &run_id);
}

// ---------------------------------------------------------------------------
// Clock Boundary Tests for Approval Expiry Cutoffs
// ---------------------------------------------------------------------------

#[test]
fn test_approval_at_exact_expiry_boundary() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 32);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    // Exactly at expiry boundary - should still be valid
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS;
    });

    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

#[test]
fn test_approval_one_tick_before_expiry() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 33);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    // One tick before expiry - should still be valid
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS - 1;
    });

    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

#[test]
fn test_approval_one_tick_after_expiry() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 34);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    // One tick after expiry - should be expired
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
    });

    assert!(payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}

#[test]
fn test_finalize_at_exact_expiry_boundary_succeeds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 35);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    // Exactly at expiry boundary - finalization should succeed
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS;
    });

    payroll.finalize_payroll_run(&admin, &run_id);
    assert!(payroll.get_run_counter() >= run_id);
}

#[test]
#[should_panic(expected = "Payroll approval expired: approval record exceeds maximum allowed age")]
fn test_finalize_one_tick_after_expiry_panics() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 36);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    // One tick after expiry - finalization should panic
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS + 1;
    });

    payroll.finalize_payroll_run(&admin, &run_id);
}

#[test]
fn test_approval_expiry_with_custom_expiry_seconds() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 37);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer, &run_id);

    let custom_expiry = 500u64;

    // Before custom expiry
    env.ledger().with_mut(|li| {
        li.timestamp += custom_expiry - 1;
    });
    assert!(!payroll.is_payroll_approval_expired(&run_id, &custom_expiry));

    // At custom expiry boundary
    env.ledger().with_mut(|li| {
        li.timestamp += 1;
    });
    assert!(!payroll.is_payroll_approval_expired(&run_id, &custom_expiry));

    // After custom expiry
    env.ledger().with_mut(|li| {
        li.timestamp += 1;
    });
    assert!(payroll.is_payroll_approval_expired(&run_id, &custom_expiry));
}

#[test]
fn test_multiple_approvals_with_different_timestamps() {
    let env = Env::default();
    let (payroll, admin, _treasury, _treasury_owner, employee) = setup_payroll(&env);

    let reviewer1 = Address::generate(&env);
    let reviewer2 = Address::generate(&env);
    payroll.add_reviewer(&admin, &reviewer1);
    payroll.add_reviewer(&admin, &reviewer2);

    let (proofs, amounts, employees) = single_payment_batch(&env, &employee, 10_000);
    let nonce = test_nonce(&env, 38);
    let run_id = payroll.prepare_payroll_run(&proofs, &amounts, &employees, &10_000, &nonce, &None);

    payroll.approve_payroll_run(&reviewer1, &run_id);

    // Advance time
    env.ledger().with_mut(|li| {
        li.timestamp += 100;
    });

    payroll.approve_payroll_run(&reviewer2, &run_id);

    // Advance to just before expiry from the first approval
    env.ledger().with_mut(|li| {
        li.timestamp += DEFAULT_APPROVAL_EXPIRY_SECONDS - 100 - 1;
    });

    // Should still be valid since the second approval is more recent
    assert!(!payroll.is_payroll_approval_expired(&run_id, &DEFAULT_APPROVAL_EXPIRY_SECONDS));
}
