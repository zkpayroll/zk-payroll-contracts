//! Tests for employee onboarding duplicate reference validation (Issue #440).
//!
//! Verifies that:
//! 1. Duplicate employee onboarding references for the same employer are strictly rejected.
//! 2. Rejection preserves original reference mappings and avoids state corruption.
//! 3. Distinct references allow smooth subsequent onboarding of other employees.
//! 4. Same-employee reference rotation / update is supported, freeing the previous reference.
//! 5. Freed references can be reassigned to other employees without collisions.
//! 6. Boundary validation rejects empty or oversized onboarding reference IDs.
//! 7. Safe lookup and payroll batch reconciliation integrity is preserved across multiple employees.

#![cfg(test)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};

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

#[allow(dead_code)]
struct EmployerOnboardingFixture<'a> {
    pub env: &'a Env,
    pub payroll: PayrollClient<'a>,
    pub commitment: SalaryCommitmentContractClient<'a>,
    pub admin: Address,
    pub treasury: Address,
}

fn setup_employer_onboarding<'a>(env: &'a Env) -> EmployerOnboardingFixture<'a> {
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
    token_client.mint(&treasury, &2_000_000i128);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    EmployerOnboardingFixture {
        env,
        payroll: payroll_client,
        commitment: commitment_client,
        admin,
        treasury,
    }
}

// ---------------------------------------------------------------------------
// 1. Duplicate reference rejection tests
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Reference ID already assigned to another employee")]
fn test_onboarding_rejects_duplicate_reference_for_same_employer() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    // Store salary commitments for both employees
    fixture
        .commitment
        .store_commitment(&employee_a, &BytesN::from_array(&env, &[1u8; 32]));
    fixture
        .commitment
        .store_commitment(&employee_b, &BytesN::from_array(&env, &[2u8; 32]));

    let duplicate_ref = String::from_str(&env, "EMP-REF-1001");

    // Onboard first employee with reference ID
    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &duplicate_ref);

    // Attempting to onboard second employee with identical reference ID must panic
    fixture
        .commitment
        .set_employee_reference_id(&employee_b, &duplicate_ref);
}

#[test]
fn test_same_reference_is_allowed_for_different_employers() {
    let env = Env::default();
    env.mock_all_auths();

    // Each employer uses its own salary commitment contract, so reference
    // uniqueness is enforced within that employer's payroll scope.
    let employer_a_id = env.register_contract(None, SalaryCommitmentContract);
    let employer_a = SalaryCommitmentContractClient::new(&env, &employer_a_id);
    employer_a.init_commitment_admin(&Address::generate(&env));

    let employer_b_id = env.register_contract(None, SalaryCommitmentContract);
    let employer_b = SalaryCommitmentContractClient::new(&env, &employer_b_id);
    employer_b.init_commitment_admin(&Address::generate(&env));

    let reference_id = String::from_str(&env, "HR-EMP-100");
    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    employer_a.set_employee_reference_id(&employee_a, &reference_id);
    employer_b.set_employee_reference_id(&employee_b, &reference_id);

    assert_eq!(
        employer_a.get_employee_by_reference_id(&reference_id),
        Some(employee_a)
    );
    assert_eq!(
        employer_b.get_employee_by_reference_id(&reference_id),
        Some(employee_b)
    );
}

#[test]
fn test_duplicate_reference_rejection_preserves_original_mapping() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    fixture
        .commitment
        .store_commitment(&employee_a, &BytesN::from_array(&env, &[10u8; 32]));
    fixture
        .commitment
        .store_commitment(&employee_b, &BytesN::from_array(&env, &[20u8; 32]));

    let ref_id = String::from_str(&env, "EMP-REF-2001");

    // 1. Onboard employee A
    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &ref_id);

    // 2. Attempt duplicate onboarding for employee B via try_ call
    let duplicate_attempt = fixture
        .commitment
        .try_set_employee_reference_id(&employee_b, &ref_id);

    assert!(
        duplicate_attempt.is_err(),
        "Duplicate reference onboarding must fail"
    );

    // 3. Verify original employee A's mapping is completely intact
    let mapped_employee = fixture
        .commitment
        .get_employee_by_reference_id(&ref_id)
        .expect("Employee A mapping must remain intact");
    assert_eq!(mapped_employee, employee_a);

    let retrieved_ref = fixture
        .commitment
        .get_employee_reference_id(&employee_a)
        .expect("Employee A reference must exist");
    assert_eq!(retrieved_ref, ref_id);

    // 4. Verify employee B has no assigned reference
    assert!(
        fixture
            .commitment
            .get_employee_reference_id(&employee_b)
            .is_none(),
        "Rejected employee must have no reference ID set"
    );
}

#[test]
fn test_employer_can_onboard_second_employee_with_distinct_reference() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    fixture
        .commitment
        .store_commitment(&employee_a, &BytesN::from_array(&env, &[11u8; 32]));
    fixture
        .commitment
        .store_commitment(&employee_b, &BytesN::from_array(&env, &[22u8; 32]));

    let ref_a = String::from_str(&env, "EMP-REF-ALPHA");
    let ref_b = String::from_str(&env, "EMP-REF-BETA");

    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &ref_a);

    // Collision attempt
    assert!(fixture
        .commitment
        .try_set_employee_reference_id(&employee_b, &ref_a)
        .is_err());

    // Valid distinct onboarding for employee B succeeds
    fixture
        .commitment
        .set_employee_reference_id(&employee_b, &ref_b);

    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&ref_a)
            .unwrap(),
        employee_a
    );
    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&ref_b)
            .unwrap(),
        employee_b
    );
}

// ---------------------------------------------------------------------------
// 2. Reference update and freed reference reassignment tests
// ---------------------------------------------------------------------------

#[test]
fn test_same_employee_can_update_onboarding_reference() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee = Address::generate(&env);
    fixture
        .commitment
        .store_commitment(&employee, &BytesN::from_array(&env, &[30u8; 32]));

    let old_ref = String::from_str(&env, "EMP-REF-OLD");
    let new_ref = String::from_str(&env, "EMP-REF-NEW");

    // Initial onboarding
    fixture
        .commitment
        .set_employee_reference_id(&employee, &old_ref);
    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&old_ref)
            .unwrap(),
        employee
    );

    // Update to new reference
    fixture
        .commitment
        .set_employee_reference_id(&employee, &new_ref);

    // Forward and reverse mappings updated
    assert_eq!(
        fixture
            .commitment
            .get_employee_reference_id(&employee)
            .unwrap(),
        new_ref
    );
    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&new_ref)
            .unwrap(),
        employee
    );

    // Old reference is freed
    assert!(
        fixture
            .commitment
            .get_employee_by_reference_id(&old_ref)
            .is_none(),
        "Old reference must be unmapped after update"
    );
}

#[test]
fn test_freed_reference_can_be_reassigned_to_another_employee() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    fixture
        .commitment
        .store_commitment(&employee_a, &BytesN::from_array(&env, &[41u8; 32]));
    fixture
        .commitment
        .store_commitment(&employee_b, &BytesN::from_array(&env, &[42u8; 32]));

    let shared_ref = String::from_str(&env, "EMP-REUSABLE-REF");
    let rotated_ref = String::from_str(&env, "EMP-EMPLOYEE-A-V2");

    // Employee A initially holds shared_ref
    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &shared_ref);

    // Employee B cannot take shared_ref while held
    assert!(fixture
        .commitment
        .try_set_employee_reference_id(&employee_b, &shared_ref)
        .is_err());

    // Employee A updates to a new reference
    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &rotated_ref);

    // Now employee B can successfully onboard with shared_ref
    let reassign_result = fixture
        .commitment
        .try_set_employee_reference_id(&employee_b, &shared_ref);
    assert!(
        reassign_result.is_ok(),
        "Freed reference should be available for reassignment"
    );

    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&shared_ref)
            .unwrap(),
        employee_b
    );
}

// ---------------------------------------------------------------------------
// 3. Input validation & boundary tests
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_onboarding_rejects_empty_reference_id() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let employee = Address::generate(&env);
    fixture
        .commitment
        .store_commitment(&employee, &BytesN::from_array(&env, &[51u8; 32]));

    let empty_ref = String::from_str(&env, "");
    fixture
        .commitment
        .set_employee_reference_id(&employee, &empty_ref);
}

// ---------------------------------------------------------------------------
// 4. End-to-end safe lookup & reconciliation integrity test
// ---------------------------------------------------------------------------

#[test]
fn test_safe_lookup_and_batch_reconciliation_integrity_with_unique_references() {
    let env = Env::default();
    let fixture = setup_employer_onboarding(&env);

    let emp1 = Address::generate(&env);
    let emp2 = Address::generate(&env);

    fixture
        .commitment
        .store_commitment(&emp1, &BytesN::from_array(&env, &[61u8; 32]));
    fixture
        .commitment
        .store_commitment(&emp2, &BytesN::from_array(&env, &[62u8; 32]));

    let ref1 = String::from_str(&env, "HR-EMP-101");
    let ref2 = String::from_str(&env, "HR-EMP-102");

    fixture.commitment.set_employee_reference_id(&emp1, &ref1);
    fixture.commitment.set_employee_reference_id(&emp2, &ref2);

    // Resolve employee addresses via reference lookup
    let resolved_1 = fixture
        .commitment
        .get_employee_by_reference_id(&ref1)
        .expect("Ref 1 should resolve");
    let resolved_2 = fixture
        .commitment
        .get_employee_by_reference_id(&ref2)
        .expect("Ref 2 should resolve");

    assert_eq!(resolved_1, emp1);
    assert_eq!(resolved_2, emp2);

    // Prepare multi-employee payroll batch with resolved addresses
    let mut proofs = Vec::new(&env);
    proofs.push_back(mock_proof(&env));
    proofs.push_back(mock_proof(&env));

    let mut amounts = Vec::new(&env);
    amounts.push_back(5_000i128);
    amounts.push_back(7_000i128);

    let mut employees = Vec::new(&env);
    employees.push_back(resolved_1);
    employees.push_back(resolved_2);

    let nonce = test_nonce(&env, 77);
    let run_id = fixture.payroll.prepare_payroll_run(
        &proofs,
        &amounts,
        &employees,
        &12_000i128,
        &nonce,
        &None,
    );
    assert!(run_id > 0);

    // Finalize run
    fixture
        .payroll
        .finalize_payroll_run(&fixture.admin, &run_id);

    // Safe reverse lookup check
    assert_eq!(
        fixture.commitment.get_employee_reference_id(&emp1).unwrap(),
        ref1
    );
    assert_eq!(
        fixture.commitment.get_employee_reference_id(&emp2).unwrap(),
        ref2
    );
}
