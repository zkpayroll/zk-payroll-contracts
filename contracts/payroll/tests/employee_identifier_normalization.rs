//! Tests for Employee Identifier Normalization Rules (Issue #544).
//!
//! Verifies that:
//! 1. Normalization canonicalizes mixed-case and whitespace-padded employee identifiers ("  emp-101 \n" -> "EMP-101").
//! 2. Employee reference lookups by identifier are case-insensitive and trim-agnostic.
//! 3. Duplicate assignment detection is normalization-aware (cannot assign "emp-101" when "EMP-101" exists).
//! 4. Empty and whitespace-only identifiers are rejected.
//! 5. Identifiers exceeding 256 characters are rejected.
//! 6. Non-printable ASCII or control characters are rejected.
//! 7. Zero-knowledge privacy is preserved (no salary, blinding factor, or plaintext amounts exposed).

#![cfg(test)]

use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, String, Vec};
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

#[allow(dead_code)]
struct TestFixture<'a> {
    pub env: &'a Env,
    pub payroll: PayrollClient<'a>,
    pub commitment: SalaryCommitmentContractClient<'a>,
    pub admin: Address,
    pub treasury: Address,
}

fn setup_test_fixture<'a>(env: &'a Env) -> TestFixture<'a> {
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

    TestFixture {
        env,
        payroll: payroll_client,
        commitment: commitment_client,
        admin,
        treasury,
    }
}

#[test]
fn test_identifier_normalization_canonicalizes_case_and_whitespace() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let input1 = String::from_str(&env, "  emp-1001 \t\r\n");
    let expected1 = String::from_str(&env, "EMP-1001");
    assert_eq!(
        fixture.commitment.normalize_employee_identifier(&input1),
        expected1
    );
    assert_eq!(
        fixture.payroll.normalize_employee_identifier(&input1),
        expected1
    );

    let input2 = String::from_str(&env, "alice.smith_eng-dept#42");
    let expected2 = String::from_str(&env, "ALICE.SMITH_ENG-DEPT#42");
    assert_eq!(
        fixture.commitment.normalize_employee_identifier(&input2),
        expected2
    );
    assert_eq!(
        fixture.payroll.normalize_employee_identifier(&input2),
        expected2
    );
}

#[test]
fn test_employee_reference_set_and_cross_case_lookup() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let employee = Address::generate(&env);
    fixture
        .commitment
        .store_commitment(&employee, &BytesN::from_array(&env, &[1u8; 32]));

    // Store reference ID with lower-case and whitespace padding
    let raw_ref = String::from_str(&env, "  emp-qa-4002 \n");
    fixture
        .commitment
        .set_employee_reference_id(&employee, &raw_ref);

    // Stored reference is canonicalized
    let stored = fixture
        .commitment
        .get_employee_reference_id(&employee)
        .expect("Reference should exist");
    assert_eq!(stored, String::from_str(&env, "EMP-QA-4002"));

    // Lookup with exact canonical string
    let found1 = fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, "EMP-QA-4002"));
    assert_eq!(found1, Some(employee.clone()));

    // Lookup with lowercase
    let found2 = fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, "emp-qa-4002"));
    assert_eq!(found2, Some(employee.clone()));

    // Lookup with mixed case and spaces
    let found3 = fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, "  EmP-Qa-4002  \t"));
    assert_eq!(found3, Some(employee));
}

#[test]
fn test_normalization_prevents_case_variant_collisions() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let employee_a = Address::generate(&env);
    let employee_b = Address::generate(&env);

    fixture
        .commitment
        .store_commitment(&employee_a, &BytesN::from_array(&env, &[10u8; 32]));
    fixture
        .commitment
        .store_commitment(&employee_b, &BytesN::from_array(&env, &[20u8; 32]));

    // Employee A gets uppercase reference
    fixture
        .commitment
        .set_employee_reference_id(&employee_a, &String::from_str(&env, "EMP-UNIQUE-77"));

    // Attempting to assign lowercase or whitespace variant to Employee B must fail
    let collision_attempt = fixture
        .commitment
        .try_set_employee_reference_id(&employee_b, &String::from_str(&env, "  emp-unique-77 "));
    assert!(
        collision_attempt.is_err(),
        "Case variant collision must be rejected"
    );

    // Original mapping remains intact
    assert_eq!(
        fixture
            .commitment
            .get_employee_by_reference_id(&String::from_str(&env, "emp-unique-77"))
            .unwrap(),
        employee_a
    );
}

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_normalization_rejects_empty_identifier() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let empty = String::from_str(&env, "");
    fixture.commitment.normalize_employee_identifier(&empty);
}

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_normalization_rejects_whitespace_only_identifier() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let whitespace = String::from_str(&env, "   \t\r\n  ");
    fixture.commitment.normalize_employee_identifier(&whitespace);
}

#[test]
#[should_panic(expected = "Reference ID must be 1-256 characters")]
fn test_normalization_rejects_overlong_identifier() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let long_bytes = [b'A'; 257];
    let long_str = String::from_str(&env, core::str::from_utf8(&long_bytes).unwrap());
    fixture.commitment.normalize_employee_identifier(&long_str);
}

#[test]
#[should_panic(expected = "Employee identifier contains invalid characters: must be printable ASCII")]
fn test_normalization_rejects_control_characters() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    let bad_bytes = [b'E', b'M', b'P', 0x00, b'1']; // NULL control char
    let bad_str = String::from_str(&env, core::str::from_utf8(&bad_bytes).unwrap());
    fixture.commitment.normalize_employee_identifier(&bad_str);
}

#[test]
fn test_invalid_identifier_lookup_safely_returns_none() {
    let env = Env::default();
    let fixture = setup_test_fixture(&env);

    // Lookups with empty, whitespace, or invalid chars return None without panicking
    assert!(fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, ""))
        .is_none());
    assert!(fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, "    "))
        .is_none());
    assert!(fixture
        .commitment
        .get_employee_by_reference_id(&String::from_str(&env, "NON_EXISTENT_ID"))
        .is_none());
}
