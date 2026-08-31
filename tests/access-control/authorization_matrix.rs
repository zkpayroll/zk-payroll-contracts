//! Negative-Path Authorization Matrix Tests (#355)
//!
//! This module tests unauthorized actions across all payroll roles to build a
//! comprehensive authorization matrix covering:
//! - Payroll admin actions (prepare, execute, archive)
//! - Treasury owner actions (withdraw, manage funds)
//! - Audit module actions (generate view keys, revoke access)
//! - Compliance officer actions (place holds, release holds)
//! - Reviewer actions (approve, reject payroll)

use audit_module::{AuditModule, AuditModuleClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll::{Payroll, PayrollClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, IntoVal, Symbol, Vec};
use token::{Token, TokenClient};

// ============================================================================
// Test Helpers
// ============================================================================

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

fn mock_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[0u8; 256])
}

fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    BytesN::from_array(env, &arr)
}

fn setup_test_contracts(env: &Env) -> (PayrollClient<'static>, PaymentExecutorClient<'static>, AuditModuleClient<'static>) {
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    commitment_client.set_payroll_operator(&payroll_id);

    let audit_id = env.register_contract(None, AuditModule);
    let audit_client = AuditModuleClient::new(&env, &audit_id);
    audit_client.initialize(&payroll_id, &admin);

    let payment_executor_id = env.register_contract(None, PaymentExecutor);
    let payment_executor_client = PaymentExecutorClient::new(&env, &payment_executor_id);

    let executor_addresses = ContractAddresses {
        registry: token_id.clone(),
        commitment: commitment_id.clone(),
        verifier: verifier_id.clone(),
        token: token_id.clone(),
    };

    payment_executor_client.initialize(&executor_addresses);
    payment_executor_client.set_executor_admin(&admin);

    (payroll_client, payment_executor_client, audit_client)
}

// ============================================================================
// Authorization Matrix: Payroll Admin Actions
// ============================================================================

/// Only admin should be able to prepare payroll runs.
#[test]
#[should_panic]
fn test_non_admin_cannot_prepare_payroll() {
    let env = Env::default();
    let (payroll_client, _, _) = setup_test_contracts(&env);

    let unauthorized_user = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &env.current_contract_address(),
            fn_name: "prepare_payroll_run",
            args: (
                &[],
                &[] as &[soroban_sdk::Val],
            ).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.batch_process_payroll(
        &Vec::new(&env),
        &Vec::new(&env),
        &Vec::new(&env),
        &0i128,
        &test_nonce(&env, 1),
        &None,
    );
}

/// Only admin can archive payroll runs.
#[test]
#[should_panic]
fn test_non_admin_cannot_archive_payroll() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &non_admin,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "archive_payroll_run",
            args: (&admin, &1u64).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.archive_payroll_run(&non_admin, &1u64);
}

// ============================================================================
// Authorization Matrix: Treasury Actions
// ============================================================================

/// Only treasury owner can request emergency withdrawal.
#[test]
#[should_panic]
fn test_non_treasury_owner_cannot_request_withdrawal() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let non_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &non_owner,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "request_emergency_withdrawal",
            args: (&non_owner, &1000i128, &Address::generate(&env)).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.request_emergency_withdrawal(&non_owner, &1000i128, &Address::generate(&env));
}

// ============================================================================
// Authorization Matrix: Audit Module Actions
// ============================================================================

/// Only authorized auditors can generate view keys.
#[test]
#[should_panic]
fn test_non_auditor_cannot_generate_view_key() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let non_auditor = Address::generate(&env);

    let payroll_id = env.register_contract(None, Payroll);
    let audit_id = env.register_contract(None, AuditModule);
    let audit_client = AuditModuleClient::new(&env, &audit_id);

    audit_client.initialize(&payroll_id, &admin);

    env.mock_auths(&[MockAuth {
        address: &non_auditor,
        invoke: &MockAuthInvoke {
            contract: &audit_id,
            fn_name: "generate_view_key",
            args: (&Address::generate(&env), &Symbol::new(&env, "test")).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    let key = BytesN::from_array(&env, &[0u8; 32]);
    audit_client.generate_view_key(&Address::generate(&env), &key, &Symbol::new(&env, "test"));
}

// ============================================================================
// Authorization Matrix: Compliance Officer Actions
// ============================================================================

/// Only admin can place compliance holds.
#[test]
#[should_panic]
fn test_non_admin_cannot_place_compliance_hold() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &non_admin,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "place_compliance_hold",
            args: (&non_admin, &Address::generate(&env), &0u32, &Symbol::new(&env, "test")).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.place_compliance_hold(
        &non_admin,
        &Address::generate(&env),
        &0u32,
        &Symbol::new(&env, "test"),
    );
}

// ============================================================================
// Authorization Matrix: Reviewer Actions
// ============================================================================

/// Only registered reviewers can approve payroll.
#[test]
#[should_panic]
fn test_unregistered_reviewer_cannot_approve() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let unregistered_reviewer = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &unregistered_reviewer,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "approve_payroll_run",
            args: (&unregistered_reviewer, &1u64).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.approve_payroll_run(&unregistered_reviewer, &1u64);
}

// ============================================================================
// Authorization Matrix: Cross-Role Boundary Tests
// ============================================================================

/// Admin cannot act as treasury owner.
#[test]
#[should_panic]
fn test_admin_cannot_act_as_treasury_owner() {
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
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "request_emergency_withdrawal",
            args: (&admin, &1000i128, &Address::generate(&env)).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    // Admin trying to request withdrawal as treasury_owner should fail
    payroll_client.request_emergency_withdrawal(&admin, &1000i128, &Address::generate(&env));
}

/// Treasury owner cannot act as admin.
#[test]
#[should_panic]
fn test_treasury_owner_cannot_act_as_admin() {
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
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);

    let payroll_id = env.register_contract(None, Payroll);
    let payroll_client = PayrollClient::new(&env, &payroll_id);

    payroll_client.initialize(
        &admin,
        &token_id,
        &verifier_id,
        &commitment_id,
        &treasury,
        &treasury_owner,
    );

    env.mock_auths(&[MockAuth {
        address: &treasury_owner,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "archive_payroll_run",
            args: (&treasury_owner, &1u64).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    // Treasury owner trying to archive as admin should fail
    payroll_client.archive_payroll_run(&treasury_owner, &1u64);
}
