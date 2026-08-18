//! Access Control Tests for Unauthorized Payroll Actions
//!
//! This module contains negative tests that verify unauthorized users cannot perform
//! protected payroll actions. These tests complement the happy-path tests by explicitly
//! testing permission boundaries.
//!
//! Test Categories:
//! - Unauthorized payroll creation (prepare_payroll_run, batch_process_payroll)
//! - Unauthorized employee state modifications (add_employee, update_commitment, set_employee_status)
//! - Unauthorized payroll execution (execute_payment in payment_executor)
//! - Unauthorized audit access changes (revoke_view_key, generate_view_key)

use audit_module::{AuditModule, AuditModuleClient};
use payment_executor::{ContractAddresses, PaymentExecutor, PaymentExecutorClient};
use payroll::{Payroll, PayrollClient};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, Symbol, Vec};
use token::{Token, TokenClient};

// ============================================================================
// Helper Functions
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

// ============================================================================
// Category 1: Unauthorized Payroll Creation Tests
// ============================================================================

/// Test that unauthorized users cannot prepare payroll runs.
/// Only the contract admin should be able to call prepare_payroll_run.
#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_unauthorized_prepare_payroll_run_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

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

    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.set_payroll_operator(&payroll_id);

    // Attempt to prepare payroll run as unauthorized user
    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "prepare_payroll_run",
            args: (
                Vec::from_array(&env, [mock_proof(&env)]),
                Vec::from_array(&env, [1000i128]),
                Vec::from_array(&env, [Address::generate(&env)]),
                1000i128,
                test_nonce(&env, 1),
                None::<BytesN<32>>,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.prepare_payroll_run(
        &Vec::from_array(&env, [mock_proof(&env)]),
        &Vec::from_array(&env, [1000i128]),
        &Vec::from_array(&env, [Address::generate(&env)]),
        &1000i128,
        &test_nonce(&env, 1),
        &None::<BytesN<32>>,
    );
}

/// Test that unauthorized users cannot execute batch payroll.
/// Only the contract admin should be able to call batch_process_payroll.
#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_unauthorized_batch_process_payroll_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

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

    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.set_payroll_operator(&payroll_id);

    // Attempt to batch process payroll as unauthorized user
    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &payroll_id,
            fn_name: "batch_process_payroll",
            args: (
                Vec::from_array(&env, [mock_proof(&env)]),
                Vec::from_array(&env, [1000i128]),
                Vec::from_array(&env, [Address::generate(&env)]),
                1000i128,
                test_nonce(&env, 1),
                None::<BytesN<32>>,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    payroll_client.batch_process_payroll(
        &Vec::from_array(&env, [mock_proof(&env)]),
        &Vec::from_array(&env, [1000i128]),
        &Vec::from_array(&env, [Address::generate(&env)]),
        &1000i128,
        &test_nonce(&env, 1),
        &None::<BytesN<32>>,
    );
}

/// Test that unauthorized users cannot cancel payroll runs.
/// Only the contract admin should be able to call cancel_payroll_run.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_cancel_payroll_run_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

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

    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.set_payroll_operator(&payroll_id);

    // First prepare a payroll run as admin
    let run_id = payroll_client.prepare_payroll_run(
        &Vec::from_array(&env, [mock_proof(&env)]),
        &Vec::from_array(&env, [1000i128]),
        &Vec::from_array(&env, [Address::generate(&env)]),
        &1000i128,
        &test_nonce(&env, 1),
        &None::<BytesN<32>>,
    );

    // Attempt to cancel as unauthorized user
    payroll_client.cancel_payroll_run(&unauthorized_user, &run_id);
}

/// Test that unauthorized users cannot commit draft hashes.
/// Only the contract admin should be able to call commit_draft.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_commit_draft_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

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

    let draft_hash = BytesN::from_array(&env, &[1u8; 32]);

    // Attempt to commit draft as unauthorized user
    payroll_client.commit_draft(&unauthorized_user, &draft_hash);
}

// ============================================================================
// Category 2: Unauthorized Employee State Modification Tests
// ============================================================================

/// Test that unauthorized users cannot add employees to a company.
/// Only the company admin should be able to call add_employee.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_add_employee_fails() {
    let env = Env::default();

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "register_company",
            args: (admin.clone(), treasury.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    let company_id = registry.register_company(&admin, &treasury);

    let attacker = Address::generate(&env);
    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "add_employee",
            args: (company_id, employee.clone(), commitment.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.add_employee(&company_id, &employee, &commitment);
}

/// Test that unauthorized users cannot update employee commitments.
/// Only the company admin should be able to call update_commitment.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_update_commitment_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    registry.add_employee(&company_id, &employee, &commitment);

    let attacker = Address::generate(&env);
    let new_commitment = BytesN::from_array(&env, &[10u8; 32]);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "update_commitment",
            args: (company_id, employee.clone(), new_commitment.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.update_commitment(&company_id, &employee, &new_commitment);
}

/// Test that unauthorized users cannot set employee status.
/// Only the company admin should be able to call set_employee_status.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_set_employee_status_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    registry.add_employee(&company_id, &employee, &commitment);

    let attacker = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "set_employee_status",
            args: (
                company_id,
                employee.clone(),
                payroll_registry::EmployeeStatus::Inactive,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.set_employee_status(
        &company_id,
        &employee,
        &payroll_registry::EmployeeStatus::Inactive,
    );
}

/// Test that unauthorized users cannot remove employees.
/// Only the company admin should be able to call remove_employee.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_remove_employee_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, PayrollRegistry);
    let registry = PayrollRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    registry.add_employee(&company_id, &employee, &commitment);

    let attacker = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &attacker,
        invoke: &MockAuthInvoke {
            contract: &registry_id,
            fn_name: "remove_employee",
            args: (company_id, employee.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    registry.remove_employee(&company_id, &employee);
}

// ============================================================================
// Category 3: Unauthorized Payroll Execution Tests
// ============================================================================

/// Test that unauthorized users cannot execute payments.
/// Only the company admin should be able to call execute_payment.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_execute_payment_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(&env, &executor_id);
    let registry = PayrollRegistryClient::new(&env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let verifier = ProofVerifierClient::new(&env, &verifier_id);
    let token = TokenClient::new(&env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(&env));
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    executor.create_period(&company_id);

    let employee = Address::generate(&env);
    let commitment = BytesN::from_array(&env, &[9u8; 32]);
    commitment_client.store_commitment(&employee, &commitment);
    registry.add_employee(&company_id, &employee, &commitment);

    token.mint(&treasury, &100_000);

    let unauthorized_user = Address::generate(&env);
    let proof_a = BytesN::from_array(&env, &[1u8; 64]);
    let proof_b = BytesN::from_array(&env, &[2u8; 128]);
    let proof_c = BytesN::from_array(&env, &[3u8; 64]);
    let nullifier = BytesN::from_array(&env, &[4u8; 32]);

    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &executor_id,
            fn_name: "execute_payment",
            args: (
                company_id,
                employee.clone(),
                1000i128,
                proof_a.clone(),
                proof_b.clone(),
                proof_c.clone(),
                nullifier.clone(),
                1u32,
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);

    executor.execute_payment(
        &company_id,
        &employee,
        &1000,
        &proof_a,
        &proof_b,
        &proof_c,
        &nullifier,
        &1,
    );
}

/// Test that unauthorized users cannot create payroll periods.
/// Only the company admin should be able to call create_period.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_create_period_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(&env, &executor_id);
    let registry = PayrollRegistryClient::new(&env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let verifier = ProofVerifierClient::new(&env, &verifier_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(&env));
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    let unauthorized_user = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &executor_id,
            fn_name: "create_period",
            args: (company_id,).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    executor.create_period(&company_id);
}

/// Test that unauthorized users cannot close payroll periods.
/// Only the company admin should be able to call close_period.
#[test]
#[should_panic(expected = "authorized")]
fn test_unauthorized_close_period_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(&env, &executor_id);
    let registry = PayrollRegistryClient::new(&env, &registry_id);
    let commitment_client = SalaryCommitmentContractClient::new(&env, &commitment_id);
    let verifier = ProofVerifierClient::new(&env, &verifier_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: commitment_id,
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(&env));
    verifier.initialize_verifier(&mock_vk(&env));

    let commitment_admin = Address::generate(&env);
    commitment_client.init_commitment_admin(&commitment_admin);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let company_id = registry.register_company(&admin, &treasury);

    executor.create_period(&company_id);

    let unauthorized_user = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &executor_id,
            fn_name: "close_period",
            args: (company_id, 1u32).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    executor.close_period(&company_id, &1);
}

// ============================================================================
// Category 4: Unauthorized Audit Access Change Tests
// ============================================================================

/// Test that unauthorized users cannot revoke view keys.
/// Only the admin who granted the key should be able to revoke it.
#[test]
fn test_unauthorized_revoke_view_key_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    let auditor = Address::generate(&env);
    let seq = env.ledger().sequence();
    client.generate_view_key(&auditor, &(seq + 1_000));

    let unauthorized_admin = Address::generate(&env);
    let result = client.try_revoke_view_key(&unauthorized_admin, &auditor);

    // Should fail with NotKeyGranter error
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().unwrap(),
        audit_module::AuditError::NotKeyGranter
    );

    // Verify the key is still active
    assert!(client.verify_access(&auditor));
}

/// Test that non-admins cannot set pause manager in audit module.
/// Only the admin should be able to call set_pause_manager.
#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_unauthorized_set_audit_pause_manager_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, AuditModule);
    let client = AuditModuleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let pause_manager = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    env.mock_auths(&[MockAuth {
        address: &unauthorized_user,
        invoke: &MockAuthInvoke {
            contract: &contract_id,
            fn_name: "set_pause_manager",
            args: (admin.clone(), pause_manager.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    client.set_pause_manager(&admin, &pause_manager);
}

/// Test that unauthorized users cannot approve emergency withdrawal.
/// Only the contract admin should be able to call approve_emergency_withdrawal.
#[test]
#[should_panic(expected = "Unauthorized")]
fn test_unauthorized_approve_emergency_withdrawal_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

    let token_id = env.register_contract(None, Token);
    let token_client = TokenClient::new(&env, &token_id);

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

    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.set_payroll_operator(&payroll_id);

    // Fund the treasury
    token_client.mint(&treasury, &10_000);

    // Request emergency withdrawal as treasury owner
    let recipient = Address::generate(&env);
    payroll_client.request_emergency_withdrawal(&treasury_owner, &5000, &recipient);

    // Attempt to approve as unauthorized user
    payroll_client.approve_emergency_withdrawal(&unauthorized_user);
}

/// Test that unauthorized users cannot request emergency withdrawal.
/// Only the treasury_owner should be able to call request_emergency_withdrawal.
#[test]
#[should_panic(expected = "Unauthorized: caller is not treasury owner")]
fn test_unauthorized_request_emergency_withdrawal_fails() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    let treasury_owner = Address::generate(&env);
    let unauthorized_user = Address::generate(&env);

    let verifier_id = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
    verifier_client.init_verifier_admin(&admin);
    verifier_client.initialize_verifier(&mock_vk(&env));

    let commitment_id = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.init_commitment_admin(&admin);

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

    let commitment_client_init = SalaryCommitmentContractClient::new(&env, &commitment_id);
    commitment_client_init.set_payroll_operator(&payroll_id);

    let recipient = Address::generate(&env);

    // Attempt to request emergency withdrawal as unauthorized user
    payroll_client.request_emergency_withdrawal(&unauthorized_user, &5000, &recipient);
}
