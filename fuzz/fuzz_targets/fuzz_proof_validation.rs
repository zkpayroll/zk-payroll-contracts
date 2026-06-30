#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use soroban_sdk::{
    Address, BytesN, Env, Vec, testutils::Address as _,
};
use payment_executor::{
    ContractAddresses, PaymentExecutor, PaymentExecutorClient, PaymentError,
};
use payroll_registry::{PayrollRegistry, PayrollRegistryClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey, Groth16Proof};
use token::{Token, TokenClient};

#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    pub action: FuzzAction,
}

#[derive(Arbitrary, Debug)]
pub enum FuzzAction {
    VerifyDirect {
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs: std::vec::Vec<[u8; 32]>,
        vk_alpha: [u8; 64],
        vk_beta: [u8; 128],
        vk_gamma: [u8; 128],
        vk_delta: [u8; 128],
        vk_ic: std::vec::Vec<[u8; 64]>,
    },
    VerifyPaymentProofDirect {
        proof_bytes: [u8; 256],
        public_inputs: std::vec::Vec<[u8; 32]>,
        vk_alpha: [u8; 64],
        vk_beta: [u8; 128],
        vk_gamma: [u8; 128],
        vk_delta: [u8; 128],
        vk_ic: std::vec::Vec<[u8; 64]>,
    },
    ExecutePayment {
        amount: i128,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        nullifier: [u8; 32],
        period: u32,
        commitment: [u8; 32],
        use_valid_inputs: bool,
    },
    ExecuteBatchPayroll {
        amounts: std::vec::Vec<i128>,
        proofs_a: std::vec::Vec<[u8; 64]>,
        proofs_b: std::vec::Vec<[u8; 128]>,
        proofs_c: std::vec::Vec<[u8; 64]>,
        nullifiers: std::vec::Vec<[u8; 32]>,
        commitments: std::vec::Vec<[u8; 32]>,
        period: u32,
        force_duplicate_nullifier: bool,
        force_empty_batch: bool,
        force_mismatched_length: bool,
    },
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
            ],
        ),
    }
}

struct TestSystem<'a> {
    env: Env,
    executor: PaymentExecutorClient<'a>,
    registry: PayrollRegistryClient<'a>,
    verifier: ProofVerifierClient<'a>,
    token: TokenClient<'a>,
    company_id: u64,
    admin: Address,
    treasury: Address,
}

fn setup_system(env: &Env) -> TestSystem {
    env.mock_all_auths();

    let executor_id = env.register_contract(None, PaymentExecutor);
    let registry_id = env.register_contract(None, PayrollRegistry);
    let verifier_id = env.register_contract(None, ProofVerifier);
    let token_id = env.register_contract(None, Token);

    let executor = PaymentExecutorClient::new(env, &executor_id);
    let registry = PayrollRegistryClient::new(env, &registry_id);
    let verifier = ProofVerifierClient::new(env, &verifier_id);
    let token = TokenClient::new(env, &token_id);

    let addresses = ContractAddresses {
        registry: registry_id,
        commitment: Address::generate(env),
        verifier: verifier_id,
        token: token_id,
    };

    executor.initialize(&addresses);
    verifier.init_verifier_admin(&Address::generate(env));
    verifier.initialize_verifier(&mock_vk(env));

    let admin = Address::generate(env);
    let treasury = Address::generate(env);

    let company_id = registry.register_company(&admin, &treasury);
    executor.create_period(&company_id).unwrap();

    token.mint(&treasury, &1_000_000);

    TestSystem {
        env: env.clone(),
        executor,
        registry,
        verifier,
        token,
        company_id,
        admin,
        treasury,
    }
}

fuzz_target!(|input: FuzzInput| {
    match input.action {
        FuzzAction::VerifyDirect {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            vk_alpha,
            vk_beta,
            vk_gamma,
            vk_delta,
            vk_ic,
        } => {
            let env = Env::default();
            env.mock_all_auths();

            let verifier_id = env.register_contract(None, ProofVerifier);
            let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
            verifier_client.init_verifier_admin(&Address::generate(&env));

            let vk = VerificationKey {
                alpha: BytesN::from_array(&env, &vk_alpha),
                beta: BytesN::from_array(&env, &vk_beta),
                gamma: BytesN::from_array(&env, &vk_gamma),
                delta: BytesN::from_array(&env, &vk_delta),
                ic: {
                    let mut vec = Vec::new(&env);
                    // limit to avoid high CPU/memory overhead during fuzzer execution
                    for ic_bytes in vk_ic.iter().take(10) {
                        vec.push_back(BytesN::from_array(&env, ic_bytes));
                    }
                    vec
                },
            };

            verifier_client.initialize_verifier(&vk);

            let proof = Groth16Proof {
                a: BytesN::from_array(&env, &proof_a),
                b: BytesN::from_array(&env, &proof_b),
                c: BytesN::from_array(&env, &proof_c),
            };

            let mut inputs = Vec::new(&env);
            for input_bytes in public_inputs.iter().take(10) {
                inputs.push_back(BytesN::from_array(&env, input_bytes));
            }

            let _ = verifier_client.try_verify(&proof, &inputs);
        }

        FuzzAction::VerifyPaymentProofDirect {
            proof_bytes,
            public_inputs,
            vk_alpha,
            vk_beta,
            vk_gamma,
            vk_delta,
            vk_ic,
        } => {
            let env = Env::default();
            env.mock_all_auths();

            let verifier_id = env.register_contract(None, ProofVerifier);
            let verifier_client = ProofVerifierClient::new(&env, &verifier_id);
            verifier_client.init_verifier_admin(&Address::generate(&env));

            let vk = VerificationKey {
                alpha: BytesN::from_array(&env, &vk_alpha),
                beta: BytesN::from_array(&env, &vk_beta),
                gamma: BytesN::from_array(&env, &vk_gamma),
                delta: BytesN::from_array(&env, &vk_delta),
                ic: {
                    let mut vec = Vec::new(&env);
                    for ic_bytes in vk_ic.iter().take(10) {
                        vec.push_back(BytesN::from_array(&env, ic_bytes));
                    }
                    vec
                },
            };

            verifier_client.initialize_verifier(&vk);

            let proof = BytesN::from_array(&env, &proof_bytes);

            let mut inputs = Vec::new(&env);
            for input_bytes in public_inputs.iter().take(10) {
                inputs.push_back(BytesN::from_array(&env, input_bytes));
            }

            let _ = verifier_client.try_verify_payment_proof(&proof, &inputs);
        }

        FuzzAction::ExecutePayment {
            amount,
            proof_a,
            proof_b,
            proof_c,
            nullifier,
            period,
            commitment,
            use_valid_inputs,
        } => {
            let env = Env::default();
            let sys = setup_system(&env);

            let employee = Address::generate(&env);

            let test_amount = if use_valid_inputs {
                if amount == i128::MIN {
                    1
                } else {
                    amount.abs().max(1)
                }
            } else {
                amount
            };

            let test_period = if use_valid_inputs { 1 } else { period };

            sys.registry.add_employee(
                &sys.company_id,
                &employee,
                &BytesN::from_array(&env, &commitment),
            );

            let initial_treasury = sys.token.balance(&sys.treasury);
            let initial_employee = sys.token.balance(&employee);

            let res = sys.executor.try_execute_payment(
                &sys.company_id,
                &employee,
                &test_amount,
                &BytesN::from_array(&env, &proof_a),
                &BytesN::from_array(&env, &proof_b),
                &BytesN::from_array(&env, &proof_c),
                &BytesN::from_array(&env, &nullifier),
                &test_period,
            );

            if let Ok(Ok(_record)) = res {
                // Invariant assertions on successful payment execution
                assert!(test_amount >= 0);
                assert_eq!(sys.token.balance(&employee), initial_employee + test_amount);
                assert_eq!(sys.token.balance(&sys.treasury), initial_treasury - test_amount);
                assert!(sys.executor.is_paid(&employee, &test_period));
                assert!(sys.executor.get_total_paid(&sys.company_id) >= test_amount);

                // Proof Replay Prevention Invariant: Re-submitting same nullifier must fail
                let replay_res = sys.executor.try_execute_payment(
                    &sys.company_id,
                    &employee,
                    &test_amount,
                    &BytesN::from_array(&env, &proof_a),
                    &BytesN::from_array(&env, &proof_b),
                    &BytesN::from_array(&env, &proof_c),
                    &BytesN::from_array(&env, &nullifier),
                    &test_period,
                );
                assert_eq!(replay_res.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
            } else {
                // Transaction Atomicity Invariant: Check that no state / balance changed on failure
                assert_eq!(sys.token.balance(&employee), initial_employee);
                assert_eq!(sys.token.balance(&sys.treasury), initial_treasury);
            }
        }

        FuzzAction::ExecuteBatchPayroll {
            amounts,
            proofs_a,
            proofs_b,
            proofs_c,
            nullifiers,
            commitments,
            period,
            force_duplicate_nullifier,
            force_empty_batch,
            force_mismatched_length,
        } => {
            let env = Env::default();
            let sys = setup_system(&env);

            let mut batch_size = if force_empty_batch {
                0
            } else {
                let mut sz = amounts.len()
                    .min(proofs_a.len())
                    .min(proofs_b.len())
                    .min(proofs_c.len())
                    .min(nullifiers.len())
                    .min(commitments.len());
                if sz > 15 {
                    sz = 15; // limit size to keep execution fast
                }
                sz
            };

            let mut test_amounts = std::vec::Vec::new();
            let mut test_proofs_a = std::vec::Vec::new();
            let mut test_proofs_b = std::vec::Vec::new();
            let mut test_proofs_c = std::vec::Vec::new();
            let mut test_nullifiers = std::vec::Vec::new();
            let mut test_employees = std::vec::Vec::new();

            for i in 0..batch_size {
                let employee = Address::generate(&env);
                sys.registry.add_employee(
                    &sys.company_id,
                    &employee,
                    &BytesN::from_array(&env, &commitments[i]),
                );
                test_employees.push(employee);
                let amt = if amounts[i] == i128::MIN {
                    1
                } else {
                    amounts[i].abs().max(1)
                };
                test_amounts.push(amt);
                test_proofs_a.push(BytesN::from_array(&env, &proofs_a[i]));
                test_proofs_b.push(BytesN::from_array(&env, &proofs_b[i]));
                test_proofs_c.push(BytesN::from_array(&env, &proofs_c[i]));
                test_nullifiers.push(BytesN::from_array(&env, &nullifiers[i]));
            }

            if force_duplicate_nullifier && batch_size >= 2 {
                test_nullifiers[1] = test_nullifiers[0].clone();
            }

            if force_mismatched_length {
                // Deliberately push an extra element to test error handling for length mismatches
                test_amounts.push(100);
            }

            let mut sdk_employees = Vec::new(&env);
            for emp in &test_employees {
                sdk_employees.push_back(emp.clone());
            }

            let mut sdk_amounts = Vec::new(&env);
            for amt in &test_amounts {
                sdk_amounts.push_back(*amt);
            }

            let mut sdk_proofs_a = Vec::new(&env);
            for p in &test_proofs_a {
                sdk_proofs_a.push_back(p.clone());
            }

            let mut sdk_proofs_b = Vec::new(&env);
            for p in &test_proofs_b {
                sdk_proofs_b.push_back(p.clone());
            }

            let mut sdk_proofs_c = Vec::new(&env);
            for p in &test_proofs_c {
                sdk_proofs_c.push_back(p.clone());
            }

            let mut sdk_nullifiers = Vec::new(&env);
            for n in &test_nullifiers {
                sdk_nullifiers.push_back(n.clone());
            }

            let initial_treasury = sys.token.balance(&sys.treasury);
            let mut initial_balances = std::vec::Vec::new();
            for emp in &test_employees {
                initial_balances.push(sys.token.balance(emp));
            }

            let res = sys.executor.try_execute_batch_payroll(
                &sys.company_id,
                &sdk_employees,
                &sdk_amounts,
                &sdk_proofs_a,
                &sdk_proofs_b,
                &sdk_proofs_c,
                &sdk_nullifiers,
                &period,
            );

            match res {
                Ok(Ok(records)) => {
                    // Invariant assertions on successful batch execution
                    assert_eq!(records.len() as usize, batch_size);
                    let mut total_expected_deduction = 0;
                    for (i, emp) in test_employees.iter().enumerate() {
                        assert_eq!(sys.token.balance(emp), initial_balances[i] + test_amounts[i]);
                        total_expected_deduction += test_amounts[i];
                    }
                    assert_eq!(sys.token.balance(&sys.treasury), initial_treasury - total_expected_deduction);

                    // Duplicate nullifier checks: if batch succeeded, then all nullifiers used must be registered
                    for (i, emp) in test_employees.iter().enumerate() {
                        let replay_res = sys.executor.try_execute_payment(
                            &sys.company_id,
                            emp,
                            &test_amounts[i],
                            &test_proofs_a[i],
                            &test_proofs_b[i],
                            &test_proofs_c[i],
                            &test_nullifiers[i],
                            &period,
                        );
                        assert_eq!(replay_res.unwrap_err().unwrap(), PaymentError::ProofAlreadyUsed);
                    }
                }
                _ => {
                    // Transaction Atomicity Invariant: If batch execution fails, no state/balance changes must persist
                    assert_eq!(sys.token.balance(&sys.treasury), initial_treasury);
                    for (i, emp) in test_employees.iter().enumerate() {
                        assert_eq!(sys.token.balance(emp), initial_balances[i]);
                    }
                }
            }
        }
    }
});
