#![cfg(test)]

use soroban_sdk::{Env, Address, BytesN, testutils::Address as _};
use zk_payroll_contracts::{ZkPayrollContract, ZkPayrollContractClient, types::ApprovalError};

#[test]
fn test_successful_signed_approval_increments_nonce() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkPayrollContract);
    let client = ZkPayrollContractClient::new(&env, &contract_id);

    let approver = Address::generate(&env);
    let payroll_id = BytesN::from_array(&env, &[1u8; 32]);
    let payload_hash = BytesN::from_array(&env, &[2u8; 32]);
    let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

    assert_eq!(client.get_approver_nonce(&payroll_id, &approver), 0);

    env.mock_all_signatures();
    let result = client.try_submit_payroll_approval(&payroll_id, &approver, &0, &payload_hash, &dummy_sig);
    assert!(result.is_ok());

    assert_eq!(client.get_approver_nonce(&payroll_id, &approver), 1);
}

#[test]
fn test_replayed_approval_signature_fails_with_invalid_nonce() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ZkPayrollContract);
    let client = ZkPayrollContractClient::new(&env, &contract_id);

    let approver = Address::generate(&env);
    let payroll_id = BytesN::from_array(&env, &[1u8; 32]);
    let payload_hash = BytesN::from_array(&env, &[2u8; 32]);
    let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

    env.mock_all_signatures();

    let first_attempt = client.try_submit_payroll_approval(&payroll_id, &approver, &0, &payload_hash, &dummy_sig);
    assert!(first_attempt.is_ok());

    let replay_attempt = client.try_submit_payroll_approval(&payroll_id, &approver, &0, &payload_hash, &dummy_sig);
    assert_eq!(replay_attempt, Err(Ok(ApprovalError::InvalidNonce)));
}
