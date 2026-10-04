use soroban_sdk::{contract, contractimpl, Env, Address, BytesN};
use crate::approval::ApprovalManager;
use crate::types::ApprovalError;

pub mod types;
pub mod approval;

#[contract]
pub struct ZkPayrollContract;

#[contractimpl]
impl ZkPayrollContract {
    pub fn get_approver_nonce(env: Env, payroll_id: BytesN<32>, approver: Address) -> u64 {
        ApprovalManager::get_nonce(&env, &payroll_id, &approver)
    }

    pub fn submit_payroll_approval(
        env: Env,
        payroll_id: BytesN<32>,
        approver: Address,
        nonce: u64,
        payload_hash: BytesN<32>,
        signature: BytesN<64>,
    ) -> Result<(), ApprovalError> {
        approver.require_auth();

        ApprovalManager::verify_and_consume_approval(
            &env,
            &payroll_id,
            &approver,
            nonce,
            &signature,
            &payload_hash,
        )?;

        Ok(())
    }
}
