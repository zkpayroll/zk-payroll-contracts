use soroban_sdk::{Env, Address, BytesN, Vec};
use crate::types::{DataKey, ApprovalError};

pub struct ApprovalManager;

impl ApprovalManager {
    pub fn get_nonce(env: &Env, payroll_id: &BytesN<32>, approver: &Address) -> u64 {
        let key = DataKey::ApproverNonce(payroll_id.clone(), approver.clone());
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn verify_and_consume_approval(
        env: &Env,
        payroll_id: &BytesN<32>,
        approver: &Address,
        provided_nonce: u64,
        signature: &BytesN<64>,
        payload_hash: &BytesN<32>,
    ) -> Result<(), ApprovalError> {
        let current_nonce = Self::get_nonce(env, payroll_id, approver);

        if provided_nonce != current_nonce {
            return Err(ApprovalError::InvalidNonce);
        }

        let mut msg_bytes = Vec::new(env);
        msg_bytes.append(&payroll_id.to_xdr(env));
        msg_bytes.append(&approver.to_xdr(env));
        msg_bytes.append(&provided_nonce.to_xdr(env));
        msg_bytes.append(&payload_hash.to_xdr(env));

        let binding_hash = env.crypto().sha256(&msg_bytes);

        env.crypto().ed25519_verify(approver, &binding_hash, signature);

        let next_nonce = current_nonce.checked_add(1).ok_or(ApprovalError::InvalidNonce)?;
        let key = DataKey::ApproverNonce(payroll_id.clone(), approver.clone());
        env.storage().persistent().set(&key, &next_nonce);

        Ok(())
    }
}
