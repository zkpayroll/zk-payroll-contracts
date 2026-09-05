#![allow(dead_code)]

use ::token::{Token, TokenClient};
use payroll::{Payroll, PayrollClient};
use proof_verifier::{ProofVerifier, ProofVerifierClient, VerificationKey};
use salary_commitment::{SalaryCommitmentContract, SalaryCommitmentContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, Vec};

fn mock_vk(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[0; 64]),
        beta: BytesN::from_array(env, &[0; 128]),
        gamma: BytesN::from_array(env, &[0; 128]),
        delta: BytesN::from_array(env, &[0; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
                BytesN::from_array(env, &[0; 64]),
            ],
        ),
    }
}

pub fn setup(env: &Env) -> (PayrollClient<'_>, Address, Address) {
    env.mock_all_auths();

    let verifier = env.register_contract(None, ProofVerifier);
    let verifier_client = ProofVerifierClient::new(env, &verifier);
    verifier_client.init_verifier_admin(&Address::generate(env));
    verifier_client.initialize_verifier(&mock_vk(env));

    let commitment = env.register_contract(None, SalaryCommitmentContract);
    let commitment_client = SalaryCommitmentContractClient::new(env, &commitment);
    commitment_client.init_commitment_admin(&Address::generate(env));

    let token = env.register_contract(None, Token);
    let treasury = Address::generate(env);
    TokenClient::new(env, &token).mint(&treasury, &1_000_000);

    let contract = env.register_contract(None, Payroll);
    let client = PayrollClient::new(env, &contract);
    let admin = Address::generate(env);
    client.initialize(
        &admin,
        &token,
        &verifier,
        &commitment,
        &treasury,
        &Address::generate(env),
    );
    commitment_client.set_payroll_operator(&contract);

    let employee = Address::generate(env);
    commitment_client.store_commitment(&employee, &BytesN::from_array(env, &[0; 32]));
    (client, token, employee)
}

pub fn nonce(env: &Env, marker: u8) -> BytesN<32> {
    let mut bytes = [0; 32];
    bytes[0] = marker;
    BytesN::from_array(env, &bytes)
}

pub fn one_payment(env: &Env, employee: &Address) -> (Vec<BytesN<256>>, Vec<i128>, Vec<Address>) {
    (
        Vec::from_array(env, [BytesN::from_array(env, &[1; 256])]),
        Vec::from_array(env, [100_i128]),
        Vec::from_array(env, [employee.clone()]),
    )
}

/// Normalize an asset symbol for allowlist/reservation checks.
/// The canonical form is trimmed, uppercase, alphanumeric-only, and at most 12 characters.
pub fn normalize_asset_symbol(symbol: &str) -> Result<String, &'static str> {
    let trimmed = symbol.trim();
    if trimmed.is_empty() {
        return Err("asset symbol cannot be empty");
    }
    if trimmed.len() > 12 {
        return Err("asset symbol must be at most 12 characters");
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("asset symbol must contain only alphanumeric characters");
    }
    Ok(trimmed.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::normalize_asset_symbol;

    #[test]
    fn test_normalize_asset_symbol_uppercases() {
        assert_eq!(normalize_asset_symbol("usdc"), Ok("USDC".to_string()));
    }

    #[test]
    fn test_normalize_asset_symbol_trims_whitespace() {
        assert_eq!(normalize_asset_symbol("  usdc  "), Ok("USDC".to_string()));
    }

    #[test]
    fn test_normalize_asset_symbol_accepts_uppercase() {
        assert_eq!(normalize_asset_symbol("USDC"), Ok("USDC".to_string()));
    }

    #[test]
    fn test_normalize_asset_symbol_rejects_empty() {
        assert_eq!(normalize_asset_symbol("   "), Err("asset symbol cannot be empty"));
    }

    #[test]
    fn test_normalize_asset_symbol_rejects_too_long() {
        assert_eq!(
            normalize_asset_symbol("TOOLONGSYMBOL"),
            Err("asset symbol must be at most 12 characters")
        );
    }

    #[test]
    fn test_normalize_asset_symbol_rejects_special_characters() {
        assert_eq!(
            normalize_asset_symbol("usdc-"),
            Err("asset symbol must contain only alphanumeric characters")
        );
    }
}
