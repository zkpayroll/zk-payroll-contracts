//! Deterministic payroll run identifiers (#480).
//!
//! # Coverage
//! | Test | Scenario |
//! |------|----------|
//! | `computed_identifier_matches_documented_formula` | Query helper, off-chain SHA-256, and input sensitivity agree |
//! | `executed_run_exposes_reproducible_identifier` | Direct execution exposes the identifier the caller could compute beforehand |
//! | `pending_identifier_is_stable_after_finalization` | A prepared run keeps the same identifier once finalized |
//! | `unknown_and_reserved_ids_fail_without_leaking_values` | Checked failure states are stable and payload-free |
//! | `get_identifier_panics_for_unknown_run` | Panicking lookup is actionable and value-free |

#![cfg(test)]

mod common;

use payroll::PayrollRunIdentifierError;
use soroban_sdk::{Bytes, BytesN, Env};

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

/// Independent implementation of the documented encoding, standing in for an
/// SDK or dashboard computing the identifier without calling the contract.
fn off_chain_identifier(
    env: &Env,
    nonce: &BytesN<32>,
    employee_count: u32,
    draft_hash: &BytesN<32>,
) -> BytesN<32> {
    let mut preimage = Bytes::new(env);
    preimage.extend_from_slice(b"zkpayroll_run_identifier_v1");
    preimage.extend_from_array(&nonce.to_array());
    preimage.extend_from_array(&employee_count.to_be_bytes());
    preimage.extend_from_array(&draft_hash.to_array());
    env.crypto().sha256(&preimage).into()
}

#[test]
fn computed_identifier_matches_documented_formula() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    let nonce = common::nonce(&env, 11);
    let draft_hash = BytesN::from_array(&env, &[7u8; 32]);

    let on_chain = client.compute_payroll_run_identifier(&nonce, &2u32, &draft_hash);
    assert_eq!(on_chain, off_chain_identifier(&env, &nonce, 2, &draft_hash));

    // Same inputs are reproducible; each bound field changes the identifier.
    assert_eq!(
        on_chain,
        client.compute_payroll_run_identifier(&nonce, &2u32, &draft_hash)
    );
    assert_ne!(
        on_chain,
        client.compute_payroll_run_identifier(&common::nonce(&env, 12), &2u32, &draft_hash)
    );
    assert_ne!(
        on_chain,
        client.compute_payroll_run_identifier(&nonce, &3u32, &draft_hash)
    );
    assert_ne!(
        on_chain,
        client.compute_payroll_run_identifier(&nonce, &2u32, &zero_hash(&env))
    );
}

#[test]
fn executed_run_exposes_reproducible_identifier() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    let source = common::authorized_source(&env, &client);
    let nonce = common::nonce(&env, 21);
    let draft_hash = zero_hash(&env);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    // The caller can compute the identifier before the transaction lands.
    let expected = client.compute_payroll_run_identifier(&nonce, &1u32, &draft_hash);

    let run_id = client.batch_process_payroll(
        &proofs, &amounts, &employees, &100i128, &nonce, &None, &source,
    );

    let stored = client.get_payroll_run_identifier(&run_id);
    assert_eq!(stored, expected);
    assert_eq!(stored, off_chain_identifier(&env, &nonce, 1, &draft_hash));
}

#[test]
fn pending_identifier_is_stable_after_finalization() {
    let env = Env::default();
    let (client, _token, employee) = common::setup(&env);
    let nonce = common::nonce(&env, 31);
    let (proofs, amounts, employees) = common::one_payment(&env, &employee);

    let run_id = client.prepare_payroll_run(&proofs, &amounts, &employees, &100i128, &nonce, &None);

    let while_pending = client.get_payroll_run_identifier(&run_id);
    assert_eq!(
        while_pending,
        off_chain_identifier(&env, &nonce, 1, &zero_hash(&env))
    );

    let admin = client.get_addresses().admin;
    client.finalize_payroll_run(&admin, &run_id);

    assert_eq!(client.get_payroll_run_identifier(&run_id), while_pending);
}

#[test]
fn unknown_and_reserved_ids_fail_without_leaking_values() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);

    let reserved = client
        .try_get_run_identifier_checked(&u64::MAX)
        .unwrap_err();
    assert_eq!(reserved, Ok(PayrollRunIdentifierError::InvalidRunId));

    let missing = client
        .try_get_run_identifier_checked(&12345u64)
        .unwrap_err();
    assert_eq!(missing, Ok(PayrollRunIdentifierError::RunNotFound));
}

#[test]
#[should_panic(expected = "Payroll run identifier not available")]
fn get_identifier_panics_for_unknown_run() {
    let env = Env::default();
    let (client, _token, _employee) = common::setup(&env);
    client.get_payroll_run_identifier(&12345u64);
}
