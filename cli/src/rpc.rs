//! Soroban JSON-RPC client for querying `PayrollProcessed` contract events.
//!
//! Calls the `getEvents` RPC method and returns strongly-typed
//! [`PayrollEvent`] values for every confirmed payment belonging to a given
//! company.
//!
//! # XDR layout produced by `payment_executor`
//!
//! ```text
//! topics[0]  ScVal::Symbol("PayrollProcessed")
//! topics[1]  ScVal::Symbol(<company_id>)
//! data       ScVal::Vec([
//!                ScVal::Address(<employee>),   // Stellar account address
//!                ScVal::I128(Int128Parts),      // amount in stroops
//!                ScVal::U32(<period>),
//!            ])
//! ```

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use stellar_xdr::curr::{
    AccountId, Int128Parts, Limits, PublicKey, ReadXdr, ScAddress, ScVal, ScVec,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A decoded `PayrollProcessed` event emitted by `payment_executor`.
#[derive(Debug, Clone)]
pub struct PayrollEvent {
    /// Stellar G-address of the paid employee.
    pub employee: String,
    /// Payment amount in stroops.
    pub amount: i128,
    /// Payroll period number (e.g. month counter).
    pub period: u32,
    /// ISO-8601 timestamp from the ledger that closed the event.
    pub ledger_closed_at: String,
}

// ── JSON-RPC response types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<GetEventsResult>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GetEventsResult {
    events: Vec<RawEvent>,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    #[serde(rename = "ledgerClosedAt")]
    ledger_closed_at: String,
    topic: Vec<String>,
    value: String,
    #[serde(rename = "inSuccessfulContractCall")]
    in_successful_contract_call: bool,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch all `PayrollProcessed` events for `company_id` from `contract_id`.
///
/// # Arguments
/// * `rpc_url`      — Soroban RPC endpoint (e.g. `https://soroban-testnet.stellar.org`).
/// * `contract_id`  — Strkey contract address (C… address).
/// * `company_id`   — Company symbol used as the second event topic.
/// * `start_ledger` — First ledger sequence to include in the scan.
pub fn fetch_payroll_events(
    rpc_url: &str,
    contract_id: &str,
    company_id: &str,
    start_ledger: u32,
) -> Result<Vec<PayrollEvent>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getEvents",
        "params": {
            "startLedger": start_ledger,
            "filters": [{
                "type": "contract",
                "contractIds": [contract_id]
            }],
            "pagination": { "limit": 200 }
        }
    });

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client")?;

    let resp: RpcResponse = client
        .post(rpc_url)
        .json(&body)
        .send()
        .context("Failed to reach Soroban RPC — check your --rpc-url")?
        .json()
        .context("Failed to parse Soroban RPC response")?;

    if let Some(err) = resp.error {
        bail!("Soroban RPC error: {}", err);
    }

    let raw_events = resp.result.map(|r| r.events).unwrap_or_default();

    let mut out = Vec::new();
    for ev in raw_events {
        if !ev.in_successful_contract_call {
            continue;
        }
        // Filter to PayrollProcessed events for the requested company.
        if let Some(event) = try_decode_payroll_event(&ev, company_id)? {
            out.push(event);
        }
    }
    Ok(out)
}

// ── XDR decoding helpers ──────────────────────────────────────────────────────

/// Try to decode a raw RPC event as a `PayrollProcessed` event for `company_id`.
///
/// Returns `Ok(None)` when the event is a different type or a different company.
fn try_decode_payroll_event(ev: &RawEvent, company_id: &str) -> Result<Option<PayrollEvent>> {
    if ev.topic.len() < 2 {
        return Ok(None);
    }

    // Topic 0 must be Symbol("PayrollProcessed").
    let topic0 = decode_scval(&ev.topic[0]).context("Failed to decode event topic[0]")?;
    let event_name = match &topic0 {
        ScVal::Symbol(s) => std::str::from_utf8(s.as_slice())
            .context("Event name is not valid UTF-8")?
            .to_owned(),
        _ => return Ok(None),
    };
    if event_name != "PayrollProcessed" {
        return Ok(None);
    }

    // Topic 1 must be Symbol(<company_id>) matching the requested company.
    let topic1 = decode_scval(&ev.topic[1]).context("Failed to decode event topic[1]")?;
    let event_company = match &topic1 {
        ScVal::Symbol(s) => std::str::from_utf8(s.as_slice())
            .context("Company ID is not valid UTF-8")?
            .to_owned(),
        _ => return Ok(None),
    };
    if event_company != company_id {
        return Ok(None);
    }

    // Data is Vec([Address(employee), I128(amount), U32(period)]).
    let data = decode_scval(&ev.value).context("Failed to decode event data")?;
    let vec = match data {
        ScVal::Vec(Some(v)) => v,
        _ => bail!("Expected ScVal::Vec for PayrollProcessed data"),
    };

    let employee = extract_address(&vec, 0)?;
    let amount = extract_i128(&vec, 1)?;
    let period = extract_u32(&vec, 2)?;

    Ok(Some(PayrollEvent {
        employee,
        amount,
        period,
        ledger_closed_at: ev.ledger_closed_at.clone(),
    }))
}

fn decode_scval(b64: &str) -> Result<ScVal> {
    let bytes = B64
        .decode(b64)
        .context("Failed to base64-decode XDR ScVal")?;
    ScVal::from_xdr(&bytes, Limits::none()).context("Failed to XDR-decode ScVal")
}

fn extract_address(vec: &ScVec, idx: usize) -> Result<String> {
    match vec.get(idx) {
        Some(ScVal::Address(addr)) => scaddress_to_strkey(addr),
        Some(other) => bail!("Expected ScVal::Address at index {idx}, got {:?}", other),
        None => bail!("Missing element at index {idx} in event data Vec"),
    }
}

fn extract_i128(vec: &ScVec, idx: usize) -> Result<i128> {
    match vec.get(idx) {
        Some(ScVal::I128(Int128Parts { hi, lo })) => Ok(((*hi as i128) << 64) | (*lo as i128)),
        Some(other) => bail!("Expected ScVal::I128 at index {idx}, got {:?}", other),
        None => bail!("Missing element at index {idx} in event data Vec"),
    }
}

fn extract_u32(vec: &ScVec, idx: usize) -> Result<u32> {
    match vec.get(idx) {
        Some(ScVal::U32(v)) => Ok(*v),
        Some(other) => bail!("Expected ScVal::U32 at index {idx}, got {:?}", other),
        None => bail!("Missing element at index {idx} in event data Vec"),
    }
}

/// Convert a Soroban `ScAddress` to a Stellar G-address StrKey string.
fn scaddress_to_strkey(addr: &ScAddress) -> Result<String> {
    match addr {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(bytes))) => {
            let pk = stellar_strkey::ed25519::PublicKey(bytes.0);
            Ok(stellar_strkey::Strkey::PublicKeyEd25519(pk).to_string())
        }
        ScAddress::Contract(hash) => {
            // Contract addresses are not expected here; return hex as fallback.
            Ok(format!("C:{}", hex::encode(hash.0)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_symbol_scval_roundtrip() {
        use stellar_xdr::curr::WriteXdr;
        let sym = ScVal::Symbol("PayrollProcessed".try_into().unwrap());
        let xdr = sym.to_xdr(Limits::none()).unwrap();
        let b64 = B64.encode(&xdr);
        let decoded = decode_scval(&b64).unwrap();
        match decoded {
            ScVal::Symbol(s) => {
                assert_eq!(
                    std::str::from_utf8(s.as_slice()).unwrap(),
                    "PayrollProcessed"
                )
            }
            other => panic!("expected Symbol, got {:?}", other),
        }
    }
}
