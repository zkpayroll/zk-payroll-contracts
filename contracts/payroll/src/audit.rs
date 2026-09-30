use soroban_sdk::{contracttype, BytesN, Env, Symbol};

/// Privacy-safe confidential audit trail marker.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialAuditMarker {
    pub action_type: Symbol,
    pub run_or_draft_id: u64,
    pub entity_hash: BytesN<32>,
    pub timestamp: u64,
}

/// Records a privacy-safe audit marker emitting an event with non-sensitive metadata only.
pub fn record_audit_marker(
    env: &Env,
    action_type: Symbol,
    run_or_draft_id: u64,
    entity_hash: BytesN<32>,
) -> ConfidentialAuditMarker {
    let timestamp = env.ledger().timestamp();
    payroll_events::emit_audit_marker(
        env,
        action_type.clone(),
        run_or_draft_id,
        entity_hash.clone(),
    );
    ConfidentialAuditMarker {
        action_type,
        run_or_draft_id,
        entity_hash,
        timestamp,
    }
}
