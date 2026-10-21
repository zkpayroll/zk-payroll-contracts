# Contract Audit Event Sequence Verification (#701)

This document specifies the audit event sequence verification mechanism in the `audit_module` contract.

## Overview

The `AuditModule::verify_audit_event_sequence` function validates that audit-related lifecycle events emitted by the smart contract adhere to strict ordering guarantees. This ensures tamper-evident audit trails, prevents out-of-order execution, and guarantees integrity for off-chain compliance monitors and indexers.

## Audit Lifecycle Stages

Auditors transition through canonical lifecycle stages:
1. **None**: Auditor has never been granted access.
2. **Granted**: Key generated (`ViewKeyGenerated`).
3. **Active**: Auditor performs verifications (`AuditSuccessful`, `MetadataVerified`, `AggregateAuditGenerated`, `AuditSummaryExported`) or key refreshes (`ViewKeyRefreshed`).
4. **Revoked**: Key access revoked (`AuditAccessRevoked`) or expired (`AuditAccessExpired`).
5. **Pruned**: Key permanently scrubbed from state after retention window (`AuditGrantPruned`).

## Event Sequence Rules

1. **Initialization Requirement**: Any valid audit sequence MUST begin with `ViewKeyGenerated`.
2. **Active Operations**: Audit verification operations cannot occur prior to key generation or after revocation/pruning.
3. **Revocation & Expiry**: `AuditAccessRevoked` or `AuditAccessExpired` mark termination of access.
4. **Pruning Prerequisites**: `AuditGrantPruned` requires prior termination and permanently closes the lifecycle sequence.
5. **Violation Handling**: Sequences violating ordering return `Err(AuditError::InvalidEventSequence)`.
