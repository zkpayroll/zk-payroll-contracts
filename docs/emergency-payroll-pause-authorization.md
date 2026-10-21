# Contract Emergency Payroll Pause Authorization (#698)

This document specifies the emergency payroll pause authorization framework implemented in the `payroll` contract.

## Overview

The `emergency_pause_authorization` module provides decentralized, multi-tiered emergency pause authorization mechanisms. It allows designated emergency guardians and contract administrators to halt payroll disbursements immediately when anomalous activity or security threats are detected.

## Roles & Authority

- **Emergency Guardian**: Designated security addresses authorized to invoke `execute_emergency_pause` directly through a fast-path trigger without waiting for full multi-sig unpause procedures.
- **Contract Administrator**: Authorized to configure pause policies, enact emergency pauses, and execute `execute_emergency_unpause` to restore normal payroll operations.
- **Unauthorized**: Any caller not explicitly enumerated in the `EmergencyPauseConfig` is rejected with `EmergencyPauseError::UnauthorizedCaller`.

## Pause Scopes

1. **Global (`EmergencyPauseScope::Global`)**: Suspends all payroll runs, batch processing, and contract disbursements.
2. **Run-Specific (`EmergencyPauseScope::RunOnly`)**: Halts execution only for a targeted `run_id`, allowing unrelated payroll periods to proceed uninterrupted.
3. **Batch-Specific (`EmergencyPauseScope::BatchOnly`)**: Halts execution specifically for a disputed or compromised batch within a multi-batch pipeline.

## Safety & Expiration Guardrails

- **Auto-Expiry (`max_pause_duration_secs`)**: Pauses can be configured with an upper time bound. If the administrative team does not renew or resolve the issue before expiry, operations can automatically unblock to prevent indefinite fund lockups.
- **Audit Logging**: Each pause records `paused_by`, `paused_at`, `scope`, `target_id`, and a standardized `reason_code` for transparency.
- **Pre-flight Assertion**: The contract exposes `assert_payroll_not_paused` and `is_payroll_operation_paused` for SDK and frontend client integration.
