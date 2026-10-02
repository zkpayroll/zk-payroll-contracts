#![no_std]

extern crate alloc;

use pause_manager::PauseManagerClient;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, BytesN, Env, String, Symbol, Vec,
};

const STELLAR_ACCOUNT_STRKEY_LEN: u32 = 56;
const STELLAR_ACCOUNT_STRKEY_LEN_USIZE: usize = 56;
const STELLAR_ACCOUNT_VERSION_BYTE: u8 = 6 << 3;

/// Tolerance (seconds) applied when comparing a caller-supplied compensation
/// policy effective date against the current ledger clock.
///
/// An effective date is chosen off-chain and submitted by the HR admin, so it
/// can legitimately trail the network clock by the usual consensus skew. Dates
/// further behind than this are treated as genuinely in the past.
pub const COMPENSATION_POLICY_PAST_SKEW_SECONDS: u64 = 300;

/// Upper bound (seconds) on how far in the future a compensation policy may be
/// scheduled. A year is comfortably longer than any payroll planning horizon
/// while still turning a mistyped timestamp (a millisecond value, a
/// seconds/milliseconds mix-up) into a clear rejection instead of a policy
/// nobody can pay against.
pub const MAX_COMPENSATION_POLICY_HORIZON_SECONDS: u64 = 60 * 60 * 24 * 365;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Persistent company record. Keyed by auto-incremented u64 company ID.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CompanyInfo {
    pub admin: Address,
    pub treasury: Address,
}

// ?? Issue #90: employee eligibility ??????????????????????????????????????????

/// Registration state for an employee.
///
/// Eligibility checks use this to decide whether an employee can be included
/// in a payroll execution:
///   - `Active`     ? eligible; commitment is registered and record is complete.
///   - `Inactive`   ? temporarily ineligible (e.g. on leave, terminated).
///   - `Incomplete` ? missing required registration data; never eligible until
///                    the record is corrected and marked `Active`.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EmployeeStatus {
    Active = 0,
    Inactive = 1,
    Incomplete = 2,
}

// -- Issue #615: employee eligibility status evaluation ----------------------

/// Why an employee is, or is not, eligible for payroll execution.
///
/// `is_eligible` reports only *whether* an employee can be paid, so an
/// integrator seeing a refused payout cannot tell "never onboarded" from
/// "deactivated", and neither case names a remediation. Each variant here
/// maps to exactly one thing the caller can do next.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EligibilityReason {
    /// Registered and `Active` — may be included in a payroll run.
    Eligible = 0,
    /// No employee record exists for this address under this company.
    Unregistered = 1,
    /// Registered, but required registration data is still missing.
    Incomplete = 2,
    /// Deactivated, e.g. the employee is on leave or has left.
    Inactive = 3,
}

impl EligibilityReason {
    /// Human-readable explanation, for panic messages and client output.
    pub fn as_str(&self) -> &'static str {
        match self {
            EligibilityReason::Eligible => "eligible",
            EligibilityReason::Unregistered => {
                "employee is not registered with this company; onboard the employee first"
            }
            EligibilityReason::Incomplete => {
                "employee record is incomplete; complete registration and set status to Active"
            }
            EligibilityReason::Inactive => {
                "employee is inactive; set status to Active to restore eligibility"
            }
        }
    }
}

/// Structured verdict describing one employee's payroll eligibility (#615).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EligibilityAssessment {
    /// Stored status, defaulting to `Incomplete` when never set.
    pub status: EmployeeStatus,
    /// The single reason that determines eligibility.
    pub reason: EligibilityReason,
    /// Convenience flag; always agrees with `reason == Eligible`.
    pub eligible: bool,
}

// -- Compensation policy effective-date validation --------------------------

/// A company compensation policy, effective from a single ledger timestamp.
///
/// The policy carries only a *hashed* schedule commitment, never a salary
/// amount or pay-rate value: on-chain state and events must never leak
/// compensation, so the amounts stay off-chain behind the commitment exactly
/// as employee salary commitments do.
///
/// A policy applies from `effective_at` (inclusive) until the effective date of
/// the next scheduled policy. Effective dates in a company's schedule are
/// strictly increasing, so the policy in force at any timestamp is unique.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompensationPolicy {
    pub company_id: u64,
    /// Poseidon hash of the compensation schedule. Never a plaintext amount.
    pub policy_commitment: BytesN<32>,
    /// Ledger timestamp from which this policy applies (inclusive).
    pub effective_at: u64,
    /// Ledger timestamp at which the policy was scheduled.
    pub created_at: u64,
    /// Company admin that scheduled the policy.
    pub created_by: Address,
}

/// Why a proposed compensation policy effective date cannot be accepted.
///
/// Each variant names the one thing the caller must change, so a rejected
/// schedule can be corrected without reading contract source.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CompensationPolicyEffectiveDateIssue {
    /// The effective date is acceptable.
    None = 0,
    /// The date is more than `COMPENSATION_POLICY_PAST_SKEW_SECONDS` behind the
    /// ledger clock.
    InThePast = 1,
    /// The date is beyond `MAX_COMPENSATION_POLICY_HORIZON_SECONDS` ahead.
    BeyondSchedulingHorizon = 2,
    /// The date is not strictly after the latest policy already scheduled.
    NotAfterScheduledPolicy = 3,
}

impl CompensationPolicyEffectiveDateIssue {
    /// Human-readable explanation, for panic messages and client output.
    pub fn as_str(&self) -> &'static str {
        match self {
            CompensationPolicyEffectiveDateIssue::None => "effective date is acceptable",
            CompensationPolicyEffectiveDateIssue::InThePast => {
                "effective date is in the past; schedule it at or after the current ledger timestamp"
            }
            CompensationPolicyEffectiveDateIssue::BeyondSchedulingHorizon => {
                "effective date is too far in the future; schedule within the one-year scheduling horizon"
            }
            CompensationPolicyEffectiveDateIssue::NotAfterScheduledPolicy => {
                "effective date is not after the latest scheduled policy; use a strictly later timestamp"
            }
        }
    }
}

/// Structured verdict for a proposed compensation policy effective date.
///
/// `valid` always agrees with `issue == None`. The remaining fields let a
/// client render the failure without re-deriving ledger state: the ledger
/// clock the verdict was taken at, and the effective date a new policy must
/// beat to extend a company's schedule.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompensationPolicyEffectiveDateCheck {
    /// The proposed effective date under evaluation.
    pub effective_at: u64,
    /// Ledger timestamp the verdict was taken at.
    pub ledger_now: u64,
    /// Effective date of the newest policy already scheduled, if any.
    pub latest_scheduled_effective_at: Option<u64>,
    /// The single issue deciding the verdict.
    pub issue: CompensationPolicyEffectiveDateIssue,
    /// Convenience flag; always agrees with `issue == None`.
    pub valid: bool,
}

// ?? Issue #91: privileged-role rotation ??????????????????????????????????????

/// Pending two-step company admin or treasury rotation.
///
/// The current holder proposes a successor, and the successor must explicitly
/// accept. Proposals can be cancelled by the current holder before acceptance.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingCompanyRotation {
    pub new_holder: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

// ?? Issue #353: Approver Threshold Rotation Controls ???????????????????????????

/// Approval threshold configuration for payroll authorization (#353).
///
/// Thresholds determine how many approvals are required before a payroll run
/// can be executed. Rotating thresholds allows changes without invalidating
/// already locked payroll decisions.
#[contracttype]
#[derive(Clone, Debug)]
pub struct ApprovalThreshold {
    pub company_id: u64,
    pub required_approvals: u32,
    pub configured_at: u64,
    pub configured_by: Address,
    pub is_active: bool,
}

/// Pending threshold rotation awaiting activation (#353).
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingThresholdRotation {
    pub company_id: u64,
    pub new_threshold: u32,
    pub proposed_at: u64,
    pub proposed_by: Address,
    pub effective_after: u64,
}

/// Storage key space for the payroll registry.
///
/// - `Company(u64)`               ? `CompanyInfo`              (Persistent)
/// - `Employee(u64, Address)`     ? `BytesN<32>`               (Persistent, commitment)
/// - `EmpStatus(u64, Address)`    ? `EmployeeStatus`           (Persistent, eligibility)
/// - `CompanySequence`            ? `u64`                      (Persistent, counter)
/// - `PendingAdminRotation(u64)`  ? `PendingCompanyRotation`   (Persistent, issue #91)
/// - `PendingTreasuryRotation(u64)` ? `PendingCompanyRotation` (Persistent, issue #91)
/// - `ApprovalThreshold(u64)`     ? `ApprovalThreshold`        (Persistent, issue #353)
/// - `PendingThresholdRotation(u64)` ? `PendingThresholdRotation` (Persistent, issue #353)
/// - `CompensationPolicy(u64, u64)` ? `CompensationPolicy`     (Persistent, keyed by effective date)
/// - `CompensationPolicySchedule(u64)` ? `Vec<u64>`            (Persistent, ascending effective dates)
#[contracttype]
pub enum DataKey {
    Company(u64),
    Employee(u64, Address),
    CompanySequence,
    /// Per-employee eligibility status (issue #90).
    EmpStatus(u64, Address),
    /// Pending admin rotation for a company (issue #91).
    PendingAdminRotation(u64),
    /// Pending treasury rotation for a company (issue #91).
    PendingTreasuryRotation(u64),
    /// Per-admin company ID lookup (issue #152: reject duplicate company registration).
    CompanyAdmin(Address),
    /// Pause manager address (issue #167).
    PauseManager,
    /// Active approval threshold for a company (issue #353).
    ApprovalThreshold(u64),
    /// Pending approval threshold rotation (issue #353).
    PendingThresholdRotation(u64),
    /// A scheduled compensation policy, keyed by `(company_id, effective_at)`.
    CompensationPolicy(u64, u64),
    /// Ascending list of a company's scheduled compensation policy effective
    /// dates. Strictly increasing by construction, so it doubles as the
    /// "latest scheduled date" used by effective-date validation and as the
    /// ordering used to resolve the policy in force at a timestamp.
    CompensationPolicySchedule(u64),
}

// ---------------------------------------------------------------------------
// Trait ? canonical interface specification for #12
// ---------------------------------------------------------------------------

pub trait PayrollRegistryTrait {
    /// Register a new company. Returns the newly assigned company ID.
    /// Requires authorisation from the provided admin address.
    fn register_company(env: Env, admin: Address, treasury: Address) -> u64;

    /// Add an employee commitment under a company.
    /// Requires authorisation from the company admin.
    /// The employee's initial status is set to `Active`.
    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>);

    /// Validate a canonical Stellar account wallet string for employee onboarding.
    fn validate_employee_wallet_format(env: Env, employee_wallet: String) -> bool;

    /// Add an employee commitment from a Stellar account wallet string.
    /// Requires authorisation from the company admin.
    fn add_employee_by_wallet(
        env: Env,
        company_id: u64,
        employee_wallet: String,
        commitment: BytesN<32>,
    );

    /// Permanently remove an employee record from storage.
    /// Requires authorisation from the company admin.
    fn remove_employee(env: Env, company_id: u64, employee: Address);

    /// Replace an employee's active Poseidon commitment.
    /// Requires authorisation from the company admin.
    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>);

    /// Read company metadata by company ID.
    fn get_company(env: Env, company_id: u64) -> CompanyInfo;

    /// Read an employee's active commitment under a company.
    fn get_commitment(env: Env, company_id: u64, employee: Address) -> BytesN<32>;

    // ?? Issue #90: employee eligibility ??????????????????????????????????????

    /// Set the eligibility status for a registered employee.
    /// Requires authorisation from the company admin.
    fn set_employee_status(env: Env, company_id: u64, employee: Address, status: EmployeeStatus);

    /// Return the eligibility status of an employee.
    /// Returns `Incomplete` if no explicit status has been set.
    fn get_employee_status(env: Env, company_id: u64, employee: Address) -> EmployeeStatus;

    /// Return `true` iff the employee is registered AND has `Active` status.
    fn is_eligible(env: Env, company_id: u64, employee: Address) -> bool;

    /// Read-only helper for clients that only need active/inactive state.
    fn is_employee_active(env: Env, company_id: u64, employee: Address) -> bool;

    /// Evaluate payroll eligibility and report *why*, not just whether (#615).
    ///
    /// Purely read-only: no authorisation and no state change. `eligible`
    /// agrees with `reason == Eligible`, so this is a strict superset of
    /// `is_eligible`.
    fn evaluate_eligibility(env: Env, company_id: u64, employee: Address) -> EligibilityAssessment;

    /// Assert eligibility, returning the status on success.
    ///
    /// Panics with an actionable message naming the remediation when the
    /// employee cannot be paid, so a failed call tells the caller what to fix
    /// rather than just that something is wrong.
    fn require_eligible(env: Env, company_id: u64, employee: Address) -> EmployeeStatus;

    // ?? Issue #91: company-level admin/treasury rotation ?????????????????????

    /// Propose a new company admin (step 1 of 2).
    fn propose_admin_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_admin: Address,
    );

    /// Accept a pending admin rotation (step 2 of 2).
    fn accept_admin_rotation(env: Env, company_id: u64, new_admin: Address);

    /// Cancel a pending admin rotation.
    fn cancel_admin_rotation(env: Env, company_id: u64, current_admin: Address);

    /// Propose a new company treasury address (step 1 of 2).
    fn propose_treasury_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_treasury: Address,
    );

    /// Accept a pending treasury rotation (step 2 of 2).
    fn accept_treasury_rotation(env: Env, company_id: u64, new_treasury: Address);

    /// Cancel a pending treasury rotation.
    fn cancel_treasury_rotation(env: Env, company_id: u64, current_admin: Address);

    /// Return the current company sequence counter (defaults to 0).
    fn get_company_sequence(env: Env) -> u64;

    /// Return any pending admin rotation proposal for a company.
    fn get_pending_admin_rotation(env: Env, company_id: u64) -> Option<PendingCompanyRotation>;

    /// Return any pending treasury rotation proposal for a company.
    fn get_pending_treasury_rotation(env: Env, company_id: u64) -> Option<PendingCompanyRotation>;

    // ?? Issue #353: Approver Threshold Rotation Controls ???????????????????????????

    /// Propose a new approval threshold for a company (step 1 of 2).
    /// The new threshold becomes effective after a grace period.
    fn propose_threshold_rotation(
        env: Env,
        company_id: u64,
        admin: Address,
        new_threshold: u32,
        grace_period_seconds: u64,
    );

    /// Activate a pending threshold rotation after the grace period expires (#353).
    fn activate_threshold_rotation(env: Env, company_id: u64, admin: Address);

    /// Cancel a pending threshold rotation before it takes effect.
    fn cancel_threshold_rotation(env: Env, company_id: u64, admin: Address);

    /// Get the current approval threshold for a company (#353).
    fn get_approval_threshold(env: Env, company_id: u64) -> Option<ApprovalThreshold>;

    /// Get any pending approval threshold rotation for a company (#353).
    fn get_pending_threshold_rotation(env: Env, company_id: u64) -> Option<PendingThresholdRotation>;

    /// Set the initial approval threshold when a company is registered (#353).
    fn set_initial_approval_threshold(env: Env, company_id: u64, admin: Address, required_approvals: u32);

    // -- Compensation policy effective-date validation ------------------------

    /// Schedule a compensation policy for a company, effective from
    /// `effective_at`.
    ///
    /// Requires authorisation from the company admin. The effective date is
    /// validated before anything is written: it may not sit behind the ledger
    /// clock (beyond the documented skew tolerance), may not exceed the
    /// scheduling horizon, and must be strictly after the latest policy
    /// already scheduled for the company.
    fn schedule_compensation_policy(
        env: Env,
        company_id: u64,
        admin: Address,
        policy_commitment: BytesN<32>,
        effective_at: u64,
    ) -> CompensationPolicy;

    /// Evaluate a proposed compensation policy effective date and report *why*
    /// it is or is not acceptable.
    ///
    /// Purely read-only: no authorisation and no state change. `valid` agrees
    /// with `issue == None`, and `schedule_compensation_policy` enforces
    /// exactly the same rules, so this is the preflight companion to it.
    ///
    /// Named without the `compensation_` prefix only because the Soroban
    /// contract-spec limit is 32 characters per function name; "policy" means
    /// the compensation policy everywhere in this contract.
    fn check_policy_effective_date(
        env: Env,
        company_id: u64,
        effective_at: u64,
    ) -> CompensationPolicyEffectiveDateCheck;

    /// Assert that `effective_at` is an acceptable effective date for a new
    /// compensation policy, panicking with the issue and its remediation
    /// otherwise.
    ///
    /// Read-only, so other contracts can call it as a guard before accepting a
    /// payroll input that claims to fall under a compensation policy. Shorter
    /// than `require_valid_compensation_policy_effective_date` for the same
    /// 32-character reason as `check_policy_effective_date`.
    fn require_valid_effective_date(env: Env, company_id: u64, effective_at: u64);

    /// Return the compensation policy scheduled for exactly `effective_at`.
    fn get_compensation_policy(
        env: Env,
        company_id: u64,
        effective_at: u64,
    ) -> Option<CompensationPolicy>;

    /// Return a company's compensation policies in ascending effective-date
    /// order (earliest first).
    fn get_compensation_policy_schedule(env: Env, company_id: u64) -> Vec<CompensationPolicy>;

    /// Return the policy in force at `at_timestamp`, i.e. the scheduled policy
    /// with the greatest effective date `<= at_timestamp`.
    ///
    /// Returns `None` when `at_timestamp` precedes the company's first policy,
    /// meaning no policy covers that point in time.
    fn get_compensation_policy_at(
        env: Env,
        company_id: u64,
        at_timestamp: u64,
    ) -> Option<CompensationPolicy>;

    /// Return `true` iff a compensation policy is in force at `at_timestamp`.
    fn is_compensation_policy_effective(env: Env, company_id: u64, at_timestamp: u64) -> bool;
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct PayrollRegistry;

#[contractimpl]
impl PayrollRegistry {
    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Payroll is paused");
            }
        }
    }

    /// Validates an employer display-name/reference-id style metadata value
    /// (issue #378): non-empty and within a reasonable length bound.
    /// `CompanyInfo` does not yet store employer metadata fields, so this is
    /// a standalone helper ready to be wired into a future
    /// `set_company_metadata`-style entrypoint rather than a change to the
    /// existing company record.
    fn validate_employer_metadata_value(env: &Env, value: &String, field_name: &str) {
        const MAX_METADATA_LEN: u32 = 256;
        if value.len() == 0 {
            panic!("{} must not be empty", field_name);
        }
        if value.len() > MAX_METADATA_LEN {
            panic!("{} exceeds maximum length", field_name);
        }
        let _ = env; // reserved for a future emitted validation event
    }

    pub fn set_pause_manager(env: Env, admin: Address, pause_manager: Address) {
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
        payroll_events::emit_registry_pause_manager_set(&env, pause_manager);
    }

    // -- Compensation policy effective-date validation ------------------------

    /// A company's scheduled compensation policy effective dates, ascending.
    fn load_compensation_policy_schedule(env: &Env, company_id: u64) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::CompensationPolicySchedule(company_id))
            .unwrap_or_else(|| Vec::new(env))
    }

    /// The effective date a new policy must beat to extend the schedule, if
    /// the company already has one.
    fn latest_scheduled_effective_at(env: &Env, company_id: u64) -> Option<u64> {
        Self::load_compensation_policy_schedule(env, company_id).last()
    }

    /// Single source of truth for effective-date validation. Read-only: it
    /// touches no state and takes no authorisation, so both the read-only
    /// entrypoints and `schedule_compensation_policy` agree by construction.
    fn evaluate_compensation_effective_date(
        env: &Env,
        company_id: u64,
        effective_at: u64,
    ) -> CompensationPolicyEffectiveDateCheck {
        let now = env.ledger().timestamp();
        let latest_scheduled_effective_at = Self::latest_scheduled_effective_at(env, company_id);

        let issue = if effective_at.saturating_add(COMPENSATION_POLICY_PAST_SKEW_SECONDS) < now {
            // A date in the past would silently rewrite the policy that was
            // already in force when earlier payroll was run.
            CompensationPolicyEffectiveDateIssue::InThePast
        } else if effective_at > now.saturating_add(MAX_COMPENSATION_POLICY_HORIZON_SECONDS) {
            CompensationPolicyEffectiveDateIssue::BeyondSchedulingHorizon
        } else if matches!(
            latest_scheduled_effective_at,
            Some(latest) if effective_at <= latest
        ) {
            // Strictly increasing effective dates are what make the policy in
            // force at a timestamp unique, so ties and rewinds are refused.
            CompensationPolicyEffectiveDateIssue::NotAfterScheduledPolicy
        } else {
            CompensationPolicyEffectiveDateIssue::None
        };

        CompensationPolicyEffectiveDateCheck {
            effective_at,
            ledger_now: now,
            latest_scheduled_effective_at,
            valid: issue == CompensationPolicyEffectiveDateIssue::None,
            issue,
        }
    }

    fn assert_compensation_effective_date_is_valid(
        env: &Env,
        company_id: u64,
        effective_at: u64,
    ) -> CompensationPolicyEffectiveDateCheck {
        let check = Self::evaluate_compensation_effective_date(env, company_id, effective_at);
        match check.issue {
            CompensationPolicyEffectiveDateIssue::None => check,
            // The ordering failure is the one case where the caller needs a
            // number to fix the call, so it carries the bar to beat.
            CompensationPolicyEffectiveDateIssue::NotAfterScheduledPolicy => panic!(
                "Compensation policy effective date is invalid for company {}: {} (requested {}, latest scheduled {})",
                company_id,
                check.issue.as_str(),
                effective_at,
                check.latest_scheduled_effective_at.unwrap_or_default()
            ),
            issue => panic!(
                "Compensation policy effective date is invalid for company {}: {} (requested {}, ledger now {})",
                company_id,
                issue.as_str(),
                effective_at,
                check.ledger_now
            ),
        }
    }

    /// The policy in force at `at_timestamp`: the scheduled policy with the
    /// greatest effective date `<= at_timestamp`.
    fn resolve_effective_compensation_policy(
        env: &Env,
        company_id: u64,
        at_timestamp: u64,
    ) -> Option<CompensationPolicy> {
        let schedule = Self::load_compensation_policy_schedule(env, company_id);
        // Effective dates are strictly increasing, so the newest acceptable
        // date is the last entry that is not in the future.
        for i in (0..schedule.len()).rev() {
            let effective_at = schedule.get(i).unwrap();
            if effective_at <= at_timestamp {
                return env
                    .storage()
                    .persistent()
                    .get(&DataKey::CompensationPolicy(company_id, effective_at));
            }
        }
        None
    }

    fn add_employee_record(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        let emp = employee.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Employee(company_id, emp.clone()), &commitment);

        // Default status for newly registered employees is Active (issue #90).
        env.storage().persistent().set(
            &DataKey::EmpStatus(company_id, emp),
            &EmployeeStatus::Active,
        );

        payroll_events::emit_employee_added(&env, company_id, employee, commitment);
    }

    fn require_valid_employee_wallet_format(employee_wallet: &String) {
        if !Self::employee_wallet_format_is_valid(employee_wallet) {
            panic!("Invalid employee wallet address format");
        }
    }

    fn employee_wallet_format_is_valid(employee_wallet: &String) -> bool {
        if employee_wallet.len() != STELLAR_ACCOUNT_STRKEY_LEN {
            return false;
        }

        let mut encoded = [0u8; STELLAR_ACCOUNT_STRKEY_LEN_USIZE];
        employee_wallet.copy_into_slice(&mut encoded);

        let mut decoded = [0u8; 35];
        if !Self::decode_stellar_base32(&encoded, &mut decoded) {
            return false;
        }

        if decoded[0] != STELLAR_ACCOUNT_VERSION_BYTE {
            return false;
        }

        let expected_checksum = u16::from_le_bytes([decoded[33], decoded[34]]);
        let actual_checksum = Self::crc16_xmodem(&decoded[..33]);
        expected_checksum == actual_checksum
    }

    fn decode_stellar_base32(
        encoded: &[u8; STELLAR_ACCOUNT_STRKEY_LEN_USIZE],
        decoded: &mut [u8; 35],
    ) -> bool {
        let mut buffer: u16 = 0;
        let mut bits_left: u8 = 0;
        let mut out_index: usize = 0;

        for ch in encoded {
            let Some(value) = Self::decode_base32_char(*ch) else {
                return false;
            };
            buffer = (buffer << 5) | u16::from(value);
            bits_left += 5;

            if bits_left >= 8 {
                bits_left -= 8;
                if out_index >= decoded.len() {
                    return false;
                }
                decoded[out_index] = (buffer >> bits_left) as u8;
                out_index += 1;

                if bits_left > 0 {
                    buffer &= (1u16 << bits_left) - 1;
                } else {
                    buffer = 0;
                }
            }
        }

        out_index == decoded.len() && bits_left == 0
    }

    fn decode_base32_char(ch: u8) -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'2'..=b'7' => Some(ch - b'2' + 26),
            _ => None,
        }
    }

    fn crc16_xmodem(bytes: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for byte in bytes {
            crc ^= u16::from(*byte) << 8;
            for _ in 0..8 {
                if (crc & 0x8000) != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}

#[contractimpl]
impl PayrollRegistryTrait for PayrollRegistry {
    fn register_company(env: Env, admin: Address, treasury: Address) -> u64 {
        Self::require_not_paused(&env);
        admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::CompanyAdmin(admin.clone()))
        {
            panic!("Company already registered");
        }

        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::CompanySequence)
            .unwrap_or(0u64);

        let next = id + 1;
        env.storage()
            .persistent()
            .set(&DataKey::CompanySequence, &next);

        let info = CompanyInfo {
            admin: admin.clone(),
            treasury: treasury.clone(),
        };
        env.storage().persistent().set(&DataKey::Company(id), &info);
        env.storage()
            .persistent()
            .set(&DataKey::CompanyAdmin(admin.clone()), &id);

        payroll_events::emit_company_registered(&env, id, admin, treasury);

        id
    }

    fn add_employee(env: Env, company_id: u64, employee: Address, commitment: BytesN<32>) {
        Self::add_employee_record(env, company_id, employee, commitment);
    }

    fn validate_employee_wallet_format(_env: Env, employee_wallet: String) -> bool {
        Self::employee_wallet_format_is_valid(&employee_wallet)
    }

    fn add_employee_by_wallet(
        env: Env,
        company_id: u64,
        employee_wallet: String,
        commitment: BytesN<32>,
    ) {
        Self::require_valid_employee_wallet_format(&employee_wallet);
        let employee = Address::from_string(&employee_wallet);
        Self::add_employee_record(env, company_id, employee, commitment);
    }

    fn remove_employee(env: Env, company_id: u64, employee: Address) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        let emp = employee.clone();
        env.storage()
            .persistent()
            .remove(&DataKey::Employee(company_id, emp));

        payroll_events::emit_employee_removed(&env, company_id, employee);
    }

    fn update_commitment(env: Env, company_id: u64, employee: Address, new_commitment: BytesN<32>) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        info.admin.require_auth();

        let emp = employee.clone();
        let key = DataKey::Employee(company_id, emp);
        if !env.storage().persistent().has(&key) {
            panic!("Employee not found");
        }

        env.storage().persistent().set(&key, &new_commitment);

        payroll_events::emit_registry_commitment_updated(
            &env,
            company_id,
            employee,
            new_commitment,
        );
    }

    fn get_company(env: Env, company_id: u64) -> CompanyInfo {
        env.storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found")
    }

    fn get_commitment(env: Env, company_id: u64, employee: Address) -> BytesN<32> {
        env.storage()
            .persistent()
            .get(&DataKey::Employee(company_id, employee))
            .expect("Employee not found")
    }

    // ?? Issue #90: employee eligibility ??????????????????????????????????????

    fn set_employee_status(env: Env, company_id: u64, employee: Address, status: EmployeeStatus) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        info.admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()))
        {
            panic!("Employee not found");
        }

        let previous_status: EmployeeStatus = env
            .storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee.clone()))
            .unwrap_or(EmployeeStatus::Incomplete);

        if previous_status == status {
            return;
        }

        env.storage()
            .persistent()
            .set(&DataKey::EmpStatus(company_id, employee.clone()), &status);

        let event_name = match status {
            EmployeeStatus::Active => Symbol::new(&env, "EmployeeReactivated"),
            EmployeeStatus::Inactive => Symbol::new(&env, "EmployeeDeactivated"),
            EmployeeStatus::Incomplete => Symbol::new(&env, "EmployeeStatusUpdated"),
        };
        env.events().publish(
            (event_name, company_id, employee),
            (
                previous_status,
                status,
                env.ledger().sequence(),
                env.ledger().timestamp(),
            ),
        );
        // topics : ("EmployeeDeactivated" | "EmployeeReactivated" | "EmployeeStatusUpdated", company_id, employee)
        // data   : (previous_status, new_status, ledger_sequence, timestamp)
    }

    fn get_employee_status(env: Env, company_id: u64, employee: Address) -> EmployeeStatus {
        env.storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee))
            .unwrap_or(EmployeeStatus::Incomplete)
    }

    fn is_eligible(env: Env, company_id: u64, employee: Address) -> bool {
        Self::is_employee_active(env, company_id, employee)
    }

    fn is_employee_active(env: Env, company_id: u64, employee: Address) -> bool {
        Self::evaluate_eligibility(env, company_id, employee).eligible
    }

    fn evaluate_eligibility(env: Env, company_id: u64, employee: Address) -> EligibilityAssessment {
        let registered = env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()));
        let status: EmployeeStatus = env
            .storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee))
            .unwrap_or(EmployeeStatus::Incomplete);

        // An employee record is a precondition for *every* status, including
        // `Active`, so an address that was never onboarded can never be paid
        // even if a status key exists for it.
        let (reason, eligible) = if !registered {
            (EligibilityReason::Unregistered, false)
        } else {
            match status {
                EmployeeStatus::Active => (EligibilityReason::Eligible, true),
                EmployeeStatus::Inactive => (EligibilityReason::Inactive, false),
                EmployeeStatus::Incomplete => (EligibilityReason::Incomplete, false),
            }
        };

        EligibilityAssessment {
            status,
            reason,
            eligible,
        }
    }

    fn require_eligible(env: Env, company_id: u64, employee: Address) -> EmployeeStatus {
        let assessment = Self::evaluate_eligibility(env.clone(), company_id, employee.clone());
        if assessment.eligible {
            return assessment.status;
        }
        panic!(
            "Employee {:?} is not eligible for payroll in company {}: {}",
            employee,
            company_id,
            assessment.reason.as_str()
        );
    }

    // ?? Issue #91: company-level admin/treasury rotation ?????????????????????

    fn propose_admin_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_admin: Address,
    ) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized: caller is not the company admin");
        }
        current_admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation(company_id))
        {
            panic!("A pending admin rotation already exists for this company");
        }

        let proposal = PendingCompanyRotation {
            new_holder: new_admin.clone(),
            proposed_by: current_admin.clone(),
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdminRotation(company_id), &proposal);
        payroll_events::emit_company_admin_proposed(&env, company_id, current_admin, new_admin);
    }

    fn accept_admin_rotation(env: Env, company_id: u64, new_admin: Address) {
        Self::require_not_paused(&env);
        let proposal: PendingCompanyRotation = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation(company_id))
            .expect("No pending admin rotation for this company");

        if new_admin != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed admin");
        }
        new_admin.require_auth();

        let mut info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        let old_admin = info.admin.clone();

        info.admin = new_admin.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Company(company_id), &info);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation(company_id));
        env.storage()
            .persistent()
            .remove(&DataKey::CompanyAdmin(old_admin.clone()));
        env.storage()
            .persistent()
            .set(&DataKey::CompanyAdmin(new_admin.clone()), &company_id);
        payroll_events::emit_company_admin_rotated(&env, company_id, old_admin, new_admin);
    }

    fn cancel_admin_rotation(env: Env, company_id: u64, current_admin: Address) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation(company_id))
        {
            panic!("No pending admin rotation to cancel");
        }
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation(company_id));
        payroll_events::emit_company_admin_rotation_cancelled(&env, company_id, current_admin);
    }

    fn propose_treasury_rotation(
        env: Env,
        company_id: u64,
        current_admin: Address,
        new_treasury: Address,
    ) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized: caller is not the company admin");
        }
        current_admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation(company_id))
        {
            panic!("A pending treasury rotation already exists for this company");
        }

        let proposal = PendingCompanyRotation {
            new_holder: new_treasury.clone(),
            proposed_by: current_admin.clone(),
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PendingTreasuryRotation(company_id), &proposal);

        env.events().publish(
            (Symbol::new(&env, "TreasuryRotationProposed"), company_id),
            (current_admin, new_treasury, env.ledger().timestamp()),
        );
    }

    fn accept_treasury_rotation(env: Env, company_id: u64, new_treasury: Address) {
        Self::require_not_paused(&env);
        let proposal: PendingCompanyRotation = env
            .storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation(company_id))
            .expect("No pending treasury rotation for this company");

        if new_treasury != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed treasury");
        }
        new_treasury.require_auth();

        let mut info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");

        let old_treasury = info.treasury.clone();

        info.treasury = new_treasury.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Company(company_id), &info);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation(company_id));

        env.events().publish(
            (Symbol::new(&env, "TreasuryRotated"), company_id),
            (old_treasury, new_treasury),
        );
    }

    fn cancel_treasury_rotation(env: Env, company_id: u64, current_admin: Address) {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if current_admin != info.admin {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingTreasuryRotation(company_id))
        {
            panic!("No pending treasury rotation to cancel");
        }
        env.storage()
            .persistent()
            .remove(&DataKey::PendingTreasuryRotation(company_id));

        env.events().publish(
            (Symbol::new(&env, "TreasuryRotationCancelled"), company_id),
            (current_admin,),
        );
    }

    fn get_company_sequence(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::CompanySequence)
            .unwrap_or(0u64)
    }

    fn get_pending_admin_rotation(env: Env, company_id: u64) -> Option<PendingCompanyRotation> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation(company_id))
    }

    fn get_pending_treasury_rotation(env: Env, company_id: u64) -> Option<PendingCompanyRotation> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingTreasuryRotation(company_id))
    }

    // ?? Issue #353: Approver Threshold Rotation Controls ???????????????????????????

    fn propose_threshold_rotation(
        env: Env,
        company_id: u64,
        admin: Address,
        new_threshold: u32,
        grace_period_seconds: u64,
    ) {
        Self::require_not_paused(&env);
        admin.require_auth();

        let company = env
            .storage()
            .persistent()
            .get::<DataKey, CompanyInfo>(&DataKey::Company(company_id))
            .expect("Company not found");

        if company.admin != admin {
            panic!("Only company admin can propose threshold rotation");
        }

        if new_threshold == 0 {
            panic!("Threshold must be at least 1");
        }

        let effective_after = env.ledger().timestamp() + grace_period_seconds;

        let pending = PendingThresholdRotation {
            company_id,
            new_threshold,
            proposed_at: env.ledger().timestamp(),
            proposed_by: admin.clone(),
            effective_after,
        };

        env.storage().persistent().set(
            &DataKey::PendingThresholdRotation(company_id),
            &pending,
        );

        env.events().publish(
            (Symbol::new(&env, "ThresholdRotationProposed"), company_id),
            (new_threshold, effective_after),
        );
    }

    fn activate_threshold_rotation(env: Env, company_id: u64, admin: Address) {
        Self::require_not_paused(&env);
        admin.require_auth();

        let company = env
            .storage()
            .persistent()
            .get::<DataKey, CompanyInfo>(&DataKey::Company(company_id))
            .expect("Company not found");

        if company.admin != admin {
            panic!("Only company admin can activate threshold rotation");
        }

        let pending = env
            .storage()
            .persistent()
            .get::<DataKey, PendingThresholdRotation>(&DataKey::PendingThresholdRotation(company_id))
            .expect("No pending threshold rotation");

        if env.ledger().timestamp() < pending.effective_after {
            panic!("Threshold rotation is still in grace period");
        }

        let threshold = ApprovalThreshold {
            company_id,
            required_approvals: pending.new_threshold,
            configured_at: env.ledger().timestamp(),
            configured_by: admin.clone(),
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&DataKey::ApprovalThreshold(company_id), &threshold);

        env.storage()
            .persistent()
            .remove(&DataKey::PendingThresholdRotation(company_id));

        env.events().publish(
            (Symbol::new(&env, "ThresholdRotationActivated"), company_id),
            (pending.new_threshold, env.ledger().timestamp()),
        );
    }

    fn cancel_threshold_rotation(env: Env, company_id: u64, admin: Address) {
        Self::require_not_paused(&env);
        admin.require_auth();

        let company = env
            .storage()
            .persistent()
            .get::<DataKey, CompanyInfo>(&DataKey::Company(company_id))
            .expect("Company not found");

        if company.admin != admin {
            panic!("Only company admin can cancel threshold rotation");
        }

        let pending = env
            .storage()
            .persistent()
            .get::<DataKey, PendingThresholdRotation>(&DataKey::PendingThresholdRotation(company_id))
            .expect("No pending threshold rotation");

        env.storage()
            .persistent()
            .remove(&DataKey::PendingThresholdRotation(company_id));

        env.events().publish(
            (Symbol::new(&env, "ThresholdRotationCancelled"), company_id),
            (pending.new_threshold, env.ledger().timestamp()),
        );
    }

    fn get_approval_threshold(env: Env, company_id: u64) -> Option<ApprovalThreshold> {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovalThreshold(company_id))
    }

    fn get_pending_threshold_rotation(env: Env, company_id: u64) -> Option<PendingThresholdRotation> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingThresholdRotation(company_id))
    }

    fn set_initial_approval_threshold(
        env: Env,
        company_id: u64,
        admin: Address,
        required_approvals: u32,
    ) {
        Self::require_not_paused(&env);
        admin.require_auth();

        if required_approvals == 0 {
            panic!("Threshold must be at least 1");
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::ApprovalThreshold(company_id))
        {
            panic!("Approval threshold already configured for this company");
        }

        let threshold = ApprovalThreshold {
            company_id,
            required_approvals,
            configured_at: env.ledger().timestamp(),
            configured_by: admin.clone(),
            is_active: true,
        };

        env.storage()
            .persistent()
            .set(&DataKey::ApprovalThreshold(company_id), &threshold);

        env.events().publish(
            (Symbol::new(&env, "InitialThresholdConfigured"), company_id),
            (required_approvals, env.ledger().timestamp()),
        );
    }

    // -- Compensation policy effective-date validation ------------------------

    fn schedule_compensation_policy(
        env: Env,
        company_id: u64,
        admin: Address,
        policy_commitment: BytesN<32>,
        effective_at: u64,
    ) -> CompensationPolicy {
        Self::require_not_paused(&env);
        let info: CompanyInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Company(company_id))
            .expect("Company not found");
        if admin != info.admin {
            panic!("Unauthorized: caller is not the company admin");
        }
        admin.require_auth();

        // The commitment must bind something: an all-zero policy is the
        // uninitialized slot rather than a real hashed schedule, and would
        // otherwise read as a valid policy.
        if policy_commitment == BytesN::from_array(&env, &[0u8; 32]) {
            panic!(
                "Compensation policy commitment must not be zero: hash the schedule before scheduling it"
            );
        }

        // Effective-date validation runs after the identity and authorisation
        // checks, not before: an unauthorised caller must not be able to probe
        // a company's existing schedule through the effective-date errors.
        Self::assert_compensation_effective_date_is_valid(&env, company_id, effective_at);

        let policy = CompensationPolicy {
            company_id,
            policy_commitment: policy_commitment.clone(),
            effective_at,
            created_at: env.ledger().timestamp(),
            created_by: admin.clone(),
        };

        let schedule_key = DataKey::CompensationPolicySchedule(company_id);
        let mut schedule = Self::load_compensation_policy_schedule(&env, company_id);
        schedule.push_back(effective_at);
        env.storage().persistent().set(&schedule_key, &schedule);
        env.storage().persistent().set(
            &DataKey::CompensationPolicy(company_id, effective_at),
            &policy,
        );

        payroll_events::emit_compensation_policy_scheduled(
            &env,
            company_id,
            policy_commitment,
            effective_at,
        );

        policy
    }

    fn check_policy_effective_date(
        env: Env,
        company_id: u64,
        effective_at: u64,
    ) -> CompensationPolicyEffectiveDateCheck {
        Self::evaluate_compensation_effective_date(&env, company_id, effective_at)
    }

    fn require_valid_effective_date(env: Env, company_id: u64, effective_at: u64) {
        Self::assert_compensation_effective_date_is_valid(&env, company_id, effective_at);
    }

    fn get_compensation_policy(
        env: Env,
        company_id: u64,
        effective_at: u64,
    ) -> Option<CompensationPolicy> {
        env.storage()
            .persistent()
            .get(&DataKey::CompensationPolicy(company_id, effective_at))
    }

    fn get_compensation_policy_schedule(env: Env, company_id: u64) -> Vec<CompensationPolicy> {
        let schedule = Self::load_compensation_policy_schedule(&env, company_id);
        let mut policies = Vec::new(&env);
        for i in 0..schedule.len() {
            let effective_at = schedule.get(i).unwrap();
            if let Some(policy) = env
                .storage()
                .persistent()
                .get(&DataKey::CompensationPolicy(company_id, effective_at))
            {
                policies.push_back(policy);
            }
        }
        policies
    }

    fn get_compensation_policy_at(
        env: Env,
        company_id: u64,
        at_timestamp: u64,
    ) -> Option<CompensationPolicy> {
        Self::resolve_effective_compensation_policy(&env, company_id, at_timestamp)
    }

    fn is_compensation_policy_effective(env: Env, company_id: u64, at_timestamp: u64) -> bool {
        Self::resolve_effective_compensation_policy(&env, company_id, at_timestamp).is_some()
    }
}

#[cfg(test)]
mod tests;
