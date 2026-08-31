#![no_std]

extern crate alloc;

use pause_manager::PauseManagerClient;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Symbol};

const STELLAR_ACCOUNT_STRKEY_LEN: u32 = 56;
const STELLAR_ACCOUNT_STRKEY_LEN_USIZE: usize = 56;
const STELLAR_ACCOUNT_VERSION_BYTE: u8 = 6 << 3;

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

        env.events().publish(
            (Symbol::new(&env, "EmployeeAdded"), company_id, employee),
            (commitment,),
        );
        // topics : ("EmployeeAdded", company_id, employee)
        // data   : (commitment,)
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
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Employee(company_id, employee.clone()))
        {
            return false;
        }
        let status: EmployeeStatus = env
            .storage()
            .persistent()
            .get(&DataKey::EmpStatus(company_id, employee))
            .unwrap_or(EmployeeStatus::Incomplete);
        status == EmployeeStatus::Active
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
}

#[cfg(test)]
mod tests;
