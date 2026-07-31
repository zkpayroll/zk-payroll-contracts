//! # Migration State Fixtures
//!
//! Defines representative pre-upgrade state fixtures for companies, employees,
//! payroll runs, inactive employees, failed runs, treasury state, audit
//! permissions, and commitment references.
//!
//! These fixtures mirror the current (v1) storage schema and are used by
//! migration tests to validate that state written under v1 remains readable
//! after a simulated upgrade.
//!
//! ## Structure
//!
//! Each fixture constructor writes state directly to a contract's persistent
//! storage using the v1 `DataKey` enum discriminants. This models the
//! scenario where historical state written by a previous contract wasm is
//! still present in storage after a new contract version is deployed.
//!
//! ## Usage
//!
//! ```ignore
//! use state_fixtures::{
//!     write_v1_company_fixture,
//!     CompanyFixture,
//! };
//! use soroban_sdk::Env;
//!
//! let env = Env::default();
//! let (company_id, fixture) = write_v1_company_fixture(&env, &contract_id);
//! ```

use payroll_registry::{CompanyInfo, EmployeeStatus, PendingCompanyRotation};
use salary_commitment::{CommitmentSnapshot, PaymentNullifier, SalaryCommitment};
use soroban_sdk::{Address, BytesN, Env};

use payroll::{
    ContractAddresses as PayrollContractAddresses, DataKey as PayrollDataKey,
    EmergencyWithdrawalRequest, PayrollRun, PendingPayrollRun, ReconciliationStatus,
};
use payroll_registry::DataKey as RegistryDataKey;
use salary_commitment::DataKey as CommitmentDataKey;
// Audit permissions are set up via contract client APIs in the main test flow.
// Direct storage fixtures for audit are avoided because the DataKey enum
// serialization is internal to the audit_module crate.
use payment_executor::{
    ContractAddresses as ExecutorContractAddresses, DataKey as ExecutorDataKey,
};

// ── Address generators ──────────────────────────────────────────────────────

/// Generates a deterministic Address from a seed byte.
pub fn seed_address(env: &Env, seed: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    let strkey = stellar_strkey::Strkey::Contract(stellar_strkey::Contract(bytes)).to_string();
    Address::from_string(&soroban_sdk::String::from_str(env, &strkey))
}

/// Generates a deterministic 32-byte value from a seed byte.
pub fn seed_bytes32(env: &Env, seed: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    BytesN::from_array(env, &bytes)
}

/// Generates a deterministic 256-byte proof placeholder from a seed byte.
pub fn seed_proof(env: &Env, seed: u8) -> BytesN<256> {
    let mut bytes = [0u8; 256];
    bytes[255] = seed;
    BytesN::from_array(env, &bytes)
}

// ── Company Fixtures ────────────────────────────────────────────────────────

pub struct CompanyFixture {
    pub admin: Address,
    pub treasury: Address,
    pub company_id: u64,
}

/// Write a v1 company fixture directly into contract storage.
pub fn write_v1_company_fixture(
    env: &Env,
    registry_id: &Address,
    company_id: u64,
) -> CompanyFixture {
    let admin = seed_address(env, 0xCA);
    let treasury = seed_address(env, 0xCB);

    let info = CompanyInfo {
        admin: admin.clone(),
        treasury: treasury.clone(),
    };

    env.as_contract(registry_id, || {
        env.storage()
            .persistent()
            .set(&RegistryDataKey::CompanySequence, &(company_id + 1));
        env.storage()
            .persistent()
            .set(&RegistryDataKey::Company(company_id), &info);
        env.storage()
            .persistent()
            .set(&RegistryDataKey::CompanyAdmin(admin.clone()), &company_id);
    });

    CompanyFixture {
        admin,
        treasury,
        company_id,
    }
}

// ── Employee Fixtures ───────────────────────────────────────────────────────

pub struct EmployeeFixture {
    pub employee: Address,
    pub commitment: SalaryCommitment,
    pub status: EmployeeStatus,
    pub company_id: u64,
}

/// Write a v1 employee fixture (active, with commitment) directly into storage.
pub fn write_v1_employee_fixture(
    env: &Env,
    registry_id: &Address,
    commitment_id: &Address,
    company_id: u64,
    employee_seed: u8,
    status: EmployeeStatus,
) -> EmployeeFixture {
    let employee = seed_address(env, employee_seed);
    let commitment_value = seed_bytes32(env, employee_seed);
    let timestamp = env.ledger().timestamp();

    let salary_commitment = SalaryCommitment {
        commitment: commitment_value.clone(),
        created_at: timestamp,
        updated_at: timestamp,
        version: 1,
        revoked: false,
    };

    // Write to salary_commitment storage
    env.as_contract(commitment_id, || {
        env.storage().persistent().set(
            &CommitmentDataKey::Commitment(employee.clone()),
            &salary_commitment,
        );
    });

    // Write to payroll_registry storage
    env.as_contract(registry_id, || {
        env.storage().persistent().set(
            &RegistryDataKey::Employee(company_id, employee.clone()),
            &commitment_value,
        );
        env.storage().persistent().set(
            &RegistryDataKey::EmpStatus(company_id, employee.clone()),
            &status,
        );
    });

    EmployeeFixture {
        employee,
        commitment: salary_commitment,
        status,
        company_id,
    }
}

// ── Payroll Run Fixtures ────────────────────────────────────────────────────

pub struct PayrollRunFixture {
    pub run_id: u64,
    pub run: PayrollRun,
}

/// Write a v1 historical payroll run fixture directly into storage.
pub fn write_v1_payroll_run_fixture(
    env: &Env,
    payroll_id: &Address,
    run_id: u64,
    admin: &Address,
    total_amount: i128,
    employee_count: u32,
    status: ReconciliationStatus,
) -> PayrollRunFixture {
    let timestamp = env.ledger().timestamp();

    let run = PayrollRun {
        run_id,
        executed_at: timestamp,
        admin: admin.clone(),
        total_amount,
        employee_count,
        draft_hash: seed_bytes32(env, 0xDD),
        nonce: seed_bytes32(env, run_id as u8),
        reconciliation_status: status,
        metadata_hash: seed_bytes32(env, 0xEE),
    };

    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::PayrollRun(run_id), &run);
    });

    PayrollRunFixture { run_id, run }
}

/// Write a v1 pending payroll run fixture (prepared but not finalized).
pub fn write_v1_pending_run_fixture(
    env: &Env,
    payroll_id: &Address,
    run_id: u64,
    admin: &Address,
    total_amount: i128,
    employee_count: u32,
) {
    let timestamp = env.ledger().timestamp();

    let pending = PendingPayrollRun {
        run_id,
        prepared_at: timestamp,
        admin: admin.clone(),
        total_amount,
        employee_count,
        draft_hash: seed_bytes32(env, 0xDF),
        nonce: seed_bytes32(env, run_id as u8),
    };

    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::PendingRun(run_id), &pending);
    });
}

// ── Run Counter Fixture ─────────────────────────────────────────────────────

/// Write a v1 run counter into payroll contract storage.
pub fn write_v1_run_counter(env: &Env, payroll_id: &Address, count: u64) {
    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::RunCounter, &count);
    });
}

// ── Run Nonce Fixture ───────────────────────────────────────────────────────

/// Write a v1 consumed run nonce into payroll contract storage.
pub fn write_v1_run_nonce(env: &Env, payroll_id: &Address, nonce: &BytesN<32>, run_id: u64) {
    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::RunNonce(nonce.clone()), &run_id);
    });
}

// ── Nullifier Fixture ───────────────────────────────────────────────────────

/// Write a v1 nullifier (used status) into salary_commitment storage.
pub fn write_v1_nullifier(env: &Env, commitment_id: &Address, nullifier: &BytesN<32>) {
    let payment_nullifier = PaymentNullifier {
        nullifier: nullifier.clone(),
        used_at: env.ledger().timestamp(),
    };

    env.as_contract(commitment_id, || {
        env.storage().persistent().set(
            &CommitmentDataKey::Nullifier(nullifier.clone()),
            &payment_nullifier,
        );
    });
}

// ── Commitment History Fixture ──────────────────────────────────────────────

/// Write a v1 commitment history snapshot entry.
pub fn write_v1_commitment_history(
    env: &Env,
    commitment_id: &Address,
    employee: &Address,
    idx: u32,
    commitment: &BytesN<32>,
    version: u32,
) {
    let snapshot = CommitmentSnapshot {
        commitment: commitment.clone(),
        version,
        rotated_at: env.ledger().timestamp(),
    };

    env.as_contract(commitment_id, || {
        env.storage().persistent().set(
            &CommitmentDataKey::CommitmentHistory(employee.clone(), idx),
            &snapshot,
        );
    });
}

// ── Employee Reference ID Fixture ───────────────────────────────────────────

/// Write a v1 employee reference ID mapping.
pub fn write_v1_employee_reference_id(
    env: &Env,
    commitment_id: &Address,
    employee: &Address,
    ref_id: &soroban_sdk::String,
) {
    env.as_contract(commitment_id, || {
        env.storage().persistent().set(
            &CommitmentDataKey::EmployeeReferenceId(employee.clone()),
            ref_id,
        );
        env.storage().persistent().set(
            &CommitmentDataKey::ReferenceIdIndex(ref_id.clone()),
            employee,
        );
    });
}

// ── Admin Rotation Fixture ──────────────────────────────────────────────────

/// Write a v1 pending admin rotation into payroll contract storage.
pub fn write_v1_pending_admin_rotation(
    env: &Env,
    payroll_id: &Address,
    new_admin: &Address,
    proposed_by: &Address,
) {
    let proposal = payroll::PendingRotation {
        new_holder: new_admin.clone(),
        proposed_by: proposed_by.clone(),
        proposed_at: env.ledger().timestamp(),
    };

    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::PendingAdminRotation, &proposal);
    });
}

// ── Company Admin Rotation Fixture ──────────────────────────────────────────

/// Write a v1 pending admin rotation into payroll_registry contract storage.
pub fn write_v1_registry_admin_rotation(
    env: &Env,
    registry_id: &Address,
    company_id: u64,
    new_admin: &Address,
    proposed_by: &Address,
) {
    let proposal = PendingCompanyRotation {
        new_holder: new_admin.clone(),
        proposed_by: proposed_by.clone(),
        proposed_at: env.ledger().timestamp(),
    };

    env.as_contract(registry_id, || {
        env.storage().persistent().set(
            &RegistryDataKey::PendingAdminRotation(company_id),
            &proposal,
        );
    });
}

// ── Emergency Withdrawal Fixture ────────────────────────────────────────────

/// Write a v1 emergency withdrawal request.
pub fn write_v1_emergency_withdrawal(
    env: &Env,
    payroll_id: &Address,
    amount: i128,
    recipient: &Address,
) {
    let request = EmergencyWithdrawalRequest {
        amount,
        recipient: recipient.clone(),
        requested_at: env.ledger().timestamp(),
        approved: false,
    };

    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::EmergencyRequest, &request);
    });
}

// ── Treasury Owner Fixture ──────────────────────────────────────────────────

/// Write a v1 treasury owner into payroll contract storage.
pub fn write_v1_treasury_owner(env: &Env, payroll_id: &Address, owner: &Address) {
    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::TreasuryOwner, owner);
    });
}

// ── Payroll Contract Addresses Fixture ──────────────────────────────────────

/// Write v1 payroll contract addresses into storage.
pub fn write_v1_payroll_addresses(
    env: &Env,
    payroll_id: &Address,
    addrs: &PayrollContractAddresses,
) {
    env.as_contract(payroll_id, || {
        env.storage()
            .persistent()
            .set(&PayrollDataKey::Addresses, addrs);
    });
}

// ── Commitment Contract Admin Fixture ───────────────────────────────────────

/// Initialize a v1 admin in salary_commitment contract.
pub fn write_v1_commitment_admin(env: &Env, commitment_id: &Address, admin: &Address) {
    env.as_contract(commitment_id, || {
        env.storage()
            .persistent()
            .set(&CommitmentDataKey::Admin, admin);
    });
}

// ── Payroll Operator Fixture ────────────────────────────────────────────────

/// Write a v1 payroll operator into salary_commitment contract.
pub fn write_v1_payroll_operator(env: &Env, commitment_id: &Address, operator: &Address) {
    env.as_contract(commitment_id, || {
        env.storage()
            .persistent()
            .set(&CommitmentDataKey::PayrollOperator, operator);
    });
}

// ── Commitment Lock Fixture ─────────────────────────────────────────────────

/// Write a v1 commitment lock (locked = true) for an employee.
pub fn write_v1_commitment_lock(env: &Env, commitment_id: &Address, employee: &Address) {
    env.as_contract(commitment_id, || {
        env.storage()
            .persistent()
            .set(&CommitmentDataKey::CommitmentLock(employee.clone()), &true);
    });
}

// ── Audit Permission Fixtures ───────────────────────────────────────────────
//
// Audit view keys are set up via the audit_module client API
// (audit_client.generate_view_key()) in the main test setup flow.
// Direct storage-level fixtures for audit are **not provided** because
// the audit_module's `DataKey::AuditorKey(Address)` enum serialization
// is internal to that crate. Using the contract client ensures storage
// keys are written correctly and remain compatible.
//
// See `migration_helpers::MigrationContext::write_full_v1_state()` for
// the standard audit permission setup.

// ── Payment Executor Fixtures ───────────────────────────────────────────────

/// Write v1 payment executor contract addresses.
pub fn write_v1_executor_addresses(
    env: &Env,
    executor_id: &Address,
    addrs: &ExecutorContractAddresses,
) {
    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::Addresses, addrs);
    });
}

/// Write v1 executor admin.
pub fn write_v1_executor_admin(env: &Env, executor_id: &Address, admin: &Address) {
    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::ExecutorAdmin, admin);
    });
}

/// Write v1 storage version.
pub fn write_v1_storage_version(env: &Env, executor_id: &Address, version: u32) {
    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::StorageVersion, &version);
    });
}

/// Write a v1 total paid accumulator for a company.
pub fn write_v1_total_paid(env: &Env, executor_id: &Address, company_id: u64, total: i128) {
    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::TotalPaid(company_id), &total);
    });
}

// ── Payroll Period Fixture ──────────────────────────────────────────────────

/// Write a v1 payroll period into executor storage.
pub fn write_v1_payroll_period(
    env: &Env,
    executor_id: &Address,
    company_id: u64,
    period_id: u32,
    closed: bool,
) {
    let period = payment_executor::PayrollPeriod {
        period_id,
        company_id,
        start_ledger: env.ledger().sequence(),
        end_ledger: if closed {
            env.ledger().sequence() + 100
        } else {
            0
        },
        created_at: env.ledger().timestamp(),
        closed,
        payment_count: 0,
    };

    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::Period(company_id, period_id), &period);
        env.storage().persistent().set(
            &ExecutorDataKey::PeriodSequence(company_id),
            &(period_id + 1),
        );
    });
}

/// Write a v1 payment record into executor storage.
pub fn write_v1_payment_record(
    env: &Env,
    executor_id: &Address,
    company_id: u64,
    employee: &Address,
    period: u32,
) {
    let record = payment_executor::PaymentRecord {
        company_id,
        employee: employee.clone(),
        proof_hash: seed_bytes32(env, 0xAB),
        timestamp: env.ledger().timestamp(),
        period,
    };

    env.as_contract(executor_id, || {
        env.storage()
            .persistent()
            .set(&ExecutorDataKey::Payment(employee.clone(), period), &record);
    });
}
