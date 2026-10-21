#![no_std]

use pause_manager::PauseManagerClient;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Symbol, Vec};

// ---------------------------------------------------------------------------
// Operational roles
//
// The salary commitment contract separates four operational roles:
//   HR_ADMIN    â€” Registered in `initialize()`. Authorizes all writes
//                 (store / update / revoke commitment, record nullifier).
//   PAYROLL_OP  â€” An address delegated to execute payroll (record nullifiers
//                 only). Set via `set_payroll_operator`.
//   AUDITOR     â€” Grant access via the audit_module (view keys).
//   TREASURY    â€” Does NOT interact with this contract; payment source lives
//                 in payment_executor.
//
// Unauthorized role actions fail with `require_auth()` / explicit role checks.
// ---------------------------------------------------------------------------

/// Commitment data structure
#[contracttype]
#[derive(Clone, Debug)]
pub struct SalaryCommitment {
    pub commitment: BytesN<32>, // Poseidon(salary, blinding_factor)
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u32,
    /// True when this commitment has been rotated out and must not be used
    /// for future payroll proofs.
    pub revoked: bool,
}

/// Nullifier to prevent double-spending
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentNullifier {
    pub nullifier: BytesN<32>,
    pub used_at: u64,
}

/// Previous commitment snapshot retained for audit history on rotation.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CommitmentSnapshot {
    pub commitment: BytesN<32>,
    pub version: u32,
    pub rotated_at: u64,
}

/// Pending two-step role-rotation request (issue #192).
#[contracttype]
#[derive(Clone, Debug)]
pub struct PendingRotation {
    pub new_holder: Address,
    pub proposed_by: Address,
    pub proposed_at: u64,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Commitment(Address),
    Nullifier(BytesN<32>),
    CompanyRoot(Symbol),
    /// Previous commitment history per employee (appended on rotation).
    CommitmentHistory(Address, u32),
    /// The HR admin address that can write to this contract.
    Admin,
    /// A delegated payroll operator that can record nullifiers.
    PayrollOperator,
    /// External reference ID mapping for HR system integration (employee -> ref_id).
    EmployeeReferenceId(Address),
    /// Reverse mapping to detect collisions (ref_id -> employee).
    ReferenceIdIndex(soroban_sdk::String),
    /// When true, the employee's commitment is locked and cannot be updated.
    /// Set by the admin via `lock_commitment_updates` and cleared via
    /// `unlock_commitment_updates`.
    CommitmentLock(Address),
    /// Marks a commitment value as already bound to an employee, active or
    /// archived (issue #242). Once set it is never cleared: a commitment
    /// value that has participated in any active or completed payroll run
    /// must never be reassigned to a different (or the same) employee, since
    /// reuse would weaken privacy assumptions and confuse reconciliation.
    CommitmentIndex(BytesN<32>),
    /// Pause manager address (issue #193).
    PauseManager,
    /// Pending admin rotation proposal (issue #192).
    PendingAdminRotation,
}

#[contract]
pub struct SalaryCommitmentContract;

#[contractimpl]
impl SalaryCommitmentContract {
    /// Initialize the contract with an HR admin address.
    /// Must be called once. The admin is the only address allowed to
    /// store / update / revoke commitments.
    pub fn init_commitment_admin(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("Already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Set a delegated payroll operator that may record nullifiers
    /// (required for batch payroll execution). Only the admin may call.
    pub fn set_payroll_operator(env: Env, operator: Address) {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PayrollOperator, &operator);
        payroll_events::emit_payroll_operator_set(&env, operator);
    }

    /// Remove the delegated payroll operator. Only the HR admin may call.
    /// Emits a privacy-safe event indicating the operator address that was
    /// removed. This does not disclose any payroll-sensitive values.
    pub fn remove_payroll_operator(env: Env) {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        let key = DataKey::PayrollOperator;
        let prev: Option<Address> = env.storage().persistent().get(&key);
        if prev.is_none() {
            panic!("No payroll operator set");
        }
        let prev_op = prev.unwrap();
        env.storage().persistent().remove(&key);
        payroll_events::emit_payroll_operator_removed(&env, prev_op);
    }

    /// Lock an employee's commitment to prevent updates via `update_commitment`
    /// or `rotate_commitment`. Both the HR admin and the delegated payroll
    /// operator may call.
    ///
    /// The lock is meant to be set when a payroll draft is finalized or a
    /// payroll run is executed, ensuring the commitment cannot be silently
    /// altered after approval or audit review.
    pub fn lock_commitment_updates(env: Env, employee: Address) {
        Self::require_not_paused(&env);
        Self::require_admin_or_operator(&env);
        let key = DataKey::CommitmentLock(employee.clone());
        if env.storage().persistent().has(&key) {
            panic!("Commitment is already locked");
        }
        env.storage().persistent().set(&key, &true);

        payroll_events::emit_commitment_locked(&env, employee);
    }

    /// Unlock an employee's commitment so it can be updated again.
    /// Only the HR admin may call.
    pub fn unlock_commitment_updates(env: Env, employee: Address) {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        let key = DataKey::CommitmentLock(employee.clone());
        if !env.storage().persistent().has(&key) {
            panic!("Commitment is not locked");
        }
        env.storage().persistent().remove(&key);

        payroll_events::emit_commitment_unlocked(&env, employee);
    }

    /// Check if an employee's commitment is currently locked.
    pub fn is_commitment_locked(env: Env, employee: Address) -> bool {
        let key = DataKey::CommitmentLock(employee);
        env.storage().persistent().has(&key)
    }

    /// Get the stored admin address.
    pub fn get_commitment_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized")
    }

    /// Get the payroll operator address (if set).
    pub fn get_payroll_operator(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::PayrollOperator)
    }

    /// Store a new salary commitment for an employee.
    /// Only the HR admin may call.
    ///
    /// The commitment value must be globally unique (issue #242): it cannot
    /// already be bound to any employee, active or archived.
    pub fn store_commitment(
        env: Env,
        employee: Address,
        commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_not_paused(&env);
        Self::require_admin(&env);
        Self::register_commitment_uniqueness(&env, &commitment);

        let timestamp = env.ledger().timestamp();

        let salary_commitment = SalaryCommitment {
            commitment: commitment.clone(),
            created_at: timestamp,
            updated_at: timestamp,
            version: 1,
            revoked: false,
        };

        let key = DataKey::Commitment(employee.clone());
        env.storage().persistent().set(&key, &salary_commitment);

        // Emit CommitmentUpdated event so off-chain indexers track commitment history.
        payroll_events::emit_commitment_stored(&env, employee, commitment);

        salary_commitment
    }

    /// Update an existing salary commitment (rotation for compensation changes).
    /// Only the HR admin may call.
    ///
    /// The previous commitment is archived in CommitmentHistory so it remains
    /// auditable. The new commitment replaces the active record and the version
    /// is incremented.
    ///
    /// Fails if the employee's commitment is currently locked (see
    /// `lock_commitment_updates` / `unlock_commitment_updates`).
    pub fn update_commitment(
        env: Env,
        employee: Address,
        new_commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        if Self::is_commitment_locked(env.clone(), employee.clone()) {
            panic!("Commitment is locked: cannot update until unlocked by admin");
        }

        let key = DataKey::Commitment(employee.clone());
        let existing: SalaryCommitment = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found");

        Self::register_commitment_uniqueness(&env, &new_commitment);

        // Archive current commitment before replacing
        Self::archive_commitment(&env, &employee, &existing.commitment, existing.version);

        let updated = SalaryCommitment {
            commitment: new_commitment.clone(),
            created_at: existing.created_at,
            updated_at: env.ledger().timestamp(),
            version: existing.version + 1,
            revoked: false,
        };

        env.storage().persistent().set(&key, &updated);

        payroll_events::emit_commitment_stored(&env, employee, new_commitment);

        updated
    }

    /// Rotate a salary commitment: archive the old one and store the new one.
    /// Old commitments CANNOT be used for future payroll proofs (see
    /// `is_commitment_active`).
    /// Only the HR admin may call.
    ///
    /// Fails if the employee's commitment is currently locked (see
    /// `lock_commitment_updates` / `unlock_commitment_updates`). To rotate a
    /// locked commitment without dropping its lock, use
    /// `rotate_approved_commitment`.
    pub fn rotate_commitment(
        env: Env,
        employee: Address,
        new_commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        if Self::is_commitment_locked(env.clone(), employee.clone()) {
            panic!("Commitment is locked: cannot rotate until unlocked by admin (or use rotate_approved_commitment to rotate it in place)");
        }

        let existing: SalaryCommitment = Self::load_commitment(&env, &employee);

        let rotated = Self::apply_rotation(&env, &employee, &existing, &new_commitment);

        // Emit an explicit rotation event
        payroll_events::emit_commitment_rotated(
            &env,
            employee,
            existing.commitment,
            rotated.commitment.clone(),
        );

        rotated
    }

    /// Rotate a commitment that is currently **locked** (issue #520).
    ///
    /// `payroll` locks an employee's commitment when a payroll run executes
    /// against it, so the commitment value that the settled payroll record
    /// refers to cannot be silently changed afterwards. That also means a
    /// routine compensation change (raise, bonus, correction) after a
    /// settlement had no supported path: the admin had to unlock first, which
    /// left the approved binding unprotected for as long as the two calls were
    /// separate transactions.
    ///
    /// This entry-point performs the rotation in a single authorized call and
    /// deliberately **keeps the lock in place**, so:
    ///
    /// - the previous commitment value is archived in `CommitmentHistory` and
    ///   stays permanently reserved (#242), which keeps every settled payroll
    ///   record attributable to the commitment it was paid against;
    /// - the `version` counter keeps increasing monotonically, so audit
    ///   tooling can order commitment revisions;
    /// - the approved/settled binding is still enforced after the rotation.
    ///
    /// Only the HR admin may call.
    ///
    /// # Panics
    /// - `"Commitment is not locked: use rotate_commitment to rotate an
    ///   unlocked commitment"` when the employee's commitment is not locked.
    /// - `"Commitment not found"` when the employee has no stored commitment.
    /// - `"New commitment must differ from the current commitment"` when the
    ///   new value equals the current one (no-op rotation).
    /// - `"Commitment already in use: commitments must be unique across
    ///   employees and payroll runs"` when the new value was already bound to
    ///   any employee (#242).
    ///
    /// All failure messages are privacy-safe: they never include the
    /// commitment values, salaries, or blinding factors.
    pub fn rotate_approved_commitment(
        env: Env,
        employee: Address,
        new_commitment: BytesN<32>,
    ) -> SalaryCommitment {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        // Only a locked (approved / already settled) commitment may take this
        // path; unlocked commitments keep using `rotate_commitment` so the two
        // operations stay distinguishable in the audit trail.
        if !Self::is_commitment_locked(env.clone(), employee.clone()) {
            panic!(
                "Commitment is not locked: use rotate_commitment to rotate an unlocked commitment"
            );
        }

        let existing: SalaryCommitment = Self::load_commitment(&env, &employee);

        // Reject no-op rotations before the uniqueness check, which would
        // otherwise report the employee's own current value as "already in
        // use" and send the caller looking in the wrong direction.
        if existing.commitment == new_commitment {
            panic!("New commitment must differ from the current commitment");
        }

        let rotated = Self::apply_rotation(&env, &employee, &existing, &new_commitment);

        // The lock is intentionally left in place: the settlement that caused
        // it must stay bound to its recorded commitment.
        payroll_events::emit_commitment_approved_rotated(
            &env,
            employee,
            existing.commitment,
            rotated.commitment.clone(),
        );

        rotated
    }

    /// Whether `rotate_approved_commitment` would currently succeed for
    /// `employee`: the employee must have an active, locked commitment.
    /// Privacy-safe read-only view (no salary or commitment values returned).
    pub fn can_rotate_approved_commitment(env: Env, employee: Address) -> bool {
        Self::is_commitment_active(env.clone(), employee.clone())
            && Self::is_commitment_locked(env, employee)
    }

    /// Check whether a commitment is currently active (not revoked).
    pub fn is_commitment_active(env: Env, employee: Address) -> bool {
        let key = DataKey::Commitment(employee);
        if let Some(c) = env
            .storage()
            .persistent()
            .get::<DataKey, SalaryCommitment>(&key)
        {
            return !c.revoked;
        }
        false
    }

    /// Retrieve the commitment history for an employee.
    /// Returns archived snapshots from previous rotations.
    pub fn get_commitment_history(env: Env, employee: Address) -> Vec<CommitmentSnapshot> {
        let mut history = Vec::new(&env);
        let mut idx: u32 = 0;
        loop {
            let history_key = DataKey::CommitmentHistory(employee.clone(), idx);
            if let Some(snapshot) = env
                .storage()
                .persistent()
                .get::<DataKey, CommitmentSnapshot>(&history_key)
            {
                history.push_back(snapshot);
                idx += 1;
            } else {
                break;
            }
        }
        history
    }

    /// Get commitment for an employee
    pub fn get_commitment(env: Env, employee: Address) -> SalaryCommitment {
        let key = DataKey::Commitment(employee);
        env.storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found")
    }

    /// Check if a commitment exists
    pub fn has_commitment(env: Env, employee: Address) -> bool {
        let key = DataKey::Commitment(employee);
        env.storage().persistent().has(&key)
    }

    /// Normalize an employee reference identifier according to standard rules (#544).
    ///
    /// Rules applied:
    /// 1. Trims leading and trailing whitespace (spaces, tabs, newlines, carriage returns).
    /// 2. Converts ASCII lowercase letters to uppercase for canonical matching.
    /// 3. Validates length is between 1 and 256 characters after trimming.
    /// 4. Validates that the identifier contains only printable ASCII characters (32..=126).
    /// 5. Rejects empty or all-whitespace strings.
    ///
    /// Privacy-safe: operates strictly on opaque reference identifier strings without
    /// exposing or logging salary amounts or cryptographic blinding factors.
    ///
    /// # Panics
    /// - Panics with `"Reference ID must be 1-256 characters"` if empty, all-whitespace, or > 256 chars.
    /// - Panics with `"Employee identifier contains invalid characters: must be printable ASCII"` if non-printable.
    pub fn normalize_employee_identifier(env: Env, identifier: soroban_sdk::String) -> soroban_sdk::String {
        Self::normalize_employee_identifier_internal(&env, &identifier)
    }

    /// Internal helper that normalizes an employee reference identifier.
    fn normalize_employee_identifier_internal(
        env: &Env,
        identifier: &soroban_sdk::String,
    ) -> soroban_sdk::String {
        let raw_len = identifier.len() as usize;
        if raw_len == 0 || raw_len > 512 {
            panic!("Reference ID must be 1-256 characters");
        }

        let mut buf = [0u8; 512];
        identifier.copy_into_slice(&mut buf[..raw_len]);
        let slice = &buf[..raw_len];

        let mut start = 0;
        while start < raw_len
            && (slice[start] == b' '
                || slice[start] == b'\t'
                || slice[start] == b'\n'
                || slice[start] == b'\r')
        {
            start += 1;
        }

        let mut end = raw_len;
        while end > start
            && (slice[end - 1] == b' '
                || slice[end - 1] == b'\t'
                || slice[end - 1] == b'\n'
                || slice[end - 1] == b'\r')
        {
            end -= 1;
        }

        let trimmed_len = end - start;
        if trimmed_len == 0 || trimmed_len > 256 {
            panic!("Reference ID must be 1-256 characters");
        }

        let mut out_buf = [0u8; 256];
        for i in 0..trimmed_len {
            let b = slice[start + i];
            if b < 32 || b > 126 {
                panic!("Employee identifier contains invalid characters: must be printable ASCII");
            }
            out_buf[i] = if b.is_ascii_lowercase() {
                b - 32
            } else {
                b
            };
        }

        let normalized_str = core::str::from_utf8(&out_buf[..trimmed_len])
            .expect("normalized employee identifier is valid UTF-8");
        soroban_sdk::String::from_str(env, normalized_str)
    }

    /// Try normalizing an identifier for read-only lookups, returning None if invalid.
    fn try_normalize_employee_identifier_internal(
        env: &Env,
        identifier: &soroban_sdk::String,
    ) -> Option<soroban_sdk::String> {
        let raw_len = identifier.len() as usize;
        if raw_len == 0 || raw_len > 512 {
            return None;
        }

        let mut buf = [0u8; 512];
        identifier.copy_into_slice(&mut buf[..raw_len]);
        let slice = &buf[..raw_len];

        let mut start = 0;
        while start < raw_len
            && (slice[start] == b' '
                || slice[start] == b'\t'
                || slice[start] == b'\n'
                || slice[start] == b'\r')
        {
            start += 1;
        }

        let mut end = raw_len;
        while end > start
            && (slice[end - 1] == b' '
                || slice[end - 1] == b'\t'
                || slice[end - 1] == b'\n'
                || slice[end - 1] == b'\r')
        {
            end -= 1;
        }

        let trimmed_len = end - start;
        if trimmed_len == 0 || trimmed_len > 256 {
            return None;
        }

        let mut out_buf = [0u8; 256];
        for i in 0..trimmed_len {
            let b = slice[start + i];
            if b < 32 || b > 126 {
                return None;
            }
            out_buf[i] = if b.is_ascii_lowercase() {
                b - 32
            } else {
                b
            };
        }

        let normalized_str = core::str::from_utf8(&out_buf[..trimmed_len]).ok()?;
        Some(soroban_sdk::String::from_str(env, normalized_str))
    }

    /// Set an external reference ID (e.g., HR system employee ID) for an employee.
    /// Only the HR admin may call. Reference IDs must be unique (no collisions).
    /// Applies employee identifier normalization rules (#544).
    /// Non-sensitive IDs only (e.g., "EMP12345", not salary or bank account).
    pub fn set_employee_reference_id(
        env: Env,
        employee: Address,
        reference_id: soroban_sdk::String,
    ) {
        Self::require_not_paused(&env);
        Self::require_admin(&env);

        let normalized_id = Self::normalize_employee_identifier_internal(&env, &reference_id);

        // Check if this reference ID is already assigned to a different employee
        // in this employer's salary commitment contract (the payroll scope).
        let index_key = DataKey::ReferenceIdIndex(normalized_id.clone());
        if let Some(existing_employee) = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&index_key)
        {
            if existing_employee != employee {
                panic!("Reference ID already assigned to another employee");
            }
        }

        // Check if this employee already has a different reference ID
        let employee_key = DataKey::EmployeeReferenceId(employee.clone());
        if let Some(old_ref_id) = env
            .storage()
            .persistent()
            .get::<DataKey, soroban_sdk::String>(&employee_key)
        {
            if old_ref_id != normalized_id {
                // Remove old reverse mapping
                env.storage()
                    .persistent()
                    .remove(&DataKey::ReferenceIdIndex(old_ref_id));
            }
        }

        // Store both forward and reverse mappings using canonical normalized form
        env.storage().persistent().set(&employee_key, &normalized_id);
        env.storage().persistent().set(&index_key, &employee);

        payroll_events::emit_reference_id_set(&env, employee, normalized_id);
    }

    /// Get the external reference ID for an employee (if set).
    pub fn get_employee_reference_id(env: Env, employee: Address) -> Option<soroban_sdk::String> {
        let key = DataKey::EmployeeReferenceId(employee);
        env.storage().persistent().get(&key)
    }

    /// Get the employee address associated with a reference ID (for lookups).
    /// Normalizes the lookup identifier so mixed-case or padded queries resolve (#544).
    /// Returns None if no employee is associated with this ID or if invalid.
    pub fn get_employee_by_reference_id(
        env: Env,
        reference_id: soroban_sdk::String,
    ) -> Option<Address> {
        let normalized_id = Self::try_normalize_employee_identifier_internal(&env, &reference_id)?;
        let key = DataKey::ReferenceIdIndex(normalized_id);
        env.storage().persistent().get(&key)
    }

    /// Record a payment nullifier (prevents double payment).
    /// Authorized for both the HR admin and the delegated payroll operator.
    pub fn record_nullifier(env: Env, nullifier: BytesN<32>) {
        Self::require_not_paused(&env);
        Self::require_admin_or_operator(&env);

        let key = DataKey::Nullifier(nullifier.clone());

        if env.storage().persistent().has(&key) {
            panic!("Nullifier already used");
        }

        let payment_nullifier = PaymentNullifier {
            nullifier,
            used_at: env.ledger().timestamp(),
        };

        env.storage().persistent().set(&key, &payment_nullifier);
        payroll_events::emit_nullifier_recorded(&env, payment_nullifier.nullifier);
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        let key = DataKey::Nullifier(nullifier);
        env.storage().persistent().has(&key)
    }

    /// Compute a commitment hash for a salary and blinding factor.
    pub fn compute_commitment(env: Env, salary: u64, blinding_factor: BytesN<32>) -> BytesN<32> {
        let mut preimage = soroban_sdk::Bytes::new(&env);
        preimage.extend_from_array(&salary.to_le_bytes());
        let blinding_bytes: [u8; 32] = blinding_factor.into();
        preimage.extend_from_array(&blinding_bytes);

        env.crypto().sha256(&preimage).into()
    }

    /// Verify a commitment matches a salary (with proof)
    pub fn verify_commitment(
        env: Env,
        employee: Address,
        claimed_salary: u64,
        blinding_factor: BytesN<32>,
    ) -> bool {
        let stored = Self::get_commitment(env.clone(), employee);
        let computed = Self::compute_commitment(env, claimed_salary, blinding_factor);

        stored.commitment == computed && !stored.revoked
    }

    // -----------------------------------------------------------------------
    // Role guards
    // -----------------------------------------------------------------------

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        admin.require_auth();
    }

    fn require_admin_or_operator(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");

        let operator: Option<Address> = env.storage().persistent().get(&DataKey::PayrollOperator);

        match operator {
            Some(op) => op.require_auth(),
            None => admin.require_auth(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    // ── Issue #192: two-step admin rotation ──────────────────────────────────

    /// Propose a new admin (step 1 of 2).
    pub fn propose_admin_rotation(env: Env, current_admin: Address, new_admin: Address) {
        Self::require_not_paused(&env);
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        if current_admin != stored {
            panic!("Unauthorized: caller is not the current admin");
        }
        current_admin.require_auth();

        if env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation)
        {
            panic!("A pending admin rotation already exists");
        }

        let proposal = PendingRotation {
            new_holder: new_admin.clone(),
            proposed_by: current_admin.clone(),
            proposed_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdminRotation, &proposal);

        payroll_events::emit_commitment_admin_proposed(&env, current_admin, new_admin);
    }

    /// Accept a pending admin rotation (step 2 of 2).
    pub fn accept_admin_rotation(env: Env, new_admin: Address) {
        Self::require_not_paused(&env);
        let proposal: PendingRotation = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation)
            .expect("No pending admin rotation");

        if new_admin != proposal.new_holder {
            panic!("Unauthorized: caller is not the proposed admin");
        }
        new_admin.require_auth();

        env.storage().persistent().set(&DataKey::Admin, &new_admin);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        payroll_events::emit_commitment_admin_accepted(&env, new_admin);
    }

    /// Cancel a pending admin rotation proposal.
    pub fn cancel_admin_rotation(env: Env, current_admin: Address) {
        Self::require_not_paused(&env);
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        if current_admin != stored {
            panic!("Unauthorized");
        }
        current_admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::PendingAdminRotation)
        {
            panic!("No pending admin rotation to cancel");
        }
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdminRotation);

        payroll_events::emit_commitment_admin_cancelled(&env, current_admin);
    }

    /// Get the pending admin rotation proposal, if any.
    pub fn get_pending_admin_rotation(env: Env) -> Option<PendingRotation> {
        env.storage()
            .persistent()
            .get(&DataKey::PendingAdminRotation)
    }

    // ── Issue #193: pause support ────────────────────────────────────────────

    /// Set the pause manager contract address (only admin).
    pub fn set_pause_manager(env: Env, pause_manager: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::PauseManager, &pause_manager);
        payroll_events::emit_commitment_pause_manager_set(&env, pause_manager);
    }

    fn require_not_paused(env: &Env) {
        if env.storage().persistent().has(&DataKey::PauseManager) {
            let pm_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::PauseManager)
                .unwrap();
            let pm_client = PauseManagerClient::new(env, &pm_addr);
            if pm_client.is_paused() {
                panic!("Salary commitment operations are paused");
            }
        }
    }

    /// Load the active commitment record for an employee.
    fn load_commitment(env: &Env, employee: &Address) -> SalaryCommitment {
        env.storage()
            .persistent()
            .get(&DataKey::Commitment(employee.clone()))
            .expect("Commitment not found")
    }

    /// Shared rotation body for `rotate_commitment` and
    /// `rotate_approved_commitment` (issue #520).
    ///
    /// Reserves the incoming value, archives the outgoing one into the
    /// employee's history, and writes the new active record with a
    /// monotonically increasing `version`. The caller's lock state is not
    /// touched here — that is the difference between the two entry-points.
    fn apply_rotation(
        env: &Env,
        employee: &Address,
        previous: &SalaryCommitment,
        new_commitment: &BytesN<32>,
    ) -> SalaryCommitment {
        // #242: the retired value stays permanently reserved, so a settled
        // payroll record can always be matched to the commitment it used and
        // the value can never be re-bound to another employee.
        Self::register_commitment_uniqueness(env, new_commitment);

        // Archive the previous commitment so it remains auditable.
        Self::archive_commitment(env, employee, &previous.commitment, previous.version);

        let timestamp = env.ledger().timestamp();
        let rotated = SalaryCommitment {
            commitment: new_commitment.clone(),
            created_at: timestamp,
            updated_at: timestamp,
            // Versions increase monotonically across updates *and* rotations
            // so audit tooling can order commitment revisions.
            version: previous.version.saturating_add(1),
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Commitment(employee.clone()), &rotated);

        payroll_events::emit_commitment_stored(env, employee.clone(), new_commitment.clone());

        rotated
    }

    /// Reject a commitment value that has already been bound to any
    /// employee (active or archived) and register it as used (issue #242).
    fn register_commitment_uniqueness(env: &Env, commitment: &BytesN<32>) {
        let key = DataKey::CommitmentIndex(commitment.clone());
        if env.storage().persistent().has(&key) {
            panic!("Commitment already in use: commitments must be unique across employees and payroll runs");
        }
        env.storage().persistent().set(&key, &true);
    }

    fn archive_commitment(env: &Env, employee: &Address, commitment: &BytesN<32>, version: u32) {
        let mut idx: u32 = 0;
        loop {
            let history_key = DataKey::CommitmentHistory(employee.clone(), idx);
            if !env.storage().persistent().has(&history_key) {
                let snapshot = CommitmentSnapshot {
                    commitment: commitment.clone(),
                    version,
                    rotated_at: env.ledger().timestamp(),
                };
                env.storage().persistent().set(&history_key, &snapshot);
                break;
            }
            idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Env, IntoVal, Symbol, TryIntoVal};

    fn setup_with_admin() -> (Env, soroban_sdk::Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        (env, contract_id, admin)
    }

    #[test]
    fn test_store_commitment() {
        let (env, contract_id, admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let _admin = admin;

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[42u8; 32]);

        let result = client.store_commitment(&employee, &commitment);

        assert_eq!(result.commitment, commitment);
        assert_eq!(result.version, 1);

        let events = env.events().all();
        assert_eq!(events.len(), 1);
        let event = events.get(0).unwrap();
        assert_eq!(event.1.len(), 2);
        let sym0: Symbol = event.1.get(0).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(sym0, Symbol::new(&env, "CommitmentUpdated"));
        let addr0: Address = event.1.get(1).unwrap().try_into_val(&env.clone()).unwrap();
        assert_eq!(addr0, employee);
    }

    #[test]
    fn test_update_commitment() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = BytesN::from_array(&env, &[1u8; 32]);
        let updated = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &initial);
        let before = env.events().all().len();
        let result = client.update_commitment(&employee, &updated);
        let after = env.events().all().len();
        assert_eq!(after, before + 1);

        assert_eq!(result.commitment, updated);
        assert_eq!(result.version, 2);
    }

    // ── Issue #242: payroll commitment uniqueness enforcement ────────────────

    /// The same commitment value must not be assignable to two different
    /// employees — reuse would weaken privacy assumptions (two employees
    /// appearing to share the same salary + blinding factor) and confuse
    /// reconciliation.
    #[test]
    #[should_panic(expected = "Commitment already in use")]
    fn test_duplicate_commitment_rejected_for_different_employee() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee_a = Address::generate(&env);
        let employee_b = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[7u8; 32]);

        client.store_commitment(&employee_a, &commitment);
        client.store_commitment(&employee_b, &commitment);
    }

    /// Rotating or updating a commitment to a value already bound to another
    /// employee must be rejected the same way as `store_commitment`.
    #[test]
    #[should_panic(expected = "Commitment already in use")]
    fn test_update_commitment_rejects_value_already_used_elsewhere() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee_a = Address::generate(&env);
        let employee_b = Address::generate(&env);
        let commitment_a = BytesN::from_array(&env, &[8u8; 32]);
        let commitment_b = BytesN::from_array(&env, &[9u8; 32]);

        client.store_commitment(&employee_a, &commitment_a);
        client.store_commitment(&employee_b, &commitment_b);

        // Attempt to rotate employee B onto employee A's active commitment.
        client.update_commitment(&employee_b, &commitment_a);
    }

    #[test]
    fn test_remove_payroll_operator_emits_event() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        // Set operator first
        client.set_payroll_operator(&operator);

        let before = env.events().all().len();
        // Remove the operator
        client.remove_payroll_operator();
        let events = env.events().all();
        assert_eq!(events.len(), before + 1);

        // Find an event whose topics/data include our removal symbol and operator
        let mut found_symbol = false;
        let mut found_operator = false;
        for ev in events.iter() {
            for i in 0..ev.1.len() {
                if let Ok(s) = ev.1.get(i).unwrap().try_into_val::<Symbol>(&env.clone()) {
                    if s == Symbol::new(&env, "PayrollOperatorRemoved") {
                        found_symbol = true;
                    }
                }
                if let Ok(a) = ev.1.get(i).unwrap().try_into_val::<Address>(&env.clone()) {
                    if a == operator {
                        found_operator = true;
                    }
                }
            }
        }
        assert!(found_symbol, "PayrollOperatorRemoved event not emitted");
        assert!(
            found_operator,
            "Removed operator address not present in event data"
        );
    }

    /// A commitment value that was rotated out (archived) can never be
    /// reused, even by a brand-new employee — it must remain retired for
    /// the lifetime of the contract (issue #242).
    #[test]
    #[should_panic(expected = "Commitment already in use")]
    fn test_archived_commitment_cannot_be_reused() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let new_employee = Address::generate(&env);
        let old_commitment = BytesN::from_array(&env, &[10u8; 32]);
        let new_commitment = BytesN::from_array(&env, &[11u8; 32]);

        client.store_commitment(&employee, &old_commitment);
        client.rotate_commitment(&employee, &new_commitment);

        // old_commitment is now archived/revoked but must remain retired.
        client.store_commitment(&new_employee, &old_commitment);
    }

    #[test]
    fn test_nullifier() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = BytesN::from_array(&env, &[99u8; 32]);

        assert!(!client.is_nullifier_used(&nullifier));

        client.record_nullifier(&nullifier);

        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    #[should_panic(expected = "Nullifier already used")]
    fn test_double_nullifier_fails() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let nullifier = BytesN::from_array(&env, &[99u8; 32]);

        client.record_nullifier(&nullifier);
        client.record_nullifier(&nullifier);
    }

    #[test]
    fn test_rotate_commitment_archives_and_revokes() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let old_cmt = BytesN::from_array(&env, &[1u8; 32]);
        let new_cmt = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &old_cmt);
        let rotated = client.rotate_commitment(&employee, &new_cmt);

        assert_eq!(rotated.commitment, new_cmt);
        assert!(!rotated.revoked);

        let history = client.get_commitment_history(&employee);
        assert!(!history.is_empty());
    }

    #[test]
    fn test_rotated_commitment_not_active() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let old_cmt = BytesN::from_array(&env, &[1u8; 32]);
        let new_cmt = BytesN::from_array(&env, &[2u8; 32]);

        client.store_commitment(&employee, &old_cmt);
        assert!(client.is_commitment_active(&employee));

        client.rotate_commitment(&employee, &new_cmt);
        assert!(client.is_commitment_active(&employee));
    }

    #[test]
    fn test_multiple_sequential_rotations() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let cmt1 = BytesN::from_array(&env, &[1u8; 32]);
        let cmt2 = BytesN::from_array(&env, &[2u8; 32]);
        let cmt3 = BytesN::from_array(&env, &[3u8; 32]);

        client.store_commitment(&employee, &cmt1);
        client.rotate_commitment(&employee, &cmt2);
        client.rotate_commitment(&employee, &cmt3);

        let current = client.get_commitment(&employee);
        assert_eq!(current.commitment, cmt3);
        assert!(!current.revoked);

        let history = client.get_commitment_history(&employee);
        assert!(history.len() >= 2);
    }

    #[test]
    fn test_payroll_operator_can_record_nullifier() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let operator = Address::generate(&env);
        client.set_payroll_operator(&operator);

        let nullifier = BytesN::from_array(&env, &[55u8; 32]);
        client.record_nullifier(&nullifier);
        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_store_commitment_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        // No mock_auths â€” store_commitment should require admin auth and panic
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[99u8; 32]);
        client.store_commitment(&employee, &commitment);
    }

    // â”€â”€ Issue #171: admin / payroll-operator role-separation tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Role separation: a delegated payroll operator may record nullifiers
    /// but must not be able to perform admin-only writes such as storing a
    /// new salary commitment.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_payroll_operator_cannot_store_commitment() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        let operator = Address::generate(&env);
        client.set_payroll_operator(&operator);

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[1u8; 32]);

        // Narrow auth to exactly the operator signing this call â€” the
        // operator role must not satisfy the admin-only guard.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &operator,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "store_commitment",
                args: (employee.clone(), commitment.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.store_commitment(&employee, &commitment);
    }

    /// Once a payroll operator is delegated, `record_nullifier` only
    /// accepts the operator's own signature (see `require_admin_or_operator`)
    /// â€” the admin who delegated the role can no longer authorize this call
    /// directly. This is a real, non-obvious role-separation property worth
    /// locking in: delegating the payroll-operator role *transfers* this
    /// privilege rather than merely adding a second authorized signer.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_admin_cannot_record_nullifier_once_operator_delegated() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        let operator = Address::generate(&env);
        client.set_payroll_operator(&operator);

        let nullifier = BytesN::from_array(&env, &[2u8; 32]);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "record_nullifier",
                args: (nullifier.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.record_nullifier(&nullifier);
    }

    // â”€â”€ Issue #178: commitment update restrictions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_lock_commitment_updates_prevents_update() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = BytesN::from_array(&env, &[10u8; 32]);
        let replacement = BytesN::from_array(&env, &[20u8; 32]);

        client.store_commitment(&employee, &initial);
        client.lock_commitment_updates(&employee);

        let result = client.try_update_commitment(&employee, &replacement);
        assert!(result.is_err(), "Locked commitment must reject update");
    }

    #[test]
    fn test_lock_commitment_updates_prevents_rotate() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = BytesN::from_array(&env, &[11u8; 32]);
        let replacement = BytesN::from_array(&env, &[21u8; 32]);

        client.store_commitment(&employee, &initial);
        client.lock_commitment_updates(&employee);

        let result = client.try_rotate_commitment(&employee, &replacement);
        assert!(result.is_err(), "Locked commitment must reject rotation");
    }

    #[test]
    fn test_unlock_commitment_allows_update_after_lock() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let initial = BytesN::from_array(&env, &[12u8; 32]);
        let replacement = BytesN::from_array(&env, &[22u8; 32]);

        client.store_commitment(&employee, &initial);
        client.lock_commitment_updates(&employee);
        client.unlock_commitment_updates(&employee);

        let result = client.update_commitment(&employee, &replacement);
        assert_eq!(result.commitment, replacement);
        assert_eq!(result.version, 2);
    }

    #[test]
    fn test_is_commitment_locked_returns_correct_state() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[13u8; 32]);
        client.store_commitment(&employee, &commitment);

        assert!(!client.is_commitment_locked(&employee));

        client.lock_commitment_updates(&employee);
        assert!(client.is_commitment_locked(&employee));

        client.unlock_commitment_updates(&employee);
        assert!(!client.is_commitment_locked(&employee));
    }

    #[test]
    fn test_lock_commitment_twice_panics() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[14u8; 32]);
        client.store_commitment(&employee, &commitment);
        client.lock_commitment_updates(&employee);

        let result = client.try_lock_commitment_updates(&employee);
        assert!(result.is_err(), "Double lock must fail");
    }

    #[test]
    fn test_unlock_without_lock_panics() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let result = client.try_unlock_commitment_updates(&employee);
        assert!(result.is_err(), "Unlock without lock must fail");
    }

    #[test]
    fn test_store_commitment_not_blocked_by_lock() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let existing_emp = Address::generate(&env);
        let new_emp = Address::generate(&env);
        let cmt = BytesN::from_array(&env, &[15u8; 32]);
        let other_cmt = BytesN::from_array(&env, &[16u8; 32]);

        client.store_commitment(&existing_emp, &cmt);
        client.lock_commitment_updates(&existing_emp);

        // A new employee should still be able to get a (distinct) commitment stored
        let result = client.store_commitment(&new_emp, &other_cmt);
        assert_eq!(result.version, 1);
        assert_eq!(result.commitment, other_cmt);
    }

    /// A stranger who is neither the admin nor the delegated operator must
    /// not be able to record a nullifier once an operator has been set.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_stranger_cannot_record_nullifier_when_operator_set() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        let operator = Address::generate(&env);
        client.set_payroll_operator(&operator);

        let stranger = Address::generate(&env);
        let nullifier = BytesN::from_array(&env, &[3u8; 32]);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &stranger,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "record_nullifier",
                args: (nullifier.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.record_nullifier(&nullifier);
    }

    // ── Issue #190: treasury / auditor role-separation tests ────────────
    /// A treasury-role address (holds company funds per `payroll_registry`,
    /// see `CompanyInfo.treasury`) has no admin authority in this contract.
    /// Treasury never interacts with `salary_commitment` at all — it must
    /// not be able to write a salary commitment just because it happens to
    /// be a known, funded address in the system.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_treasury_role_cannot_store_commitment() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        // Represents the company's treasury address (as registered via
        // `payroll_registry::register_company(admin, treasury)`).
        let treasury = Address::generate(&env);
        let employee = Address::generate(&env);
        let commitment = BytesN::from_array(&env, &[3u8; 32]);
        // Narrow auth to exactly the treasury address signing this call —
        // the treasury role must not satisfy the admin-only guard.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &treasury,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "store_commitment",
                args: (employee.clone(), commitment.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.store_commitment(&employee, &commitment);
    }
    /// A treasury-role address must not be able to delegate the
    /// payroll-operator role — that is an admin-only responsibility, and
    /// treasury has no write access to this contract's role assignments.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_treasury_role_cannot_set_payroll_operator() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        let treasury = Address::generate(&env);
        let operator = Address::generate(&env);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &treasury,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_payroll_operator",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_payroll_operator(&operator);
    }
    /// An auditor-role address (view-only access via `audit_module`) must
    /// not be able to record payment nullifiers — that is a payroll
    /// execution privilege, and read access to audit data must never imply
    /// write access to payroll execution state.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_auditor_role_cannot_record_nullifier() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        // Represents an address holding a valid audit_module view key —
        // read access only, never a payroll-execution role in this contract.
        let auditor = Address::generate(&env);
        let nullifier = BytesN::from_array(&env, &[4u8; 32]);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &auditor,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "record_nullifier",
                args: (nullifier.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.record_nullifier(&nullifier);
    }
    /// An auditor-role address must not be able to delegate the
    /// payroll-operator role — audit access is strictly read-only and must
    /// never grant the ability to assign write-capable roles.
    #[test]
    #[should_panic(expected = "authorized")]
    fn test_auditor_role_cannot_set_payroll_operator() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);
        let auditor = Address::generate(&env);
        let operator = Address::generate(&env);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &auditor,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_payroll_operator",
                args: (operator.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_payroll_operator(&operator);
    }

    // ── Issue #520: commitment rotation controls ─────────────────────────────

    /// Main path: a commitment that was approved (locked) by a settled payroll
    /// run can be rotated in a single admin call, without dropping the lock and
    /// without invalidating the settled record. The settled record refers to the
    /// commitment value that was active when payroll executed, so that value
    /// must remain in the rotation history and permanently reserved (#242).
    #[test]
    fn test_rotate_approved_commitment_keeps_lock_and_history() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let approved = BytesN::from_array(&env, &[31u8; 32]);
        let replacement = BytesN::from_array(&env, &[32u8; 32]);

        client.store_commitment(&employee, &approved);
        // Payroll execution locks the commitment (#178) — this is the
        // "approved payroll commitment" case.
        client.lock_commitment_updates(&employee);
        assert!(client.can_rotate_approved_commitment(&employee));

        let rotated = client.rotate_approved_commitment(&employee, &replacement);

        // The new commitment is active and the version advanced monotonically.
        assert_eq!(rotated.commitment, replacement);
        assert!(!rotated.revoked);
        assert_eq!(rotated.version, 2);
        assert!(client.is_commitment_active(&employee));

        // The settled record stays attributable: the approved value is retained
        // in history and is still the value the payroll run was paid against.
        let history = client.get_commitment_history(&employee);
        assert_eq!(history.len(), 1);
        assert_eq!(history.get(0).unwrap().commitment, approved);
        assert_eq!(history.get(0).unwrap().version, 1);

        // The approved binding is still enforced after the rotation.
        assert!(client.is_commitment_locked(&employee));
        assert!(client
            .try_update_commitment(&employee, &replacement)
            .is_err());
    }

    /// Edge case: a no-op rotation is rejected with an actionable message and
    /// leaves the approved commitment completely untouched. Without the
    /// explicit guard this would surface as the misleading "already in use"
    /// uniqueness error, because the employee's own current value is, by
    /// construction, already reserved.
    #[test]
    fn test_rotate_approved_commitment_rejects_noop() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let approved = BytesN::from_array(&env, &[33u8; 32]);

        client.store_commitment(&employee, &approved);
        client.lock_commitment_updates(&employee);

        let result = client.try_rotate_approved_commitment(&employee, &approved);
        assert!(result.is_err(), "No-op rotation must be rejected");

        // State is unchanged: still the approved value, still version 1, still
        // locked, and no history entry was written.
        let current = client.get_commitment(&employee);
        assert_eq!(current.commitment, approved);
        assert_eq!(current.version, 1);
        assert!(!current.revoked);
        assert!(client.is_commitment_locked(&employee));
        assert!(client.get_commitment_history(&employee).is_empty());
    }

    /// An unlocked commitment must keep using `rotate_commitment`; the
    /// approved-rotation path is rejected so the audit trail stays
    /// unambiguous.
    #[test]
    #[should_panic(expected = "Commitment is not locked")]
    fn test_rotate_approved_commitment_rejects_unlocked() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let current = BytesN::from_array(&env, &[34u8; 32]);
        let replacement = BytesN::from_array(&env, &[35u8; 32]);

        client.store_commitment(&employee, &current);
        assert!(!client.can_rotate_approved_commitment(&employee));

        client.rotate_approved_commitment(&employee, &replacement);
    }

    /// Rotating an approved commitment onto a value that is already bound to
    /// another employee is still rejected (#242) — the settled record for that
    /// other employee must keep its own value.
    #[test]
    #[should_panic(expected = "Commitment already in use")]
    fn test_rotate_approved_commitment_rejects_value_in_use_elsewhere() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee_a = Address::generate(&env);
        let employee_b = Address::generate(&env);
        let commitment_a = BytesN::from_array(&env, &[36u8; 32]);
        let commitment_b = BytesN::from_array(&env, &[37u8; 32]);

        client.store_commitment(&employee_a, &commitment_a);
        client.store_commitment(&employee_b, &commitment_b);
        client.lock_commitment_updates(&employee_a);

        client.rotate_approved_commitment(&employee_a, &commitment_b);
    }

    /// `can_rotate_approved_commitment` is false for an unknown employee and
    /// returns no commitment values (privacy-safe read-only view).
    #[test]
    fn test_can_rotate_approved_commitment_defaults_false() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        assert!(!client.can_rotate_approved_commitment(&employee));

        let commitment = BytesN::from_array(&env, &[38u8; 32]);
        client.store_commitment(&employee, &commitment);
        assert!(!client.can_rotate_approved_commitment(&employee));
        client.lock_commitment_updates(&employee);
        assert!(client.can_rotate_approved_commitment(&employee));
    }

    /// Rotation keeps the commitment version monotonic across rotation and
    /// update, so revision ordering survives a compensation change history
    /// (mirrors the UP-05 upgrade invariant).
    #[test]
    fn test_rotation_increments_version_monotonically() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        client.store_commitment(&employee, &BytesN::from_array(&env, &[39u8; 32]));
        let v1 = client.get_commitment(&employee).version;

        let rotated = client.rotate_commitment(&employee, &BytesN::from_array(&env, &[40u8; 32]));
        assert_eq!(rotated.version, v1 + 1);

        let updated = client.update_commitment(&employee, &BytesN::from_array(&env, &[41u8; 32]));
        assert_eq!(updated.version, v1 + 2);
    }

    // ── Employee Reference ID Tests ──────────────────────────────────────────

    #[test]
    fn test_set_and_get_employee_reference_id() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let reference_id = soroban_sdk::String::from_str(&env, "EMP-12345");

        assert!(client.get_employee_reference_id(&employee).is_none());
        assert!(client.get_employee_by_reference_id(&reference_id).is_none());

        client.set_employee_reference_id(&employee, &reference_id);

        assert_eq!(
            client.get_employee_reference_id(&employee).unwrap(),
            reference_id
        );
        assert_eq!(
            client.get_employee_by_reference_id(&reference_id).unwrap(),
            employee
        );
    }

    #[test]
    fn test_update_employee_reference_id() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let old_ref_id = soroban_sdk::String::from_str(&env, "EMP-OLD");
        let new_ref_id = soroban_sdk::String::from_str(&env, "EMP-NEW");

        client.set_employee_reference_id(&employee, &old_ref_id);
        assert_eq!(
            client.get_employee_by_reference_id(&old_ref_id).unwrap(),
            employee
        );

        client.set_employee_reference_id(&employee, &new_ref_id);

        assert_eq!(
            client.get_employee_reference_id(&employee).unwrap(),
            new_ref_id
        );
        assert_eq!(
            client.get_employee_by_reference_id(&new_ref_id).unwrap(),
            employee
        );

        // Old reverse mapping should be cleared
        assert!(client.get_employee_by_reference_id(&old_ref_id).is_none());
    }

    #[test]
    #[should_panic(expected = "Reference ID already assigned to another employee")]
    fn test_set_duplicate_reference_id_panics() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee1 = Address::generate(&env);
        let employee2 = Address::generate(&env);
        let reference_id = soroban_sdk::String::from_str(&env, "EMP-COLLISION");

        client.set_employee_reference_id(&employee1, &reference_id);
        client.set_employee_reference_id(&employee2, &reference_id);
    }

    #[test]
    #[should_panic(expected = "Reference ID must be 1-256 characters")]
    fn test_set_empty_reference_id_panics() {
        let (env, contract_id, _admin) = setup_with_admin();
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let employee = Address::generate(&env);
        let reference_id = soroban_sdk::String::from_str(&env, "");

        client.set_employee_reference_id(&employee, &reference_id);
    }

    #[test]
    #[should_panic(expected = "authorized")]
    fn test_unauthorized_set_reference_id_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SalaryCommitmentContract);
        let client = SalaryCommitmentContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init_commitment_admin(&admin);

        let unauthorized_user = Address::generate(&env);
        let employee = Address::generate(&env);
        let reference_id = soroban_sdk::String::from_str(&env, "EMP-999");

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &unauthorized_user,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "set_employee_reference_id",
                args: (employee.clone(), reference_id.clone()).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        client.set_employee_reference_id(&employee, &reference_id);
    }
}
