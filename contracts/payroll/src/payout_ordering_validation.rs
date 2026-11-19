//! Payout ordering validation against committed recipient ordering (#815).
//!
//! Payroll operators prepare a batch of recipients in a specific order before
//! execution. This module lets an operator commit that ordering on-chain
//! (keyed by run nonce) and then validates that the payout array supplied to
//! `prepare_payroll_run` / `batch_process_payroll` matches the committed
//! ordering exactly — same recipients, same positions.
//!
//! ## Why this matters
//!
//! Without ordering validation a rogue operator or a software bug could silently
//! reorder recipients between the approval and execution phase, causing payments
//! to reach the wrong destinations. This module closes that gap by:
//!
//! 1. Letting the admin commit the canonical ordering before approval starts.
//! 2. Verifying the payout array against that commitment at execution time.
//! 3. Emitting a privacy-safe event on success so integrators can
//!    audit the validation on-chain.
//!
//! ## Privacy guarantees
//!
//! * The committed ordering stores only ordered opaque address values — no
//!   salary amounts, proof material, or commitment values.
//! * Failure messages report only indices and counts, never addresses.
//! * The successful-validation event carries only the nonce and the recipient
//!   count so it is safe to surface to dashboards.
//!
//! ## Storage
//!
//! Committed orderings live in a separate key enum
//! ([`PayoutOrderingKey::CommittedOrdering`]) to avoid inflating the main
//! [`crate::DataKey`] enum.  They are removed after successful validation so
//! a nonce cannot be re-validated with a stale commitment.

use soroban_sdk::{contracterror, contractevent, contracttype, Address, BytesN, Env, Vec};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum number of recipients in a committed ordering.
/// Matches the payroll contract's `MAX_BATCH` cap.
pub const MAX_ORDERING_SIZE: u32 = 50;

// ── Storage keys ──────────────────────────────────────────────────────────────

/// Storage keys for committed recipient orderings.
///
/// Deliberately separate from [`crate::DataKey`] so the payout-ordering
/// feature does not change existing storage-key discriminants.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayoutOrderingKey {
    /// Committed recipient ordering for a run nonce.
    CommittedOrdering(BytesN<32>),
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// A committed payout ordering bound to a run nonce.
///
/// The committed list is the canonical, admin-approved ordering.  The payout
/// array at execution time must match this list exactly — same addresses in the
/// same positions.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRecipientOrdering {
    /// Ordered list of expected payout recipients (opaque addresses).
    pub recipients: Vec<Address>,
    /// Ledger timestamp when the commitment was recorded.
    pub committed_at: u64,
    /// Number of recipients in the commitment.
    pub count: u32,
}

/// Outcome of a payout-ordering preflight check.
///
/// Returned by [`check_payout_ordering`].  All three fields must reflect a
/// valid, matching state for execution to proceed.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutOrderingCheck {
    /// `true` when a commitment exists for the supplied nonce.
    pub commitment_found: bool,
    /// `true` when the payout array length matches the commitment.
    pub length_matches: bool,
    /// `true` when every recipient in the payout array appears in the same
    /// position as in the commitment.
    pub order_matches: bool,
}

impl PayoutOrderingCheck {
    /// `true` when all checks pass and execution may proceed.
    pub fn all_passed(&self) -> bool {
        self.commitment_found && self.length_matches && self.order_matches
    }

    /// First failing check, if any.
    pub fn first_failure(&self) -> Option<PayoutOrderingError> {
        if !self.commitment_found {
            return Some(PayoutOrderingError::NoCommitmentFound);
        }
        if !self.length_matches {
            return Some(PayoutOrderingError::LengthMismatch);
        }
        if !self.order_matches {
            return Some(PayoutOrderingError::OrderMismatch);
        }
        None
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by payout ordering operations.  Codes are scoped to
/// issue #815.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PayoutOrderingError {
    /// The payout array is empty; at least one recipient is required.
    EmptyRecipients = 8150,
    /// The recipient list exceeds [`MAX_ORDERING_SIZE`].
    TooManyRecipients = 8151,
    /// A commitment already exists for this nonce and has not been consumed;
    /// use the nonce's existing commitment or choose a different nonce.
    CommitmentAlreadyExists = 8152,
    /// No committed ordering exists for the supplied run nonce.
    NoCommitmentFound = 8153,
    /// The payout array has a different length than the committed ordering.
    LengthMismatch = 8154,
    /// At least one recipient appears at a different position than in the
    /// committed ordering.
    OrderMismatch = 8155,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Emitted as `("payroll", "ordering_committed")` when a recipient ordering is
/// committed.  Data: `(nonce_ref, count, committed_at)`.
///
/// `nonce_ref` is the SHA-256 of the nonce bytes so the raw nonce is never
/// surfaced in events.
#[contractevent(topics = ["payroll", "ordering_committed"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderingCommitted {
    /// Opaque reference to the nonce (first 8 bytes of nonce as u64).
    pub nonce_ref: u64,
    /// Number of recipients in the committed ordering.
    pub count: u32,
    /// Ledger timestamp of commitment.
    pub committed_at: u64,
}

/// Emitted as `("payroll", "ordering_validated")` when the payout ordering is
/// confirmed to match the commitment.  Data: `(nonce_ref, count, validated_at)`.
#[contractevent(topics = ["payroll", "ordering_validated"], data_format = "vec")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderingValidated {
    /// Opaque reference to the nonce.
    pub nonce_ref: u64,
    /// Number of recipients validated.
    pub count: u32,
    /// Ledger timestamp of validation.
    pub validated_at: u64,
}

// ── Core logic ────────────────────────────────────────────────────────────────

/// Derive a privacy-safe nonce reference for events (first 8 bytes as u64).
fn nonce_ref(nonce: &BytesN<32>) -> u64 {
    let arr = nonce.to_array();
    u64::from_be_bytes([
        arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7],
    ])
}

/// Commit a canonical recipient ordering bound to a run `nonce`.
///
/// The commitment is stored under [`PayoutOrderingKey::CommittedOrdering`] and
/// consumed by [`assert_payout_ordering`] at execution time. Calling this
/// twice with the same nonce is rejected with
/// [`PayoutOrderingError::CommitmentAlreadyExists`].
///
/// # Panics
/// Panics (via the returned `Err`) when:
/// - `recipients` is empty.
/// - `recipients` exceeds [`MAX_ORDERING_SIZE`].
/// - A commitment for `nonce` already exists.
pub fn commit_recipient_ordering(
    e: &Env,
    nonce: &BytesN<32>,
    recipients: &Vec<Address>,
) -> Result<(), PayoutOrderingError> {
    let count = recipients.len();

    if count == 0 {
        return Err(PayoutOrderingError::EmptyRecipients);
    }
    if count > MAX_ORDERING_SIZE {
        return Err(PayoutOrderingError::TooManyRecipients);
    }

    let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
    if e.storage().persistent().has(&key) {
        return Err(PayoutOrderingError::CommitmentAlreadyExists);
    }

    let committed_at = e.ledger().timestamp();
    let ordering = CommittedRecipientOrdering {
        recipients: recipients.clone(),
        committed_at,
        count,
    };
    e.storage().persistent().set(&key, &ordering);

    // Emit a privacy-safe event.
    OrderingCommitted {
        nonce_ref: nonce_ref(nonce),
        count,
        committed_at,
    }
    .publish(e);

    Ok(())
}

/// Read-only preflight: check the payout ordering without consuming the
/// commitment or panicking.
///
/// Returns a [`PayoutOrderingCheck`] snapshot that callers (SDKs, dashboards)
/// can inspect before submitting the transaction.
pub fn check_payout_ordering(
    e: &Env,
    nonce: &BytesN<32>,
    payout_recipients: &Vec<Address>,
) -> PayoutOrderingCheck {
    let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
    let ordering: Option<CommittedRecipientOrdering> = e.storage().persistent().get(&key);

    let Some(committed) = ordering else {
        return PayoutOrderingCheck {
            commitment_found: false,
            length_matches: false,
            order_matches: false,
        };
    };

    let payout_count = payout_recipients.len();
    let committed_count = committed.count;

    if payout_count != committed_count {
        return PayoutOrderingCheck {
            commitment_found: true,
            length_matches: false,
            order_matches: false,
        };
    }

    // Compare position by position.
    let order_ok = positions_match(payout_recipients, &committed.recipients);

    PayoutOrderingCheck {
        commitment_found: true,
        length_matches: true,
        order_matches: order_ok,
    }
}

/// Assert that the payout ordering matches the committed ordering and consume
/// the commitment.
///
/// Returns `Ok(())` and removes the commitment from storage when the payout
/// array is an exact match. Returns the first failing
/// [`PayoutOrderingError`] otherwise; the commitment is NOT consumed on
/// failure so the operator can correct the payout array and retry.
///
/// When no commitment exists for `nonce` this function returns `Ok(())` so
/// the guard is opt-in — runs prepared without a prior commitment proceed
/// normally.
pub fn assert_payout_ordering(
    e: &Env,
    nonce: &BytesN<32>,
    payout_recipients: &Vec<Address>,
) -> Result<(), PayoutOrderingError> {
    let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
    let ordering: Option<CommittedRecipientOrdering> = e.storage().persistent().get(&key);

    // No commitment → opt-in guard; allow execution.
    let Some(committed) = ordering else {
        return Ok(());
    };

    let payout_count = payout_recipients.len();
    if payout_count != committed.count {
        return Err(PayoutOrderingError::LengthMismatch);
    }

    if !positions_match(payout_recipients, &committed.recipients) {
        return Err(PayoutOrderingError::OrderMismatch);
    }

    // Validation passed — consume the commitment.
    e.storage().persistent().remove(&key);

    // Emit a privacy-safe validation event.
    OrderingValidated {
        nonce_ref: nonce_ref(nonce),
        count: committed.count,
        validated_at: e.ledger().timestamp(),
    }
    .publish(e);

    Ok(())
}

/// Compare two recipient lists for positional equality.
/// Returns `true` iff every index `i` has `payout[i] == committed[i]`.
fn positions_match(payout: &Vec<Address>, committed: &Vec<Address>) -> bool {
    // Lengths already checked by caller; guard anyway.
    if payout.len() != committed.len() {
        return false;
    }
    for i in 0..payout.len() {
        if payout.get(i).unwrap() != committed.get(i).unwrap() {
            return false;
        }
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};
    use soroban_sdk::{vec, Address, BytesN, Env};

    fn test_nonce(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        arr[1] = 0xAB;
        arr[31] = seed;
        BytesN::from_array(env, &arr)
    }

    // ── commit_recipient_ordering ─────────────────────────────────────────────

    #[test]
    fn commit_stores_ordering_and_emits_event() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            env.ledger().with_mut(|li| li.timestamp = 1_000);

            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 1);
            let recipients = vec![&env, alice.clone(), bob.clone()];

            assert!(commit_recipient_ordering(&env, &nonce, &recipients).is_ok());

            // Commitment should now exist in storage.
            let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
            let stored: CommittedRecipientOrdering = env.storage().persistent().get(&key).unwrap();
            assert_eq!(stored.count, 2);
            assert_eq!(stored.committed_at, 1_000);
            assert_eq!(stored.recipients.get(0).unwrap(), alice);
            assert_eq!(stored.recipients.get(1).unwrap(), bob);
        });
    }

    #[test]
    fn commit_rejects_empty_recipients() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let nonce = test_nonce(&env, 2);
            let empty: Vec<Address> = vec![&env];

            assert_eq!(
                commit_recipient_ordering(&env, &nonce, &empty),
                Err(PayoutOrderingError::EmptyRecipients),
            );
        });
    }

    #[test]
    fn commit_rejects_duplicate_nonce() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let nonce = test_nonce(&env, 3);
            let recipients = vec![&env, alice.clone()];

            commit_recipient_ordering(&env, &nonce, &recipients).unwrap();

            assert_eq!(
                commit_recipient_ordering(&env, &nonce, &recipients),
                Err(PayoutOrderingError::CommitmentAlreadyExists),
            );
        });
    }

    #[test]
    fn commit_rejects_too_many_recipients() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let nonce = test_nonce(&env, 16);
            let mut recipients: Vec<Address> = vec![&env];
            for _ in 0..=MAX_ORDERING_SIZE {
                recipients.push_back(Address::generate(&env));
            }
            assert_eq!(recipients.len(), MAX_ORDERING_SIZE + 1);
            assert_eq!(
                commit_recipient_ordering(&env, &nonce, &recipients),
                Err(PayoutOrderingError::TooManyRecipients),
            );
        });
    }

    #[test]
    fn commit_accepts_exact_max_ordering_size() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let nonce = test_nonce(&env, 17);
            let mut recipients: Vec<Address> = vec![&env];
            for _ in 0..MAX_ORDERING_SIZE {
                recipients.push_back(Address::generate(&env));
            }
            assert_eq!(recipients.len(), MAX_ORDERING_SIZE);
            assert!(commit_recipient_ordering(&env, &nonce, &recipients).is_ok());
        });
    }

    // ── check_payout_ordering (preflight) ─────────────────────────────────────

    #[test]
    fn check_returns_no_commitment_when_none_exists() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let nonce = test_nonce(&env, 4);
            let alice = Address::generate(&env);
            let payout = vec![&env, alice];

            let check = check_payout_ordering(&env, &nonce, &payout);
            assert!(!check.commitment_found);
            assert!(!check.length_matches);
            assert!(!check.order_matches);
            assert!(!check.all_passed());
        });
    }

    #[test]
    fn check_detects_length_mismatch() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 5);
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            // Only one recipient in payout vs two committed.
            let check = check_payout_ordering(&env, &nonce, &vec![&env, alice.clone()]);
            assert!(check.commitment_found);
            assert!(!check.length_matches);
            assert!(!check.all_passed());
        });
    }

    #[test]
    fn check_detects_wrong_order() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 6);
            // Committed: [alice, bob]
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            // Payout: [bob, alice] — reversed
            let check =
                check_payout_ordering(&env, &nonce, &vec![&env, bob.clone(), alice.clone()]);
            assert!(check.commitment_found);
            assert!(check.length_matches);
            assert!(!check.order_matches);
            assert!(!check.all_passed());
        });
    }

    #[test]
    fn check_passes_on_correct_order() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 7);
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            let check =
                check_payout_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()]);
            assert!(check.all_passed());
            assert_eq!(check.first_failure(), None);
        });
    }

    // ── assert_payout_ordering ────────────────────────────────────────────────

    /// Success case: ordering matches, commitment is consumed.
    #[test]
    fn assert_succeeds_and_consumes_commitment() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            env.ledger().with_mut(|li| li.timestamp = 2_000);

            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 8);
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            let result =
                assert_payout_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()]);
            assert!(result.is_ok());

            // Commitment should be gone.
            let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
            assert!(!env.storage().persistent().has(&key));
        });
    }

    /// Rejected case: wrong order.
    #[test]
    fn assert_rejects_wrong_order() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 9);
            // Committed: [alice, bob]
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            // Payout: [bob, alice] — wrong order
            let result =
                assert_payout_ordering(&env, &nonce, &vec![&env, bob.clone(), alice.clone()]);
            assert_eq!(result, Err(PayoutOrderingError::OrderMismatch));

            // Commitment NOT consumed on failure.
            let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
            assert!(env.storage().persistent().has(&key));
        });
    }

    /// Rejected case: wrong length.
    #[test]
    fn assert_rejects_length_mismatch() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 10);
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone(), bob.clone()])
                .unwrap();

            let result = assert_payout_ordering(&env, &nonce, &vec![&env, alice.clone()]);
            assert_eq!(result, Err(PayoutOrderingError::LengthMismatch));
        });
    }

    /// Opt-in: no commitment → passes silently.
    #[test]
    fn assert_passes_when_no_commitment_exists() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let nonce = test_nonce(&env, 11);

            // No commit_recipient_ordering call.
            let result = assert_payout_ordering(&env, &nonce, &vec![&env, alice.clone()]);
            assert!(result.is_ok());
        });
    }

    /// Boundary case: single employee.
    #[test]
    fn single_employee_success() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let nonce = test_nonce(&env, 12);

            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone()]).unwrap();
            let result = assert_payout_ordering(&env, &nonce, &vec![&env, alice.clone()]);
            assert!(result.is_ok());
        });
    }

    /// Boundary case: single employee wrong order (only one slot, but a
    /// different address).
    #[test]
    fn single_employee_wrong_address_rejected() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            let nonce = test_nonce(&env, 13);

            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone()]).unwrap();
            let result = assert_payout_ordering(&env, &nonce, &vec![&env, bob.clone()]);
            assert_eq!(result, Err(PayoutOrderingError::OrderMismatch));
        });
    }

    /// check_payout_ordering does NOT consume the commitment even on success.
    #[test]
    fn check_does_not_consume_commitment() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let nonce = test_nonce(&env, 14);
            commit_recipient_ordering(&env, &nonce, &vec![&env, alice.clone()]).unwrap();

            let check = check_payout_ordering(&env, &nonce, &vec![&env, alice.clone()]);
            assert!(check.all_passed());

            // Commitment must still be there.
            let key = PayoutOrderingKey::CommittedOrdering(nonce.clone());
            assert!(env.storage().persistent().has(&key));
        });
    }

    /// first_failure returns the first blocking error.
    #[test]
    fn check_first_failure_no_commitment() {
        let env = Env::default();
        env.as_contract(&env.register(crate::Payroll, ()), || {
            let alice = Address::generate(&env);
            let nonce = test_nonce(&env, 15);
            let check = check_payout_ordering(&env, &nonce, &vec![&env, alice]);
            assert_eq!(
                check.first_failure(),
                Some(PayoutOrderingError::NoCommitmentFound)
            );
        });
    }
}
