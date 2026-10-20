//! Beneficiary verification status preflight checks (#786).
//! Verification evidence stays off-chain; only its opaque reference is used.

use soroban_sdk::{contracterror, contracttype, Address, BytesN, Env};

/// An authoritative verifier's decision about a beneficiary.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeneficiaryVerificationStatus {
    Pending,
    Verified,
    Rejected,
    Revoked,
}

/// Minimal verification metadata, with no identity documents or personal data.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeneficiaryVerification {
    pub beneficiary: Address,
    pub status: BeneficiaryVerificationStatus,
    pub evidence_ref: BytesN<32>,
    pub verified_at: u64,
    /// Zero means no expiry; otherwise the expiry is exclusive.
    pub expires_at: u64,
}

/// Stable status-check errors, scoped to issue #786.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BeneficiaryVerificationError {
    MissingVerification = 7860,
    BeneficiaryMismatch = 7861,
    Pending = 7862,
    Rejected = 7863,
    Revoked = 7864,
    MissingEvidence = 7865,
    InvalidVerificationTime = 7866,
    Expired = 7867,
}

/// Read-only contract interface for beneficiary verification preflight.
pub trait BeneficiaryStatusValidation {
    /// Check an authoritative record; does not authenticate its issuer.
    fn check_beneficiary_status(
        env: Env,
        beneficiary: Address,
        verification: Option<BeneficiaryVerification>,
    ) -> Result<(), BeneficiaryVerificationError>;
}

/// Require a matching, verified, non-expired record at the current timestamp.
/// The caller must authenticate the evidence and its issuer separately.
pub fn check_beneficiary_status(
    env: &Env,
    beneficiary: &Address,
    verification: Option<&BeneficiaryVerification>,
) -> Result<(), BeneficiaryVerificationError> {
    let record = verification.ok_or(BeneficiaryVerificationError::MissingVerification)?;
    if record.beneficiary != *beneficiary {
        return Err(BeneficiaryVerificationError::BeneficiaryMismatch);
    }
    match record.status {
        BeneficiaryVerificationStatus::Pending => {
            return Err(BeneficiaryVerificationError::Pending)
        }
        BeneficiaryVerificationStatus::Rejected => {
            return Err(BeneficiaryVerificationError::Rejected)
        }
        BeneficiaryVerificationStatus::Revoked => {
            return Err(BeneficiaryVerificationError::Revoked)
        }
        BeneficiaryVerificationStatus::Verified => {}
    }
    if record.evidence_ref.to_array() == [0; 32] {
        return Err(BeneficiaryVerificationError::MissingEvidence);
    }
    let now = env.ledger().timestamp();
    if record.verified_at == 0
        || record.verified_at > now
        || (record.expires_at != 0 && record.expires_at <= record.verified_at)
    {
        return Err(BeneficiaryVerificationError::InvalidVerificationTime);
    }
    if record.expires_at != 0 && now >= record.expires_at {
        return Err(BeneficiaryVerificationError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger};

    fn record(env: &Env) -> BeneficiaryVerification {
        BeneficiaryVerification {
            beneficiary: Address::generate(env),
            status: BeneficiaryVerificationStatus::Verified,
            evidence_ref: BytesN::from_array(env, &[1; 32]),
            verified_at: 100,
            expires_at: 200,
        }
    }
    #[test]
    fn verified_record_accepts_exact_start_and_open_ended_expiry() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 100);
        let mut record = record(&env);
        assert_eq!(
            check_beneficiary_status(&env, &record.beneficiary, Some(&record)),
            Ok(())
        );
        record.expires_at = 0;
        env.ledger().with_mut(|li| li.timestamp = u64::MAX);
        assert_eq!(
            check_beneficiary_status(&env, &record.beneficiary, Some(&record)),
            Ok(())
        );
    }
    #[test]
    fn rejects_missing_or_mismatched_beneficiaries() {
        let env = Env::default();
        let record = record(&env);
        assert_eq!(
            check_beneficiary_status(&env, &record.beneficiary, None),
            Err(BeneficiaryVerificationError::MissingVerification)
        );
        assert_eq!(
            check_beneficiary_status(&env, &Address::generate(&env), Some(&record)),
            Err(BeneficiaryVerificationError::BeneficiaryMismatch)
        );
    }
    #[test]
    fn rejects_pending_rejected_and_revoked_statuses() {
        let env = Env::default();
        let mut record = record(&env);
        for (status, error) in [
            (
                BeneficiaryVerificationStatus::Pending,
                BeneficiaryVerificationError::Pending,
            ),
            (
                BeneficiaryVerificationStatus::Rejected,
                BeneficiaryVerificationError::Rejected,
            ),
            (
                BeneficiaryVerificationStatus::Revoked,
                BeneficiaryVerificationError::Revoked,
            ),
        ] {
            record.status = status;
            assert_eq!(
                check_beneficiary_status(&env, &record.beneficiary, Some(&record)),
                Err(error)
            );
        }
    }
    #[test]
    fn expiry_is_exclusive_and_does_not_mutate_the_record() {
        let env = Env::default();
        let record = record(&env);
        let before = record.clone();
        env.ledger().with_mut(|li| li.timestamp = 199);
        assert_eq!(
            check_beneficiary_status(&env, &record.beneficiary, Some(&record)),
            Ok(())
        );
        env.ledger().with_mut(|li| li.timestamp = 200);
        assert_eq!(
            check_beneficiary_status(&env, &record.beneficiary, Some(&record)),
            Err(BeneficiaryVerificationError::Expired)
        );
        assert_eq!(record, before);
    }
    #[test]
    fn rejects_unbound_evidence_and_invalid_verification_times() {
        let env = Env::default();
        env.ledger().with_mut(|li| li.timestamp = 150);
        let original = record(&env);
        let mut invalid = original.clone();
        invalid.evidence_ref = BytesN::from_array(&env, &[0; 32]);
        assert_eq!(
            check_beneficiary_status(&env, &invalid.beneficiary, Some(&invalid)),
            Err(BeneficiaryVerificationError::MissingEvidence)
        );
        for verified_at in [0, 151] {
            let mut invalid = original.clone();
            invalid.verified_at = verified_at;
            assert_eq!(
                check_beneficiary_status(&env, &invalid.beneficiary, Some(&invalid)),
                Err(BeneficiaryVerificationError::InvalidVerificationTime)
            );
        }
        let mut invalid = original;
        invalid.expires_at = invalid.verified_at;
        assert_eq!(
            check_beneficiary_status(&env, &invalid.beneficiary, Some(&invalid)),
            Err(BeneficiaryVerificationError::InvalidVerificationTime)
        );
    }
}
