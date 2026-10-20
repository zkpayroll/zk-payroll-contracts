//! Validate exported configuration-ledger pages against canonical records (#785).

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracterror, contracttype, Bytes, BytesN, Env, Vec};

use crate::ConfigLedgerEntry;

/// Same bound as `get_config_ledger`.
pub const MAX_LEDGER_EXPORT_ENTRIES: u32 = 50;

/// A validated, complete inclusive revision range and its deterministic digest.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerExportValidation {
    pub first_revision: u64,
    pub last_revision: u64,
    pub entry_count: u32,
    pub integrity_hash: BytesN<32>,
}

/// Stable validation errors, scoped to issue #785.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LedgerExportError {
    InvalidRange = 7850,
    TooManyEntries = 7851,
    EntryCountMismatch = 7852,
    NonConsecutiveRevision = 7853,
    CanonicalEntryMissing = 7854,
    EntryMismatch = 7855,
}

/// Read-only contract interface for validating exported ledger pages.
pub trait LedgerExportVerification {
    /// Compare a complete revision range with records read from contract storage.
    fn validate_ledger_export(
        env: Env,
        first_revision: u64,
        last_revision: u64,
        entries: Vec<ConfigLedgerEntry>,
    ) -> Result<LedgerExportValidation, LedgerExportError>;
}

/// Validate inclusive range bounds before any storage reads or iteration.
pub fn ledger_export_count(first: u64, last: u64) -> Result<u32, LedgerExportError> {
    if first == 0 || last < first {
        return Err(LedgerExportError::InvalidRange);
    }
    let difference = last - first;
    if difference >= u64::from(MAX_LEDGER_EXPORT_ENTRIES) {
        return Err(LedgerExportError::TooManyEntries);
    }
    Ok(difference as u32 + 1)
}

/// Compare an export to the exact canonical page, including every entry field.
/// `canonical` must be read from storage, not accepted from an untrusted exporter.
pub fn validate_ledger_export(
    env: &Env,
    first_revision: u64,
    last_revision: u64,
    entries: &Vec<ConfigLedgerEntry>,
    canonical: &Vec<ConfigLedgerEntry>,
) -> Result<LedgerExportValidation, LedgerExportError> {
    let count = ledger_export_count(first_revision, last_revision)?;
    if entries.len() != count {
        return Err(LedgerExportError::EntryCountMismatch);
    }
    if canonical.len() != count {
        return Err(LedgerExportError::CanonicalEntryMissing);
    }
    for i in 0..count {
        let entry = entries
            .get(i)
            .ok_or(LedgerExportError::EntryCountMismatch)?;
        let stored = canonical
            .get(i)
            .ok_or(LedgerExportError::CanonicalEntryMissing)?;
        let revision = first_revision + u64::from(i); // <= validated last_revision
        if entry.revision != revision {
            return Err(LedgerExportError::NonConsecutiveRevision);
        }
        if stored.revision != revision {
            return Err(LedgerExportError::CanonicalEntryMissing);
        }
        if entry != stored {
            return Err(LedgerExportError::EntryMismatch);
        }
    }
    let mut payload = Bytes::from_slice(env, b"zkpayroll_ledger_export_v1");
    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&first_revision.to_xdr(env));
    payload.append(&last_revision.to_xdr(env));
    payload.append(&entries.clone().to_xdr(env));
    Ok(LedgerExportValidation {
        first_revision,
        last_revision,
        entry_count: count,
        integrity_hash: env.crypto().sha256(&payload).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Address, Symbol};

    fn entry(env: &Env, revision: u64) -> ConfigLedgerEntry {
        ConfigLedgerEntry {
            key: Symbol::new(env, "capacity_limits"),
            actor: Address::generate(env),
            subject_ref: BytesN::from_array(env, &[1; 32]),
            previous_ref: BytesN::from_array(env, &[2; 32]),
            new_ref: BytesN::from_array(env, &[3; 32]),
            revision,
            ledger_sequence: 100,
            timestamp: 1000,
        }
    }
    #[test]
    fn authentic_page_has_a_stable_contract_bound_hash() {
        let env = Env::default();
        let contract = env.register(crate::Payroll, ());
        let page = vec![&env, entry(&env, 1), entry(&env, 2)];
        let first = env.as_contract(&contract, || {
            validate_ledger_export(&env, 1, 2, &page, &page).unwrap()
        });
        let second = env.as_contract(&contract, || {
            validate_ledger_export(&env, 1, 2, &page, &page).unwrap()
        });
        assert_eq!(first, second);
        assert_eq!(first.entry_count, 2);
        assert_ne!(first.integrity_hash.to_array(), [0; 32]);
        let other = env.register(crate::Payroll, ());
        let other = env.as_contract(&other, || {
            validate_ledger_export(&env, 1, 2, &page, &page).unwrap()
        });
        assert_ne!(first.integrity_hash, other.integrity_hash);
    }
    #[test]
    fn rejects_missing_extra_duplicate_and_reordered_entries() {
        let env = Env::default();
        let first = entry(&env, 1);
        let second = entry(&env, 2);
        let page = vec![&env, first.clone(), second.clone()];
        assert_eq!(
            validate_ledger_export(&env, 1, 2, &vec![&env, first.clone()], &page),
            Err(LedgerExportError::EntryCountMismatch)
        );
        assert_eq!(
            validate_ledger_export(&env, 1, 1, &page, &page),
            Err(LedgerExportError::EntryCountMismatch)
        );
        for invalid in [
            vec![&env, first.clone(), first],
            vec![&env, second.clone(), second],
        ] {
            assert_eq!(
                validate_ledger_export(&env, 1, 2, &invalid, &page),
                Err(LedgerExportError::NonConsecutiveRevision)
            );
        }
        let reversed = vec![&env, page.get(1).unwrap(), page.get(0).unwrap()];
        assert_eq!(
            validate_ledger_export(&env, 1, 2, &reversed, &page),
            Err(LedgerExportError::NonConsecutiveRevision)
        );
    }
    #[test]
    fn detects_every_tampered_field_and_a_missing_canonical_record() {
        let env = Env::default();
        let original = entry(&env, 1);
        let canonical = vec![&env, original.clone()];
        for field in 0..7 {
            let mut changed = original.clone();
            match field {
                0 => changed.key = Symbol::new(&env, "other"),
                1 => changed.actor = Address::generate(&env),
                2 => changed.subject_ref = BytesN::from_array(&env, &[9; 32]),
                3 => changed.previous_ref = BytesN::from_array(&env, &[9; 32]),
                4 => changed.new_ref = BytesN::from_array(&env, &[9; 32]),
                5 => changed.ledger_sequence += 1,
                _ => changed.timestamp += 1,
            }
            assert_eq!(
                validate_ledger_export(&env, 1, 1, &vec![&env, changed], &canonical),
                Err(LedgerExportError::EntryMismatch)
            );
        }
        assert_eq!(
            validate_ledger_export(&env, 1, 1, &canonical, &Vec::new(&env)),
            Err(LedgerExportError::CanonicalEntryMissing)
        );
    }
    #[test]
    fn validates_range_boundaries_without_overflow() {
        assert_eq!(
            ledger_export_count(0, 1),
            Err(LedgerExportError::InvalidRange)
        );
        assert_eq!(
            ledger_export_count(2, 1),
            Err(LedgerExportError::InvalidRange)
        );
        assert_eq!(
            ledger_export_count(1, 51),
            Err(LedgerExportError::TooManyEntries)
        );
        assert_eq!(ledger_export_count(1, 50), Ok(50));
        assert_eq!(ledger_export_count(u64::MAX, u64::MAX), Ok(1));
        assert_eq!(
            ledger_export_count(1, u64::MAX),
            Err(LedgerExportError::TooManyEntries)
        );
        let env = Env::default();
        let contract = env.register(crate::Payroll, ());
        let page = vec![&env, entry(&env, u64::MAX)];
        assert!(env
            .as_contract(&contract, || validate_ledger_export(
                &env,
                u64::MAX,
                u64::MAX,
                &page,
                &page
            ))
            .is_ok());
    }
}
