// Stable error code for unsupported proof formats (#899).
//
// `InvalidProofFormat` (100) means the bytes are malformed. `UnsupportedProofFormat`
// (107) means the bytes are well formed but use a proof format or schema version
// this deployment does not accept. Clients need to tell the two apart: the first
// is a bug in proof generation, the second is "use a supported format".
//
// The code carries no payload by design, so it cannot expose salary amounts,
// commitments or employee identifiers.

#[cfg(test)]
mod unsupported_proof_format_tests {
    use shared_errors::*;

    /// Success: the code has the documented, stable value inside the proof range.
    #[test]
    fn test_unsupported_proof_format_has_stable_code() {
        assert_eq!(ProofError::UnsupportedProofFormat as u32, 107);
        assert_eq!(ProofError::UnsupportedProofFormat.code(), 107);
    }

    /// Rejection: it is a distinct code from the malformed-proof error and from
    /// every other proof error, so clients can branch on it.
    #[test]
    fn test_unsupported_proof_format_is_distinct_from_other_proof_errors() {
        let unsupported = ProofError::UnsupportedProofFormat as u32;
        let others = [
            ProofError::InvalidProofFormat as u32,
            ProofError::ProofVerificationFailed as u32,
            ProofError::CommitmentMismatch as u32,
            ProofError::ProofExpired as u32,
            ProofError::InvalidPublicInputs as u32,
            ProofError::VerifyingKeyMismatch as u32,
            ProofError::InvalidNullifier as u32,
        ];
        for other in others {
            assert_ne!(unsupported, other);
        }
        assert_ne!(ProofError::UnsupportedProofFormat, ProofError::InvalidProofFormat);
    }

    /// Boundary: it sits inside the reserved 100-199 proof range and does not
    /// collide with the first code of the next category (audit, 200).
    #[test]
    fn test_unsupported_proof_format_stays_inside_the_proof_range() {
        let code = ProofError::UnsupportedProofFormat as u32;
        assert!((100..200).contains(&code));
        assert_ne!(code, AuditError::ViewKeyNotFound as u32);
        // Existing codes keep their values: adding 107 must not renumber anything.
        assert_eq!(ProofError::InvalidProofFormat as u32, 100);
        assert_eq!(ProofError::InvalidNullifier as u32, 106);
    }

    /// The code is a plain, copyable value: nothing in it can carry private data.
    #[test]
    fn test_unsupported_proof_format_is_a_plain_copyable_value() {
        let a = ProofError::UnsupportedProofFormat;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(core::mem::size_of::<ProofError>(), core::mem::size_of::<u32>());
    }
}
