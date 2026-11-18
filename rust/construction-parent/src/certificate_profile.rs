//! Frozen dimensions and framing for the certificate-parent profile.
//!
//! These constants cover both the native certificate accumulator and the
//! qualified recurrence relation. Dimensions alone do not select or
//! authenticate a Nova suite, witness, or proof.

use crate::RelationError;

pub(crate) const CERTIFICATE_LEAF_GATE_COUNT: usize = 2_048;
pub(crate) const CERTIFICATE_LEAF_NORM_LENGTH: usize = 4_096;
pub(crate) const CERTIFICATE_LEAF_ROUNDS: usize = 12;

pub(crate) const CERTIFICATE_ROOT_ROUNDS: usize = 13;
pub(crate) const CERTIFICATE_ROOT_STATE_ARITY: usize = 3 + CERTIFICATE_ROOT_ROUNDS;
pub(crate) const CERTIFICATE_ROOT_BYTES: usize = 33 + 32 + 32 * CERTIFICATE_ROOT_ROUNDS;
pub(crate) const CERTIFICATE_RECURRENCE_STATE_ARITY: usize = CERTIFICATE_ROOT_STATE_ARITY + 10;
pub(crate) const ROOT_PREFIX_INDEX: usize = 0;
pub(crate) const ROOT_X_INDEX: usize = 1;
pub(crate) const ROOT_SCALE_INDEX: usize = 2;
pub(crate) const ROOT_FACTORS_START: usize = 3;
pub(crate) const CONTEXT_HIGH_INDEX: usize = CERTIFICATE_ROOT_STATE_ARITY;
pub(crate) const CONTEXT_LOW_INDEX: usize = CONTEXT_HIGH_INDEX + 1;
pub(crate) const TOTAL_RESPONSES_INDEX: usize = CONTEXT_LOW_INDEX + 1;
pub(crate) const NONCE_PREFIX_INDEX: usize = TOTAL_RESPONSES_INDEX + 1;
pub(crate) const NONCE_X_INDEX: usize = NONCE_PREFIX_INDEX + 1;
pub(crate) const RECORD_MANIFEST_INDEX: usize = NONCE_X_INDEX + 1;
pub(crate) const RESPONSE_ORDINAL_INDEX: usize = RECORD_MANIFEST_INDEX + 1;
pub(crate) const MEMBER_ORDINAL_INDEX: usize = RESPONSE_ORDINAL_INDEX + 1;
pub(crate) const MEMBER_COUNT_INDEX: usize = MEMBER_ORDINAL_INDEX + 1;
pub(crate) const RESPONSE_BINDING_INDEX: usize = MEMBER_COUNT_INDEX + 1;
pub(crate) const CERTIFICATE_RECURRENCE_RELATION_AUXILIARY: usize = 7_485_953;
pub(crate) const CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS: usize = 7_525_946;

pub(crate) const CERTIFICATE_MEMBER_BATCH_CAPACITY: u32 = 128;
pub(crate) const CERTIFICATE_TREE_FANOUT: u64 = 16;
pub(crate) const CERTIFICATE_MAX_RESPONSES: u64 = 1 << 60;

pub(crate) const CERTIFICATE_NONCE_PROOF_BYTES: usize = 1_072;
pub(crate) const CERTIFICATE_REDUCTION_PROOF_BYTES: usize = 890;
pub(crate) const CERTIFICATE_STEP_PROOF_BYTES: usize = 924;

/// Native `NormAccumBasisV2` digest for the certificate nonce-leaf domain and
/// its fixed 4,096-by-4,096 dimensions.
pub(crate) const CERTIFICATE_PARENT_BASIS_DIGEST: [u8; 32] = [
    0x9b, 0x48, 0xdf, 0x1e, 0xd8, 0xf8, 0x2f, 0x09, 0xc0, 0xce, 0x3d, 0xf8, 0x93, 0x84, 0x50, 0xef,
    0x3b, 0x58, 0xa7, 0xc3, 0x53, 0xba, 0xee, 0xc7, 0xec, 0xdb, 0x02, 0xe3, 0x27, 0xed, 0x14, 0xfe,
];

/// SHA256 of the exact 8,192 raw V4 generator encodings used by certificate
/// nonce leaves.
pub(crate) const CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST: [u8; 32] = [
    0x44, 0xab, 0x48, 0xd4, 0xab, 0x2f, 0xdb, 0xb9, 0x5e, 0xee, 0xd5, 0x72, 0xe9, 0xe0, 0xa6, 0xc4,
    0x69, 0xdb, 0xc1, 0xa3, 0x21, 0x16, 0xeb, 0xd9, 0x18, 0xb4, 0x87, 0xca, 0x5e, 0xa6, 0x05, 0x82,
];

/// Immutable trace frame shared by every response in one certificate witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertificateWitnessFrame {
    certificate_context_digest: [u8; 32],
    total_responses: u64,
}

impl CertificateWitnessFrame {
    pub(crate) fn new(
        certificate_context_digest: [u8; 32],
        total_responses: u64,
    ) -> Result<Self, RelationError> {
        if certificate_context_digest == [0; 32] {
            return Err(RelationError::Malformed(
                "empty certificate witness context",
            ));
        }
        if total_responses == 0 || total_responses > CERTIFICATE_MAX_RESPONSES {
            return Err(RelationError::Malformed(
                "certificate witness response count",
            ));
        }
        Ok(Self {
            certificate_context_digest,
            total_responses,
        })
    }

    pub(crate) const fn certificate_context_digest(&self) -> [u8; 32] {
        self.certificate_context_digest
    }

    pub(crate) const fn total_responses(&self) -> u64 {
        self.total_responses
    }

    pub(crate) fn response(
        &self,
        ordinal: u64,
        member_count: u32,
    ) -> Result<CertificateResponseBoundary, RelationError> {
        CertificateResponseBoundary::new(*self, ordinal, member_count)
    }
}

/// Exact response/member boundary consumed by a certificate witness decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertificateResponseBoundary {
    frame: CertificateWitnessFrame,
    ordinal: u64,
    member_count: u32,
}

impl CertificateResponseBoundary {
    fn new(
        frame: CertificateWitnessFrame,
        ordinal: u64,
        member_count: u32,
    ) -> Result<Self, RelationError> {
        if ordinal >= frame.total_responses
            || member_count == 0
            || member_count > CERTIFICATE_MEMBER_BATCH_CAPACITY
        {
            return Err(RelationError::Malformed(
                "certificate witness response boundary",
            ));
        }
        Ok(Self {
            frame,
            ordinal,
            member_count,
        })
    }

    pub(crate) const fn frame(&self) -> CertificateWitnessFrame {
        self.frame
    }

    pub(crate) const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub(crate) const fn member_count(&self) -> u32 {
        self.member_count
    }
}

pub(crate) fn certificate_tree_step_count(response_count: u64) -> Result<u64, RelationError> {
    if response_count == 0 || response_count > CERTIFICATE_MAX_RESPONSES {
        return Err(RelationError::Malformed(
            "certificate witness response count",
        ));
    }
    let mut level_count = response_count;
    let mut proof_count = 0u64;
    while level_count > 1 {
        let parent_count = 1 + (level_count - 1) / CERTIFICATE_TREE_FANOUT;
        proof_count = proof_count
            .checked_add(parent_count)
            .ok_or(RelationError::Malformed("certificate witness tree count"))?;
        level_count = parent_count;
    }
    Ok(proof_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_matches_native_certificate_dimensions() {
        assert_eq!(
            CERTIFICATE_LEAF_NORM_LENGTH,
            2 * CERTIFICATE_LEAF_GATE_COUNT
        );
        assert_eq!(
            CERTIFICATE_LEAF_ROUNDS,
            CERTIFICATE_LEAF_NORM_LENGTH.ilog2() as usize
        );
        assert_eq!(
            CERTIFICATE_ROOT_ROUNDS,
            (2 * CERTIFICATE_LEAF_NORM_LENGTH).ilog2() as usize
        );
        assert_eq!(CERTIFICATE_ROOT_STATE_ARITY, 16);
        assert_eq!(
            CERTIFICATE_NONCE_PROOF_BYTES,
            228 + 65 * CERTIFICATE_LEAF_ROUNDS + 64
        );
        assert_eq!(
            CERTIFICATE_REDUCTION_PROOF_BYTES,
            66 * CERTIFICATE_LEAF_ROUNDS + 98
        );
        assert_eq!(
            CERTIFICATE_STEP_PROOF_BYTES,
            66 * CERTIFICATE_ROOT_ROUNDS + 66
        );
    }

    #[test]
    fn frame_fixes_response_and_member_ranges() {
        assert!(CertificateWitnessFrame::new([0; 32], 1).is_err());
        assert!(CertificateWitnessFrame::new([1; 32], 0).is_err());
        assert!(CertificateWitnessFrame::new([1; 32], CERTIFICATE_MAX_RESPONSES + 1).is_err());

        let frame = CertificateWitnessFrame::new([1; 32], 2).expect("valid frame");
        assert!(frame.response(0, 1).is_ok());
        assert!(frame.response(1, CERTIFICATE_MEMBER_BATCH_CAPACITY).is_ok());
        assert!(frame.response(2, 1).is_err());
        assert!(frame.response(0, 0).is_err());
        assert!(frame
            .response(0, CERTIFICATE_MEMBER_BATCH_CAPACITY + 1)
            .is_err());
    }

    #[test]
    fn tree_step_count_matches_native_level_order() {
        assert_eq!(certificate_tree_step_count(1), Ok(0));
        assert_eq!(certificate_tree_step_count(16), Ok(1));
        assert_eq!(certificate_tree_step_count(17), Ok(3));
        assert_eq!(certificate_tree_step_count(1_000), Ok(68));
        assert!(certificate_tree_step_count(0).is_err());
        assert!(certificate_tree_step_count(CERTIFICATE_MAX_RESPONSES + 1).is_err());
    }
}
