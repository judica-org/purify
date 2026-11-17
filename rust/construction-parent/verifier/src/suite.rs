//! Locally pinned identity of one recursive proof suite.
//!
//! A suite fixes the step relation, both engines, the public parameters, the
//! compression scheme, and the proof codec. Receipts and peers never supply
//! any of these values: the library compiles in one [`QUALIFIED`] profile.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::codec::{
    FixedSerdeError, ProofShape, R1csDimensions, NOVA_COMPRESSED_PROOF_CODEC_VERSION,
};
use statement::profile::STATE_ARITY;
use statement::STEP_RELATION_ENCODING_VERSION;

const SUITE_ID_TAG: &[u8] = b"Purify/Accountable/ConstructionParentNovaSuite/v2";
const SUITE_ENCODING_VERSION: u8 = 2;
const NOVA_VERSION: [u8; 3] = [0, 76, 0];
const PRIMARY_ENGINE_SECQ256K1_SHA256: u8 = 1;
const SECONDARY_ENGINE_SECP256K1_SHA256: u8 = 2;
const FOLDING_SCHEME_NOVA: u8 = 1;
const COMPRESSION_SCHEME_SPARTAN: u8 = 1;
const EVALUATION_ENGINE_IPA_PC: u8 = 1;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SuiteError {
    #[error(transparent)]
    Codec(#[from] FixedSerdeError),
    #[error("direct Nova suite identity failed: {0}")]
    Identity(&'static str),
    #[error("direct Nova selected suite mismatch: {0}")]
    Mismatch(&'static str),
}

/// Receipt-layer versions whose meanings are external to the Nova matrix.
///
/// They are part of the suite ID so a changed receipt meaning selects a
/// different suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstructionVersions {
    pub payload: u32,
    pub statement: u32,
    pub manifest: u32,
    pub native_decision: u32,
}

/// Constraint and variable counts of one augmented R1CS shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R1csSize {
    pub constraints: u64,
    pub variables: u64,
}

impl R1csSize {
    fn dimensions(self) -> Result<R1csDimensions, SuiteError> {
        Ok(R1csDimensions::new(
            usize::try_from(self.constraints)
                .map_err(|_| SuiteError::Identity("constraint count"))?,
            usize::try_from(self.variables).map_err(|_| SuiteError::Identity("variable count"))?,
        ))
    }
}

/// Everything a suite ID commits to besides the derived proof codec shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuiteParameters {
    pub versions: ConstructionVersions,
    pub state_arity: u32,
    pub relation_id: [u8; 32],
    pub public_parameter_digest: [u8; 32],
    pub primary: R1csSize,
    pub secondary: R1csSize,
}

impl SuiteParameters {
    /// Derives the fixed proof codec shape implied by these dimensions.
    pub fn proof_shape(&self) -> Result<ProofShape, SuiteError> {
        let state_arity =
            usize::try_from(self.state_arity).map_err(|_| SuiteError::Identity("state arity"))?;
        Ok(ProofShape::from_suite_dimensions(
            self.primary.dimensions()?,
            self.secondary.dimensions()?,
            state_arity,
        )?)
    }

    /// Commits to the complete local proof suite with BIP340 tagged SHA256.
    pub fn suite_id(&self, proof_shape: &ProofShape) -> Result<[u8; 32], SuiteError> {
        let tag_hash = Sha256::digest(SUITE_ID_TAG);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        // Canonical body order is: two one-byte suite/relation versions; four
        // big-endian u32 receipt-layer versions; the three one-byte Nova
        // semantic-version components; six one-byte ordered
        // engine/backend/codec identifiers; big-endian u32 arity; relation
        // and PP digests; five big-endian u64 dimensions/lengths; then a
        // big-endian u32 schedule count and every schedule length as u32.
        digest.update([SUITE_ENCODING_VERSION, STEP_RELATION_ENCODING_VERSION]);
        digest.update(self.versions.payload.to_be_bytes());
        digest.update(self.versions.statement.to_be_bytes());
        digest.update(self.versions.manifest.to_be_bytes());
        digest.update(self.versions.native_decision.to_be_bytes());
        digest.update(NOVA_VERSION);
        digest.update([
            PRIMARY_ENGINE_SECQ256K1_SHA256,
            SECONDARY_ENGINE_SECP256K1_SHA256,
            FOLDING_SCHEME_NOVA,
            COMPRESSION_SCHEME_SPARTAN,
            EVALUATION_ENGINE_IPA_PC,
            NOVA_COMPRESSED_PROOF_CODEC_VERSION,
        ]);
        digest.update(self.state_arity.to_be_bytes());
        digest.update(self.relation_id);
        digest.update(self.public_parameter_digest);
        for value in [
            self.primary.constraints,
            self.primary.variables,
            self.secondary.constraints,
            self.secondary.variables,
            suite_u64(proof_shape.encoded_len(), "proof length")?,
        ] {
            digest.update(value.to_be_bytes());
        }
        digest
            .update(suite_u32(proof_shape.sequence_count(), "codec sequence count")?.to_be_bytes());
        for &length in proof_shape.suite_sequence_lengths() {
            digest.update(suite_u32(length, "codec sequence length")?.to_be_bytes());
        }
        Ok(digest.finalize().into())
    }
}

fn suite_u32(value: usize, label: &'static str) -> Result<u32, SuiteError> {
    u32::try_from(value).map_err(|_| SuiteError::Identity(label))
}

fn suite_u64(value: usize, label: &'static str) -> Result<u64, SuiteError> {
    u64::try_from(value).map_err(|_| SuiteError::Identity(label))
}

/// One locally selected suite. Receipts and peers never construct this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Suite {
    pub parameters: SuiteParameters,
    pub proof_length: u64,
    pub proof_sequences: u32,
    pub suite_id: [u8; 32],
}

impl Suite {
    /// Derives the proof codec shape and checks every pinned value that the
    /// pinned parameters independently determine: the encoded proof length,
    /// the codec sequence count, and the suite ID.
    pub fn proof_shape(&self) -> Result<ProofShape, SuiteError> {
        let proof_shape = self.parameters.proof_shape()?;
        if suite_u64(proof_shape.encoded_len(), "proof length")? != self.proof_length {
            return Err(SuiteError::Mismatch("proof length"));
        }
        if suite_u32(proof_shape.sequence_count(), "codec sequence count")? != self.proof_sequences
        {
            return Err(SuiteError::Mismatch("codec sequence count"));
        }
        if self.parameters.suite_id(&proof_shape)? != self.suite_id {
            return Err(SuiteError::Mismatch("suite ID"));
        }
        Ok(proof_shape)
    }
}

pub const QUALIFIED_PROOF_LENGTH: usize = 15_076;

/// Exact mixed construction-parent profile selected by qualification.
///
/// Native-decision version 1 binds `CandidateAccumStep/v1` and the native
/// linear decision over `point:33 || scale:32 || factors:15*32`, the current
/// 545-byte construction-root semantics.
pub static QUALIFIED: Suite = Suite {
    parameters: SuiteParameters {
        versions: ConstructionVersions {
            payload: 4,
            statement: 5,
            manifest: 3,
            native_decision: 1,
        },
        state_arity: STATE_ARITY as u32,
        relation_id: [
            0xa6, 0x6c, 0x58, 0xa8, 0x6a, 0xfc, 0xe6, 0x4b, 0x2b, 0x69, 0xd5, 0x3e, 0x83, 0xd3,
            0xd5, 0x43, 0x0d, 0x08, 0x0f, 0xaf, 0x0b, 0x68, 0x06, 0x4c, 0xad, 0xb3, 0xa6, 0xd8,
            0xb4, 0x39, 0xee, 0xa9,
        ],
        public_parameter_digest: [
            0x12, 0x4d, 0x07, 0x56, 0x20, 0x3e, 0xbf, 0x5b, 0x41, 0x6b, 0x6f, 0x12, 0x30, 0x35,
            0x6e, 0xf9, 0x92, 0x1f, 0xb3, 0x05, 0x38, 0xa8, 0xf7, 0xfc, 0xeb, 0xb1, 0x06, 0x18,
            0x19, 0x49, 0x71, 0x00,
        ],
        primary: R1csSize {
            constraints: 9_418_542,
            variables: 9_372_224,
        },
        secondary: R1csSize {
            constraints: 728_974,
            variables: 728_211,
        },
    },
    proof_length: QUALIFIED_PROOF_LENGTH as u64,
    proof_sequences: 152,
    suite_id: [
        0xcc, 0xba, 0x9e, 0xd4, 0xb0, 0xee, 0xc0, 0x37, 0xc8, 0xdc, 0x34, 0xbf, 0x33, 0xfd, 0x29,
        0x2c, 0xc4, 0x76, 0x37, 0x5e, 0xc4, 0x70, 0x0a, 0x36, 0xc0, 0x70, 0xe3, 0x71, 0x0d, 0xd1,
        0xa9, 0x02,
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VERSIONS: ConstructionVersions = ConstructionVersions {
        payload: 0x0102_0304,
        statement: 0x1112_1314,
        manifest: 0x2122_2324,
        native_decision: 0x3132_3334,
    };
    const TEST_SUITE_ID: [u8; 32] = [
        0x75, 0xaf, 0xf8, 0x3f, 0x39, 0x05, 0x05, 0x67, 0x86, 0x99, 0x2a, 0xb4, 0x24, 0x9f, 0x29,
        0x4b, 0x6b, 0x62, 0xab, 0x02, 0x64, 0x69, 0xfa, 0xad, 0x60, 0xfa, 0xb4, 0xfb, 0x3c, 0x47,
        0xed, 0x03,
    ];
    const TEST_PARAMETERS: SuiteParameters = SuiteParameters {
        versions: TEST_VERSIONS,
        state_arity: 20,
        relation_id: [0x11; 32],
        public_parameter_digest: [0x22; 32],
        primary: R1csSize {
            constraints: 101,
            variables: 103,
        },
        secondary: R1csSize {
            constraints: 107,
            variables: 109,
        },
    };
    /// A self-consistent synthetic profile, repeated in the prover's session
    /// tests.
    const TEST_SUITE: Suite = Suite {
        parameters: TEST_PARAMETERS,
        proof_length: 6_376,
        proof_sequences: 62,
        suite_id: TEST_SUITE_ID,
    };

    #[test]
    fn suite_id_has_a_fixed_codec_complete_encoding() {
        let proof_shape = TEST_PARAMETERS
            .proof_shape()
            .expect("synthetic suite proof shape");
        let suite_id = TEST_PARAMETERS
            .suite_id(&proof_shape)
            .expect("tiny suite ID");
        eprintln!("tiny_sha256_suite_id={suite_id:02x?}\nparameters={TEST_PARAMETERS:#?}");
        assert_eq!(suite_id, TEST_SUITE_ID);

        let mut changed_schedule = proof_shape.clone();
        changed_schedule.increment_suite_sequence_length_for_test(7);
        assert_ne!(
            TEST_PARAMETERS
                .suite_id(&changed_schedule)
                .expect("changed codec schedule suite ID"),
            suite_id
        );

        let mut changed_digest = TEST_PARAMETERS;
        changed_digest.public_parameter_digest[0] ^= 1;
        assert_ne!(
            changed_digest
                .suite_id(&proof_shape)
                .expect("changed suite ID"),
            suite_id
        );

        let mut changed_version = TEST_PARAMETERS;
        changed_version.versions.payload = 0x0102_0305;
        assert_ne!(
            changed_version
                .suite_id(&proof_shape)
                .expect("changed construction version suite ID"),
            suite_id
        );

        let mut changed_arity = TEST_PARAMETERS;
        changed_arity.state_arity = 21;
        assert_ne!(
            changed_arity
                .suite_id(&proof_shape)
                .expect("changed state arity suite ID"),
            suite_id
        );
    }

    #[test]
    fn qualified_construction_parent_suite_frame_is_frozen() {
        assert_eq!(QUALIFIED.parameters.state_arity as usize, STATE_ARITY);
        let proof_shape = QUALIFIED
            .parameters
            .proof_shape()
            .expect("qualified SHA-256 proof shape");
        assert_eq!(proof_shape.encoded_len(), QUALIFIED_PROOF_LENGTH);
        assert_eq!(proof_shape.sequence_count(), 152);
        assert_eq!(
            QUALIFIED
                .parameters
                .suite_id(&proof_shape)
                .expect("qualified SHA-256 suite ID"),
            QUALIFIED.suite_id
        );
        assert_eq!(
            QUALIFIED
                .proof_shape()
                .expect("qualified SHA-256 suite profile"),
            proof_shape
        );
    }

    #[test]
    fn suite_profile_rejects_every_derived_value_drift() {
        TEST_SUITE.proof_shape().expect("exact local suite profile");

        let mut changed = TEST_SUITE;
        changed.proof_length += 1;
        assert_eq!(
            changed.proof_shape(),
            Err(SuiteError::Mismatch("proof length"))
        );

        let mut changed = TEST_SUITE;
        changed.proof_sequences += 1;
        assert_eq!(
            changed.proof_shape(),
            Err(SuiteError::Mismatch("codec sequence count"))
        );

        let mut changed = TEST_SUITE;
        changed.parameters.versions.payload = 0x0102_0305;
        assert_eq!(changed.proof_shape(), Err(SuiteError::Mismatch("suite ID")));

        let mut changed = TEST_SUITE;
        changed.parameters.relation_id[0] ^= 1;
        assert_eq!(changed.proof_shape(), Err(SuiteError::Mismatch("suite ID")));

        let mut changed = TEST_SUITE;
        changed.parameters.public_parameter_digest[0] ^= 1;
        assert_eq!(changed.proof_shape(), Err(SuiteError::Mismatch("suite ID")));

        let mut changed = TEST_SUITE;
        changed.suite_id = [0x55; 32];
        assert_eq!(changed.proof_shape(), Err(SuiteError::Mismatch("suite ID")));
    }
}
