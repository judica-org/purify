//! Authenticated local storage for one selected direct Nova prover.
//!
//! This artifact contains transparent public setup material, not toxic waste.
//! Its identity is selected locally and authenticated before Serde sees any
//! bytes. It never carries a verifier key, suite metadata, proof shape, or
//! cached padded R1CS shape.

use std::io::{self, Read, Seek};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    NovaProverKey, NovaPublicParams, Prover, SelectedProver, SessionError, SessionStep,
    SuiteMetadata,
};
use circuit::relation::identity::RelationId;
use verifier::artifact::{
    read_artifact_payload, ArtifactCodecError, ArtifactFormat, ArtifactIdentity,
};
use verifier::nova::one_thread_pool;
use verifier::suite::Suite;

const MAX_COMPRESSED_PAYLOAD_LENGTH: usize = 1_000_000_000;
const MAX_DECODED_PAYLOAD_LENGTH: usize = 4_000_000_000;
const PROVER_ARTIFACT_FORMAT: ArtifactFormat = ArtifactFormat {
    magic: *b"Purify/Nova/PK1\0",
    encoding_version: 1,
    digest_tag: b"Purify/Accountable/DirectNovaProverArtifact/v1",
    window_log: 23,
    max_compressed_payload_length: MAX_COMPRESSED_PAYLOAD_LENGTH,
    max_decoded_payload_length: MAX_DECODED_PAYLOAD_LENGTH,
};

/// Public parameters and the compression prover key are the entire payload.
///
/// Nova marks its padded-shape cache as skipped Serde state. Proving after a
/// reload therefore reconstructs that cache from these public parameters.
#[derive(Deserialize, Serialize)]
#[serde(bound = "")]
struct ProverArtifactPayload<C: SessionStep<ARITY>, const ARITY: usize> {
    public_params: NovaPublicParams<C>,
    prover_key: NovaProverKey<C>,
}

/// Exact prover state emitted by setup-only qualification.
///
/// This byte identity is deliberately distinct from the semantic suite ID.
/// No file-derived or caller-selected identity can reach production loading.
/// The ordinary artifact SHA-256 is
/// `cd4bece27897e8634e837a4acb85ed091f2175df62d8c38e65497ef07066f816`.
pub(crate) const QUALIFIED_PROVER_ARTIFACT: ArtifactIdentity = ArtifactIdentity::new(
    693_582_375,
    3_022_457_782,
    [
        0x37, 0xb3, 0x1a, 0x1c, 0xea, 0x00, 0x12, 0xca, 0xd3, 0xb5, 0x34, 0x2d, 0xeb, 0x2c, 0x2d,
        0xf8, 0x5d, 0x6b, 0x0e, 0x43, 0xce, 0x91, 0x3e, 0xb8, 0x0e, 0x4d, 0xff, 0x6a, 0xf3, 0x59,
        0x22, 0x3b,
    ],
);

/// Failure while loading a selected prover artifact.
#[derive(Debug, Error)]
pub(crate) enum ProverArtifactError {
    #[error("direct Nova prover artifact length is invalid")]
    Length,
    #[error("direct Nova prover artifact digest mismatch")]
    Digest,
    #[error("direct Nova prover artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova prover artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova prover artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Suite(#[from] SessionError),
}

impl From<ArtifactCodecError> for ProverArtifactError {
    fn from(error: ArtifactCodecError) -> Self {
        match error {
            ArtifactCodecError::Length => Self::Length,
            ArtifactCodecError::Digest => Self::Digest,
            ArtifactCodecError::Header(context) => Self::Header(context),
            ArtifactCodecError::Io(error) => Self::Io(error),
            ArtifactCodecError::Decode(error) => Self::Decode(error),
        }
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SelectedProver<ARITY, C> {
    /// Load a selected prover from its complete authenticated byte source.
    ///
    /// The complete file is hashed before header parsing or Serde and every
    /// consumed byte is hashed again. File-backed callers must keep the source
    /// as an immutable read-only snapshot for both passes.
    pub(crate) fn from_artifact_reader<R>(
        source: &mut R,
        expected_suite: &'static Suite,
        expected_artifact: &ArtifactIdentity,
    ) -> Result<Self, ProverArtifactError>
    where
        R: Read + Seek,
    {
        let proof_shape = expected_suite.proof_shape().map_err(SessionError::from)?;
        let payload = read_artifact_payload::<
            ProverArtifactPayload<C, ARITY>,
            _,
            MAX_DECODED_PAYLOAD_LENGTH,
        >(
            source,
            &PROVER_ARTIFACT_FORMAT,
            expected_suite.suite_id,
            ARITY,
            *expected_artifact,
        )?;

        // Public parameters do not carry a relation ID, so the selected
        // profile's ID is recorded as declared and only the measured digest
        // and dimensions are compared.
        SuiteMetadata::measure::<ARITY, C>(
            RelationId::from_frozen_bytes(expected_suite.parameters.relation_id),
            &payload.public_params,
            &proof_shape,
        )?
        .validate_parameters::<ARITY>(expected_suite)?;
        Ok(Self {
            expected: expected_suite,
            inner: Prover {
                public_params: payload.public_params,
                prover_key: payload.prover_key,
                proof_shape,
                pool: one_thread_pool().map_err(SessionError::Setup)?,
                operation: Mutex::new(()),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ff::Field;
    use nova_snark::frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};

    use std::io::Write;

    use super::*;
    use crate::artifact_writer::{identity_of_bytes, write_artifact_payload, ArtifactWriteError};
    use crate::session::setup::SessionSuite;
    use statement::Scalar;
    use verifier::suite::ConstructionVersions;

    impl<const ARITY: usize, C: SessionStep<ARITY>> SelectedProver<ARITY, C> {
        /// Consume and stream this selected prover into a new empty destination.
        ///
        /// Consuming the prover ensures qualification must reload the exact
        /// persisted state before using it. The returned identity is setup
        /// output and must be reviewed and compiled into the production tool.
        pub(crate) fn write_artifact<W>(
            self,
            destination: &mut W,
        ) -> Result<ArtifactIdentity, ArtifactWriteError>
        where
            W: Read + Write + Seek,
        {
            let expected = self.expected;
            let Prover {
                public_params,
                prover_key,
                proof_shape: _,
                pool: _,
                operation: _,
            } = self.inner;
            let payload = ProverArtifactPayload::<C, ARITY> {
                public_params,
                prover_key,
            };
            write_artifact_payload(
                destination,
                &PROVER_ARTIFACT_FORMAT,
                expected.suite_id,
                ARITY,
                &payload,
            )
        }

        /// Load one immutable, locally authenticated artifact byte slice.
        pub(crate) fn from_artifact(
            artifact: &[u8],
            expected_suite: &'static Suite,
            expected_artifact: &ArtifactIdentity,
        ) -> Result<Self, ProverArtifactError> {
            let mut source = io::Cursor::new(artifact);
            Self::from_artifact_reader(&mut source, expected_suite, expected_artifact)
        }
    }

    #[test]
    fn qualified_pk1_identity_is_frozen() {
        assert_eq!(MAX_COMPRESSED_PAYLOAD_LENGTH, 1_000_000_000);
        assert_eq!(MAX_DECODED_PAYLOAD_LENGTH, 4_000_000_000);
        assert_eq!(QUALIFIED_PROVER_ARTIFACT.encoded_length(), 693_582_375);
        assert_eq!(
            QUALIFIED_PROVER_ARTIFACT.decoded_payload_length(),
            3_022_457_782
        );
        assert_eq!(
            QUALIFIED_PROVER_ARTIFACT.digest(),
            [
                0x37, 0xb3, 0x1a, 0x1c, 0xea, 0x00, 0x12, 0xca, 0xd3, 0xb5, 0x34, 0x2d, 0xeb, 0x2c,
                0x2d, 0xf8, 0x5d, 0x6b, 0x0e, 0x43, 0xce, 0x91, 0x3e, 0xb8, 0x0e, 0x4d, 0xff, 0x6a,
                0xf3, 0x59, 0x22, 0x3b,
            ]
        );
        assert!(QUALIFIED_PROVER_ARTIFACT.encoded_length() <= MAX_COMPRESSED_PAYLOAD_LENGTH as u64);
        assert!(
            QUALIFIED_PROVER_ARTIFACT.decoded_payload_length() <= MAX_DECODED_PAYLOAD_LENGTH as u64
        );
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SmallPayload {
        public_params: Vec<u64>,
        prover_key: Vec<u64>,
    }

    fn encode_small_payload(suite_id: [u8; 32], arity: usize) -> (Vec<u8>, ArtifactIdentity) {
        let payload = SmallPayload {
            public_params: vec![3, 5, 8],
            prover_key: vec![13, 21],
        };
        let mut encoded = Cursor::new(Vec::new());
        let identity = write_artifact_payload(
            &mut encoded,
            &PROVER_ARTIFACT_FORMAT,
            suite_id,
            arity,
            &payload,
        )
        .expect("encode small prover artifact");
        (encoded.into_inner(), identity)
    }

    fn decode_small_payload(
        encoded: &[u8],
        suite_id: [u8; 32],
        arity: usize,
        descriptor: ArtifactIdentity,
    ) -> Result<SmallPayload, ProverArtifactError> {
        let mut source = Cursor::new(encoded);
        Ok(read_artifact_payload::<
            SmallPayload,
            _,
            MAX_DECODED_PAYLOAD_LENGTH,
        >(
            &mut source,
            &PROVER_ARTIFACT_FORMAT,
            suite_id,
            arity,
            descriptor,
        )?)
    }

    #[test]
    fn pk1_frame_roundtrips_and_authenticates_every_byte() {
        let suite_id = [0x5a; 32];
        let arity = 20;
        let (encoded, descriptor) = encode_small_payload(suite_id, arity);
        assert_eq!(&encoded[..16], b"Purify/Nova/PK1\0");
        assert_eq!(&encoded[16..20], &[0, 0, 0, 1]);
        assert_eq!(&encoded[20..52], &suite_id);
        assert_eq!(&encoded[52..56], &[0, 0, 0, 20]);
        assert_eq!(descriptor.encoded_length(), encoded.len() as u64);
        assert_ne!(descriptor.digest(), [0; 32]);
        assert_eq!(
            decode_small_payload(&encoded, suite_id, arity, descriptor)
                .expect("decode small prover artifact"),
            SmallPayload {
                public_params: vec![3, 5, 8],
                prover_key: vec![13, 21],
            }
        );

        let mut corrupted = encoded.clone();
        *corrupted.last_mut().expect("artifact payload") ^= 1;
        assert!(matches!(
            decode_small_payload(&corrupted, suite_id, arity, descriptor),
            Err(ProverArtifactError::Digest)
        ));
        assert!(matches!(
            decode_small_payload(&encoded[..encoded.len() - 1], suite_id, arity, descriptor,),
            Err(ProverArtifactError::Length)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_small_payload(&trailing, suite_id, arity, descriptor),
            Err(ProverArtifactError::Length)
        ));
    }

    #[test]
    fn pk1_frame_rejects_wrong_suite_and_arity_after_authentication() {
        let suite_id = [0xa5; 32];
        let arity = 20;
        let (encoded, descriptor) = encode_small_payload(suite_id, arity);

        assert!(matches!(
            decode_small_payload(&encoded, [0x5a; 32], arity, descriptor),
            Err(ProverArtifactError::Header("suite ID"))
        ));
        assert!(matches!(
            decode_small_payload(&encoded, suite_id, arity + 1, descriptor),
            Err(ProverArtifactError::Header("state arity"))
        ));

        let mut changed_suite = encoded.clone();
        changed_suite[20] ^= 1;
        let changed_suite_descriptor = identity_of_bytes(
            &PROVER_ARTIFACT_FORMAT,
            &changed_suite,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_suite, suite_id, arity, changed_suite_descriptor,),
            Err(ProverArtifactError::Header("suite ID"))
        ));

        let mut changed_arity = encoded.clone();
        changed_arity[55] ^= 1;
        let changed_arity_descriptor = identity_of_bytes(
            &PROVER_ARTIFACT_FORMAT,
            &changed_arity,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_arity, suite_id, arity, changed_arity_descriptor,),
            Err(ProverArtifactError::Header("state arity"))
        ));

        let mut changed_magic = encoded.clone();
        changed_magic[0] ^= 1;
        let changed_magic_descriptor = identity_of_bytes(
            &PROVER_ARTIFACT_FORMAT,
            &changed_magic,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_magic, suite_id, arity, changed_magic_descriptor,),
            Err(ProverArtifactError::Header("magic"))
        ));

        let mut changed_version = encoded;
        changed_version[19] = 2;
        let changed_version_descriptor = identity_of_bytes(
            &PROVER_ARTIFACT_FORMAT,
            &changed_version,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(
                &changed_version,
                suite_id,
                arity,
                changed_version_descriptor,
            ),
            Err(ProverArtifactError::Header("encoding version"))
        ));
    }

    const TINY_ARITY: usize = 1;
    const TINY_VERSIONS: ConstructionVersions = ConstructionVersions {
        payload: 1,
        statement: 1,
        manifest: 1,
        native_decision: 1,
    };
    const TINY_RELATION: RelationId = RelationId::from_frozen_bytes([0x42; 32]);

    #[derive(Clone)]
    struct TinyStep {
        input: [Scalar; TINY_ARITY],
    }

    impl nova_snark::traits::circuit::StepCircuit<Scalar> for TinyStep {
        fn arity(&self) -> usize {
            TINY_ARITY
        }

        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            cs: &mut CS,
            z: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(Scalar::ONE))?;
            cs.enforce(
                || "one is constant",
                |linear| linear + one.get_variable(),
                |linear| linear + CS::one(),
                |linear| linear + CS::one(),
            );
            let output =
                AllocatedNum::alloc(
                    cs.namespace(|| "output"),
                    || Ok(self.input[0] + Scalar::ONE),
                )?;
            cs.enforce(
                || "increment",
                |linear| linear + z[0].get_variable() + one.get_variable(),
                |linear| linear + CS::one(),
                |linear| linear + output.get_variable(),
            );
            Ok(vec![output])
        }
    }

    impl SessionStep<TINY_ARITY> for TinyStep {
        fn relation_id(&self) -> RelationId {
            TINY_RELATION
        }

        fn input_state(&self) -> &[Scalar; TINY_ARITY] {
            &self.input
        }
    }

    #[test]
    #[ignore = "performs transparent setup, proving, and compression"]
    fn real_selected_prover_roundtrips_through_pk1() {
        let initial_state = [Scalar::from(7u64)];
        let expected_final_state = [Scalar::from(8u64)];
        let suite = SessionSuite::<TINY_ARITY, TinyStep>::setup(TinyStep {
            input: initial_state,
        })
        .expect("setup tiny prover")
        .select_generated_for_qualification(TINY_VERSIONS)
        .expect("select tiny prover");
        let expected = suite.expected();
        let verifier = suite.verifier;
        let mut encoded = Cursor::new(Vec::new());
        let descriptor = suite
            .prover
            .write_artifact(&mut encoded)
            .expect("write tiny prover artifact");
        let encoded = encoded.into_inner();
        let loaded =
            SelectedProver::<TINY_ARITY, TinyStep>::from_artifact(&encoded, expected, &descriptor)
                .expect("reload tiny prover artifact");
        assert_eq!(loaded.expected(), expected);
        let proof = loaded
            .start(initial_state, 1)
            .expect("start reloaded tiny prover")
            .add_step(TinyStep {
                input: initial_state,
            })
            .expect("fold with reloaded public parameters")
            .finish()
            .expect("compress with deserialized prover key");
        verifier
            .verify_exact(&initial_state, 1, &expected_final_state, &proof)
            .expect("verify proof from reloaded prover state");
    }
}
