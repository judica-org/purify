//! Authenticated local storage for one selected direct Nova prover.
//!
//! This artifact contains transparent public setup material, not toxic waste.
//! Its identity is selected locally and authenticated before Serde sees any
//! bytes. It never carries a verifier key, suite metadata, proof shape, or
//! cached padded R1CS shape.

use std::io::{self, Read, Seek, Write};
use std::sync::Mutex;

use ff::PrimeField;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::artifact_codec::{
    read_artifact_payload, write_artifact_payload, ArtifactCodecError, ArtifactFormat,
    ArtifactIdentity,
};
use super::{
    direct_nova_thread_pool, DirectNovaSessionError, DirectNovaSuiteMetadata,
    ExpectedDirectNovaSuite, NovaProver, NovaProverKey, NovaPublicParams, NovaSessionStep,
    SelectedNovaProver,
};
use crate::nova_types::DirectRelationId;

const ZSTD_WINDOW_LOG: u32 = 23;
const MAX_COMPRESSED_PAYLOAD_LENGTH: usize = 8 * 1024 * 1024 * 1024;
const MAX_DECODED_PAYLOAD_LENGTH: usize = 16 * 1024 * 1024 * 1024;
const PROVER_ARTIFACT_FORMAT: ArtifactFormat = ArtifactFormat::new(
    *b"Purify/Nova/PK1\0",
    1,
    b"Purify/Accountable/DirectNovaProverArtifact/v1",
    ZSTD_WINDOW_LOG,
    MAX_COMPRESSED_PAYLOAD_LENGTH,
    MAX_DECODED_PAYLOAD_LENGTH,
);

/// Public parameters and the compression prover key are the entire payload.
///
/// Nova marks its padded-shape cache as skipped Serde state. Proving after a
/// reload therefore reconstructs that cache from these public parameters.
#[derive(Deserialize, Serialize)]
#[serde(bound = "")]
struct NovaProverArtifactPayload<C: NovaSessionStep<ARITY>, const ARITY: usize> {
    public_params: NovaPublicParams<C>,
    prover_key: NovaProverKey<C>,
}

/// One reviewed byte identity for a selected local prover artifact.
///
/// This identity is deliberately distinct from the semantic suite ID. The
/// production descriptor will be pinned only after setup-only qualification;
/// no file-derived or placeholder production identity exists here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedDirectNovaProverArtifact {
    identity: ArtifactIdentity,
}

impl ExpectedDirectNovaProverArtifact {
    pub(crate) const fn new(
        encoded_length: u64,
        decoded_payload_length: u64,
        digest: [u8; 32],
    ) -> Self {
        Self {
            identity: ArtifactIdentity::new(encoded_length, decoded_payload_length, digest),
        }
    }

    pub(crate) const fn encoded_length(self) -> u64 {
        self.identity.encoded_length()
    }

    pub(crate) const fn decoded_payload_length(self) -> u64 {
        self.identity.decoded_payload_length()
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.identity.digest()
    }

    #[cfg(test)]
    fn for_test_bytes(encoded: &[u8], decoded_payload_length: u64) -> Self {
        Self {
            identity: ArtifactIdentity::for_test_bytes(
                &PROVER_ARTIFACT_FORMAT,
                encoded,
                decoded_payload_length,
            ),
        }
    }

    const fn identity(self) -> ArtifactIdentity {
        self.identity
    }
}

/// Failure while writing or loading a selected prover artifact.
#[derive(Debug, Error)]
pub(crate) enum DirectNovaProverArtifactError {
    #[error("direct Nova prover artifact destination is not empty")]
    DestinationNotEmpty,
    #[error("direct Nova prover artifact length is invalid")]
    Length,
    #[error("direct Nova prover artifact digest mismatch")]
    Digest,
    #[error("direct Nova prover artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova prover artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova prover artifact encoding failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("direct Nova prover artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Suite(#[from] DirectNovaSessionError),
}

impl From<ArtifactCodecError> for DirectNovaProverArtifactError {
    fn from(error: ArtifactCodecError) -> Self {
        match error {
            ArtifactCodecError::DestinationNotEmpty => Self::DestinationNotEmpty,
            ArtifactCodecError::Length => Self::Length,
            ArtifactCodecError::Digest => Self::Digest,
            ArtifactCodecError::Header(context) => Self::Header(context),
            ArtifactCodecError::Io(error) => Self::Io(error),
            ArtifactCodecError::Encode(error) => Self::Encode(error),
            ArtifactCodecError::Decode(error) => Self::Decode(error),
        }
    }
}

impl<const ARITY: usize, C: NovaSessionStep<ARITY>> SelectedNovaProver<ARITY, C> {
    /// Consume and stream this selected prover into a new empty destination.
    ///
    /// Consuming the prover ensures qualification must reload the exact
    /// persisted state before using it. The returned descriptor is setup
    /// output and must be reviewed and compiled into the production tool.
    pub(crate) fn write_artifact<W>(
        self,
        destination: &mut W,
    ) -> Result<ExpectedDirectNovaProverArtifact, DirectNovaProverArtifactError>
    where
        W: Read + Write + Seek,
    {
        let expected = self.expected;
        let NovaProver {
            public_params,
            prover_key,
            proof_shape: _,
            pool: _,
            operation: _,
        } = self.inner;
        let payload = NovaProverArtifactPayload::<C, ARITY> {
            public_params,
            prover_key,
        };
        let identity = write_artifact_payload(
            destination,
            &PROVER_ARTIFACT_FORMAT,
            *expected.suite_id().bytes(),
            ARITY,
            &payload,
        )?;
        Ok(ExpectedDirectNovaProverArtifact { identity })
    }

    /// Load one immutable, locally authenticated artifact byte slice.
    pub(crate) fn from_artifact(
        artifact: &[u8],
        expected_suite: &'static ExpectedDirectNovaSuite,
        expected_artifact: &ExpectedDirectNovaProverArtifact,
    ) -> Result<Self, DirectNovaProverArtifactError> {
        let mut source = io::Cursor::new(artifact);
        Self::from_artifact_reader(&mut source, expected_suite, expected_artifact)
    }

    /// Load a selected prover from its complete authenticated byte source.
    ///
    /// The complete file is hashed before header parsing or Serde and every
    /// consumed byte is hashed again. File-backed callers must keep the source
    /// as an immutable read-only snapshot for both passes.
    pub(crate) fn from_artifact_reader<R>(
        source: &mut R,
        expected_suite: &'static ExpectedDirectNovaSuite,
        expected_artifact: &ExpectedDirectNovaProverArtifact,
    ) -> Result<Self, DirectNovaProverArtifactError>
    where
        R: Read + Seek,
    {
        let (_, proof_shape) = expected_suite.local_verifier_components::<ARITY>()?;
        let payload = read_artifact_payload::<
            NovaProverArtifactPayload<C, ARITY>,
            _,
            MAX_DECODED_PAYLOAD_LENGTH,
        >(
            source,
            &PROVER_ARTIFACT_FORMAT,
            *expected_suite.suite_id().bytes(),
            ARITY,
            expected_artifact.identity(),
        )?;

        validate_public_parameters::<ARITY, C>(
            &payload.public_params,
            expected_suite,
            &proof_shape,
        )?;
        Ok(Self {
            expected: expected_suite,
            inner: NovaProver {
                public_params: payload.public_params,
                prover_key: payload.prover_key,
                proof_shape,
                pool: direct_nova_thread_pool()?,
                operation: Mutex::new(()),
            },
        })
    }
}

fn validate_public_parameters<const ARITY: usize, C: NovaSessionStep<ARITY>>(
    public_params: &NovaPublicParams<C>,
    expected_suite: &ExpectedDirectNovaSuite,
    proof_shape: &crate::fixed_serde::NovaCompressedProofShape,
) -> Result<(), DirectNovaSessionError> {
    let digest: [u8; 32] = public_params
        .digest()
        .to_repr()
        .as_ref()
        .try_into()
        .map_err(|_| DirectNovaSessionError::Setup("public-parameter digest width"))?;
    let (primary_constraints, secondary_constraints) = public_params.num_constraints();
    let (primary_variables, secondary_variables) = public_params.num_variables();
    let metadata = DirectNovaSuiteMetadata {
        relation_id: DirectRelationId::from_frozen_bytes(expected_suite.relation_id),
        public_parameter_digest: digest,
        primary_constraints,
        secondary_constraints,
        primary_variables,
        secondary_variables,
        proof_length: proof_shape.encoded_len(),
        codec_sequence_count: proof_shape.sequence_count(),
    };
    expected_suite.validate::<ARITY>(&metadata, proof_shape)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ff::Field;
    use nova_snark::frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};

    use super::*;
    use crate::nova_session::{
        ConstructionManifestVersion, ConstructionNativeDecisionVersion, ConstructionPayloadVersion,
        ConstructionStatementVersion, DirectNovaConstructionVersions, NovaSessionSuite,
    };
    use crate::Scalar;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SmallPayload {
        public_params: Vec<u64>,
        prover_key: Vec<u64>,
    }

    fn encode_small_payload(
        suite_id: [u8; 32],
        arity: usize,
    ) -> (Vec<u8>, ExpectedDirectNovaProverArtifact) {
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
        (
            encoded.into_inner(),
            ExpectedDirectNovaProverArtifact::new(
                identity.encoded_length(),
                identity.decoded_payload_length(),
                identity.digest(),
            ),
        )
    }

    fn decode_small_payload(
        encoded: &[u8],
        suite_id: [u8; 32],
        arity: usize,
        descriptor: ExpectedDirectNovaProverArtifact,
    ) -> Result<SmallPayload, DirectNovaProverArtifactError> {
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
            descriptor.identity(),
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
            Err(DirectNovaProverArtifactError::Digest)
        ));
        assert!(matches!(
            decode_small_payload(&encoded[..encoded.len() - 1], suite_id, arity, descriptor,),
            Err(DirectNovaProverArtifactError::Length)
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_small_payload(&trailing, suite_id, arity, descriptor),
            Err(DirectNovaProverArtifactError::Length)
        ));
    }

    #[test]
    fn pk1_frame_rejects_wrong_suite_and_arity_after_authentication() {
        let suite_id = [0xa5; 32];
        let arity = 20;
        let (encoded, descriptor) = encode_small_payload(suite_id, arity);

        assert!(matches!(
            decode_small_payload(&encoded, [0x5a; 32], arity, descriptor),
            Err(DirectNovaProverArtifactError::Header("suite ID"))
        ));
        assert!(matches!(
            decode_small_payload(&encoded, suite_id, arity + 1, descriptor),
            Err(DirectNovaProverArtifactError::Header("state arity"))
        ));

        let mut changed_suite = encoded.clone();
        changed_suite[20] ^= 1;
        let changed_suite_descriptor = ExpectedDirectNovaProverArtifact::for_test_bytes(
            &changed_suite,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_suite, suite_id, arity, changed_suite_descriptor,),
            Err(DirectNovaProverArtifactError::Header("suite ID"))
        ));

        let mut changed_arity = encoded.clone();
        changed_arity[55] ^= 1;
        let changed_arity_descriptor = ExpectedDirectNovaProverArtifact::for_test_bytes(
            &changed_arity,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_arity, suite_id, arity, changed_arity_descriptor,),
            Err(DirectNovaProverArtifactError::Header("state arity"))
        ));

        let mut changed_magic = encoded.clone();
        changed_magic[0] ^= 1;
        let changed_magic_descriptor = ExpectedDirectNovaProverArtifact::for_test_bytes(
            &changed_magic,
            descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            decode_small_payload(&changed_magic, suite_id, arity, changed_magic_descriptor,),
            Err(DirectNovaProverArtifactError::Header("magic"))
        ));

        let mut changed_version = encoded;
        changed_version[19] = 2;
        let changed_version_descriptor = ExpectedDirectNovaProverArtifact::for_test_bytes(
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
            Err(DirectNovaProverArtifactError::Header("encoding version"))
        ));
    }

    const TINY_ARITY: usize = 1;
    const TINY_VERSIONS: DirectNovaConstructionVersions = DirectNovaConstructionVersions::new(
        ConstructionPayloadVersion::new(1),
        ConstructionStatementVersion::new(1),
        ConstructionManifestVersion::new(1),
        ConstructionNativeDecisionVersion::new(1),
    );
    const TINY_RELATION: DirectRelationId = DirectRelationId::from_frozen_bytes([0x42; 32]);

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

    impl NovaSessionStep<TINY_ARITY> for TinyStep {
        fn relation_id(&self) -> DirectRelationId {
            TINY_RELATION
        }

        fn input_state(&self) -> &[Scalar; TINY_ARITY] {
            &self.input
        }
    }

    #[test]
    #[ignore = "performs transparent Nova setup and serializes prover state"]
    fn real_selected_prover_roundtrips_through_pk1() {
        let suite = NovaSessionSuite::<TINY_ARITY, TinyStep>::setup(TinyStep {
            input: [Scalar::from(7u64)],
        })
        .expect("setup tiny prover")
        .select_generated_for_qualification(TINY_VERSIONS)
        .expect("select tiny prover");
        let expected = suite.expected();
        let mut encoded = Cursor::new(Vec::new());
        let descriptor = suite
            .prover
            .write_artifact(&mut encoded)
            .expect("write tiny prover artifact");
        let encoded = encoded.into_inner();
        let loaded = SelectedNovaProver::<TINY_ARITY, TinyStep>::from_artifact(
            &encoded,
            expected,
            &descriptor,
        )
        .expect("reload tiny prover artifact");
        assert_eq!(loaded.expected(), expected);
    }
}
