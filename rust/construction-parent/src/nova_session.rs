//! Serialized one-thread Nova lifecycle for one exact direct relation.
//!
//! This module owns the generic fixed-template mechanics and the one frozen
//! construction-parent profile. Setup and proving compile only for
//! qualification; production loads the profile's authenticated verifier key.

use std::sync::Mutex;

#[cfg(test)]
use ff::PrimeField;
use nova_snark::{
    errors::NovaError,
    nova::{CompressedSNARK, VerifierKey},
    provider::ipa_pc,
    spartan::snark::RelaxedR1CSSNARK,
    traits::circuit::StepCircuit,
};
#[cfg(test)]
use nova_snark::{
    nova::{ProverKey, PublicParams, RecursiveSNARK},
    traits::snark::RelaxedR1CSSNARKTrait,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    fixed_serde::{
        FixedSerdeError, NovaCompressedProofShape, NovaR1csDimensions,
        NOVA_COMPRESSED_PROOF_CODEC_VERSION,
    },
    nova_types::{
        DirectNovaPrimaryEngine, DirectNovaScalar, DirectNovaSecondaryEngine, DirectRelationId,
        DIRECT_STEP_RELATION_ENCODING_VERSION,
    },
};

pub(crate) mod verifier_artifact;

type PrimaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaPrimaryEngine>;
type SecondaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaSecondaryEngine>;
type PrimarySnark = RelaxedR1CSSNARK<DirectNovaPrimaryEngine, PrimaryEvaluationEngine>;
type SecondarySnark = RelaxedR1CSSNARK<DirectNovaSecondaryEngine, SecondaryEvaluationEngine>;
#[cfg(test)]
type NovaPublicParams<C> = PublicParams<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C>;
#[cfg(test)]
type NovaRecursiveSnark<C> = RecursiveSNARK<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C>;
type NovaCompressedSnark<C> = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    C,
    PrimarySnark,
    SecondarySnark,
>;
#[cfg(test)]
type NovaProverKey<C> =
    ProverKey<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C, PrimarySnark, SecondarySnark>;
type NovaVerifierKey<C> = VerifierKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    C,
    PrimarySnark,
    SecondarySnark,
>;
#[cfg(test)]
type VerifierOnlyCompressedSnark<const ARITY: usize> = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    crate::nova_types::VerifierOnlyNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;
#[cfg(test)]
type VerifierOnlyKey<const ARITY: usize> = VerifierKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    crate::nova_types::VerifierOnlyNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;

#[cfg(any(test, feature = "prover"))]
pub(crate) trait NovaSessionStep<const ARITY: usize>: StepCircuit<DirectNovaScalar> {
    fn relation_id(&self) -> DirectRelationId;
    fn input_state(&self) -> &[DirectNovaScalar; ARITY];
}

const DIRECT_NOVA_SUITE_ID_TAG: &[u8] = b"Purify/Accountable/ConstructionParentNovaSuite/v2";
const DIRECT_NOVA_SUITE_ENCODING_VERSION: u8 = 2;
const NOVA_VERSION: [u8; 3] = [0, 76, 0];
const PRIMARY_ENGINE_SECQ256K1_SHA256: u8 = 1;
const SECONDARY_ENGINE_SECP256K1_SHA256: u8 = 2;
const FOLDING_SCHEME_NOVA: u8 = 1;
const COMPRESSION_SCHEME_SPARTAN: u8 = 1;
const EVALUATION_ENGINE_IPA_PC: u8 = 1;

macro_rules! construction_version {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) struct $name(u32);

        impl $name {
            const fn new(value: u32) -> Self {
                Self(value)
            }

            const fn value(self) -> u32 {
                self.0
            }
        }
    };
}

construction_version!(ConstructionPayloadVersion);
construction_version!(ConstructionStatementVersion);
construction_version!(ConstructionManifestVersion);
construction_version!(ConstructionNativeDecisionVersion);

/// Receipt-layer versions whose meanings are external to the Nova matrix.
///
/// The qualified profile below fixes one explicit combination. These versions
/// remain separate from the Nova matrix so a changed receipt meaning selects a
/// different suite ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectNovaConstructionVersions {
    payload: ConstructionPayloadVersion,
    statement: ConstructionStatementVersion,
    manifest: ConstructionManifestVersion,
    native_decision: ConstructionNativeDecisionVersion,
}

impl DirectNovaConstructionVersions {
    const fn new(
        payload: ConstructionPayloadVersion,
        statement: ConstructionStatementVersion,
        manifest: ConstructionManifestVersion,
        native_decision: ConstructionNativeDecisionVersion,
    ) -> Self {
        Self {
            payload,
            statement,
            manifest,
            native_decision,
        }
    }

    #[cfg(test)]
    pub(crate) const fn values(self) -> (u32, u32, u32, u32) {
        (
            self.payload.value(),
            self.statement.value(),
            self.manifest.value(),
            self.native_decision.value(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectNovaSuiteId([u8; 32]);

impl DirectNovaSuiteId {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum DirectNovaSessionError {
    #[error(transparent)]
    Nova(#[from] NovaError),
    #[error(transparent)]
    Codec(#[from] FixedSerdeError),
    #[error("direct Nova suite setup failed: {0}")]
    Setup(&'static str),
    #[error("direct Nova suite identity failed: {0}")]
    SuiteIdentity(&'static str),
    #[error("direct Nova selected suite mismatch: {0}")]
    SuiteMismatch(&'static str),
    #[cfg(test)]
    #[error("direct Nova step relation mismatch")]
    StepRelation,
    #[cfg(test)]
    #[error("direct Nova state continuity mismatch")]
    StateContinuity,
    #[error("direct Nova verified final state mismatch")]
    FinalState,
    #[error("direct Nova step count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
    #[error("direct Nova proof length mismatch: expected {expected}, actual {actual}")]
    ProofLength { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectNovaSuiteMetadata {
    pub(crate) relation_id: DirectRelationId,
    pub(crate) public_parameter_digest: [u8; 32],
    pub(crate) primary_constraints: usize,
    pub(crate) secondary_constraints: usize,
    pub(crate) primary_variables: usize,
    pub(crate) secondary_variables: usize,
    pub(crate) proof_length: usize,
    pub(crate) codec_sequence_count: usize,
}

impl DirectNovaSuiteMetadata {
    /// Commits to the complete local proof suite with BIP340 tagged SHA256.
    fn suite_id<const ARITY: usize>(
        &self,
        proof_shape: &NovaCompressedProofShape,
        construction: DirectNovaConstructionVersions,
    ) -> Result<DirectNovaSuiteId, DirectNovaSessionError> {
        if self.proof_length != proof_shape.encoded_len()
            || self.codec_sequence_count != proof_shape.sequence_count()
        {
            return Err(DirectNovaSessionError::SuiteIdentity(
                "proof codec metadata",
            ));
        }

        let tag_hash = Sha256::digest(DIRECT_NOVA_SUITE_ID_TAG);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        // Canonical body order is: two one-byte suite/relation versions; four
        // big-endian u32 receipt-layer versions; the three one-byte Nova
        // semantic-version components; six one-byte ordered
        // engine/backend/codec identifiers; big-endian u32 arity; relation
        // and PP digests; five big-endian u64 dimensions/lengths; then a
        // big-endian u32 schedule count and every schedule length as u32.
        digest.update([
            DIRECT_NOVA_SUITE_ENCODING_VERSION,
            DIRECT_STEP_RELATION_ENCODING_VERSION,
        ]);
        digest.update(construction.payload.value().to_be_bytes());
        digest.update(construction.statement.value().to_be_bytes());
        digest.update(construction.manifest.value().to_be_bytes());
        digest.update(construction.native_decision.value().to_be_bytes());
        digest.update(NOVA_VERSION);
        digest.update([
            PRIMARY_ENGINE_SECQ256K1_SHA256,
            SECONDARY_ENGINE_SECP256K1_SHA256,
            FOLDING_SCHEME_NOVA,
            COMPRESSION_SCHEME_SPARTAN,
            EVALUATION_ENGINE_IPA_PC,
            NOVA_COMPRESSED_PROOF_CODEC_VERSION,
        ]);
        digest.update(suite_u32(ARITY, "state arity")?.to_be_bytes());
        digest.update(self.relation_id.bytes());
        digest.update(self.public_parameter_digest);
        for (value, label) in [
            (self.primary_constraints, "primary constraints"),
            (self.primary_variables, "primary variables"),
            (self.secondary_constraints, "secondary constraints"),
            (self.secondary_variables, "secondary variables"),
            (self.proof_length, "proof length"),
        ] {
            digest.update(suite_u64(value, label)?.to_be_bytes());
        }
        digest
            .update(suite_u32(proof_shape.sequence_count(), "codec sequence count")?.to_be_bytes());
        for &length in proof_shape.suite_sequence_lengths() {
            digest.update(suite_u32(length, "codec sequence length")?.to_be_bytes());
        }
        Ok(DirectNovaSuiteId(digest.finalize().into()))
    }
}

fn suite_u32(value: usize, label: &'static str) -> Result<u32, DirectNovaSessionError> {
    u32::try_from(value).map_err(|_| DirectNovaSessionError::SuiteIdentity(label))
}

fn suite_u64(value: usize, label: &'static str) -> Result<u64, DirectNovaSessionError> {
    u64::try_from(value).map_err(|_| DirectNovaSessionError::SuiteIdentity(label))
}

fn suite_usize(value: u64, label: &'static str) -> Result<usize, DirectNovaSessionError> {
    usize::try_from(value).map_err(|_| DirectNovaSessionError::SuiteIdentity(label))
}

fn direct_nova_thread_pool() -> Result<ThreadPool, DirectNovaSessionError> {
    ThreadPoolBuilder::new()
        .num_threads(1)
        .thread_name(|_| "purify-direct-nova".to_owned())
        .build()
        .map_err(|_| DirectNovaSessionError::Setup("one-thread Rayon pool"))
}

#[cfg(test)]
pub(crate) struct NovaSessionSuite<const ARITY: usize, C: NovaSessionStep<ARITY>> {
    public_params: NovaPublicParams<C>,
    prover_key: NovaProverKey<C>,
    verifier: NovaVerifier<ARITY, C>,
}

/// Verification-only state for one fixed direct Nova suite.
///
/// This deliberately contains no relation template, public parameters, or
/// prover key. Converting a suite into this type is a one-way release of all
/// proving capability.
pub(crate) struct NovaVerifier<const ARITY: usize, C: StepCircuit<DirectNovaScalar>> {
    verifier_key: NovaVerifierKey<C>,
    proof_shape: NovaCompressedProofShape,
    #[cfg(test)]
    metadata: DirectNovaSuiteMetadata,
    pool: ThreadPool,
    operation: Mutex<()>,
}

type DirectNovaVerifierCircuit<const ARITY: usize> = crate::nova_types::VerifierOnlyNovaStep<ARITY>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenNovaDimensions {
    constraints: u64,
    variables: u64,
}

impl FrozenNovaDimensions {
    const fn new(constraints: u64, variables: u64) -> Self {
        Self {
            constraints,
            variables,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenNovaProofMetrics {
    encoded_length: u64,
    sequence_count: u32,
}

impl FrozenNovaProofMetrics {
    const fn new(encoded_length: u64, sequence_count: u32) -> Self {
        Self {
            encoded_length,
            sequence_count,
        }
    }
}

/// One locally selected suite. Receipts and peers never construct this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedDirectNovaSuite {
    construction_versions: DirectNovaConstructionVersions,
    relation_id: [u8; 32],
    public_parameter_digest: [u8; 32],
    primary: FrozenNovaDimensions,
    secondary: FrozenNovaDimensions,
    proof: FrozenNovaProofMetrics,
    suite_id: DirectNovaSuiteId,
}

impl ExpectedDirectNovaSuite {
    const fn new(
        construction_versions: DirectNovaConstructionVersions,
        relation_id: [u8; 32],
        public_parameter_digest: [u8; 32],
        primary: FrozenNovaDimensions,
        secondary: FrozenNovaDimensions,
        proof: FrozenNovaProofMetrics,
        suite_id: DirectNovaSuiteId,
    ) -> Self {
        Self {
            construction_versions,
            relation_id,
            public_parameter_digest,
            primary,
            secondary,
            proof,
            suite_id,
        }
    }

    #[cfg(test)]
    pub(crate) const fn suite_id(&self) -> DirectNovaSuiteId {
        self.suite_id
    }

    fn precheck_relation(
        &self,
        relation_id: DirectRelationId,
    ) -> Result<(), DirectNovaSessionError> {
        if relation_id.bytes() != &self.relation_id {
            return Err(DirectNovaSessionError::SuiteMismatch("relation ID"));
        }
        Ok(())
    }

    fn validate<const ARITY: usize>(
        &self,
        metadata: &DirectNovaSuiteMetadata,
        proof_shape: &NovaCompressedProofShape,
    ) -> Result<(), DirectNovaSessionError> {
        self.precheck_relation(metadata.relation_id)?;
        if metadata.public_parameter_digest != self.public_parameter_digest {
            return Err(DirectNovaSessionError::SuiteMismatch(
                "public-parameter digest",
            ));
        }
        for (actual, expected, label) in [
            (
                suite_u64(metadata.primary_constraints, "primary constraints")?,
                self.primary.constraints,
                "primary constraints",
            ),
            (
                suite_u64(metadata.secondary_constraints, "secondary constraints")?,
                self.secondary.constraints,
                "secondary constraints",
            ),
            (
                suite_u64(metadata.primary_variables, "primary variables")?,
                self.primary.variables,
                "primary variables",
            ),
            (
                suite_u64(metadata.secondary_variables, "secondary variables")?,
                self.secondary.variables,
                "secondary variables",
            ),
            (
                suite_u64(metadata.proof_length, "proof length")?,
                self.proof.encoded_length,
                "proof length",
            ),
        ] {
            if actual != expected {
                return Err(DirectNovaSessionError::SuiteMismatch(label));
            }
        }
        if suite_u32(metadata.codec_sequence_count, "codec sequence count")?
            != self.proof.sequence_count
        {
            return Err(DirectNovaSessionError::SuiteMismatch(
                "codec sequence count",
            ));
        }
        let suite_id = metadata.suite_id::<ARITY>(proof_shape, self.construction_versions)?;
        if suite_id != self.suite_id {
            return Err(DirectNovaSessionError::SuiteMismatch("suite ID"));
        }
        Ok(())
    }

    /// Reconstructs verifier metadata exclusively from this local profile.
    fn local_verifier_components<const ARITY: usize>(
        &self,
    ) -> Result<(DirectNovaSuiteMetadata, NovaCompressedProofShape), DirectNovaSessionError> {
        let primary_constraints = suite_usize(self.primary.constraints, "primary constraints")?;
        let primary_variables = suite_usize(self.primary.variables, "primary variables")?;
        let secondary_constraints =
            suite_usize(self.secondary.constraints, "secondary constraints")?;
        let secondary_variables = suite_usize(self.secondary.variables, "secondary variables")?;
        let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
            NovaR1csDimensions::new(primary_constraints, primary_variables),
            NovaR1csDimensions::new(secondary_constraints, secondary_variables),
            ARITY,
        )?;
        let metadata = DirectNovaSuiteMetadata {
            relation_id: DirectRelationId::from_frozen_bytes(self.relation_id),
            public_parameter_digest: self.public_parameter_digest,
            primary_constraints,
            secondary_constraints,
            primary_variables,
            secondary_variables,
            proof_length: proof_shape.encoded_len(),
            codec_sequence_count: proof_shape.sequence_count(),
        };
        self.validate::<ARITY>(&metadata, &proof_shape)?;
        Ok((metadata, proof_shape))
    }
}

const QUALIFIED_CONSTRUCTION_PAYLOAD_VERSION: ConstructionPayloadVersion =
    ConstructionPayloadVersion::new(4);
const QUALIFIED_CONSTRUCTION_STATEMENT_VERSION: ConstructionStatementVersion =
    ConstructionStatementVersion::new(5);
const QUALIFIED_CONSTRUCTION_MANIFEST_VERSION: ConstructionManifestVersion =
    ConstructionManifestVersion::new(3);

/// Candidate-decision v1 binds `CandidateAccumStep/v1` and the native linear
/// decision over `point:33 || scale:32 || factors:15*32`, the current 545-byte
/// construction-root semantics.
const QUALIFIED_NATIVE_CANDIDATE_DECISION_VERSION: ConstructionNativeDecisionVersion =
    ConstructionNativeDecisionVersion::new(1);
pub(crate) const QUALIFIED_CONSTRUCTION_VERSIONS: DirectNovaConstructionVersions =
    DirectNovaConstructionVersions::new(
        QUALIFIED_CONSTRUCTION_PAYLOAD_VERSION,
        QUALIFIED_CONSTRUCTION_STATEMENT_VERSION,
        QUALIFIED_CONSTRUCTION_MANIFEST_VERSION,
        QUALIFIED_NATIVE_CANDIDATE_DECISION_VERSION,
    );

const QUALIFIED_CONSTRUCTION_PARENT_RELATION_ID: [u8; 32] = [
    0xa6, 0x6c, 0x58, 0xa8, 0x6a, 0xfc, 0xe6, 0x4b, 0x2b, 0x69, 0xd5, 0x3e, 0x83, 0xd3, 0xd5, 0x43,
    0x0d, 0x08, 0x0f, 0xaf, 0x0b, 0x68, 0x06, 0x4c, 0xad, 0xb3, 0xa6, 0xd8, 0xb4, 0x39, 0xee, 0xa9,
];
const QUALIFIED_CONSTRUCTION_PARENT_PP_DIGEST: [u8; 32] = [
    0x12, 0x4d, 0x07, 0x56, 0x20, 0x3e, 0xbf, 0x5b, 0x41, 0x6b, 0x6f, 0x12, 0x30, 0x35, 0x6e, 0xf9,
    0x92, 0x1f, 0xb3, 0x05, 0x38, 0xa8, 0xf7, 0xfc, 0xeb, 0xb1, 0x06, 0x18, 0x19, 0x49, 0x71, 0x00,
];
const QUALIFIED_CONSTRUCTION_PARENT_SUITE_ID: DirectNovaSuiteId = DirectNovaSuiteId::new([
    0xcc, 0xba, 0x9e, 0xd4, 0xb0, 0xee, 0xc0, 0x37, 0xc8, 0xdc, 0x34, 0xbf, 0x33, 0xfd, 0x29, 0x2c,
    0xc4, 0x76, 0x37, 0x5e, 0xc4, 0x70, 0x0a, 0x36, 0xc0, 0x70, 0xe3, 0x71, 0x0d, 0xd1, 0xa9, 0x02,
]);
pub(crate) const QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH: usize = 15_076;

/// Exact mixed construction-parent profile selected by qualification.
pub(crate) static QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE: ExpectedDirectNovaSuite =
    ExpectedDirectNovaSuite::new(
        QUALIFIED_CONSTRUCTION_VERSIONS,
        QUALIFIED_CONSTRUCTION_PARENT_RELATION_ID,
        QUALIFIED_CONSTRUCTION_PARENT_PP_DIGEST,
        FrozenNovaDimensions::new(9_418_542, 9_372_224),
        FrozenNovaDimensions::new(728_974, 728_211),
        FrozenNovaProofMetrics::new(QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH as u64, 152),
        QUALIFIED_CONSTRUCTION_PARENT_SUITE_ID,
    );

/// A generic suite promoted through one exact local selection profile.
#[cfg(test)]
pub(crate) struct SelectedNovaSessionSuite<const ARITY: usize, C: NovaSessionStep<ARITY>> {
    expected: &'static ExpectedDirectNovaSuite,
    inner: NovaSessionSuite<ARITY, C>,
}

/// A verification-only context promoted through one exact local profile.
pub(crate) struct SelectedNovaVerifier<const ARITY: usize, C: StepCircuit<DirectNovaScalar>> {
    expected: &'static ExpectedDirectNovaSuite,
    inner: NovaVerifier<ARITY, C>,
}

pub(crate) type SelectedDirectNovaVerifier<const ARITY: usize> =
    SelectedNovaVerifier<ARITY, DirectNovaVerifierCircuit<ARITY>>;

#[cfg(test)]
impl<const ARITY: usize, C: NovaSessionStep<ARITY>> NovaSessionSuite<ARITY, C> {
    /// Builds an unselected suite for internal experiments and test tools.
    #[cfg(test)]
    pub(crate) fn setup(trusted_step: C) -> Result<Self, DirectNovaSessionError> {
        Self::setup_prepared(trusted_step)
    }

    /// Promotes one freshly generated qualification suite under its exact
    /// metadata and receipt-layer versions.
    ///
    /// The leaked profile is scoped to the resource-gated test process. It is
    /// deliberately not reachable by the production artifact loader, which
    /// remains pinned and fail-closed until these outputs are reviewed.
    pub(crate) fn select_generated_for_qualification(
        self,
        construction_versions: DirectNovaConstructionVersions,
    ) -> Result<SelectedNovaSessionSuite<ARITY, C>, DirectNovaSessionError> {
        let metadata = self.verifier.metadata;
        let suite_id =
            metadata.suite_id::<ARITY>(&self.verifier.proof_shape, construction_versions)?;
        let expected = Box::leak(Box::new(ExpectedDirectNovaSuite::new(
            construction_versions,
            *metadata.relation_id.bytes(),
            metadata.public_parameter_digest,
            FrozenNovaDimensions::new(
                suite_u64(metadata.primary_constraints, "primary constraints")?,
                suite_u64(metadata.primary_variables, "primary variables")?,
            ),
            FrozenNovaDimensions::new(
                suite_u64(metadata.secondary_constraints, "secondary constraints")?,
                suite_u64(metadata.secondary_variables, "secondary variables")?,
            ),
            FrozenNovaProofMetrics::new(
                suite_u64(metadata.proof_length, "proof length")?,
                suite_u32(metadata.codec_sequence_count, "codec sequence count")?,
            ),
            suite_id,
        )));
        expected.validate::<ARITY>(&metadata, &self.verifier.proof_shape)?;
        Ok(SelectedNovaSessionSuite {
            expected,
            inner: self,
        })
    }

    /// Qualifies a suite only after its relation and complete resulting
    /// metadata match one local profile. Production acceptance loads the
    /// resulting frozen verifier artifact; it never performs setup.
    pub(crate) fn setup_exact(
        trusted_step: C,
        expected: &'static ExpectedDirectNovaSuite,
    ) -> Result<SelectedNovaSessionSuite<ARITY, C>, DirectNovaSessionError> {
        expected.precheck_relation(trusted_step.relation_id())?;
        let suite = Self::setup_prepared(trusted_step)?;
        expected.validate::<ARITY>(&suite.verifier.metadata, &suite.verifier.proof_shape)?;
        Ok(SelectedNovaSessionSuite {
            expected,
            inner: suite,
        })
    }

    fn setup_prepared(trusted_step: C) -> Result<Self, DirectNovaSessionError> {
        let relation_id = trusted_step.relation_id();
        let pool = direct_nova_thread_pool()?;

        let (public_params, prover_key, verifier_key, proof_shape, metadata) =
            pool.install(move || -> Result<_, DirectNovaSessionError> {
                let public_params = NovaPublicParams::<C>::setup(
                    &trusted_step,
                    &*PrimarySnark::ck_floor(),
                    &*SecondarySnark::ck_floor(),
                )?;
                drop(trusted_step);
                let (primary_constraints, secondary_constraints) = public_params.num_constraints();
                let (primary_variables, secondary_variables) = public_params.num_variables();
                let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
                    NovaR1csDimensions::new(primary_constraints, primary_variables),
                    NovaR1csDimensions::new(secondary_constraints, secondary_variables),
                    ARITY,
                )?;
                let (prover_key, verifier_key) = NovaCompressedSnark::<C>::setup(&public_params)?;
                let digest_repr = public_params.digest().to_repr();
                let public_parameter_digest = digest_repr
                    .as_ref()
                    .try_into()
                    .map_err(|_| DirectNovaSessionError::Setup("public-parameter digest width"))?;
                let metadata = DirectNovaSuiteMetadata {
                    relation_id,
                    public_parameter_digest,
                    primary_constraints,
                    secondary_constraints,
                    primary_variables,
                    secondary_variables,
                    proof_length: proof_shape.encoded_len(),
                    codec_sequence_count: proof_shape.sequence_count(),
                };
                Ok((
                    public_params,
                    prover_key,
                    verifier_key,
                    proof_shape,
                    metadata,
                ))
            })?;

        Ok(Self {
            public_params,
            prover_key,
            verifier: NovaVerifier {
                verifier_key,
                proof_shape,
                metadata,
                pool,
                operation: Mutex::new(()),
            },
        })
    }

    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.verifier.metadata()
    }

    pub(crate) fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
    ) -> Result<NovaProverSession<'_, ARITY, C>, DirectNovaSessionError> {
        if expected_steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        Ok(NovaProverSession {
            suite: self,
            initial_state,
            current_state: initial_state,
            expected_steps,
            completed_steps: 0,
            recursive: None,
        })
    }

    fn serialized<T: Send>(
        &self,
        operation: impl FnOnce() -> Result<T, DirectNovaSessionError> + Send,
    ) -> Result<T, DirectNovaSessionError> {
        self.verifier.serialized(operation)
    }

    fn into_verifier(self) -> NovaVerifier<ARITY, C> {
        self.verifier
    }
}

impl<const ARITY: usize, C: StepCircuit<DirectNovaScalar>> NovaVerifier<ARITY, C> {
    fn from_loaded_key(
        verifier_key: NovaVerifierKey<C>,
        proof_shape: NovaCompressedProofShape,
        metadata: DirectNovaSuiteMetadata,
    ) -> Result<Self, DirectNovaSessionError> {
        #[cfg(not(test))]
        let _ = metadata;
        Ok(Self {
            verifier_key,
            proof_shape,
            #[cfg(test)]
            metadata,
            pool: direct_nova_thread_pool()?,
            operation: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.metadata
    }

    /// Verifies the proof against the exact initial state and external step
    /// count, returning its authenticated recurrence output.
    pub(crate) fn verify_final(
        &self,
        initial_state: &[DirectNovaScalar; ARITY],
        expected_steps: usize,
        proof: &[u8],
    ) -> Result<[DirectNovaScalar; ARITY], DirectNovaSessionError> {
        if expected_steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        if proof.len() != self.proof_shape.encoded_len() {
            return Err(DirectNovaSessionError::ProofLength {
                expected: self.proof_shape.encoded_len(),
                actual: proof.len(),
            });
        }

        self.serialized(|| {
            let shape = self.proof_shape.as_fixed_serde_shape();
            let compressed = shape.decode_canonical::<NovaCompressedSnark<C>>(proof)?;
            let final_state =
                compressed.verify(&self.verifier_key, expected_steps, initial_state)?;
            final_state
                .try_into()
                .map_err(|_| DirectNovaSessionError::FinalState)
        })
    }

    #[cfg(test)]
    pub(crate) fn verify_exact(
        &self,
        initial_state: &[DirectNovaScalar; ARITY],
        expected_steps: usize,
        expected_final_state: &[DirectNovaScalar; ARITY],
        proof: &[u8],
    ) -> Result<(), DirectNovaSessionError> {
        if self.verify_final(initial_state, expected_steps, proof)? != *expected_final_state {
            return Err(DirectNovaSessionError::FinalState);
        }
        Ok(())
    }

    fn serialized<T: Send>(
        &self,
        operation: impl FnOnce() -> Result<T, DirectNovaSessionError> + Send,
    ) -> Result<T, DirectNovaSessionError> {
        let _guard = self
            .operation
            .lock()
            .expect("direct Nova suite operation mutex poisoned");
        self.pool.install(operation)
    }
}

#[cfg(test)]
impl<const ARITY: usize, C: NovaSessionStep<ARITY>> SelectedNovaSessionSuite<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static ExpectedDirectNovaSuite {
        self.expected
    }

    #[cfg(test)]
    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.inner.metadata()
    }

    pub(crate) fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
    ) -> Result<NovaProverSession<'_, ARITY, C>, DirectNovaSessionError> {
        self.inner.start(initial_state, expected_steps)
    }

    /// Permanently releases every proving component while retaining the
    /// exact selected verifier.
    pub(crate) fn into_verifier(self) -> SelectedNovaVerifier<ARITY, C> {
        SelectedNovaVerifier {
            expected: self.expected,
            inner: self.inner.into_verifier(),
        }
    }
}

impl<const ARITY: usize, C: StepCircuit<DirectNovaScalar>> SelectedNovaVerifier<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static ExpectedDirectNovaSuite {
        self.expected
    }

    #[cfg(test)]
    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.inner.metadata()
    }

    /// Authenticates the recurrence output under this selected suite.
    ///
    /// The returned state is not construction-receipt acceptance: the
    /// construction wrapper must still bind its verifier-derived suffix and
    /// complete the native final accumulation decision.
    pub(crate) fn verify_final(
        &self,
        initial_state: &[DirectNovaScalar; ARITY],
        expected_steps: usize,
        proof: &[u8],
    ) -> Result<[DirectNovaScalar; ARITY], DirectNovaSessionError> {
        self.inner
            .verify_final(initial_state, expected_steps, proof)
    }

    /// Verifies only the caller's exact statement. The proof supplies neither
    /// suite metadata nor its own recursive step count.
    #[cfg(test)]
    pub(crate) fn verify_exact(
        &self,
        initial_state: &[DirectNovaScalar; ARITY],
        expected_steps: usize,
        expected_final_state: &[DirectNovaScalar; ARITY],
        proof: &[u8],
    ) -> Result<(), DirectNovaSessionError> {
        self.inner
            .verify_exact(initial_state, expected_steps, expected_final_state, proof)
    }
}

#[cfg(test)]
pub(crate) struct NovaProverSession<'suite, const ARITY: usize, C: NovaSessionStep<ARITY>> {
    suite: &'suite NovaSessionSuite<ARITY, C>,
    initial_state: [DirectNovaScalar; ARITY],
    current_state: [DirectNovaScalar; ARITY],
    expected_steps: usize,
    completed_steps: usize,
    recursive: Option<NovaRecursiveSnark<C>>,
}

#[cfg(test)]
fn validate_step_relation<const ARITY: usize, C: NovaSessionStep<ARITY>>(
    expected: DirectRelationId,
    step: &C,
) -> Result<(), DirectNovaSessionError> {
    if step.relation_id() != expected {
        return Err(DirectNovaSessionError::StepRelation);
    }
    Ok(())
}

#[cfg(test)]
impl<const ARITY: usize, C: NovaSessionStep<ARITY>> NovaProverSession<'_, ARITY, C> {
    /// Consumes the session on both success and failure, so a partially
    /// mutated Nova proof can never be retried as if the fold were atomic.
    pub(crate) fn add_step(mut self, step: C) -> Result<Self, DirectNovaSessionError> {
        if self.completed_steps >= self.expected_steps {
            return Err(DirectNovaSessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps + 1,
            });
        }
        validate_step_relation(self.suite.verifier.metadata.relation_id, &step)?;
        if step.input_state() != &self.current_state {
            return Err(DirectNovaSessionError::StateContinuity);
        }

        let recursive = &mut self.recursive;
        self.suite.serialized(|| {
            if let Some(recursive) = recursive.as_mut() {
                recursive.prove_step(&self.suite.public_params, &step)?;
            } else {
                let mut first = NovaRecursiveSnark::<C>::new(
                    &self.suite.public_params,
                    &step,
                    &self.initial_state,
                )?;
                // `new` executes the first circuit with internal `i = 0`.
                // The first prove call advances the counter to one without
                // executing the circuit a second time.
                first.prove_step(&self.suite.public_params, &step)?;
                if first.num_steps() != 1 {
                    return Err(DirectNovaSessionError::StepCount {
                        expected: 1,
                        actual: first.num_steps(),
                    });
                }
                *recursive = Some(first);
            }
            Ok(())
        })?;

        self.current_state = self
            .recursive
            .as_ref()
            .ok_or(DirectNovaSessionError::FinalState)?
            .outputs()
            .try_into()
            .map_err(|_| DirectNovaSessionError::FinalState)?;
        self.completed_steps += 1;
        Ok(self)
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, DirectNovaSessionError> {
        if self.completed_steps != self.expected_steps {
            return Err(DirectNovaSessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps,
            });
        }
        let recursive = self.recursive.ok_or(DirectNovaSessionError::StepCount {
            expected: self.expected_steps,
            actual: 0,
        })?;

        self.suite.serialized(|| {
            let verified = recursive.verify(
                &self.suite.public_params,
                self.completed_steps,
                &self.initial_state,
            )?;
            if verified.as_slice() != self.current_state {
                return Err(DirectNovaSessionError::FinalState);
            }
            let compressed = NovaCompressedSnark::<C>::prove_owned(
                &self.suite.public_params,
                &self.suite.prover_key,
                recursive,
            )?;
            Ok(self
                .suite
                .verifier
                .proof_shape
                .as_fixed_serde_shape()
                .encode(&compressed)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use nova_snark::frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};

    use super::verifier_artifact::{
        DirectNovaVerifierArtifactError, ExpectedDirectNovaVerifierArtifact,
    };
    use super::*;
    use crate::{nova_relation_identity::direct_step_relation_shape, Scalar};

    const TEST_ARITY: usize = 20;

    const TEST_CONSTRUCTION_VERSIONS: DirectNovaConstructionVersions =
        DirectNovaConstructionVersions::new(
            ConstructionPayloadVersion::new(0x0102_0304),
            ConstructionStatementVersion::new(0x1112_1314),
            ConstructionManifestVersion::new(0x2122_2324),
            ConstructionNativeDecisionVersion::new(0x3132_3334),
        );
    const TEST_SUITE_ID: DirectNovaSuiteId = DirectNovaSuiteId::new([
        0x75, 0xaf, 0xf8, 0x3f, 0x39, 0x05, 0x05, 0x67, 0x86, 0x99, 0x2a, 0xb4, 0x24, 0x9f, 0x29,
        0x4b, 0x6b, 0x62, 0xab, 0x02, 0x64, 0x69, 0xfa, 0xad, 0x60, 0xfa, 0xb4, 0xfb, 0x3c, 0x47,
        0xed, 0x03,
    ]);

    fn source_state(seed: u64) -> [Scalar; TEST_ARITY] {
        std::array::from_fn(|index| Scalar::from(seed + index as u64))
    }

    fn increment(state: [Scalar; TEST_ARITY]) -> [Scalar; TEST_ARITY] {
        state.map(|value| value + Scalar::ONE)
    }

    #[derive(Clone)]
    struct TestSessionStep {
        input_state: [Scalar; TEST_ARITY],
        increment: bool,
    }

    impl TestSessionStep {
        fn new(input_state: [Scalar; TEST_ARITY], increment: bool) -> Self {
            Self {
                input_state,
                increment,
            }
        }
    }

    impl StepCircuit<Scalar> for TestSessionStep {
        fn arity(&self) -> usize {
            TEST_ARITY
        }

        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            cs: &mut CS,
            z: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            if z.len() != TEST_ARITY {
                return Err(SynthesisError::Unsatisfiable(
                    "test session state arity".to_owned(),
                ));
            }
            if !self.increment {
                return Ok(z.to_vec());
            }
            z.iter()
                .enumerate()
                .map(|(index, input)| {
                    let next = AllocatedNum::alloc(
                        cs.namespace(|| format!("next state {index}")),
                        || {
                            input
                                .get_value()
                                .map(|value| value + Scalar::ONE)
                                .ok_or(SynthesisError::AssignmentMissing)
                        },
                    )?;
                    cs.enforce(
                        || format!("increment state {index}"),
                        |linear| linear + input.get_variable() + CS::one(),
                        |linear| linear + CS::one(),
                        |linear| linear + next.get_variable(),
                    );
                    Ok(next)
                })
                .collect()
        }
    }

    impl NovaSessionStep<TEST_ARITY> for TestSessionStep {
        fn relation_id(&self) -> DirectRelationId {
            direct_step_relation_shape::<TEST_ARITY, _>(self)
                .expect("test session relation")
                .relation_id()
        }

        fn input_state(&self) -> &[Scalar; TEST_ARITY] {
            &self.input_state
        }
    }

    fn fixed_suite_fixture() -> (DirectNovaSuiteMetadata, NovaCompressedProofShape) {
        let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
            NovaR1csDimensions::new(101, 103),
            NovaR1csDimensions::new(107, 109),
            TEST_ARITY,
        )
        .expect("synthetic suite proof shape");
        let metadata = DirectNovaSuiteMetadata {
            relation_id: DirectRelationId::from_frozen_bytes([0x11; 32]),
            public_parameter_digest: [0x22; 32],
            primary_constraints: 101,
            secondary_constraints: 107,
            primary_variables: 103,
            secondary_variables: 109,
            proof_length: proof_shape.encoded_len(),
            codec_sequence_count: proof_shape.sequence_count(),
        };
        (metadata, proof_shape)
    }

    #[test]
    fn bound_step_with_another_shape_fails_relation_check() {
        let trusted = TestSessionStep::new(source_state(3), true);
        let different = TestSessionStep::new(source_state(3), false);

        assert!(validate_step_relation(trusted.relation_id(), &trusted).is_ok());
        assert_eq!(
            validate_step_relation(trusted.relation_id(), &different),
            Err(DirectNovaSessionError::StepRelation)
        );
    }

    #[test]
    fn suite_id_has_a_fixed_codec_complete_encoding() {
        let (metadata, proof_shape) = fixed_suite_fixture();
        let suite_id = metadata
            .suite_id::<TEST_ARITY>(&proof_shape, TEST_CONSTRUCTION_VERSIONS)
            .expect("tiny suite ID");
        eprintln!(
            "tiny_sha256_suite_id={:02x?}\nmetadata={metadata:#?}",
            suite_id.bytes()
        );
        assert_eq!(suite_id, TEST_SUITE_ID);

        let mut changed_schedule = proof_shape.clone();
        changed_schedule.increment_suite_sequence_length_for_test(7);
        assert_ne!(
            metadata
                .suite_id::<TEST_ARITY>(&changed_schedule, TEST_CONSTRUCTION_VERSIONS)
                .expect("changed codec schedule suite ID"),
            suite_id
        );

        let mut changed_metadata = metadata;
        changed_metadata.public_parameter_digest[0] ^= 1;
        assert_ne!(
            changed_metadata
                .suite_id::<TEST_ARITY>(&proof_shape, TEST_CONSTRUCTION_VERSIONS)
                .expect("changed suite ID"),
            suite_id
        );
        assert_ne!(
            metadata
                .suite_id::<TEST_ARITY>(
                    &proof_shape,
                    DirectNovaConstructionVersions::new(
                        ConstructionPayloadVersion::new(0x0102_0305),
                        ConstructionStatementVersion::new(0x1112_1314),
                        ConstructionManifestVersion::new(0x2122_2324),
                        ConstructionNativeDecisionVersion::new(0x3132_3334),
                    ),
                )
                .expect("changed construction version suite ID"),
            suite_id
        );

        let mut inconsistent = metadata;
        inconsistent.proof_length += 1;
        assert!(matches!(
            inconsistent.suite_id::<TEST_ARITY>(&proof_shape, TEST_CONSTRUCTION_VERSIONS),
            Err(DirectNovaSessionError::SuiteIdentity(
                "proof codec metadata"
            ))
        ));
    }

    #[test]
    fn qualified_construction_parent_suite_frame_is_frozen() {
        let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
            NovaR1csDimensions::new(9_418_542, 9_372_224),
            NovaR1csDimensions::new(728_974, 728_211),
            TEST_ARITY,
        )
        .expect("qualified SHA-256 proof shape");
        assert_eq!(
            proof_shape.encoded_len(),
            QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH
        );
        assert_eq!(proof_shape.sequence_count(), 152);

        let metadata = DirectNovaSuiteMetadata {
            relation_id: DirectRelationId::from_frozen_bytes(
                QUALIFIED_CONSTRUCTION_PARENT_RELATION_ID,
            ),
            public_parameter_digest: QUALIFIED_CONSTRUCTION_PARENT_PP_DIGEST,
            primary_constraints: 9_418_542,
            primary_variables: 9_372_224,
            secondary_constraints: 728_974,
            secondary_variables: 728_211,
            proof_length: proof_shape.encoded_len(),
            codec_sequence_count: proof_shape.sequence_count(),
        };
        let suite_id = metadata
            .suite_id::<TEST_ARITY>(&proof_shape, QUALIFIED_CONSTRUCTION_VERSIONS)
            .expect("qualified SHA-256 suite ID");
        assert_eq!(suite_id, QUALIFIED_CONSTRUCTION_PARENT_SUITE_ID);
        QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE
            .validate::<TEST_ARITY>(&metadata, &proof_shape)
            .expect("qualified SHA-256 suite profile");
    }

    const TEST_EXPECTED_SUITE: ExpectedDirectNovaSuite = ExpectedDirectNovaSuite::new(
        TEST_CONSTRUCTION_VERSIONS,
        [0x11; 32],
        [0x22; 32],
        FrozenNovaDimensions::new(101, 103),
        FrozenNovaDimensions::new(107, 109),
        FrozenNovaProofMetrics::new(6_376, 62),
        TEST_SUITE_ID,
    );
    const TEST_WRONG_RELATION_SUITE: ExpectedDirectNovaSuite = ExpectedDirectNovaSuite::new(
        TEST_CONSTRUCTION_VERSIONS,
        [0; 32],
        [0x22; 32],
        FrozenNovaDimensions::new(101, 103),
        FrozenNovaDimensions::new(107, 109),
        FrozenNovaProofMetrics::new(6_376, 62),
        TEST_SUITE_ID,
    );
    #[test]
    fn exact_suite_profile_rejects_every_metadata_drift() {
        let (metadata, proof_shape) = fixed_suite_fixture();
        let expected = TEST_EXPECTED_SUITE;
        expected
            .validate::<TEST_ARITY>(&metadata, &proof_shape)
            .expect("exact local suite profile");

        let mut changed = expected;
        changed.relation_id[0] ^= 1;
        assert!(matches!(
            changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
            Err(DirectNovaSessionError::SuiteMismatch("relation ID"))
        ));

        let mut changed = expected;
        changed.public_parameter_digest[0] ^= 1;
        assert!(matches!(
            changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
            Err(DirectNovaSessionError::SuiteMismatch(
                "public-parameter digest"
            ))
        ));

        for label in [
            "primary constraints",
            "secondary constraints",
            "primary variables",
            "secondary variables",
            "proof length",
        ] {
            let mut changed = expected;
            match label {
                "primary constraints" => changed.primary.constraints += 1,
                "secondary constraints" => changed.secondary.constraints += 1,
                "primary variables" => changed.primary.variables += 1,
                "secondary variables" => changed.secondary.variables += 1,
                "proof length" => changed.proof.encoded_length += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
                Err(DirectNovaSessionError::SuiteMismatch(label))
            );
        }

        let mut changed = expected;
        changed.proof.sequence_count += 1;
        assert!(matches!(
            changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
            Err(DirectNovaSessionError::SuiteMismatch(
                "codec sequence count"
            ))
        ));

        let mut changed = expected;
        changed.construction_versions = DirectNovaConstructionVersions::new(
            ConstructionPayloadVersion::new(0x0102_0305),
            ConstructionStatementVersion::new(0x1112_1314),
            ConstructionManifestVersion::new(0x2122_2324),
            ConstructionNativeDecisionVersion::new(0x3132_3334),
        );
        assert!(matches!(
            changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
            Err(DirectNovaSessionError::SuiteMismatch("suite ID"))
        ));

        let mut changed = expected;
        changed.suite_id = DirectNovaSuiteId::new([0x55; 32]);
        assert!(matches!(
            changed.validate::<TEST_ARITY>(&metadata, &proof_shape),
            Err(DirectNovaSessionError::SuiteMismatch("suite ID"))
        ));
    }

    #[test]
    fn exact_suite_prechecks_relation_before_parameter_setup() {
        let trusted_step = TestSessionStep::new(source_state(3), true);
        assert!(matches!(
            NovaSessionSuite::<TEST_ARITY, TestSessionStep>::setup_exact(
                trusted_step,
                &TEST_WRONG_RELATION_SUITE,
            ),
            Err(DirectNovaSessionError::SuiteMismatch("relation ID"))
        ));
    }

    #[test]
    #[ignore = "explicit slow real two-step Nova session"]
    fn tiny_twenty_state_session_round_trips_canonically() {
        let source_z0 = source_state(3);
        let source_z1 = increment(source_z0);
        let source_z2 = increment(source_z1);
        let z0 = source_z0;
        let z1 = source_z1;
        let z2 = source_z2;

        let trusted_step = TestSessionStep::new(source_z0, true);
        let first_step = TestSessionStep::new(source_z0, true);
        let second_step = TestSessionStep::new(source_z1, true);
        let suite = NovaSessionSuite::<TEST_ARITY, TestSessionStep>::setup(trusted_step)
            .expect("unselected tiny direct Nova suite");
        let metadata = suite.metadata();
        let proof_shape = suite.verifier.proof_shape.clone();
        let suite_id = metadata
            .suite_id::<TEST_ARITY>(&proof_shape, TEST_CONSTRUCTION_VERSIONS)
            .expect("tiny suite ID");
        let expected = Box::leak(Box::new(ExpectedDirectNovaSuite::new(
            TEST_CONSTRUCTION_VERSIONS,
            *metadata.relation_id.bytes(),
            metadata.public_parameter_digest,
            FrozenNovaDimensions::new(
                u64::try_from(metadata.primary_constraints).expect("primary constraints fit u64"),
                u64::try_from(metadata.primary_variables).expect("primary variables fit u64"),
            ),
            FrozenNovaDimensions::new(
                u64::try_from(metadata.secondary_constraints)
                    .expect("secondary constraints fit u64"),
                u64::try_from(metadata.secondary_variables).expect("secondary variables fit u64"),
            ),
            FrozenNovaProofMetrics::new(
                u64::try_from(metadata.proof_length).expect("proof length fits u64"),
                u32::try_from(metadata.codec_sequence_count).expect("sequence count fits u32"),
            ),
            suite_id,
        )));
        expected
            .validate::<TEST_ARITY>(&metadata, &proof_shape)
            .expect("derived tiny suite profile");
        let selected = SelectedNovaSessionSuite {
            expected,
            inner: suite,
        };
        assert_eq!(selected.expected(), expected);

        let incomplete = selected.start(z0, 2).expect("incomplete session");
        assert!(matches!(
            incomplete.finish(),
            Err(DirectNovaSessionError::StepCount {
                expected: 2,
                actual: 0
            })
        ));

        let discontinuous = selected
            .start(z0, 2)
            .expect("discontinuous session")
            .add_step(second_step.clone());
        assert!(matches!(
            discontinuous,
            Err(DirectNovaSessionError::StateContinuity)
        ));

        let session = selected
            .start(z0, 2)
            .expect("two-step session")
            .add_step(first_step)
            .expect("first fold")
            .add_step(second_step)
            .expect("second fold");
        let proof = session.finish().expect("compress two-step proof");
        assert_eq!(proof.len(), metadata.proof_length);
        let verifier = selected.into_verifier();
        assert_eq!(verifier.expected(), expected);
        assert_eq!(verifier.metadata(), metadata);

        let verifier_key_bytes = bincode::serde::encode_to_vec(
            &verifier.inner.verifier_key,
            bincode::config::legacy()
                .with_little_endian()
                .with_fixed_int_encoding(),
        )
        .expect("encode real-circuit verifier key");
        let (verifier_only_key, consumed) =
            bincode::serde::decode_from_slice::<VerifierOnlyKey<TEST_ARITY>, _>(
                &verifier_key_bytes,
                bincode::config::legacy()
                    .with_little_endian()
                    .with_fixed_int_encoding(),
            )
            .expect("decode verifier-only key");
        assert_eq!(consumed, verifier_key_bytes.len());
        assert_eq!(
            bincode::serde::encode_to_vec(
                &verifier_only_key,
                bincode::config::legacy()
                    .with_little_endian()
                    .with_fixed_int_encoding(),
            )
            .expect("re-encode verifier-only key"),
            verifier_key_bytes
        );
        let fixed_shape = proof_shape.as_fixed_serde_shape();
        let verifier_only_proof = fixed_shape
            .decode_canonical::<VerifierOnlyCompressedSnark<TEST_ARITY>>(&proof)
            .expect("decode verifier-only proof");
        assert_eq!(
            fixed_shape
                .encode(&verifier_only_proof)
                .expect("re-encode verifier-only proof"),
            proof
        );
        assert_eq!(
            verifier_only_proof
                .verify(&verifier_only_key, 2, &z0)
                .expect("verify with uninhabited circuit marker"),
            z2
        );

        let mut first_artifact = std::io::Cursor::new(Vec::new());
        let first_descriptor = verifier
            .write_artifact(&mut first_artifact)
            .expect("write selected verifier artifact");
        assert!(first_descriptor.encoded_length() > 72);
        assert!(first_descriptor.decoded_payload_length() > 0);
        assert_ne!(first_descriptor.digest(), [0; 32]);
        eprintln!("tiny_sha256_artifact={first_descriptor:#?}");
        let first_artifact = first_artifact.into_inner();
        let mut second_artifact = std::io::Cursor::new(Vec::new());
        let second_descriptor = verifier
            .write_artifact(&mut second_artifact)
            .expect("rewrite selected verifier artifact");
        assert_eq!(second_artifact.into_inner(), first_artifact);
        assert_eq!(second_descriptor, first_descriptor);

        let mut nonempty = std::io::Cursor::new(vec![0]);
        assert!(matches!(
            verifier.write_artifact(&mut nonempty),
            Err(DirectNovaVerifierArtifactError::DestinationNotEmpty)
        ));

        let mut artifact_reader = std::io::Cursor::new(first_artifact.as_slice());
        artifact_reader.set_position(7);
        let loaded = SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact_reader(
            &mut artifact_reader,
            expected,
            &first_descriptor,
        )
        .expect("load selected verifier artifact");
        assert_eq!(loaded.expected(), expected);
        assert_eq!(loaded.metadata(), metadata);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &first_artifact,
                &TEST_EXPECTED_SUITE,
                &first_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Header("suite ID"))
        ));
        assert_eq!(
            loaded
                .verify_final(&z0, 2, &proof)
                .expect("authenticate final state"),
            z2
        );
        loaded
            .verify_exact(&z0, 2, &z2, &proof)
            .expect("verify canonical proof");

        let wrong_length = ExpectedDirectNovaVerifierArtifact::new(
            first_descriptor.encoded_length() + 1,
            first_descriptor.decoded_payload_length(),
            first_descriptor.digest(),
        );
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &first_artifact,
                expected,
                &wrong_length,
            ),
            Err(DirectNovaVerifierArtifactError::Length)
        ));
        let wrong_digest = ExpectedDirectNovaVerifierArtifact::new(
            first_descriptor.encoded_length(),
            first_descriptor.decoded_payload_length(),
            [0; 32],
        );
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &first_artifact,
                expected,
                &wrong_digest,
            ),
            Err(DirectNovaVerifierArtifactError::Digest)
        ));

        let mut corrupted_payload = first_artifact.clone();
        corrupted_payload[72] ^= 1;
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &corrupted_payload,
                expected,
                &first_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Digest)
        ));

        let mut malformed_header = first_artifact.clone();
        malformed_header[0] ^= 1;
        let mut malformed_reader = std::io::Cursor::new(malformed_header);
        malformed_reader.set_position(11);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact_reader(
                &mut malformed_reader,
                expected,
                &first_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Digest)
        ));
        assert_eq!(
            malformed_reader.position(),
            first_descriptor.encoded_length()
        );

        let mut extra_bytes = first_artifact.clone();
        extra_bytes.push(0);
        let mut extra_reader = std::io::Cursor::new(extra_bytes);
        extra_reader.set_position(13);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact_reader(
                &mut extra_reader,
                expected,
                &first_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Length)
        ));

        for (offset, label) in [
            (0, "magic"),
            (19, "encoding version"),
            (20, "suite ID"),
            (55, "state arity"),
            (63, "compressed payload length"),
            (71, "decoded payload length"),
        ] {
            let mut malformed = first_artifact.clone();
            malformed[offset] ^= 1;
            let descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(
                &malformed,
                first_descriptor.decoded_payload_length(),
            );
            assert!(matches!(
                SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                    &malformed,
                    expected,
                    &descriptor,
                ),
                Err(DirectNovaVerifierArtifactError::Header(actual)) if actual == label
            ));
        }

        let mut truncated = first_artifact.clone();
        truncated.pop();
        let truncated_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(
            &truncated,
            first_descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &truncated,
                expected,
                &truncated_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Header(
                "compressed payload length"
            ))
        ));

        let payload_length =
            u64::try_from(truncated.len() - 72).expect("test artifact payload length fits u64");
        truncated[56..64].copy_from_slice(&payload_length.to_be_bytes());
        let truncated_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(
            &truncated,
            first_descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &truncated,
                expected,
                &truncated_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Decode(_))
                | Err(DirectNovaVerifierArtifactError::Io(_))
        ));

        let mut trailing = first_artifact.clone();
        trailing.push(0);
        let payload_length =
            u64::try_from(trailing.len() - 72).expect("test artifact payload length fits u64");
        trailing[56..64].copy_from_slice(&payload_length.to_be_bytes());
        let trailing_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(
            &trailing,
            first_descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &trailing,
                expected,
                &trailing_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Length)
        ));

        let mut short = proof.clone();
        short.pop();
        assert!(matches!(
            loaded.verify_final(&z0, 2, &short),
            Err(DirectNovaSessionError::ProofLength { .. })
        ));
        let malformed = vec![0xff; proof.len()];
        assert!(loaded.verify_final(&z0, 2, &malformed).is_err());
        assert!(matches!(
            loaded.verify_final(&z0, 0, &proof),
            Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0
            })
        ));

        let mut wrong_final = z2;
        wrong_final[0] += DirectNovaScalar::ONE;
        assert!(matches!(
            loaded.verify_exact(&z0, 2, &wrong_final, &proof),
            Err(DirectNovaSessionError::FinalState)
        ));
        assert!(loaded.verify_exact(&z0, 1, &z1, &proof).is_err());
    }
}
