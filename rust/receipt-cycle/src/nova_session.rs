//! Serialized one-thread Nova lifecycle for one exact direct relation.
//!
//! This module owns only the generic fixed-template mechanics. A production
//! receipt suite must still select a trusted canonical relation fixture and
//! freeze its relation ID, public-parameter digest, matrix dimensions, and
//! proof-codec shape before exposing an acceptance API.

use std::sync::Mutex;

use ff::PrimeField;
use nova_snark::{
    errors::NovaError,
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey},
    provider::ipa_pc,
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    direct_nova::{
        DirectNovaPrimaryEngine, DirectNovaScalar, DirectNovaSecondaryEngine, DirectNovaStep,
        DirectRelationId, DIRECT_LOWERING_VERSION, DIRECT_RELATION_ENCODING_VERSION,
    },
    fixed_serde::{
        FixedSerdeError, NovaCompressedProofShape, NovaR1csDimensions,
        NOVA_COMPRESSED_PROOF_CODEC_VERSION,
    },
    ReceiptCycleError,
};

pub(crate) mod verifier_artifact;

type PrimaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaPrimaryEngine>;
type SecondaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaSecondaryEngine>;
type PrimarySnark = RelaxedR1CSSNARK<DirectNovaPrimaryEngine, PrimaryEvaluationEngine>;
type SecondarySnark = RelaxedR1CSSNARK<DirectNovaSecondaryEngine, SecondaryEvaluationEngine>;
type DirectPublicParams<const ARITY: usize> =
    PublicParams<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, DirectNovaStep<ARITY>>;
type DirectRecursiveSnark<const ARITY: usize> =
    RecursiveSNARK<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, DirectNovaStep<ARITY>>;
type DirectCompressedSnark<const ARITY: usize> = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;
type DirectProverKey<const ARITY: usize> = ProverKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;
type DirectVerifierKey<const ARITY: usize> = VerifierKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;

const DIRECT_NOVA_SUITE_ID_TAG: &[u8] = b"Purify/Accountable/ConstructionParentNovaSuite/v1";
const DIRECT_NOVA_SUITE_ENCODING_VERSION: u8 = 1;
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
/// No production value is defined here. Receipt activation must supply one
/// explicit, locally selected combination after its acceptance boundary is
/// fixed.
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
    Relation(#[from] ReceiptCycleError),
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
    #[error("direct Nova step relation mismatch")]
    StepRelation,
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
        // Canonical body order is: three one-byte suite/relation/lowering
        // versions; four big-endian u32 receipt-layer versions; the three
        // one-byte Nova semantic-version components; six one-byte ordered
        // engine/backend/codec identifiers; big-endian u32 arity; relation
        // and PP digests; five big-endian u64 dimensions/lengths; then a
        // big-endian u32 schedule count and every schedule length as u32.
        digest.update([
            DIRECT_NOVA_SUITE_ENCODING_VERSION,
            DIRECT_RELATION_ENCODING_VERSION,
            DIRECT_LOWERING_VERSION,
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

pub(crate) struct DirectNovaSuite<const ARITY: usize> {
    public_params: DirectPublicParams<ARITY>,
    prover_key: DirectProverKey<ARITY>,
    verifier: DirectNovaVerifier<ARITY>,
}

/// Verification-only state for one fixed direct Nova suite.
///
/// This deliberately contains no relation template, public parameters, or
/// prover key. Converting a suite into this type is a one-way release of all
/// proving capability.
pub(crate) struct DirectNovaVerifier<const ARITY: usize> {
    verifier_key: DirectVerifierKey<ARITY>,
    proof_shape: NovaCompressedProofShape,
    metadata: DirectNovaSuiteMetadata,
    pool: ThreadPool,
    operation: Mutex<()>,
}

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

/// A generic suite promoted through one exact local selection profile.
pub(crate) struct SelectedDirectNovaSuite<const ARITY: usize> {
    expected: &'static ExpectedDirectNovaSuite,
    inner: DirectNovaSuite<ARITY>,
}

/// A verification-only context promoted through one exact local profile.
pub(crate) struct SelectedDirectNovaVerifier<const ARITY: usize> {
    expected: &'static ExpectedDirectNovaSuite,
    inner: DirectNovaVerifier<ARITY>,
}

impl<const ARITY: usize> DirectNovaSuite<ARITY> {
    /// Builds an unselected suite for internal qualification and test tools.
    /// Receipt acceptance must use `setup_exact` instead.
    #[cfg(test)]
    pub(crate) fn setup(
        trusted_step: DirectNovaStep<ARITY>,
    ) -> Result<Self, DirectNovaSessionError> {
        Self::setup_prepared(trusted_step)
    }

    /// Promotes setup output only inside the offline qualification test.
    ///
    /// Production callers cannot compile this path and must use one frozen
    /// [`ExpectedDirectNovaSuite`] through [`Self::setup_exact`].
    #[cfg(test)]
    pub(crate) fn select_observed_construction_parent_for_qualification(
        self,
    ) -> Result<SelectedDirectNovaSuite<ARITY>, DirectNovaSessionError> {
        let construction_versions = DirectNovaConstructionVersions::new(
            ConstructionPayloadVersion::new(2),
            ConstructionStatementVersion::new(3),
            ConstructionManifestVersion::new(2),
            ConstructionNativeDecisionVersion::new(1),
        );
        let metadata = self.verifier.metadata;
        let proof_shape = self.verifier.proof_shape.clone();
        let suite_id = metadata.suite_id::<ARITY>(&proof_shape, construction_versions)?;
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
        expected.validate::<ARITY>(&metadata, &proof_shape)?;
        Ok(SelectedDirectNovaSuite {
            expected,
            inner: self,
        })
    }

    /// Builds a suite only after its relation and complete resulting metadata
    /// match one local profile. There is no alternate or fallback profile.
    pub(crate) fn setup_exact(
        trusted_step: DirectNovaStep<ARITY>,
        expected: &'static ExpectedDirectNovaSuite,
    ) -> Result<SelectedDirectNovaSuite<ARITY>, DirectNovaSessionError> {
        expected.precheck_relation(trusted_step.relation_id())?;
        let suite = Self::setup_prepared(trusted_step)?;
        expected.validate::<ARITY>(&suite.verifier.metadata, &suite.verifier.proof_shape)?;
        Ok(SelectedDirectNovaSuite {
            expected,
            inner: suite,
        })
    }

    fn setup_prepared(trusted_step: DirectNovaStep<ARITY>) -> Result<Self, DirectNovaSessionError> {
        let relation_id = trusted_step.relation_id();
        let pool = direct_nova_thread_pool()?;

        let (public_params, prover_key, verifier_key, proof_shape, metadata) =
            pool.install(move || -> Result<_, DirectNovaSessionError> {
                let public_params = DirectPublicParams::<ARITY>::setup(
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
                let (prover_key, verifier_key) =
                    DirectCompressedSnark::<ARITY>::setup(&public_params)?;
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
            verifier: DirectNovaVerifier {
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
    ) -> Result<DirectNovaProverSession<'_, ARITY>, DirectNovaSessionError> {
        if expected_steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        Ok(DirectNovaProverSession {
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

    fn into_verifier(self) -> DirectNovaVerifier<ARITY> {
        self.verifier
    }
}

impl<const ARITY: usize> DirectNovaVerifier<ARITY> {
    fn from_loaded_key(
        verifier_key: DirectVerifierKey<ARITY>,
        proof_shape: NovaCompressedProofShape,
        metadata: DirectNovaSuiteMetadata,
    ) -> Result<Self, DirectNovaSessionError> {
        Ok(Self {
            verifier_key,
            proof_shape,
            metadata,
            pool: direct_nova_thread_pool()?,
            operation: Mutex::new(()),
        })
    }

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
            let compressed = shape.decode_canonical::<DirectCompressedSnark<ARITY>>(proof)?;
            let final_state =
                compressed.verify(&self.verifier_key, expected_steps, initial_state)?;
            final_state
                .try_into()
                .map_err(|_| DirectNovaSessionError::FinalState)
        })
    }

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

impl<const ARITY: usize> SelectedDirectNovaSuite<ARITY> {
    pub(crate) const fn expected(&self) -> &'static ExpectedDirectNovaSuite {
        self.expected
    }

    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.inner.metadata()
    }

    pub(crate) fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
    ) -> Result<DirectNovaProverSession<'_, ARITY>, DirectNovaSessionError> {
        self.inner.start(initial_state, expected_steps)
    }

    /// Permanently releases every proving component while retaining the
    /// exact selected verifier.
    pub(crate) fn into_verifier(self) -> SelectedDirectNovaVerifier<ARITY> {
        SelectedDirectNovaVerifier {
            expected: self.expected,
            inner: self.inner.into_verifier(),
        }
    }
}

impl<const ARITY: usize> SelectedDirectNovaVerifier<ARITY> {
    pub(crate) const fn expected(&self) -> &'static ExpectedDirectNovaSuite {
        self.expected
    }

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

pub(crate) struct DirectNovaProverSession<'suite, const ARITY: usize> {
    suite: &'suite DirectNovaSuite<ARITY>,
    initial_state: [DirectNovaScalar; ARITY],
    current_state: [DirectNovaScalar; ARITY],
    expected_steps: usize,
    completed_steps: usize,
    recursive: Option<DirectRecursiveSnark<ARITY>>,
}

fn validate_step_relation<const ARITY: usize>(
    expected: DirectRelationId,
    step: &DirectNovaStep<ARITY>,
) -> Result<(), DirectNovaSessionError> {
    if step.relation_id() != expected {
        return Err(DirectNovaSessionError::StepRelation);
    }
    Ok(())
}

impl<const ARITY: usize> DirectNovaProverSession<'_, ARITY> {
    /// Consumes the session on both success and failure, so a partially
    /// mutated Nova proof can never be retried as if the fold were atomic.
    pub(crate) fn add_step(
        mut self,
        step: DirectNovaStep<ARITY>,
    ) -> Result<Self, DirectNovaSessionError> {
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
                let mut first = DirectRecursiveSnark::<ARITY>::new(
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

        self.current_state = *step.output_state();
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
            let compressed = DirectCompressedSnark::<ARITY>::prove_owned(
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
    use bulletproofs_cycle::Cycle;
    use ff::{Field, PrimeField};
    use golden_halo2curves::Secq256k1Cycle;

    use super::verifier_artifact::{
        DirectNovaVerifierArtifactError, ExpectedDirectNovaVerifierArtifact,
    };
    use super::*;
    use crate::{
        direct_nova::{direct_nova_raw_metrics, DirectNovaTemplate},
        relation_builder::{Builder, Expression, StateVariable, StatefulRelation},
        Scalar,
    };

    const TEST_ARITY: usize = 20;

    const TEST_CONSTRUCTION_VERSIONS: DirectNovaConstructionVersions =
        DirectNovaConstructionVersions::new(
            ConstructionPayloadVersion::new(0x0102_0304),
            ConstructionStatementVersion::new(0x1112_1314),
            ConstructionManifestVersion::new(0x2122_2324),
            ConstructionNativeDecisionVersion::new(0x3132_3334),
        );
    const TEST_SUITE_ID: DirectNovaSuiteId = DirectNovaSuiteId::new([
        0x18, 0x7a, 0x5c, 0xc5, 0xa0, 0x1f, 0x17, 0xbf, 0x67, 0x27, 0xb8, 0xf5, 0x85, 0x91, 0x6b,
        0xd3, 0x22, 0xb7, 0x2e, 0x33, 0x87, 0xc8, 0xf4, 0x6a, 0x26, 0xf5, 0xa5, 0x8e, 0xba, 0x96,
        0xb3, 0x60,
    ]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticQualificationShape {
        direct_constraints: usize,
        direct_variables: usize,
        direct_nnz: usize,
        six_term_rows: usize,
        bulk_semantic_rows: usize,
    }

    fn qualification_value(name: &str) -> usize {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("set {name} before running the qualification harness"))
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a positive integer"))
    }

    fn synthetic_qualification_shape() -> SyntheticQualificationShape {
        let direct_constraints =
            qualification_value("PURIFY_NOVA_QUALIFICATION_DIRECT_CONSTRAINTS");
        let direct_variables = qualification_value("PURIFY_NOVA_QUALIFICATION_DIRECT_VARIABLES");
        let direct_nnz = qualification_value("PURIFY_NOVA_QUALIFICATION_DIRECT_NNZ");
        let bulk_semantic_rows = direct_constraints
            .checked_sub(TEST_ARITY * 2)
            .expect("direct constraints cover state bindings");
        let five_term_nnz = bulk_semantic_rows
            .checked_mul(6)
            .and_then(|value| value.checked_add(TEST_ARITY * 6))
            .expect("synthetic five-term nonzeros");
        let six_term_rows = direct_nnz
            .checked_sub(five_term_nnz)
            .expect("direct nonzeros cover five-term rows");
        assert!(six_term_rows <= bulk_semantic_rows);
        assert!(direct_variables >= TEST_ARITY * 2);

        SyntheticQualificationShape {
            direct_constraints,
            direct_variables,
            direct_nnz,
            six_term_rows,
            bulk_semantic_rows,
        }
    }

    fn sum_zero_states(inputs: &[StateVariable], count: usize) -> Expression {
        inputs
            .iter()
            .take(count)
            .fold(Expression::constant(Scalar::ZERO), |sum, input| {
                sum.add(input.expression())
            })
    }

    fn synthetic_qualification_relation(shape: SyntheticQualificationShape) -> StatefulRelation {
        let mut builder = Builder::default();
        let inputs = (0..TEST_ARITY)
            .map(|_| builder.allocate_state(Scalar::ZERO))
            .collect::<Vec<_>>();
        let filler_gates = shape.direct_variables - TEST_ARITY * 2;
        for _ in 0..filler_gates {
            let _ = builder.allocate(Scalar::ZERO);
        }

        let five_terms = sum_zero_states(&inputs, 5);
        let six_terms = sum_zero_states(&inputs, 6);
        for row in 0..shape.bulk_semantic_rows {
            builder.constrain_zero(if row < shape.six_term_rows {
                six_terms.clone()
            } else {
                five_terms.clone()
            });
        }

        let outputs = inputs
            .iter()
            .map(|input| builder.expose_state(input.expression()))
            .collect::<Vec<_>>();
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("synthetic Nova qualification relation")
    }

    fn source_state(seed: u64) -> [Scalar; TEST_ARITY] {
        std::array::from_fn(|index| Scalar::from(seed + index as u64))
    }

    fn increment(state: [Scalar; TEST_ARITY]) -> [Scalar; TEST_ARITY] {
        state.map(|value| value + Scalar::ONE)
    }

    fn relation(state: [Scalar; TEST_ARITY]) -> StatefulRelation {
        let mut builder = Builder::default();
        let inputs: Vec<StateVariable> = state
            .iter()
            .map(|&value| builder.allocate_state(value))
            .collect();
        let mut outputs = Vec::with_capacity(TEST_ARITY);
        for input in &inputs {
            let next = input
                .expression()
                .clone()
                .add(&crate::relation_builder::Expression::constant(Scalar::ONE));
            outputs.push(builder.expose_state(&next));
        }
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("twenty-state Nova relation")
    }

    fn identity_relation(state: [Scalar; TEST_ARITY]) -> StatefulRelation {
        let mut builder = Builder::default();
        let inputs: Vec<StateVariable> = state
            .iter()
            .map(|&value| builder.allocate_state(value))
            .collect();
        let outputs = inputs
            .iter()
            .map(|input| builder.expose_state(input.expression()))
            .collect::<Vec<_>>();
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("identity Nova relation")
    }

    fn nova_state(state: [Scalar; TEST_ARITY]) -> [DirectNovaScalar; TEST_ARITY] {
        state.map(|value| {
            let bytes = Secq256k1Cycle::scalar_to_canonical(&value);
            let mut repr = <DirectNovaScalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            Option::<DirectNovaScalar>::from(DirectNovaScalar::from_repr(repr))
                .expect("canonical Nova state")
        })
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
        let (_, trusted) =
            DirectNovaTemplate::<TEST_ARITY>::from_relation(relation(source_state(3)))
                .expect("trusted direct Nova step");
        let (_, different) =
            DirectNovaTemplate::<TEST_ARITY>::from_relation(identity_relation(source_state(3)))
                .expect("different direct Nova step");

        assert!(validate_step_relation(trusted.relation_id(), &trusted).is_ok());
        assert_eq!(
            validate_step_relation(trusted.relation_id(), &different),
            Err(DirectNovaSessionError::StepRelation)
        );
    }

    #[test]
    #[ignore = "explicit resource-gated Nova setup; set qualification shape"]
    fn staged_synthetic_nova_setup_reports_shape() {
        // Read and validate the complete shape before allocating circuit data.
        let shape = synthetic_qualification_shape();
        eprintln!("synthetic_nova_qualification_expected={shape:#?}");

        let relation = synthetic_qualification_relation(shape);
        let raw = direct_nova_raw_metrics::<TEST_ARITY>(&relation.shape)
            .expect("synthetic direct Nova metrics");
        assert_eq!(raw.direct_constraints, shape.direct_constraints);
        assert_eq!(raw.direct_variables, shape.direct_variables);
        assert_eq!(raw.direct_nnz_upper_bound, shape.direct_nnz);

        let (_, trusted_step) = DirectNovaTemplate::<TEST_ARITY>::from_relation(relation)
            .expect("synthetic direct Nova template");
        let suite = DirectNovaSuite::<TEST_ARITY>::setup(trusted_step)
            .expect("synthetic direct Nova qualification suite");
        let metadata = suite.metadata();
        let primary_constraint_overhead = metadata
            .primary_constraints
            .checked_sub(shape.direct_constraints)
            .expect("primary constraints include the direct relation");
        let primary_variable_overhead = metadata
            .primary_variables
            .checked_sub(shape.direct_variables)
            .expect("primary variables include the direct relation");
        assert!(metadata.secondary_constraints > 0);
        assert!(metadata.secondary_variables > 0);
        assert!(metadata.proof_length > 0);
        assert!(metadata.codec_sequence_count > 0);
        eprintln!(
            "primary_constraint_overhead={primary_constraint_overhead}\n\
             primary_variable_overhead={primary_variable_overhead}\n\
             relation_id={:02x?}\npp_digest={:02x?}\nmetadata={metadata:#?}",
            metadata.relation_id.bytes(),
            metadata.public_parameter_digest,
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
        let (_, trusted_step) =
            DirectNovaTemplate::<TEST_ARITY>::from_relation(relation(source_state(3)))
                .expect("direct Nova template");
        assert!(matches!(
            DirectNovaSuite::<TEST_ARITY>::setup_exact(trusted_step, &TEST_WRONG_RELATION_SUITE),
            Err(DirectNovaSessionError::SuiteMismatch("relation ID"))
        ));
    }

    #[test]
    #[ignore = "explicit slow real two-step Nova session"]
    fn tiny_twenty_state_session_round_trips_canonically() {
        let source_z0 = source_state(3);
        let source_z1 = increment(source_z0);
        let source_z2 = increment(source_z1);
        let z0 = nova_state(source_z0);
        let z1 = nova_state(source_z1);
        let z2 = nova_state(source_z2);

        let (template, trusted_step) =
            DirectNovaTemplate::<TEST_ARITY>::from_relation(relation(source_z0))
                .expect("tiny direct Nova template");
        let first_step = template
            .bind_relation(relation(source_z0))
            .expect("first tiny direct Nova step");
        let second_step = template
            .bind_relation(relation(source_z1))
            .expect("second tiny direct Nova step");
        drop(template);
        let suite = DirectNovaSuite::<TEST_ARITY>::setup(trusted_step)
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
        let selected = SelectedDirectNovaSuite {
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

        let mut first_artifact = std::io::Cursor::new(Vec::new());
        let first_descriptor = verifier
            .write_artifact(&mut first_artifact)
            .expect("write selected verifier artifact");
        assert!(first_descriptor.encoded_length() > 64);
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
        let wrong_digest =
            ExpectedDirectNovaVerifierArtifact::new(first_descriptor.encoded_length(), [0; 32]);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &first_artifact,
                expected,
                &wrong_digest,
            ),
            Err(DirectNovaVerifierArtifactError::Digest)
        ));

        let mut corrupted_payload = first_artifact.clone();
        corrupted_payload[64] ^= 1;
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
            (63, "payload length"),
        ] {
            let mut malformed = first_artifact.clone();
            malformed[offset] ^= 1;
            let descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(&malformed);
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
        let truncated_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(&truncated);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &truncated,
                expected,
                &truncated_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Header("payload length"))
        ));

        let payload_length =
            u64::try_from(truncated.len() - 64).expect("test artifact payload length fits u64");
        truncated[56..64].copy_from_slice(&payload_length.to_be_bytes());
        let truncated_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(&truncated);
        assert!(matches!(
            SelectedDirectNovaVerifier::<TEST_ARITY>::from_artifact(
                &truncated,
                expected,
                &truncated_descriptor,
            ),
            Err(DirectNovaVerifierArtifactError::Decode(_))
        ));

        let mut trailing = first_artifact.clone();
        trailing.push(0);
        let payload_length =
            u64::try_from(trailing.len() - 64).expect("test artifact payload length fits u64");
        trailing[56..64].copy_from_slice(&payload_length.to_be_bytes());
        let trailing_descriptor = ExpectedDirectNovaVerifierArtifact::for_test_bytes(&trailing);
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
