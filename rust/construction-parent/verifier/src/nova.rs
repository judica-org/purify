//! Verification-only Nova state for one locally pinned suite.
//!
//! A [`Verifier`] holds an authenticated verifier key and the proof codec
//! shape derived from its suite. It contains no relation template, public
//! parameters, or prover key, and it cannot perform setup or proving.

use std::io::{self, Read, Seek};
use std::sync::Mutex;

use nova_snark::{
    errors::NovaError,
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, VerifierKey},
    provider::ipa_pc,
    spartan::snark::RelaxedR1CSSNARK,
    traits::circuit::StepCircuit,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use thiserror::Error;

use crate::artifact::{
    read_artifact_payload, ArtifactCodecError, ArtifactFormat, ArtifactIdentity,
};
use crate::codec::{FixedSerdeError, NovaCompressedProofShape};
use crate::suite::{Suite, SuiteError};
use statement::profile::CONSTRUCTION_STATE_ARITY;
use statement::Scalar;
use statement::{DirectNovaPrimaryEngine, DirectNovaSecondaryEngine};

pub type PrimarySnark =
    RelaxedR1CSSNARK<DirectNovaPrimaryEngine, ipa_pc::EvaluationEngine<DirectNovaPrimaryEngine>>;
pub type SecondarySnark = RelaxedR1CSSNARK<
    DirectNovaSecondaryEngine,
    ipa_pc::EvaluationEngine<DirectNovaSecondaryEngine>,
>;

/// Uninhabited circuit marker for verification-only Nova types.
///
/// Nova verifier keys and compressed proofs retain their circuit generic only
/// through `PhantomData`. Verification uses the authenticated arity stored in
/// the key and never synthesizes the circuit. Keeping this marker uninhabited
/// makes accidental setup or proving against it impossible.
#[derive(Clone, Copy, Debug)]
pub enum VerifierOnlyStep {}

impl StepCircuit<Scalar> for VerifierOnlyStep {
    fn arity(&self) -> usize {
        match *self {}
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        match *self {}
    }
}

pub type CompressedProof = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    VerifierOnlyStep,
    PrimarySnark,
    SecondarySnark,
>;
pub type Key = VerifierKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    VerifierOnlyStep,
    PrimarySnark,
    SecondarySnark,
>;

const MAX_DECODED_PAYLOAD_LENGTH: usize = 4_000_000_000;

/// Authenticated local storage format for one verifier key.
///
/// This is a deployment artifact, not a receipt or consensus-selected
/// parameter format.
pub const VERIFIER_ARTIFACT_FORMAT: ArtifactFormat = ArtifactFormat {
    magic: *b"Purify/Nova/VK2\0",
    encoding_version: 2,
    digest_tag: b"Purify/Accountable/DirectNovaVerifierArtifact/v2",
    window_log: 23,
    max_compressed_payload_length: 2_000_000_000,
    max_decoded_payload_length: MAX_DECODED_PAYLOAD_LENGTH,
};

/// The one verifier artifact identity compiled into this library.
///
/// It is deliberately separate from the semantic suite ID. Receipts never
/// supply this value, and a serialization-only change must replace it without
/// changing the proof statement.
pub const QUALIFIED_VERIFIER_ARTIFACT: ArtifactIdentity = ArtifactIdentity::new(
    693_708_278,
    3_206_736_424,
    [
        0x18, 0x4c, 0x33, 0x40, 0xde, 0x8f, 0x00, 0x5a, 0x6e, 0x3a, 0x83, 0x99, 0x7e, 0x90, 0xff,
        0x99, 0x3d, 0x24, 0x50, 0x26, 0xd6, 0xae, 0xc0, 0x48, 0x04, 0xdc, 0xb7, 0x36, 0xf2, 0x9c,
        0xa0, 0xaa,
    ],
);

/// Failure while loading one authenticated verifier artifact.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("direct Nova verifier artifact length is invalid")]
    Length,
    #[error("direct Nova verifier artifact digest mismatch")]
    Digest,
    #[error("direct Nova verifier artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova verifier artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova verifier artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Suite(#[from] SuiteError),
    #[error("direct Nova suite setup failed: {0}")]
    Setup(&'static str),
}

impl From<ArtifactCodecError> for LoadError {
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

/// Failure while authenticating one compressed proof.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VerifyError {
    #[error(transparent)]
    Nova(#[from] NovaError),
    #[error(transparent)]
    Codec(#[from] FixedSerdeError),
    #[error("direct Nova verified final state mismatch")]
    FinalState,
    #[error("direct Nova step count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
    #[error("direct Nova proof length mismatch: expected {expected}, actual {actual}")]
    ProofLength { expected: usize, actual: usize },
}

/// Builds the one-thread pool that serializes every Nova operation.
pub fn one_thread_pool() -> Result<ThreadPool, &'static str> {
    ThreadPoolBuilder::new()
        .num_threads(1)
        .thread_name(|_| "purify-direct-nova".to_owned())
        .build()
        .map_err(|_| "one-thread Rayon pool")
}

/// Verification-only state for one pinned suite.
pub struct Verifier {
    key: Key,
    proof_shape: NovaCompressedProofShape,
    pool: ThreadPool,
    operation: Mutex<()>,
}

impl Verifier {
    /// Loads a verifier key from its complete seekable byte source.
    ///
    /// The suite and artifact identity are local constants; the artifact
    /// supplies neither suite metadata nor the proof shape. The first pass
    /// authenticates the complete source. Only a matching digest permits the
    /// second pass to parse the header or invoke Serde. The second pass hashes
    /// the bytes Serde consumes and rechecks the final length, so swapped
    /// bytes cannot be accepted. A file-backed caller must still provide an
    /// immutable local snapshot: a malicious same-length mutation can
    /// otherwise make Serde allocate before the second digest rejects it.
    pub fn load<R>(
        artifact: &mut R,
        suite: &Suite,
        identity: &ArtifactIdentity,
    ) -> Result<Self, LoadError>
    where
        R: Read + Seek,
    {
        if usize::try_from(suite.parameters.state_arity) != Ok(CONSTRUCTION_STATE_ARITY) {
            return Err(SuiteError::Mismatch("state arity").into());
        }
        let proof_shape = suite.proof_shape()?;
        let key = read_artifact_payload::<Key, _, MAX_DECODED_PAYLOAD_LENGTH>(
            artifact,
            &VERIFIER_ARTIFACT_FORMAT,
            suite.suite_id,
            CONSTRUCTION_STATE_ARITY,
            *identity,
        )?;
        Ok(Self {
            key,
            proof_shape,
            pool: one_thread_pool().map_err(LoadError::Setup)?,
            operation: Mutex::new(()),
        })
    }

    /// Verifies the proof against the exact initial state and external step
    /// count, returning its authenticated recurrence output.
    ///
    /// The proof supplies neither suite metadata nor its own recursive step
    /// count. The returned state is not construction-receipt acceptance.
    pub fn verify_final(
        &self,
        initial_state: &[Scalar; CONSTRUCTION_STATE_ARITY],
        expected_steps: usize,
        proof: &[u8],
    ) -> Result<[Scalar; CONSTRUCTION_STATE_ARITY], VerifyError> {
        if expected_steps == 0 {
            return Err(VerifyError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        if proof.len() != self.proof_shape.encoded_len() {
            return Err(VerifyError::ProofLength {
                expected: self.proof_shape.encoded_len(),
                actual: proof.len(),
            });
        }

        let _guard = self
            .operation
            .lock()
            .expect("direct Nova suite operation mutex poisoned");
        self.pool.install(|| {
            let shape = self.proof_shape.as_fixed_serde_shape();
            let compressed = shape.decode_canonical::<CompressedProof>(proof)?;
            let final_state = compressed.verify(&self.key, expected_steps, initial_state)?;
            final_state.try_into().map_err(|_| VerifyError::FinalState)
        })
    }
}
