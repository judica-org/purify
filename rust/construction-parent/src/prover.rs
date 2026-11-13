//! Checked construction-parent prover inputs.
//!
//! Decoding accepts only the fixed Wit3 framing and canonical native proof
//! values. Binding is a separate, deliberately expensive boundary: it
//! executes every production constraint, derives the complete state chain,
//! and returns an opaque input that later prover APIs can consume.

use std::fs::File;
use std::io;
use std::path::Path;

use thiserror::Error;

pub use crate::construction_parent_prover_binding::ConstructionParentWitnessBindingError;

use crate::construction_parent_prover_binding::BoundConstructionParentWitness;
use crate::construction_parent_prover_fixture::ConstructionParentProverFixture;
use crate::construction_parent_verifier::load_qualified_construction_parent_verifier;
use crate::construction_profile::CONSTRUCTION_RECURRENCE_STATE_ARITY;
use crate::nova_construction_recurrence::ConstructionParentStep;
use crate::nova_session::prover_artifact::QUALIFIED_CONSTRUCTION_PARENT_PROVER_ARTIFACT;
use crate::nova_session::{
    DirectNovaSessionError, SelectedDirectNovaVerifier, SelectedNovaProver,
    QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE, QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH,
};
use crate::Scalar;

/// Failure while decoding the canonical Wit3 framing or native proof values.
#[derive(Debug, Error)]
#[error("invalid construction parent Wit3 witness: {detail}")]
pub struct ConstructionParentWitnessDecodeError {
    detail: String,
}

/// Canonically decoded Wit3 data that has not yet executed the Nova relation.
pub struct ConstructionParentWitness {
    fixture: ConstructionParentProverFixture,
}

impl ConstructionParentWitness {
    /// Decode and canonically validate one complete Wit3 byte string.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConstructionParentWitnessDecodeError> {
        let fixture = ConstructionParentProverFixture::parse(bytes).map_err(|error| {
            ConstructionParentWitnessDecodeError {
                detail: error.to_string(),
            }
        })?;
        Ok(Self { fixture })
    }

    /// Return the authenticated number of ordered recurrence steps.
    pub fn step_count(&self) -> usize {
        self.fixture.inputs.step_count()
    }

    /// Execute every production constraint and bind the exact state chain.
    pub fn bind(
        self,
    ) -> Result<CheckedConstructionParentWitness, ConstructionParentWitnessBindingError> {
        Ok(CheckedConstructionParentWitness {
            inner: self.fixture.bind()?,
        })
    }
}

/// Opaque construction-parent input after complete relation validation.
pub struct CheckedConstructionParentWitness {
    inner: BoundConstructionParentWitness,
}

impl CheckedConstructionParentWitness {
    /// Return the number of checked, ordered recurrence steps.
    pub fn step_count(&self) -> usize {
        self.inner.steps().len()
    }

    /// Clone one fully checked production step for transparent setup.
    ///
    /// Setup qualification is test-only. Production proving can load only a
    /// pinned artifact and never derives parameters from caller input.
    #[cfg(test)]
    pub(crate) fn trusted_setup_step(&self) -> Option<ConstructionParentStep> {
        self.inner.steps().first().cloned()
    }

    /// Prove this exact checked state chain with the qualified prover.
    ///
    /// The selected prover and this witness are consumed. Public parameters
    /// and the prover key are explicitly dropped before the opaque proof state
    /// is returned. The result is not an accepted construction receipt; it
    /// must still be checked by the separately qualified verifier and the
    /// native final accumulation decision.
    pub(crate) fn prove_with(
        self,
        prover: SelectedConstructionParentProver,
    ) -> Result<UnverifiedConstructionParentProof, ConstructionParentProvingError> {
        if prover.expected() != &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE {
            return Err(ConstructionParentProvingError::Suite);
        }

        let (initial_state, final_state, steps) = self.inner.into_parts();
        let step_count = steps.len();
        let mut session = prover.start(initial_state, step_count)?;
        for step in steps {
            session = session.add_step(step)?;
        }
        let proof = session.finish()?;
        require_frozen_proof_length(&proof)?;

        drop(prover);
        Ok(UnverifiedConstructionParentProof {
            initial_state,
            final_state,
            step_count,
            proof,
        })
    }
}

type SelectedConstructionParentProver =
    SelectedNovaProver<CONSTRUCTION_RECURRENCE_STATE_ARITY, ConstructionParentStep>;

/// Failure while proving or independently rechecking one checked witness.
#[derive(Debug, Error)]
pub(crate) enum ConstructionParentProvingError {
    /// The caller supplied a locally selected suite other than qualification.
    #[error("construction parent selected an unexpected Nova suite")]
    Suite,
    /// Nova setup, folding, compression, or verification failed.
    #[error(transparent)]
    Nova(#[from] DirectNovaSessionError),
    /// The compressed proof differs from the frozen receipt wire length.
    #[error("construction parent proof length mismatch: expected {expected}, actual {actual}")]
    ProofLength { expected: usize, actual: usize },
    /// The separate verifier authenticated a different final state.
    #[error("construction parent verified final state mismatch")]
    FinalState,
}

/// A compressed proof that has not yet passed the separate verifier artifact.
///
/// State fields are private so callers cannot replace the statement that the
/// prover consumed before re-verification.
pub(crate) struct UnverifiedConstructionParentProof {
    initial_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    step_count: usize,
    proof: Vec<u8>,
}

impl UnverifiedConstructionParentProof {
    /// Recheck the exact initial state, step count, and final state.
    ///
    /// The separately loaded verifier is consumed and dropped before the
    /// verified proof bytes become available to an output boundary.
    pub(crate) fn verify_with(
        self,
        verifier: SelectedDirectNovaVerifier<CONSTRUCTION_RECURRENCE_STATE_ARITY>,
    ) -> Result<VerifiedConstructionParentProof, ConstructionParentProvingError> {
        if verifier.expected() != &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE {
            return Err(ConstructionParentProvingError::Suite);
        }
        let authenticated =
            verifier.verify_final(&self.initial_state, self.step_count, &self.proof)?;
        require_exact_final_state(&self.final_state, &authenticated)?;
        drop(verifier);
        Ok(VerifiedConstructionParentProof { proof: self.proof })
    }
}

/// Exact proof bytes after independent recursive re-verification.
///
/// This remains construction input, not an accepted receipt. The native
/// construction verifier must still parse and decide its authenticated root.
pub(crate) struct VerifiedConstructionParentProof {
    proof: Vec<u8>,
}

impl VerifiedConstructionParentProof {
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.proof
    }
}

/// Failure in the purpose-specific qualified construction-parent prover.
#[derive(Debug, Error)]
pub enum QualifiedConstructionParentProvingError {
    /// The locally selected PK1 file could not be opened read-only.
    #[error("cannot open the qualified construction-parent prover artifact: {source}")]
    OpenProverArtifact {
        #[source]
        source: io::Error,
    },
    /// The PK1 file did not match the compiled qualified identity.
    #[error("the qualified construction-parent prover artifact was rejected: {detail}")]
    LoadProverArtifact { detail: String },
    /// Folding or compression failed for the checked witness.
    #[error("qualified construction-parent proving failed: {detail}")]
    Prove { detail: String },
    /// The separately qualified VK2 file could not be opened read-only.
    #[error("cannot open the qualified construction-parent verifier artifact: {source}")]
    OpenVerifierArtifact {
        #[source]
        source: io::Error,
    },
    /// The VK2 file did not match the compiled qualified identity.
    #[error("the qualified construction-parent verifier artifact was rejected: {detail}")]
    LoadVerifierArtifact { detail: String },
    /// The independent verifier did not authenticate the exact proven state.
    #[error("qualified construction-parent proof re-verification failed: {detail}")]
    Reverify { detail: String },
}

/// Produce and independently reverify one qualified raw parent proof.
///
/// `witness` has already executed every production constraint through
/// [`ConstructionParentWitness::bind`]. The PK1 source is opened read-only,
/// authenticated against the compiled setup-only qualification identity, and
/// consumed for folding. Its public parameters and prover key are dropped
/// before the VK2 source is opened. The returned bytes are exactly the frozen
/// 15,076-byte recursive proof with no wrapper or caller-selected metadata.
///
/// This operation does not accept a construction receipt. C++ must still bind
/// the proof to its typed receipt inputs and complete the native final
/// accumulation decision.
pub fn prove_qualified_construction_parent(
    witness: CheckedConstructionParentWitness,
    prover_artifact_path: &Path,
    verifier_artifact_path: &Path,
) -> Result<Vec<u8>, QualifiedConstructionParentProvingError> {
    let mut prover_artifact = File::open(prover_artifact_path)
        .map_err(|source| QualifiedConstructionParentProvingError::OpenProverArtifact { source })?;
    let prover = SelectedConstructionParentProver::from_artifact_reader(
        &mut prover_artifact,
        &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE,
        &QUALIFIED_CONSTRUCTION_PARENT_PROVER_ARTIFACT,
    )
    .map_err(
        |error| QualifiedConstructionParentProvingError::LoadProverArtifact {
            detail: error.to_string(),
        },
    )?;
    drop(prover_artifact);

    let unverified = witness.prove_with(prover).map_err(|error| {
        QualifiedConstructionParentProvingError::Prove {
            detail: error.to_string(),
        }
    })?;

    // `prove_with` consumes and drops the complete PK1 state before this
    // independently selected verifier artifact is opened.
    let mut verifier_artifact = File::open(verifier_artifact_path).map_err(|source| {
        QualifiedConstructionParentProvingError::OpenVerifierArtifact { source }
    })?;
    let verifier =
        load_qualified_construction_parent_verifier(&mut verifier_artifact).map_err(|error| {
            QualifiedConstructionParentProvingError::LoadVerifierArtifact {
                detail: error.to_string(),
            }
        })?;
    drop(verifier_artifact);

    unverified
        .verify_with(verifier)
        .map(VerifiedConstructionParentProof::into_bytes)
        .map_err(|error| QualifiedConstructionParentProvingError::Reverify {
            detail: error.to_string(),
        })
}

fn require_frozen_proof_length(proof: &[u8]) -> Result<(), ConstructionParentProvingError> {
    if proof.len() != QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH {
        return Err(ConstructionParentProvingError::ProofLength {
            expected: QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH,
            actual: proof.len(),
        });
    }
    Ok(())
}

fn require_exact_final_state(
    expected: &[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    authenticated: &[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
) -> Result<(), ConstructionParentProvingError> {
    if authenticated != expected {
        return Err(ConstructionParentProvingError::FinalState);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_decoder_rejects_truncated_wit3() {
        let error = ConstructionParentWitness::decode(&[])
            .err()
            .expect("empty witness rejects");
        assert!(error
            .to_string()
            .contains("truncated construction prover fixture"));
    }

    #[test]
    fn public_decoder_accepts_checked_wit3_without_binding() {
        let witness = ConstructionParentWitness::decode(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("decode accepted construction parent witness");
        assert_eq!(witness.step_count(), 5);
    }

    #[test]
    fn one_shot_boundary_requires_the_frozen_proof_length() {
        let short = vec![0; QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH - 1];
        assert!(matches!(
            require_frozen_proof_length(&short),
            Err(ConstructionParentProvingError::ProofLength {
                expected: QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH,
                actual
            }) if actual == short.len()
        ));
        let exact = vec![0; QUALIFIED_CONSTRUCTION_PARENT_PROOF_LENGTH];
        require_frozen_proof_length(&exact).expect("frozen proof length");
    }

    #[test]
    fn one_shot_boundary_requires_the_exact_final_state() {
        let expected = [Scalar::from(7u64); CONSTRUCTION_RECURRENCE_STATE_ARITY];
        require_exact_final_state(&expected, &expected).expect("exact final state");

        let mut changed = expected;
        changed[CONSTRUCTION_RECURRENCE_STATE_ARITY - 1] = Scalar::from(8u64);
        assert!(matches!(
            require_exact_final_state(&expected, &changed),
            Err(ConstructionParentProvingError::FinalState)
        ));
    }

    #[test]
    #[ignore = "executes every constraint in five production recurrences"]
    fn public_binder_executes_the_complete_checked_witness() {
        let witness = ConstructionParentWitness::decode(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("decode accepted construction parent witness");
        let checked = witness.bind().expect("bind accepted witness state chain");
        assert_eq!(checked.step_count(), 5);
    }
}
