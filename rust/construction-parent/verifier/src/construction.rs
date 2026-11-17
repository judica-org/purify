//! Exact recursive verifier for one construction-parent receipt.
//!
//! A successful verification authenticates the final pending accumulation
//! root. It does not establish receipt acceptance: the native verifier must
//! parse that root against the construction-leaf basis and complete `decide()`.

use std::io::{Read, Seek};

use thiserror::Error;

use crate::nova::{LoadError, Verifier, VerifyError, QUALIFIED_VERIFIER_ARTIFACT};
use crate::suite::QUALIFIED;
use statement::inputs::ConstructionParentInputs;
use statement::manifest::ConstructionRoot;
use statement::profile::{
    CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_STATE_ARITY,
};
use statement::{RelationError, Scalar};

/// The sole production verifier: Nova verification under the qualified suite.
///
/// The only constructor loads the compiled-in suite and artifact identity, so
/// holding this type is proof that verification runs under that suite.
pub struct ConstructionParentVerifier {
    nova: Verifier,
}

impl ConstructionParentVerifier {
    /// Loads the qualified verifier from one seekable artifact snapshot.
    ///
    /// Authentication of the complete encoding precedes all Serde work. A
    /// second digest over the bytes actually consumed rejects a changed
    /// snapshot.
    pub fn load<R>(artifact: &mut R) -> Result<Self, LoadError>
    where
        R: Read + Seek,
    {
        Ok(Self {
            nova: Verifier::load(artifact, &QUALIFIED, &QUALIFIED_VERIFIER_ARTIFACT)?,
        })
    }

    /// Verifies one profile-checked recursive parent and returns its pending
    /// root.
    ///
    /// The typed input is the only path into this boundary, so proof
    /// verification cannot bypass the native basis and raw-generator identity
    /// checks.
    pub(crate) fn authenticate(
        &self,
        inputs: &ConstructionParentInputs,
        proof: &[u8],
    ) -> Result<AuthenticatedConstructionParentOutput, ConstructionParentVerifierError> {
        let authenticated_final =
            self.verify_final(inputs.initial_state(), inputs.step_count(), proof)?;
        validated_output_from_authenticated_state(authenticated_final, inputs.expected_suffix())
    }

    /// Authenticates the raw recurrence output for an exact initial state and
    /// step count. The returned state is not receipt acceptance.
    pub fn verify_final(
        &self,
        initial_state: &[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
        expected_steps: usize,
        proof: &[u8],
    ) -> Result<[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY], VerifyError> {
        self.nova.verify_final(initial_state, expected_steps, proof)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum ConstructionParentVerifierError {
    #[error(transparent)]
    State(#[from] RelationError),
    #[error(transparent)]
    Nova(#[from] VerifyError),
    #[error("construction parent final manifest mismatch")]
    FinalManifest,
    #[error("construction parent final index mismatch")]
    FinalIndex,
}

/// Proof-authenticated pending accumulation root.
///
/// This capability is deliberately not an accepted construction receipt. Its
/// bytes must be parsed against the native construction-leaf basis and pass
/// the final accumulation decision before an acceptance type may be produced.
pub(crate) struct AuthenticatedConstructionParentOutput {
    canonical_root: [u8; CONSTRUCTION_ROOT_BYTES],
}

impl AuthenticatedConstructionParentOutput {
    pub(crate) fn canonical_root_bytes(&self) -> &[u8; CONSTRUCTION_ROOT_BYTES] {
        &self.canonical_root
    }
}

fn validated_output_from_authenticated_state(
    authenticated_final: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    expected_suffix: [Scalar; 2],
) -> Result<AuthenticatedConstructionParentOutput, ConstructionParentVerifierError> {
    if authenticated_final[CONSTRUCTION_ROOT_STATE_ARITY] != expected_suffix[0] {
        return Err(ConstructionParentVerifierError::FinalManifest);
    }
    if authenticated_final[CONSTRUCTION_ROOT_STATE_ARITY + 1] != expected_suffix[1] {
        return Err(ConstructionParentVerifierError::FinalIndex);
    }
    let root_fields = authenticated_final[..CONSTRUCTION_ROOT_STATE_ARITY]
        .try_into()
        .expect("construction state has a fixed root prefix");
    let root = ConstructionRoot::from_state_fields(root_fields)?;
    Ok(AuthenticatedConstructionParentOutput {
        canonical_root: *root.canonical_bytes(),
    })
}

#[cfg(test)]
mod tests;
