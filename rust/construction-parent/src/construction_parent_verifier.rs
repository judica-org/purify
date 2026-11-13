//! Exact recursive verifier for one construction-parent receipt.
//!
//! A successful verification authenticates the final pending accumulation
//! root. It does not establish receipt acceptance: the native verifier must
//! parse that root against the construction-leaf basis and complete `decide()`.

use std::io::{Read, Seek};

use thiserror::Error;

use crate::construction_manifest::ConstructionRoot;
use crate::construction_parent_input::ConstructionParentInputs;
use crate::construction_profile::{
    CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::nova_session::verifier_artifact::DirectNovaVerifierArtifactError;
use crate::nova_session::{
    DirectNovaSessionError, SelectedDirectNovaVerifier, QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE,
};
use crate::{RelationError, Scalar};

/// Rejects verifier loading until the mixed relation has been qualified.
///
/// No stale centralized artifact bytes are inspected. The later qualification
/// commit must replace this gate while pinning the mixed parameters and
/// artifact.
pub(crate) fn require_qualified_construction_parent_profile(
) -> Result<(), DirectNovaVerifierArtifactError> {
    Err(DirectNovaVerifierArtifactError::QualificationPending)
}

pub(crate) fn load_qualified_construction_parent_verifier<R>(
    _artifact: &mut R,
) -> Result<
    SelectedDirectNovaVerifier<CONSTRUCTION_RECURRENCE_STATE_ARITY>,
    DirectNovaVerifierArtifactError,
>
where
    R: Read + Seek,
{
    require_qualified_construction_parent_profile()?;
    unreachable!("a qualification-pending profile cannot load an artifact")
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum ConstructionParentVerifierError {
    #[error(transparent)]
    State(#[from] RelationError),
    #[error(transparent)]
    Nova(#[from] DirectNovaSessionError),
    #[error("construction parent selected an unexpected Nova suite")]
    Suite,
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

/// Verifies one profile-checked recursive parent and returns its pending root.
///
/// The typed input is the only path into this boundary, so proof verification
/// cannot bypass the native basis and raw-generator identity checks.
pub(crate) fn verify_construction_parent(
    verifier: &SelectedDirectNovaVerifier<CONSTRUCTION_RECURRENCE_STATE_ARITY>,
    inputs: &ConstructionParentInputs,
    proof: &[u8],
) -> Result<AuthenticatedConstructionParentOutput, ConstructionParentVerifierError> {
    if verifier.expected() != &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE {
        return Err(ConstructionParentVerifierError::Suite);
    }

    let authenticated_final =
        verifier.verify_final(inputs.initial_state(), inputs.step_count(), proof)?;
    validated_output_from_authenticated_state(authenticated_final, inputs.expected_suffix())
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
