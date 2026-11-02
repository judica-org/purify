//! Exact recursive verifier for one construction-parent receipt.
//!
//! A successful verification authenticates the final pending accumulation
//! root. It does not establish receipt acceptance: the native verifier must
//! parse that root against the anchor basis and complete `decide()`.

use thiserror::Error;

use crate::anchor_recurrence::ANCHOR_RECURRENCE_STATE_ARITY;
use crate::construction_manifest::{
    ConstructionRoot, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::construction_parent_input::ConstructionParentInputs;
use crate::direct_nova::{nova_state_to_source, source_state_to_nova};
use crate::nova_session::{
    DirectNovaSessionError, SelectedDirectNovaVerifier, QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE,
};
use crate::{ReceiptCycleError, Scalar};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum ConstructionParentVerifierError {
    #[error(transparent)]
    State(#[from] ReceiptCycleError),
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
/// bytes must be parsed against the native anchor basis and pass the final
/// accumulation decision before an acceptance type may be produced.
pub(crate) struct AuthenticatedConstructionParentOutput {
    pending_root: ConstructionRoot,
}

impl AuthenticatedConstructionParentOutput {
    pub(crate) fn canonical_root_bytes(&self) -> &[u8; CONSTRUCTION_ROOT_BYTES] {
        self.pending_root.canonical_bytes()
    }
}

/// Verifies one profile-checked recursive parent and returns its pending root.
///
/// The typed input is the only path into this boundary, so proof verification
/// cannot bypass the native basis and raw-generator identity checks.
pub(crate) fn verify_construction_parent(
    verifier: &SelectedDirectNovaVerifier<ANCHOR_RECURRENCE_STATE_ARITY>,
    inputs: &ConstructionParentInputs,
    proof: &[u8],
) -> Result<AuthenticatedConstructionParentOutput, ConstructionParentVerifierError> {
    if verifier.expected() != &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE {
        return Err(ConstructionParentVerifierError::Suite);
    }

    let proof_length = verifier.metadata().proof_length;
    if proof.len() != proof_length {
        return Err(DirectNovaSessionError::ProofLength {
            expected: proof_length,
            actual: proof.len(),
        }
        .into());
    }

    let seed = inputs.seed();
    let anchors = inputs.anchors();
    let expected_final = seed.derive_expected_final(anchors)?;
    let expected_suffix = expected_final.state_suffix_fields()?;
    let initial_state = source_state_to_nova(seed.initial_state_fields()?)?;
    let authenticated_final = verifier.verify_final(&initial_state, anchors.len(), proof)?;
    let authenticated_final = nova_state_to_source(authenticated_final)?;
    validated_output_from_authenticated_state(authenticated_final, expected_suffix)
}

fn validated_output_from_authenticated_state(
    authenticated_final: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
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
    Ok(AuthenticatedConstructionParentOutput {
        pending_root: ConstructionRoot::from_state_fields(root_fields)?,
    })
}

#[cfg(test)]
mod tests;
