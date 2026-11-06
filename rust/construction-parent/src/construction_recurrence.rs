//! Backend-independent construction-parent recurrence inputs.
//!
//! The recursive backends share one witness model and one exact 20-field
//! public-state encoding. Backend-specific constraint code must bind this
//! encoding rather than reinterpret or reorder it.

use ff::Field;

use crate::candidate::{CandidateRootClaim, CandidateStepProofWitness};
use crate::circuit_norm::{CandidateNormReductionProofWitness, ManifestBoundAnchorLeafStatementV4};
use crate::circuit_transcript::CircuitCommitmentModeV4;
use crate::construction_profile::{
    ANCHOR_GATE_COUNT, ANCHOR_LEAF_ROUNDS, ANCHOR_NORM_LENGTH, ANCHOR_RECURRENCE_STATE_ARITY,
    CONSTRUCTION_ROOT_ROUNDS, CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::secp_native::{
    canonical_scalar_value, coordinate_field_value, encoded_point_value, SecpScalarWitness,
};
use crate::{RelationError, Scalar};

pub(crate) const ROOT_PREFIX_INDEX: usize = 0;
pub(crate) const ROOT_X_INDEX: usize = 1;
pub(crate) const ROOT_SCALE_INDEX: usize = 2;
pub(crate) const ROOT_FACTORS_START: usize = 3;
pub(crate) const MANIFEST_INDEX: usize = CONSTRUCTION_ROOT_STATE_ARITY;
pub(crate) const STEP_INDEX: usize = MANIFEST_INDEX + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorRecurrenceStateWitness {
    pub(crate) root: CandidateRootClaim,
    /// Canonical big-endian secp256k1 coordinate-field element.
    pub(crate) manifest: [u8; 32],
    pub(crate) index: u32,
}

impl AnchorRecurrenceStateWitness {
    /// Returns the recurrence's exact public-state field order.
    pub(crate) fn state_fields(
        &self,
    ) -> Result<[Scalar; ANCHOR_RECURRENCE_STATE_ARITY], RelationError> {
        if self.root.factors.len() != CONSTRUCTION_ROOT_ROUNDS {
            return Err(RelationError::Malformed("anchor recurrence root factors"));
        }
        let point = encoded_point_value(self.root.point)?;
        let mut state = [Scalar::ZERO; ANCHOR_RECURRENCE_STATE_ARITY];
        state[ROOT_PREFIX_INDEX] = Scalar::from(u64::from(self.root.point.encoded[0]));
        state[ROOT_X_INDEX] = point.x;
        state[ROOT_SCALE_INDEX] = secp_scalar_value(self.root.scale)?;
        for (index, factor) in self.root.factors.iter().enumerate() {
            state[ROOT_FACTORS_START + index] = secp_scalar_value(*factor)?;
        }
        state[MANIFEST_INDEX] = coordinate_field_value(self.manifest)?;
        state[STEP_INDEX] = Scalar::from(u64::from(self.index));
        Ok(state)
    }
}

fn secp_scalar_value(witness: SecpScalarWitness) -> Result<Scalar, RelationError> {
    canonical_scalar_value(witness)
}

pub(crate) fn validate_production_shape(
    statement: ManifestBoundAnchorLeafStatementV4,
    reduction: &CandidateNormReductionProofWitness,
    step: &CandidateStepProofWitness,
) -> Result<(), RelationError> {
    let shape = statement.shape;
    if shape.mode != CircuitCommitmentModeV4::Public
        || shape.gate_count != ANCHOR_GATE_COUNT
        || shape.commitment_count != 1
        || shape.n_vec_len != ANCHOR_NORM_LENGTH
        || shape.l_vec_len != ANCHOR_NORM_LENGTH
        || shape.round_count() != ANCHOR_LEAF_ROUNDS
        || reduction.left.len() != ANCHOR_LEAF_ROUNDS
        || reduction.right.len() != ANCHOR_LEAF_ROUNDS
        || step.left.len() != CONSTRUCTION_ROOT_ROUNDS
        || step.right.len() != CONSTRUCTION_ROOT_ROUNDS
    {
        return Err(RelationError::Malformed(
            "production anchor recurrence shape",
        ));
    }
    Ok(())
}
