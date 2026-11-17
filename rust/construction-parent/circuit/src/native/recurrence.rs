//! Backend-independent construction-parent recurrence inputs.
//!
//! The recursive backends share one witness model and one exact 20-field
//! public-state encoding. Backend-specific constraint code must bind this
//! encoding rather than reinterpret or reorder it.

use ff::Field;

use crate::native::candidate::{CandidateRootClaim, CandidateStepProofWitness};
use crate::native::circuit_norm::{
    CandidateNormReductionProofWitness, ManifestBoundConstructionLeafStatementV4,
};
use crate::native::circuit_transcript::CircuitCommitmentModeV4;
use crate::native::secp::{
    canonical_scalar_value, coordinate_field_value, encoded_point_value, SecpScalarWitness,
};
use crate::profile::{
    CONSTRUCTION_LEAF_GATE_COUNT, CONSTRUCTION_LEAF_NORM_LENGTH, CONSTRUCTION_LEAF_ROUNDS,
    CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_ROUNDS, CONSTRUCTION_ROOT_STATE_ARITY,
};
use statement::{RelationError, Scalar};

pub(crate) const ROOT_PREFIX_INDEX: usize = 0;
pub(crate) const ROOT_X_INDEX: usize = 1;
pub(crate) const ROOT_SCALE_INDEX: usize = 2;
pub(crate) const ROOT_FACTORS_START: usize = 3;
pub(crate) const MANIFEST_INDEX: usize = CONSTRUCTION_ROOT_STATE_ARITY;
pub(crate) const STEP_INDEX: usize = MANIFEST_INDEX + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructionRecurrenceStateWitness {
    pub root: CandidateRootClaim,
    /// Canonical big-endian secp256k1 coordinate-field element.
    pub manifest: [u8; 32],
    pub index: u32,
}

impl ConstructionRecurrenceStateWitness {
    /// Returns the recurrence's exact public-state field order.
    pub fn state_fields(
        &self,
    ) -> Result<[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY], RelationError> {
        if self.root.factors.len() != CONSTRUCTION_ROOT_ROUNDS {
            return Err(RelationError::Malformed(
                "construction recurrence root factors",
            ));
        }
        let point = encoded_point_value(self.root.point)?;
        let mut state = [Scalar::ZERO; CONSTRUCTION_RECURRENCE_STATE_ARITY];
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

pub fn validate_production_shape(
    statement: ManifestBoundConstructionLeafStatementV4,
    reduction: &CandidateNormReductionProofWitness,
    step: &CandidateStepProofWitness,
) -> Result<(), RelationError> {
    let shape = statement.shape;
    if shape.mode != CircuitCommitmentModeV4::Public
        || shape.gate_count != CONSTRUCTION_LEAF_GATE_COUNT
        || shape.commitment_count != 1
        || shape.n_vec_len != CONSTRUCTION_LEAF_NORM_LENGTH
        || shape.l_vec_len != CONSTRUCTION_LEAF_NORM_LENGTH
        || shape.round_count() != CONSTRUCTION_LEAF_ROUNDS
        || reduction.left.len() != CONSTRUCTION_LEAF_ROUNDS
        || reduction.right.len() != CONSTRUCTION_LEAF_ROUNDS
        || step.left.len() != CONSTRUCTION_ROOT_ROUNDS
        || step.right.len() != CONSTRUCTION_ROOT_ROUNDS
    {
        return Err(RelationError::Malformed(
            "production construction leaf recurrence shape",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_STATE_ARITY};
    use statement::manifest::ConstructionManifestSeed;

    #[test]
    fn initial_recurrence_witness_matches_the_verifier_derived_state() {
        let seed = ConstructionManifestSeed::new([0x31; 32], [0x52; 32], [0x71; 64], 1, 1)
            .expect("construction manifest seed");
        assert_eq!(seed.root().canonical_bytes(), &[0; CONSTRUCTION_ROOT_BYTES]);
        let (fields, manifest) = seed
            .initial_state_and_manifest()
            .expect("nonzero initial manifest");
        let witness = ConstructionRecurrenceStateWitness {
            root: CandidateRootClaim::from_root(seed.root()),
            manifest: manifest.manifest(),
            index: manifest.index(),
        };
        assert_eq!(witness.index, 0);
        assert_eq!(
            witness.state_fields().expect("recurrence witness fields"),
            fields
        );
        assert_eq!(fields.len(), CONSTRUCTION_STATE_ARITY);
        assert_eq!(
            &fields[..CONSTRUCTION_ROOT_STATE_ARITY],
            &seed.root().state_fields()
        );
    }
}
