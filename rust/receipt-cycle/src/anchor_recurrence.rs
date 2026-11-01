//! Fixed-matrix construction-parent recurrence for one public anchor.
//!
//! This relation authenticates one V4 leaf and one ordered algebraic
//! accumulation transition. It deliberately does not select a recursive
//! backend, encode a proof, or accept a construction receipt.
//!
//! Activation must fix the shape, generator digests, basis digest, and
//! manifest domain. The native verifier around the recursion must authenticate
//! the initial setup root in the coalition registry, derive `m0` from the
//! domain and version, construction statement digest, resolved setup digest,
//! seed root, and payload count, and start the index at zero. It must compare
//! the final manifest and count with the exact ordered public anchor payload
//! and run the native final decision on the resulting root. The compressed
//! root prefix and x coordinate are recursive state; its y coordinate remains
//! private but is curve- and parity-constrained here.

use ff::Field;

use crate::algebraic_circuit_norm_leaf::{
    install_manifest_bound_anchor_leaf, ManifestBoundAnchorLeaf, ManifestBoundAnchorLeafStatementV4,
};
use crate::algebraic_circuit_transcript::{
    CircuitCommitmentModeV4, CircuitProofTranscriptWitnessV4,
};
use crate::algebraic_transcript::BuilderTranscript;
use crate::construction_manifest::{
    CONSTRUCTION_ROOT_ROUNDS, CONSTRUCTION_STATE_ARITY, CONSTRUCTION_STEP_MANIFEST_DOMAIN,
};
use crate::norm_reduction::CandidateNormReductionProofWitness;
use crate::parent_relation::{
    allocate_encoded_point, append_constant_bytes, append_encoded_point, append_scalar,
    encoded_point_value, install_constrained_candidate_step, CandidateRootClaim,
    CandidateStepProofWitness, ConstrainedPendingClaim, ConstrainedPolynomialTerm,
};
use crate::relation_builder::{Builder, Expression, StateVariable, StatefulRelation};
use crate::secp_scalar::{
    allocate_canonical_scalar, canonical_scalar_value, coordinate_field_value, embedded_integer,
    SecpScalarVar, SecpScalarWitness,
};
use crate::{ReceiptCycleError, Scalar};

const ANCHOR_GATE_COUNT: usize = 8_192;
const ANCHOR_NORM_LENGTH: usize = 16_384;
const ANCHOR_LEAF_ROUNDS: usize = 14;
pub(crate) const ANCHOR_RECURRENCE_STATE_ARITY: usize = CONSTRUCTION_STATE_ARITY;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnchorRecurrenceStateWitness {
    pub(crate) root: CandidateRootClaim,
    /// Canonical big-endian secp256k1 coordinate-field element.
    pub(crate) manifest: [u8; 32],
    pub(crate) index: u32,
}

fn outer_scalar(bytes: [u8; 32]) -> Result<Scalar, ReceiptCycleError> {
    coordinate_field_value(bytes)
}

fn secp_scalar_value(witness: SecpScalarWitness) -> Result<Scalar, ReceiptCycleError> {
    canonical_scalar_value(witness)
}

fn allocate_state_inputs(
    builder: &mut Builder,
    state: &AnchorRecurrenceStateWitness,
) -> Result<Vec<StateVariable>, ReceiptCycleError> {
    if state.root.factors.len() != CONSTRUCTION_ROOT_ROUNDS {
        return Err(ReceiptCycleError::Malformed(
            "anchor recurrence root factors",
        ));
    }
    let point = encoded_point_value(state.root.point)?;
    let mut inputs = Vec::with_capacity(ANCHOR_RECURRENCE_STATE_ARITY);
    inputs.push(builder.allocate_state(Scalar::from(u64::from(state.root.point.encoded[0]))));
    inputs.push(builder.allocate_state(point.x));
    inputs.push(builder.allocate_state(secp_scalar_value(state.root.scale)?));
    for &factor in &state.root.factors {
        inputs.push(builder.allocate_state(secp_scalar_value(factor)?));
    }
    inputs.push(builder.allocate_state(outer_scalar(state.manifest)?));
    inputs.push(builder.allocate_state(Scalar::from(u64::from(state.index))));
    debug_assert_eq!(inputs.len(), ANCHOR_RECURRENCE_STATE_ARITY);
    Ok(inputs)
}

fn bind_state_scalar(
    builder: &mut Builder,
    state: &StateVariable,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let scalar = allocate_canonical_scalar(builder, witness)?;
    builder.constrain_equal(state.expression(), &embedded_integer(&scalar));
    Ok(scalar)
}

fn bind_prior_root(
    builder: &mut Builder,
    inputs: &[StateVariable],
    root: &CandidateRootClaim,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    let point = allocate_encoded_point(builder, root.point)?;
    builder.constrain_equal(inputs[0].expression(), &point.prefix);
    builder.constrain_equal(inputs[1].expression(), &point.point.x);
    let scale = bind_state_scalar(builder, &inputs[2], root.scale)?;
    let factors = root
        .factors
        .iter()
        .enumerate()
        .map(|(index, &factor)| bind_state_scalar(builder, &inputs[3 + index], factor))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConstrainedPendingClaim {
        point,
        polynomial: vec![ConstrainedPolynomialTerm {
            scale,
            offset: 0,
            factors,
        }],
    })
}

fn install_manifest_transition(
    builder: &mut Builder,
    prior_manifest: &Expression,
    index: &Expression,
    leaf: &ManifestBoundAnchorLeaf,
) -> Result<Expression, ReceiptCycleError> {
    let mut transcript = BuilderTranscript::new();
    append_constant_bytes(&mut transcript, builder, CONSTRUCTION_STEP_MANIFEST_DOMAIN)?;
    transcript.append_field(builder, prior_manifest.clone());
    transcript.append_field(builder, index.clone());
    leaf.circuit_binding_digest
        .append_to(&mut transcript, builder)?;
    append_scalar(&mut transcript, builder, &leaf.precommitment);
    append_encoded_point(&mut transcript, builder, &leaf.coefficient_commitment);
    append_encoded_point(&mut transcript, builder, &leaf.anchored_offset);
    Ok(transcript.challenge(builder, 0)[0].clone())
}

fn expose_output_state(
    builder: &mut Builder,
    root: &crate::parent_relation::CandidateDerivedRoot,
    manifest: &Expression,
    next_index: &Expression,
) -> Vec<StateVariable> {
    let mut outputs = Vec::with_capacity(ANCHOR_RECURRENCE_STATE_ARITY);
    outputs.push(builder.expose_state(&root.point.prefix));
    outputs.push(builder.expose_state(&root.point.point.x));
    outputs.push(builder.expose_state(&embedded_integer(&root.scale)));
    for factor in &root.factors {
        outputs.push(builder.expose_state(&embedded_integer(factor)));
    }
    outputs.push(builder.expose_state(manifest));
    outputs.push(builder.expose_state(next_index));
    debug_assert_eq!(outputs.len(), ANCHOR_RECURRENCE_STATE_ARITY);
    outputs
}

fn validate_production_shape(
    statement: ManifestBoundAnchorLeafStatementV4,
    reduction: &CandidateNormReductionProofWitness,
    step: &CandidateStepProofWitness,
) -> Result<(), ReceiptCycleError> {
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
        return Err(ReceiptCycleError::Malformed(
            "production anchor recurrence shape",
        ));
    }
    Ok(())
}

fn build_anchor_recurrence_relation_inner(
    mut builder: Builder,
    state: &AnchorRecurrenceStateWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
    step_proof: &CandidateStepProofWitness,
    require_production_shape: bool,
) -> Result<StatefulRelation, ReceiptCycleError> {
    if require_production_shape {
        validate_production_shape(statement, reduction_proof, step_proof)?;
    } else if step_proof.left.len() != CONSTRUCTION_ROOT_ROUNDS
        || step_proof.right.len() != CONSTRUCTION_ROOT_ROUNDS
    {
        return Err(ReceiptCycleError::Malformed(
            "anchor recurrence step rounds",
        ));
    }
    state
        .index
        .checked_add(1)
        .ok_or(ReceiptCycleError::Malformed("anchor recurrence index"))?;
    let inputs = allocate_state_inputs(&mut builder, state)?;
    let prior_root = bind_prior_root(&mut builder, &inputs, &state.root)?;
    let leaf = install_manifest_bound_anchor_leaf(
        &mut builder,
        statement,
        transcript_witness,
        reduction_proof,
    )?;
    let next_manifest = install_manifest_transition(
        &mut builder,
        inputs[18].expression(),
        inputs[19].expression(),
        &leaf,
    )?;
    let claims = [prior_root, leaf.claim];
    let root = install_constrained_candidate_step(
        &mut builder,
        statement.basis_digest,
        &claims,
        step_proof,
    )?;
    let next_index = inputs[19]
        .expression()
        .clone()
        .add(&Expression::constant(Scalar::ONE));
    let outputs = expose_output_state(&mut builder, &root, &next_manifest, &next_index);
    builder.finish_stateful(&inputs, &outputs)
}

pub(crate) fn build_anchor_recurrence_relation(
    state: &AnchorRecurrenceStateWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
    step_proof: &CandidateStepProofWitness,
) -> Result<StatefulRelation, ReceiptCycleError> {
    build_anchor_recurrence_relation_with_builder(
        Builder::default(),
        state,
        statement,
        transcript_witness,
        reduction_proof,
        step_proof,
    )
}

pub(crate) fn build_anchor_recurrence_relation_with_builder(
    builder: Builder,
    state: &AnchorRecurrenceStateWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
    step_proof: &CandidateStepProofWitness,
) -> Result<StatefulRelation, ReceiptCycleError> {
    build_anchor_recurrence_relation_inner(
        builder,
        state,
        statement,
        transcript_witness,
        reduction_proof,
        step_proof,
        true,
    )
}
#[cfg(test)]
mod tests;
