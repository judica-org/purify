//! Direct Nova state binding and ordered construction manifests.

use std::array;

use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError},
    traits::circuit::StepCircuit,
};

use crate::candidate::CandidateStepProofWitness;
use crate::circuit_norm::{CandidateNormReductionProofWitness, ManifestBoundAnchorLeafStatementV4};
use crate::circuit_transcript::{CircuitCommitmentModeV4, CircuitProofTranscriptWitnessV4};
use crate::construction_manifest::CONSTRUCTION_STEP_MANIFEST_DOMAIN;
use crate::construction_profile::{
    ANCHOR_RECURRENCE_STATE_ARITY, CONSTRUCTION_PARENT_BASIS_DIGEST,
    CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST, CONSTRUCTION_ROOT_ROUNDS,
};
use crate::construction_recurrence::{
    validate_production_shape, AnchorRecurrenceStateWitness, MANIFEST_INDEX, ROOT_FACTORS_START,
    ROOT_PREFIX_INDEX, ROOT_SCALE_INDEX, ROOT_X_INDEX, STEP_INDEX,
};
use crate::nova_candidate::{
    install_constrained_candidate_step, DirectCandidateRoot, DirectPendingClaim,
    DirectPolynomialTerm,
};
use crate::nova_circuit_norm_leaf::constrain_manifest_bound_anchor_leaf;
use crate::nova_protocol_transcript::{
    append_bytes, append_constant_bytes, append_point, append_scalar, challenge,
};
use crate::nova_secp::{allocate_encoded_point, DirectEncodedSecpPoint};
use crate::nova_secp_scalar::{allocate_canonical_scalar, CanonicalSecpScalar};
use crate::nova_sha256_transcript::{NovaByte, NovaTranscript};
use crate::nova_types::DirectRelationId;
use crate::Scalar;

const FIELD_BITS: usize = 256;

/// Relation identity of the exact production construction-parent profile.
pub(crate) const CONSTRUCTION_PARENT_DIRECT_RELATION_ID: DirectRelationId =
    DirectRelationId::from_frozen_bytes([
        0x92, 0xee, 0x3f, 0x35, 0x72, 0xc6, 0xff, 0x1c, 0x9c, 0x41, 0xc7, 0x71, 0x99, 0x5c, 0xd7,
        0x08, 0x81, 0xdb, 0x85, 0x44, 0x47, 0x2d, 0x87, 0xac, 0x00, 0xa5, 0x67, 0x5c, 0x99, 0x81,
        0xbe, 0xde,
    ]);

pub(crate) struct DirectPriorState {
    pub(crate) root_claim: DirectPendingClaim,
    manifest: [NovaByte; 32],
    index: AllocatedNum<Scalar>,
    index_bytes: [NovaByte; 32],
}

#[derive(Clone)]
pub(crate) struct ConstructionParentStep {
    state: AnchorRecurrenceStateWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript: CircuitProofTranscriptWitnessV4,
    reduction: CandidateNormReductionProofWitness,
    proof: CandidateStepProofWitness,
    input_state: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
}

/// Reduced-shape test circuit, intentionally ineligible for Nova sessions.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestConstructionParentStep(ConstructionParentStep);

impl ConstructionParentStep {
    pub(crate) fn new(
        state: AnchorRecurrenceStateWitness,
        statement: ManifestBoundAnchorLeafStatementV4,
        transcript: CircuitProofTranscriptWitnessV4,
        reduction: CandidateNormReductionProofWitness,
        proof: CandidateStepProofWitness,
    ) -> Result<Self, crate::RelationError> {
        validate_production_shape(statement, &reduction, &proof)?;
        if statement.raw_generator_digest != CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST
            || statement.basis_digest != CONSTRUCTION_PARENT_BASIS_DIGEST
        {
            return Err(crate::RelationError::Malformed(
                "construction recurrence profile digest",
            ));
        }
        Self::new_inner(state, statement, transcript, reduction, proof)
    }

    fn new_inner(
        state: AnchorRecurrenceStateWitness,
        statement: ManifestBoundAnchorLeafStatementV4,
        transcript: CircuitProofTranscriptWitnessV4,
        reduction: CandidateNormReductionProofWitness,
        proof: CandidateStepProofWitness,
    ) -> Result<Self, crate::RelationError> {
        statement.shape.validate()?;
        state
            .index
            .checked_add(1)
            .ok_or(crate::RelationError::Malformed(
                "construction recurrence index",
            ))?;
        let input_state = state.state_fields()?;
        Ok(Self {
            state,
            statement,
            transcript,
            reduction,
            proof,
            input_state,
        })
    }

    pub(crate) const fn input_state(&self) -> &[Scalar; ANCHOR_RECURRENCE_STATE_ARITY] {
        &self.input_state
    }

    fn synthesize_relation<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        if z.len() != ANCHOR_RECURRENCE_STATE_ARITY {
            return Err(synthesis_error("construction recurrence state arity"));
        }
        let prior = bind_prior_state(cs.namespace(|| "prior state"), z, &self.state)?;
        let leaf = constrain_manifest_bound_anchor_leaf(
            cs.namespace(|| "anchor leaf"),
            self.statement,
            &self.transcript,
            &self.reduction,
        )?;
        let manifest = install_manifest_transition(
            cs.namespace(|| "manifest transition"),
            &prior,
            DirectManifestLeaf::new(
                &leaf.circuit_binding_digest,
                &leaf.precommitment,
                &leaf.coefficient_commitment,
                &leaf.anchored_offset,
            ),
        )?;
        let claims = [prior.root_claim.clone(), leaf.claim];
        let root = install_constrained_candidate_step(
            cs.namespace(|| "candidate step"),
            self.statement.basis_digest,
            &claims,
            &self.proof,
        )?;
        expose_output_state(cs.namespace(|| "output state"), &prior, &root, &manifest)
    }
}

#[cfg(test)]
impl TestConstructionParentStep {
    pub(crate) fn new(
        state: AnchorRecurrenceStateWitness,
        statement: ManifestBoundAnchorLeafStatementV4,
        transcript: CircuitProofTranscriptWitnessV4,
        reduction: CandidateNormReductionProofWitness,
        proof: CandidateStepProofWitness,
    ) -> Result<Self, crate::RelationError> {
        if statement.shape.mode != CircuitCommitmentModeV4::Public
            || statement.shape.commitment_count != 1
            || reduction.left.len() != statement.shape.round_count()
            || reduction.right.len() != statement.shape.round_count()
            || proof.left.len() != CONSTRUCTION_ROOT_ROUNDS
            || proof.right.len() != CONSTRUCTION_ROOT_ROUNDS
        {
            return Err(crate::RelationError::Malformed(
                "direct construction recurrence shape",
            ));
        }
        ConstructionParentStep::new_inner(state, statement, transcript, reduction, proof).map(Self)
    }
}

impl StepCircuit<Scalar> for ConstructionParentStep {
    fn arity(&self) -> usize {
        ANCHOR_RECURRENCE_STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        self.synthesize_relation(cs, z)
    }
}

#[cfg(test)]
impl StepCircuit<Scalar> for TestConstructionParentStep {
    fn arity(&self) -> usize {
        self.0.arity()
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        self.0.synthesize(cs, z)
    }
}

/// Values from a verified leaf that are ordered into the parent manifest.
///
/// This is the only seam between the direct norm leaf and the recurrence.
/// It deliberately carries constrained values, not a second witness model.
pub(crate) struct DirectManifestLeaf<'a> {
    binding_digest: &'a [NovaByte; 32],
    precommitment: &'a CanonicalSecpScalar,
    coefficient_commitment: &'a DirectEncodedSecpPoint,
    anchored_offset: &'a DirectEncodedSecpPoint,
}

impl<'a> DirectManifestLeaf<'a> {
    pub(crate) fn new(
        binding_digest: &'a [NovaByte; 32],
        precommitment: &'a CanonicalSecpScalar,
        coefficient_commitment: &'a DirectEncodedSecpPoint,
        anchored_offset: &'a DirectEncodedSecpPoint,
    ) -> Self {
        Self {
            binding_digest,
            precommitment,
            coefficient_commitment,
            anchored_offset,
        }
    }
}

impl DirectPriorState {
    pub(crate) fn index(&self) -> &AllocatedNum<Scalar> {
        &self.index
    }
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn enforce_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
    expected: LinearCombination<Scalar>,
) {
    cs.enforce(
        || "state field binding",
        |linear| linear + value.get_variable(),
        |linear| linear + CS::one(),
        |_| expected,
    );
}

fn field_bytes_be<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<[NovaByte; 32], SynthesisError> {
    let bits = value.to_bits_le_strict(cs.namespace(|| "canonical field bits"))?;
    if bits.len() != FIELD_BITS {
        return Err(synthesis_error("construction state field width"));
    }
    Ok(array::from_fn(|byte| {
        let offset = (31 - byte) * 8;
        NovaByte::from_constrained_bits_le(array::from_fn(|bit| bits[offset + bit].clone()))
    }))
}

fn bind_scalar<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &AllocatedNum<Scalar>,
    witness: crate::secp_native::SecpScalarWitness,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let scalar = allocate_canonical_scalar(cs.namespace(|| "canonical scalar"), witness)?;
    enforce_equal(cs.namespace(|| "embedded scalar"), state, scalar.embedded());
    Ok(scalar)
}

pub(crate) fn bind_prior_state<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &[AllocatedNum<Scalar>],
    witness: &AnchorRecurrenceStateWitness,
) -> Result<DirectPriorState, SynthesisError> {
    if state.len() != ANCHOR_RECURRENCE_STATE_ARITY
        || witness.root.factors.len() != CONSTRUCTION_ROOT_ROUNDS
    {
        return Err(synthesis_error("construction recurrence state shape"));
    }

    let point = allocate_encoded_point(cs.namespace(|| "root point"), witness.root.point)?;
    enforce_equal(
        cs.namespace(|| "root prefix"),
        &state[ROOT_PREFIX_INDEX],
        LinearCombination::zero() + point.prefix().get_variable(),
    );
    enforce_equal(
        cs.namespace(|| "root x"),
        &state[ROOT_X_INDEX],
        LinearCombination::zero() + point.point().x().get_variable(),
    );
    let scale = bind_scalar(
        cs.namespace(|| "root scale"),
        &state[ROOT_SCALE_INDEX],
        witness.root.scale,
    )?;
    let factors = witness
        .root
        .factors
        .iter()
        .copied()
        .enumerate()
        .map(|(index, factor)| {
            bind_scalar(
                cs.namespace(|| format!("root factor {index}")),
                &state[ROOT_FACTORS_START + index],
                factor,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let manifest = field_bytes_be(cs.namespace(|| "prior manifest"), &state[MANIFEST_INDEX])?;
    let index_bytes = field_bytes_be(cs.namespace(|| "step index"), &state[STEP_INDEX])?;
    Ok(DirectPriorState {
        root_claim: DirectPendingClaim {
            point,
            polynomial: vec![DirectPolynomialTerm {
                scale,
                offset: 0,
                factors,
            }],
        },
        manifest,
        index: state[STEP_INDEX].clone(),
        index_bytes,
    })
}

pub(crate) fn install_manifest_transition<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &DirectPriorState,
    leaf: DirectManifestLeaf<'_>,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let mut transcript = NovaTranscript::new();
    append_constant_bytes(&mut transcript, CONSTRUCTION_STEP_MANIFEST_DOMAIN)?;
    transcript.append_field(&state.manifest);
    transcript.append_field(&state.index_bytes);
    append_bytes(&mut transcript, leaf.binding_digest)?;
    append_scalar(&mut transcript, leaf.precommitment)?;
    append_point(&mut transcript, leaf.coefficient_commitment);
    append_point(&mut transcript, leaf.anchored_offset);
    challenge(cs.namespace(|| "next manifest"), &mut transcript, 0)
}

fn scalar_assignment(value: &CanonicalSecpScalar) -> Result<Option<Scalar>, SynthesisError> {
    value
        .integer()
        .map(|value| {
            Scalar::from_str_vartime(&value.to_string())
                .ok_or_else(|| synthesis_error("construction scalar embedding"))
        })
        .transpose()
}

fn materialize_scalar<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &CanonicalSecpScalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let output = AllocatedNum::alloc(cs.namespace(|| "state output"), || {
        scalar_assignment(value)?.ok_or(SynthesisError::AssignmentMissing)
    })?;
    enforce_equal(
        cs.namespace(|| "state output binding"),
        &output,
        value.embedded(),
    );
    Ok(output)
}

fn increment_index<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    index: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let next = AllocatedNum::alloc(cs.namespace(|| "next index"), || {
        index
            .get_value()
            .map(|value| value + Scalar::ONE)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "increment index",
        |linear| linear + index.get_variable() + CS::one(),
        |linear| linear + CS::one(),
        |linear| linear + next.get_variable(),
    );
    Ok(next)
}

pub(crate) fn expose_output_state<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    prior: &DirectPriorState,
    root: &DirectCandidateRoot,
    manifest: &CanonicalSecpScalar,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    if root.factors.len() != CONSTRUCTION_ROOT_ROUNDS {
        return Err(synthesis_error("construction output root shape"));
    }
    let mut output = Vec::with_capacity(ANCHOR_RECURRENCE_STATE_ARITY);
    output.push(root.point.prefix().clone());
    output.push(root.point.point().x().clone());
    output.push(materialize_scalar(
        cs.namespace(|| "root scale"),
        &root.scale,
    )?);
    for (index, factor) in root.factors.iter().enumerate() {
        output.push(materialize_scalar(
            cs.namespace(|| format!("root factor {index}")),
            factor,
        )?);
    }
    output.push(materialize_scalar(cs.namespace(|| "manifest"), manifest)?);
    output.push(increment_index(
        cs.namespace(|| "step index"),
        prior.index(),
    )?);
    debug_assert_eq!(output.len(), ANCHOR_RECURRENCE_STATE_ARITY);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use nova_snark::frontend::{
        shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem,
    };

    use super::*;
    use crate::candidate::CandidateRootClaim;
    use crate::construction_manifest::{
        derive_step_manifest, ConstructionManifestAnchor, ConstructionManifestStepInput,
    };
    use crate::nova_secp::allocate_encoded_point;
    use crate::nova_secp_scalar::allocate_canonical_scalar;
    use crate::nova_types::DirectNovaPrimaryEngine;
    use crate::secp_native::{SecpEncodedPointWitness, SecpScalarWitness};

    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn generator(prefix: u8) -> SecpEncodedPointWitness {
        let mut encoded = [0; 33];
        encoded[0] = prefix;
        encoded[1..].copy_from_slice(&GENERATOR_X);
        SecpEncodedPointWitness::parse(encoded).expect("generator")
    }

    fn state(marker: u8, point: SecpEncodedPointWitness) -> AnchorRecurrenceStateWitness {
        AnchorRecurrenceStateWitness {
            root: CandidateRootClaim {
                point,
                scale: SecpScalarWitness::from_u64(u64::from(marker) + 1),
                factors: (0..CONSTRUCTION_ROOT_ROUNDS)
                    .map(|index| SecpScalarWitness::from_u64(u64::from(marker) + index as u64 + 2))
                    .collect(),
            },
            manifest: [marker; 32],
            index: u32::from(marker),
        }
    }

    fn allocate_state<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        witness: &AnchorRecurrenceStateWitness,
    ) -> Vec<AllocatedNum<Scalar>> {
        witness
            .state_fields()
            .expect("state fields")
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                AllocatedNum::alloc_input(cs.namespace(|| format!("state {index}")), || Ok(value))
                    .expect("state input")
            })
            .collect()
    }

    fn allocate_bytes<CS: ConstraintSystem<Scalar>>(mut cs: CS, value: [u8; 32]) -> [NovaByte; 32] {
        array::from_fn(|index| {
            NovaByte::allocate(cs.namespace(|| format!("byte {index}")), value[index])
                .expect("byte")
        })
    }

    fn direct_scalar_bytes(value: &CanonicalSecpScalar) -> [u8; 32] {
        let (_, encoded) = value.integer().expect("scalar witness").to_bytes_be();
        let mut bytes = [0; 32];
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        bytes
    }

    fn synthesize(
        state_witness: &AnchorRecurrenceStateWitness,
        binding: [u8; 32],
        precommitment: SecpScalarWitness,
        coefficient: SecpEncodedPointWitness,
        offset: SecpEncodedPointWitness,
    ) -> ShapeCS<DirectNovaPrimaryEngine> {
        let mut cs = ShapeCS::<DirectNovaPrimaryEngine>::new();
        let inputs = allocate_state(cs.namespace(|| "state inputs"), state_witness);
        let state = bind_prior_state(cs.namespace(|| "state binding"), &inputs, state_witness)
            .expect("state binding");
        let binding = allocate_bytes(cs.namespace(|| "binding digest"), binding);
        let precommitment =
            allocate_canonical_scalar(cs.namespace(|| "precommitment"), precommitment)
                .expect("precommitment");
        let coefficient = allocate_encoded_point(cs.namespace(|| "coefficient"), coefficient)
            .expect("coefficient");
        let offset = allocate_encoded_point(cs.namespace(|| "offset"), offset).expect("offset");
        let manifest = install_manifest_transition(
            cs.namespace(|| "manifest"),
            &state,
            DirectManifestLeaf::new(&binding, &precommitment, &coefficient, &offset),
        )
        .expect("manifest transition");
        let root_claim = state.root_claim.clone();
        let root_term = &root_claim.polynomial[0];
        let root = DirectCandidateRoot {
            point: root_claim.point,
            scale: root_term.scale.clone(),
            factors: root_term.factors.clone(),
        };
        expose_output_state(cs.namespace(|| "output state"), &state, &root, &manifest)
            .expect("output state");
        cs
    }

    #[test]
    fn direct_manifest_matches_native_transition() {
        let state_witness = state(7, generator(2));
        let binding = [0x31; 32];
        let precommitment = SecpScalarWitness::from_u64(19);
        let coefficient = generator(3);
        let offset = SecpEncodedPointWitness::identity();

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let inputs = allocate_state(cs.namespace(|| "state inputs"), &state_witness);
        let state = bind_prior_state(cs.namespace(|| "state binding"), &inputs, &state_witness)
            .expect("state binding");
        assert_eq!(state.index().get_value(), Some(Scalar::from(7)));
        assert_eq!(
            state.root_claim.point.prefix().get_value(),
            inputs[ROOT_PREFIX_INDEX].get_value()
        );
        assert_eq!(
            state.root_claim.point.point().x().get_value(),
            inputs[ROOT_X_INDEX].get_value()
        );
        assert_eq!(state.root_claim.polynomial.len(), 1);
        let root_term = &state.root_claim.polynomial[0];
        assert_eq!(root_term.offset, 0);
        assert_eq!(
            direct_scalar_bytes(&root_term.scale),
            state_witness.root.scale.bytes
        );
        assert_eq!(root_term.factors.len(), CONSTRUCTION_ROOT_ROUNDS);
        for (actual, expected) in root_term.factors.iter().zip(&state_witness.root.factors) {
            assert_eq!(direct_scalar_bytes(actual), expected.bytes);
        }
        assert_eq!(
            state.manifest.each_ref().map(NovaByte::value),
            state_witness.manifest
        );
        let binding_vars = allocate_bytes(cs.namespace(|| "binding digest"), binding);
        let precommitment_var =
            allocate_canonical_scalar(cs.namespace(|| "precommitment"), precommitment)
                .expect("precommitment");
        let coefficient_var = allocate_encoded_point(cs.namespace(|| "coefficient"), coefficient)
            .expect("coefficient");
        let offset_var = allocate_encoded_point(cs.namespace(|| "offset"), offset).expect("offset");
        let actual = install_manifest_transition(
            cs.namespace(|| "manifest"),
            &state,
            DirectManifestLeaf::new(
                &binding_vars,
                &precommitment_var,
                &coefficient_var,
                &offset_var,
            ),
        )
        .expect("direct manifest");

        let anchor = ConstructionManifestAnchor::new(
            binding,
            precommitment.bytes,
            coefficient.encoded,
            offset.encoded,
        )
        .expect("manifest anchor");
        let expected = derive_step_manifest(
            &ConstructionManifestStepInput::new(state_witness.manifest, 7, anchor)
                .expect("manifest input"),
        )
        .expect("native manifest");
        assert_eq!(direct_scalar_bytes(&actual), expected);

        let root_claim = state.root_claim.clone();
        let root_term = &root_claim.polynomial[0];
        let root = DirectCandidateRoot {
            point: root_claim.point,
            scale: root_term.scale.clone(),
            factors: root_term.factors.clone(),
        };
        let output = expose_output_state(cs.namespace(|| "output state"), &state, &root, &actual)
            .expect("output state");
        let expected_state = AnchorRecurrenceStateWitness {
            root: state_witness.root.clone(),
            manifest: expected,
            index: state_witness.index + 1,
        }
        .state_fields()
        .expect("expected output state");
        assert_eq!(output.len(), ANCHOR_RECURRENCE_STATE_ARITY);
        assert_eq!(
            output
                .iter()
                .map(AllocatedNum::get_value)
                .collect::<Option<Vec<_>>>()
                .expect("output assignments"),
            expected_state
        );
        assert!(cs.is_satisfied(), "{:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn direct_state_and_manifest_shape_exclude_witnesses() {
        let first = synthesize(
            &state(7, generator(2)),
            [0x31; 32],
            SecpScalarWitness::from_u64(19),
            generator(3),
            SecpEncodedPointWitness::identity(),
        );
        let second = synthesize(
            &state(8, SecpEncodedPointWitness::identity()),
            [0x52; 32],
            SecpScalarWitness::from_u64(23),
            SecpEncodedPointWitness::identity(),
            generator(2),
        );
        assert_eq!(first.num_inputs(), ANCHOR_RECURRENCE_STATE_ARITY + 1);
        assert_eq!(first.num_inputs(), second.num_inputs());
        assert_eq!(first.num_aux(), second.num_aux());
        assert_eq!(first.constraints, second.constraints);
    }
}
