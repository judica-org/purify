use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;

use super::*;
use crate::algebraic_circuit_norm_leaf::install_manifest_bound_anchor_leaf;
use crate::algebraic_circuit_transcript::{
    install_transcript, CircuitPointPairWitnessV4, CircuitTranscriptShapeV4,
};
use crate::construction_manifest::{
    derive_step_manifest, ConstructionManifestAnchor, ConstructionManifestStepInput,
};
use crate::parent_relation::{
    add_point_values, derive_candidate_folded_generator, CandidatePendingClaimWitness,
    CandidatePolynomialTermWitness, ConstrainedPendingClaim, EncodedSecpPoint, PointValue,
    SecpEncodedPointWitness,
};
use crate::relation_builder::{circuit_digest, Builder, StateWire};
use crate::secp_scalar::SecpScalarVar;
use crate::{Assignment, Circuit, WireKind};

const RAW_GENERATORS: [u8; 32] = [0x52; 32];
const BASIS: [u8; 32] = [0x73; 32];
const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn small_anchor_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: 2,
        commitment_count: 1,
        n_vec_len: 4,
        l_vec_len: 4,
    }
}

fn production_anchor_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: ANCHOR_GATE_COUNT,
        commitment_count: 1,
        n_vec_len: ANCHOR_NORM_LENGTH,
        l_vec_len: ANCHOR_NORM_LENGTH,
    }
}

fn identity_pair() -> CircuitPointPairWitnessV4 {
    CircuitPointPairWitnessV4 {
        encoded: [0; 65],
        first_y: [0; 32],
        second_y: [0; 32],
    }
}

fn zero_transcript_witness(shape: CircuitTranscriptShapeV4) -> CircuitProofTranscriptWitnessV4 {
    CircuitProofTranscriptWitnessV4 {
        public_commitments: vec![SecpEncodedPointWitness::identity()],
        raw_commitment: SecpEncodedPointWitness::identity(),
        coefficient_commitment: SecpEncodedPointWitness::identity(),
        anchored_offset: SecpEncodedPointWitness::identity(),
        anchored_commitment: SecpEncodedPointWitness::identity(),
        batched_public_commitment: SecpEncodedPointWitness::identity(),
        dlog_nonce: SecpEncodedPointWitness::identity(),
        dlog_response: SecpScalarWitness::from_u64(0),
        mask_commitment: SecpEncodedPointWitness::identity(),
        t2: SecpScalarWitness::from_u64(0),
        combined_commitment: SecpEncodedPointWitness::identity(),
        rounds: vec![identity_pair(); shape.round_count()],
        terminal_n: SecpScalarWitness::from_u64(0),
        terminal_l: SecpScalarWitness::from_u64(0),
    }
}

fn zero_reduction_proof(shape: CircuitTranscriptShapeV4) -> CandidateNormReductionProofWitness {
    CandidateNormReductionProofWitness {
        coefficient_evaluation: SecpScalarWitness::from_u64(0),
        left: vec![SecpEncodedPointWitness::identity(); shape.round_count()],
        right: vec![SecpEncodedPointWitness::identity(); shape.round_count()],
        terminal_scalar: SecpScalarWitness::from_u64(0),
        folded_generator: SecpEncodedPointWitness::identity(),
    }
}

fn generator() -> SecpEncodedPointWitness {
    let mut encoded = [0; 33];
    encoded[0] = 2;
    encoded[1..].copy_from_slice(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ]);
    SecpEncodedPointWitness {
        encoded,
        y: [
            0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4,
            0x17, 0xfd, 0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26,
            0x77, 0xda, 0x3a, 0x48,
        ],
    }
}

fn point_value(point: SecpEncodedPointWitness) -> PointValue {
    if point.encoded == [0; 33] {
        return PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        };
    }
    let mut x = [0; 32];
    x.copy_from_slice(&point.encoded[1..]);
    x.reverse();
    PointValue {
        x: Secq256k1Cycle::scalar_from_canonical(&x).expect("canonical x"),
        y: Secq256k1Cycle::scalar_from_canonical(&point.y).expect("canonical y"),
        identity: false,
    }
}

fn encoded_value(point: PointValue) -> SecpEncodedPointWitness {
    if point.identity {
        return SecpEncodedPointWitness::identity();
    }
    let mut x = Secq256k1Cycle::scalar_to_canonical(&point.x);
    let y = Secq256k1Cycle::scalar_to_canonical(&point.y);
    x.reverse();
    let mut encoded = [0; 33];
    encoded[0] = if y[0] & 1 == 0 { 2 } else { 3 };
    encoded[1..].copy_from_slice(&x);
    SecpEncodedPointWitness { encoded, y }
}

fn scale_value(point: PointValue, scalar: &BigUint) -> PointValue {
    let mut accumulator = PointValue {
        x: Scalar::ZERO,
        y: Scalar::ZERO,
        identity: true,
    };
    let mut addend = point;
    for bit in 0..256 {
        if scalar.bit(bit) {
            accumulator = add_point_values(accumulator, addend);
        }
        addend = add_point_values(addend, addend);
    }
    accumulator
}

fn scalar_witness(value: &BigUint) -> SecpScalarWitness {
    let encoded = value.to_bytes_be();
    assert!(encoded.len() <= 32);
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    SecpScalarWitness::from_bytes_be(bytes)
}

fn scalar_add_one(value: &BigUint) -> SecpScalarWitness {
    scalar_witness(&((value + BigUint::from(1u64)) % BigUint::from_bytes_be(&SECP_ORDER)))
}

fn finite_witness(
    shape: CircuitTranscriptShapeV4,
    binding: [u8; 32],
    raw: SecpEncodedPointWitness,
    offset: SecpEncodedPointWitness,
    mask: SecpEncodedPointWitness,
) -> CircuitProofTranscriptWitnessV4 {
    let mut witness = zero_transcript_witness(shape);
    witness.public_commitments = vec![generator()];
    witness.batched_public_commitment = generator();
    witness.dlog_nonce = generator();
    witness.raw_commitment = raw;
    witness.anchored_offset = offset;
    witness.anchored_commitment =
        encoded_value(add_point_values(point_value(raw), point_value(offset)));
    witness.mask_commitment = mask;
    let dlog_challenge = {
        let mut builder = Builder::default();
        install_transcript(&mut builder, shape, binding, RAW_GENERATORS, &witness)
            .expect("derive anchor DLog challenge")
            .dlog_challenge
            .integer()
            .clone()
    };
    witness.dlog_response = scalar_add_one(&dlog_challenge);
    let alpha = {
        let mut builder = Builder::default();
        install_transcript(&mut builder, shape, binding, RAW_GENERATORS, &witness)
            .expect("derive anchor alpha")
            .alpha
            .integer()
            .clone()
    };
    let masked = scale_value(point_value(mask), &alpha);
    witness.combined_commitment = encoded_value(add_point_values(
        point_value(witness.anchored_commitment),
        masked,
    ));
    witness
}

fn constrained_point_witness(point: &EncodedSecpPoint) -> SecpEncodedPointWitness {
    encoded_value(point.point.witness)
}

fn constrained_scalar_witness(scalar: &SecpScalarVar) -> SecpScalarWitness {
    scalar_witness(scalar.integer())
}

fn claim_witness(claim: &ConstrainedPendingClaim) -> CandidatePendingClaimWitness {
    CandidatePendingClaimWitness {
        point: constrained_point_witness(&claim.point),
        polynomial: claim
            .polynomial
            .iter()
            .map(|term| CandidatePolynomialTermWitness {
                scale: constrained_scalar_witness(&term.scale),
                offset: term.offset,
                factors: term
                    .factors
                    .iter()
                    .map(constrained_scalar_witness)
                    .collect(),
            })
            .collect(),
    }
}

fn root_claim_witness(root: &CandidateRootClaim) -> CandidatePendingClaimWitness {
    CandidatePendingClaimWitness {
        point: root.point,
        polynomial: vec![CandidatePolynomialTermWitness {
            scale: root.scale,
            offset: 0,
            factors: root.factors.clone(),
        }],
    }
}

fn leaf_claim_witness(
    statement: ManifestBoundAnchorLeafStatementV4,
    witness: &CircuitProofTranscriptWitnessV4,
    reduction: &CandidateNormReductionProofWitness,
) -> CandidatePendingClaimWitness {
    let mut builder = Builder::default();
    let leaf = install_manifest_bound_anchor_leaf(&mut builder, statement, witness, reduction)
        .expect("manifest-bound leaf");
    claim_witness(&leaf.claim)
}

fn step_proof(claims: &[CandidatePendingClaimWitness]) -> CandidateStepProofWitness {
    let mut proof = CandidateStepProofWitness {
        left: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        right: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        terminal_scalar: SecpScalarWitness::from_u64(1),
        folded_generator: SecpEncodedPointWitness::identity(),
    };
    proof.folded_generator =
        derive_candidate_folded_generator(BASIS, claims, &proof).expect("derive folded generator");
    proof
}

fn prior_state(manifest_byte: u8) -> AnchorRecurrenceStateWitness {
    AnchorRecurrenceStateWitness {
        root: CandidateRootClaim {
            point: generator(),
            scale: SecpScalarWitness::from_u64(0),
            factors: vec![SecpScalarWitness::from_u64(0); CONSTRUCTION_ROOT_ROUNDS],
        },
        manifest: [manifest_byte; 32],
        index: u32::from(manifest_byte),
    }
}

struct Fixture {
    state: AnchorRecurrenceStateWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
    witness: CircuitProofTranscriptWitnessV4,
    reduction: CandidateNormReductionProofWitness,
    claims: Vec<CandidatePendingClaimWitness>,
    proof: CandidateStepProofWitness,
}

fn fixture(
    binding_byte: u8,
    manifest_byte: u8,
    raw: SecpEncodedPointWitness,
    offset: SecpEncodedPointWitness,
    mask: SecpEncodedPointWitness,
) -> Fixture {
    let shape = small_anchor_shape();
    let statement = ManifestBoundAnchorLeafStatementV4 {
        shape,
        circuit_binding_digest: [binding_byte; 32],
        raw_generator_digest: RAW_GENERATORS,
        basis_digest: BASIS,
    };
    let witness = finite_witness(shape, statement.circuit_binding_digest, raw, offset, mask);
    let reduction = zero_reduction_proof(shape);
    let state = prior_state(manifest_byte);
    let claims = vec![
        root_claim_witness(&state.root),
        leaf_claim_witness(statement, &witness, &reduction),
    ];
    let proof = step_proof(&claims);
    Fixture {
        state,
        statement,
        witness,
        reduction,
        claims,
        proof,
    }
}

fn build_fixture(fixture: &Fixture) -> StatefulRelation {
    build_anchor_recurrence_relation_inner(
        &fixture.state,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
        &fixture.proof,
        false,
    )
    .expect("anchor recurrence")
}

fn structured_relation_satisfied(circuit: &Circuit, assignment: &Assignment) -> bool {
    circuit.constraints.iter().all(|constraint| {
        constraint.iter().fold(Scalar::ZERO, |sum, term| {
            let value = match term.kind {
                WireKind::One => Scalar::ONE,
                WireKind::Left => assignment.gates[term.index].0,
                WireKind::Right => assignment.gates[term.index].1,
                WireKind::Output => assignment.gates[term.index].0 * assignment.gates[term.index].1,
            };
            sum + term.coefficient * value
        }) == Scalar::ZERO
    })
}

fn relation_satisfied(circuit: &[u8], assignment: &[u8]) -> bool {
    let circuit = Circuit::parse(circuit).expect("test circuit");
    let assignment = Assignment::parse(assignment).expect("test assignment");
    structured_relation_satisfied(&circuit, &assignment)
}

fn change_state_wire(assignment: &Assignment, wire: StateWire) -> Assignment {
    assert_eq!(wire.kind, WireKind::Left);
    let mut assignment = assignment.clone();
    assignment.gates[wire.index].0 += Scalar::ONE;
    assignment
}

#[test]
fn manifest_transition_matches_native_transcript() {
    let fixture = fixture(
        0x31,
        1,
        generator(),
        SecpEncodedPointWitness::identity(),
        generator(),
    );
    let mut builder = Builder::default();
    let leaf = install_manifest_bound_anchor_leaf(
        &mut builder,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
    )
    .expect("manifest-bound leaf");
    let prior_manifest = outer_scalar(fixture.state.manifest).expect("manifest field");
    let index = Scalar::from(u64::from(fixture.state.index));
    let prior_variable = builder.allocate(prior_manifest);
    let index_variable = builder.allocate(index);
    let actual = install_manifest_transition(&mut builder, &prior_variable, &index_variable, &leaf)
        .expect("manifest transition");
    let anchor = ConstructionManifestAnchor::new(
        fixture.statement.circuit_binding_digest,
        constrained_scalar_witness(&leaf.precommitment),
        fixture.witness.coefficient_commitment,
        fixture.witness.anchored_offset,
    )
    .expect("native manifest anchor");
    let input =
        ConstructionManifestStepInput::new(fixture.state.manifest, fixture.state.index, anchor)
            .expect("native manifest input");
    let expected = outer_scalar(derive_step_manifest(&input).expect("native manifest"))
        .expect("manifest field");
    assert_eq!(actual.value(), expected);
    let (circuit, assignment) = builder.finish().expect("manifest relation");
    assert!(relation_satisfied(&circuit, &assignment));
}

#[test]
fn production_shape_is_exact() {
    assert_eq!(ANCHOR_RECURRENCE_STATE_ARITY, 20);
    let shape = production_anchor_shape();
    let statement = ManifestBoundAnchorLeafStatementV4 {
        shape,
        circuit_binding_digest: [0x31; 32],
        raw_generator_digest: RAW_GENERATORS,
        basis_digest: BASIS,
    };
    let reduction = zero_reduction_proof(shape);
    let step = CandidateStepProofWitness {
        left: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        right: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        terminal_scalar: SecpScalarWitness::from_u64(1),
        folded_generator: SecpEncodedPointWitness::identity(),
    };
    validate_production_shape(statement, &reduction, &step).expect("production shape");
}

#[test]
#[ignore = "run explicitly in release mode; the 15-round recurrence is large"]
fn recurrence_matrix_binds_state_order_and_anchor_substitution() {
    let generator = generator();
    let twice = encoded_value(add_point_values(
        point_value(generator),
        point_value(generator),
    ));
    let first = fixture(
        0x31,
        1,
        generator,
        SecpEncodedPointWitness::identity(),
        generator,
    );
    let second = fixture(0x32, 2, twice, generator, twice);

    let first_relation = build_fixture(&first);
    assert_eq!(
        first_relation.shape.inputs.len(),
        ANCHOR_RECURRENCE_STATE_ARITY
    );
    assert_eq!(
        first_relation.shape.outputs.len(),
        ANCHOR_RECURRENCE_STATE_ARITY
    );
    assert!(structured_relation_satisfied(
        &first_relation.shape.circuit,
        &first_relation.assignment
    ));
    for wire in [
        first_relation.shape.inputs[0],
        first_relation.shape.inputs[18],
        first_relation.shape.inputs[19],
        first_relation.shape.outputs[18],
    ] {
        let changed = change_state_wire(&first_relation.assignment, wire);
        assert!(!structured_relation_satisfied(
            &first_relation.shape.circuit,
            &changed
        ));
    }

    let second_relation = build_fixture(&second);
    assert_eq!(first_relation.shape.inputs, second_relation.shape.inputs);
    assert_eq!(first_relation.shape.outputs, second_relation.shape.outputs);
    assert_eq!(first_relation.shape.circuit, second_relation.shape.circuit);
    assert_ne!(first_relation.assignment, second_relation.assignment);
    assert!(structured_relation_satisfied(
        &second_relation.shape.circuit,
        &second_relation.assignment
    ));
    let expected_circuit_digest = circuit_digest(&second_relation.shape.circuit);
    drop(first_relation);
    drop(second_relation);

    let substituted = Fixture {
        witness: second.witness.clone(),
        ..first
    };
    let substituted_relation = build_fixture(&substituted);
    assert_eq!(
        circuit_digest(&substituted_relation.shape.circuit),
        expected_circuit_digest
    );
    assert!(!structured_relation_satisfied(
        &substituted_relation.shape.circuit,
        &substituted_relation.assignment
    ));
    drop(substituted_relation);

    let mut reversed_claims = second.claims.clone();
    reversed_claims.reverse();
    let wrong_order = Fixture {
        proof: step_proof(&reversed_claims),
        ..second
    };
    let wrong_order_relation = build_fixture(&wrong_order);
    assert_eq!(
        circuit_digest(&wrong_order_relation.shape.circuit),
        expected_circuit_digest
    );
    assert!(!structured_relation_satisfied(
        &wrong_order_relation.shape.circuit,
        &wrong_order_relation.assignment
    ));
    drop(wrong_order_relation);
}
