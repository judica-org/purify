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
    derive_step_manifest, ConstructionManifestAnchor, ConstructionManifestSeed,
    ConstructionManifestStepInput, ConstructionRoot, CONSTRUCTION_ROOT_BYTES,
    CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::direct_nova::{direct_nova_raw_metrics, source_state_to_nova, DirectNovaTemplate};
use crate::fixed_serde::{NovaCompressedProofShape, NovaR1csDimensions};
use crate::nova_session::{DirectNovaSuite, QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE};
use crate::parent_relation::{
    add_point_values, derive_candidate_folded_generator, CandidatePendingClaimWitness,
    CandidatePolynomialTermWitness, ConstrainedPendingClaim, EncodedSecpPoint, PointValue,
    SecpEncodedPointWitness,
};
use crate::relation_builder::{circuit_digest, Builder, StateWire};
use crate::secp_scalar::SecpScalarVar;
use crate::{Assignment, Circuit, WireKind};

const PRODUCTION_DIRECT_NOVA_RELATION_ID: [u8; 32] = [
    0xec, 0xfd, 0x8e, 0x56, 0x08, 0x40, 0x83, 0xba, 0x9a, 0x94, 0x43, 0x1f, 0xad, 0x5a, 0x5b, 0x1e,
    0x09, 0x91, 0xd7, 0x59, 0x77, 0x46, 0x44, 0x0e, 0x76, 0xcc, 0xf7, 0x79, 0x24, 0x44, 0x4a, 0x66,
];
const PRODUCTION_DIRECT_NOVA_VARIABLES: usize = 1_851_594;
const PRODUCTION_DIRECT_NOVA_CONSTRAINTS: usize = 1_962_058;

// Nova 0.76, Secq primary/Secp secondary, and arity 20 only. The primary
// overhead is the pinned tiny suite's augmented 13,606/13,636 shape minus
// its 40/40 direct relation. The secondary augmented circuit is independent
// of that direct relation at this fixed arity.
const NOVA_076_ARITY_20_PRIMARY_CONSTRAINT_OVERHEAD: usize = 13_566;
const NOVA_076_ARITY_20_PRIMARY_VARIABLE_OVERHEAD: usize = 13_596;
const NOVA_076_ARITY_20_SECONDARY_CONSTRAINTS: usize = 10_787;
const NOVA_076_ARITY_20_SECONDARY_VARIABLES: usize = 10_769;
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
        install_transcript(
            &mut builder,
            shape,
            binding,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            &witness,
        )
        .expect("derive anchor DLog challenge")
        .dlog_challenge
        .integer()
        .clone()
    };
    witness.dlog_response = scalar_add_one(&dlog_challenge);
    let alpha = {
        let mut builder = Builder::default();
        install_transcript(
            &mut builder,
            shape,
            binding,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            &witness,
        )
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

fn leaf_claim_and_manifest_anchor(
    statement: ManifestBoundAnchorLeafStatementV4,
    witness: &CircuitProofTranscriptWitnessV4,
    reduction: &CandidateNormReductionProofWitness,
) -> (CandidatePendingClaimWitness, ConstructionManifestAnchor) {
    let mut builder = Builder::default();
    let leaf = install_manifest_bound_anchor_leaf(&mut builder, statement, witness, reduction)
        .expect("manifest-bound leaf");
    let anchor = ConstructionManifestAnchor::new(
        statement.circuit_binding_digest,
        constrained_scalar_witness(&leaf.precommitment),
        witness.coefficient_commitment,
        witness.anchored_offset,
    )
    .expect("construction manifest anchor");
    (claim_witness(&leaf.claim), anchor)
}

fn step_proof(claims: &[CandidatePendingClaimWitness]) -> CandidateStepProofWitness {
    let mut proof = CandidateStepProofWitness {
        left: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        right: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        terminal_scalar: SecpScalarWitness::from_u64(1),
        folded_generator: SecpEncodedPointWitness::identity(),
    };
    proof.folded_generator =
        derive_candidate_folded_generator(CONSTRUCTION_PARENT_BASIS_DIGEST, claims, &proof)
            .expect("derive folded generator");
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
    manifest_anchor: ConstructionManifestAnchor,
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
    fixture_for_shape(
        small_anchor_shape(),
        binding_byte,
        manifest_byte,
        raw,
        offset,
        mask,
    )
}

fn fixture_for_shape(
    shape: CircuitTranscriptShapeV4,
    binding_byte: u8,
    manifest_byte: u8,
    raw: SecpEncodedPointWitness,
    offset: SecpEncodedPointWitness,
    mask: SecpEncodedPointWitness,
) -> Fixture {
    let statement = ManifestBoundAnchorLeafStatementV4 {
        shape,
        circuit_binding_digest: [binding_byte; 32],
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
    };
    let witness = finite_witness(shape, statement.circuit_binding_digest, raw, offset, mask);
    let reduction = zero_reduction_proof(shape);
    let state = prior_state(manifest_byte);
    let (leaf_claim, manifest_anchor) =
        leaf_claim_and_manifest_anchor(statement, &witness, &reduction);
    let claims = vec![root_claim_witness(&state.root), leaf_claim];
    let proof = step_proof(&claims);
    Fixture {
        state,
        statement,
        witness,
        reduction,
        manifest_anchor,
        claims,
        proof,
    }
}

fn registry_seed_root(root: &CandidateRootClaim) -> ConstructionRoot {
    assert_eq!(root.factors.len(), CONSTRUCTION_ROOT_ROUNDS);
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&root.point.encoded);
    encoded[33..65].copy_from_slice(&root.scale.bytes);
    for (index, factor) in root.factors.iter().enumerate() {
        let offset = 65 + 32 * index;
        encoded[offset..offset + 32].copy_from_slice(&factor.bytes);
    }
    ConstructionRoot::parse(&encoded).expect("construction registry seed root")
}

fn relation_state(
    relation: &StatefulRelation,
    wires: &[StateWire],
) -> [Scalar; ANCHOR_RECURRENCE_STATE_ARITY] {
    assert_eq!(wires.len(), ANCHOR_RECURRENCE_STATE_ARITY);
    std::array::from_fn(|index| {
        let wire = wires[index];
        assert_eq!(wire.kind, WireKind::Left);
        relation.assignment.gates[wire.index].0
    })
}

fn build_fixture(fixture: &Fixture) -> StatefulRelation {
    build_anchor_recurrence_relation_inner(
        Builder::default(),
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
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
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
fn production_relation_digests_match_the_native_anchor_profile() {
    assert_eq!(
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        [
            0x10, 0x1c, 0xdb, 0x8d, 0x99, 0x28, 0x00, 0xb0, 0x3c, 0x39, 0x24, 0x6e, 0xb9, 0x20,
            0xc8, 0x37, 0xa8, 0x04, 0x0c, 0x5a, 0x36, 0xa0, 0x97, 0x0f, 0x0e, 0xbf, 0x85, 0x51,
            0x11, 0x21, 0xca, 0x8a,
        ]
    );
    assert_eq!(
        CONSTRUCTION_PARENT_BASIS_DIGEST,
        [
            0x69, 0xfe, 0x6d, 0x47, 0x5b, 0x58, 0x97, 0x97, 0x28, 0xf5, 0x52, 0x42, 0x84, 0x32,
            0x42, 0x4a, 0xf6, 0xe1, 0xcc, 0x39, 0xbb, 0x8b, 0x88, 0xb6, 0x94, 0x37, 0x90, 0x41,
            0xfb, 0x9b, 0x54, 0x23,
        ]
    );
    assert_ne!(
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        CONSTRUCTION_PARENT_BASIS_DIGEST
    );
}

#[test]
fn production_nova_076_pre_pp_forecast_is_exact() {
    assert_eq!(ANCHOR_RECURRENCE_STATE_ARITY, 20);
    assert_eq!(13_606 - 40, NOVA_076_ARITY_20_PRIMARY_CONSTRAINT_OVERHEAD);
    assert_eq!(13_636 - 40, NOVA_076_ARITY_20_PRIMARY_VARIABLE_OVERHEAD);

    let primary_constraints =
        PRODUCTION_DIRECT_NOVA_CONSTRAINTS + NOVA_076_ARITY_20_PRIMARY_CONSTRAINT_OVERHEAD;
    let primary_variables =
        PRODUCTION_DIRECT_NOVA_VARIABLES + NOVA_076_ARITY_20_PRIMARY_VARIABLE_OVERHEAD;
    let secondary_constraints = NOVA_076_ARITY_20_SECONDARY_CONSTRAINTS;
    let secondary_variables = NOVA_076_ARITY_20_SECONDARY_VARIABLES;
    assert_eq!(
        (primary_constraints, primary_variables),
        (1_975_624, 1_865_190)
    );
    assert_eq!(
        (secondary_constraints, secondary_variables),
        (10_787, 10_769)
    );
    assert_eq!(
        primary_constraints
            .max(primary_variables)
            .next_power_of_two(),
        1 << 21
    );
    assert_eq!(
        secondary_constraints
            .max(secondary_variables)
            .next_power_of_two(),
        1 << 14
    );

    let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
        NovaR1csDimensions::new(primary_constraints, primary_variables),
        NovaR1csDimensions::new(secondary_constraints, secondary_variables),
        ANCHOR_RECURRENCE_STATE_ARITY,
    )
    .expect("forecast compressed proof shape");
    assert_eq!(proof_shape.encoded_len(), 12_466);
    assert_eq!(proof_shape.sequence_count(), 125);

    // This forecast checks dimensions independently of the separately
    // qualified native-profile relation, PP digest, and suite identity. It
    // does not activate construction-receipt acceptance.
    assert_ne!(PRODUCTION_DIRECT_NOVA_RELATION_ID, [0; 32]);
}

#[test]
#[ignore = "run explicitly in release mode; builds two production recurrences"]
fn production_public_anchor_recurrence_reports_direct_shape() {
    eprintln!("production_shape_metrics: deriving fixture");
    let fixture = fixture_for_shape(
        production_anchor_shape(),
        0x31,
        1,
        generator(),
        SecpEncodedPointWitness::identity(),
        generator(),
    );
    assert_eq!(
        fixture.statement.shape.mode,
        CircuitCommitmentModeV4::Public
    );
    assert_eq!(fixture.statement.shape.gate_count, 8_192);
    assert_eq!(fixture.statement.shape.commitment_count, 1);
    assert_eq!(fixture.statement.shape.n_vec_len, 16_384);
    assert_eq!(fixture.statement.shape.l_vec_len, 16_384);
    assert_eq!(fixture.statement.shape.round_count(), 14);
    assert_eq!(fixture.claims.len(), 2);
    assert_eq!(fixture.proof.left.len(), 15);
    assert_eq!(fixture.proof.right.len(), 15);
    eprintln!("production_shape_metrics: building recurrence");
    let relation = build_anchor_recurrence_relation(
        &fixture.state,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
        &fixture.proof,
    )
    .expect("production anchor recurrence");
    let StatefulRelation { shape, assignment } = relation;
    assert!(structured_relation_satisfied(&shape.circuit, &assignment));

    eprintln!("production_shape_metrics: measuring direct lowering");
    let metrics = direct_nova_raw_metrics::<ANCHOR_RECURRENCE_STATE_ARITY>(&shape)
        .expect("direct Nova raw metrics");
    eprintln!(
        "relation_id={:02x?}\n{metrics:#?}",
        metrics.relation_id.bytes()
    );

    assert_eq!(
        metrics.relation_id.bytes(),
        &PRODUCTION_DIRECT_NOVA_RELATION_ID
    );
    assert_eq!(
        (
            metrics.source_gates,
            metrics.source_constraints,
            metrics.source_terms,
            metrics.allocated_operations,
            metrics.boolean_operations,
            metrics.product_operations,
            metrics.semantic_constraints,
        ),
        (1_851_594, 3_813_632, 14_293_837, 57_328, 898_123, 896_143, 167_772,)
    );
    assert_eq!(
        (
            metrics.direct_variables,
            metrics.direct_constraints,
            metrics.direct_nnz_upper_bound,
            metrics.direct_power_of_two_bucket,
            metrics.direct_bucket_headroom,
            metrics.direct_rounds,
        ),
        (
            PRODUCTION_DIRECT_NOVA_VARIABLES,
            PRODUCTION_DIRECT_NOVA_CONSTRAINTS,
            12_552_747,
            2_097_152,
            135_094,
            21,
        )
    );
    assert_eq!(
        metrics.source_gates,
        metrics.allocated_operations + metrics.boolean_operations + metrics.product_operations
    );
    assert!(metrics.source_terms >= metrics.source_constraints);
    assert!(metrics.semantic_constraints <= metrics.source_constraints);
    assert_eq!(
        metrics.direct_constraints,
        metrics.source_constraints - metrics.source_gates + ANCHOR_RECURRENCE_STATE_ARITY
    );
    assert_eq!(metrics.direct_variables, metrics.source_gates);
    assert!(metrics.direct_nnz_upper_bound >= metrics.direct_constraints);
    assert!(metrics.direct_power_of_two_bucket.is_power_of_two());
    assert_eq!(
        metrics.direct_bucket_headroom,
        metrics.direct_power_of_two_bucket
            - metrics.direct_variables.max(metrics.direct_constraints)
    );
    assert_eq!(
        metrics.direct_rounds,
        metrics.direct_power_of_two_bucket.ilog2()
    );

    eprintln!("production_shape_metrics: selecting trusted template");
    let (template, first) =
        DirectNovaTemplate::<ANCHOR_RECURRENCE_STATE_ARITY>::from_relation(StatefulRelation {
            shape,
            assignment,
        })
        .expect("production direct Nova template");
    let relation_id = first.relation_id();
    drop(first);

    eprintln!("production_shape_metrics: building matching recurrence");
    let matching = build_anchor_recurrence_relation_with_builder(
        template.matching_builder(),
        &fixture.state,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
        &fixture.proof,
    )
    .expect("matching production anchor recurrence");
    let second = template
        .bind_relation(matching)
        .expect("matching production direct Nova step");
    assert_eq!(second.relation_id(), relation_id);
}

#[test]
#[ignore = "pending native-profile full compression qualification"]
fn native_profile_anchor_nova_lifecycle_is_exact() {
    // Setup and one full-scale fold are qualified for the native relation
    // constants. Full Spartan compression remains pending under the no-swap
    // resource gate. This test is not construction-receipt acceptance.
    let total_started = std::time::Instant::now();
    eprintln!("native_profile_nova: deriving fixture and verifier seed");
    let mut fixture = fixture_for_shape(
        production_anchor_shape(),
        0x31,
        1,
        generator(),
        SecpEncodedPointWitness::identity(),
        generator(),
    );
    let seed = ConstructionManifestSeed::new(
        [0x91; 32],
        [0xa2; 32],
        registry_seed_root(&fixture.state.root),
        1,
    )
    .expect("one-anchor construction manifest seed");
    fixture.state = seed.initial_recurrence_witness();
    let source_z0 = seed.initial_state_fields().expect("verifier-derived z0");
    assert_eq!(
        fixture.state.state_fields().expect("fixture state fields"),
        source_z0
    );
    let expected_suffix = seed
        .derive_expected_final(&[fixture.manifest_anchor])
        .expect("independent final manifest")
        .state_suffix_fields()
        .expect("final manifest state suffix");

    eprintln!("native_profile_nova: building trusted recurrence");
    let relation = build_anchor_recurrence_relation(
        &fixture.state,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
        &fixture.proof,
    )
    .expect("full-scale fixture anchor recurrence");

    let (template, trusted_step) =
        DirectNovaTemplate::<ANCHOR_RECURRENCE_STATE_ARITY>::from_relation(relation)
            .expect("full-scale direct Nova template");
    eprintln!("native_profile_nova: building matching recurrence");
    let matching = build_anchor_recurrence_relation_with_builder(
        template.matching_builder(),
        &fixture.state,
        fixture.statement,
        &fixture.witness,
        &fixture.reduction,
        &fixture.proof,
    )
    .expect("matching full-scale anchor recurrence");
    assert_eq!(relation_state(&matching, &matching.shape.inputs), source_z0);
    let source_z1 = relation_state(&matching, &matching.shape.outputs);
    assert_eq!(
        &source_z1[CONSTRUCTION_ROOT_STATE_ARITY..],
        expected_suffix.as_slice()
    );
    let matching_step = template
        .bind_relation(matching)
        .expect("matching full-scale direct Nova step");
    drop(template);
    drop(fixture);

    let setup_started = std::time::Instant::now();
    eprintln!("native_profile_nova: constructing transparent parameters");
    let selected = DirectNovaSuite::<ANCHOR_RECURRENCE_STATE_ARITY>::setup_exact(
        trusted_step,
        &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE,
    )
    .expect("qualified full-scale direct Nova suite");
    eprintln!(
        "native_profile_nova: setup complete in {:.3}s",
        setup_started.elapsed().as_secs_f64()
    );
    assert_eq!(
        selected.expected(),
        &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE
    );
    let metadata = selected.metadata();
    assert_eq!(metadata.proof_length, 12_466);
    assert_eq!(metadata.codec_sequence_count, 125);

    let z0 = source_state_to_nova(source_z0).expect("Nova z0");
    let z1 = source_state_to_nova(source_z1).expect("Nova z1");

    let fold_started = std::time::Instant::now();
    eprintln!("native_profile_nova: folding one matching recurrence");
    let session = selected
        .start(z0, 1)
        .expect("one-step native-profile session")
        .add_step(matching_step)
        .expect("native-profile recurrence fold");
    eprintln!(
        "native_profile_nova: fold complete in {:.3}s",
        fold_started.elapsed().as_secs_f64()
    );

    let compression_started = std::time::Instant::now();
    eprintln!("native_profile_nova: recursively verifying and compressing");
    let proof = session
        .finish()
        .expect("recursive verify and Spartan IPA compression");
    eprintln!(
        "native_profile_nova: compression complete in {:.3}s",
        compression_started.elapsed().as_secs_f64()
    );
    assert_eq!(proof.len(), metadata.proof_length);

    let verifier = selected.into_verifier();
    let verify_started = std::time::Instant::now();
    eprintln!("native_profile_nova: verifying canonical compressed proof");
    verifier
        .verify_exact(&z0, 1, &z1, &proof)
        .expect("exact compressed native-profile proof");

    if let Some(path) = std::env::var_os("PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT") {
        let path = std::path::PathBuf::from(path);
        let mut artifact = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create new native-profile verifier artifact");
        let descriptor = verifier
            .write_artifact(&mut artifact)
            .expect("write native-profile verifier artifact");
        artifact
            .sync_all()
            .expect("sync native-profile verifier artifact");
        let digest = descriptor.digest();
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        eprintln!(
            "native_profile_nova: artifact path={} bytes={} digest={digest_hex}",
            path.display(),
            descriptor.encoded_length(),
        );
        drop(artifact);
        drop(verifier);

        let mut artifact =
            std::fs::File::open(&path).expect("open native-profile verifier artifact for reload");
        let loaded = crate::nova_session::SelectedDirectNovaVerifier::<
            ANCHOR_RECURRENCE_STATE_ARITY,
        >::from_artifact_reader(
            &mut artifact,
            &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE,
            &descriptor,
        )
        .expect("reload native-profile verifier artifact");
        loaded
            .verify_exact(&z0, 1, &z1, &proof)
            .expect("loaded verifier accepts native-profile proof");
    }
    eprintln!(
        "native_profile_nova: compressed verify complete in {:.3}s; total {:.3}s; proof_bytes={}",
        verify_started.elapsed().as_secs_f64(),
        total_started.elapsed().as_secs_f64(),
        proof.len()
    );
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
