use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use nova_snark::nova::{PublicParams, PublicParamsShapeMetrics, R1CSShapeMetrics};
use num_bigint::BigUint;

use super::*;
use crate::circuit_norm_leaf::install_manifest_bound_anchor_leaf;
use crate::construction_manifest::{
    derive_step_manifest, ConstructionManifestAnchor, ConstructionManifestStepInput,
    ConstructionRoot, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::construction_parent_prover_fixture::{
    ConstructionParentProverFixture, NONDECIDING_PROVER_FIXTURE_SHA256,
    QUALIFIED_PROVER_FIXTURE_SHA256,
};
use crate::direct_nova::{
    direct_nova_raw_metrics, nova_state_to_source, source_state_to_nova, DirectNovaPrimaryEngine,
    DirectNovaScalar, DirectNovaSecondaryEngine, DirectNovaStep, DirectNovaTemplate,
};
use crate::fixed_serde::{NovaCompressedProofShape, NovaR1csDimensions};
use crate::nova_session::{DirectNovaSuite, SelectedDirectNovaSuite, SelectedDirectNovaVerifier};
use crate::parent_relation::{
    add_point_values, derive_candidate_folded_generator, CandidatePendingClaimWitness,
    CandidatePolynomialTermWitness, ConstrainedPendingClaim, EncodedSecpPoint, PointValue,
    SecpEncodedPointWitness,
};
use crate::relation_builder::{circuit_digest, Builder, StateWire};
use crate::secp_scalar::SecpScalarVar;
use crate::sha256_circuit_transcript::{
    install_transcript, CircuitPointPairWitnessV4, CircuitTranscriptShapeV4,
};
use crate::{Assignment, Circuit, WireKind};
use sha2::{Digest, Sha256};

const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const SHA_VERIFIER_PAYLOAD_LENGTH: u64 = 3_793_960_104;
const SHA_VERIFIER_ARTIFACT_LENGTH: u64 = SHA_VERIFIER_PAYLOAD_LENGTH + 64;

// The pinned Nova revision encodes each sparse term as a 32-byte scalar and
// an eight-byte index. This setup-free estimate must match the produced file.
fn fixed_bincode_shape_length(metrics: R1CSShapeMetrics) -> u64 {
    let padded_dimension = metrics
        .constraints
        .max(metrics.variables)
        .next_power_of_two() as u64;
    let nonzero_terms = (metrics.a_terms + metrics.b_terms + metrics.c_terms) as u64;
    40 * nonzero_terms + 24 * padded_dimension + 144
}

fn fixed_bincode_verifier_payload_length(metrics: PublicParamsShapeMetrics) -> u64 {
    let primary_dimension = metrics
        .primary
        .constraints
        .max(metrics.primary.variables)
        .next_power_of_two() as u64;
    let secondary_dimension = metrics
        .secondary
        .constraints
        .max(metrics.secondary.variables)
        .next_power_of_two() as u64;
    fixed_bincode_shape_length(metrics.primary)
        + fixed_bincode_shape_length(metrics.secondary)
        + 33 * (primary_dimension + secondary_dimension)
        + 352
}

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

fn recurrence_state_from_fields(
    fields: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
    expected_index: u32,
) -> AnchorRecurrenceStateWitness {
    let root_fields = fields[..CONSTRUCTION_ROOT_STATE_ARITY]
        .try_into()
        .expect("fixed construction root state");
    let root = ConstructionRoot::from_state_fields(root_fields)
        .expect("authenticated construction root fields");
    let manifest_field = fields[CONSTRUCTION_ROOT_STATE_ARITY];
    let mut manifest = Secq256k1Cycle::scalar_to_canonical(&manifest_field);
    manifest.reverse();
    assert_eq!(
        fields[CONSTRUCTION_ROOT_STATE_ARITY + 1],
        Scalar::from(u64::from(expected_index))
    );
    AnchorRecurrenceStateWitness {
        root: root.claim(),
        manifest,
        index: expected_index,
    }
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
    assert_eq!(fixture.statement.shape.gate_count, ANCHOR_GATE_COUNT);
    assert_eq!(fixture.statement.shape.commitment_count, 1);
    assert_eq!(fixture.statement.shape.n_vec_len, ANCHOR_NORM_LENGTH);
    assert_eq!(fixture.statement.shape.l_vec_len, ANCHOR_NORM_LENGTH);
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
        &[
            0x84, 0x94, 0xab, 0x8c, 0xa7, 0xe6, 0x04, 0x2e, 0x24, 0x5e, 0x1e, 0xe1, 0xa5, 0x5b,
            0x91, 0x50, 0x89, 0xb9, 0xf2, 0xe3, 0xfc, 0x16, 0x1c, 0x47, 0x85, 0x23, 0x5d, 0x1f,
            0xac, 0x46, 0x51, 0xb2,
        ]
    );
    assert_eq!(metrics.source_gates, 10_428_979);
    assert_eq!(metrics.source_constraints, 21_056_835);
    assert_eq!(metrics.source_terms, 66_078_014);
    assert_eq!(metrics.direct_variables, 10_428_979);
    assert_eq!(metrics.direct_constraints, 10_627_876);
    assert_eq!(metrics.direct_nnz_upper_bound, 55_847_972);
    assert_eq!(metrics.direct_power_of_two_bucket, 1 << 24);
    assert_eq!(metrics.direct_bucket_headroom, 6_149_340);
    assert_eq!(metrics.direct_rounds, 24);

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
    assert_eq!(relation_id, metrics.relation_id);

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
    drop(second);
    drop(template);
    drop(fixture);

    eprintln!("production_shape_metrics: planning augmented shapes");
    let augmented =
        PublicParams::<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, _>::shape_metrics(
            &first,
        )
        .expect("production Nova augmented shapes");
    assert_eq!(augmented.primary.public_inputs, 2);
    assert_eq!(augmented.secondary.public_inputs, 2);
    assert!(augmented.primary.constraints > metrics.direct_constraints);
    assert!(augmented.primary.variables > metrics.direct_variables);
    assert!(augmented.secondary.constraints > 0);
    assert!(augmented.secondary.variables > 0);
    assert_eq!(augmented.primary.constraints, 12_392_865);
    assert_eq!(augmented.primary.variables, 12_192_189);
    assert_eq!(augmented.primary.a_terms, 36_494_260);
    assert_eq!(augmented.primary.b_terms, 14_798_793);
    assert_eq!(augmented.primary.c_terms, 14_173_431);
    assert_eq!(augmented.secondary.constraints, 728_974);
    assert_eq!(augmented.secondary.variables, 728_211);
    assert_eq!(augmented.secondary.a_terms, 1_676_035);
    assert_eq!(augmented.secondary.b_terms, 736_338);
    assert_eq!(augmented.secondary.c_terms, 1_568_376);
    assert_eq!(
        fixed_bincode_verifier_payload_length(augmented),
        SHA_VERIFIER_PAYLOAD_LENGTH
    );

    let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
        NovaR1csDimensions::new(augmented.primary.constraints, augmented.primary.variables),
        NovaR1csDimensions::new(
            augmented.secondary.constraints,
            augmented.secondary.variables,
        ),
        ANCHOR_RECURRENCE_STATE_ARITY,
    )
    .expect("production compressed proof shape");
    eprintln!(
        "augmented_shape_metrics={augmented:#?}\n\
         compressed_proof_length={}\n\
         compressed_proof_sequence_count={}",
        proof_shape.encoded_len(),
        proof_shape.sequence_count(),
    );
    assert_eq!(proof_shape.encoded_len(), 15_076);
    assert_eq!(proof_shape.sequence_count(), 152);
}

struct BoundQualificationFixture {
    initial_state: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
    steps: Vec<DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>>,
}

fn read_qualification_fixture(
    environment: &str,
    expected_sha256: [u8; 32],
) -> ConstructionParentProverFixture {
    let path = std::env::var_os(environment)
        .unwrap_or_else(|| panic!("set {environment} before qualification"));
    let bytes = std::fs::read(path).expect("read construction parent prover fixture");
    assert_eq!(bytes.len(), 8_314);
    assert_eq!(Sha256::digest(&bytes).as_slice(), expected_sha256);
    ConstructionParentProverFixture::parse(&bytes)
        .expect("parse construction parent prover fixture")
}

fn assert_matching_public_fixtures(
    accepted: &ConstructionParentProverFixture,
    nondeciding: &ConstructionParentProverFixture,
) {
    assert_eq!(accepted.anchors.len(), 2);
    assert_eq!(nondeciding.anchors.len(), accepted.anchors.len());
    assert_eq!(accepted.inputs.anchors(), nondeciding.inputs.anchors());
    assert_eq!(
        accepted
            .inputs
            .seed()
            .initial_state_fields()
            .expect("accepted initial state"),
        nondeciding
            .inputs
            .seed()
            .initial_state_fields()
            .expect("nondeciding initial state")
    );
    for (accepted_anchor, nondeciding_anchor) in accepted.anchors.iter().zip(&nondeciding.anchors) {
        assert_eq!(accepted_anchor.statement, nondeciding_anchor.statement);
        assert_eq!(
            accepted_anchor.transcript.public_commitments,
            nondeciding_anchor.transcript.public_commitments
        );
    }
    assert_ne!(
        accepted.expected_root.canonical_bytes(),
        nondeciding.expected_root.canonical_bytes()
    );
}

fn bind_qualification_fixture(
    template: &DirectNovaTemplate<ANCHOR_RECURRENCE_STATE_ARITY>,
    fixture: &ConstructionParentProverFixture,
    mut first_step: Option<DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>>,
) -> BoundQualificationFixture {
    let initial_state = fixture
        .inputs
        .seed()
        .initial_state_fields()
        .expect("verifier-derived qualification z0");
    let expected_suffix = fixture
        .inputs
        .seed()
        .derive_expected_final(fixture.inputs.anchors())
        .expect("independent final construction manifest")
        .state_suffix_fields()
        .expect("final construction manifest fields");
    let mut state = fixture
        .inputs
        .seed()
        .initial_recurrence_witness()
        .expect("initial qualification recurrence witness");
    assert_eq!(
        state.state_fields().expect("initial recurrence state"),
        initial_state
    );

    let mut expected_input = initial_state;
    let mut steps = Vec::with_capacity(fixture.anchors.len());
    for (index, anchor) in fixture.anchors.iter().enumerate() {
        eprintln!(
            "sha_parent_qualification: binding recurrence {}/{}",
            index + 1,
            fixture.anchors.len()
        );
        let (step, output) = if index == 0 {
            if let Some(step) = first_step.take() {
                assert_eq!(
                    nova_state_to_source(*step.input_state())
                        .expect("trusted qualification input state"),
                    expected_input
                );
                let output = nova_state_to_source(*step.output_state())
                    .expect("trusted qualification output state");
                (step, output)
            } else {
                bind_qualification_step(template, &state, anchor, expected_input)
            }
        } else {
            bind_qualification_step(template, &state, anchor, expected_input)
        };
        state = recurrence_state_from_fields(
            output,
            u32::try_from(index + 1).expect("qualification anchor index fits u32"),
        );
        expected_input = output;
        steps.push(step);
    }

    assert_eq!(
        &expected_input[CONSTRUCTION_ROOT_STATE_ARITY..],
        expected_suffix.as_slice()
    );
    assert_eq!(
        registry_seed_root(&state.root).canonical_bytes(),
        fixture.expected_root.canonical_bytes()
    );
    BoundQualificationFixture {
        initial_state,
        final_state: expected_input,
        steps,
    }
}

fn bind_qualification_step(
    template: &DirectNovaTemplate<ANCHOR_RECURRENCE_STATE_ARITY>,
    state: &AnchorRecurrenceStateWitness,
    anchor: &crate::construction_parent_prover_fixture::ConstructionParentProverAnchor,
    expected_input: [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
) -> (
    DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>,
    [Scalar; ANCHOR_RECURRENCE_STATE_ARITY],
) {
    let relation = build_anchor_recurrence_relation_with_builder(
        template.matching_builder(),
        state,
        anchor.statement,
        &anchor.transcript,
        &anchor.reduction,
        &anchor.step,
    )
    .expect("matching qualification recurrence");
    assert_eq!(
        relation_state(&relation, &relation.shape.inputs),
        expected_input
    );
    let output = relation_state(&relation, &relation.shape.outputs);
    let step = template
        .bind_relation(relation)
        .expect("bind matching qualification recurrence");
    (step, output)
}

fn bind_both_qualification_fixtures(
    accepted: &ConstructionParentProverFixture,
    nondeciding: &ConstructionParentProverFixture,
) -> (
    DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>,
    BoundQualificationFixture,
    BoundQualificationFixture,
) {
    assert_matching_public_fixtures(accepted, nondeciding);
    let accepted_initial = accepted
        .inputs
        .seed()
        .initial_recurrence_witness()
        .expect("trusted qualification recurrence witness");
    let trusted_anchor = &accepted.anchors[0];
    let trusted_relation = build_anchor_recurrence_relation(
        &accepted_initial,
        trusted_anchor.statement,
        &trusted_anchor.transcript,
        &trusted_anchor.reduction,
        &trusted_anchor.step,
    )
    .expect("trusted qualification recurrence");
    eprintln!(
        "sha_parent_qualification: source_gates={} source_constraints={} source_terms={}",
        trusted_relation.shape.circuit.gate_count,
        trusted_relation.shape.circuit.constraints.len(),
        trusted_relation
            .shape
            .circuit
            .constraints
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
    );
    let (template, trusted_step) =
        DirectNovaTemplate::<ANCHOR_RECURRENCE_STATE_ARITY>::from_relation(trusted_relation)
            .expect("qualification direct Nova template");
    let accepted_bound =
        bind_qualification_fixture(&template, accepted, Some(trusted_step.clone()));
    let nondeciding_bound = bind_qualification_fixture(&template, nondeciding, None);
    assert_eq!(
        accepted_bound.initial_state,
        nondeciding_bound.initial_state
    );
    assert_ne!(accepted_bound.final_state, nondeciding_bound.final_state);
    let relation_id = trusted_step.relation_id();
    assert!(accepted_bound
        .steps
        .iter()
        .chain(&nondeciding_bound.steps)
        .all(|step| step.relation_id() == relation_id));
    drop(template);
    (trusted_step, accepted_bound, nondeciding_bound)
}

fn produce_qualification_proof(
    suite: &SelectedDirectNovaSuite<ANCHOR_RECURRENCE_STATE_ARITY>,
    initial_state: [DirectNovaScalar; ANCHOR_RECURRENCE_STATE_ARITY],
    steps: Vec<DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>>,
) -> Vec<u8> {
    let step_count = steps.len();
    let mut session = suite
        .start(initial_state, step_count)
        .expect("start qualification proof session");
    for (index, step) in steps.into_iter().enumerate() {
        eprintln!(
            "sha_parent_qualification: folding recurrence {}/{}",
            index + 1,
            step_count
        );
        session = session
            .add_step(step)
            .expect("fold qualification recurrence");
    }
    session
        .finish()
        .expect("verify and compress qualification proof")
}

fn qualification_output_path(environment: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os(environment)
            .unwrap_or_else(|| panic!("set {environment} before qualification")),
    );
    assert!(!path.as_os_str().is_empty(), "{environment} is empty");
    assert!(!path.exists(), "{environment} already exists");
    path
}

fn write_new_qualification_output(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create new qualification output");
    output
        .write_all(bytes)
        .expect("write complete qualification output");
    output.sync_all().expect("sync qualification output");
    eprintln!(
        "sha_parent_qualification: output={} bytes={}",
        path.display(),
        bytes.len()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "requires both fixtures and builds production recurrences"]
fn exported_sha_parent_fixtures_reconstruct_one_shape() {
    let accepted = read_qualification_fixture(
        "PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE",
        QUALIFIED_PROVER_FIXTURE_SHA256,
    );
    let nondeciding = read_qualification_fixture(
        "PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE",
        NONDECIDING_PROVER_FIXTURE_SHA256,
    );
    let (trusted_step, accepted_bound, nondeciding_bound) =
        bind_both_qualification_fixtures(&accepted, &nondeciding);
    assert_eq!(accepted_bound.steps.len(), accepted.anchors.len());
    assert_eq!(nondeciding_bound.steps.len(), nondeciding.anchors.len());
    assert_eq!(
        trusted_step.relation_id(),
        accepted_bound.steps[0].relation_id()
    );
}

#[test]
#[ignore = "run explicitly under the native no-swap resource gate"]
fn native_profile_sha_parent_qualification_is_exact() {
    let total_started = std::time::Instant::now();
    let accepted_proof_path = qualification_output_path("PURIFY_CONSTRUCTION_PARENT_PROOF_OUT");
    let nondeciding_proof_path =
        qualification_output_path("PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT");
    let artifact_path =
        qualification_output_path("PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT");
    let accepted = read_qualification_fixture(
        "PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE",
        QUALIFIED_PROVER_FIXTURE_SHA256,
    );
    let nondeciding = read_qualification_fixture(
        "PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE",
        NONDECIDING_PROVER_FIXTURE_SHA256,
    );
    let (trusted_step, accepted_bound, nondeciding_bound) =
        bind_both_qualification_fixtures(&accepted, &nondeciding);
    drop(accepted);
    drop(nondeciding);

    let augmented =
        PublicParams::<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, _>::shape_metrics(
            &trusted_step,
        )
        .expect("preflight qualification verifier shape");
    let verifier_payload_length = fixed_bincode_verifier_payload_length(augmented);
    assert_eq!(verifier_payload_length, SHA_VERIFIER_PAYLOAD_LENGTH);
    eprintln!("sha_parent_qualification: verifier_payload_preflight={verifier_payload_length}");

    let setup_started = std::time::Instant::now();
    eprintln!("sha_parent_qualification: constructing transparent parameters");
    let suite = DirectNovaSuite::<ANCHOR_RECURRENCE_STATE_ARITY>::setup(trusted_step)
        .expect("unselected production qualification suite");
    let selected = suite
        .select_observed_construction_parent_for_qualification()
        .expect("select observed production qualification suite");
    let metadata = selected.metadata();
    eprintln!(
        "sha_parent_qualification: setup_seconds={:.3}\n\
         relation_id={}\npublic_parameter_digest={}\n\
         suite_id={}\nmetadata={metadata:#?}",
        setup_started.elapsed().as_secs_f64(),
        hex(metadata.relation_id.bytes()),
        hex(&metadata.public_parameter_digest),
        hex(selected.expected().suite_id().bytes()),
    );

    let z0 = source_state_to_nova(accepted_bound.initial_state).expect("qualification Nova z0");
    let accepted_final =
        source_state_to_nova(accepted_bound.final_state).expect("accepted Nova final state");
    let nondeciding_final =
        source_state_to_nova(nondeciding_bound.final_state).expect("nondeciding Nova final state");
    let step_count = accepted_bound.steps.len();
    assert_eq!(nondeciding_bound.steps.len(), step_count);

    let accepted_proof = produce_qualification_proof(&selected, z0, accepted_bound.steps);
    let nondeciding_proof = produce_qualification_proof(&selected, z0, nondeciding_bound.steps);
    assert_eq!(accepted_proof.len(), metadata.proof_length);
    assert_eq!(nondeciding_proof.len(), metadata.proof_length);
    eprintln!(
        "accepted_proof_sha256={}\nnondeciding_proof_sha256={}",
        hex(&Sha256::digest(&accepted_proof)),
        hex(&Sha256::digest(&nondeciding_proof)),
    );

    let verifier = selected.into_verifier();
    let expected_suite = verifier.expected();
    verifier
        .verify_exact(&z0, step_count, &accepted_final, &accepted_proof)
        .expect("verify accepted qualification proof");
    verifier
        .verify_exact(&z0, step_count, &nondeciding_final, &nondeciding_proof)
        .expect("verify nondeciding qualification proof");
    let mut artifact = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&artifact_path)
        .expect("create new qualification verifier artifact");
    let descriptor = verifier
        .write_artifact(&mut artifact)
        .expect("write qualification verifier artifact");
    assert_eq!(descriptor.encoded_length(), SHA_VERIFIER_ARTIFACT_LENGTH);
    artifact
        .sync_all()
        .expect("sync qualification verifier artifact");
    eprintln!(
        "verifier_artifact={}\nartifact_bytes={}\nartifact_tagged_digest={}",
        artifact_path.display(),
        descriptor.encoded_length(),
        hex(&descriptor.digest()),
    );
    drop(artifact);
    drop(verifier);

    let mut artifact = std::fs::File::open(&artifact_path)
        .expect("open qualification verifier artifact for reload");
    let loaded = SelectedDirectNovaVerifier::<ANCHOR_RECURRENCE_STATE_ARITY>::from_artifact_reader(
        &mut artifact,
        expected_suite,
        &descriptor,
    )
    .expect("reload qualification verifier artifact");
    loaded
        .verify_exact(&z0, step_count, &accepted_final, &accepted_proof)
        .expect("reloaded verifier accepts qualification proof");
    loaded
        .verify_exact(&z0, step_count, &nondeciding_final, &nondeciding_proof)
        .expect("reloaded verifier accepts nondeciding proof");
    write_new_qualification_output(&accepted_proof_path, &accepted_proof);
    write_new_qualification_output(&nondeciding_proof_path, &nondeciding_proof);
    eprintln!(
        "sha_parent_qualification: total_seconds={:.3}",
        total_started.elapsed().as_secs_f64()
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
