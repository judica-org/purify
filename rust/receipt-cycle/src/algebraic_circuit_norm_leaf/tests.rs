use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;

use super::*;
use crate::algebraic_circuit_transcript::{
    CircuitPointPairWitnessV4, CircuitProofTranscriptWitnessV4,
};
use crate::parent_relation::{add_point_values, PointValue, SecpEncodedPointWitness};
use crate::relation_builder::Builder;
use crate::secp_scalar::SecpScalarWitness;
use crate::{Assignment, Circuit, Scalar, WireKind};

const CIRCUIT_BINDING: [u8; 32] = [0x31; 32];
const RAW_GENERATORS: [u8; 32] = [0x52; 32];
const BASIS: [u8; 32] = [0x73; 32];
const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn shape_for_n(n_vec_len: usize) -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Hidden,
        gate_count: n_vec_len / 2,
        // Anchor escrow has one hidden output commitment.
        commitment_count: 1,
        n_vec_len,
        l_vec_len: n_vec_len,
    }
}

fn public_shape_for_n(n_vec_len: usize) -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        ..shape_for_n(n_vec_len)
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
        public_commitments: vec![],
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

fn relation_satisfied(circuit: &[u8], assignment: &[u8]) -> bool {
    let circuit = Circuit::parse(circuit).expect("test circuit");
    let assignment = Assignment::parse(assignment).expect("test assignment");
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

fn leaf_constants(
    shape: CircuitTranscriptShapeV4,
    witness: &CircuitProofTranscriptWitnessV4,
) -> CircuitNormLeafConstantsV4 {
    let mut builder = Builder::default();
    let transcript = install_transcript(
        &mut builder,
        shape,
        CIRCUIT_BINDING,
        RAW_GENERATORS,
        witness,
    )
    .expect("derive transcript constants");
    CircuitNormLeafConstantsV4 {
        precommitment: scalar_witness(transcript.precommitment.integer()),
        coefficient_commitment: witness.coefficient_commitment,
        anchored_offset: witness.anchored_offset,
    }
}

fn statement(
    shape: CircuitTranscriptShapeV4,
    constants: CircuitNormLeafConstantsV4,
) -> CircuitNormLeafStatementV4 {
    CircuitNormLeafStatementV4 {
        shape,
        circuit_binding_digest: CIRCUIT_BINDING,
        raw_generator_digest: RAW_GENERATORS,
        basis_digest: BASIS,
        constants,
    }
}

fn public_statement(
    shape: CircuitTranscriptShapeV4,
    constants: CircuitNormLeafConstantsV4,
) -> PublicCircuitNormLeafStatementV4 {
    PublicCircuitNormLeafStatementV4 {
        leaf: statement(shape, constants),
        public_commitments: vec![generator()],
    }
}

fn build_leaf(
    shape: CircuitTranscriptShapeV4,
    witness: &CircuitProofTranscriptWitnessV4,
    expected: CircuitNormLeafConstantsV4,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let claim = install_hidden_circuit_norm_leaf(
        &mut builder,
        statement(shape, expected),
        witness,
        &zero_reduction_proof(shape),
    )?;
    assert_eq!(claim.polynomial.len(), 3);
    assert_eq!(claim.polynomial[0].offset, 0);
    assert_eq!(claim.polynomial[1].offset, shape.n_vec_len);
    assert_eq!(claim.polynomial[2].offset, shape.n_vec_len);
    assert!(claim
        .polynomial
        .iter()
        .all(|term| term.factors.len() == shape.round_count()));
    builder.finish()
}

fn finite_transcript_witness(shape: CircuitTranscriptShapeV4) -> CircuitProofTranscriptWitnessV4 {
    let mut witness = zero_transcript_witness(shape);
    let base = generator();
    witness.raw_commitment = base;
    witness.anchored_commitment = base;
    witness.mask_commitment = base;
    if shape.mode == CircuitCommitmentModeV4::Public {
        witness.public_commitments = vec![base];
        witness.batched_public_commitment = base;
        witness.dlog_nonce = base;
        let challenge = {
            let mut builder = Builder::default();
            let transcript = install_transcript(
                &mut builder,
                shape,
                CIRCUIT_BINDING,
                RAW_GENERATORS,
                &witness,
            )
            .expect("derive public DLog challenge");
            transcript.dlog_challenge.integer().clone()
        };
        witness.dlog_response = scalar_add_one(&challenge);
    }
    let alpha = {
        let mut builder = Builder::default();
        let transcript = install_transcript(
            &mut builder,
            shape,
            CIRCUIT_BINDING,
            RAW_GENERATORS,
            &witness,
        )
        .expect("derive mask challenge");
        transcript.alpha.integer().clone()
    };
    let combined_scalar = (alpha + BigUint::from(1u64)) % BigUint::from_bytes_be(&SECP_ORDER);
    witness.combined_commitment = encoded_value(scale_value(point_value(base), &combined_scalar));
    assert_ne!(
        witness.combined_commitment,
        SecpEncodedPointWitness::identity()
    );
    witness
}

fn build_public_leaf(
    shape: CircuitTranscriptShapeV4,
    witness: &CircuitProofTranscriptWitnessV4,
    expected: CircuitNormLeafConstantsV4,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let statement = public_statement(shape, expected);
    let claim = install_public_circuit_norm_leaf(
        &mut builder,
        &statement,
        witness,
        &zero_reduction_proof(shape),
    )?;
    assert_eq!(claim.polynomial.len(), 3);
    builder.finish()
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
    encoded[0] = if y[0] & 1 == 0 { 0x02 } else { 0x03 };
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

#[test]
fn hidden_finite_leaf_is_one_pending_claim() {
    let shape = shape_for_n(4);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (valid_circuit, valid_assignment) =
        build_leaf(shape, &witness, expected).expect("hidden finite leaf");
    assert!(relation_satisfied(&valid_circuit, &valid_assignment));
    drop(valid_assignment);

    let mut wrong_anchor = witness.clone();
    wrong_anchor.anchored_commitment = SecpEncodedPointWitness::identity();
    let (wrong_circuit, wrong_assignment) = build_leaf(shape, &wrong_anchor, expected)
        .expect("wrong anchor still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_circuit);
    assert!(!relation_satisfied(&wrong_circuit, &wrong_assignment));
    drop((wrong_circuit, wrong_assignment));

    let mut identity_raw = witness.clone();
    identity_raw.raw_commitment = SecpEncodedPointWitness::identity();
    let (identity_raw_circuit, identity_raw_assignment) =
        build_leaf(shape, &identity_raw, expected)
            .expect("identity raw commitment builds an unsatisfied assignment");
    assert_eq!(valid_circuit, identity_raw_circuit);
    assert!(!relation_satisfied(
        &identity_raw_circuit,
        &identity_raw_assignment
    ));
    drop((identity_raw_circuit, identity_raw_assignment));

    let mut identity_mask = witness.clone();
    identity_mask.mask_commitment = SecpEncodedPointWitness::identity();
    let (identity_mask_circuit, identity_mask_assignment) =
        build_leaf(shape, &identity_mask, expected)
            .expect("identity mask commitment builds an unsatisfied assignment");
    assert_eq!(valid_circuit, identity_mask_circuit);
    assert!(!relation_satisfied(
        &identity_mask_circuit,
        &identity_mask_assignment
    ));
    drop((identity_mask_circuit, identity_mask_assignment));

    let mut identity_combined = witness.clone();
    identity_combined.combined_commitment = SecpEncodedPointWitness::identity();
    let (identity_combined_circuit, identity_combined_assignment) =
        build_leaf(shape, &identity_combined, expected)
            .expect("identity combined commitment builds an unsatisfied assignment");
    assert_eq!(valid_circuit, identity_combined_circuit);
    assert!(!relation_satisfied(
        &identity_combined_circuit,
        &identity_combined_assignment
    ));
    drop((identity_combined_circuit, identity_combined_assignment));

    let mut wrong_coefficient = witness.clone();
    wrong_coefficient.coefficient_commitment = generator();
    let (wrong_coefficient_circuit, wrong_coefficient_assignment) =
        build_leaf(shape, &wrong_coefficient, expected)
            .expect("wrong coefficient still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_coefficient_circuit);
    assert!(!relation_satisfied(
        &wrong_coefficient_circuit,
        &wrong_coefficient_assignment
    ));
    drop((wrong_coefficient_circuit, wrong_coefficient_assignment));

    let mut wrong_offset = witness;
    wrong_offset.anchored_offset = generator();
    let (wrong_offset_circuit, wrong_offset_assignment) =
        build_leaf(shape, &wrong_offset, expected)
            .expect("wrong offset still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_offset_circuit);
    assert!(!relation_satisfied(
        &wrong_offset_circuit,
        &wrong_offset_assignment
    ));
}

#[test]
fn production_fixture_has_fourteen_rounds() {
    let shape = shape_for_n(16_384);
    let witness = zero_transcript_witness(shape);
    let reduction = zero_reduction_proof(shape);
    assert_eq!(shape.round_count(), 14);
    assert_eq!(witness.rounds.len(), 14);
    assert_eq!(reduction.left.len(), 14);
    assert_eq!(reduction.right.len(), 14);
}

#[test]
fn public_mode_cannot_enter_hidden_leaf() {
    let mut shape = shape_for_n(4);
    shape.mode = CircuitCommitmentModeV4::Public;
    let witness = zero_transcript_witness(shape);
    let expected = CircuitNormLeafConstantsV4 {
        precommitment: SecpScalarWitness::from_u64(1),
        coefficient_commitment: SecpEncodedPointWitness::identity(),
        anchored_offset: SecpEncodedPointWitness::identity(),
    };
    let mut builder = Builder::default();
    assert!(matches!(
        install_hidden_circuit_norm_leaf(
            &mut builder,
            statement(shape, expected),
            &witness,
            &zero_reduction_proof(shape),
        ),
        Err(ReceiptCycleError::Malformed(
            "hidden V4 circuit norm leaf mode"
        ))
    ));
}

#[test]
fn public_setup_schnorr_is_constrained() {
    let shape = public_shape_for_n(4);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (valid_circuit, valid_assignment) =
        build_public_leaf(shape, &witness, expected).expect("public setup leaf");
    assert!(relation_satisfied(&valid_circuit, &valid_assignment));
    drop(valid_assignment);

    let mut wrong_response = witness.clone();
    wrong_response.dlog_response =
        scalar_add_one(&BigUint::from_bytes_be(&wrong_response.dlog_response.bytes));
    let (wrong_response_circuit, wrong_response_assignment) =
        build_public_leaf(shape, &wrong_response, expected)
            .expect("wrong response still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_response_circuit);
    assert!(!relation_satisfied(
        &wrong_response_circuit,
        &wrong_response_assignment
    ));
    drop((wrong_response_circuit, wrong_response_assignment));

    let mut zero_response = witness.clone();
    zero_response.dlog_response = SecpScalarWitness::from_u64(0);
    let (zero_response_circuit, zero_response_assignment) =
        build_public_leaf(shape, &zero_response, expected)
            .expect("zero response still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, zero_response_circuit);
    assert!(!relation_satisfied(
        &zero_response_circuit,
        &zero_response_assignment
    ));
    drop((zero_response_circuit, zero_response_assignment));

    let mut wrong_batch = witness;
    wrong_batch.batched_public_commitment = SecpEncodedPointWitness::identity();
    let (wrong_batch_circuit, wrong_batch_assignment) =
        build_public_leaf(shape, &wrong_batch, expected)
            .expect("wrong batch still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_batch_circuit);
    assert!(!relation_satisfied(
        &wrong_batch_circuit,
        &wrong_batch_assignment
    ));
    drop((wrong_batch_circuit, wrong_batch_assignment));

    let mut wrong_public = finite_transcript_witness(shape);
    wrong_public.public_commitments[0] = SecpEncodedPointWitness::identity();
    let (wrong_public_circuit, wrong_public_assignment) =
        build_public_leaf(shape, &wrong_public, expected)
            .expect("wrong public point still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_public_circuit);
    assert!(!relation_satisfied(
        &wrong_public_circuit,
        &wrong_public_assignment
    ));
}

#[test]
#[ignore = "run explicitly in release mode; production relation is large"]
fn production_public_setup_leaf_reports_relation_size() {
    let shape = public_shape_for_n(4096);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (circuit, assignment) = build_public_leaf(shape, &witness, expected)
        .expect("production public setup circuit norm leaf relation");
    drop(assignment);
    let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("leaf gate count"));
    let proof_bytes = crate::proof_wire_len(&circuit).expect("leaf proof length");
    eprintln!("production_public_norm_leaf_gates={gates} proof_bytes={proof_bytes}");
    assert_eq!(gates, 854_293);
    assert_eq!(proof_bytes, 1_745);
}

#[test]
#[ignore = "run explicitly in release mode; composed V4 leaf proof is large"]
fn hidden_finite_leaf_proves_and_wrong_anchor_fails() {
    let shape = shape_for_n(4);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (circuit, assignment) = build_leaf(shape, &witness, expected).expect("hidden finite leaf");
    let statement = b"candidate hidden V4 circuit norm leaf";
    let proof = crate::prove(&circuit, &assignment, statement, [0x95; 32]).expect("leaf proof");
    crate::verify(&circuit, statement, &proof).expect("leaf verification");

    let mut wrong_anchor = witness;
    wrong_anchor.anchored_commitment = SecpEncodedPointWitness::identity();
    let (wrong_circuit, wrong_assignment) =
        build_leaf(shape, &wrong_anchor, expected).expect("wrong anchor assignment");
    assert_eq!(circuit, wrong_circuit);
    let wrong_proof = crate::prove(&wrong_circuit, &wrong_assignment, statement, [0x96; 32])
        .expect("unsatisfied proof transcript");
    assert!(crate::verify(&wrong_circuit, statement, &wrong_proof).is_err());

    let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("leaf gate count"));
    eprintln!(
        "algebraic_circuit_norm_leaf_gates={gates} proof_bytes={}",
        proof.len()
    );
}

#[test]
#[ignore = "run explicitly in release mode; composed V4 leaf proof is large"]
fn public_setup_leaf_proves_and_wrong_response_fails() {
    let shape = public_shape_for_n(4);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (circuit, assignment) =
        build_public_leaf(shape, &witness, expected).expect("public setup leaf");
    let statement = b"candidate public V4 circuit norm leaf";
    let proof =
        crate::prove(&circuit, &assignment, statement, [0xa7; 32]).expect("public leaf proof");
    crate::verify(&circuit, statement, &proof).expect("public leaf verification");

    let mut wrong_response = witness;
    wrong_response.dlog_response =
        scalar_add_one(&BigUint::from_bytes_be(&wrong_response.dlog_response.bytes));
    let (wrong_circuit, wrong_assignment) =
        build_public_leaf(shape, &wrong_response, expected).expect("wrong response assignment");
    assert_eq!(circuit, wrong_circuit);
    let wrong_proof = crate::prove(&wrong_circuit, &wrong_assignment, statement, [0xa8; 32])
        .expect("unsatisfied proof transcript");
    assert!(crate::verify(&wrong_circuit, statement, &wrong_proof).is_err());

    let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("leaf gate count"));
    eprintln!(
        "public_circuit_norm_leaf_gates={gates} proof_bytes={}",
        proof.len()
    );
}

#[test]
#[ignore = "run explicitly in release mode; production relation is large"]
fn production_hidden_leaf_reports_relation_size() {
    let shape = shape_for_n(16_384);
    let witness = finite_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (circuit, assignment) = build_leaf(shape, &witness, expected)
        .expect("production hidden circuit norm leaf relation");
    drop(assignment);
    let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("leaf gate count"));
    let proof_bytes = crate::proof_wire_len(&circuit).expect("leaf proof length");
    eprintln!("production_circuit_norm_leaf_gates={gates} proof_bytes={proof_bytes}");
    assert_eq!(gates, 949_880);
    assert_eq!(proof_bytes, 1_745);
}
