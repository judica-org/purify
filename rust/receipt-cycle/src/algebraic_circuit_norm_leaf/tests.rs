use num_bigint::BigUint;

use super::*;
use crate::algebraic_circuit_transcript::{
    CircuitPointPairWitnessV4, CircuitProofTranscriptWitnessV4,
};
use crate::parent_relation::SecpEncodedPointWitness;
use crate::relation_builder::Builder;
use crate::secp_scalar::SecpScalarWitness;

const CIRCUIT_BINDING: [u8; 32] = [0x31; 32];
const RAW_GENERATORS: [u8; 32] = [0x52; 32];
const BASIS: [u8; 32] = [0x73; 32];

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
    .expect("derive hidden transcript constants");
    CircuitNormLeafConstantsV4 {
        precommitment: scalar_witness(transcript.precommitment.integer()),
        coefficient_commitment: SecpEncodedPointWitness::identity(),
        anchored_offset: SecpEncodedPointWitness::identity(),
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
        CircuitNormLeafStatementV4 {
            shape,
            circuit_binding_digest: CIRCUIT_BINDING,
            raw_generator_digest: RAW_GENERATORS,
            basis_digest: BASIS,
            constants: expected,
        },
        witness,
        &zero_reduction_proof(shape),
    )?;
    assert!(claim.point.point.witness.identity);
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

#[test]
fn hidden_zero_leaf_is_one_pending_claim() {
    let shape = shape_for_n(4);
    let witness = zero_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (valid_circuit, _) = build_leaf(shape, &witness, expected).expect("hidden zero leaf");

    let mut wrong_anchor = witness;
    wrong_anchor.anchored_commitment = generator();
    let (wrong_circuit, _) = build_leaf(shape, &wrong_anchor, expected)
        .expect("wrong anchor still builds an unsatisfied assignment");
    assert_eq!(valid_circuit, wrong_circuit);
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
            CircuitNormLeafStatementV4 {
                shape,
                circuit_binding_digest: CIRCUIT_BINDING,
                raw_generator_digest: RAW_GENERATORS,
                basis_digest: BASIS,
                constants: expected,
            },
            &witness,
            &zero_reduction_proof(shape),
        ),
        Err(ReceiptCycleError::Malformed(
            "hidden V4 circuit norm leaf mode"
        ))
    ));
}

#[test]
#[ignore = "run explicitly in release mode; composed V4 leaf proof is large"]
fn hidden_zero_leaf_proves_and_wrong_anchor_fails() {
    let shape = shape_for_n(4);
    let witness = zero_transcript_witness(shape);
    let expected = leaf_constants(shape, &witness);
    let (circuit, assignment) = build_leaf(shape, &witness, expected).expect("hidden zero leaf");
    let statement = b"candidate hidden V4 circuit norm leaf";
    let proof = crate::prove(&circuit, &assignment, statement, [0x95; 32]).expect("leaf proof");
    crate::verify(&circuit, statement, &proof).expect("leaf verification");

    let mut wrong_anchor = witness;
    wrong_anchor.anchored_commitment = generator();
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
#[ignore = "run explicitly in release mode; production relation is large"]
fn production_hidden_leaf_reports_relation_size() {
    let shape = shape_for_n(16_384);
    let witness = zero_transcript_witness(shape);
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
