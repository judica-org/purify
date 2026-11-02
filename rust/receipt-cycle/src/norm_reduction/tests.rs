use super::*;

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;

use crate::parent_relation::{
    add_point_values, constrain_encoded_point_constant, constrain_scalar_constant,
    install_constrained_candidate_step, CandidatePendingClaimWitness,
    CandidatePolynomialTermWitness, CandidateRootClaim, CandidateStepProofWitness, PointValue,
};
use crate::{proof_wire_len, prove, verify};

const SQRT_EXPONENT: [u64; 4] = [
    0xffff_ffff_bfff_ff0c,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
];
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

#[derive(Clone)]
struct PreparedNormWitness {
    prepared_binding: SecpScalarWitness,
    coefficient_commitment: SecpEncodedPointWitness,
    residual: SecpEncodedPointWitness,
    polynomial: Vec<CandidatePolynomialTermWitness>,
}

fn decode_hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() & 1, 0);
    (0..value.len() / 2)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex byte"))
        .collect()
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    decode_hex_vec(value).try_into().expect("fixed hex width")
}

fn json_string<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\": \"");
    let start = json.find(&needle).expect("JSON key") + needle.len();
    let rest = &json[start..];
    &rest[..rest.find('"').expect("JSON string")]
}

fn json_array<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{key}\": [");
    let start = json.find(&needle).expect("JSON array key") + needle.len();
    let rest = &json[start..];
    let array = &rest[..rest.find(']').expect("JSON array")];
    let mut values = Vec::new();
    let mut cursor = array;
    while let Some(start) = cursor.find('"') {
        cursor = &cursor[start + 1..];
        let end = cursor.find('"').expect("JSON array string");
        values.push(&cursor[..end]);
        cursor = &cursor[end + 1..];
    }
    values
}

fn scalar_witness(value: &str) -> SecpScalarWitness {
    SecpScalarWitness::from_bytes_be(decode_hex(value))
}

fn encoded_point(value: &str) -> SecpEncodedPointWitness {
    let encoded = decode_hex::<33>(value);
    if encoded == [0; 33] {
        return SecpEncodedPointWitness::identity();
    }
    assert!(matches!(encoded[0], 0x02 | 0x03));
    let mut x = [0; 32];
    x.copy_from_slice(&encoded[1..]);
    x.reverse();
    let x = Secq256k1Cycle::scalar_from_canonical(&x).expect("canonical point x");
    let mut y = (x.square() * x + Scalar::from(7)).pow_vartime(SQRT_EXPONENT);
    assert_eq!(y.square(), x.square() * x + Scalar::from(7));
    let mut y_bytes = Secq256k1Cycle::scalar_to_canonical(&y);
    if (y_bytes[0] & 1 != 0) != (encoded[0] == 0x03) {
        y = -y;
        y_bytes = Secq256k1Cycle::scalar_to_canonical(&y);
    }
    SecpEncodedPointWitness {
        encoded,
        y: y_bytes,
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

fn parse_polynomial(value: &str) -> Vec<CandidatePolynomialTermWitness> {
    let encoded = decode_hex_vec(value);
    let mut cursor = 0;
    let take_u64 = |cursor: &mut usize| {
        let end = *cursor + 8;
        let value = u64::from_le_bytes(encoded[*cursor..end].try_into().expect("u64"));
        *cursor = end;
        value
    };
    let count = take_u64(&mut cursor) as usize;
    let mut polynomial = Vec::with_capacity(count);
    for _ in 0..count {
        let scale = SecpScalarWitness::from_bytes_be(
            encoded[cursor..cursor + 32].try_into().expect("scalar"),
        );
        cursor += 32;
        let offset = take_u64(&mut cursor) as usize;
        let factor_count = take_u64(&mut cursor) as usize;
        let mut factors = Vec::with_capacity(factor_count);
        for _ in 0..factor_count {
            factors.push(SecpScalarWitness::from_bytes_be(
                encoded[cursor..cursor + 32].try_into().expect("factor"),
            ));
            cursor += 32;
        }
        polynomial.push(CandidatePolynomialTermWitness {
            scale,
            offset,
            factors,
        });
    }
    assert_eq!(cursor, encoded.len());
    polynomial
}

fn allocate_term(
    builder: &mut Builder,
    witness: &CandidatePolynomialTermWitness,
) -> Result<ConstrainedPolynomialTerm, ReceiptCycleError> {
    let scale = allocate_canonical_scalar(builder, witness.scale)?;
    let factors = witness
        .factors
        .iter()
        .map(|&factor| allocate_canonical_scalar(builder, factor))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConstrainedPolynomialTerm {
        scale,
        offset: witness.offset,
        factors,
    })
}

fn allocate_prepared(
    builder: &mut Builder,
    witness: &PreparedNormWitness,
) -> Result<ConstrainedPreparedNorm, ReceiptCycleError> {
    if witness.prepared_binding.bytes == [0; 32] {
        return Err(ReceiptCycleError::Malformed("zero prepared binding"));
    }
    Ok(ConstrainedPreparedNorm {
        prepared_binding: allocate_canonical_scalar(builder, witness.prepared_binding)?,
        coefficient_commitment: allocate_encoded_point(builder, witness.coefficient_commitment)?,
        residual: allocate_encoded_point(builder, witness.residual)?,
        polynomial: witness
            .polynomial
            .iter()
            .map(|term| allocate_term(builder, term))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn constrain_claim(
    builder: &mut Builder,
    actual: &ConstrainedPendingClaim,
    expected: &CandidatePendingClaimWitness,
) -> Result<(), ReceiptCycleError> {
    if actual.polynomial.len() != expected.polynomial.len() {
        return Err(ReceiptCycleError::Malformed("expected reduction claim"));
    }
    constrain_encoded_point_constant(builder, &actual.point, expected.point)?;
    for (actual, expected) in actual.polynomial.iter().zip(&expected.polynomial) {
        if actual.offset != expected.offset || actual.factors.len() != expected.factors.len() {
            return Err(ReceiptCycleError::Malformed(
                "expected reduction polynomial",
            ));
        }
        constrain_scalar_constant(builder, &actual.scale, expected.scale)?;
        for (actual, &expected) in actual.factors.iter().zip(&expected.factors) {
            constrain_scalar_constant(builder, actual, expected)?;
        }
    }
    Ok(())
}

fn assert_claim_value(actual: &ConstrainedPendingClaim, expected: &CandidatePendingClaimWitness) {
    assert_eq!(actual.point.point.witness, point_value(expected.point));
    assert_eq!(
        actual.point.prefix.value(),
        Scalar::from(u64::from(expected.point.encoded[0]))
    );
    assert_eq!(actual.polynomial.len(), expected.polynomial.len());
    for (actual, expected) in actual.polynomial.iter().zip(&expected.polynomial) {
        assert_eq!(actual.offset, expected.offset);
        assert_eq!(
            actual.scale.integer(),
            &BigUint::from_bytes_be(&expected.scale.bytes)
        );
        assert_eq!(actual.factors.len(), expected.factors.len());
        for (actual, expected) in actual.factors.iter().zip(&expected.factors) {
            assert_eq!(actual.integer(), &BigUint::from_bytes_be(&expected.bytes));
        }
    }
}

fn fixture() -> (
    [u8; 32],
    PreparedNormWitness,
    CandidateNormReductionProofWitness,
    CandidatePendingClaimWitness,
) {
    let vector = include_str!("../../tests/vectors/sha256_accumulation_v2.json");
    let polynomial = parse_polynomial(json_string(vector, "norm_polynomial"));
    let evaluation = scalar_witness(json_string(vector, "coefficient_evaluation"));
    let shift = (BigUint::from_bytes_be(&polynomial[1].scale.bytes)
        * BigUint::from_bytes_be(&evaluation.bytes))
        % BigUint::from_bytes_be(&ORDER);
    let norm_point = point_value(encoded_point(json_string(vector, "norm_point")));
    let residual = add_point_values(norm_point, scale_value(standard_generator(), &shift));
    let prepared = PreparedNormWitness {
        prepared_binding: scalar_witness(json_string(vector, "prepared_binding")),
        coefficient_commitment: encoded_point(json_string(vector, "coefficient_commitment")),
        residual: encoded_value(residual),
        polynomial,
    };
    let proof = CandidateNormReductionProofWitness {
        coefficient_evaluation: evaluation,
        left: json_array(vector, "norm_round_left")
            .into_iter()
            .map(encoded_point)
            .collect(),
        right: json_array(vector, "norm_round_right")
            .into_iter()
            .map(encoded_point)
            .collect(),
        terminal_scalar: scalar_witness(json_string(vector, "norm_terminal")),
        folded_generator: encoded_point(json_string(vector, "norm_folded_generator")),
    };
    let expected = CandidatePendingClaimWitness {
        point: encoded_point(json_string(vector, "claim_point")),
        polynomial: parse_polynomial(json_string(vector, "claim_polynomial")),
    };
    (
        decode_hex(json_string(vector, "basis_digest")),
        prepared,
        proof,
        expected,
    )
}

fn bigint_witness(value: &BigUint) -> SecpScalarWitness {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32);
    let mut encoded = [0; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    SecpScalarWitness::from_bytes_be(encoded)
}

fn step_fixture() -> (CandidateStepProofWitness, CandidateRootClaim) {
    let vector = include_str!("../../tests/vectors/sha256_accumulation_v2.json");
    let left = json_array(vector, "step_round_left")
        .into_iter()
        .map(encoded_point)
        .collect::<Vec<_>>();
    let right = json_array(vector, "step_round_right")
        .into_iter()
        .map(encoded_point)
        .collect::<Vec<_>>();
    let proof = CandidateStepProofWitness {
        left,
        right,
        terminal_scalar: scalar_witness(json_string(vector, "step_terminal")),
        folded_generator: encoded_point(json_string(vector, "step_folded_generator")),
    };
    let order = BigUint::from_bytes_be(&ORDER);
    let mut scale = BigUint::from(1u64);
    let mut factors = vec![BigUint::from(0u64); proof.left.len()];
    for (round, challenge) in json_array(vector, "step_round_challenge")
        .into_iter()
        .map(|value| BigUint::from_bytes_be(&decode_hex::<32>(value)))
        .enumerate()
    {
        let inverse = challenge.modpow(&(&order - BigUint::from(2u64)), &order);
        scale = scale * inverse % &order;
        let index = factors.len() - 1 - round;
        factors[index] = &challenge * &challenge % &order;
    }
    let root = CandidateRootClaim {
        point: proof.folded_generator,
        scale: bigint_witness(&scale),
        factors: factors.iter().map(bigint_witness).collect(),
    };
    (proof, root)
}

fn constrain_root(
    builder: &mut Builder,
    actual: &crate::parent_relation::CandidateDerivedRoot,
    expected: &CandidateRootClaim,
) -> Result<(), ReceiptCycleError> {
    if actual.factors.len() != expected.factors.len() {
        return Err(ReceiptCycleError::Malformed("expected candidate root"));
    }
    constrain_encoded_point_constant(builder, &actual.point, expected.point)?;
    constrain_scalar_constant(builder, &actual.scale, expected.scale)?;
    for (actual, &expected) in actual.factors.iter().zip(&expected.factors) {
        constrain_scalar_constant(builder, actual, expected)?;
    }
    Ok(())
}

fn assert_root_value(
    actual: &crate::parent_relation::CandidateDerivedRoot,
    expected: &CandidateRootClaim,
) {
    assert_eq!(actual.point.point.witness, point_value(expected.point));
    assert_eq!(
        actual.scale.integer(),
        &BigUint::from_bytes_be(&expected.scale.bytes)
    );
    assert_eq!(actual.factors.len(), expected.factors.len());
    for (actual, expected) in actual.factors.iter().zip(&expected.factors) {
        assert_eq!(actual.integer(), &BigUint::from_bytes_be(&expected.bytes));
    }
}

fn build_fixture(
    basis_digest: [u8; 32],
    prepared: &PreparedNormWitness,
    proof: &CandidateNormReductionProofWitness,
    expected: &CandidatePendingClaimWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let prepared = allocate_prepared(&mut builder, prepared)?;
    let claim = install_candidate_norm_reduction(&mut builder, basis_digest, 4, &prepared, proof)?;
    constrain_claim(&mut builder, &claim, expected)?;
    builder.finish()
}

fn build_composed_fixture(
    basis_digest: [u8; 32],
    prepared: &PreparedNormWitness,
    reduction: &CandidateNormReductionProofWitness,
    step: &CandidateStepProofWitness,
    root: &CandidateRootClaim,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let prepared = allocate_prepared(&mut builder, prepared)?;
    let claim =
        install_candidate_norm_reduction(&mut builder, basis_digest, 4, &prepared, reduction)?;
    let derived = install_constrained_candidate_step(
        &mut builder,
        basis_digest,
        std::slice::from_ref(&claim),
        step,
    )?;
    constrain_root(&mut builder, &derived, root)?;
    builder.finish()
}

#[test]
fn candidate_norm_reduction_matches_shared_vector() {
    let (basis, prepared, proof, expected) = fixture();
    let mut builder = Builder::default();
    let constrained = allocate_prepared(&mut builder, &prepared).expect("prepared norm");
    let claim = install_candidate_norm_reduction(&mut builder, basis, 4, &constrained, &proof)
        .expect("vector reduction");
    assert_claim_value(&claim, &expected);
    constrain_claim(&mut builder, &claim, &expected).expect("expected claim");
    let (circuit, assignment) = builder.finish().expect("vector relation");
    assert!(!circuit.is_empty());
    assert!(!assignment.is_empty());
}

#[test]
fn candidate_norm_reduction_feeds_constrained_step() {
    let (basis, prepared, reduction, _) = fixture();
    let (step, root) = step_fixture();
    let mut builder = Builder::default();
    let prepared = allocate_prepared(&mut builder, &prepared).expect("prepared norm");
    let claim = install_candidate_norm_reduction(&mut builder, basis, 4, &prepared, &reduction)
        .expect("reduction");
    let derived = install_constrained_candidate_step(
        &mut builder,
        basis,
        std::slice::from_ref(&claim),
        &step,
    )
    .expect("constrained step");
    assert_root_value(&derived, &root);
    constrain_root(&mut builder, &derived, &root).expect("expected root");
    let (circuit, assignment) = builder.finish().expect("composed relation");
    assert!(!circuit.is_empty());
    assert!(!assignment.is_empty());
}

#[test]
fn candidate_norm_reduction_rejects_bad_shapes() {
    let (basis, prepared, proof, expected) = fixture();
    assert!(build_fixture(basis, &prepared, &proof, &expected).is_ok());

    let mut missing_right = proof.clone();
    missing_right.right.clear();
    assert!(build_fixture(basis, &prepared, &missing_right, &expected).is_err());

    let mut malformed = prepared.clone();
    malformed.polynomial[1].offset = 3;
    assert!(build_fixture(basis, &malformed, &proof, &expected).is_err());

    let mut zero_binding = prepared.clone();
    zero_binding.prepared_binding = SecpScalarWitness::from_u64(0);
    assert!(build_fixture(basis, &zero_binding, &proof, &expected).is_err());

    let mut too_wide = prepared;
    too_wide.polynomial[1]
        .factors
        .push(SecpScalarWitness::from_u64(1));
    assert!(build_fixture(basis, &too_wide, &proof, &expected).is_err());
}

#[test]
#[ignore = "run explicitly in release mode; composed reduction proof is large"]
fn candidate_norm_reduction_binds_composed_step() {
    let (basis, prepared, reduction, _) = fixture();
    let (step, root) = step_fixture();
    let (circuit, assignment) = build_composed_fixture(basis, &prepared, &reduction, &step, &root)
        .expect("composed relation");
    let statement = b"candidate algebraic norm reduction and step";
    let accepted = prove(&circuit, &assignment, statement, [0x96; 32]).expect("proof");
    verify(&circuit, statement, &accepted).expect("valid composition");

    let mut changed_prepared = prepared.clone();
    changed_prepared.prepared_binding.bytes[31] ^= 1;
    let (same_circuit, false_assignment) =
        build_composed_fixture(basis, &changed_prepared, &reduction, &step, &root)
            .expect("changed transcript witness");
    assert_eq!(same_circuit, circuit);
    let false_proof =
        prove(&circuit, &false_assignment, statement, [0x97; 32]).expect("false assignment proof");
    assert!(verify(&circuit, statement, &false_proof).is_err());

    let mut changed_root = root;
    changed_root.scale.bytes[31] ^= 1;
    let (changed_circuit, _) =
        build_composed_fixture(basis, &prepared, &reduction, &step, &changed_root)
            .expect("changed root constant");
    assert_ne!(changed_circuit, circuit);
    assert!(verify(&changed_circuit, statement, &accepted).is_err());

    let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("gate count"));
    eprintln!(
        "candidate_reduction_step_gates={gates} proof_bytes={}",
        accepted.len()
    );
    assert_eq!(
        accepted.len(),
        proof_wire_len(&circuit).expect("proof size")
    );
}
