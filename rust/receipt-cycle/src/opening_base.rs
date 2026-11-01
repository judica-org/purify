//! Candidate opening-base derivation for public IPA relations.
//!
//! This module does not change the accepted SHA-based accumulation suite. It
//! pins the transparent constants and constrained relation for a separately
//! versioned algebraic transcript migration.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use sha2::{Digest, Sha256};

use crate::algebraic_transcript::BuilderTranscript;
use crate::parent_relation::{
    add_point_values, add_points, scale_constant_point, PointValue, SecpEncodedPointWitness,
    SecpPoint,
};
use crate::relation_builder::{Builder, Expression};
use crate::secp_scalar::select_challenge_lanes;
use crate::{ReceiptCycleError, Scalar};

#[cfg(test)]
const SECP_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const SVDW_NEG_C_BE: [u8; 32] = [
    0xf5, 0xd2, 0xd4, 0x56, 0xca, 0xf8, 0x0e, 0x20, 0xdc, 0xc8, 0x8f, 0x3d, 0x58, 0x68, 0x69, 0xd3,
    0x39, 0xe0, 0x92, 0xea, 0x25, 0xeb, 0x13, 0x2b, 0x82, 0x72, 0xd8, 0x50, 0xe3, 0x2a, 0x03, 0xdd,
];

const SVDW_D_BE: [u8; 32] = [
    0x85, 0x16, 0x95, 0xd4, 0x9a, 0x83, 0xf8, 0xef, 0x91, 0x9b, 0xb8, 0x61, 0x53, 0xcb, 0xcb, 0x16,
    0x63, 0x0f, 0xb6, 0x8a, 0xed, 0x0a, 0x76, 0x6a, 0x3e, 0xc6, 0x93, 0xd6, 0x8e, 0x6a, 0xfa, 0x40,
];

const SECP_SQRT_EXPONENT: [u64; 4] = [
    0xffff_ffff_bfff_ff0c,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
];

const OPENING_PAIR_TAG: &[u8] = b"Purify/BPPP/OpeningGeneratorPairV2";
const PUBLIC_HASH_TO_POINT_TAG: &[u8] = b"Purify/BPPP/PublicHashToPointV1";
const FIRST_GENERATION_PREFIX: &[u8] = b"1st generation: ";
const SECOND_GENERATION_PREFIX: &[u8] = b"2nd generation: ";

/// Domain role for a public coefficient-opening reduction.
pub const REDUCTION_OPENING_BASE_ROLE: u64 = 1;
/// Domain role for a public accumulation transition.
pub const ACCUMULATION_OPENING_BASE_ROLE: u64 = 2;

fn field_constant_from_be(mut bytes: [u8; 32]) -> Scalar {
    bytes.reverse();
    Secq256k1Cycle::scalar_from_canonical(&bytes)
        .expect("the pinned secp256k1 field constant is canonical")
}

fn inverse_or_zero(value: Scalar) -> Scalar {
    Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO)
}

fn quadratic_root(value: Scalar) -> (Scalar, bool) {
    let root = value.pow_vartime(SECP_SQRT_EXPONENT);
    (root, root.square() == value)
}

fn scalar_is_odd(value: Scalar) -> bool {
    Secq256k1Cycle::scalar_to_canonical(&value)[0] & 1 != 0
}

fn svdw_point_value(input: Scalar) -> PointValue {
    let neg_c = field_constant_from_be(SVDW_NEG_C_BE);
    let d = field_constant_from_be(SVDW_D_BE);
    let input_squared = input.square();
    let wd = input_squared + Scalar::from(8);
    let x3d = -Scalar::from(3) * input_squared;
    let joint_inverse = inverse_or_zero(wd * x3d);
    let x1 = d + neg_c * input_squared * x3d * joint_inverse;
    let x2 = -(x1 + Scalar::ONE);
    let x3 = Scalar::ONE + wd.square() * wd * joint_inverse;

    let (x, mut y) = [x1, x2, x3]
        .into_iter()
        .find_map(|x| {
            let (root, square) = quadratic_root(x.square() * x + Scalar::from(7));
            square.then_some((x, root))
        })
        .expect("the pinned SvdW map always selects a curve point");
    if scalar_is_odd(input) {
        y = -y;
    }
    PointValue {
        x,
        y,
        identity: false,
    }
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

fn public_hash_to_point_value(input: &[u8]) -> Result<PointValue, ReceiptCycleError> {
    let key = tagged_sha256(PUBLIC_HASH_TO_POINT_TAG, input);
    let map = |prefix: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(prefix);
        hash.update(key);
        let mut input: [u8; 32] = hash.finalize().into();
        input.reverse();
        Secq256k1Cycle::scalar_from_canonical(&input)
            .map(svdw_point_value)
            .ok_or(ReceiptCycleError::Malformed(
                "opening generator field sample",
            ))
    };
    Ok(add_point_values(
        map(FIRST_GENERATION_PREFIX)?,
        map(SECOND_GENERATION_PREFIX)?,
    ))
}

fn opening_generator_pair(
    basis_digest: [u8; 32],
    role: u64,
) -> Result<[PointValue; 2], ReceiptCycleError> {
    if !matches!(
        role,
        REDUCTION_OPENING_BASE_ROLE | ACCUMULATION_OPENING_BASE_ROLE
    ) {
        return Err(ReceiptCycleError::Malformed("opening generator role"));
    }
    let mut points = Vec::with_capacity(2);
    for index in 0..2u8 {
        let mut message = Vec::with_capacity(41);
        message.extend_from_slice(&basis_digest);
        message.extend_from_slice(&role.to_le_bytes());
        message.push(index);
        let seed = tagged_sha256(OPENING_PAIR_TAG, &message);
        let point = public_hash_to_point_value(&seed)?;
        if point.identity {
            return Err(ReceiptCycleError::Malformed("identity opening generator"));
        }
        points.push(point);
    }
    if points[0] == points[1] {
        return Err(ReceiptCycleError::Malformed("duplicate opening generators"));
    }
    points
        .try_into()
        .map_err(|_| ReceiptCycleError::Malformed("opening generator pair"))
}

fn constant_point(value: PointValue) -> SecpPoint {
    SecpPoint {
        x: Expression::constant(value.x),
        y: Expression::constant(value.y),
        identity: Expression::constant(if value.identity {
            Scalar::ONE
        } else {
            Scalar::ZERO
        }),
        witness: value,
    }
}

fn parse_expected_point(
    expected: SecpEncodedPointWitness,
) -> Result<PointValue, ReceiptCycleError> {
    let y = Secq256k1Cycle::scalar_from_canonical(&expected.y)
        .ok_or(ReceiptCycleError::Malformed("noncanonical expected y"))?;
    if expected.encoded == [0; 33] {
        if y != Scalar::ZERO {
            return Err(ReceiptCycleError::Malformed("nonzero identity y"));
        }
        return Ok(PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        });
    }
    if !matches!(expected.encoded[0], 0x02 | 0x03) {
        return Err(ReceiptCycleError::Malformed("expected point prefix"));
    }
    let mut x = [0; 32];
    x.copy_from_slice(&expected.encoded[1..]);
    x.reverse();
    let x = Secq256k1Cycle::scalar_from_canonical(&x)
        .ok_or(ReceiptCycleError::Malformed("noncanonical expected x"))?;
    if y.square() != x.square() * x + Scalar::from(7) {
        return Err(ReceiptCycleError::Malformed("expected point curve"));
    }
    if scalar_is_odd(y) != (expected.encoded[0] == 0x03) {
        return Err(ReceiptCycleError::Malformed("expected point parity"));
    }
    Ok(PointValue {
        x,
        y,
        identity: false,
    })
}

fn constrain_expected_constant(
    builder: &mut Builder,
    actual: &SecpPoint,
    expected: SecpEncodedPointWitness,
) -> Result<(), ReceiptCycleError> {
    let expected = parse_expected_point(expected)?;
    builder.constrain_equal(&actual.x, &Expression::constant(expected.x));
    builder.constrain_equal(&actual.y, &Expression::constant(expected.y));
    builder.constrain_equal(
        &actual.identity,
        &Expression::constant(if expected.identity {
            Scalar::ONE
        } else {
            Scalar::ZERO
        }),
    );
    Ok(())
}

/// Constrain `U = U0 + u U1` for one versioned basis and transcript role.
///
/// `U0` and `U1` are transparently derived outside the circuit with distinct
/// domains. The selected `u` is sampled only after the claimed opening is
/// fixed. No intentionally known discrete-log relation is introduced.
pub(crate) fn constrain_opening_base_pair(
    builder: &mut Builder,
    challenge_lanes: [Expression; 2],
    basis_digest: [u8; 32],
    role: u64,
) -> Result<SecpPoint, ReceiptCycleError> {
    let scalar = select_challenge_lanes(builder, &challenge_lanes[0], &challenge_lanes[1]);
    let [first, second] = opening_generator_pair(basis_digest, role)?;
    let first = constant_point(first);
    let scaled = scale_constant_point(builder, second, &scalar)?;
    let output = add_points(builder, &first, &scaled);
    builder.constrain_zero(output.identity.clone());
    Ok(output)
}

/// Squeeze and constrain an opening base from one exact typed transcript.
pub(crate) fn constrain_transcript_opening_base(
    builder: &mut Builder,
    transcript: &BuilderTranscript,
    basis_digest: [u8; 32],
    role: u64,
) -> Result<SecpPoint, ReceiptCycleError> {
    let challenge_lanes = transcript.opening_base_scalar(builder, basis_digest, role);
    constrain_opening_base_pair(builder, challenge_lanes, basis_digest, role)
}

/// Builds the candidate two-generator opening-base relation.
///
/// Inputs are two canonical little-endian coordinate-field candidates for an
/// unbiased nonzero secp256k1 scalar. Production callers must obtain them from
/// the separately framed opening-base transcript squeeze.
pub fn build_opening_base_pair_relation(
    challenge_lanes: [[u8; 32]; 2],
    basis_digest: [u8; 32],
    role: u64,
    expected: SecpEncodedPointWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let mut inputs = Vec::with_capacity(challenge_lanes.len());
    for bytes in challenge_lanes {
        let value = Secq256k1Cycle::scalar_from_canonical(&bytes)
            .ok_or(ReceiptCycleError::Malformed("noncanonical challenge lane"))?;
        inputs.push(builder.allocate(value));
    }
    let challenge_lanes = inputs
        .try_into()
        .map_err(|_| ReceiptCycleError::Malformed("opening-base challenge lanes"))?;
    let actual = constrain_opening_base_pair(&mut builder, challenge_lanes, basis_digest, role)?;
    constrain_expected_constant(&mut builder, &actual, expected)?;
    builder.finish()
}

/// Builds a no-SHA probe from a typed Poseidon transcript to an opening base.
///
/// This pins the intended composition while the candidate transcript suite is
/// still separate from the accepted native accumulation format.
pub fn build_poseidon_opening_base_probe_relation(
    transcript_fields: [[u8; 32]; 2],
    basis_digest: [u8; 32],
    role: u64,
    expected: SecpEncodedPointWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let mut fields = Vec::with_capacity(transcript_fields.len());
    for bytes in transcript_fields {
        let value = Secq256k1Cycle::scalar_from_canonical(&bytes).ok_or(
            ReceiptCycleError::Malformed("noncanonical transcript field"),
        )?;
        fields.push(builder.allocate(value));
    }
    let mut transcript = BuilderTranscript::new();
    for field in fields {
        transcript.append_field(&mut builder, field);
    }
    let actual = constrain_transcript_opening_base(&mut builder, &transcript, basis_digest, role)?;
    constrain_expected_constant(&mut builder, &actual, expected)?;
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{proof_wire_len, prove, verify};

    fn from_be_hex(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().rev().enumerate() {
            let offset = 2 * index;
            *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).expect("hex byte");
        }
        out
    }

    fn encoded_from_hex(hex: &str, y: &str) -> SecpEncodedPointWitness {
        assert_eq!(hex.len(), 66);
        let mut encoded = [0; 33];
        for (index, byte) in encoded.iter_mut().enumerate() {
            let offset = 2 * index;
            *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).expect("hex byte");
        }
        SecpEncodedPointWitness {
            encoded,
            y: from_be_hex(y),
        }
    }

    fn digest_from_hex(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            let offset = 2 * index;
            *byte = u8::from_str_radix(&hex[offset..offset + 2], 16).expect("hex byte");
        }
        digest
    }

    fn encoded_value(point: PointValue) -> SecpEncodedPointWitness {
        if point.identity {
            return SecpEncodedPointWitness::identity();
        }
        let mut encoded = [0; 33];
        encoded[0] = if scalar_is_odd(point.y) { 0x03 } else { 0x02 };
        let mut x = Secq256k1Cycle::scalar_to_canonical(&point.x);
        x.reverse();
        encoded[1..].copy_from_slice(&x);
        SecpEncodedPointWitness {
            encoded,
            y: Secq256k1Cycle::scalar_to_canonical(&point.y),
        }
    }

    fn encoded_hex(point: PointValue) -> String {
        encoded_value(point)
            .encoded
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn map_input(value: u64) -> [u8; 32] {
        Secq256k1Cycle::scalar_to_canonical(&Scalar::from(value))
    }

    fn gate_count(circuit: &[u8]) -> u32 {
        u32::from_le_bytes(circuit[1..5].try_into().expect("gate count"))
    }

    fn scale_point_value(point: PointValue, scalar_le: [u8; 32]) -> PointValue {
        let mut accumulator = PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        };
        let mut addend = point;
        for bit in 0..256 {
            if scalar_le[bit / 8] >> (bit % 8) & 1 != 0 {
                accumulator = add_point_values(accumulator, addend);
            }
            if bit != 255 {
                addend = add_point_values(addend, addend);
            }
        }
        accumulator
    }

    fn select_challenge_value(lanes: [Scalar; 2]) -> Result<[u8; 32], ReceiptCycleError> {
        for lane in lanes {
            let scalar_le = Secq256k1Cycle::scalar_to_canonical(&lane);
            let mut scalar_be = scalar_le;
            scalar_be.reverse();
            if scalar_be != [0; 32] && scalar_be < SECP_ORDER_BE {
                return Ok(scalar_le);
            }
        }
        Err(ReceiptCycleError::Malformed(
            "opening-base challenge exhausted",
        ))
    }

    fn opening_base_value(
        basis_digest: [u8; 32],
        role: u64,
        challenge_lanes: [Scalar; 2],
    ) -> Result<PointValue, ReceiptCycleError> {
        let [first, second] = opening_generator_pair(basis_digest, role)?;
        let scalar = select_challenge_value(challenge_lanes)?;
        let output = add_point_values(first, scale_point_value(second, scalar));
        if output.identity {
            return Err(ReceiptCycleError::Malformed("identity opening base"));
        }
        Ok(output)
    }

    #[test]
    fn opening_base_pair_matches_the_reference_vectors() -> Result<(), ReceiptCycleError> {
        let vectors = include_str!("../tests/vectors/opening_base_pair.txt");
        let mut role_one_gate_count = None;
        let mut role_one_circuits = Vec::new();
        for line in vectors.lines().filter(|line| line.starts_with("vector ")) {
            let words = line.split_ascii_whitespace().collect::<Vec<_>>();
            assert_eq!(words.len(), 9);
            let basis_digest = digest_from_hex(words[1]);
            let role = words[2].parse::<u64>().expect("role");
            let scalar = from_be_hex(words[3]);
            let pair = opening_generator_pair(basis_digest, role).expect("generator pair");
            assert_eq!(encoded_hex(pair[0]), words[4]);
            assert_eq!(encoded_hex(pair[1]), words[5]);
            let expected = encoded_from_hex(words[6], words[7]);
            assert_eq!(words[8], "ok");
            let (circuit, _) = build_opening_base_pair_relation(
                [scalar, map_input(1)],
                basis_digest,
                role,
                expected,
            )
            .expect("opening-base pair relation");
            if role == REDUCTION_OPENING_BASE_ROLE {
                if let Some(previous) = role_one_gate_count {
                    assert_eq!(previous, gate_count(&circuit));
                } else {
                    role_one_gate_count = Some(gate_count(&circuit));
                }
                role_one_circuits.push(circuit);
            }
        }
        assert!(role_one_gate_count.is_some());
        assert_eq!(role_one_circuits.len(), 2);
        assert_ne!(role_one_circuits[0], role_one_circuits[1]);

        let basis_digest =
            digest_from_hex("4047eedb842ea65b60ce2a08b26117a40a684a431a6040dfabe5b271d65e919f");
        let order = from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let lanes = [
            Secq256k1Cycle::scalar_from_canonical(&order).expect("n below p"),
            Scalar::ONE,
        ];
        let expected = encoded_value(opening_base_value(
            basis_digest,
            REDUCTION_OPENING_BASE_ROLE,
            lanes,
        )?);
        let (fallback_circuit, _) = build_opening_base_pair_relation(
            [order, map_input(1)],
            basis_digest,
            REDUCTION_OPENING_BASE_ROLE,
            expected,
        )?;
        assert_eq!(role_one_gate_count, Some(gate_count(&fallback_circuit)));
        assert!(opening_generator_pair(basis_digest, 0).is_err());
        Ok::<(), ReceiptCycleError>(())
    }

    #[test]
    #[ignore = "run explicitly in release mode; this proves a scalar multiplication"]
    fn poseidon_opening_base_probe_has_no_sha_gates() {
        let fields = [Scalar::from(11), Scalar::from(29)];
        let role = ACCUMULATION_OPENING_BASE_ROLE;
        let basis_digest = [0x42; 32];
        let lanes =
            crate::algebraic_transcript::native_opening_base_probe(fields, basis_digest, role);
        let expected = encoded_value(
            opening_base_value(basis_digest, role, lanes).expect("native opening base"),
        );
        let (circuit, assignment) = build_poseidon_opening_base_probe_relation(
            fields.map(|value| Secq256k1Cycle::scalar_to_canonical(&value)),
            basis_digest,
            role,
            expected,
        )
        .expect("Poseidon opening-base relation");
        assert_eq!(gate_count(&circuit), 25_918);
        assert_eq!(proof_wire_len(&circuit).expect("proof size"), 1_415);

        let statement = b"candidate Poseidon opening base";
        let proof = prove(&circuit, &assignment, statement, [0x71; 32]).expect("proof");
        verify(&circuit, statement, &proof).expect("verification");

        let mut wrong = expected;
        wrong.y = Secq256k1Cycle::scalar_to_canonical(
            &-Secq256k1Cycle::scalar_from_canonical(&wrong.y).expect("expected y"),
        );
        wrong.encoded[0] ^= 1;
        let (changed_circuit, false_assignment) = build_poseidon_opening_base_probe_relation(
            fields.map(|value| Secq256k1Cycle::scalar_to_canonical(&value)),
            basis_digest,
            role,
            wrong,
        )
        .expect("false relation");
        assert_ne!(changed_circuit, circuit);
        assert_eq!(gate_count(&changed_circuit), gate_count(&circuit));
        assert!(verify(&changed_circuit, statement, &proof).is_err());
        let false_proof =
            prove(&changed_circuit, &false_assignment, statement, [0x72; 32]).expect("false proof");
        assert!(verify(&changed_circuit, statement, &false_proof).is_err());
    }
}
