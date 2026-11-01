//! Arithmetic foundations for the purpose-specific parent receipt relation.
//!
//! This module only constructs authenticated R1CS circuit and assignment
//! encodings. It does not claim that a construction receipt is accepted. The
//! receipt verifier must still install every V3 transcript, reduction, and
//! accumulator constraint before exposing an acceptance API.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;

use crate::relation_builder::{Builder, Expression};
use crate::secp_scalar::{allocate_canonical_scalar, SecpScalarVar, SecpScalarWitness};
use crate::{ReceiptCycleError, Scalar};

/// Canonical affine witness for the native secp256k1 base field.
///
/// The identity has the unique representation `(0, 0, true)`. Non-identity
/// coordinates are canonical little-endian field elements and must satisfy
/// `y^2 = x^3 + 7`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpAffineWitness {
    /// Canonical little-endian x coordinate.
    pub x: [u8; 32],
    /// Canonical little-endian y coordinate.
    pub y: [u8; 32],
    /// Whether this is the group identity.
    pub identity: bool,
}

/// Canonical non-identity secp256k1 point with its compressed parity bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpCompressedWitness {
    /// Canonical little-endian x coordinate.
    pub x: [u8; 32],
    /// Canonical little-endian y coordinate used to open the point.
    pub y: [u8; 32],
    /// The SEC1 prefix bit: true for an odd y coordinate.
    pub odd: bool,
}

/// Exact 33-byte accumulation-proof point and its affine y opening.
///
/// `encoded` is either the unique all-zero identity or a compressed SEC1
/// point `02/03 || x` with a big-endian x coordinate. `y` is canonical
/// little-endian field data and is not part of the public point encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpEncodedPointWitness {
    /// The exact native accumulation `PointBytes` value.
    pub encoded: [u8; 33],
    /// Canonical little-endian affine y opening, or zero for the identity.
    pub y: [u8; 32],
}

impl SecpEncodedPointWitness {
    /// Returns the unique all-zero accumulation identity encoding.
    pub const fn identity() -> Self {
        Self {
            encoded: [0; 33],
            y: [0; 32],
        }
    }
}

impl SecpAffineWitness {
    /// Returns the unique identity witness.
    pub const fn identity() -> Self {
        Self {
            x: [0; 32],
            y: [0; 32],
            identity: true,
        }
    }
}

#[derive(Clone)]
struct SecpPoint {
    x: Expression,
    y: Expression,
    identity: Expression,
    witness: PointValue,
}

#[derive(Clone, Copy)]
struct PointValue {
    x: Scalar,
    y: Scalar,
    identity: bool,
}

#[derive(Clone, Copy)]
struct EncodedPointValue {
    point: PointValue,
    prefix: u8,
    odd: bool,
}

struct EncodedSecpPoint {
    point: SecpPoint,
    prefix: Expression,
    odd: Expression,
}

const SECP_FIELD_MODULUS_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

fn field_modulus_bit(index: usize) -> bool {
    let byte = SECP_FIELD_MODULUS_BE[31 - index / 8];
    ((byte >> (index % 8)) & 1) != 0
}

fn parse_point(witness: SecpAffineWitness) -> Result<PointValue, ReceiptCycleError> {
    let x = Secq256k1Cycle::scalar_from_canonical(&witness.x)
        .ok_or(ReceiptCycleError::Malformed("noncanonical secp x"))?;
    let y = Secq256k1Cycle::scalar_from_canonical(&witness.y)
        .ok_or(ReceiptCycleError::Malformed("noncanonical secp y"))?;
    Ok(PointValue {
        x,
        y,
        identity: witness.identity,
    })
}

fn parse_compressed_point(witness: SecpCompressedWitness) -> Result<PointValue, ReceiptCycleError> {
    parse_point(SecpAffineWitness {
        x: witness.x,
        y: witness.y,
        identity: false,
    })
}

fn parse_encoded_point(
    witness: SecpEncodedPointWitness,
) -> Result<EncodedPointValue, ReceiptCycleError> {
    let mut x_bytes = [0; 32];
    x_bytes.copy_from_slice(&witness.encoded[1..]);
    x_bytes.reverse();
    let x = Secq256k1Cycle::scalar_from_canonical(&x_bytes)
        .ok_or(ReceiptCycleError::Malformed("noncanonical encoded secp x"))?;
    let y = Secq256k1Cycle::scalar_from_canonical(&witness.y)
        .ok_or(ReceiptCycleError::Malformed("noncanonical encoded secp y"))?;
    let prefix = witness.encoded[0];
    Ok(EncodedPointValue {
        point: PointValue {
            x,
            y,
            identity: prefix == 0,
        },
        prefix,
        odd: prefix & 1 != 0,
    })
}

fn allocate_point(builder: &mut Builder, value: PointValue) -> SecpPoint {
    let x = builder.allocate(value.x);
    let y = builder.allocate(value.y);
    let identity = builder.allocate_boolean(value.identity);
    let one = Expression::constant(Scalar::ONE);
    let active = one.sub(&identity);

    let y_squared = builder.multiply(&y, &y);
    let x_squared = builder.multiply(&x, &x);
    let x_cubed = builder.multiply(&x_squared, &x);
    let curve = y_squared
        .sub(&x_cubed)
        .sub(&Expression::constant(Scalar::from(7)));
    let active_curve = builder.multiply(&active, &curve);
    builder.constrain_zero(active_curve);

    let identity_x = builder.multiply(&identity, &x);
    let identity_y = builder.multiply(&identity, &y);
    builder.constrain_zero(identity_x);
    builder.constrain_zero(identity_y);

    SecpPoint {
        x,
        y,
        identity,
        witness: value,
    }
}

fn canonical_field_bits(builder: &mut Builder, value: &Expression) -> Vec<Expression> {
    let encoded = Secq256k1Cycle::scalar_to_canonical(&value.value());
    let mut bits = Vec::with_capacity(256);
    let mut reconstructed = Expression::constant(Scalar::ZERO);
    let mut coefficient = Scalar::ONE;
    for index in 0..256 {
        let bit = ((encoded[index / 8] >> (index % 8)) & 1) != 0;
        let bit = builder.allocate_boolean(bit);
        reconstructed = reconstructed.add(&bit.clone().scale(coefficient));
        coefficient = coefficient + coefficient;
        bits.push(bit);
    }
    builder.constrain_equal(&reconstructed, value);

    // Equality modulo p alone would also permit the 256-bit integer value+p.
    // Constraining the decomposition below p makes the low parity bit unique.
    let one = Expression::constant(Scalar::ONE);
    let mut equal = one.clone();
    let mut less = Expression::constant(Scalar::ZERO);
    for index in (0..256).rev() {
        let equal_and_bit = builder.multiply(&equal, &bits[index]);
        if field_modulus_bit(index) {
            less = less.add(&equal.clone().sub(&equal_and_bit));
            equal = equal_and_bit;
        } else {
            builder.constrain_zero(equal_and_bit.clone());
            equal = equal.sub(&equal_and_bit);
        }
    }
    builder.constrain_equal(&less, &one);
    bits
}

fn allocate_compressed_point(
    builder: &mut Builder,
    witness: SecpCompressedWitness,
) -> Result<SecpPoint, ReceiptCycleError> {
    let point = allocate_point(builder, parse_compressed_point(witness)?);
    builder.constrain_zero(point.identity.clone());
    let y_bits = canonical_field_bits(builder, &point.y);
    let odd = builder.allocate_boolean(witness.odd);
    builder.constrain_equal(&odd, &y_bits[0]);
    Ok(point)
}

fn allocate_encoded_point(
    builder: &mut Builder,
    witness: SecpEncodedPointWitness,
) -> Result<EncodedSecpPoint, ReceiptCycleError> {
    let value = parse_encoded_point(witness)?;
    let point = allocate_point(builder, value.point);
    let y_bits = canonical_field_bits(builder, &point.y);
    let odd = builder.allocate_boolean(value.odd);
    builder.constrain_equal(&odd, &y_bits[0]);

    let prefix = builder.allocate(Scalar::from(u64::from(value.prefix)));
    let active = Expression::constant(Scalar::ONE).sub(&point.identity);
    let finite_prefix = Expression::constant(Scalar::from(2)).add(&odd);
    let expected_prefix = builder.multiply(&active, &finite_prefix);
    builder.constrain_equal(&prefix, &expected_prefix);

    Ok(EncodedSecpPoint { point, prefix, odd })
}

fn inverse_or_zero(value: Scalar) -> Scalar {
    Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO)
}

fn equality_bit(
    builder: &mut Builder,
    left: &Expression,
    right: &Expression,
) -> (Expression, Expression) {
    let difference = left.clone().sub(right);
    let equal = builder.allocate_boolean(difference.value() == Scalar::ZERO);
    let inverse = builder.allocate(inverse_or_zero(difference.value()));
    let product = builder.multiply(&difference, &inverse);
    let one_minus_equal = Expression::constant(Scalar::ONE).sub(&equal);
    builder.constrain_equal(&product, &one_minus_equal);
    let equal_difference = builder.multiply(&equal, &difference);
    builder.constrain_zero(equal_difference);
    (equal, inverse)
}

fn add_point_values(left: PointValue, right: PointValue) -> PointValue {
    if left.identity {
        return right;
    }
    if right.identity {
        return left;
    }
    if left.x != right.x {
        let slope = (right.y - left.y) * inverse_or_zero(right.x - left.x);
        let x = slope.square() - left.x - right.x;
        let y = slope * (left.x - x) - left.y;
        return PointValue {
            x,
            y,
            identity: false,
        };
    }
    if left.y != right.y {
        return PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        };
    }
    let slope = Scalar::from(3) * left.x.square() * inverse_or_zero(Scalar::from(2) * left.y);
    let x = slope.square() - Scalar::from(2) * left.x;
    let y = slope * (left.x - x) - left.y;
    PointValue {
        x,
        y,
        identity: false,
    }
}

fn add_points(builder: &mut Builder, left: &SecpPoint, right: &SecpPoint) -> SecpPoint {
    let one = Expression::constant(Scalar::ONE);
    let not_left_identity = one.clone().sub(&left.identity);
    let not_right_identity = one.clone().sub(&right.identity);
    let both_active = builder.multiply(&not_left_identity, &not_right_identity);
    let (same_x, inverse_dx) = equality_bit(builder, &left.x, &right.x);
    let (same_y, _) = equality_bit(builder, &left.y, &right.y);
    let distinct_x = one.clone().sub(&same_x);
    let distinct = builder.multiply(&both_active, &distinct_x);
    let same_active_x = builder.multiply(&both_active, &same_x);
    let doubled = builder.multiply(&same_active_x, &same_y);
    let not_same_y = one.clone().sub(&same_y);
    let inverse = builder.multiply(&same_active_x, &not_same_y);
    let left_only = builder.multiply(&not_left_identity, &right.identity);
    let right_only = builder.multiply(&left.identity, &not_right_identity);
    let both_identity = builder.multiply(&left.identity, &right.identity);

    // `inverse_dx` opens `(left.x - right.x)^-1`, so use the same
    // orientation for the numerator.
    let dy = left.y.clone().sub(&right.y);
    let add_slope = builder.multiply(&dy, &inverse_dx);
    let add_slope_squared = builder.multiply(&add_slope, &add_slope);
    let add_x = add_slope_squared.sub(&left.x).sub(&right.x);
    let left_x_minus_add_x = left.x.clone().sub(&add_x);
    let add_y_product = builder.multiply(&add_slope, &left_x_minus_add_x);
    let add_y = add_y_product.sub(&left.y);

    let two_y = left.y.clone().scale(Scalar::from(2));
    let double_inverse_value = if left.witness.identity {
        Scalar::ZERO
    } else {
        inverse_or_zero(Scalar::from(2) * left.witness.y)
    };
    let double_inverse = builder.allocate(double_inverse_value);
    let denominator_check = builder.multiply(&two_y, &double_inverse);
    let denominator_error = denominator_check.sub(&one);
    let selected_denominator_error = builder.multiply(&doubled, &denominator_error);
    builder.constrain_zero(selected_denominator_error);
    let x_squared = builder.multiply(&left.x, &left.x);
    let three_x_squared = x_squared.scale(Scalar::from(3));
    let double_slope = builder.multiply(&three_x_squared, &double_inverse);
    let double_slope_squared = builder.multiply(&double_slope, &double_slope);
    let double_x = double_slope_squared.sub(&left.x.clone().scale(Scalar::from(2)));
    let left_x_minus_double_x = left.x.clone().sub(&double_x);
    let double_y_product = builder.multiply(&double_slope, &left_x_minus_double_x);
    let double_y = double_y_product.sub(&left.y);

    let left_x_selected = builder.multiply(&left_only, &left.x);
    let right_x_selected = builder.multiply(&right_only, &right.x);
    let add_x_selected = builder.multiply(&distinct, &add_x);
    let double_x_selected = builder.multiply(&doubled, &double_x);
    let selected_x = left_x_selected
        .add(&right_x_selected)
        .add(&add_x_selected)
        .add(&double_x_selected);

    let left_y_selected = builder.multiply(&left_only, &left.y);
    let right_y_selected = builder.multiply(&right_only, &right.y);
    let add_y_selected = builder.multiply(&distinct, &add_y);
    let double_y_selected = builder.multiply(&doubled, &double_y);
    let selected_y = left_y_selected
        .add(&right_y_selected)
        .add(&add_y_selected)
        .add(&double_y_selected);
    let selected_identity = both_identity.add(&inverse);

    let output = allocate_point(builder, add_point_values(left.witness, right.witness));
    builder.constrain_equal(&output.x, &selected_x);
    builder.constrain_equal(&output.y, &selected_y);
    builder.constrain_equal(&output.identity, &selected_identity);
    output
}

fn select_point(
    builder: &mut Builder,
    condition: &Expression,
    when_false: &SecpPoint,
    when_true: &SecpPoint,
) -> SecpPoint {
    let select = |builder: &mut Builder, when_false: &Expression, when_true: &Expression| {
        let difference = when_true.clone().sub(when_false);
        when_false
            .clone()
            .add(&builder.multiply(condition, &difference))
    };
    let witness = if condition.value() == Scalar::ONE {
        when_true.witness
    } else {
        when_false.witness
    };
    SecpPoint {
        x: select(builder, &when_false.x, &when_true.x),
        y: select(builder, &when_false.y, &when_true.y),
        identity: select(builder, &when_false.identity, &when_true.identity),
        witness,
    }
}

fn scale_point(builder: &mut Builder, point: &SecpPoint, scalar: &SecpScalarVar) -> SecpPoint {
    let mut accumulator = allocate_point(
        builder,
        PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        },
    );
    let mut addend = point.clone();
    for (index, bit) in scalar.bits.iter().enumerate() {
        let sum = add_points(builder, &accumulator, &addend);
        accumulator = select_point(builder, bit, &accumulator, &sum);
        if index + 1 != scalar.bits.len() {
            addend = add_points(builder, &addend, &addend);
        }
    }
    accumulator
}

fn msm_points(
    builder: &mut Builder,
    points: &[SecpPoint],
    scalars: &[SecpScalarVar],
) -> Result<SecpPoint, ReceiptCycleError> {
    if points.is_empty() || points.len() != scalars.len() {
        return Err(ReceiptCycleError::Malformed("secp MSM shape"));
    }
    let bit_count = scalars[0].bits.len();
    if bit_count == 0 || scalars.iter().any(|scalar| scalar.bits.len() != bit_count) {
        return Err(ReceiptCycleError::Malformed("secp MSM scalar width"));
    }

    let mut accumulator = allocate_point(
        builder,
        PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        },
    );
    for bit in (0..bit_count).rev() {
        if bit + 1 != bit_count {
            accumulator = add_points(builder, &accumulator, &accumulator);
        }
        for (point, scalar) in points.iter().zip(scalars) {
            let sum = add_points(builder, &accumulator, point);
            accumulator = select_point(builder, &scalar.bits[bit], &accumulator, &sum);
        }
    }
    Ok(accumulator)
}

/// Builds the canonical compressed-point relation used by parent transcripts.
///
/// The private y coordinate must open a non-identity secp256k1 point and its
/// canonical integer decomposition must have the advertised SEC1 parity. The
/// circuit shape is independent of the point and parity witnesses.
pub fn build_secp_compressed_point_relation(
    witness: SecpCompressedWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let _point = allocate_compressed_point(&mut builder, witness)?;
    builder.finish()
}

/// Builds the exact accumulation-proof point decoding relation.
///
/// This accepts only the unique all-zero identity or a finite compressed SEC1
/// point. The y opening and prefix parity are constrained without changing the
/// circuit shape between identity and finite encodings.
pub fn build_secp_encoded_point_relation(
    witness: SecpEncodedPointWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let encoded = allocate_encoded_point(&mut builder, witness)?;
    let _ = (encoded.point, encoded.prefix, encoded.odd);
    builder.finish()
}

/// Builds a native-field secp256k1 addition relation.
///
/// This narrow constructor exists so the complete exceptional-case group
/// gadget can be tested and benchmarked independently before it is embedded
/// in the full parent verifier. The returned circuit is statement-independent;
/// all three points are private witnesses and `expected` is constrained to be
/// the exact sum of `left` and `right`.
pub fn build_secp_addition_relation(
    left: SecpAffineWitness,
    right: SecpAffineWitness,
    expected: SecpAffineWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let left = allocate_point(&mut builder, parse_point(left)?);
    let right = allocate_point(&mut builder, parse_point(right)?);
    let expected = allocate_point(&mut builder, parse_point(expected)?);
    let sum = add_points(&mut builder, &left, &right);
    builder.constrain_equal(&sum.x, &expected.x);
    builder.constrain_equal(&sum.y, &expected.y);
    builder.constrain_equal(&sum.identity, &expected.identity);
    builder.finish()
}

/// Builds `scalar * point = expected` in the secp256k1 group.
///
/// The scalar is canonical modulo the secp256k1 group order. The complete
/// point addition gadget covers zero, identity, doubling, inverse, and
/// distinct-point branches without changing the circuit shape.
pub fn build_secp_scalar_multiplication_relation(
    point: SecpAffineWitness,
    scalar: SecpScalarWitness,
    expected: SecpAffineWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let point = allocate_point(&mut builder, parse_point(point)?);
    let scalar = allocate_canonical_scalar(&mut builder, scalar)?;
    let expected = allocate_point(&mut builder, parse_point(expected)?);
    let product = scale_point(&mut builder, &point, &scalar);
    builder.constrain_equal(&product.x, &expected.x);
    builder.constrain_equal(&product.y, &expected.y);
    builder.constrain_equal(&product.identity, &expected.identity);
    builder.finish()
}

/// Builds one shared variable-base secp256k1 MSM relation.
///
/// The public term count fixes the circuit shape. All scalars are canonical
/// modulo the secp256k1 group order. One MSB-first accumulator shares the 255
/// doublings across every term instead of repeating them per scalar.
pub fn build_secp_msm_relation(
    terms: &[(SecpAffineWitness, SecpScalarWitness)],
    expected: SecpAffineWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    const MAX_PARENT_MSM_TERMS: usize = 64;
    if terms.is_empty() || terms.len() > MAX_PARENT_MSM_TERMS {
        return Err(ReceiptCycleError::Malformed("secp MSM term count"));
    }

    let mut builder = Builder::default();
    let mut points = Vec::with_capacity(terms.len());
    let mut scalars = Vec::with_capacity(terms.len());
    for &(point, scalar) in terms {
        points.push(allocate_point(&mut builder, parse_point(point)?));
        scalars.push(allocate_canonical_scalar(&mut builder, scalar)?);
    }
    let expected = allocate_point(&mut builder, parse_point(expected)?);
    let result = msm_points(&mut builder, &points, &scalars)?;
    builder.constrain_equal(&result.x, &expected.x);
    builder.constrain_equal(&result.y, &expected.y);
    builder.constrain_equal(&result.identity, &expected.identity);
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

    fn generator() -> SecpAffineWitness {
        SecpAffineWitness {
            x: from_be_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            y: from_be_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
            identity: false,
        }
    }

    fn twice_generator() -> SecpAffineWitness {
        SecpAffineWitness {
            x: from_be_hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            y: from_be_hex("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
            identity: false,
        }
    }

    fn three_times_generator() -> SecpAffineWitness {
        SecpAffineWitness {
            x: from_be_hex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            y: from_be_hex("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
            identity: false,
        }
    }

    fn negate(point: SecpAffineWitness) -> SecpAffineWitness {
        let value = parse_point(point).expect("point");
        SecpAffineWitness {
            x: point.x,
            y: Secq256k1Cycle::scalar_to_canonical(&-value.y),
            identity: false,
        }
    }

    fn compressed(point: SecpAffineWitness, odd: bool) -> SecpCompressedWitness {
        assert!(!point.identity);
        SecpCompressedWitness {
            x: point.x,
            y: point.y,
            odd,
        }
    }

    fn encoded(point: SecpAffineWitness, prefix: u8) -> SecpEncodedPointWitness {
        assert!(!point.identity);
        let mut encoded = [0; 33];
        encoded[0] = prefix;
        let mut x = point.x;
        x.reverse();
        encoded[1..].copy_from_slice(&x);
        SecpEncodedPointWitness {
            encoded,
            y: point.y,
        }
    }

    fn prove_compressed_point(witness: SecpCompressedWitness) -> Result<(), ReceiptCycleError> {
        let (circuit, assignment) = build_secp_compressed_point_relation(witness)?;
        let statement = b"secp compressed-point foundation";
        let proof = prove(&circuit, &assignment, statement, [0x92; 32])?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        verify(&circuit, statement, &proof)
    }

    fn prove_encoded_point(
        witness: SecpEncodedPointWitness,
    ) -> Result<(Vec<u8>, usize), ReceiptCycleError> {
        let (circuit, assignment) = build_secp_encoded_point_relation(witness)?;
        let statement = b"secp encoded-point foundation";
        let proof = prove(&circuit, &assignment, statement, [0x93; 32])?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        verify(&circuit, statement, &proof)?;
        Ok((circuit, proof.len()))
    }

    fn prove_relation(
        left: SecpAffineWitness,
        right: SecpAffineWitness,
        expected: SecpAffineWitness,
    ) -> Result<(), ReceiptCycleError> {
        let (circuit, assignment) = build_secp_addition_relation(left, right, expected)?;
        let statement = b"secp addition foundation";
        let proof = prove(&circuit, &assignment, statement, [0x91; 32])?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        verify(&circuit, statement, &proof)
    }

    fn prove_scale_relation(
        point: SecpAffineWitness,
        scalar: SecpScalarWitness,
        expected: SecpAffineWitness,
    ) -> Result<(Vec<u8>, usize, usize), ReceiptCycleError> {
        let (circuit, assignment) =
            build_secp_scalar_multiplication_relation(point, scalar, expected)?;
        let statement = b"secp scalar multiplication foundation";
        let proof = prove(&circuit, &assignment, statement, [0x81; 32])?;
        verify(&circuit, statement, &proof)?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("gate count")) as usize;
        Ok((circuit, gates, proof.len()))
    }

    fn prove_msm_relation(
        terms: &[(SecpAffineWitness, SecpScalarWitness)],
        expected: SecpAffineWitness,
    ) -> Result<(Vec<u8>, usize, usize), ReceiptCycleError> {
        let (circuit, assignment) = build_secp_msm_relation(terms, expected)?;
        let statement = b"shared secp MSM foundation";
        let proof = prove(&circuit, &assignment, statement, [0x82; 32])?;
        verify(&circuit, statement, &proof)?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("gate count")) as usize;
        Ok((circuit, gates, proof.len()))
    }

    #[test]
    fn complete_addition_handles_double_inverse_and_identity() {
        let g = generator();
        prove_relation(g, g, twice_generator()).expect("double");
        prove_relation(g, twice_generator(), three_times_generator()).expect("distinct points");
        prove_relation(g, negate(g), SecpAffineWitness::identity()).expect("inverse");
        prove_relation(SecpAffineWitness::identity(), g, g).expect("left identity");
        prove_relation(g, SecpAffineWitness::identity(), g).expect("right identity");
        prove_relation(
            SecpAffineWitness::identity(),
            SecpAffineWitness::identity(),
            SecpAffineWitness::identity(),
        )
        .expect("both identity");
    }

    #[test]
    fn compressed_point_binds_canonical_y_parity() {
        let even = compressed(generator(), false);
        let odd = compressed(negate(generator()), true);
        prove_compressed_point(even).expect("even generator");
        prove_compressed_point(odd).expect("odd negated generator");

        let mut wrong_parity = even;
        wrong_parity.odd = true;
        assert!(prove_compressed_point(wrong_parity).is_err());

        let (even_circuit, _) = build_secp_compressed_point_relation(even).expect("even circuit");
        let (odd_circuit, _) = build_secp_compressed_point_relation(odd).expect("odd circuit");
        assert_eq!(even_circuit, odd_circuit);
        assert_eq!(
            crate::Circuit::parse(&even_circuit)
                .expect("circuit")
                .gate_count,
            522
        );
        assert_eq!(proof_wire_len(&even_circuit).expect("proof size"), 1085);
    }

    #[test]
    fn compressed_point_rejects_noncanonical_coordinates() {
        let mut noncanonical = compressed(generator(), false);
        noncanonical.y = [0xff; 32];
        assert!(build_secp_compressed_point_relation(noncanonical).is_err());
    }

    #[test]
    fn encoded_point_accepts_identity_and_finite_sec1() {
        let identity = SecpEncodedPointWitness::identity();
        let g = generator();
        let generator = encoded(g, 0x02);
        let odd_generator = encoded(negate(g), 0x03);

        let (identity_circuit, proof_bytes) =
            prove_encoded_point(identity).expect("encoded identity");
        prove_encoded_point(generator).expect("encoded finite point");

        let (generator_circuit, _) =
            build_secp_encoded_point_relation(generator).expect("finite circuit");
        let (odd_circuit, _) =
            build_secp_encoded_point_relation(odd_generator).expect("odd circuit");
        assert_eq!(identity_circuit, generator_circuit);
        assert_eq!(identity_circuit, odd_circuit);
        assert_eq!(
            crate::Circuit::parse(&identity_circuit)
                .expect("circuit")
                .gate_count,
            524
        );
        assert_eq!(proof_bytes, 1085);
    }

    #[test]
    fn encoded_point_rejects_noncanonical_forms() {
        let generator = generator();

        let mut zero_prefix_hybrid = encoded(generator, 0x00);
        assert!(prove_encoded_point(zero_prefix_hybrid).is_err());
        zero_prefix_hybrid.encoded[1] ^= 1;
        assert!(prove_encoded_point(zero_prefix_hybrid).is_err());

        let invalid_prefix = encoded(generator, 0x04);
        assert!(prove_encoded_point(invalid_prefix).is_err());

        let wrong_parity = encoded(generator, 0x03);
        assert!(prove_encoded_point(wrong_parity).is_err());

        let mut off_curve = encoded(generator, 0x02);
        off_curve.y[0] ^= 1;
        assert!(prove_encoded_point(off_curve).is_err());

        let mut noncanonical_x = encoded(generator, 0x02);
        noncanonical_x.encoded[1..].fill(0xff);
        assert!(build_secp_encoded_point_relation(noncanonical_x).is_err());

        let mut noncanonical_y = encoded(generator, 0x02);
        noncanonical_y.y = [0xff; 32];
        assert!(build_secp_encoded_point_relation(noncanonical_y).is_err());
    }

    #[test]
    fn circuit_is_independent_of_private_addition_branch() {
        let g = generator();
        let (double, _) =
            build_secp_addition_relation(g, g, twice_generator()).expect("double circuit");
        let (distinct, _) =
            build_secp_addition_relation(g, twice_generator(), three_times_generator())
                .expect("distinct circuit");
        let (inverse, _) =
            build_secp_addition_relation(g, negate(g), SecpAffineWitness::identity())
                .expect("inverse circuit");
        let (identity, _) = build_secp_addition_relation(SecpAffineWitness::identity(), g, g)
            .expect("identity circuit");
        assert_eq!(double, distinct);
        assert_eq!(double, inverse);
        assert_eq!(double, identity);
    }

    #[test]
    fn invalid_curve_point_and_wrong_sum_are_unsatisfied() {
        let g = generator();
        let mut invalid = g;
        invalid.y[0] ^= 1;
        assert!(prove_relation(invalid, g, twice_generator()).is_err());
        assert!(prove_relation(g, g, g).is_err());
    }

    #[test]
    fn noncanonical_identity_is_unsatisfied() {
        let mut identity = SecpAffineWitness::identity();
        identity.x[0] = 1;
        assert!(prove_relation(identity, generator(), generator()).is_err());
    }

    #[test]
    fn scalar_multiplication_handles_zero_two_and_order_boundary() {
        let (_, gates, proof_bytes) = prove_scale_relation(
            generator(),
            SecpScalarWitness::from_u64(0),
            SecpAffineWitness::identity(),
        )
        .expect("zero scalar");
        prove_scale_relation(
            generator(),
            SecpScalarWitness::from_u64(2),
            twice_generator(),
        )
        .expect("doubling scalar");
        let maximum = SecpScalarWitness::from_bytes_be([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ]);
        prove_scale_relation(generator(), maximum, negate(generator())).expect("order minus one");
        eprintln!("receipt_secp_scalar_mul_gates={gates} proof_bytes={proof_bytes}");
        assert_eq!(gates, 23_280);
        assert_eq!(proof_bytes, 1_415);
    }

    #[test]
    fn scalar_multiplication_shape_is_secret_independent() {
        let (zero, _) = build_secp_scalar_multiplication_relation(
            generator(),
            SecpScalarWitness::from_u64(0),
            SecpAffineWitness::identity(),
        )
        .expect("zero circuit");
        let (one, _) = build_secp_scalar_multiplication_relation(
            generator(),
            SecpScalarWitness::from_u64(1),
            generator(),
        )
        .expect("one circuit");
        let (two, _) = build_secp_scalar_multiplication_relation(
            generator(),
            SecpScalarWitness::from_u64(2),
            twice_generator(),
        )
        .expect("two circuit");
        assert_eq!(zero, one);
        assert_eq!(zero, two);
    }

    #[test]
    fn scalar_multiplication_rejects_wrong_and_noncanonical_witnesses() {
        assert!(prove_scale_relation(
            generator(),
            SecpScalarWitness::from_u64(2),
            three_times_generator(),
        )
        .is_err());
        let order = SecpScalarWitness::from_bytes_be([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ]);
        assert!(prove_scale_relation(generator(), order, SecpAffineWitness::identity(),).is_err());
    }

    #[test]
    fn shared_msm_handles_sum_cancellation_and_zero() {
        let sum_terms = [
            (generator(), SecpScalarWitness::from_u64(1)),
            (generator(), SecpScalarWitness::from_u64(2)),
        ];
        let (_, gates, proof_bytes) =
            prove_msm_relation(&sum_terms, three_times_generator()).expect("shared sum");
        let cancellation_terms = [
            (generator(), SecpScalarWitness::from_u64(1)),
            (negate(generator()), SecpScalarWitness::from_u64(1)),
        ];
        prove_msm_relation(&cancellation_terms, SecpAffineWitness::identity())
            .expect("shared cancellation");
        let zero_terms = [
            (generator(), SecpScalarWitness::from_u64(0)),
            (twice_generator(), SecpScalarWitness::from_u64(0)),
        ];
        prove_msm_relation(&zero_terms, SecpAffineWitness::identity()).expect("shared zero");

        eprintln!("receipt_secp_two_term_msm_gates={gates} proof_bytes={proof_bytes}");
        assert_eq!(gates, 35_577);
        assert_eq!(proof_bytes, 1_481);
    }

    #[test]
    fn shared_msm_rejects_wrong_output_and_bad_shape() {
        let terms = [
            (generator(), SecpScalarWitness::from_u64(1)),
            (generator(), SecpScalarWitness::from_u64(2)),
        ];
        assert!(prove_msm_relation(&terms, twice_generator()).is_err());
        assert!(build_secp_msm_relation(&[], SecpAffineWitness::identity()).is_err());
        let excessive = vec![(generator(), SecpScalarWitness::from_u64(0)); 65];
        assert!(build_secp_msm_relation(&excessive, SecpAffineWitness::identity()).is_err());
    }

    #[test]
    fn shared_msm_shape_is_secret_independent() {
        let first = [
            (generator(), SecpScalarWitness::from_u64(1)),
            (generator(), SecpScalarWitness::from_u64(2)),
        ];
        let second = [
            (generator(), SecpScalarWitness::from_u64(0)),
            (twice_generator(), SecpScalarWitness::from_u64(0)),
        ];
        let (first_circuit, _) =
            build_secp_msm_relation(&first, three_times_generator()).expect("first circuit");
        let (second_circuit, _) = build_secp_msm_relation(&second, SecpAffineWitness::identity())
            .expect("second circuit");
        assert_eq!(first_circuit, second_circuit);
    }
}
