//! Arithmetic foundations for the purpose-specific parent receipt relation.
//!
//! This module only constructs authenticated R1CS circuit and assignment
//! encodings. It does not claim that a construction receipt is accepted. The
//! receipt verifier must still install every V3 transcript, reduction, and
//! accumulator constraint before exposing an acceptance API.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::opening_base::{constrain_transcript_opening_base, ACCUMULATION_OPENING_BASE_ROLE};
use crate::relation_builder::{Builder, Expression};
use crate::secp_scalar::{
    add_scalars, allocate_canonical_scalar, constant_scalar, constrain_scalar_equal,
    embedded_integer, invert_scalar, multiply_scalars, nonzero_scalar_from_sha256,
    subtract_scalars, SecpScalarVar, SecpScalarWitness,
};
use crate::sha256_builder::{Bit, Byte};
use crate::sha256_transcript::BuilderTranscript;
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

/// One compact public coefficient term in a candidate pending claim.
///
/// It represents `scale * X^offset * product(1 + factor[j] *
/// X^(2^j))`. The candidate step relation fixes the term shape in its
/// regenerated circuit and treats only the canonical scalar values as
/// private witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePolynomialTermWitness {
    /// Canonical term scale modulo the secp256k1 group order.
    pub scale: SecpScalarWitness,
    /// Public monomial offset fixed by the claim shape.
    pub offset: usize,
    /// Canonical compact tensor factors.
    pub factors: Vec<SecpScalarWitness>,
}

/// One candidate accumulation input claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePendingClaimWitness {
    /// Exact native `PointBytes` claim point and its y opening.
    pub point: SecpEncodedPointWitness,
    /// One to three compact public coefficient terms.
    pub polynomial: Vec<CandidatePolynomialTermWitness>,
}

/// The logarithmic public IPA fields for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateStepProofWitness {
    /// Ordered left round points.
    pub left: Vec<SecpEncodedPointWitness>,
    /// Ordered right round points.
    pub right: Vec<SecpEncodedPointWitness>,
    /// Canonical terminal coefficient scalar.
    pub terminal_scalar: SecpScalarWitness,
    /// Exact folded-generator point returned as the next obligation.
    pub folded_generator: SecpEncodedPointWitness,
}

/// Public next-claim constants for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRootClaim {
    /// Exact folded-generator point and its deterministic affine y opening.
    pub point: SecpEncodedPointWitness,
    /// Compact polynomial scale.
    pub scale: SecpScalarWitness,
    /// Compact polynomial factors in low-bit-first order.
    pub factors: Vec<SecpScalarWitness>,
}

impl SecpEncodedPointWitness {
    /// Returns the unique all-zero accumulation identity encoding.
    pub const fn identity() -> Self {
        Self {
            encoded: [0; 33],
            y: [0; 32],
        }
    }

    /// Parses one canonical native accumulation-point encoding.
    ///
    /// The public encoding determines the unique affine y opening. Callers
    /// must never accept a separate prover-supplied y coordinate for the same
    /// point.
    pub(crate) fn parse(encoded: [u8; 33]) -> Result<Self, ReceiptCycleError> {
        if encoded == [0; 33] {
            return Ok(Self::identity());
        }
        if encoded[0] != 2 && encoded[0] != 3 {
            return Err(ReceiptCycleError::Malformed("encoded secp point prefix"));
        }

        let mut x_bytes: [u8; 32] = encoded[1..].try_into().expect("fixed encoded secp x slice");
        x_bytes.reverse();
        let x = Secq256k1Cycle::scalar_from_canonical(&x_bytes)
            .ok_or(ReceiptCycleError::Malformed("noncanonical encoded secp x"))?;
        let rhs = x.square() * x + Scalar::from(7);
        let mut y = Option::<Scalar>::from(rhs.sqrt()).ok_or(ReceiptCycleError::Malformed(
            "encoded secp point not on curve",
        ))?;
        let expected_parity = encoded[0] & 1;
        if Secq256k1Cycle::scalar_to_canonical(&y)[0] & 1 != expected_parity {
            y = -y;
        }
        let y = Secq256k1Cycle::scalar_to_canonical(&y);
        if y[0] & 1 != expected_parity {
            return Err(ReceiptCycleError::Malformed("encoded secp point parity"));
        }

        let witness = Self { encoded, y };
        encoded_point_value(witness)?;
        Ok(witness)
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
pub(crate) struct SecpPoint {
    pub(crate) x: Expression,
    pub(crate) y: Expression,
    pub(crate) identity: Expression,
    pub(crate) witness: PointValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PointValue {
    pub(crate) x: Scalar,
    pub(crate) y: Scalar,
    pub(crate) identity: bool,
}

pub(crate) fn standard_generator() -> PointValue {
    const X: [u8; 32] = [
        0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b,
        0x02, 0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66,
        0xbe, 0x79,
    ];
    const Y: [u8; 32] = [
        0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17,
        0xfd, 0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda,
        0x3a, 0x48,
    ];
    PointValue {
        x: Secq256k1Cycle::scalar_from_canonical(&X).expect("generator x is canonical"),
        y: Secq256k1Cycle::scalar_from_canonical(&Y).expect("generator y is canonical"),
        identity: false,
    }
}

#[derive(Clone, Copy)]
struct EncodedPointValue {
    point: PointValue,
    prefix: u8,
    odd: bool,
}

#[derive(Clone)]
pub(crate) struct EncodedSecpPoint {
    pub(crate) point: SecpPoint,
    pub(crate) prefix: Expression,
    pub(crate) odd: Expression,
}

const SECP_FIELD_MODULUS_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

const SECP_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const CANDIDATE_STEP_DOMAIN: &[u8] = b"Purify/BPPP/CandidateAccumStep/v1";
const MAX_CANDIDATE_CLAIMS: usize = 1024;
const MAX_CANDIDATE_ROUNDS: usize = 24;

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

/// Validates an exact encoded point constant and returns its affine value.
pub(crate) fn encoded_point_value(
    witness: SecpEncodedPointWitness,
) -> Result<PointValue, ReceiptCycleError> {
    let encoded = parse_encoded_point(witness)?;
    validate_constant_point(encoded.point)?;
    let expected_prefix = if encoded.point.identity {
        0
    } else {
        2 + (Secq256k1Cycle::scalar_to_canonical(&encoded.point.y)[0] & 1)
    };
    if encoded.prefix != expected_prefix {
        return Err(ReceiptCycleError::Malformed(
            "noncanonical encoded point constant",
        ));
    }
    Ok(encoded.point)
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

pub(crate) fn canonical_field_bits(builder: &mut Builder, value: &Expression) -> Vec<Expression> {
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

pub(crate) fn allocate_encoded_point(
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

pub(crate) fn add_point_values(left: PointValue, right: PointValue) -> PointValue {
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

pub(crate) fn add_points(builder: &mut Builder, left: &SecpPoint, right: &SecpPoint) -> SecpPoint {
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

fn constant_identity_point() -> SecpPoint {
    constant_point(PointValue {
        x: Scalar::ZERO,
        y: Scalar::ZERO,
        identity: true,
    })
}

pub(crate) fn scale_point(
    builder: &mut Builder,
    point: &SecpPoint,
    scalar: &SecpScalarVar,
) -> SecpPoint {
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

#[cfg(test)]
fn msm_points_bitwise(
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

fn secp_order() -> BigUint {
    BigUint::from_bytes_be(&SECP_ORDER_BE)
}

fn scalar_witness(value: &BigUint) -> Result<SecpScalarWitness, ReceiptCycleError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(ReceiptCycleError::Malformed("candidate scalar width"));
    }
    let mut encoded = [0; 32];
    encoded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(SecpScalarWitness::from_bytes_be(encoded))
}

fn scalar_expression_value(value: &BigUint) -> Result<Scalar, ReceiptCycleError> {
    let bytes = value.to_bytes_le();
    if bytes.len() > 32 {
        return Err(ReceiptCycleError::Malformed("candidate scalar width"));
    }
    let mut encoded = [0; 32];
    encoded[..bytes.len()].copy_from_slice(&bytes);
    Secq256k1Cycle::scalar_from_canonical(&encoded)
        .ok_or(ReceiptCycleError::Malformed("candidate scalar embedding"))
}

pub(crate) fn derived_add(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let value = (left.integer() + right.integer()) % secp_order();
    add_scalars(builder, left, right, scalar_witness(&value)?)
}

pub(crate) fn derived_subtract(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let order = secp_order();
    let value = (left.integer() + &order - right.integer()) % &order;
    subtract_scalars(builder, left, right, scalar_witness(&value)?)
}

pub(crate) fn derived_multiply(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let value = (left.integer() * right.integer()) % secp_order();
    multiply_scalars(builder, left, right, scalar_witness(&value)?)
}

pub(crate) fn derived_inverse(
    builder: &mut Builder,
    value: &SecpScalarVar,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let order = secp_order();
    let inverse = if value.integer().is_zero() {
        BigUint::zero()
    } else {
        value
            .integer()
            .modpow(&(&order - BigUint::from(2u64)), &order)
    };
    invert_scalar(builder, value, scalar_witness(&inverse)?)
}

fn constrained_byte(bits: &[Expression]) -> Byte {
    assert_eq!(bits.len(), 8);
    Byte::from_constrained_bits(std::array::from_fn(|index| {
        let expression = bits[index].clone();
        Bit::from_constrained_expression(expression.clone(), expression.value() == Scalar::ONE)
    }))
}

fn constrained_bytes_be(bits_le: &[Expression]) -> [Byte; 32] {
    assert_eq!(bits_le.len(), 256);
    std::array::from_fn(|byte| {
        let offset = (31 - byte) * 8;
        constrained_byte(&bits_le[offset..offset + 8])
    })
}

pub(crate) fn constrained_field_bytes(builder: &mut Builder, value: &Expression) -> [Byte; 32] {
    constrained_bytes_be(&canonical_field_bits(builder, value))
}

fn constrained_scalar_bytes(value: &SecpScalarVar) -> [Byte; 32] {
    constrained_bytes_be(&value.bits)
}

fn constrained_point_prefix(point: &EncodedSecpPoint) -> Byte {
    let zero = Expression::constant(Scalar::ZERO);
    let active = Expression::constant(Scalar::ONE).sub(&point.point.identity);
    constrained_byte(&[
        point.odd.clone(),
        active,
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero,
    ])
}

pub(crate) fn append_constant_bytes(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    bytes: &[u8],
) -> Result<(), ReceiptCycleError> {
    let _ = builder;
    transcript.append_bytes(
        &bytes
            .iter()
            .copied()
            .map(Byte::constant)
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn append_scalar(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    value: &SecpScalarVar,
) {
    let _ = builder;
    transcript.append_scalar(&constrained_scalar_bytes(value));
}

pub(crate) fn append_encoded_point(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    point: &EncodedSecpPoint,
) {
    let prefix = constrained_point_prefix(point);
    let x = constrained_field_bytes(builder, &point.point.x);
    transcript.append_point(&prefix, &x);
}

pub(crate) fn encode_computed_point(builder: &mut Builder, point: &SecpPoint) -> EncodedSecpPoint {
    let y_bits = canonical_field_bits(builder, &point.y);
    let active = Expression::constant(Scalar::ONE).sub(&point.identity);
    let finite_prefix = Expression::constant(Scalar::from(2)).add(&y_bits[0]);
    let prefix = builder.multiply(&active, &finite_prefix);
    EncodedSecpPoint {
        point: point.clone(),
        prefix,
        odd: y_bits[0].clone(),
    }
}

pub(crate) fn append_computed_point(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    point: &SecpPoint,
) -> EncodedSecpPoint {
    let encoded = encode_computed_point(builder, point);
    append_encoded_point(transcript, builder, &encoded);
    encoded
}

pub(crate) fn append_challenge(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    round: u64,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let challenge = transcript.challenge(builder, round)?;
    Ok(nonzero_scalar_from_sha256(builder, challenge.scalar()))
}

pub(crate) fn constrain_scalar_constant(
    builder: &mut Builder,
    actual: &SecpScalarVar,
    expected: SecpScalarWitness,
) -> Result<(), ReceiptCycleError> {
    let expected = allocate_canonical_scalar(builder, expected)?;
    let constant = Expression::constant(scalar_expression_value(expected.integer())?);
    builder.constrain_equal(&embedded_integer(&expected), &constant);
    constrain_scalar_equal(builder, actual, &expected);
    Ok(())
}

fn allocate_encoded_point_constant(
    builder: &mut Builder,
    expected: SecpEncodedPointWitness,
) -> Result<EncodedSecpPoint, ReceiptCycleError> {
    let expected = allocate_encoded_point(builder, expected)?;
    let constant = |value| Expression::constant(value);
    builder.constrain_equal(&expected.point.x, &constant(expected.point.witness.x));
    builder.constrain_equal(&expected.point.y, &constant(expected.point.witness.y));
    let identity = if expected.point.witness.identity {
        Scalar::ONE
    } else {
        Scalar::ZERO
    };
    builder.constrain_equal(&expected.point.identity, &constant(identity));
    builder.constrain_equal(&expected.prefix, &constant(expected.prefix.value()));
    Ok(expected)
}

pub(crate) fn constrain_encoded_point_constant(
    builder: &mut Builder,
    actual: &EncodedSecpPoint,
    expected: SecpEncodedPointWitness,
) -> Result<(), ReceiptCycleError> {
    let expected = allocate_encoded_point_constant(builder, expected)?;
    builder.constrain_equal(&actual.point.x, &expected.point.x);
    builder.constrain_equal(&actual.point.y, &expected.point.y);
    builder.constrain_equal(&actual.point.identity, &expected.point.identity);
    builder.constrain_equal(&actual.prefix, &expected.prefix);
    Ok(())
}

#[derive(Clone)]
pub(crate) struct ConstrainedPolynomialTerm {
    pub(crate) scale: SecpScalarVar,
    pub(crate) offset: usize,
    pub(crate) factors: Vec<SecpScalarVar>,
}

#[derive(Clone)]
pub(crate) struct ConstrainedPendingClaim {
    pub(crate) point: EncodedSecpPoint,
    pub(crate) polynomial: Vec<ConstrainedPolynomialTerm>,
}

pub(crate) struct CandidateDerivedRoot {
    pub(crate) point: EncodedSecpPoint,
    pub(crate) scale: SecpScalarVar,
    pub(crate) factors: Vec<SecpScalarVar>,
    #[cfg(test)]
    equation_residual: PointValue,
}

fn candidate_step_shape(
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
    root: Option<&CandidateRootClaim>,
) -> Result<(usize, usize), ReceiptCycleError> {
    if claims.is_empty() || claims.len() > MAX_CANDIDATE_CLAIMS {
        return Err(ReceiptCycleError::Malformed("candidate claim count"));
    }
    let rounds = proof.left.len();
    if rounds == 0
        || rounds > MAX_CANDIDATE_ROUNDS
        || proof.right.len() != rounds
        || root.is_some_and(|root| root.factors.len() != rounds)
    {
        return Err(ReceiptCycleError::Malformed("candidate step rounds"));
    }
    let dimension = 1usize
        .checked_shl(rounds as u32)
        .ok_or(ReceiptCycleError::Malformed("candidate step dimension"))?;
    for claim in claims {
        if claim.polynomial.is_empty() || claim.polynomial.len() > 3 {
            return Err(ReceiptCycleError::Malformed("candidate polynomial terms"));
        }
        for term in &claim.polynomial {
            if term.factors.len() > rounds {
                return Err(ReceiptCycleError::Malformed("candidate polynomial factors"));
            }
            let width = 1usize
                .checked_shl(term.factors.len() as u32)
                .ok_or(ReceiptCycleError::Malformed("candidate polynomial width"))?;
            if term.offset > dimension.saturating_sub(width) {
                return Err(ReceiptCycleError::Malformed("candidate polynomial degree"));
            }
        }
    }
    Ok((rounds, dimension))
}

fn allocate_candidate_claims(
    builder: &mut Builder,
    claims: &[CandidatePendingClaimWitness],
) -> Result<Vec<ConstrainedPendingClaim>, ReceiptCycleError> {
    let mut allocated = Vec::with_capacity(claims.len());
    for claim in claims {
        let point = allocate_encoded_point(builder, claim.point)?;
        let mut polynomial = Vec::with_capacity(claim.polynomial.len());
        for term in &claim.polynomial {
            let scale = allocate_canonical_scalar(builder, term.scale)?;
            let mut factors = Vec::with_capacity(term.factors.len());
            for &factor in &term.factors {
                let factor = allocate_canonical_scalar(builder, factor)?;
                factors.push(factor);
            }
            polynomial.push(ConstrainedPolynomialTerm {
                scale,
                offset: term.offset,
                factors,
            });
        }
        allocated.push(ConstrainedPendingClaim { point, polynomial });
    }
    Ok(allocated)
}

pub(crate) fn append_constrained_polynomial(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    polynomial: &[ConstrainedPolynomialTerm],
) {
    transcript.append_u64(polynomial.len() as u64);
    for term in polynomial {
        append_scalar(transcript, builder, &term.scale);
        transcript.append_u64(term.offset as u64);
        transcript.append_u64(term.factors.len() as u64);
        for factor in &term.factors {
            append_scalar(transcript, builder, factor);
        }
    }
}

fn append_constrained_claims(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    claims: &[ConstrainedPendingClaim],
) {
    transcript.append_u64(claims.len() as u64);
    for claim in claims {
        append_encoded_point(transcript, builder, &claim.point);
        append_constrained_polynomial(transcript, builder, &claim.polynomial);
    }
}

fn candidate_power_ladder(
    builder: &mut Builder,
    x: &SecpScalarVar,
    rounds: usize,
) -> Result<Vec<SecpScalarVar>, ReceiptCycleError> {
    if rounds == 0 {
        return Err(ReceiptCycleError::Malformed("candidate power ladder"));
    }
    let mut powers = Vec::with_capacity(rounds);
    powers.push(x.clone());
    for _ in 1..rounds {
        let previous = powers.last().expect("nonempty power ladder");
        let next = derived_multiply(builder, previous, previous)?;
        powers.push(next);
    }
    Ok(powers)
}

fn candidate_offset_power(
    builder: &mut Builder,
    powers: &[SecpScalarVar],
    offset: usize,
) -> Result<Option<SecpScalarVar>, ReceiptCycleError> {
    if offset == 0 {
        return Ok(None);
    }
    if offset >> powers.len() != 0 {
        return Err(ReceiptCycleError::Malformed("candidate term offset"));
    }
    let mut selected = None;
    for (index, power) in powers.iter().enumerate() {
        if offset & (1usize << index) != 0 {
            selected = Some(match selected {
                None => power.clone(),
                Some(value) => derived_multiply(builder, &value, power)?,
            });
        }
    }
    Ok(selected)
}

fn evaluate_candidate_term(
    builder: &mut Builder,
    term: &ConstrainedPolynomialTerm,
    powers: &[SecpScalarVar],
) -> Result<SecpScalarVar, ReceiptCycleError> {
    if term.factors.len() > powers.len() {
        return Err(ReceiptCycleError::Malformed("candidate term factors"));
    }
    let mut value = match candidate_offset_power(builder, powers, term.offset)? {
        Some(offset) => derived_multiply(builder, &term.scale, &offset)?,
        None => term.scale.clone(),
    };
    for (factor, x_power) in term.factors.iter().zip(powers) {
        let product = derived_multiply(builder, factor, x_power)?;
        let one_plus_product = derived_add(builder, &constant_scalar(1), &product)?;
        value = derived_multiply(builder, &value, &one_plus_product)?;
    }
    Ok(value)
}

#[cfg(test)]
fn install_candidate_step(
    builder: &mut Builder,
    basis_digest: [u8; 32],
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
) -> Result<CandidateDerivedRoot, ReceiptCycleError> {
    install_candidate_step_for_role(
        builder,
        basis_digest,
        ACCUMULATION_OPENING_BASE_ROLE,
        claims,
        proof,
    )
}

fn install_candidate_step_for_role(
    builder: &mut Builder,
    basis_digest: [u8; 32],
    opening_base_role: u64,
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
) -> Result<CandidateDerivedRoot, ReceiptCycleError> {
    candidate_step_shape(claims, proof, None)?;
    let claims = allocate_candidate_claims(builder, claims)?;
    install_constrained_step_for_role(builder, basis_digest, opening_base_role, &claims, proof)
}

#[allow(dead_code)]
pub(crate) fn install_constrained_candidate_step(
    builder: &mut Builder,
    basis_digest: [u8; 32],
    claims: &[ConstrainedPendingClaim],
    proof: &CandidateStepProofWitness,
) -> Result<CandidateDerivedRoot, ReceiptCycleError> {
    install_constrained_step_for_role(
        builder,
        basis_digest,
        ACCUMULATION_OPENING_BASE_ROLE,
        claims,
        proof,
    )
}

fn install_constrained_step_for_role(
    builder: &mut Builder,
    basis_digest: [u8; 32],
    opening_base_role: u64,
    claims: &[ConstrainedPendingClaim],
    proof: &CandidateStepProofWitness,
) -> Result<CandidateDerivedRoot, ReceiptCycleError> {
    let rounds = proof.left.len();
    if claims.is_empty()
        || claims.len() > MAX_CANDIDATE_CLAIMS
        || rounds == 0
        || rounds > MAX_CANDIDATE_ROUNDS
        || proof.right.len() != rounds
    {
        return Err(ReceiptCycleError::Malformed("candidate step shape"));
    }
    let dimension = 1usize
        .checked_shl(rounds as u32)
        .ok_or(ReceiptCycleError::Malformed("candidate step dimension"))?;
    for claim in claims {
        if claim.polynomial.is_empty() || claim.polynomial.len() > 3 {
            return Err(ReceiptCycleError::Malformed("candidate polynomial terms"));
        }
        for term in &claim.polynomial {
            if term.factors.len() > rounds {
                return Err(ReceiptCycleError::Malformed("candidate polynomial factors"));
            }
            let width = 1usize
                .checked_shl(term.factors.len() as u32)
                .ok_or(ReceiptCycleError::Malformed("candidate polynomial width"))?;
            if term.offset > dimension.saturating_sub(width) {
                return Err(ReceiptCycleError::Malformed("candidate polynomial degree"));
            }
        }
    }
    let mut transcript = BuilderTranscript::new();
    append_constant_bytes(&mut transcript, builder, CANDIDATE_STEP_DOMAIN)?;
    append_constant_bytes(&mut transcript, builder, &basis_digest)?;
    transcript.append_u64(rounds as u64);
    append_constrained_claims(&mut transcript, builder, claims);

    let beta = append_challenge(&mut transcript, builder, 0)?;
    let mut claim_weights = Vec::with_capacity(claims.len());
    claim_weights.push(constant_scalar(1));
    for _ in 1..claims.len() {
        let next = derived_multiply(
            builder,
            claim_weights.last().expect("nonempty claim weights"),
            &beta,
        )?;
        claim_weights.push(next);
    }
    let commitment_points = claims
        .iter()
        .map(|claim| claim.point.point.clone())
        .collect::<Vec<_>>();
    let commitment = msm_points(builder, &commitment_points, &claim_weights)?;
    append_computed_point(&mut transcript, builder, &commitment);

    let x = append_challenge(&mut transcript, builder, 1)?;
    let x_powers = candidate_power_ladder(builder, &x, rounds)?;
    let mut y = None;
    for (index, (claim, weight)) in claims.iter().zip(&claim_weights).enumerate() {
        let mut terms = claim.polynomial.iter();
        let mut evaluation = evaluate_candidate_term(
            builder,
            terms.next().expect("nonempty candidate polynomial"),
            &x_powers,
        )?;
        for term in terms {
            let term = evaluate_candidate_term(builder, term, &x_powers)?;
            evaluation = derived_add(builder, &evaluation, &term)?;
        }
        let weighted = if index == 0 {
            evaluation
        } else {
            derived_multiply(builder, weight, &evaluation)?
        };
        y = Some(match y {
            None => weighted,
            Some(value) => derived_add(builder, &value, &weighted)?,
        });
    }
    let y = y.expect("nonempty candidate claims");
    append_scalar(&mut transcript, builder, &y);

    let opening_base =
        constrain_transcript_opening_base(builder, &transcript, basis_digest, opening_base_role)?;
    append_computed_point(&mut transcript, builder, &opening_base);

    let mut equation_points = vec![commitment];
    let mut equation_scalars = vec![constant_scalar(1)];
    let mut folded_scale = constant_scalar(1);
    let mut folded_factors = vec![constant_scalar(0); rounds];
    for round in 0..rounds {
        let left = allocate_encoded_point(builder, proof.left[round])?;
        let right = allocate_encoded_point(builder, proof.right[round])?;
        append_encoded_point(&mut transcript, builder, &left);
        append_encoded_point(&mut transcript, builder, &right);
        let challenge = append_challenge(&mut transcript, builder, 2 + round as u64)?;
        let inverse = derived_inverse(builder, &challenge)?;
        let squared = derived_multiply(builder, &challenge, &challenge)?;
        let inverse_squared = derived_multiply(builder, &inverse, &inverse)?;
        folded_scale = derived_multiply(builder, &folded_scale, &inverse)?;
        folded_factors[rounds - 1 - round] = squared.clone();
        equation_points.push(left.point);
        equation_scalars.push(squared);
        equation_points.push(right.point);
        equation_scalars.push(inverse_squared);
    }

    let terminal = allocate_canonical_scalar(builder, proof.terminal_scalar)?;
    let mut b_final = folded_scale.clone();
    for (factor, x_power) in folded_factors.iter().zip(&x_powers) {
        let product = derived_multiply(builder, factor, x_power)?;
        let one_plus_product = derived_add(builder, &constant_scalar(1), &product)?;
        b_final = derived_multiply(builder, &b_final, &one_plus_product)?;
    }
    let terminal_evaluation = derived_multiply(builder, &terminal, &b_final)?;
    let opening_scalar = derived_subtract(builder, &y, &terminal_evaluation)?;
    let negative_terminal = derived_subtract(builder, &constant_scalar(0), &terminal)?;
    equation_points.push(opening_base);
    equation_scalars.push(opening_scalar);

    let folded_generator = allocate_encoded_point(builder, proof.folded_generator)?;
    equation_points.push(folded_generator.point.clone());
    equation_scalars.push(negative_terminal);
    let residual = msm_points(builder, &equation_points, &equation_scalars)?;
    #[cfg(test)]
    let equation_residual = residual.witness;
    builder.constrain_zero(residual.x);
    builder.constrain_zero(residual.y);
    builder.constrain_equal(&residual.identity, &Expression::constant(Scalar::ONE));

    Ok(CandidateDerivedRoot {
        point: folded_generator,
        scale: folded_scale,
        factors: folded_factors,
        #[cfg(test)]
        equation_residual,
    })
}

fn precompute_window(
    builder: &mut Builder,
    point: &SecpPoint,
    window_bits: usize,
) -> Vec<SecpPoint> {
    let table_size = 1usize << window_bits;
    let mut table = Vec::with_capacity(table_size);
    table.push(constant_identity_point());
    table.push(point.clone());
    while table.len() != table_size {
        let next = add_points(builder, table.last().expect("nonempty table"), point);
        // The cofactor-one group has no nontrivial order below this table.
        // Pinning the identity class lets the mux derive its identity bit
        // without selecting every table identity through extra gates.
        builder.constrain_equal(&next.identity, &point.identity);
        table.push(next);
    }
    table
}

fn select_window_expression(
    builder: &mut Builder,
    bits: &[Expression],
    values: impl IntoIterator<Item = Expression>,
) -> Expression {
    let mut level = values.into_iter().collect::<Vec<_>>();
    for bit in bits {
        let (pairs, remainder) = level.as_chunks::<2>();
        assert!(remainder.is_empty());
        let next = pairs
            .iter()
            .map(|pair| {
                let difference = pair[1].clone().sub(&pair[0]);
                pair[0].clone().add(&builder.multiply(bit, &difference))
            })
            .collect();
        level = next;
    }
    assert_eq!(level.len(), 1);
    level.pop().expect("one selected expression")
}

fn select_window_point(
    builder: &mut Builder,
    bits: &[Expression],
    table: &[SecpPoint],
    source_identity: &Expression,
) -> SecpPoint {
    assert_eq!(table.len(), 1usize << bits.len());
    let x = select_window_expression(builder, bits, table.iter().map(|point| point.x.clone()));
    let y = select_window_expression(builder, bits, table.iter().map(|point| point.y.clone()));
    let one = Expression::constant(Scalar::ONE);
    let mut digit_is_zero = one.clone().sub(&bits[0]);
    for bit in &bits[1..] {
        digit_is_zero = builder.multiply(&digit_is_zero, &one.clone().sub(bit));
    }
    let both = builder.multiply(source_identity, &digit_is_zero);
    let identity = source_identity.clone().add(&digit_is_zero).sub(&both);
    let digit = bits.iter().enumerate().fold(0usize, |value, (index, bit)| {
        let selected = if bit.value() == Scalar::ONE { 1 } else { 0 };
        value | (selected << index)
    });
    SecpPoint {
        x,
        y,
        identity,
        witness: table[digit].witness,
    }
}

fn msm_points_windowed<const WINDOW_BITS: usize>(
    builder: &mut Builder,
    points: &[SecpPoint],
    scalars: &[SecpScalarVar],
) -> Result<SecpPoint, ReceiptCycleError> {
    if WINDOW_BITS == 0 || WINDOW_BITS > 4 {
        return Err(ReceiptCycleError::Malformed("secp MSM window width"));
    }
    if points.is_empty() || points.len() != scalars.len() {
        return Err(ReceiptCycleError::Malformed("secp MSM shape"));
    }
    let bit_count = scalars[0].bits.len();
    if bit_count == 0 || scalars.iter().any(|scalar| scalar.bits.len() != bit_count) {
        return Err(ReceiptCycleError::Malformed("secp MSM scalar width"));
    }

    let tables = points
        .iter()
        .map(|point| precompute_window(builder, point, WINDOW_BITS))
        .collect::<Vec<_>>();
    let window_count = bit_count.div_ceil(WINDOW_BITS);
    let mut accumulator = constant_identity_point();
    for window in (0..window_count).rev() {
        if window + 1 != window_count {
            for _ in 0..WINDOW_BITS {
                accumulator = add_points(builder, &accumulator, &accumulator);
            }
        }
        let offset = window * WINDOW_BITS;
        for ((table, point), scalar) in tables.iter().zip(points).zip(scalars) {
            let active_bits = WINDOW_BITS.min(bit_count - offset);
            let bits = (0..active_bits)
                .map(|index| scalar.bits[offset + index].clone())
                .collect::<Vec<_>>();
            let selected = select_window_point(
                builder,
                &bits,
                &table[..1usize << active_bits],
                &point.identity,
            );
            accumulator = add_points(builder, &accumulator, &selected);
        }
    }
    Ok(accumulator)
}

pub(crate) fn msm_points(
    builder: &mut Builder,
    points: &[SecpPoint],
    scalars: &[SecpScalarVar],
) -> Result<SecpPoint, ReceiptCycleError> {
    msm_points_windowed::<3>(builder, points, scalars)
}

fn validate_constant_point(point: PointValue) -> Result<(), ReceiptCycleError> {
    if point.identity {
        if point.x != Scalar::ZERO || point.y != Scalar::ZERO {
            return Err(ReceiptCycleError::Malformed(
                "noncanonical constant identity",
            ));
        }
    } else if point.y.square() != point.x.square() * point.x + Scalar::from(7) {
        return Err(ReceiptCycleError::Malformed("constant point off curve"));
    }
    Ok(())
}

fn precompute_constant_window(
    point: PointValue,
    window_bits: usize,
) -> Result<Vec<SecpPoint>, ReceiptCycleError> {
    let table_size = 1usize << window_bits;
    let mut values = Vec::with_capacity(table_size);
    values.push(PointValue {
        x: Scalar::ZERO,
        y: Scalar::ZERO,
        identity: true,
    });
    values.push(point);
    while values.len() != table_size {
        values.push(add_point_values(
            *values.last().expect("nonempty constant table"),
            point,
        ));
    }
    for &multiple in &values {
        validate_constant_point(multiple)?;
    }
    if values
        .iter()
        .skip(1)
        .any(|multiple| multiple.identity != point.identity)
    {
        return Err(ReceiptCycleError::Malformed(
            "constant point has a small order",
        ));
    }
    Ok(values.into_iter().map(constant_point).collect())
}

fn scale_constant_point_windowed<const WINDOW_BITS: usize>(
    builder: &mut Builder,
    point: PointValue,
    scalar: &SecpScalarVar,
) -> Result<SecpPoint, ReceiptCycleError> {
    if WINDOW_BITS == 0 || WINDOW_BITS > 4 || scalar.bits.is_empty() {
        return Err(ReceiptCycleError::Malformed(
            "constant scalar multiplication window",
        ));
    }
    validate_constant_point(point)?;
    let window_count = scalar.bits.len().div_ceil(WINDOW_BITS);
    let mut tables = Vec::with_capacity(window_count);
    let mut shifted = point;
    for window in 0..window_count {
        tables.push(precompute_constant_window(shifted, WINDOW_BITS)?);
        if window + 1 != window_count {
            for _ in 0..WINDOW_BITS {
                shifted = add_point_values(shifted, shifted);
            }
        }
    }

    let mut accumulator = constant_identity_point();
    for (window, table) in tables.iter().enumerate() {
        let offset = window * WINDOW_BITS;
        let active_bits = WINDOW_BITS.min(scalar.bits.len() - offset);
        let bits = &scalar.bits[offset..offset + active_bits];
        let selected = select_window_point(
            builder,
            bits,
            &table[..1usize << active_bits],
            &table[1].identity,
        );
        accumulator = add_points(builder, &accumulator, &selected);
    }
    Ok(accumulator)
}

/// Multiply a verifier-derived constant point by a canonical secp scalar.
pub(crate) fn scale_constant_point(
    builder: &mut Builder,
    point: PointValue,
    scalar: &SecpScalarVar,
) -> Result<SecpPoint, ReceiptCycleError> {
    scale_constant_point_windowed::<4>(builder, point, scalar)
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

/// Builds `scalar * point = expected` for a verifier-derived constant point.
///
/// The point coordinates are embedded in the regenerated circuit. Four-bit
/// pre-shifted tables therefore require no constrained table construction or
/// inter-window doublings. The scalar remains a canonical private witness.
pub fn build_secp_fixed_base_scalar_multiplication_relation(
    point: SecpAffineWitness,
    scalar: SecpScalarWitness,
    expected: SecpAffineWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let point = parse_point(point)?;
    let scalar = allocate_canonical_scalar(&mut builder, scalar)?;
    let expected = allocate_point(&mut builder, parse_point(expected)?);
    let product = scale_constant_point(&mut builder, point, &scalar)?;
    builder.constrain_equal(&product.x, &expected.x);
    builder.constrain_equal(&product.y, &expected.y);
    builder.constrain_equal(&product.identity, &expected.identity);
    builder.finish()
}

/// Builds one shared variable-base secp256k1 MSM relation.
///
/// The public term count fixes the circuit shape. All scalars are canonical
/// modulo the secp256k1 group order. One MSB-first windowed accumulator shares
/// every inter-window doubling across all terms.
fn build_secp_msm_relation_with(
    terms: &[(SecpAffineWitness, SecpScalarWitness)],
    expected: SecpAffineWitness,
    msm: impl FnOnce(
        &mut Builder,
        &[SecpPoint],
        &[SecpScalarVar],
    ) -> Result<SecpPoint, ReceiptCycleError>,
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
    let result = msm(&mut builder, &points, &scalars)?;
    builder.constrain_equal(&result.x, &expected.x);
    builder.constrain_equal(&result.y, &expected.y);
    builder.constrain_equal(&result.identity, &expected.identity);
    builder.finish()
}

/// Builds one complete candidate accumulation-step transition relation.
///
/// The relation binds the fixed basis digest, ordered compact claims, typed
/// SHA-256 batching and evaluation challenges, every IPA round, the short
/// secp256k1 MSM equation, and the exact next root claim. The opening base is
/// derived inside the relation after the claim and evaluation are fixed. The
/// root remains a verifier-supplied constant in the regenerated circuit.
///
/// This remains a migration primitive, not receipt acceptance. The native
/// accumulation suite must use this exact transcript before the relation can
/// participate in receipt verification.
pub fn build_candidate_accumulation_step_relation(
    basis_digest: [u8; 32],
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
    root: &CandidateRootClaim,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    build_candidate_accumulation_step_relation_for_role(
        basis_digest,
        ACCUMULATION_OPENING_BASE_ROLE,
        claims,
        proof,
        root,
    )
}

fn build_candidate_accumulation_step_relation_for_role(
    basis_digest: [u8; 32],
    opening_base_role: u64,
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
    root: &CandidateRootClaim,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    candidate_step_shape(claims, proof, Some(root))?;
    let mut builder = Builder::default();
    let derived = install_candidate_step_for_role(
        &mut builder,
        basis_digest,
        opening_base_role,
        claims,
        proof,
    )?;
    constrain_encoded_point_constant(&mut builder, &derived.point, root.point)?;
    constrain_scalar_constant(&mut builder, &derived.scale, root.scale)?;
    for (actual, &expected) in derived.factors.iter().zip(&root.factors) {
        constrain_scalar_constant(&mut builder, actual, expected)?;
    }
    builder.finish()
}

#[cfg(test)]
fn derive_candidate_root_witness(
    basis_digest: [u8; 32],
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
) -> Result<CandidateRootClaim, ReceiptCycleError> {
    let mut builder = Builder::default();
    let derived = install_candidate_step(&mut builder, basis_digest, claims, proof)?;
    Ok(CandidateRootClaim {
        point: proof.folded_generator,
        scale: scalar_witness(derived.scale.integer())?,
        factors: derived
            .factors
            .iter()
            .map(|factor| scalar_witness(factor.integer()))
            .collect::<Result<_, _>>()?,
    })
}

/// Builds one shared three-bit-window variable-base secp256k1 MSM relation.
pub fn build_secp_msm_relation(
    terms: &[(SecpAffineWitness, SecpScalarWitness)],
    expected: SecpAffineWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    build_secp_msm_relation_with(terms, expected, msm_points)
}

#[cfg(test)]
pub(crate) fn derive_candidate_folded_generator(
    basis_digest: [u8; 32],
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    let mut builder = Builder::default();
    let derived = install_candidate_step(&mut builder, basis_digest, claims, proof)?;
    let point = derived.equation_residual;
    if point.identity {
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = if Secq256k1Cycle::scalar_to_canonical(&point.y)[0] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    let mut x = Secq256k1Cycle::scalar_to_canonical(&point.x);
    x.reverse();
    encoded[1..].copy_from_slice(&x);
    Ok(SecpEncodedPointWitness {
        encoded,
        y: Secq256k1Cycle::scalar_to_canonical(&point.y),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proof_wire_len, prove, verify, Assignment, Circuit, WireKind};

    fn relation_satisfied(circuit: &[u8], assignment: &[u8]) -> bool {
        let circuit = Circuit::parse(circuit).expect("test circuit");
        let assignment = Assignment::parse(assignment).expect("test assignment");
        circuit.constraints.iter().all(|constraint| {
            constraint.iter().fold(Scalar::ZERO, |sum, term| {
                let value = match term.kind {
                    WireKind::One => Scalar::ONE,
                    WireKind::Left => assignment.gates[term.index].0,
                    WireKind::Right => assignment.gates[term.index].1,
                    WireKind::Output => {
                        assignment.gates[term.index].0 * assignment.gates[term.index].1
                    }
                };
                sum + term.coefficient * value
            }) == Scalar::ZERO
        })
    }

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

    fn order_minus_one() -> SecpScalarWitness {
        SecpScalarWitness::from_bytes_be([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ])
    }

    fn negate(point: SecpAffineWitness) -> SecpAffineWitness {
        let value = parse_point(point).expect("point");
        SecpAffineWitness {
            x: point.x,
            y: Secq256k1Cycle::scalar_to_canonical(&-value.y),
            identity: false,
        }
    }

    fn maximum_scalar() -> SecpScalarWitness {
        SecpScalarWitness::from_bytes_be([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ])
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

    fn prove_fixed_scale_relation(
        point: SecpAffineWitness,
        scalar: SecpScalarWitness,
        expected: SecpAffineWitness,
    ) -> Result<(Vec<u8>, usize, usize), ReceiptCycleError> {
        let (circuit, assignment) =
            build_secp_fixed_base_scalar_multiplication_relation(point, scalar, expected)?;
        let statement = b"fixed-base secp scalar multiplication foundation";
        let proof = prove(&circuit, &assignment, statement, [0x84; 32])?;
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

    fn candidate_step_fixture() -> (
        [u8; 32],
        Vec<CandidatePendingClaimWitness>,
        CandidateStepProofWitness,
        CandidateRootClaim,
    ) {
        let basis_digest = [0x42; 32];
        let generator = encoded(generator(), 0x02);
        let claims = vec![CandidatePendingClaimWitness {
            point: generator,
            polynomial: vec![CandidatePolynomialTermWitness {
                scale: order_minus_one(),
                offset: 0,
                factors: vec![],
            }],
        }];
        let mut proof = CandidateStepProofWitness {
            left: vec![SecpEncodedPointWitness::identity()],
            right: vec![SecpEncodedPointWitness::identity()],
            terminal_scalar: SecpScalarWitness::from_u64(1),
            folded_generator: SecpEncodedPointWitness::identity(),
        };
        proof.folded_generator = derive_candidate_folded_generator(basis_digest, &claims, &proof)
            .expect("candidate folded generator");
        let root = derive_candidate_root_witness(basis_digest, &claims, &proof)
            .expect("candidate root witness");
        (basis_digest, claims, proof, root)
    }

    fn zero_polynomial_term(offset: usize, factor_count: usize) -> CandidatePolynomialTermWitness {
        CandidatePolynomialTermWitness {
            scale: SecpScalarWitness::from_u64(0),
            offset,
            factors: vec![SecpScalarWitness::from_u64(0); factor_count],
        }
    }

    fn candidate_term_reference(
        term: &CandidatePolynomialTermWitness,
        x: SecpScalarWitness,
    ) -> SecpScalarWitness {
        let order = secp_order();
        let x = BigUint::from_bytes_be(&x.bytes);
        let mut value = BigUint::from_bytes_be(&term.scale.bytes)
            * x.modpow(&BigUint::from(term.offset), &order)
            % &order;
        for (index, factor) in term.factors.iter().enumerate() {
            let x_power = x.modpow(&BigUint::from(1usize << index), &order);
            let product = BigUint::from_bytes_be(&factor.bytes) * x_power % &order;
            value = value * (BigUint::from(1u64) + product) % &order;
        }
        scalar_witness(&value).expect("reference scalar")
    }

    fn build_candidate_term_evaluation(
        term: &CandidatePolynomialTermWitness,
        x: SecpScalarWitness,
        expected: SecpScalarWitness,
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let x = allocate_canonical_scalar(&mut builder, x)?;
        let term = ConstrainedPolynomialTerm {
            scale: allocate_canonical_scalar(&mut builder, term.scale)?,
            offset: term.offset,
            factors: term
                .factors
                .iter()
                .map(|&factor| allocate_canonical_scalar(&mut builder, factor))
                .collect::<Result<_, _>>()?,
        };
        let rounds = term.factors.len().max(3);
        let powers = candidate_power_ladder(&mut builder, &x, rounds)?;
        let actual = evaluate_candidate_term(&mut builder, &term, &powers)?;
        constrain_scalar_constant(&mut builder, &actual, expected)?;
        builder.finish()
    }

    #[test]
    fn candidate_term_shared_powers_match_reference_and_bind_inputs() {
        let x = SecpScalarWitness::from_u64(11);
        let term = CandidatePolynomialTermWitness {
            scale: SecpScalarWitness::from_u64(7),
            offset: 5,
            factors: vec![
                SecpScalarWitness::from_u64(3),
                SecpScalarWitness::from_u64(4),
                SecpScalarWitness::from_u64(5),
            ],
        };
        let expected = candidate_term_reference(&term, x);
        let (circuit, assignment) =
            build_candidate_term_evaluation(&term, x, expected).expect("candidate term");
        assert!(relation_satisfied(&circuit, &assignment));

        let mut changed = term;
        changed.factors[1] = SecpScalarWitness::from_u64(6);
        let (changed_circuit, changed_assignment) =
            build_candidate_term_evaluation(&changed, x, expected).expect("changed term");
        assert_eq!(circuit, changed_circuit);
        assert!(!relation_satisfied(&changed_circuit, &changed_assignment));

        let constant = CandidatePolynomialTermWitness {
            scale: SecpScalarWitness::from_u64(9),
            offset: 0,
            factors: vec![],
        };
        let constant_expected = candidate_term_reference(&constant, x);
        let (constant_circuit, constant_assignment) =
            build_candidate_term_evaluation(&constant, x, constant_expected)
                .expect("constant term");
        assert!(relation_satisfied(&constant_circuit, &constant_assignment));
    }

    fn mixed_fanin_claims(
        anchor_count: usize,
        include_setup: bool,
    ) -> Vec<CandidatePendingClaimWitness> {
        let setup = CandidatePendingClaimWitness {
            point: SecpEncodedPointWitness::identity(),
            polynomial: vec![
                zero_polynomial_term(0, 12),
                zero_polynomial_term(4096, 12),
                zero_polynomial_term(4096, 12),
            ],
        };
        let anchor = CandidatePendingClaimWitness {
            point: SecpEncodedPointWitness::identity(),
            polynomial: vec![
                zero_polynomial_term(0, 14),
                zero_polynomial_term(16_384, 14),
                zero_polynomial_term(16_384, 14),
            ],
        };
        let mut claims = Vec::with_capacity(anchor_count + usize::from(include_setup));
        if include_setup {
            claims.push(setup);
        }
        claims.extend(std::iter::repeat_n(anchor, anchor_count));
        claims
    }

    fn arithmetic_fanin_step_proof() -> CandidateStepProofWitness {
        CandidateStepProofWitness {
            left: vec![SecpEncodedPointWitness::identity(); 15],
            right: vec![SecpEncodedPointWitness::identity(); 15],
            terminal_scalar: SecpScalarWitness::from_u64(0),
            folded_generator: SecpEncodedPointWitness::identity(),
        }
    }

    fn prove_bitwise_msm_relation(
        terms: &[(SecpAffineWitness, SecpScalarWitness)],
        expected: SecpAffineWitness,
    ) -> Result<(Vec<u8>, usize, usize), ReceiptCycleError> {
        let (circuit, assignment) =
            build_secp_msm_relation_with(terms, expected, msm_points_bitwise)?;
        let statement = b"bitwise secp MSM comparison";
        let proof = prove(&circuit, &assignment, statement, [0x83; 32])?;
        verify(&circuit, statement, &proof)?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("gate count")) as usize;
        Ok((circuit, gates, proof.len()))
    }

    fn window_gate_count<const WINDOW_BITS: usize>(term_count: usize) -> usize {
        let terms = vec![(generator(), SecpScalarWitness::from_u64(0)); term_count];
        let (circuit, _) = build_secp_msm_relation_with(
            &terms,
            SecpAffineWitness::identity(),
            msm_points_windowed::<WINDOW_BITS>,
        )
        .expect("windowed circuit");
        crate::Circuit::parse(&circuit)
            .expect("windowed circuit parse")
            .gate_count
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
        assert!(
            encoded_point_value(identity)
                .expect("identity value")
                .identity
        );
        assert!(
            !encoded_point_value(generator)
                .expect("generator value")
                .identity
        );

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
    fn encoded_point_parser_derives_the_unique_affine_opening() {
        let g = generator();
        let even = encoded(g, 0x02);
        let odd = encoded(negate(g), 0x03);

        assert_eq!(
            SecpEncodedPointWitness::parse([0; 33]).expect("encoded identity"),
            SecpEncodedPointWitness::identity()
        );
        assert_eq!(
            SecpEncodedPointWitness::parse(even.encoded).expect("even generator"),
            even
        );
        assert_eq!(
            SecpEncodedPointWitness::parse(odd.encoded).expect("odd generator"),
            odd
        );
    }

    #[test]
    fn encoded_point_parser_rejects_noncanonical_public_bytes() {
        let generator = encoded(generator(), 0x02).encoded;

        let mut malformed_identity = generator;
        malformed_identity[0] = 0;
        assert!(SecpEncodedPointWitness::parse(malformed_identity).is_err());

        let mut invalid_prefix = generator;
        invalid_prefix[0] = 4;
        assert!(SecpEncodedPointWitness::parse(invalid_prefix).is_err());

        let mut noncanonical_x = generator;
        noncanonical_x[1..].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xfc, 0x2f,
        ]);
        assert!(SecpEncodedPointWitness::parse(noncanonical_x).is_err());

        // x = 0 is canonical, but x^3 + 7 is a nonsquare modulo secp256k1 p.
        let mut nonsquare_x = generator;
        nonsquare_x[1..].fill(0);
        assert!(SecpEncodedPointWitness::parse(nonsquare_x).is_err());
    }

    #[test]
    fn encoded_point_rejects_noncanonical_forms() {
        let generator = generator();

        let mut zero_prefix_hybrid = encoded(generator, 0x00);
        assert!(prove_encoded_point(zero_prefix_hybrid).is_err());
        assert!(encoded_point_value(zero_prefix_hybrid).is_err());
        zero_prefix_hybrid.encoded[1] ^= 1;
        assert!(prove_encoded_point(zero_prefix_hybrid).is_err());
        assert!(encoded_point_value(zero_prefix_hybrid).is_err());

        let invalid_prefix = encoded(generator, 0x04);
        assert!(prove_encoded_point(invalid_prefix).is_err());
        assert!(encoded_point_value(invalid_prefix).is_err());

        let wrong_parity = encoded(generator, 0x03);
        assert!(prove_encoded_point(wrong_parity).is_err());
        assert!(encoded_point_value(wrong_parity).is_err());

        let mut off_curve = encoded(generator, 0x02);
        off_curve.y[0] ^= 1;
        assert!(prove_encoded_point(off_curve).is_err());
        assert!(encoded_point_value(off_curve).is_err());

        let mut noncanonical_x = encoded(generator, 0x02);
        noncanonical_x.encoded[1..].fill(0xff);
        assert!(build_secp_encoded_point_relation(noncanonical_x).is_err());
        assert!(encoded_point_value(noncanonical_x).is_err());

        let mut noncanonical_y = encoded(generator, 0x02);
        noncanonical_y.y = [0xff; 32];
        assert!(build_secp_encoded_point_relation(noncanonical_y).is_err());
        assert!(encoded_point_value(noncanonical_y).is_err());
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
        prove_scale_relation(generator(), maximum_scalar(), negate(generator()))
            .expect("order minus one");
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
    fn fixed_base_scalar_multiplication_handles_boundaries() {
        let (zero_circuit, gates, proof_bytes) = prove_fixed_scale_relation(
            generator(),
            SecpScalarWitness::from_u64(0),
            SecpAffineWitness::identity(),
        )
        .expect("fixed-base zero scalar");
        let (maximum_circuit, _, _) =
            prove_fixed_scale_relation(generator(), maximum_scalar(), negate(generator()))
                .expect("fixed-base order minus one");
        prove_fixed_scale_relation(
            SecpAffineWitness::identity(),
            maximum_scalar(),
            SecpAffineWitness::identity(),
        )
        .expect("fixed-base identity");

        assert_eq!(zero_circuit, maximum_circuit);
        assert_eq!(gates, 5_449);
        assert_eq!(proof_bytes, 1_283);
        eprintln!("receipt_secp_fixed_base_gates={gates} proof_bytes={proof_bytes}");
    }

    #[test]
    fn fixed_base_scalar_multiplication_rejects_bad_inputs() {
        assert!(prove_fixed_scale_relation(
            generator(),
            SecpScalarWitness::from_u64(2),
            three_times_generator(),
        )
        .is_err());

        let mut off_curve = generator();
        off_curve.y[0] ^= 1;
        assert!(build_secp_fixed_base_scalar_multiplication_relation(
            off_curve,
            SecpScalarWitness::from_u64(1),
            generator(),
        )
        .is_err());

        let mut malformed_identity = SecpAffineWitness::identity();
        malformed_identity.x[0] = 1;
        assert!(build_secp_fixed_base_scalar_multiplication_relation(
            malformed_identity,
            SecpScalarWitness::from_u64(0),
            SecpAffineWitness::identity(),
        )
        .is_err());
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
        assert_eq!(gates, 22_824);
        assert_eq!(proof_bytes, 1_415);
    }

    #[test]
    fn windowed_msm_matches_bitwise_at_group_boundaries() {
        let generator = generator();
        let terms = [
            (generator, maximum_scalar()),
            (SecpAffineWitness::identity(), maximum_scalar()),
            (generator, SecpScalarWitness::from_u64(0)),
            (negate(generator), SecpScalarWitness::from_u64(1)),
        ];
        let expected = negate(twice_generator());
        let (_, windowed_gates, _) =
            prove_msm_relation(&terms, expected).expect("windowed boundary MSM");
        let (_, bitwise_gates, _) =
            prove_bitwise_msm_relation(&terms, expected).expect("bitwise boundary MSM");
        assert!(windowed_gates < bitwise_gates);
    }

    #[test]
    #[ignore = "large circuit cost measurement"]
    fn windowed_msm_gate_budget() {
        let two_bit_32 = window_gate_count::<2>(32);
        let three_bit_32 = window_gate_count::<3>(32);
        let four_bit_32 = window_gate_count::<4>(32);
        let three_bit_64 = window_gate_count::<3>(64);
        eprintln!(
            "receipt_secp_window_msm_gates_32=w2:{},w3:{},w4:{} w3_64:{}",
            two_bit_32, three_bit_32, four_bit_32, three_bit_64
        );
        assert_eq!(two_bit_32, 239_251);
        assert_eq!(three_bit_32, 200_574);
        assert_eq!(four_bit_32, 204_477);
        assert_eq!(three_bit_64, 390_174);
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

    #[test]
    fn candidate_step_shared_powers_preserve_transition_language() {
        let (basis, claims, proof, root) = candidate_step_fixture();
        let (circuit, assignment) =
            build_candidate_accumulation_step_relation(basis, &claims, &proof, &root)
                .expect("candidate step relation");
        assert!(relation_satisfied(&circuit, &assignment));
        drop(assignment);

        let mut changed_claims = claims;
        changed_claims[0].point = encoded(twice_generator(), 0x02);
        let (changed_circuit, changed_assignment) =
            build_candidate_accumulation_step_relation(basis, &changed_claims, &proof, &root)
                .expect("changed candidate claim");
        assert_eq!(circuit, changed_circuit);
        assert!(!relation_satisfied(&changed_circuit, &changed_assignment));
    }

    #[test]
    fn candidate_step_rejects_invalid_public_shapes() {
        let (basis, claims, proof, root) = candidate_step_fixture();
        assert!(build_candidate_accumulation_step_relation(basis, &[], &proof, &root).is_err());

        let excessive_claims = vec![claims[0].clone(); MAX_CANDIDATE_CLAIMS + 1];
        assert!(build_candidate_accumulation_step_relation(
            basis,
            &excessive_claims,
            &proof,
            &root,
        )
        .is_err());

        let mut missing_right = proof.clone();
        missing_right.right.clear();
        assert!(
            build_candidate_accumulation_step_relation(basis, &claims, &missing_right, &root,)
                .is_err()
        );

        let mut excessive_degree = claims.clone();
        excessive_degree[0].polynomial[0].offset = 2;
        assert!(build_candidate_accumulation_step_relation(
            basis,
            &excessive_degree,
            &proof,
            &root,
        )
        .is_err());

        let mut wrong_root_shape = root.clone();
        wrong_root_shape.factors.clear();
        assert!(build_candidate_accumulation_step_relation(
            basis,
            &claims,
            &proof,
            &wrong_root_shape,
        )
        .is_err());
    }

    fn measure_arithmetic_fanin_step(
        anchor_count: usize,
        include_setup: bool,
    ) -> (usize, usize, usize) {
        let basis = [0xb6; 32];
        let claims = mixed_fanin_claims(anchor_count, include_setup);
        let proof = arithmetic_fanin_step_proof();
        assert_eq!(claims.len(), anchor_count + usize::from(include_setup));
        assert_eq!(proof.left.len(), 15);
        let root = derive_candidate_root_witness(basis, &claims, &proof)
            .expect("mixed fan-in root witness");

        // A composed step consumes leaf variables that already carry their
        // point and scalar constraints. Allocate the identical claim inputs
        // once by themselves, then subtract that deterministic prefix from a
        // second builder containing the prefix plus the step. Builder gates
        // are append-only, so this removes every duplicated claim allocation
        // exactly. The delta intentionally retains all step-proof witnesses,
        // transcript work, the short equation, and public root constraints.
        let input_gates = {
            let mut input_builder = Builder::default();
            allocate_candidate_claims(&mut input_builder, &claims).expect("allocate mixed claims");
            input_builder.gate_count()
        };

        let mut builder = Builder::default();
        let constrained =
            allocate_candidate_claims(&mut builder, &claims).expect("allocate mixed claims");
        let derived = install_constrained_candidate_step(&mut builder, basis, &constrained, &proof)
            .expect("mixed fan-in step");
        constrain_encoded_point_constant(&mut builder, &derived.point, root.point)
            .expect("mixed fan-in root point");
        constrain_scalar_constant(&mut builder, &derived.scale, root.scale)
            .expect("mixed fan-in root scale");
        for (actual, &expected) in derived.factors.iter().zip(&root.factors) {
            constrain_scalar_constant(&mut builder, actual, expected)
                .expect("mixed fan-in root factor");
        }
        let total_gates = builder.gate_count();
        let step_gates = total_gates
            .checked_sub(input_gates)
            .expect("step contains claim inputs");
        eprintln!(
            "arithmetic_fanin_step anchor_count={anchor_count} include_setup={include_setup} \
             step_gates={step_gates} total_gates={total_gates} input_gates={input_gates}"
        );
        (step_gates, total_gates, input_gates)
    }

    #[test]
    #[ignore = "run explicitly in release mode; fan-in step relation is large"]
    fn fanin_sixteen_mixed_claim_step_reports_gate_delta() {
        assert_eq!(
            measure_arithmetic_fanin_step(16, true),
            (4_800_750, 5_198_266, 397_516)
        );
    }

    #[test]
    #[ignore = "run explicitly in release mode; fan-in step relation is large"]
    fn fanin_twelve_mixed_claim_step_reports_gate_delta() {
        assert_eq!(
            measure_arithmetic_fanin_step(12, true),
            (3_788_394, 4_091_654, 303_260)
        );
    }

    #[test]
    #[ignore = "run explicitly in release mode; fan-in step relation is large"]
    fn fanin_thirteen_mixed_claim_step_reports_gate_delta() {
        assert_eq!(
            measure_arithmetic_fanin_step(13, true),
            (4_037_127, 4_363_951, 326_824)
        );
    }

    #[test]
    #[ignore = "run explicitly in release mode; fan-in step relation is large"]
    fn fanin_thirteen_anchor_only_step_reports_gate_delta() {
        assert_eq!(
            measure_arithmetic_fanin_step(13, false),
            (3_821_856, 4_128_188, 306_332)
        );
    }

    #[test]
    #[ignore = "run explicitly in release mode; fan-in step relation is large"]
    fn fanin_fourteen_anchor_only_step_reports_gate_delta() {
        assert_eq!(
            measure_arithmetic_fanin_step(14, false),
            (4_070_589, 4_400_485, 329_896)
        );
    }

    #[test]
    fn maximum_arithmetic_fanin_is_explicit() {
        const MAX_GATES: usize = 1 << 24;
        const ANCHOR_LEAF_GATES: usize = 949_880;
        const SETUP_LEAF_GATES: usize = 854_293;
        const FIRST_TWELVE_STEP_GATES: usize = 3_788_394;
        const FIRST_THIRTEEN_STEP_GATES: usize = 4_037_127;
        const LATER_THIRTEEN_STEP_GATES: usize = 3_821_856;
        const LATER_FOURTEEN_STEP_GATES: usize = 4_070_589;
        let first_twelve = 12 * ANCHOR_LEAF_GATES + SETUP_LEAF_GATES + FIRST_TWELVE_STEP_GATES;
        let first_thirteen = 13 * ANCHOR_LEAF_GATES + SETUP_LEAF_GATES + FIRST_THIRTEEN_STEP_GATES;
        let later_thirteen = 13 * ANCHOR_LEAF_GATES + LATER_THIRTEEN_STEP_GATES;
        let later_fourteen = 14 * ANCHOR_LEAF_GATES + LATER_FOURTEEN_STEP_GATES;

        assert_eq!(MAX_GATES - first_twelve, 735_969);
        assert_eq!(first_thirteen - MAX_GATES, 462_644);
        assert_eq!(MAX_GATES - later_thirteen, 606_920);
        assert_eq!(later_fourteen - MAX_GATES, 591_693);
    }

    #[test]
    #[ignore = "run explicitly in release mode; candidate step proof is large"]
    fn candidate_step_binds_transition_and_public_constants() {
        let (basis, claims, proof, root) = candidate_step_fixture();
        let (circuit, assignment) =
            build_candidate_accumulation_step_relation(basis, &claims, &proof, &root)
                .expect("candidate step relation");
        let statement = b"candidate accumulation step";
        let accepted = prove(&circuit, &assignment, statement, [0x83; 32]).expect("proof");
        verify(&circuit, statement, &accepted).expect("candidate step verification");

        let mut changed_claims = claims.clone();
        changed_claims[0].point = encoded(twice_generator(), 0x02);
        let (same_circuit, false_assignment) =
            build_candidate_accumulation_step_relation(basis, &changed_claims, &proof, &root)
                .expect("changed private claim");
        assert_eq!(same_circuit, circuit);
        let rejected = prove(&circuit, &false_assignment, statement, [0x84; 32])
            .expect("false transition proof");
        assert!(verify(&circuit, statement, &rejected).is_err());

        let mut changed_root = root.clone();
        let changed_factor = (BigUint::from_bytes_be(&changed_root.factors[0].bytes)
            + BigUint::from(1u64))
            % secp_order();
        changed_root.factors[0] = scalar_witness(&changed_factor).expect("changed factor");
        let (changed_root_circuit, _) =
            build_candidate_accumulation_step_relation(basis, &claims, &proof, &changed_root)
                .expect("changed public root");
        assert_ne!(changed_root_circuit, circuit);
        assert!(verify(&changed_root_circuit, statement, &accepted).is_err());

        let (changed_role_circuit, changed_role_assignment) =
            build_candidate_accumulation_step_relation_for_role(
                basis,
                crate::opening_base::REDUCTION_OPENING_BASE_ROLE,
                &claims,
                &proof,
                &root,
            )
            .expect("changed opening-base role");
        assert_ne!(changed_role_circuit, circuit);
        assert!(verify(&changed_role_circuit, statement, &accepted).is_err());
        let changed_role_proof = prove(
            &changed_role_circuit,
            &changed_role_assignment,
            statement,
            [0x85; 32],
        )
        .expect("changed-role proof");
        assert!(verify(&changed_role_circuit, statement, &changed_role_proof,).is_err());

        let mut changed_basis = basis;
        changed_basis[0] ^= 1;
        let (changed_basis_circuit, _) =
            build_candidate_accumulation_step_relation(changed_basis, &claims, &proof, &root)
                .expect("changed public basis");
        assert_ne!(changed_basis_circuit, circuit);
        assert!(verify(&changed_basis_circuit, statement, &accepted).is_err());

        let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("gate count"));
        eprintln!(
            "candidate_accumulation_step_gates={gates} proof_bytes={}",
            accepted.len()
        );
        assert_eq!(
            accepted.len(),
            proof_wire_len(&circuit).expect("proof size")
        );
    }
}
