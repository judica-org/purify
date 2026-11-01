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

    fn prove_compressed_point(witness: SecpCompressedWitness) -> Result<(), ReceiptCycleError> {
        let (circuit, assignment) = build_secp_compressed_point_relation(witness)?;
        let statement = b"secp compressed-point foundation";
        let proof = prove(&circuit, &assignment, statement, [0x92; 32])?;
        assert_eq!(proof.len(), proof_wire_len(&circuit)?);
        verify(&circuit, statement, &proof)
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
}
