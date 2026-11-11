//! Canonical secp256k1 wrappers for direct Nova relations.
//!
//! Nova owns the generic group law. This module adds only Purify's encoding
//! rules: the identity is uniquely `(0, 0, true)`, finite points use canonical
//! field bytes, and the encoded prefix is exactly zero, two, or three.

use std::array;

use ff::Field;
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::AllocatedNum,
        },
        ConstraintSystem, SynthesisError,
    },
    gadgets::{
        ecc::AllocatedPoint,
        utils::{alloc_constant, select_zero_or_num2},
    },
    provider::Secp256k1Sha256Engine,
};

use crate::{
    nova_sha256_transcript::NovaByte,
    secp_native::{parse_encoded_point, PointValue, SecpEncodedPointWitness},
    Scalar,
};

type NovaPoint = AllocatedPoint<Secp256k1Sha256Engine>;

const SCALAR_BITS: usize = 256;

#[derive(Clone)]
pub(crate) struct DirectSecpPoint {
    point: NovaPoint,
}

#[derive(Clone)]
pub(crate) struct DirectEncodedSecpPoint {
    point: DirectSecpPoint,
    prefix: AllocatedNum<Scalar>,
    odd: Boolean,
    prefix_byte: NovaByte,
    x_bytes: [NovaByte; 32],
}

impl DirectSecpPoint {
    pub(crate) fn x(&self) -> &AllocatedNum<Scalar> {
        &self.point.x
    }

    pub(crate) fn y(&self) -> &AllocatedNum<Scalar> {
        &self.point.y
    }

    pub(crate) fn identity_num(&self) -> &AllocatedNum<Scalar> {
        &self.point.is_infinity
    }

    pub(crate) fn is_identity(&self) -> Boolean {
        infinity_boolean(&self.point)
    }

    pub(crate) fn enforce_equal<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: CS,
        other: &Self,
    ) -> Result<(), SynthesisError> {
        self.point.enforce_equal(cs, &other.point)
    }
}

impl DirectEncodedSecpPoint {
    pub(crate) fn point(&self) -> &DirectSecpPoint {
        &self.point
    }

    pub(crate) fn prefix(&self) -> &AllocatedNum<Scalar> {
        &self.prefix
    }

    pub(crate) fn odd(&self) -> &Boolean {
        &self.odd
    }

    pub(crate) fn prefix_byte(&self) -> &NovaByte {
        &self.prefix_byte
    }

    pub(crate) fn x_bytes(&self) -> &[NovaByte; 32] {
        &self.x_bytes
    }
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn infinity_boolean(point: &NovaPoint) -> Boolean {
    // AllocatedPoint constrains this variable to {0, 1}. Reinterpreting it as
    // a Boolean adds no second witness or redundant Booleanity constraint.
    let value = point
        .is_infinity
        .get_value()
        .map(|value| value == Scalar::ONE);
    Boolean::from(AllocatedBit::from_parts_unchecked(
        point.is_infinity.get_variable(),
        value,
    ))
}

fn enforce_canonical_identity<CS: ConstraintSystem<Scalar>>(mut cs: CS, point: &NovaPoint) {
    cs.enforce(
        || "identity x is zero",
        |lc| lc + point.is_infinity.get_variable(),
        |lc| lc + point.x.get_variable(),
        |lc| lc,
    );
    cs.enforce(
        || "identity y is zero",
        |lc| lc + point.is_infinity.get_variable(),
        |lc| lc + point.y.get_variable(),
        |lc| lc,
    );
}

fn canonicalize_computed_identity<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: NovaPoint,
) -> Result<NovaPoint, SynthesisError> {
    let x = select_zero_or_num2(
        cs.namespace(|| "canonical identity x"),
        &point.x,
        &point.is_infinity,
    )?;
    let y = select_zero_or_num2(
        cs.namespace(|| "canonical identity y"),
        &point.y,
        &point.is_infinity,
    )?;
    Ok(NovaPoint {
        x,
        y,
        is_infinity: point.is_infinity,
    })
}

pub(crate) fn allocate_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: PointValue,
) -> Result<DirectSecpPoint, SynthesisError> {
    let point = NovaPoint::alloc(
        cs.namespace(|| "point"),
        Some((value.x, value.y, value.identity)),
    )?;
    point.check_on_curve(cs.namespace(|| "point is on curve"))?;
    enforce_canonical_identity(cs.namespace(|| "canonical identity"), &point);
    Ok(DirectSecpPoint { point })
}

pub(crate) fn allocate_constant_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: PointValue,
) -> Result<DirectSecpPoint, SynthesisError> {
    if value.identity {
        if value.x != Scalar::ZERO || value.y != Scalar::ZERO {
            return Err(synthesis_error("noncanonical constant identity"));
        }
        return Ok(DirectSecpPoint {
            point: NovaPoint::default(cs.namespace(|| "identity"))?,
        });
    }
    if value.y.square() != value.x.square() * value.x + Scalar::from(7) {
        return Err(synthesis_error("constant point off curve"));
    }
    let is_infinity = alloc_constant(cs.namespace(|| "finite"), &Scalar::ZERO)?;
    let point = NovaPoint::alloc_constant(
        cs.namespace(|| "constant point"),
        (value.x, value.y),
        is_infinity,
    )?;
    Ok(DirectSecpPoint { point })
}

fn strict_field_bits<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let bits = value.to_bits_le_strict(cs.namespace(|| "canonical field bits"))?;
    if bits.len() != SCALAR_BITS {
        return Err(synthesis_error("secp field bit width"));
    }
    Ok(bits)
}

fn field_bytes_be(bits: &[Boolean]) -> Result<[NovaByte; 32], SynthesisError> {
    if bits.len() != SCALAR_BITS {
        return Err(synthesis_error("secp field bit width"));
    }
    Ok(array::from_fn(|byte| {
        let offset = (31 - byte) * 8;
        NovaByte::from_constrained_bits_le(array::from_fn(|bit| bits[offset + bit].clone()))
    }))
}

fn encode_with_prefix<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: DirectSecpPoint,
    prefix_value: Option<u8>,
) -> Result<DirectEncodedSecpPoint, SynthesisError> {
    let x_bits = strict_field_bits(cs.namespace(|| "x encoding"), &point.point.x)?;
    let x_bytes = field_bytes_be(&x_bits)?;
    let y_bits = strict_field_bits(cs.namespace(|| "y encoding"), &point.point.y)?;
    let odd = y_bits[0].clone();
    let active = infinity_boolean(&point.point).not();
    let derived_prefix = match (point.point.is_infinity.get_value(), odd.get_value()) {
        (Some(identity), Some(odd)) => Some(if identity == Scalar::ONE {
            0
        } else {
            2 + u8::from(odd)
        }),
        _ => None,
    };
    let prefix = AllocatedNum::alloc(cs.namespace(|| "encoded prefix"), || {
        Ok(Scalar::from(u64::from(
            prefix_value
                .or(derived_prefix)
                .ok_or(SynthesisError::AssignmentMissing)?,
        )))
    })?;
    let finite_prefix = odd.lc(CS::one(), Scalar::ONE) + (Scalar::from(2), CS::one());
    cs.enforce(
        || "canonical encoded prefix",
        |_| active.lc(CS::one(), Scalar::ONE),
        |_| finite_prefix,
        |lc| lc + prefix.get_variable(),
    );
    let prefix_byte = NovaByte::from_constrained_bits_le([
        odd.clone(),
        active,
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
    ]);
    Ok(DirectEncodedSecpPoint {
        point,
        prefix,
        odd,
        prefix_byte,
        x_bytes,
    })
}

pub(crate) fn allocate_encoded_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    witness: SecpEncodedPointWitness,
) -> Result<DirectEncodedSecpPoint, SynthesisError> {
    let value = parse_encoded_point(witness)
        .map_err(|_| synthesis_error("malformed encoded secp point"))?;
    let point = allocate_point(cs.namespace(|| "point"), value.point)?;
    encode_with_prefix(cs.namespace(|| "encoding"), point, Some(value.prefix))
}

pub(crate) fn encode_computed_point<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    point: DirectSecpPoint,
) -> Result<DirectEncodedSecpPoint, SynthesisError> {
    encode_with_prefix(cs, point, None)
}

pub(crate) fn add_points<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    left: &DirectSecpPoint,
    right: &DirectSecpPoint,
) -> Result<DirectSecpPoint, SynthesisError> {
    let point = left
        .point
        .add(cs.namespace(|| "complete addition"), &right.point)?;
    Ok(DirectSecpPoint { point })
}

pub(crate) fn scale_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &DirectSecpPoint,
    scalar_bits: &[AllocatedBit],
) -> Result<DirectSecpPoint, SynthesisError> {
    // Canonicality belongs to the scalar allocator. Reuse its constrained
    // bits here rather than allocating a second, potentially inconsistent
    // scalar witness.
    if scalar_bits.len() != SCALAR_BITS {
        return Err(synthesis_error("secp scalar bit width"));
    }
    let point = point
        .point
        .scalar_mul(cs.namespace(|| "scalar multiplication"), scalar_bits)?;
    let point = canonicalize_computed_identity(cs.namespace(|| "scaled identity"), point)?;
    Ok(DirectSecpPoint { point })
}

pub(crate) fn msm_points<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    points: &[DirectSecpPoint],
    scalars: &[Vec<AllocatedBit>],
) -> Result<DirectSecpPoint, SynthesisError> {
    if points.is_empty() || points.len() != scalars.len() {
        return Err(synthesis_error("secp MSM shape"));
    }
    let mut terms = points.iter().zip(scalars).enumerate();
    let (index, (point, scalar)) = terms.next().expect("nonempty point list");
    let mut sum = scale_point(cs.namespace(|| format!("term {index}")), point, scalar)?;
    for (index, (point, scalar)) in terms {
        let term = scale_point(cs.namespace(|| format!("term {index}")), point, scalar)?;
        sum = add_points(cs.namespace(|| format!("sum {index}")), &sum, &term)?;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use nova_snark::{
        frontend::{shape_cs::ShapeCS, test_cs::TestConstraintSystem},
        provider::Secq256k1Sha256Engine,
    };
    use num_bigint::BigUint;

    use super::*;
    use crate::{
        scalar_to_canonical,
        secp_constants::{SECP256K1_BASE_FIELD_MODULUS_BE, SECP256K1_SCALAR_ORDER_BE},
        secp_native::{add_point_values, scale_point_value},
    };

    fn generator() -> PointValue {
        let mut encoded = [0u8; 33];
        encoded[0] = 2;
        encoded[1..].copy_from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ]);
        crate::secp_native::encoded_point_value(
            SecpEncodedPointWitness::parse(encoded).expect("generator encoding"),
        )
        .expect("generator point")
    }

    fn identity() -> PointValue {
        PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        }
    }

    fn inverse(point: PointValue) -> PointValue {
        PointValue {
            y: -point.y,
            ..point
        }
    }

    fn bits(value: &BigUint) -> [bool; SCALAR_BITS] {
        array::from_fn(|index| value.bit(index as u64))
    }

    fn allocate_bits<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        value: &[bool; SCALAR_BITS],
    ) -> Vec<AllocatedBit> {
        value
            .iter()
            .enumerate()
            .map(|(index, value)| {
                AllocatedBit::alloc(cs.namespace(|| format!("bit {index}")), Some(*value))
                    .expect("scalar bit")
            })
            .collect()
    }

    fn constrain_addition<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        left: PointValue,
        right: PointValue,
        expected: PointValue,
    ) {
        let left = allocate_point(cs.namespace(|| "left"), left).expect("left point");
        let right = allocate_point(cs.namespace(|| "right"), right).expect("right point");
        let expected = allocate_point(cs.namespace(|| "expected"), expected).expect("expected");
        let sum = add_points(cs.namespace(|| "sum"), &left, &right).expect("addition");
        sum.enforce_equal(cs.namespace(|| "expected sum"), &expected)
            .expect("sum equality");
    }

    #[test]
    fn encoded_points_use_exact_sec1_bytes() {
        for value in [generator(), identity()] {
            let witness = SecpEncodedPointWitness::from_point_value(value);
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let encoded =
                allocate_encoded_point(cs.namespace(|| "encoded"), witness).expect("encoded point");
            let expected =
                allocate_point(cs.namespace(|| "expected"), value).expect("expected point");
            encoded
                .point()
                .enforce_equal(cs.namespace(|| "expected equality"), &expected)
                .expect("point equality");
            assert_eq!(encoded.point().x().get_value(), Some(value.x));
            assert_eq!(encoded.point().y().get_value(), Some(value.y));
            assert_eq!(
                encoded.point().identity_num().get_value(),
                Some(Scalar::from(u64::from(value.identity)))
            );
            assert_eq!(
                encoded.point().is_identity().get_value(),
                Some(value.identity)
            );
            assert_eq!(
                encoded.prefix().get_value(),
                Some(Scalar::from(u64::from(witness.encoded[0])))
            );
            assert_eq!(encoded.odd().get_value(), Some(witness.encoded[0] & 1 == 1));
            assert_eq!(encoded.prefix_byte().value(), witness.encoded[0]);
            assert_eq!(
                encoded.x_bytes().each_ref().map(NovaByte::value).as_slice(),
                &witness.encoded[1..]
            );
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn encoded_points_reject_noncanonical_forms() {
        let generator = SecpEncodedPointWitness::from_point_value(generator());
        let mut wrong_parity = generator;
        wrong_parity.encoded[0] ^= 1;
        let mut bad_prefix = generator;
        bad_prefix.encoded[0] = 4;
        let mut bad_identity = SecpEncodedPointWitness::identity();
        bad_identity.y[0] = 1;
        let mut bad_identity_x = SecpEncodedPointWitness::identity();
        bad_identity_x.encoded[32] = 1;
        let mut off_curve = generator;
        off_curve.y = [0; 32];
        off_curve.y[0] = 2;
        for witness in [
            wrong_parity,
            bad_prefix,
            bad_identity,
            bad_identity_x,
            off_curve,
        ] {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            allocate_encoded_point(cs.namespace(|| "invalid"), witness)
                .expect("well-sized invalid point");
            assert!(!cs.is_satisfied());
        }

        let mut noncanonical = generator;
        noncanonical.encoded[1..].copy_from_slice(&SECP256K1_BASE_FIELD_MODULUS_BE);
        let mut cs = TestConstraintSystem::<Scalar>::new();
        assert!(allocate_encoded_point(cs.namespace(|| "noncanonical"), noncanonical).is_err());
    }

    #[test]
    fn complete_addition_is_shape_independent() {
        let generator = generator();
        let cases = [
            (generator, generator, add_point_values(generator, generator)),
            (generator, inverse(generator), identity()),
            (identity(), generator, generator),
            (generator, identity(), generator),
            (identity(), identity(), identity()),
        ];
        let mut reference_shape = None;
        for (index, (left, right, expected)) in cases.into_iter().enumerate() {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            constrain_addition(&mut cs, left, right, expected);
            assert!(cs.is_satisfied(), "addition case {index}");

            let mut shape = ShapeCS::<Secq256k1Sha256Engine>::new();
            constrain_addition(&mut shape, left, right, expected);
            if let Some((aux, constraints)) = &reference_shape {
                assert_eq!(shape.num_aux(), *aux);
                assert_eq!(&shape.constraints, constraints);
            } else {
                reference_shape = Some((shape.num_aux(), shape.constraints));
            }
        }
        let (aux, constraints) = reference_shape.expect("addition cases");
        assert_eq!((aux, constraints.len()), (52, 60));
    }

    #[test]
    fn scalar_multiplication_handles_boundaries() {
        let generator = generator();
        let order = BigUint::from_bytes_be(&SECP256K1_SCALAR_ORDER_BE);
        for (base, scalar) in [
            (generator, BigUint::from(0u8)),
            (generator, BigUint::from(2u8)),
            (generator, &order - 1u8),
            (identity(), BigUint::from(1u8)),
            (identity(), &order - 1u8),
        ] {
            let expected_value = scale_point_value(base, &scalar);
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let base = allocate_point(cs.namespace(|| "base"), base).expect("base");
            let expected =
                allocate_point(cs.namespace(|| "expected"), expected_value).expect("expected");
            let scalar = allocate_bits(cs.namespace(|| "scalar"), &bits(&scalar));
            let product = scale_point(cs.namespace(|| "product"), &base, &scalar)
                .expect("scalar multiplication");
            product
                .enforce_equal(cs.namespace(|| "expected product"), &expected)
                .expect("product equality");
            assert!(cs.is_satisfied());
        }

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let base = allocate_point(cs.namespace(|| "base"), generator).expect("base");
        let scalar = allocate_bits(cs.namespace(|| "short scalar"), &bits(&BigUint::from(2u8)));
        assert!(scale_point(cs.namespace(|| "invalid product"), &base, &scalar[..255]).is_err());
    }

    #[test]
    fn direct_point_shapes_are_pinned() {
        let generator = generator();
        let double = add_point_values(generator, generator);
        let mut encoding = ShapeCS::<Secq256k1Sha256Engine>::new();
        allocate_encoded_point(
            encoding.namespace(|| "encoded point"),
            SecpEncodedPointWitness::from_point_value(generator),
        )
        .expect("encoded point");

        let mut addition = ShapeCS::<Secq256k1Sha256Engine>::new();
        constrain_addition(&mut addition, generator, generator, double);

        let mut multiplication = ShapeCS::<Secq256k1Sha256Engine>::new();
        let point = allocate_point(multiplication.namespace(|| "point"), generator).expect("point");
        let scalar = allocate_bits(
            multiplication.namespace(|| "scalar"),
            &bits(&BigUint::from(2u8)),
        );
        scale_point(multiplication.namespace(|| "product"), &point, &scalar).expect("product");

        assert_eq!(
            (encoding.num_aux(), encoding.num_constraints()),
            (1_016, 1_019)
        );
        assert_eq!((addition.num_aux(), addition.num_constraints()), (52, 60));
        assert_eq!(
            (multiplication.num_aux(), multiplication.num_constraints()),
            (2_668, 2_675)
        );
    }

    #[test]
    fn constant_points_and_msm_reuse_nova_group_law() {
        let generator = generator();
        let mut equality = TestConstraintSystem::<Scalar>::new();
        let constant = allocate_constant_point(equality.namespace(|| "constant"), generator)
            .expect("constant point");
        let allocated =
            allocate_point(equality.namespace(|| "allocated"), generator).expect("allocated point");
        constant
            .enforce_equal(equality.namespace(|| "constant equality"), &allocated)
            .expect("constant equality");
        assert!(equality.is_satisfied());

        let mut witness = TestConstraintSystem::<Scalar>::new();
        let points = vec![
            allocate_point(witness.namespace(|| "first point"), generator).expect("first point"),
            allocate_point(witness.namespace(|| "second point"), generator).expect("second point"),
        ];
        let scalars = vec![
            allocate_bits(
                witness.namespace(|| "first scalar"),
                &bits(&BigUint::from(1u8)),
            ),
            allocate_bits(
                witness.namespace(|| "second scalar"),
                &bits(&BigUint::from(2u8)),
            ),
        ];
        let sum = msm_points(witness.namespace(|| "MSM"), &points, &scalars).expect("MSM");
        let triple = add_point_values(generator, add_point_values(generator, generator));
        let expected =
            allocate_point(witness.namespace(|| "expected"), triple).expect("expected point");
        sum.enforce_equal(witness.namespace(|| "expected equality"), &expected)
            .expect("MSM equality");
        assert!(witness.is_satisfied());

        let mut msm = ShapeCS::<Secq256k1Sha256Engine>::new();
        let points = vec![
            allocate_point(msm.namespace(|| "first point"), generator).expect("first point"),
            allocate_point(msm.namespace(|| "second point"), generator).expect("second point"),
        ];
        let scalars = vec![
            allocate_bits(msm.namespace(|| "first scalar"), &bits(&BigUint::from(1u8))),
            allocate_bits(
                msm.namespace(|| "second scalar"),
                &bits(&BigUint::from(2u8)),
            ),
        ];
        msm_points(msm.namespace(|| "MSM"), &points, &scalars).expect("MSM");
        assert_eq!((msm.num_aux(), msm.num_constraints()), (5_367, 5_383));
    }

    #[test]
    fn computed_encoding_matches_native_point() {
        for value in [add_point_values(generator(), generator()), identity()] {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let point = allocate_point(cs.namespace(|| "point"), value).expect("point");
            let encoded = encode_computed_point(cs.namespace(|| "encoded"), point)
                .expect("computed encoding");
            let witness = SecpEncodedPointWitness::from_point_value(value);
            assert_eq!(encoded.prefix_byte().value(), witness.encoded[0]);
            assert_eq!(
                encoded.x_bytes().each_ref().map(NovaByte::value).as_slice(),
                &witness.encoded[1..]
            );
            let mut x = scalar_to_canonical(&value.x);
            x.reverse();
            assert_eq!(encoded.x_bytes().each_ref().map(NovaByte::value), x);
            assert!(cs.is_satisfied());
        }
    }
}
