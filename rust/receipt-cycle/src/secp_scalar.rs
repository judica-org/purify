//! Canonical secp256k1 scalar arithmetic inside the outer base field.
//!
//! Values are represented as four little-endian 64-bit limbs and constrained
//! to be smaller than the secp256k1 group order. Multiplication uses bounded
//! integer carry equations. Every carry equation has magnitude below 2^132,
//! far below the outer field modulus, so equality in the outer field cannot
//! hide an integer wrap.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::relation_builder::{Builder, Expression};
use crate::sha256_builder::Scalar255;
use crate::{ReceiptCycleError, Scalar};

const LIMB_BITS: usize = 64;
const SCALAR_BITS: usize = 256;
const LIMB_COUNT: usize = 4;
const PRODUCT_LIMBS: usize = 8;
const PRODUCT_CARRY_BITS: usize = 67;

const ORDER_N_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const ORDER_N_LIMBS: [u64; LIMB_COUNT] = [
    0xbfd2_5e8c_d036_4141,
    0xbaae_dce6_af48_a03b,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
];

const FIELD_P_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// Raw big-endian witness bytes for one secp256k1 scalar.
///
/// Construction intentionally accepts every 256-bit string. The relation,
/// rather than this transport type, enforces canonicality below the group
/// order. This lets negative tests exercise noncanonical prover witnesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpScalarWitness {
    /// Big-endian unsigned integer bytes.
    pub bytes: [u8; 32],
}

impl SecpScalarWitness {
    /// Constructs a witness from exact big-endian bytes.
    pub const fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Constructs a small canonical witness.
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self { bytes }
    }

    fn integer(self) -> BigUint {
        BigUint::from_bytes_be(&self.bytes)
    }
}

/// Canonical big-endian witness for the secp256k1 coordinate field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinateFieldWitness {
    /// Big-endian unsigned integer bytes in `[0, p - 1]`.
    pub bytes: [u8; 32],
}

impl CoordinateFieldWitness {
    /// Constructs a witness from exact big-endian bytes.
    pub const fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Constructs a small canonical witness.
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self { bytes }
    }
}

/// Parses a canonical big-endian secp256k1 coordinate-field value.
pub(crate) fn coordinate_field_value(mut bytes: [u8; 32]) -> Result<Scalar, ReceiptCycleError> {
    bytes.reverse();
    Secq256k1Cycle::scalar_from_canonical(&bytes).ok_or(ReceiptCycleError::Malformed(
        "noncanonical coordinate field element",
    ))
}

/// Parses the canonical integer embedding of one secp256k1 scalar.
pub(crate) fn canonical_scalar_value(
    witness: SecpScalarWitness,
) -> Result<Scalar, ReceiptCycleError> {
    if witness.bytes >= ORDER_N_BE {
        return Err(ReceiptCycleError::Malformed("noncanonical secp scalar"));
    }
    coordinate_field_value(witness.bytes)
}

#[derive(Clone)]
pub(crate) struct SecpScalarVar {
    limbs: [Expression; LIMB_COUNT],
    pub(crate) bits: Vec<Expression>,
    limb_values: [u64; LIMB_COUNT],
    value: BigUint,
}

impl SecpScalarVar {
    /// Returns the assignment integer used to derive subsequent witnesses.
    pub(crate) fn integer(&self) -> &BigUint {
        &self.value
    }
}

#[derive(Clone)]
struct ColumnTerm {
    expression: Expression,
    value: BigUint,
}

type Columns = Vec<Vec<ColumnTerm>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MulFault {
    None,
    Quotient,
    LeftCarry,
    RightCarry,
}

fn order_n() -> BigUint {
    BigUint::from_bytes_be(&ORDER_N_BE)
}

fn order_bit(index: usize) -> bool {
    let byte = ORDER_N_BE[31 - index / 8];
    ((byte >> (index % 8)) & 1) != 0
}

fn scalar_pow2(exponent: usize) -> Scalar {
    let mut out = Scalar::ONE;
    for _ in 0..exponent {
        out = out + out;
    }
    out
}

fn scalar_integer(value: Scalar) -> BigUint {
    BigUint::from_bytes_le(&Secq256k1Cycle::scalar_to_canonical(&value))
}

fn limbs(value: &BigUint, count: usize) -> Result<Vec<u64>, ReceiptCycleError> {
    let mut out = value.to_u64_digits();
    if out.len() > count {
        return Err(ReceiptCycleError::Malformed("integer limb width"));
    }
    out.resize(count, 0);
    Ok(out)
}

fn allocate_unsigned(
    builder: &mut Builder,
    value: &BigUint,
    width: usize,
) -> Result<Expression, ReceiptCycleError> {
    if value.bits() > width as u64 {
        return Err(ReceiptCycleError::Malformed("bounded integer width"));
    }
    let mut expression = Expression::constant(Scalar::ZERO);
    let mut coefficient = Scalar::ONE;
    for index in 0..width {
        let bit = builder.allocate_boolean(value.bit(index as u64));
        expression = expression.add(&bit.scale(coefficient));
        coefficient = coefficient + coefficient;
    }
    Ok(expression)
}

fn allocate_uint256(
    builder: &mut Builder,
    value: BigUint,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    if value.bits() > SCALAR_BITS as u64 {
        return Err(ReceiptCycleError::Malformed("uint256 width"));
    }
    let limb_vec = limbs(&value, LIMB_COUNT)?;
    let limb_values: [u64; LIMB_COUNT] = limb_vec
        .try_into()
        .map_err(|_| ReceiptCycleError::Malformed("uint256 limbs"))?;
    let mut bits = Vec::with_capacity(SCALAR_BITS);
    for index in 0..SCALAR_BITS {
        bits.push(builder.allocate_boolean(value.bit(index as u64)));
    }
    let limbs = std::array::from_fn(|limb| {
        let mut expression = Expression::constant(Scalar::ZERO);
        let mut coefficient = Scalar::ONE;
        for bit in &bits[limb * LIMB_BITS..(limb + 1) * LIMB_BITS] {
            expression = expression.add(&bit.clone().scale(coefficient));
            coefficient = coefficient + coefficient;
        }
        expression
    });
    Ok(SecpScalarVar {
        limbs,
        bits,
        limb_values,
        value,
    })
}

/// Embeds a canonical secp scalar in the outer coordinate field.
pub(crate) fn embedded_integer(value: &SecpScalarVar) -> Expression {
    let mut out = Expression::constant(Scalar::ZERO);
    let mut coefficient = Scalar::ONE;
    for bit in &value.bits {
        out = out.add(&bit.clone().scale(coefficient));
        coefficient = coefficient + coefficient;
    }
    out
}

/// Reuse one SHA-256 digest's low 255 bits as a nonzero secp scalar.
///
/// The bit width is already below the secp256k1 group order, so this only
/// binds the typed scalar representation and enforces the protocol's nonzero
/// challenge rule. No two-lane rejection selector is needed.
pub(crate) fn nonzero_scalar_from_sha256(
    builder: &mut Builder,
    challenge: &Scalar255,
) -> SecpScalarVar {
    let value = scalar_integer(challenge.value());
    let mut bits = challenge
        .bits_le()
        .iter()
        .map(|bit| bit.expression().clone())
        .collect::<Vec<_>>();
    bits.push(Expression::constant(Scalar::ZERO));

    let inverse = builder
        .allocate(Option::<Scalar>::from(challenge.value().invert()).unwrap_or(Scalar::ZERO));
    let product = builder.multiply(challenge.expression(), &inverse);
    builder.constrain_equal(&product, &Expression::constant(Scalar::ONE));

    let scalar_limbs = std::array::from_fn(|limb| {
        let mut expression = Expression::constant(Scalar::ZERO);
        let mut coefficient = Scalar::ONE;
        for bit in &bits[limb * LIMB_BITS..(limb + 1) * LIMB_BITS] {
            expression = expression.add(&bit.clone().scale(coefficient));
            coefficient = coefficient + coefficient;
        }
        expression
    });
    let limb_values = limbs(&value, LIMB_COUNT)
        .expect("a 255-bit SHA challenge has four limbs")
        .try_into()
        .expect("the SHA challenge limb count is fixed");
    SecpScalarVar {
        limbs: scalar_limbs,
        bits,
        limb_values,
        value,
    }
}

/// Constructs a typed small constant without allocating prover wires.
pub(crate) fn constant_scalar(value: u64) -> SecpScalarVar {
    let bits = (0..SCALAR_BITS)
        .map(|index| {
            let bit = if index < 64 { (value >> index) & 1 } else { 0 };
            Expression::constant(Scalar::from(bit))
        })
        .collect();
    let limbs = std::array::from_fn(|index| {
        Expression::constant(Scalar::from(if index == 0 { value } else { 0 }))
    });
    SecpScalarVar {
        limbs,
        bits,
        limb_values: [value, 0, 0, 0],
        value: BigUint::from(value),
    }
}

/// Constructs a typed canonical constant without allocating prover wires.
pub(crate) fn constant_scalar_witness(
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let value = witness.integer();
    if value >= order_n() {
        return Err(ReceiptCycleError::Malformed("noncanonical constant scalar"));
    }
    let limb_vec = limbs(&value, LIMB_COUNT)?;
    let limb_values: [u64; LIMB_COUNT] = limb_vec
        .try_into()
        .map_err(|_| ReceiptCycleError::Malformed("constant scalar limbs"))?;
    let bits = (0..SCALAR_BITS)
        .map(|index| {
            Expression::constant(if value.bit(index as u64) {
                Scalar::ONE
            } else {
                Scalar::ZERO
            })
        })
        .collect();
    let limbs = std::array::from_fn(|index| Expression::constant(Scalar::from(limb_values[index])));
    Ok(SecpScalarVar {
        limbs,
        bits,
        limb_values,
        value,
    })
}

fn constrain_less_than_order(builder: &mut Builder, value: &SecpScalarVar) {
    let one = Expression::constant(Scalar::ONE);
    let mut equal = one.clone();
    let mut less = Expression::constant(Scalar::ZERO);
    for index in (0..SCALAR_BITS).rev() {
        let equal_and_bit = builder.multiply(&equal, &value.bits[index]);
        if order_bit(index) {
            less = less.add(&equal.clone().sub(&equal_and_bit));
            equal = equal_and_bit;
        } else {
            builder.constrain_zero(equal_and_bit.clone());
            equal = equal.sub(&equal_and_bit);
        }
    }
    builder.constrain_equal(&less, &one);
}

pub(crate) fn allocate_canonical_scalar(
    builder: &mut Builder,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let value = allocate_uint256(builder, witness.integer())?;
    constrain_less_than_order(builder, &value);
    Ok(value)
}

fn empty_columns(count: usize) -> Columns {
    (0..count).map(|_| Vec::new()).collect()
}

fn push_term(columns: &mut Columns, index: usize, expression: Expression, value: BigUint) {
    columns[index].push(ColumnTerm { expression, value });
}

fn allocate_wide_limbs(
    builder: &mut Builder,
    value: &BigUint,
    count: usize,
) -> Result<Vec<Expression>, ReceiptCycleError> {
    limbs(value, count)?
        .into_iter()
        .map(|limb| allocate_unsigned(builder, &BigUint::from(limb), LIMB_BITS))
        .collect()
}

fn constrain_normalized(
    builder: &mut Builder,
    columns: &Columns,
    output: &[Expression],
    carry_bits: usize,
    faulty_carry: bool,
) -> Result<(), ReceiptCycleError> {
    if columns.len() != output.len() || columns.is_empty() {
        return Err(ReceiptCycleError::Malformed("normalization shape"));
    }
    let radix = scalar_pow2(LIMB_BITS);
    let radix_integer = BigUint::one() << LIMB_BITS;
    let mut carry_expression = Expression::constant(Scalar::ZERO);
    let mut carry_value = BigUint::zero();
    for index in 0..columns.len() {
        let mut left = carry_expression.clone();
        let mut column_value = carry_value.clone();
        for term in &columns[index] {
            left = left.add(&term.expression);
            column_value += &term.value;
        }
        if index + 1 == columns.len() {
            builder.constrain_equal(&left, &output[index]);
            continue;
        }
        let next_carry = &column_value >> LIMB_BITS;
        let witness = if faulty_carry && index == 0 {
            &next_carry + BigUint::one()
        } else {
            next_carry.clone()
        };
        let next_expression = allocate_unsigned(builder, &witness, carry_bits)?;
        let right = output[index]
            .clone()
            .add(&next_expression.clone().scale(radix));
        builder.constrain_equal(&left, &right);
        carry_expression = next_expression;
        carry_value = next_carry;
        debug_assert!(column_value < (radix_integer.clone() << carry_bits));
    }
    Ok(())
}

fn product_columns(builder: &mut Builder, left: &SecpScalarVar, right: &SecpScalarVar) -> Columns {
    let mut columns = empty_columns(PRODUCT_LIMBS);
    for i in 0..LIMB_COUNT {
        for j in 0..LIMB_COUNT {
            let expression = builder.multiply(&left.limbs[i], &right.limbs[j]);
            let value = BigUint::from(left.limb_values[i]) * BigUint::from(right.limb_values[j]);
            push_term(&mut columns, i + j, expression, value);
        }
    }
    columns
}

fn quotient_remainder_columns(quotient: &SecpScalarVar, remainder: &SecpScalarVar) -> Columns {
    let mut columns = empty_columns(PRODUCT_LIMBS);
    for i in 0..LIMB_COUNT {
        for (j, modulus_limb) in ORDER_N_LIMBS.iter().enumerate() {
            let expression = quotient.limbs[i].clone().scale(Scalar::from(*modulus_limb));
            let value = BigUint::from(quotient.limb_values[i]) * BigUint::from(*modulus_limb);
            push_term(&mut columns, i + j, expression, value);
        }
        push_term(
            &mut columns,
            i,
            remainder.limbs[i].clone(),
            BigUint::from(remainder.limb_values[i]),
        );
    }
    columns
}

fn constrain_modular_product(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    remainder: &SecpScalarVar,
    fault: MulFault,
) -> Result<(), ReceiptCycleError> {
    let product = &left.value * &right.value;
    let mut quotient = &product / order_n();
    if fault == MulFault::Quotient {
        quotient += BigUint::one();
    }
    let quotient = allocate_uint256(builder, quotient)?;
    // Canonical inputs and remainder make q < n a consequence of the
    // integer equality: a*b < n^2 and q*n <= a*b. A 256-bit range is enough
    // here; a second comparator would only restate that consequence.
    let output = allocate_wide_limbs(builder, &product, PRODUCT_LIMBS)?;
    let left_columns = product_columns(builder, left, right);
    let right_columns = quotient_remainder_columns(&quotient, remainder);
    constrain_normalized(
        builder,
        &left_columns,
        &output,
        PRODUCT_CARRY_BITS,
        fault == MulFault::LeftCarry,
    )?;
    constrain_normalized(
        builder,
        &right_columns,
        &output,
        PRODUCT_CARRY_BITS,
        fault == MulFault::RightCarry,
    )
}

fn constrain_modular_sum(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    expected: &SecpScalarVar,
) -> Result<(), ReceiptCycleError> {
    let reduction = builder.allocate_boolean(left.integer() + right.integer() >= order_n());
    let modulus = modulus_var();
    let output_value = left.integer() + right.integer();
    let output = allocate_wide_limbs(builder, &output_value, 5)?;
    let left_columns = linear_columns(builder, &[(left, None), (right, None)], 5);
    let right_columns = linear_columns(
        builder,
        &[(expected, None), (&modulus, Some(&reduction))],
        5,
    );
    constrain_normalized(builder, &left_columns, &output, 1, false)?;
    constrain_normalized(builder, &right_columns, &output, 1, false)
}

fn constrain_modular_difference(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    expected: &SecpScalarVar,
) -> Result<(), ReceiptCycleError> {
    let reduction = builder.allocate_boolean(left.integer() < right.integer());
    let modulus = modulus_var();
    let offset = if left.value < right.value {
        order_n()
    } else {
        BigUint::zero()
    };
    let output_value = left.integer() + offset;
    let output = allocate_wide_limbs(builder, &output_value, 5)?;
    let left_columns = linear_columns(builder, &[(left, None), (&modulus, Some(&reduction))], 5);
    let right_columns = linear_columns(builder, &[(right, None), (expected, None)], 5);
    constrain_normalized(builder, &left_columns, &output, 1, false)?;
    constrain_normalized(builder, &right_columns, &output, 1, false)
}

/// Constrains equality without exposing the scalar's limb representation.
pub(crate) fn constrain_scalar_equal(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
) {
    for index in 0..LIMB_COUNT {
        builder.constrain_equal(&left.limbs[index], &right.limbs[index]);
    }
}

/// Allocates a typed output and constrains `left * right` modulo the order.
pub(crate) fn multiply_scalars(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let output = allocate_canonical_scalar(builder, witness)?;
    constrain_modular_product(builder, left, right, &output, MulFault::None)?;
    Ok(output)
}

/// Allocates a typed output and constrains `left + right` modulo the order.
pub(crate) fn add_scalars(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let output = allocate_canonical_scalar(builder, witness)?;
    constrain_modular_sum(builder, left, right, &output)?;
    Ok(output)
}

/// Allocates a typed output and constrains `left - right` modulo the order.
pub(crate) fn subtract_scalars(
    builder: &mut Builder,
    left: &SecpScalarVar,
    right: &SecpScalarVar,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let output = allocate_canonical_scalar(builder, witness)?;
    constrain_modular_difference(builder, left, right, &output)?;
    Ok(output)
}

/// Allocates a typed inverse and constrains a nonzero input.
pub(crate) fn invert_scalar(
    builder: &mut Builder,
    value: &SecpScalarVar,
    witness: SecpScalarWitness,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let inverse = allocate_canonical_scalar(builder, witness)?;
    let one = constant_scalar(1);
    constrain_modular_product(builder, value, &inverse, &one, MulFault::None)?;
    Ok(inverse)
}

fn linear_columns(
    builder: &mut Builder,
    terms: &[(&SecpScalarVar, Option<&Expression>)],
    count: usize,
) -> Columns {
    let mut columns = empty_columns(count);
    for (value, selector) in terms {
        for index in 0..LIMB_COUNT {
            let (expression, integer) = match selector {
                Some(selector) => (
                    builder.multiply(&value.limbs[index], selector),
                    BigUint::from(value.limb_values[index])
                        * if selector.value() == Scalar::ONE {
                            BigUint::one()
                        } else {
                            BigUint::zero()
                        },
                ),
                None => (
                    value.limbs[index].clone(),
                    BigUint::from(value.limb_values[index]),
                ),
            };
            push_term(&mut columns, index, expression, integer);
        }
    }
    columns
}

fn modulus_var() -> SecpScalarVar {
    let bits = (0..SCALAR_BITS)
        .map(|index| Expression::constant(Scalar::from(order_bit(index) as u64)))
        .collect();
    let limbs = ORDER_N_LIMBS.map(|limb| Expression::constant(Scalar::from(limb)));
    SecpScalarVar {
        limbs,
        bits,
        limb_values: ORDER_N_LIMBS,
        value: order_n(),
    }
}

fn build_multiplication_with_fault(
    left: SecpScalarWitness,
    right: SecpScalarWitness,
    expected: SecpScalarWitness,
    fault: MulFault,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let left = allocate_canonical_scalar(&mut builder, left)?;
    let right = allocate_canonical_scalar(&mut builder, right)?;
    if fault == MulFault::None {
        multiply_scalars(&mut builder, &left, &right, expected)?;
    } else {
        let expected = allocate_canonical_scalar(&mut builder, expected)?;
        constrain_modular_product(&mut builder, &left, &right, &expected, fault)?;
    }
    builder.finish()
}

/// Builds `left * right = expected (mod n)`.
pub fn build_scalar_multiplication_relation(
    left: SecpScalarWitness,
    right: SecpScalarWitness,
    expected: SecpScalarWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    build_multiplication_with_fault(left, right, expected, MulFault::None)
}

/// Builds `left + right = expected (mod n)`.
pub fn build_scalar_addition_relation(
    left: SecpScalarWitness,
    right: SecpScalarWitness,
    expected: SecpScalarWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let left = allocate_canonical_scalar(&mut builder, left)?;
    let right = allocate_canonical_scalar(&mut builder, right)?;
    add_scalars(&mut builder, &left, &right, expected)?;
    builder.finish()
}

/// Builds `left - right = expected (mod n)`.
pub fn build_scalar_subtraction_relation(
    left: SecpScalarWitness,
    right: SecpScalarWitness,
    expected: SecpScalarWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let left = allocate_canonical_scalar(&mut builder, left)?;
    let right = allocate_canonical_scalar(&mut builder, right)?;
    subtract_scalars(&mut builder, &left, &right, expected)?;
    builder.finish()
}

/// Builds `value * inverse = 1 (mod n)`.
pub fn build_scalar_inverse_relation(
    value: SecpScalarWitness,
    inverse: SecpScalarWitness,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    let mut builder = Builder::default();
    let value = allocate_canonical_scalar(&mut builder, value)?;
    invert_scalar(&mut builder, &value, inverse)?;
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_builder::{Bit, Scalar255};
    use crate::{proof_wire_len, prove, verify};

    fn witness(value: &BigUint) -> SecpScalarWitness {
        let encoded = value.to_bytes_be();
        assert!(encoded.len() <= 32);
        let mut bytes = [0u8; 32];
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        SecpScalarWitness::from_bytes_be(bytes)
    }

    fn gate_count(circuit: &[u8]) -> u32 {
        u32::from_le_bytes(circuit[1..5].try_into().expect("gate count"))
    }

    #[test]
    fn native_value_parsers_enforce_the_coordinate_and_scalar_moduli() {
        assert_eq!(
            coordinate_field_value(CoordinateFieldWitness::from_u64(7).bytes)
                .expect("small coordinate"),
            Scalar::from(7)
        );
        assert_eq!(
            canonical_scalar_value(SecpScalarWitness::from_u64(9)).expect("small scalar"),
            Scalar::from(9)
        );
        assert!(coordinate_field_value(FIELD_P_BE).is_err());
        assert!(canonical_scalar_value(SecpScalarWitness::from_bytes_be(ORDER_N_BE)).is_err());
    }

    fn accepts(
        relation: Result<(Vec<u8>, Vec<u8>), ReceiptCycleError>,
        marker: u8,
    ) -> (Vec<u8>, u32) {
        let (circuit, assignment) = relation.expect("relation");
        let statement = b"secp scalar arithmetic foundation";
        let proof = prove(&circuit, &assignment, statement, [marker; 32]).expect("prove");
        verify(&circuit, statement, &proof).expect("verify");
        assert_eq!(proof.len(), proof_wire_len(&circuit).expect("size"));
        let count = gate_count(&circuit);
        (circuit, count)
    }

    fn rejects(relation: Result<(Vec<u8>, Vec<u8>), ReceiptCycleError>, marker: u8) {
        let (circuit, assignment) = relation.expect("relation");
        let statement = b"secp scalar arithmetic foundation";
        let proof =
            prove(&circuit, &assignment, statement, [marker; 32]).expect("prove malformed witness");
        assert!(verify(&circuit, statement, &proof).is_err());
    }

    fn build_composed_relation(
        left: SecpScalarWitness,
        right: SecpScalarWitness,
        addend: SecpScalarWitness,
        subtrahend: SecpScalarWitness,
        expected: SecpScalarWitness,
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let left = allocate_canonical_scalar(&mut builder, left)?;
        let right = allocate_canonical_scalar(&mut builder, right)?;
        let addend = allocate_canonical_scalar(&mut builder, addend)?;
        let subtrahend = allocate_canonical_scalar(&mut builder, subtrahend)?;
        let modulus = order_n();
        let product_value = (left.integer() * right.integer()) % &modulus;
        let product = multiply_scalars(&mut builder, &left, &right, witness(&product_value))?;
        let sum_value = (product.integer() + addend.integer()) % &modulus;
        let sum = add_scalars(&mut builder, &product, &addend, witness(&sum_value))?;
        let difference_value = (sum.integer() + &modulus - subtrahend.integer()) % &modulus;
        let difference =
            subtract_scalars(&mut builder, &sum, &subtrahend, witness(&difference_value))?;
        let inverse_value = difference
            .integer()
            .modpow(&(&modulus - BigUint::from(2u8)), &modulus);
        let inverse = invert_scalar(&mut builder, &difference, witness(&inverse_value))?;
        let round_trip_value = (difference.integer() * inverse.integer()) % &modulus;
        let round_trip = multiply_scalars(
            &mut builder,
            &difference,
            &inverse,
            witness(&round_trip_value),
        )?;
        let expected = allocate_canonical_scalar(&mut builder, expected)?;
        constrain_scalar_equal(&mut builder, &round_trip, &expected);
        builder.finish()
    }

    #[test]
    fn multiplication_is_canonical_and_shape_independent() {
        let order = order_n();
        let maximum = &order - BigUint::one();
        let (boundary, gates) = accepts(
            build_scalar_multiplication_relation(
                witness(&maximum),
                witness(&maximum),
                SecpScalarWitness::from_u64(1),
            ),
            0x31,
        );
        let (zero, zero_gates) = accepts(
            build_scalar_multiplication_relation(
                SecpScalarWitness::from_u64(0),
                witness(&maximum),
                SecpScalarWitness::from_u64(0),
            ),
            0x32,
        );
        assert_eq!(boundary, zero);
        assert_eq!(gates, zero_gates);
        assert_eq!(gates, 3_258);
        println!("receipt_scalar_mul_gates={gates}");

        rejects(
            build_scalar_multiplication_relation(
                witness(&order),
                SecpScalarWitness::from_u64(1),
                SecpScalarWitness::from_u64(0),
            ),
            0x33,
        );
        rejects(
            build_scalar_multiplication_relation(
                SecpScalarWitness::from_u64(3),
                SecpScalarWitness::from_u64(4),
                SecpScalarWitness::from_u64(13),
            ),
            0x34,
        );
    }

    #[test]
    fn quotient_and_carry_witnesses_are_constrained() {
        let left = SecpScalarWitness::from_u64(19);
        let right = SecpScalarWitness::from_u64(23);
        let expected = SecpScalarWitness::from_u64(437);
        rejects(
            build_multiplication_with_fault(left, right, expected, MulFault::Quotient),
            0x41,
        );
        rejects(
            build_multiplication_with_fault(left, right, expected, MulFault::LeftCarry),
            0x42,
        );
        rejects(
            build_multiplication_with_fault(left, right, expected, MulFault::RightCarry),
            0x43,
        );
        let (honest, _) = build_multiplication_with_fault(left, right, expected, MulFault::None)
            .expect("honest shape");
        for fault in [
            MulFault::Quotient,
            MulFault::LeftCarry,
            MulFault::RightCarry,
        ] {
            let (changed, _) =
                build_multiplication_with_fault(left, right, expected, fault).expect("fault shape");
            assert_eq!(honest, changed);
        }
    }

    #[test]
    fn addition_and_subtraction_reduce_at_the_order() {
        let maximum = order_n() - BigUint::one();
        let (addition, add_gates) = accepts(
            build_scalar_addition_relation(
                witness(&maximum),
                SecpScalarWitness::from_u64(1),
                SecpScalarWitness::from_u64(0),
            ),
            0x51,
        );
        let (addition_shape, _) = build_scalar_addition_relation(
            SecpScalarWitness::from_u64(0),
            SecpScalarWitness::from_u64(0),
            SecpScalarWitness::from_u64(0),
        )
        .expect("addition shape");
        assert_eq!(addition, addition_shape);
        assert_eq!(add_gates, 1_869);
        println!("receipt_scalar_add_gates={add_gates}");

        let (subtraction, sub_gates) = accepts(
            build_scalar_subtraction_relation(
                SecpScalarWitness::from_u64(0),
                SecpScalarWitness::from_u64(1),
                witness(&maximum),
            ),
            0x52,
        );
        let (subtraction_shape, _) = build_scalar_subtraction_relation(
            SecpScalarWitness::from_u64(9),
            SecpScalarWitness::from_u64(2),
            SecpScalarWitness::from_u64(7),
        )
        .expect("subtraction shape");
        assert_eq!(subtraction, subtraction_shape);
        assert_eq!(sub_gates, 1_869);
        println!("receipt_scalar_sub_gates={sub_gates}");

        rejects(
            build_scalar_addition_relation(
                witness(&maximum),
                SecpScalarWitness::from_u64(1),
                SecpScalarWitness::from_u64(1),
            ),
            0x53,
        );
        rejects(
            build_scalar_subtraction_relation(
                SecpScalarWitness::from_u64(0),
                SecpScalarWitness::from_u64(1),
                SecpScalarWitness::from_u64(0),
            ),
            0x54,
        );
    }

    #[test]
    fn inverse_requires_a_nonzero_correct_scalar() {
        let order = order_n();
        let inverse_two = (&order + BigUint::one()) >> 1;
        let (relation, gates) = accepts(
            build_scalar_inverse_relation(SecpScalarWitness::from_u64(2), witness(&inverse_two)),
            0x61,
        );
        assert_eq!(gates, 2_746);
        println!("receipt_scalar_inverse_gates={gates}");
        let maximum = &order - BigUint::one();
        let (other_relation, _) =
            build_scalar_inverse_relation(witness(&maximum), witness(&maximum))
                .expect("inverse shape");
        assert_eq!(relation, other_relation);
        rejects(
            build_scalar_inverse_relation(
                SecpScalarWitness::from_u64(0),
                SecpScalarWitness::from_u64(0),
            ),
            0x62,
        );
        rejects(
            build_scalar_inverse_relation(
                SecpScalarWitness::from_u64(2),
                SecpScalarWitness::from_u64(3),
            ),
            0x63,
        );
    }

    #[test]
    fn typed_scalar_operations_compose_at_modulus_boundaries() {
        let maximum = order_n() - BigUint::one();
        let (boundary, gates) = accepts(
            build_composed_relation(
                witness(&maximum),
                witness(&maximum),
                witness(&maximum),
                SecpScalarWitness::from_u64(1),
                SecpScalarWitness::from_u64(1),
            ),
            0x64,
        );
        let (ordinary, ordinary_gates) = accepts(
            build_composed_relation(
                SecpScalarWitness::from_u64(2),
                SecpScalarWitness::from_u64(3),
                SecpScalarWitness::from_u64(4),
                SecpScalarWitness::from_u64(5),
                SecpScalarWitness::from_u64(1),
            ),
            0x65,
        );
        assert_eq!(boundary, ordinary);
        assert_eq!(gates, ordinary_gates);
        eprintln!(
            "receipt_scalar_composition_gates={gates} proof_bytes={}",
            proof_wire_len(&boundary).expect("composition proof size")
        );
    }

    #[test]
    fn typed_scalar_composition_rejects_zero_inverse_and_wrong_result() {
        rejects(
            build_composed_relation(
                SecpScalarWitness::from_u64(2),
                SecpScalarWitness::from_u64(3),
                SecpScalarWitness::from_u64(4),
                SecpScalarWitness::from_u64(10),
                SecpScalarWitness::from_u64(1),
            ),
            0x66,
        );
        rejects(
            build_composed_relation(
                SecpScalarWitness::from_u64(2),
                SecpScalarWitness::from_u64(3),
                SecpScalarWitness::from_u64(4),
                SecpScalarWitness::from_u64(5),
                SecpScalarWitness::from_u64(2),
            ),
            0x67,
        );
    }

    fn build_sha256_challenge_relation(value: u64) -> (Vec<u8>, Vec<u8>, BigUint) {
        let mut builder = Builder::default();
        let bits = std::array::from_fn(|index| {
            let bit = index < 64 && (value >> index) & 1 != 0;
            Bit::from_constrained_expression(builder.allocate_boolean(bit), bit)
        });
        let digest = Scalar255::from_constrained_bits(bits);
        let scalar = nonzero_scalar_from_sha256(&mut builder, &digest);
        let selected = scalar.integer().clone();
        let (circuit, assignment) = builder.finish().expect("SHA challenge relation");
        (circuit, assignment, selected)
    }

    #[test]
    fn sha256_challenge_reuses_bits_and_rejects_zero() {
        let (valid_circuit, valid_assignment, selected) = build_sha256_challenge_relation(7);
        assert_eq!(selected, BigUint::from(7u8));
        let (accepted, gates) = accepts(Ok((valid_circuit, valid_assignment)), 0x76);
        assert_eq!(gates, 257);

        let (zero_circuit, zero_assignment, selected) = build_sha256_challenge_relation(0);
        assert!(selected.is_zero());
        assert_eq!(accepted, zero_circuit);
        rejects(Ok((zero_circuit, zero_assignment)), 0x77);
    }
}
