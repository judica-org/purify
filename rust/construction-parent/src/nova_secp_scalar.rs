//! Canonical secp256k1 scalar arithmetic for direct Nova circuits.
//!
//! Nova's generic `BigNat` proves modular identities and limb bounds, but a
//! modular remainder is not necessarily canonical. This wrapper gives every
//! externally usable scalar one 256-bit decomposition and an explicit `< n`
//! proof. The same bits feed scalar multiplication and transcript encoding.

use ff::{Field, PrimeField};
use nova_snark::{
    frontend::{
        gadgets::{
            boolean::{AllocatedBit, Boolean},
            num::{AllocatedNum, Num},
        },
        ConstraintSystem, LinearCombination, SynthesisError,
    },
    gadgets::nonnative::bignat::{BigNat, BigNatParams},
};
use num_bigint::{BigInt, Sign};

use crate::{secp_constants::SECP256K1_SCALAR_ORDER_BE, secp_native::SecpScalarWitness, Scalar};

const LIMB_BITS: usize = 64;
const LIMB_COUNT: usize = 4;
const SCALAR_BITS: usize = LIMB_BITS * LIMB_COUNT;
const SHA_CHALLENGE_BITS: usize = SCALAR_BITS - 1;

#[derive(Clone)]
pub(crate) struct CanonicalSecpScalar {
    value: BigNat<Scalar>,
    bits_le: Vec<Boolean>,
}

impl CanonicalSecpScalar {
    pub(crate) fn bits_le(&self) -> &[Boolean] {
        &self.bits_le
    }

    pub(crate) fn integer(&self) -> Option<&BigInt> {
        self.value.value.as_ref()
    }

    /// Return the scalar's native-field embedding as one linear combination.
    ///
    /// Canonical secp256k1 scalars are below the direct circuit field modulus,
    /// so this grouping is injective.
    pub(crate) fn embedded(&self) -> LinearCombination<Scalar> {
        self.value.group_limbs(LIMB_COUNT).limbs[0].clone()
    }

    /// Materialize Boolean views only when a gadget requires allocated bits.
    /// Existing positive allocated bits are reused without another witness.
    pub(crate) fn allocated_bits_le<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<AllocatedBit>, SynthesisError> {
        self.bits_le
            .iter()
            .enumerate()
            .map(|(index, bit)| match bit {
                Boolean::Is(bit) => Ok(bit.clone()),
                Boolean::Not(source) => {
                    let output = AllocatedBit::alloc(
                        cs.namespace(|| format!("normalized bit {index}")),
                        source.get_value().map(|value| !value),
                    )?;
                    cs.enforce(
                        || format!("bind normalized bit {index}"),
                        |lc| lc + output.get_variable() + source.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + CS::one(),
                    );
                    Ok(output)
                }
                Boolean::Constant(value) => {
                    let output = AllocatedBit::alloc(
                        cs.namespace(|| format!("constant bit {index}")),
                        Some(*value),
                    )?;
                    Boolean::enforce_equal(
                        cs.namespace(|| format!("bind constant bit {index}")),
                        &Boolean::from(output.clone()),
                        bit,
                    )?;
                    Ok(output)
                }
            })
            .collect()
    }
}

fn integer(bytes: [u8; 32]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

fn scalar_order() -> BigInt {
    integer(SECP256K1_SCALAR_ORDER_BE)
}

#[cfg(test)]
fn witness(value: &BigInt) -> SecpScalarWitness {
    let (_, encoded) = value.to_bytes_be();
    assert!(encoded.len() <= 32, "secp256k1 scalar witness width");
    let mut bytes = [0u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    SecpScalarWitness::from_bytes_be(bytes)
}

fn order_bit(order: &BigInt, index: usize) -> bool {
    let (_, bytes) = order.to_bytes_le();
    bytes
        .get(index / 8)
        .is_some_and(|byte| (byte >> (index % 8)) & 1 == 1)
}

fn constant_bignat<CS: ConstraintSystem<Scalar>>(value: &BigInt) -> BigNat<Scalar> {
    let (_, bytes) = value.to_bytes_le();
    let mut limbs = [0u64; LIMB_COUNT];
    for (index, byte) in bytes.iter().copied().enumerate() {
        limbs[index / 8] |= u64::from(byte) << (8 * (index % 8));
    }
    let limb_values = limbs.map(Scalar::from).to_vec();
    BigNat {
        limbs: limb_values
            .iter()
            .map(|&limb| LinearCombination::zero() + (limb, CS::one()))
            .collect(),
        limb_values: Some(limb_values),
        value: Some(value.clone()),
        params: BigNatParams {
            min_bits: value.bits() as usize,
            max_word: (BigInt::from(1u8) << LIMB_BITS) - 1,
            limb_width: LIMB_BITS,
            n_limbs: LIMB_COUNT,
        },
    }
}

/// Represent one relation constant without allocating a witness.
///
/// The value is part of the circuit shape. Callers must not use this for
/// per-step data whose value belongs in the assignment.
pub(crate) fn constant_scalar<CS: ConstraintSystem<Scalar>>(
    value: SecpScalarWitness,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let value = integer(value.bytes);
    if value >= scalar_order() {
        return Err(synthesis_error("noncanonical constant scalar"));
    }
    let bits_le = (0..SCALAR_BITS)
        .map(|index| Boolean::constant(order_bit(&value, index)))
        .collect();
    Ok(CanonicalSecpScalar {
        value: constant_bignat::<CS>(&value),
        bits_le,
    })
}

fn enforce_less_than_order<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<(), SynthesisError> {
    if bits.len() != SCALAR_BITS {
        return Err(synthesis_error("canonical scalar bit length"));
    }
    let order = scalar_order();
    let mut equal =
        Num::zero().add_bool_with_coeff(CS::one(), &Boolean::constant(true), Scalar::ONE);
    let mut less = Num::zero();
    for index in (0..SCALAR_BITS).rev() {
        let input = &bits[index];
        let product = AllocatedNum::alloc(cs.namespace(|| format!("equal bit {index}")), || {
            let equal = equal.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(if input.get_value() == Some(true) {
                equal
            } else {
                Scalar::ZERO
            })
        })?;
        cs.enforce(
            || format!("equal and bit {index}"),
            |_| equal.lc(Scalar::ONE),
            |_| input.lc(CS::one(), Scalar::ONE),
            |lc| lc + product.get_variable(),
        );
        let product = Num::from(product);
        if order_bit(&order, index) {
            less = less.add(&equal.add(&product.clone().scale(-Scalar::ONE)));
            equal = product;
        } else {
            cs.enforce(
                || format!("order zero bit {index}"),
                |_| product.lc(Scalar::ONE),
                |lc| lc + CS::one(),
                |lc| lc,
            );
            equal = equal.add(&product.scale(-Scalar::ONE));
        }
    }
    cs.enforce(
        || "canonical scalar",
        |_| less.lc(Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );
    Ok(())
}

fn canonicalize<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: BigNat<Scalar>,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let bits_le = value
        .decompose_allocated(cs.namespace(|| "scalar bits"))?
        .into_iter()
        .map(Boolean::from)
        .collect::<Vec<_>>();
    enforce_less_than_order(cs.namespace(|| "less than order"), &bits_le)?;
    Ok(CanonicalSecpScalar { value, bits_le })
}

fn allocate_integer<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: Option<BigInt>,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let value = BigNat::alloc_from_nat(
        cs.namespace(|| "scalar"),
        || value.ok_or(SynthesisError::AssignmentMissing),
        LIMB_BITS,
        LIMB_COUNT,
    )?;
    canonicalize(cs.namespace(|| "canonical scalar"), value)
}

pub(crate) fn allocate_canonical_scalar<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    value: SecpScalarWitness,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    allocate_integer(cs, Some(integer(value.bytes)))
}

pub(crate) fn multiply_scalars<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    left: &CanonicalSecpScalar,
    right: &CanonicalSecpScalar,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let modulus = constant_bignat::<CS::Root>(&scalar_order());
    let (_, remainder) = left.value.mult_mod(
        cs.namespace(|| "multiply modulo order"),
        &right.value,
        &modulus,
    )?;
    canonicalize(cs.namespace(|| "canonical product"), remainder)
}

pub(crate) fn add_scalars<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    left: &CanonicalSecpScalar,
    right: &CanonicalSecpScalar,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let modulus = constant_bignat::<CS::Root>(&scalar_order());
    let sum = left.value.add(&right.value)?;
    let remainder = sum.red_mod(cs.namespace(|| "add modulo order"), &modulus)?;
    canonicalize(cs.namespace(|| "canonical sum"), remainder)
}

pub(crate) fn subtract_scalars<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    left: &CanonicalSecpScalar,
    right: &CanonicalSecpScalar,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let modulus = constant_bignat::<CS::Root>(&scalar_order());
    let remainder = left.value.sub_mod(
        cs.namespace(|| "subtract modulo order"),
        &right.value,
        &modulus,
    )?;
    canonicalize(cs.namespace(|| "canonical difference"), remainder)
}

pub(crate) fn invert_scalar<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &CanonicalSecpScalar,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let order = scalar_order();
    let exponent = &order - 2;
    let inverse_value = value.integer().map(|value| value.modpow(&exponent, &order));
    let inverse = allocate_integer(cs.namespace(|| "inverse"), inverse_value)?;
    let modulus = constant_bignat::<CS::Root>(&order);
    let (_, remainder) =
        value
            .value
            .mult_mod(cs.namespace(|| "inverse product"), &inverse.value, &modulus)?;
    remainder.equal_when_carried_regroup(
        cs.namespace(|| "inverse equals one"),
        &constant_bignat::<CS::Root>(&BigInt::from(1u8)),
    )?;
    Ok(inverse)
}

fn bignat_from_bits<CS: ConstraintSystem<Scalar>>(
    bits_le: &[Boolean],
) -> Result<BigNat<Scalar>, SynthesisError> {
    if bits_le.len() != SCALAR_BITS {
        return Err(synthesis_error("SHA scalar bit length"));
    }
    let mut limbs = Vec::with_capacity(LIMB_COUNT);
    let (limb_chunks, remainder) = bits_le.as_chunks::<LIMB_BITS>();
    if !remainder.is_empty() {
        return Err(synthesis_error("SHA scalar limb shape"));
    }
    for limb_bits in limb_chunks {
        let mut coefficient = Scalar::ONE;
        let mut limb = LinearCombination::zero();
        for bit in limb_bits {
            limb = limb + &bit.lc(CS::one(), coefficient);
            coefficient = coefficient.double();
        }
        limbs.push(limb);
    }
    let limb_values = limb_chunks
        .iter()
        .map(|limb_bits| {
            let mut coefficient = Scalar::ONE;
            limb_bits.iter().try_fold(Scalar::ZERO, |mut value, bit| {
                if bit.get_value()? {
                    value += coefficient;
                }
                coefficient = coefficient.double();
                Some(value)
            })
        })
        .collect::<Option<Vec<_>>>();
    let integer =
        bits_le
            .iter()
            .enumerate()
            .try_fold(BigInt::from(0u8), |mut value, (index, bit)| {
                if bit.get_value()? {
                    value += BigInt::from(1u8) << index;
                }
                Some(value)
            });
    Ok(BigNat {
        limbs,
        limb_values,
        value: integer,
        params: BigNatParams::new(LIMB_BITS, LIMB_COUNT),
    })
}

/// Reuse a low-255-bit SHA image as a canonical, nonzero scalar.
///
/// Adding one constant zero top bit proves the value is below `2^255 < n`,
/// so no second decomposition or less-than comparator is needed.
pub(crate) fn nonzero_scalar_from_sha255<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bits_le: &[Boolean],
) -> Result<CanonicalSecpScalar, SynthesisError> {
    if bits_le.len() != SHA_CHALLENGE_BITS {
        return Err(synthesis_error("SHA challenge bit length"));
    }
    assert!(
        scalar_order() > (BigInt::from(1u8) << SHA_CHALLENGE_BITS),
        "secp256k1 order exceeds every low-255-bit challenge"
    );
    let mut scalar_bits = bits_le.to_vec();
    scalar_bits.push(Boolean::constant(false));
    let value = bignat_from_bits::<CS::Root>(&scalar_bits)?;
    let packed = value.group_limbs(LIMB_COUNT).limbs[0].clone();
    let embedded = value
        .value
        .as_ref()
        .map(|integer| {
            Scalar::from_str_vartime(&integer.to_string())
                .ok_or_else(|| synthesis_error("SHA challenge field embedding"))
        })
        .transpose()?;
    let inverse_value =
        embedded.map(|value| Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO));
    let inverse = cs.alloc(
        || "nonzero challenge inverse",
        || inverse_value.ok_or(SynthesisError::AssignmentMissing),
    )?;
    cs.enforce(
        || "nonzero SHA challenge",
        |_| packed,
        |lc| lc + inverse,
        |lc| lc + CS::one(),
    );
    Ok(CanonicalSecpScalar {
        value,
        bits_le: scalar_bits,
    })
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

#[cfg(test)]
mod tests {
    use nova_snark::{
        frontend::{
            shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem, LinearCombination,
            Variable,
        },
        provider::Secq256k1Sha256Engine,
    };

    use super::*;

    type Metrics = (usize, usize);
    type OperationMetrics = (Metrics, Metrics, Metrics, Metrics);

    struct CountingCS {
        inner: TestConstraintSystem<Scalar>,
        auxiliary: usize,
        constraints: usize,
    }

    impl CountingCS {
        fn new() -> Self {
            Self {
                inner: TestConstraintSystem::new(),
                auxiliary: 0,
                constraints: 0,
            }
        }

        fn metrics(&self) -> (usize, usize) {
            (self.auxiliary, self.constraints)
        }

        fn is_satisfied(&self) -> bool {
            self.inner.is_satisfied()
        }
    }

    impl ConstraintSystem<Scalar> for CountingCS {
        type Root = Self;

        fn alloc<F, A, AR>(&mut self, annotation: A, value: F) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<Scalar, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
        {
            self.auxiliary += 1;
            self.inner.alloc(annotation, value)
        }

        fn alloc_input<F, A, AR>(
            &mut self,
            annotation: A,
            value: F,
        ) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<Scalar, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
        {
            self.inner.alloc_input(annotation, value)
        }

        fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
        where
            A: FnOnce() -> AR,
            AR: Into<String>,
            LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
            LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
            LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        {
            self.constraints += 1;
            self.inner.enforce(annotation, a, b, c);
        }

        fn push_namespace<NR, N>(&mut self, name: N)
        where
            NR: Into<String>,
            N: FnOnce() -> NR,
        {
            self.inner.push_namespace(name);
        }

        fn pop_namespace(&mut self) {
            self.inner.pop_namespace();
        }

        fn get_root(&mut self) -> &mut Self::Root {
            self
        }
    }

    fn synthesize_scalar_path<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        source_value: Option<bool>,
    ) -> Result<(), SynthesisError> {
        let left =
            allocate_canonical_scalar(cs.namespace(|| "left"), SecpScalarWitness::from_u64(7))?;
        let right =
            allocate_canonical_scalar(cs.namespace(|| "right"), SecpScalarWitness::from_u64(11))?;
        let product = multiply_scalars(cs.namespace(|| "product"), &left, &right)?;
        let sum = add_scalars(cs.namespace(|| "sum"), &product, &left)?;
        let difference = subtract_scalars(cs.namespace(|| "difference"), &sum, &right)?;
        let inverse = invert_scalar(cs.namespace(|| "inverse"), &difference)?;
        multiply_scalars(cs.namespace(|| "inverse check"), &difference, &inverse)?;

        let source = AllocatedBit::alloc(cs.namespace(|| "source"), source_value)?;
        let mut bits = vec![Boolean::constant(false); SHA_CHALLENGE_BITS];
        bits[0] = Boolean::Not(source);
        let challenge = nonzero_scalar_from_sha255(cs.namespace(|| "challenge"), &bits)?;
        challenge.allocated_bits_le(cs.namespace(|| "challenge bits"))?;
        Ok(())
    }

    fn assert_integer(value: &CanonicalSecpScalar, expected: &BigInt) {
        assert_eq!(value.integer(), Some(expected));
        assert_eq!(value.bits_le().len(), SCALAR_BITS);
        assert!(!value.embedded().is_empty());
    }

    #[test]
    fn scalar_operations_wrap_at_the_group_order() {
        let order = scalar_order();
        let maximum = &order - 1;
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let maximum_var = allocate_canonical_scalar(cs.namespace(|| "maximum"), witness(&maximum))
            .expect("maximum scalar");
        let two = allocate_canonical_scalar(cs.namespace(|| "two"), SecpScalarWitness::from_u64(2))
            .expect("two");
        let product =
            multiply_scalars(cs.namespace(|| "product"), &maximum_var, &two).expect("product");
        assert_integer(&product, &(&order - 2));
        let sum = add_scalars(cs.namespace(|| "sum"), &maximum_var, &two).expect("sum");
        assert_integer(&sum, &BigInt::from(1u8));
        let difference = subtract_scalars(cs.namespace(|| "difference"), &two, &maximum_var)
            .expect("difference");
        assert_integer(&difference, &BigInt::from(3u8));
        let inverse = invert_scalar(cs.namespace(|| "inverse"), &maximum_var).expect("inverse");
        assert_integer(&inverse, &maximum);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn scalar_rejects_noncanonical_order_and_zero_inverse() {
        let mut noncanonical = TestConstraintSystem::<Scalar>::new();
        allocate_canonical_scalar(
            noncanonical.namespace(|| "order"),
            SecpScalarWitness::from_bytes_be(SECP256K1_SCALAR_ORDER_BE),
        )
        .expect("bounded scalar witness");
        assert!(!noncanonical.is_satisfied());

        let mut zero = TestConstraintSystem::<Scalar>::new();
        let zero_value =
            allocate_canonical_scalar(zero.namespace(|| "zero"), SecpScalarWitness::from_u64(0))
                .expect("zero scalar");
        invert_scalar(zero.namespace(|| "inverse"), &zero_value).expect("inverse relation");
        assert!(!zero.is_satisfied());
    }

    #[test]
    fn protocol_constants_allocate_no_witnesses() {
        let mut cs = CountingCS::new();
        let before = cs.metrics();
        let two =
            constant_scalar::<CountingCS>(SecpScalarWitness::from_u64(2)).expect("constant scalar");
        assert_eq!(cs.metrics(), before);
        assert_integer(&two, &BigInt::from(2u8));
        assert_eq!(two.bits_le()[1].get_value(), Some(true));

        let seven =
            allocate_canonical_scalar(cs.namespace(|| "seven"), SecpScalarWitness::from_u64(7))
                .expect("seven");
        let product = multiply_scalars(cs.namespace(|| "product"), &seven, &two).expect("product");
        assert_integer(&product, &BigInt::from(14u8));
        assert!(cs.is_satisfied());

        assert!(
            constant_scalar::<CountingCS>(SecpScalarWitness::from_bytes_be(
                SECP256K1_SCALAR_ORDER_BE,
            ))
            .is_err()
        );
    }

    #[test]
    fn sha_import_reuses_boolean_bits_and_normalizes_views() {
        let mut cs = CountingCS::new();
        let source =
            AllocatedBit::alloc(cs.namespace(|| "source"), Some(false)).expect("source bit");
        let mut bits = vec![Boolean::constant(false); SHA_CHALLENGE_BITS];
        bits[0] = Boolean::Not(source);
        let before = cs.metrics();
        let scalar =
            nonzero_scalar_from_sha255(cs.namespace(|| "SHA scalar"), &bits).expect("SHA scalar");
        assert_eq!(cs.metrics(), (before.0 + 1, before.1 + 1));
        assert_integer(&scalar, &BigInt::from(1u8));
        let allocated = scalar
            .allocated_bits_le(cs.namespace(|| "allocated view"))
            .expect("allocated bits");
        assert_eq!(allocated.len(), SCALAR_BITS);
        assert_eq!(allocated[0].get_value(), Some(true));
        assert!(cs.is_satisfied());
    }

    #[test]
    fn scalar_shape_synthesis_does_not_require_witnesses() {
        let mut shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        synthesize_scalar_path(&mut shape, None).expect("shape synthesis");

        let mut witness = CountingCS::new();
        synthesize_scalar_path(&mut witness, Some(false)).expect("witness synthesis");
        assert!(witness.is_satisfied());
        assert_eq!(
            (shape.num_aux(), shape.num_constraints()),
            witness.metrics()
        );
    }

    fn operation_metrics(
        left_value: SecpScalarWitness,
        right_value: SecpScalarWitness,
    ) -> OperationMetrics {
        let mut multiplication = CountingCS::new();
        let left = allocate_canonical_scalar(multiplication.namespace(|| "left"), left_value)
            .expect("left");
        let right = allocate_canonical_scalar(multiplication.namespace(|| "right"), right_value)
            .expect("right");
        multiply_scalars(multiplication.namespace(|| "multiply"), &left, &right).expect("multiply");

        let mut addition = CountingCS::new();
        let left =
            allocate_canonical_scalar(addition.namespace(|| "left"), left_value).expect("left");
        let right =
            allocate_canonical_scalar(addition.namespace(|| "right"), right_value).expect("right");
        add_scalars(addition.namespace(|| "add"), &left, &right).expect("add");

        let mut subtraction = CountingCS::new();
        let left =
            allocate_canonical_scalar(subtraction.namespace(|| "left"), left_value).expect("left");
        let right = allocate_canonical_scalar(subtraction.namespace(|| "right"), right_value)
            .expect("right");
        subtract_scalars(subtraction.namespace(|| "subtract"), &left, &right).expect("subtract");

        let mut inversion = CountingCS::new();
        let value =
            allocate_canonical_scalar(inversion.namespace(|| "value"), left_value).expect("value");
        invert_scalar(inversion.namespace(|| "invert"), &value).expect("invert");
        assert!(multiplication.is_satisfied());
        assert!(addition.is_satisfied());
        assert!(subtraction.is_satisfied());
        assert!(inversion.is_satisfied());
        (
            multiplication.metrics(),
            addition.metrics(),
            subtraction.metrics(),
            inversion.metrics(),
        )
    }

    #[test]
    fn scalar_shapes_are_exact_and_witness_independent() {
        let order = scalar_order();
        let maximum = witness(&(&order - 1));

        let mut allocation = CountingCS::new();
        allocate_canonical_scalar(allocation.namespace(|| "scalar"), maximum)
            .expect("canonical allocation");
        assert!(allocation.is_satisfied());
        assert_eq!(allocation.metrics(), (516, 581));

        let maximum_metrics = operation_metrics(maximum, SecpScalarWitness::from_u64(2));
        let small_metrics = operation_metrics(
            SecpScalarWitness::from_u64(7),
            SecpScalarWitness::from_u64(11),
        );
        assert_eq!(maximum_metrics, small_metrics);
        assert_eq!(maximum_metrics.0, (2_272, 2_475));
        assert_eq!(maximum_metrics.1, (1_934, 2_135));
        assert_eq!(maximum_metrics.2, (1_940, 2_139));
        assert_eq!(maximum_metrics.3, (1_762, 1_898));
    }
}
