//! Exact SHA-256 constraints for the canonical parent relation builder.
//!
//! Bits are little endian inside bytes and words. SHA-256 message words and
//! digest words retain their specified big-endian byte order. Every dynamic
//! bit enters through a Boolean relation, and every modular word addition is
//! reconstructed with enough carry bits that field wraparound cannot satisfy
//! it.

use std::array;

use ff::Field;

use crate::relation_builder::{Builder, Expression};
use crate::{ReceiptCycleError, Scalar};

/// Exact gate cost of one compression block, excluding dynamic input-byte
/// allocation. This is pinned by tests so a transcript cost change is visible.
pub(crate) const SHA256_COMPRESSION_GATES: usize = 30_952;

/// Exact semantic-row cost of one compression block. Dynamic input bytes add
/// eight Boolean gates and sixteen rows per byte.
pub(crate) const SHA256_COMPRESSION_CONSTRAINTS: usize = 62_216;

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// One Boolean expression with the witness value retained for construction.
#[derive(Clone, Debug)]
pub(crate) struct Bit {
    expression: Expression,
    value: bool,
}

/// One byte whose bits are constrained and ordered least-significant first.
#[derive(Clone, Debug)]
pub(crate) struct Byte {
    bits: [Bit; 8],
    value: u8,
}

#[derive(Clone, Debug)]
struct Word {
    bits: [Bit; 32],
    value: u32,
}

/// A constrained digest in canonical SHA-256 byte order.
#[derive(Clone, Debug)]
pub(crate) struct Digest {
    bytes: [Byte; 32],
}

/// The low 255 digest bits interpreted as an integer below `2^255`.
///
/// The expression is a native Secq scalar and, because of the explicit bit
/// bound, is also a canonical secp256k1 scalar. Protocol callers must reject
/// the all-zero value where a nonzero challenge is required.
#[derive(Clone, Debug)]
pub(crate) struct Scalar255 {
    bits_le: [Bit; 255],
    expression: Expression,
}

impl Bit {
    fn constant(value: bool) -> Self {
        Self {
            expression: Expression::constant(if value { Scalar::ONE } else { Scalar::ZERO }),
            value,
        }
    }

    /// Wrap an expression whose Booleanity is already constrained elsewhere.
    ///
    /// This avoids allocating duplicate bit witnesses when a point or scalar
    /// gadget already exposes the canonical serialization bits.
    pub(crate) fn from_constrained_expression(expression: Expression, value: bool) -> Self {
        Self { expression, value }
    }

    pub(crate) fn expression(&self) -> &Expression {
        &self.expression
    }

    pub(crate) fn value(&self) -> bool {
        self.value
    }
}

impl Byte {
    pub(crate) fn constant(value: u8) -> Self {
        Self {
            bits: array::from_fn(|bit| Bit::constant(((value >> bit) & 1) != 0)),
            value,
        }
    }

    /// Construct a byte from bits already constrained Boolean by the caller.
    pub(crate) fn from_constrained_bits(bits: [Bit; 8]) -> Self {
        let value = bits.iter().enumerate().fold(0u8, |value, (index, bit)| {
            value | (u8::from(bit.value) << index)
        });
        Self { bits, value }
    }

    pub(crate) fn bits(&self) -> &[Bit; 8] {
        &self.bits
    }

    pub(crate) fn value(&self) -> u8 {
        self.value
    }
}

impl Word {
    fn constant(value: u32) -> Self {
        Self {
            bits: array::from_fn(|bit| Bit::constant(((value >> bit) & 1) != 0)),
            value,
        }
    }
}

impl Digest {
    pub(crate) fn bytes(&self) -> &[Byte; 32] {
        &self.bytes
    }

    pub(crate) fn value(&self) -> [u8; 32] {
        self.bytes.each_ref().map(Byte::value)
    }

    /// Clear the digest's most-significant bit and expose the remaining 255
    /// constrained bits as one canonical integer expression.
    pub(crate) fn scalar_255(&self) -> Scalar255 {
        let bits_le: [Bit; 255] = self
            .bytes
            .iter()
            .rev()
            .flat_map(|byte| byte.bits.iter().cloned())
            .take(255)
            .collect::<Vec<_>>()
            .try_into()
            .expect("a SHA-256 digest has exactly 255 low bits");
        Scalar255::from_constrained_bits(bits_le)
    }
}

impl Scalar255 {
    /// Construct a low-255-bit integer from bits constrained elsewhere.
    pub(crate) fn from_constrained_bits(bits_le: [Bit; 255]) -> Self {
        let mut expression = Expression::constant(Scalar::ZERO);
        let mut coefficient = Scalar::ONE;
        for bit in &bits_le {
            expression = expression.add(&bit.expression.clone().scale(coefficient));
            coefficient = coefficient + coefficient;
        }
        Self {
            bits_le,
            expression,
        }
    }

    pub(crate) fn bits_le(&self) -> &[Bit; 255] {
        &self.bits_le
    }

    pub(crate) fn expression(&self) -> &Expression {
        &self.expression
    }

    pub(crate) fn value(&self) -> Scalar {
        self.expression.value()
    }
}

/// Allocate one private byte and constrain each bit Boolean.
pub(crate) fn allocate_byte(builder: &mut Builder, value: u8) -> Byte {
    Byte {
        bits: array::from_fn(|bit| builder_bit(builder, ((value >> bit) & 1) != 0)),
        value,
    }
}

/// Allocate private bytes with a fixed public length.
pub(crate) fn allocate_bytes(builder: &mut Builder, values: &[u8]) -> Vec<Byte> {
    values
        .iter()
        .map(|&value| allocate_byte(builder, value))
        .collect()
}

fn builder_bit(builder: &mut Builder, value: bool) -> Bit {
    Bit {
        expression: builder.allocate_boolean(value),
        value,
    }
}

fn packed(word: &Word) -> Expression {
    let mut result = Expression::constant(Scalar::ZERO);
    let mut coefficient = Scalar::ONE;
    for bit in &word.bits {
        result = result.add(&bit.expression.clone().scale(coefficient));
        coefficient = coefficient + coefficient;
    }
    result
}

fn product(builder: &mut Builder, left: &Bit, right: &Bit) -> Bit {
    Bit {
        expression: builder.multiply(&left.expression, &right.expression),
        value: left.value & right.value,
    }
}

fn xor_words(builder: &mut Builder, left: &Word, right: &Word) -> Word {
    Word {
        bits: array::from_fn(|index| {
            let product = product(builder, &left.bits[index], &right.bits[index]);
            Bit {
                expression: left.bits[index]
                    .expression
                    .clone()
                    .add(&right.bits[index].expression)
                    .sub(&product.expression.scale(Scalar::from(2))),
                value: left.bits[index].value ^ right.bits[index].value,
            }
        }),
        value: left.value ^ right.value,
    }
}

fn rotate(word: &Word, count: usize) -> Word {
    Word {
        bits: array::from_fn(|index| word.bits[(index + count) % 32].clone()),
        value: word.value.rotate_right(count as u32),
    }
}

fn shift(word: &Word, count: usize) -> Word {
    Word {
        bits: array::from_fn(|index| {
            if index + count < 32 {
                word.bits[index + count].clone()
            } else {
                Bit::constant(false)
            }
        }),
        value: word.value >> count,
    }
}

fn sigma(
    builder: &mut Builder,
    word: &Word,
    first: usize,
    second: usize,
    third: usize,
    shift_last: bool,
) -> Word {
    let first_pair = xor_words(builder, &rotate(word, first), &rotate(word, second));
    let last = if shift_last {
        shift(word, third)
    } else {
        rotate(word, third)
    };
    xor_words(builder, &first_pair, &last)
}

fn choose(builder: &mut Builder, selector: &Word, when_true: &Word, when_false: &Word) -> Word {
    Word {
        bits: array::from_fn(|index| {
            let difference = when_true.bits[index]
                .expression
                .clone()
                .sub(&when_false.bits[index].expression);
            let selected = builder.multiply(&selector.bits[index].expression, &difference);
            Bit {
                expression: when_false.bits[index].expression.clone().add(&selected),
                value: if selector.bits[index].value {
                    when_true.bits[index].value
                } else {
                    when_false.bits[index].value
                },
            }
        }),
        value: (selector.value & when_true.value) ^ (!selector.value & when_false.value),
    }
}

fn majority(builder: &mut Builder, first: &Word, second: &Word, third: &Word) -> Word {
    Word {
        bits: array::from_fn(|index| {
            let first_second = product(builder, &first.bits[index], &second.bits[index]);
            let remaining_selector = first.bits[index]
                .expression
                .clone()
                .add(&second.bits[index].expression)
                .sub(&first_second.expression.clone().scale(Scalar::from(2)));
            let remaining = builder.multiply(&third.bits[index].expression, &remaining_selector);
            Bit {
                expression: first_second.expression.add(&remaining),
                value: (first.bits[index].value & second.bits[index].value)
                    ^ (first.bits[index].value & third.bits[index].value)
                    ^ (second.bits[index].value & third.bits[index].value),
            }
        }),
        value: (first.value & second.value)
            ^ (first.value & third.value)
            ^ (second.value & third.value),
    }
}

fn add_words(builder: &mut Builder, words: &[&Word]) -> Word {
    assert!((2..=5).contains(&words.len()));
    let sum = words
        .iter()
        .fold(Expression::constant(Scalar::ZERO), |sum, word| {
            sum.add(&packed(word))
        });
    let value = words
        .iter()
        .fold(0u64, |sum, word| sum + u64::from(word.value));

    let carry_width = usize::BITS - (words.len() - 1).leading_zeros();
    let width = 32 + carry_width as usize;
    let mut reconstructed = Expression::constant(Scalar::ZERO);
    let mut coefficient = Scalar::ONE;
    let mut bits = Vec::with_capacity(width);
    for index in 0..width {
        let bit = builder_bit(builder, ((value >> index) & 1) != 0);
        reconstructed = reconstructed.add(&bit.expression.clone().scale(coefficient));
        coefficient = coefficient + coefficient;
        bits.push(bit);
    }
    builder.constrain_equal(&sum, &reconstructed);
    Word {
        bits: bits[..32]
            .to_vec()
            .try_into()
            .expect("word additions allocate at least 32 bits"),
        value: value as u32,
    }
}

fn word_from_bytes(bytes: &[Byte]) -> Word {
    assert_eq!(bytes.len(), 4);
    Word {
        bits: array::from_fn(|index| bytes[3 - index / 8].bits[index % 8].clone()),
        value: bytes
            .iter()
            .fold(0u32, |word, byte| (word << 8) | u32::from(byte.value)),
    }
}

fn padded_length(length: usize) -> Result<(usize, u64), ReceiptCycleError> {
    let bit_length = u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(ReceiptCycleError::Malformed("SHA-256 message length"))?;
    let with_suffix = length
        .checked_add(9)
        .ok_or(ReceiptCycleError::Malformed("SHA-256 padded length"))?;
    let blocks = with_suffix
        .checked_add(63)
        .ok_or(ReceiptCycleError::Malformed("SHA-256 padded length"))?
        / 64;
    let total = blocks
        .checked_mul(64)
        .ok_or(ReceiptCycleError::Malformed("SHA-256 padded length"))?;
    Ok((total, bit_length))
}

fn padded_message(message: &[Byte]) -> Result<Vec<Byte>, ReceiptCycleError> {
    let (total, bit_length) = padded_length(message.len())?;
    let mut padded = Vec::with_capacity(total);
    padded.extend_from_slice(message);
    padded.push(Byte::constant(0x80));
    while padded.len() + 8 < total {
        padded.push(Byte::constant(0));
    }
    padded.extend(bit_length.to_be_bytes().map(Byte::constant));
    debug_assert_eq!(padded.len(), total);
    Ok(padded)
}

/// Constrain SHA-256 over one fixed-length sequence of constrained bytes.
pub(crate) fn hash(builder: &mut Builder, message: &[Byte]) -> Result<Digest, ReceiptCycleError> {
    let padded = padded_message(message)?;
    let mut state: [Word; 8] = INITIAL_STATE.map(Word::constant);
    let (blocks, remainder) = padded.as_chunks::<64>();
    debug_assert!(remainder.is_empty());
    for block in blocks {
        let mut schedule: Vec<Word> = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| word_from_bytes(word))
            .collect();
        schedule.reserve(48);
        for index in 16..64 {
            let high = sigma(builder, &schedule[index - 2], 17, 19, 10, true);
            let low = sigma(builder, &schedule[index - 15], 7, 18, 3, true);
            schedule.push(add_words(
                builder,
                &[&high, &schedule[index - 7], &low, &schedule[index - 16]],
            ));
        }

        let mut work = state.clone();
        for round in 0..64 {
            let high = sigma(builder, &work[4], 6, 11, 25, false);
            let selected = choose(builder, &work[4], &work[5], &work[6]);
            let t1 = add_words(
                builder,
                &[
                    &work[7],
                    &high,
                    &selected,
                    &Word::constant(ROUND_CONSTANTS[round]),
                    &schedule[round],
                ],
            );
            let low = sigma(builder, &work[0], 2, 13, 22, false);
            let majority = majority(builder, &work[0], &work[1], &work[2]);
            let t2 = add_words(builder, &[&low, &majority]);
            work = [
                add_words(builder, &[&t1, &t2]),
                work[0].clone(),
                work[1].clone(),
                work[2].clone(),
                add_words(builder, &[&work[3], &t1]),
                work[4].clone(),
                work[5].clone(),
                work[6].clone(),
            ];
        }
        for index in 0..8 {
            state[index] = add_words(builder, &[&state[index], &work[index]]);
        }
    }

    let bytes: Vec<Byte> = state
        .iter()
        .flat_map(|word| {
            (0..4).map(move |byte_index| {
                let word_bit = 24 - 8 * byte_index;
                Byte {
                    bits: array::from_fn(|bit| word.bits[word_bit + bit].clone()),
                    value: (word.value >> word_bit) as u8,
                }
            })
        })
        .collect();
    Ok(Digest {
        bytes: bytes.try_into().expect("eight SHA-256 words are 32 bytes"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest as _, Sha256};

    use crate::{Assignment, Circuit, WireKind};

    fn relation_satisfied(circuit: &Circuit, assignment: &Assignment) -> bool {
        circuit.constraints.iter().all(|row| {
            row.iter().fold(Scalar::ZERO, |sum, term| {
                let value = match term.kind {
                    WireKind::One => Scalar::ONE,
                    WireKind::Left => assignment.gates[term.index].0,
                    WireKind::Right => assignment.gates[term.index].1,
                    WireKind::Output => {
                        assignment.gates[term.index].0 * assignment.gates[term.index].1
                    }
                };
                sum + value * term.coefficient
            }) == Scalar::ZERO
        })
    }

    fn constant_message(length: usize) -> Vec<Byte> {
        (0..length)
            .map(|index| Byte::constant((index as u8).wrapping_mul(17).wrapping_add(3)))
            .collect()
    }

    #[test]
    fn known_answers_cover_sha256_padding_boundaries() {
        for length in [0usize, 3, 55, 56, 64] {
            let message = if length == 3 {
                b"abc".to_vec()
            } else {
                constant_message(length)
                    .into_iter()
                    .map(|byte| byte.value())
                    .collect()
            };
            let expected: [u8; 32] = Sha256::digest(&message).into();
            let mut builder = Builder::default();
            let constrained: Vec<_> = message.iter().copied().map(Byte::constant).collect();
            let digest = hash(&mut builder, &constrained).expect("SHA-256 relation");
            assert_eq!(digest.value(), expected);
            let blocks = (length + 9).div_ceil(64);
            assert_eq!(builder.gate_count(), blocks * SHA256_COMPRESSION_GATES);
            let (circuit, _) = builder.finish().expect("relation");
            let circuit = Circuit::parse(&circuit).expect("circuit");
            assert_eq!(
                circuit.constraints.len(),
                blocks * SHA256_COMPRESSION_CONSTRAINTS
            );
        }
    }

    #[test]
    fn dynamic_inputs_are_boolean_and_shape_independent() {
        let build = |message: &[u8]| {
            let mut builder = Builder::default();
            let message = allocate_bytes(&mut builder, message);
            let digest = hash(&mut builder, &message).expect("SHA-256 relation");
            let value = digest.value();
            let (circuit, assignment) = builder.finish().expect("relation");
            let circuit = Circuit::parse(&circuit).expect("circuit");
            let assignment = Assignment::parse(&assignment).expect("assignment");
            (circuit, assignment, value)
        };
        let first = build(b"shape one");
        let second = build(b"shape two");
        assert_eq!(first.0, second.0);
        assert_ne!(first.1, second.1);
        assert_eq!(first.2, <[u8; 32]>::from(Sha256::digest(b"shape one")));
        assert_eq!(second.2, <[u8; 32]>::from(Sha256::digest(b"shape two")));
        assert!(relation_satisfied(&first.0, &first.1));
        assert!(relation_satisfied(&second.0, &second.1));
    }

    #[test]
    fn non_boolean_input_assignment_is_unsatisfied() {
        let mut builder = Builder::default();
        let message = allocate_bytes(&mut builder, b"input bit");
        hash(&mut builder, &message).expect("SHA-256 relation");
        let (circuit, assignment) = builder.finish().expect("relation");
        let circuit = Circuit::parse(&circuit).expect("circuit");
        let mut assignment = Assignment::parse(&assignment).expect("assignment");
        assert!(relation_satisfied(&circuit, &assignment));

        assignment.gates[0].0 = Scalar::from(2);
        assert!(!relation_satisfied(&circuit, &assignment));
    }

    #[test]
    fn wrong_digest_constraint_is_unsatisfied() {
        let mut builder = Builder::default();
        let message = allocate_bytes(&mut builder, b"bound digest");
        let digest = hash(&mut builder, &message).expect("SHA-256 relation");
        let changed = digest.bytes()[0].bits().iter().enumerate().fold(
            Expression::constant(Scalar::ZERO),
            |value, (bit, input)| {
                value.add(&input.expression().clone().scale(Scalar::from(1u64 << bit)))
            },
        );
        builder.constrain_equal(
            &changed,
            &Expression::constant(Scalar::from(u64::from(digest.value()[0] ^ 1))),
        );
        let (circuit, assignment) = builder.finish().expect("relation");
        let circuit = Circuit::parse(&circuit).expect("circuit");
        let assignment = Assignment::parse(&assignment).expect("assignment");
        assert!(!relation_satisfied(&circuit, &assignment));
    }

    #[test]
    fn scalar_255_masks_only_the_digest_msb() {
        let mut builder = Builder::default();
        let digest = hash(&mut builder, &[]).expect("SHA-256 relation");
        let scalar = digest.scalar_255();
        assert_eq!(scalar.bits_le().len(), 255);
        assert_eq!(
            scalar.bits_le()[0].value(),
            digest.bytes()[31].bits()[0].value()
        );
        assert_eq!(
            scalar.bits_le()[254].value(),
            digest.bytes()[0].bits()[6].value()
        );

        let mut masked = digest.value();
        masked[0] &= 0x7f;
        let expected = masked.iter().fold(Scalar::ZERO, |value, byte| {
            value * Scalar::from(256) + Scalar::from(u64::from(*byte))
        });
        assert_eq!(scalar.value(), expected);
    }

    #[test]
    fn length_overflow_rejects_before_building() {
        assert_eq!(
            padded_length(usize::MAX),
            Err(ReceiptCycleError::Malformed("SHA-256 message length"))
        );
    }
}
