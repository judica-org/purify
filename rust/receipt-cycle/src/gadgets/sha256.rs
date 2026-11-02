//! Exact SHA-256 constraints for the Secq receipt parent.
//!
//! Bits are little endian inside bytes and words. SHA-256 message words and
//! digest words retain their specified big-endian byte order. Every witness
//! bit is constrained Boolean, and every modular word addition is an integer
//! equality reconstructed with enough high carry bits that field wraparound
//! cannot satisfy it.

use std::array;

use bulletproofs_cycle::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use thiserror::Error;

#[cfg(test)]
use bulletproofs_cycle::r1cs::Variable;

type Scalar = <Secq256k1Cycle as Cycle>::Scalar;

/// Exact multiplier cost of one SHA-256 compression block, excluding input
/// byte allocation and the eight final public digest constraints.
pub(crate) const SHA256_COMPRESSION_MULTIPLIERS: usize = 30_952;

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

/// Construction-time failure for a fixed SHA-256 relation.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum Sha256GadgetError {
    #[error("SHA-256 message length overflows its 64-bit bit count")]
    LengthOverflow,
    #[error("SHA-256 witness length does not match its public length")]
    AssignmentLength,
    #[error("SHA-256 R1CS allocation failed: {0}")]
    Backend(#[from] R1CSError),
}

#[derive(Clone, Debug)]
pub(crate) struct Bit {
    expression: LinearCombination<Scalar>,
    value: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct Byte {
    bits: [Bit; 8],
    value: Option<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Word {
    bits: [Bit; 32],
    value: Option<u32>,
}

impl Bit {
    fn constant(value: bool) -> Self {
        Self {
            expression: LinearCombination::from(if value { Scalar::ONE } else { Scalar::ZERO }),
            value: Some(value),
        }
    }
}

impl Byte {
    fn constant(value: u8) -> Self {
        Self {
            bits: array::from_fn(|bit| Bit::constant(((value >> bit) & 1) != 0)),
            value: Some(value),
        }
    }
}

impl Word {
    fn constant(value: u32) -> Self {
        Self {
            bits: array::from_fn(|bit| Bit::constant(((value >> bit) & 1) != 0)),
            value: Some(value),
        }
    }
}

fn bool_scalar(value: bool) -> Scalar {
    if value {
        Scalar::ONE
    } else {
        Scalar::ZERO
    }
}

fn allocate_boolean<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    value: Option<bool>,
) -> Result<Bit, R1CSError> {
    let assignment = value.map(|value| (bool_scalar(value), bool_scalar(!value)));
    let (bit, complement, product) = cs.allocate_multiplier(assignment)?;
    cs.constrain(bit + complement - Scalar::ONE);
    cs.constrain(LinearCombination::from(product));
    Ok(Bit {
        expression: LinearCombination::from(bit),
        value,
    })
}

#[cfg(test)]
fn allocate_boolean_scalar<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    value: Option<Scalar>,
) -> Result<Variable<Scalar>, R1CSError> {
    let assignment = value.map(|value| (value, Scalar::ONE - value));
    let (bit, complement, product) = cs.allocate_multiplier(assignment)?;
    cs.constrain(bit + complement - Scalar::ONE);
    cs.constrain(LinearCombination::from(product));
    Ok(bit)
}

/// Allocate `length` private bytes and constrain every bit Boolean.
pub(crate) fn allocate_bytes<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    length: usize,
    assignment: Option<&[u8]>,
) -> Result<Vec<Byte>, Sha256GadgetError> {
    if assignment.is_some_and(|bytes| bytes.len() != length) {
        return Err(Sha256GadgetError::AssignmentLength);
    }
    let mut bytes = Vec::with_capacity(length);
    for index in 0..length {
        let value = assignment.map(|values| values[index]);
        let mut bits = Vec::with_capacity(8);
        for bit in 0..8 {
            bits.push(allocate_boolean(
                cs,
                value.map(|byte| ((byte >> bit) & 1) != 0),
            )?);
        }
        bytes.push(Byte {
            bits: bits
                .try_into()
                .expect("exactly eight input bits were allocated"),
            value,
        });
    }
    Ok(bytes)
}

fn packed(word: &Word) -> LinearCombination<Scalar> {
    let mut result = LinearCombination::default();
    let mut coefficient = Scalar::ONE;
    for bit in &word.bits {
        result = result + bit.expression.clone() * coefficient;
        coefficient = coefficient + coefficient;
    }
    result
}

fn product<CS: ConstraintSystem<Secq256k1Cycle>>(cs: &mut CS, left: &Bit, right: &Bit) -> Bit {
    let (_, _, output) = cs.multiply(left.expression.clone(), right.expression.clone());
    Bit {
        expression: LinearCombination::from(output),
        value: left
            .value
            .zip(right.value)
            .map(|(left, right)| left & right),
    }
}

fn xor_words<CS: ConstraintSystem<Secq256k1Cycle>>(cs: &mut CS, left: &Word, right: &Word) -> Word {
    let bits = array::from_fn(|index| {
        let product = product(cs, &left.bits[index], &right.bits[index]);
        Bit {
            expression: left.bits[index].expression.clone() + right.bits[index].expression.clone()
                - product.expression * Scalar::from(2),
            value: left.bits[index]
                .value
                .zip(right.bits[index].value)
                .map(|(left, right)| left ^ right),
        }
    });
    Word {
        bits,
        value: left
            .value
            .zip(right.value)
            .map(|(left, right)| left ^ right),
    }
}

fn rotate(word: &Word, count: usize) -> Word {
    Word {
        bits: array::from_fn(|index| word.bits[(index + count) % 32].clone()),
        value: word.value.map(|value| value.rotate_right(count as u32)),
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
        value: word.value.map(|value| value >> count),
    }
}

fn sigma<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    word: &Word,
    first: usize,
    second: usize,
    third: usize,
    shift_last: bool,
) -> Word {
    let first_pair = xor_words(cs, &rotate(word, first), &rotate(word, second));
    let last = if shift_last {
        shift(word, third)
    } else {
        rotate(word, third)
    };
    xor_words(cs, &first_pair, &last)
}

fn choose<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    selector: &Word,
    when_true: &Word,
    when_false: &Word,
) -> Word {
    let bits = array::from_fn(|index| {
        let (_, _, selected_difference) = cs.multiply(
            selector.bits[index].expression.clone(),
            when_true.bits[index].expression.clone() - when_false.bits[index].expression.clone(),
        );
        Bit {
            expression: when_false.bits[index].expression.clone() + selected_difference,
            value: selector.bits[index]
                .value
                .zip(when_true.bits[index].value)
                .zip(when_false.bits[index].value)
                .map(
                    |((selector, when_true), when_false)| {
                        if selector {
                            when_true
                        } else {
                            when_false
                        }
                    },
                ),
        }
    });
    Word {
        bits,
        value: selector
            .value
            .zip(when_true.value)
            .zip(when_false.value)
            .map(|((selector, when_true), when_false)| {
                (selector & when_true) ^ (!selector & when_false)
            }),
    }
}

fn majority<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    first: &Word,
    second: &Word,
    third: &Word,
) -> Word {
    let bits = array::from_fn(|index| {
        let first_second = product(cs, &first.bits[index], &second.bits[index]);
        let (_, _, remaining) = cs.multiply(
            third.bits[index].expression.clone(),
            first.bits[index].expression.clone() + second.bits[index].expression.clone()
                - first_second.expression.clone() * Scalar::from(2),
        );
        Bit {
            expression: first_second.expression + remaining,
            value: first.bits[index]
                .value
                .zip(second.bits[index].value)
                .zip(third.bits[index].value)
                .map(|((first, second), third)| {
                    (first & second) ^ (first & third) ^ (second & third)
                }),
        }
    });
    Word {
        bits,
        value: first
            .value
            .zip(second.value)
            .zip(third.value)
            .map(|((first, second), third)| (first & second) ^ (first & third) ^ (second & third)),
    }
}

fn add_words<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    words: &[&Word],
) -> Result<Word, R1CSError> {
    assert!((2..=5).contains(&words.len()));
    let mut sum = LinearCombination::default();
    let mut value = Some(0u64);
    for word in words {
        sum = sum + packed(word);
        value = value
            .zip(word.value)
            .map(|(sum, word)| sum + u64::from(word));
    }

    let carry_width = usize::BITS - (words.len() - 1).leading_zeros();
    let width = 32 + carry_width as usize;
    let mut reconstructed = LinearCombination::default();
    let mut coefficient = Scalar::ONE;
    let mut bits = Vec::with_capacity(width);
    for index in 0..width {
        let bit = allocate_boolean(cs, value.map(|value| ((value >> index) & 1) != 0))?;
        reconstructed = reconstructed + bit.expression.clone() * coefficient;
        coefficient = coefficient + coefficient;
        bits.push(bit);
    }
    cs.constrain(sum - reconstructed);
    Ok(Word {
        bits: bits[..32]
            .to_vec()
            .try_into()
            .expect("word additions always allocate at least 32 bits"),
        value: value.map(|value| value as u32),
    })
}

fn word_from_bytes(bytes: &[Byte]) -> Word {
    assert_eq!(bytes.len(), 4);
    Word {
        bits: array::from_fn(|index| bytes[3 - index / 8].bits[index % 8].clone()),
        value: bytes.iter().try_fold(0u32, |word, byte| {
            byte.value.map(|byte| (word << 8) | u32::from(byte))
        }),
    }
}

fn padded_length(length: usize) -> Result<(usize, u64), Sha256GadgetError> {
    let bit_length = u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(Sha256GadgetError::LengthOverflow)?;
    let with_suffix = length
        .checked_add(9)
        .ok_or(Sha256GadgetError::LengthOverflow)?;
    let blocks = with_suffix
        .checked_add(63)
        .ok_or(Sha256GadgetError::LengthOverflow)?
        / 64;
    let total = blocks
        .checked_mul(64)
        .ok_or(Sha256GadgetError::LengthOverflow)?;
    Ok((total, bit_length))
}

fn padded_message(message: &[Byte]) -> Result<Vec<Byte>, Sha256GadgetError> {
    let (total, bit_length) = padded_length(message.len())?;
    let mut padded = Vec::with_capacity(total);
    padded.extend_from_slice(message);
    padded.push(Byte::constant(0x80));
    while padded.len() + 8 < total {
        padded.push(Byte::constant(0));
    }
    for byte in bit_length.to_be_bytes() {
        padded.push(Byte::constant(byte));
    }
    debug_assert_eq!(padded.len(), total);
    Ok(padded)
}

/// Constrain the exact SHA-256 digest of already range-checked private bytes.
pub(crate) fn constrain_digest<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    message: &[Byte],
    expected_digest: &[u8; 32],
) -> Result<[Option<u32>; 8], Sha256GadgetError> {
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
            let high = sigma(cs, &schedule[index - 2], 17, 19, 10, true);
            let low = sigma(cs, &schedule[index - 15], 7, 18, 3, true);
            schedule.push(add_words(
                cs,
                &[&high, &schedule[index - 7], &low, &schedule[index - 16]],
            )?);
        }

        let mut work = state.clone();
        for round in 0..64 {
            let high = sigma(cs, &work[4], 6, 11, 25, false);
            let choose = choose(cs, &work[4], &work[5], &work[6]);
            let t1 = add_words(
                cs,
                &[
                    &work[7],
                    &high,
                    &choose,
                    &Word::constant(ROUND_CONSTANTS[round]),
                    &schedule[round],
                ],
            )?;
            let low = sigma(cs, &work[0], 2, 13, 22, false);
            let majority = majority(cs, &work[0], &work[1], &work[2]);
            let t2 = add_words(cs, &[&low, &majority])?;
            work = [
                add_words(cs, &[&t1, &t2])?,
                work[0].clone(),
                work[1].clone(),
                work[2].clone(),
                add_words(cs, &[&work[3], &t1])?,
                work[4].clone(),
                work[5].clone(),
                work[6].clone(),
            ];
        }
        for index in 0..8 {
            state[index] = add_words(cs, &[&state[index], &work[index]])?;
        }
    }

    for (word, digest) in state.iter().zip(expected_digest.as_chunks::<4>().0.iter()) {
        let expected = u32::from_be_bytes(*digest);
        cs.constrain(packed(word) - Scalar::from(u64::from(expected)));
    }
    Ok(state.each_ref().map(|word| word.value))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bulletproofs_cycle::r1cs::{Metrics, Prover, Variable, Verifier};
    use bulletproofs_cycle::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha256};

    struct TestConstraintSystem {
        transcript: Transcript,
        multipliers: usize,
        constraints: usize,
    }

    impl TestConstraintSystem {
        fn new() -> Self {
            Self {
                transcript: Transcript::new(b"Purify/SecqSha256/Test/v1"),
                multipliers: 0,
                constraints: 0,
            }
        }
    }

    impl ConstraintSystem<Secq256k1Cycle> for TestConstraintSystem {
        fn transcript(&mut self) -> &mut Transcript {
            &mut self.transcript
        }

        fn multiply(
            &mut self,
            left: LinearCombination<Scalar>,
            right: LinearCombination<Scalar>,
        ) -> (Variable<Scalar>, Variable<Scalar>, Variable<Scalar>) {
            let variables = self
                .allocate_multiplier(Some((Scalar::ZERO, Scalar::ZERO)))
                .expect("test multiplier has a complete assignment");
            self.constrain(left - variables.0);
            self.constrain(right - variables.1);
            variables
        }

        fn allocate(&mut self, assignment: Option<Scalar>) -> Result<Variable<Scalar>, R1CSError> {
            assignment.ok_or(R1CSError::MissingAssignment)?;
            Ok(Variable::committed(self.multipliers))
        }

        fn allocate_multiplier(
            &mut self,
            assignment: Option<(Scalar, Scalar)>,
        ) -> Result<(Variable<Scalar>, Variable<Scalar>, Variable<Scalar>), R1CSError> {
            assignment.ok_or(R1CSError::MissingAssignment)?;
            let index = self.multipliers;
            self.multipliers += 1;
            let variables = (
                Variable::multiplier_left(index),
                Variable::multiplier_right(index),
                Variable::multiplier_output(index),
            );
            Ok(variables)
        }

        fn metrics(&self) -> Metrics {
            Metrics {
                multipliers: self.multipliers,
                constraints: self.constraints,
                phase_one_constraints: self.constraints,
                phase_two_constraints: 0,
            }
        }

        fn constrain(&mut self, _expression: LinearCombination<Scalar>) {
            self.constraints += 1;
        }
    }

    fn message(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect()
    }

    #[test]
    fn known_answers_cover_sha256_padding_boundaries() {
        let mut compression_multipliers = None;
        for length in [0usize, 3, 55, 56, 64] {
            let message = if length == 3 {
                b"abc".to_vec()
            } else {
                message(length)
            };
            let expected: [u8; 32] = Sha256::digest(&message).into();
            let mut cs = TestConstraintSystem::new();
            let allocated = allocate_bytes(&mut cs, length, Some(&message)).expect("allocate");
            let values = constrain_digest(&mut cs, &allocated, &expected).expect("constrain");
            let expected_words: Vec<Option<u32>> = expected
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| Some(u32::from_be_bytes(*word)))
                .collect();
            assert_eq!(values.as_slice(), expected_words.as_slice());

            let blocks = (length + 9).div_ceil(64);
            let relation_multipliers = cs.metrics().multipliers - 8 * length;
            assert_eq!(relation_multipliers % blocks, 0);
            let per_block = relation_multipliers / blocks;
            assert_eq!(*compression_multipliers.get_or_insert(per_block), per_block);
            assert_eq!(per_block, SHA256_COMPRESSION_MULTIPLIERS);
        }
    }

    #[test]
    fn sha256_known_answers_match_the_standard() {
        let vectors = [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".to_vec(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ];
        for (message, expected_hex) in vectors {
            let expected = Sha256::digest(&message);
            assert_eq!(hex(&expected), expected_hex);
            let mut cs = TestConstraintSystem::new();
            let allocated =
                allocate_bytes(&mut cs, message.len(), Some(&message)).expect("allocate");
            let values =
                constrain_digest(&mut cs, &allocated, &expected.into()).expect("constrain");
            assert!(values.iter().all(Option::is_some));
        }
    }

    #[test]
    fn changed_digest_and_non_boolean_bit_are_constrained() {
        let message = b"abc";
        let mut digest: [u8; 32] = Sha256::digest(message).into();
        digest[0] ^= 1;
        let mut changed_digest = TestConstraintSystem::new();
        let allocated = allocate_bytes(&mut changed_digest, message.len(), Some(message))
            .expect("allocate changed digest");
        let values =
            constrain_digest(&mut changed_digest, &allocated, &digest).expect("constrain digest");
        assert_ne!(
            values[0],
            Some(u32::from_be_bytes(digest[..4].try_into().expect("word")))
        );

        let mut malformed_bit = TestConstraintSystem::new();
        allocate_boolean_scalar(&mut malformed_bit, Some(Scalar::from(2)))
            .expect("allocate malformed bit");
        assert_eq!(malformed_bit.metrics().multipliers, 1);
        assert_eq!(malformed_bit.metrics().constraints, 2);
    }

    #[test]
    #[ignore = "32K-gate backend proof; run explicitly in release mode"]
    fn secq_backend_proves_the_exact_sha256_relation() {
        let message = b"abc";
        let digest: [u8; 32] = Sha256::digest(message).into();
        let generators = PedersenGens::<Secq256k1Cycle>::default();

        let mut prover = Prover::<Secq256k1Cycle, _>::new(
            &generators,
            Transcript::new(b"Purify/SecqSha256/ProofTest/v1"),
        );
        let allocated = allocate_bytes(&mut prover, message.len(), Some(message))
            .expect("allocate prover message");
        constrain_digest(&mut prover, &allocated, &digest).expect("constrain prover digest");
        let gate_count = prover.metrics().multipliers.next_power_of_two();
        assert_eq!(prover.metrics().multipliers, 8 * message.len() + 30_952);
        let proof_generators = BulletproofGens::<Secq256k1Cycle>::new(gate_count, 1);
        let proof = prover
            .prove(&proof_generators, &mut ChaCha20Rng::from_seed([0x51; 32]))
            .expect("prove SHA-256 relation");

        let mut verifier =
            Verifier::<Secq256k1Cycle, _>::new(Transcript::new(b"Purify/SecqSha256/ProofTest/v1"));
        let allocated =
            allocate_bytes(&mut verifier, message.len(), None).expect("allocate verifier message");
        constrain_digest(&mut verifier, &allocated, &digest).expect("constrain verifier digest");
        verifier
            .verify(
                &proof,
                &generators,
                &proof_generators,
                &mut ChaCha20Rng::from_seed([0x91; 32]),
            )
            .expect("verify SHA-256 relation");

        let mut changed = digest;
        changed[0] ^= 1;
        let mut verifier =
            Verifier::<Secq256k1Cycle, _>::new(Transcript::new(b"Purify/SecqSha256/ProofTest/v1"));
        let allocated =
            allocate_bytes(&mut verifier, message.len(), None).expect("allocate changed verifier");
        constrain_digest(&mut verifier, &allocated, &changed).expect("constrain changed digest");
        assert!(verifier
            .verify(
                &proof,
                &generators,
                &proof_generators,
                &mut ChaCha20Rng::from_seed([0x92; 32]),
            )
            .is_err());
    }

    #[test]
    fn secq_backend_rejects_a_non_boolean_witness() {
        let generators = PedersenGens::<Secq256k1Cycle>::default();
        let proof_generators = BulletproofGens::<Secq256k1Cycle>::new(1, 1);
        let mut prover = Prover::<Secq256k1Cycle, _>::new(
            &generators,
            Transcript::new(b"Purify/SecqSha256/BooleanTest/v1"),
        );
        allocate_boolean_scalar(&mut prover, Some(Scalar::from(2)))
            .expect("allocate malformed Boolean witness");
        let proof = prover
            .prove(&proof_generators, &mut ChaCha20Rng::from_seed([0x61; 32]))
            .expect("form malformed Boolean proof transcript");

        let mut verifier = Verifier::<Secq256k1Cycle, _>::new(Transcript::new(
            b"Purify/SecqSha256/BooleanTest/v1",
        ));
        allocate_boolean_scalar(&mut verifier, None).expect("allocate verifier Boolean");
        assert!(verifier
            .verify(
                &proof,
                &generators,
                &proof_generators,
                &mut ChaCha20Rng::from_seed([0xa1; 32]),
            )
            .is_err());
    }

    #[test]
    fn witness_shape_and_length_overflow_reject() {
        let mut cs = TestConstraintSystem::new();
        assert!(matches!(
            allocate_bytes(&mut cs, 2, Some(&[1])),
            Err(Sha256GadgetError::AssignmentLength)
        ));
        assert_eq!(
            padded_length(usize::MAX),
            Err(Sha256GadgetError::LengthOverflow)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
