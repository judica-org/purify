//! Composable candidate algebraic transcript primitives.
//!
//! These constraints are migration foundations. They do not select a receipt,
//! BPPP, or accumulation transcript suite.

use std::array;

use ff::Field;

use crate::poseidon::{parameters, FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};
use crate::relation_builder::{Builder, Expression};
use crate::{ReceiptCycleError, Scalar};

const SUITE_ID: &[u8] = b"Purify/PoseidonTranscript/v1";

const FIELD_ITEM: u32 = 0x4649_454c; // FIEL
const SCALAR_ITEM: u32 = 0x5343_414c; // SCAL
const POINT_ITEM: u32 = 0x504f_494e; // POIN
const POINT_PAIR_ITEM: u32 = 0x5041_4952; // PAIR
const BYTES_ITEM: u32 = 0x4259_5445; // BYTE
const U64_ITEM: u32 = 0x5536_3420; // U64<space>
const CHALLENGE_ITEM: u32 = 0x4348_414c; // CHAL
const OPENING_BASE_ITEM: u32 = 0x4f42_4153; // OBAS

fn scalar_pow2(exponent: usize) -> Scalar {
    let mut value = Scalar::ONE;
    for _ in 0..exponent {
        value = value + value;
    }
    value
}

fn integer_from_be(bytes: &[u8]) -> Scalar {
    bytes.iter().fold(Scalar::ZERO, |value, byte| {
        value * Scalar::from(256) + Scalar::from(u64::from(*byte))
    })
}

fn suite_capacity() -> Scalar {
    integer_from_be(SUITE_ID)
}

fn header_base(item_type: u32) -> Scalar {
    Scalar::from(u64::from(item_type)) * scalar_pow2(64)
}

fn header(item_type: u32, auxiliary: u64) -> Scalar {
    header_base(item_type) + Scalar::from(auxiliary)
}

fn pow5(builder: &mut Builder, value: &Expression) -> Expression {
    let square = builder.multiply(value, value);
    let fourth = builder.multiply(&square, &square);
    builder.multiply(&fourth, value)
}

/// Constrain one exact candidate Poseidon permutation.
pub(crate) fn permute(
    builder: &mut Builder,
    mut state: [Expression; WIDTH],
) -> [Expression; WIDTH] {
    let parameters = parameters();
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        for (index, value) in state.iter_mut().enumerate() {
            *value = value.clone().add(&Expression::constant(
                parameters.round_constants[round * WIDTH + index],
            ));
        }

        let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&round);
        if full {
            for value in &mut state {
                *value = pow5(builder, value);
            }
        } else {
            state[0] = pow5(builder, &state[0]);
        }

        state = array::from_fn(|row| {
            (0..WIDTH).fold(Expression::constant(crate::Scalar::ZERO), |sum, column| {
                sum.add(&state[column].clone().scale(parameters.mds[row][column]))
            })
        });
    }
    state
}

/// Candidate typed duplex transcript on the canonical parent relation.
#[derive(Clone)]
pub(crate) struct BuilderTranscript {
    state: [Expression; WIDTH],
    rate_index: usize,
}

/// One canonical 32-byte value allocated without placing its contents in the
/// relation matrix.
///
/// Transcript byte strings use 31-byte big-endian field words. Allocating the
/// original bytes as bits both fixes that encoding and keeps different digest
/// values in the assignment rather than in constraint coefficients.
#[derive(Clone)]
pub(crate) struct ConstrainedBytes32 {
    words: [Expression; 2],
}

impl ConstrainedBytes32 {
    pub(crate) fn allocate(builder: &mut Builder, bytes: [u8; 32]) -> Self {
        let mut words = Vec::with_capacity(2);
        for chunk in bytes.chunks(31) {
            let mut word = Expression::constant(Scalar::ZERO);
            for &byte in chunk {
                let mut constrained_byte = Expression::constant(Scalar::ZERO);
                let mut coefficient = Scalar::ONE;
                for bit in 0..8 {
                    let allocated = builder.allocate_boolean(byte & (1 << bit) != 0);
                    constrained_byte = constrained_byte.add(&allocated.scale(coefficient));
                    coefficient = coefficient + coefficient;
                }
                word = word.scale(Scalar::from(256)).add(&constrained_byte);
            }
            words.push(word);
        }
        Self {
            words: words
                .try_into()
                .expect("a 32-byte value has two transcript words"),
        }
    }

    pub(crate) fn append_to(
        &self,
        transcript: &mut BuilderTranscript,
        builder: &mut Builder,
    ) -> Result<(), ReceiptCycleError> {
        transcript.append_byte_words(builder, 32, &self.words)
    }
}

impl BuilderTranscript {
    pub(crate) fn new() -> Self {
        Self {
            state: [
                Expression::constant(suite_capacity()),
                Expression::constant(Scalar::ZERO),
                Expression::constant(Scalar::ZERO),
            ],
            rate_index: 0,
        }
    }

    fn absorb(&mut self, builder: &mut Builder, value: Expression) {
        let lane = self.rate_index + 1;
        self.state[lane] = self.state[lane].clone().add(&value);
        self.rate_index += 1;
        if self.rate_index == WIDTH - 1 {
            self.state = permute(builder, self.state.clone());
            self.rate_index = 0;
        }
    }

    fn absorb_header(&mut self, builder: &mut Builder, item_type: u32, auxiliary: Expression) {
        self.absorb(
            builder,
            Expression::constant(header_base(item_type)).add(&auxiliary),
        );
    }

    pub(crate) fn append_field(&mut self, builder: &mut Builder, value: Expression) {
        self.absorb(builder, Expression::constant(header(FIELD_ITEM, 0)));
        self.absorb(builder, value);
    }

    pub(crate) fn append_scalar(&mut self, builder: &mut Builder, value: Expression) {
        self.absorb(builder, Expression::constant(header(SCALAR_ITEM, 0)));
        self.absorb(builder, value);
    }

    pub(crate) fn append_point(
        &mut self,
        builder: &mut Builder,
        prefix: Expression,
        x: Expression,
    ) {
        self.absorb_header(builder, POINT_ITEM, prefix);
        self.absorb(builder, x);
    }

    pub(crate) fn append_point_pair(
        &mut self,
        builder: &mut Builder,
        parity: Expression,
        first_x: Expression,
        second_x: Expression,
    ) {
        self.absorb_header(builder, POINT_PAIR_ITEM, parity);
        self.absorb(builder, first_x);
        self.absorb(builder, second_x);
    }

    /// Append already constrained 31-byte big-endian limbs.
    pub(crate) fn append_byte_words(
        &mut self,
        builder: &mut Builder,
        byte_length: usize,
        words: &[Expression],
    ) -> Result<(), ReceiptCycleError> {
        let expected = byte_length
            .checked_add(30)
            .ok_or(ReceiptCycleError::Malformed("transcript byte length"))?
            / 31;
        if words.len() != expected {
            return Err(ReceiptCycleError::Malformed("transcript byte words"));
        }
        let byte_length = u64::try_from(byte_length)
            .map_err(|_| ReceiptCycleError::Malformed("transcript byte length"))?;
        self.absorb(
            builder,
            Expression::constant(header(BYTES_ITEM, byte_length)),
        );
        for word in words {
            self.absorb(builder, word.clone());
        }
        Ok(())
    }

    pub(crate) fn append_bytes32(
        &mut self,
        builder: &mut Builder,
        bytes: &ConstrainedBytes32,
    ) -> Result<(), ReceiptCycleError> {
        bytes.append_to(self, builder)
    }

    pub(crate) fn append_u64(&mut self, builder: &mut Builder, value: u64) {
        self.absorb(builder, Expression::constant(header(U64_ITEM, value)));
    }

    /// Clone, frame, and squeeze two candidate coordinate-field lanes.
    pub(crate) fn challenge(&self, builder: &mut Builder, round: u64) -> [Expression; 2] {
        let mut challenge = self.clone();
        challenge.absorb(builder, Expression::constant(header(CHALLENGE_ITEM, round)));
        challenge.absorb(builder, Expression::constant(Scalar::ONE));
        while challenge.rate_index != 0 {
            challenge.absorb(builder, Expression::constant(Scalar::ZERO));
        }
        [challenge.state[1].clone(), challenge.state[2].clone()]
    }

    /// Clone, frame, and squeeze two opening-base scalar candidates.
    ///
    /// This has a distinct item type from scalar challenges. The two lanes
    /// feed unbiased selection modulo the secp256k1 group order before the
    /// selected scalar combines two unknown-discrete-log constants.
    pub(crate) fn opening_base_scalar(
        &self,
        builder: &mut Builder,
        basis_digest: [u8; 32],
        role: u64,
    ) -> [Expression; 2] {
        let mut challenge = self.clone();
        challenge.absorb(
            builder,
            Expression::constant(header(BYTES_ITEM, basis_digest.len() as u64)),
        );
        for word in basis_digest.chunks(31).map(integer_from_be) {
            challenge.absorb(builder, Expression::constant(word));
        }
        challenge.absorb(
            builder,
            Expression::constant(header(OPENING_BASE_ITEM, role)),
        );
        challenge.absorb(builder, Expression::constant(Scalar::ONE));
        while challenge.rate_index != 0 {
            challenge.absorb(builder, Expression::constant(Scalar::ZERO));
        }
        [challenge.state[1].clone(), challenge.state[2].clone()]
    }
}

#[cfg(test)]
#[derive(Clone)]
struct NativeTranscript {
    state: [Scalar; WIDTH],
    rate_index: usize,
}

#[cfg(test)]
impl NativeTranscript {
    fn new() -> Self {
        Self {
            state: [suite_capacity(), Scalar::ZERO, Scalar::ZERO],
            rate_index: 0,
        }
    }

    fn absorb(&mut self, value: Scalar) {
        self.state[self.rate_index + 1] += value;
        self.rate_index += 1;
        if self.rate_index == WIDTH - 1 {
            self.state = crate::poseidon::permute(self.state);
            self.rate_index = 0;
        }
    }

    fn append_field(&mut self, value: Scalar) {
        self.absorb(header(FIELD_ITEM, 0));
        self.absorb(value);
    }

    fn append_scalar(&mut self, value: Scalar) {
        self.absorb(header(SCALAR_ITEM, 0));
        self.absorb(value);
    }

    fn append_point(&mut self, prefix: u8, x: Scalar) {
        self.absorb(header(POINT_ITEM, u64::from(prefix)));
        self.absorb(x);
    }

    fn append_point_pair(&mut self, parity: u8, first_x: Scalar, second_x: Scalar) {
        assert!(parity <= 3);
        self.absorb(header(POINT_PAIR_ITEM, u64::from(parity)));
        self.absorb(first_x);
        self.absorb(second_x);
    }

    fn append_bytes(&mut self, bytes: &[u8]) {
        self.absorb(header(BYTES_ITEM, bytes.len() as u64));
        for word in byte_words(bytes) {
            self.absorb(word);
        }
    }

    fn append_u64(&mut self, value: u64) {
        self.absorb(header(U64_ITEM, value));
    }

    fn challenge(&self, round: u64) -> [Scalar; 2] {
        let mut challenge = self.clone();
        challenge.absorb(header(CHALLENGE_ITEM, round));
        challenge.absorb(Scalar::ONE);
        while challenge.rate_index != 0 {
            challenge.absorb(Scalar::ZERO);
        }
        [challenge.state[1], challenge.state[2]]
    }

    fn opening_base_scalar(&self, basis_digest: [u8; 32], role: u64) -> [Scalar; 2] {
        let mut challenge = self.clone();
        challenge.append_bytes(&basis_digest);
        challenge.absorb(header(OPENING_BASE_ITEM, role));
        challenge.absorb(Scalar::ONE);
        while challenge.rate_index != 0 {
            challenge.absorb(Scalar::ZERO);
        }
        [challenge.state[1], challenge.state[2]]
    }
}

#[cfg(test)]
pub(crate) fn native_opening_base_probe(
    fields: [Scalar; 2],
    basis_digest: [u8; 32],
    role: u64,
) -> [Scalar; 2] {
    let mut transcript = NativeTranscript::new();
    transcript.append_field(fields[0]);
    transcript.append_field(fields[1]);
    transcript.opening_base_scalar(basis_digest, role)
}

#[cfg(test)]
fn byte_words(bytes: &[u8]) -> Vec<Scalar> {
    bytes.chunks(31).map(integer_from_be).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bulletproofs_cycle::Cycle;
    use ff::Field;
    use golden_halo2curves::Secq256k1Cycle;

    use crate::{poseidon, proof_wire_len, prove, verify, ReceiptCycleError, Scalar};

    fn decode_hex<const SIZE: usize>(value: &str) -> [u8; SIZE] {
        assert_eq!(value.len(), 2 * SIZE);
        array::from_fn(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex")
        })
    }

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        assert_eq!(value.len() & 1, 0);
        (0..value.len() / 2)
            .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex"))
            .collect()
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

    fn scalar_hex(value: &str) -> Scalar {
        integer_from_be(&decode_hex::<32>(value))
    }

    fn selected_scalar(lanes: [Scalar; 2]) -> Scalar {
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        lanes
            .into_iter()
            .find(|value| {
                let mut encoded = Secq256k1Cycle::scalar_to_canonical(value);
                encoded.reverse();
                *value != Scalar::ZERO && encoded < ORDER
            })
            .expect("nonzero secp scalar lane")
    }

    fn append_point_hex(transcript: &mut NativeTranscript, value: &str) {
        let encoded = decode_hex::<33>(value);
        transcript.append_point(encoded[0], integer_from_be(&encoded[1..]));
    }

    fn append_polynomial_hex(transcript: &mut NativeTranscript, value: &str) {
        let encoded = decode_hex_vec(value);
        let mut offset = 0;
        let take_u64 = |offset: &mut usize| {
            let end = *offset + 8;
            let value = u64::from_le_bytes(encoded[*offset..end].try_into().expect("u64"));
            *offset = end;
            value
        };
        let term_count = take_u64(&mut offset);
        transcript.append_u64(term_count);
        for _ in 0..term_count {
            let end = offset + 32;
            transcript.append_scalar(integer_from_be(&encoded[offset..end]));
            offset = end;
            transcript.append_u64(take_u64(&mut offset));
            let factors = take_u64(&mut offset);
            transcript.append_u64(factors);
            for _ in 0..factors {
                let end = offset + 32;
                transcript.append_scalar(integer_from_be(&encoded[offset..end]));
                offset = end;
            }
        }
        assert_eq!(offset, encoded.len());
    }

    #[derive(Clone)]
    struct Probe {
        field: Scalar,
        scalar: Scalar,
        parity: u8,
        first_x: Scalar,
        second_x: Scalar,
        bytes: Vec<u8>,
        counter: u64,
        round: u64,
    }

    fn probe(seed: u64) -> Probe {
        let mut bytes = (0..33)
            .map(|index| (seed as u8).wrapping_add(index as u8))
            .collect::<Vec<_>>();
        bytes[0] |= 1;
        Probe {
            field: Scalar::from(seed + 1),
            scalar: Scalar::from(seed + 2),
            parity: (seed as u8) & 3,
            first_x: Scalar::from(seed + 3),
            second_x: Scalar::from(seed + 4),
            bytes,
            counter: seed + 5,
            round: seed + 6,
        }
    }

    fn native_probe(probe: &Probe) -> [Scalar; 2] {
        let mut transcript = NativeTranscript::new();
        transcript.append_field(probe.field);
        transcript.append_scalar(probe.scalar);
        transcript.append_point_pair(probe.parity, probe.first_x, probe.second_x);
        transcript.append_bytes(&probe.bytes);
        transcript.append_u64(probe.counter);
        transcript.challenge(probe.round)
    }

    fn build_transcript_relation(
        probe: &Probe,
        expected: [Scalar; 2],
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let field = builder.allocate(probe.field);
        let scalar = builder.allocate(probe.scalar);
        let parity = builder.allocate(Scalar::from(u64::from(probe.parity)));
        let first_x = builder.allocate(probe.first_x);
        let second_x = builder.allocate(probe.second_x);
        let words = byte_words(&probe.bytes)
            .into_iter()
            .map(|word| builder.allocate(word))
            .collect::<Vec<_>>();
        let expected = expected.map(|value| builder.allocate(value));

        let mut transcript = BuilderTranscript::new();
        transcript.append_field(&mut builder, field);
        transcript.append_scalar(&mut builder, scalar);
        transcript.append_point_pair(&mut builder, parity, first_x, second_x);
        transcript.append_byte_words(&mut builder, probe.bytes.len(), &words)?;
        transcript.append_u64(&mut builder, probe.counter);
        let challenge = transcript.challenge(&mut builder, probe.round);
        for index in 0..challenge.len() {
            builder.constrain_equal(&challenge[index], &expected[index]);
        }
        builder.finish()
    }

    fn build_bytes32_relation(
        bytes: [u8; 32],
        expected: [Scalar; 2],
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let bytes = ConstrainedBytes32::allocate(&mut builder, bytes);
        let expected = expected.map(|value| builder.allocate(value));
        let mut transcript = BuilderTranscript::new();
        transcript.append_bytes32(&mut builder, &bytes)?;
        let challenge = transcript.challenge(&mut builder, 0);
        for index in 0..challenge.len() {
            builder.constrain_equal(&challenge[index], &expected[index]);
        }
        builder.finish()
    }

    fn build_relation(
        input: [Scalar; WIDTH],
        expected: [Scalar; WIDTH],
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let input = input.map(|value| builder.allocate(value));
        let expected = expected.map(|value| builder.allocate(value));
        let output = permute(&mut builder, input);
        for index in 0..WIDTH {
            builder.constrain_equal(&output[index], &expected[index]);
        }
        builder.finish()
    }

    #[test]
    fn builder_permutation_matches_native_and_has_fixed_shape() {
        let first = [Scalar::ZERO, Scalar::ONE, Scalar::from(2)];
        let second = [Scalar::from(9), Scalar::from(11), Scalar::from(13)];
        let (first_circuit, _) =
            build_relation(first, poseidon::permute(first)).expect("first relation");
        let (second_circuit, _) =
            build_relation(second, poseidon::permute(second)).expect("second relation");
        assert_eq!(first_circuit, second_circuit);
        assert_eq!(
            u32::from_le_bytes(first_circuit[1..5].try_into().expect("gate count")),
            270
        );
        assert_eq!(proof_wire_len(&first_circuit).expect("proof size"), 1019);
    }

    #[test]
    fn builder_permutation_proof_binds_the_output() {
        let input = [Scalar::from(3), Scalar::from(5), Scalar::from(8)];
        let output = poseidon::permute(input);
        let (circuit, assignment) = build_relation(input, output).expect("relation");
        let statement = b"builder Poseidon foundation";
        let proof = prove(&circuit, &assignment, statement, [0x61; 32]).expect("proof");
        verify(&circuit, statement, &proof).expect("verification");

        let mut changed = output;
        changed[1] += Scalar::ONE;
        let (_, false_assignment) = build_relation(input, changed).expect("false relation");
        let false_proof =
            prove(&circuit, &false_assignment, statement, [0x62; 32]).expect("false proof");
        assert!(verify(&circuit, statement, &false_proof).is_err());
    }

    #[test]
    fn typed_transcript_matches_native_and_has_fixed_shape() {
        let first = probe(1);
        let mut second = probe(17);
        second.counter = first.counter;
        second.round = first.round;
        let first_expected = native_probe(&first);
        let second_expected = native_probe(&second);
        let (first_circuit, _) =
            build_transcript_relation(&first, first_expected).expect("first transcript");
        let (second_circuit, _) =
            build_transcript_relation(&second, second_expected).expect("second transcript");
        assert_eq!(first_circuit, second_circuit);
        assert_eq!(
            u32::from_le_bytes(first_circuit[1..5].try_into().expect("gate count")),
            1857
        );
        assert_eq!(proof_wire_len(&first_circuit).expect("proof size"), 1151);
    }

    #[test]
    fn typed_items_and_lengths_are_unambiguous() {
        let challenge = |transcript: &NativeTranscript| transcript.challenge(9);

        let mut field = NativeTranscript::new();
        field.append_field(Scalar::from(7));
        let mut scalar = NativeTranscript::new();
        scalar.append_scalar(Scalar::from(7));
        assert_ne!(challenge(&field), challenge(&scalar));

        let mut short = NativeTranscript::new();
        short.append_bytes(&[1]);
        let mut leading_zero = NativeTranscript::new();
        leading_zero.append_bytes(&[0, 1]);
        assert_ne!(challenge(&short), challenge(&leading_zero));

        let mut joined = NativeTranscript::new();
        joined.append_bytes(b"ab");
        let mut split = NativeTranscript::new();
        split.append_bytes(b"a");
        split.append_bytes(b"b");
        assert_ne!(challenge(&joined), challenge(&split));

        let mut even = NativeTranscript::new();
        even.append_point_pair(0, Scalar::from(3), Scalar::from(5));
        let mut odd = NativeTranscript::new();
        odd.append_point_pair(1, Scalar::from(3), Scalar::from(5));
        assert_ne!(challenge(&even), challenge(&odd));

        let mut point = NativeTranscript::new();
        point.append_point(2, Scalar::from(3));
        let mut point_pair = NativeTranscript::new();
        point_pair.append_point_pair(2, Scalar::from(3), Scalar::ZERO);
        assert_ne!(challenge(&point), challenge(&point_pair));

        let first = joined.challenge(1);
        let second = joined.challenge(2);
        assert_ne!(first, second);
        assert_eq!(first, joined.challenge(1));

        let opening_base = joined.opening_base_scalar([0x31; 32], 1);
        assert_ne!(opening_base, first);
        assert_ne!(opening_base, joined.opening_base_scalar([0x31; 32], 2));
        assert_ne!(opening_base, joined.opening_base_scalar([0x32; 32], 1));
    }

    #[test]
    fn native_transcript_matches_cross_language_vectors() {
        let vectors = include_str!("../tests/vectors/algebraic_transcript_v1.txt");
        for line in vectors.lines().filter(|line| line.starts_with("vector ")) {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(words.len(), 7);
            let seed = words[1].parse::<u64>().expect("seed");
            let basis_digest = decode_hex::<32>(words[2]);

            let mut transcript = NativeTranscript::new();
            transcript.append_field(Scalar::from(seed + 1));
            transcript.append_scalar(Scalar::from(seed + 2));
            transcript.append_point(2 + (seed as u8 & 1), Scalar::from(seed + 3));
            transcript.append_point_pair(
                seed as u8 & 3,
                Scalar::from(seed + 4),
                Scalar::from(seed + 5),
            );
            let bytes = (0..33)
                .map(|index| (seed as u8).wrapping_add(index as u8))
                .collect::<Vec<_>>();
            transcript.append_bytes(&bytes);
            transcript.append_u64(seed + 6);

            let expected = |word: &str| integer_from_be(&decode_hex::<32>(word));
            assert_eq!(
                transcript.challenge(seed + 7),
                [expected(words[3]), expected(words[4])]
            );
            assert_eq!(
                transcript.opening_base_scalar(basis_digest, 1 + (seed & 1)),
                [expected(words[5]), expected(words[6])]
            );
        }
    }

    #[test]
    fn constrained_bytes32_match_reference_vectors_with_fixed_matrix() {
        let vectors = include_str!("../tests/vectors/algebraic_transcript_v1.txt");
        let mut relations = Vec::new();
        for line in vectors.lines().filter(|line| line.starts_with("bytes32 ")) {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(words.len(), 4);
            let bytes = decode_hex::<32>(words[1]);
            let expected = [
                integer_from_be(&decode_hex::<32>(words[2])),
                integer_from_be(&decode_hex::<32>(words[3])),
            ];

            let mut native = NativeTranscript::new();
            native.append_bytes(&bytes);
            assert_eq!(native.challenge(0), expected);
            relations.push(build_bytes32_relation(bytes, expected).expect("bytes32 relation"));
        }
        assert_eq!(relations.len(), 2);
        assert_eq!(relations[0].0, relations[1].0);
        assert_ne!(relations[0].1, relations[1].1);
    }

    #[test]
    fn complete_accumulation_context_matches_shared_vector() {
        let vector = include_str!("../tests/vectors/algebraic_accumulation_v2.json");
        let basis = decode_hex::<32>(json_string(vector, "basis_digest"));

        let mut norm = NativeTranscript::new();
        norm.append_bytes(b"Purify/BPPP/CandidateNormReduction/v2");
        norm.append_bytes(&basis);
        norm.append_u64(1);
        norm.append_scalar(scalar_hex(json_string(vector, "prepared_binding")));
        append_point_hex(&mut norm, json_string(vector, "coefficient_commitment"));
        append_polynomial_hex(&mut norm, json_string(vector, "norm_weights"));
        norm.append_scalar(scalar_hex(json_string(vector, "coefficient_evaluation")));
        let norm_lanes = json_array(vector, "norm_opening_lanes")
            .into_iter()
            .map(scalar_hex)
            .collect::<Vec<_>>();
        assert_eq!(
            norm.opening_base_scalar(basis, 1),
            [norm_lanes[0], norm_lanes[1]],
        );
        assert_eq!(
            selected_scalar([norm_lanes[0], norm_lanes[1]]),
            scalar_hex(json_string(vector, "norm_opening_scalar")),
        );
        append_point_hex(&mut norm, json_string(vector, "norm_opening"));
        let left = json_array(vector, "norm_round_left");
        let right = json_array(vector, "norm_round_right");
        let challenge = json_array(vector, "norm_round_challenge");
        for round in 0..left.len() {
            append_point_hex(&mut norm, left[round]);
            append_point_hex(&mut norm, right[round]);
            let expected = scalar_hex(challenge[round]);
            assert_eq!(selected_scalar(norm.challenge(round as u64)), expected,);
            norm.append_scalar(expected);
        }
        norm.append_scalar(scalar_hex(json_string(vector, "norm_terminal")));
        append_point_hex(&mut norm, json_string(vector, "norm_folded_generator"));
        append_point_hex(&mut norm, json_string(vector, "norm_point"));
        append_polynomial_hex(&mut norm, json_string(vector, "norm_polynomial"));
        append_polynomial_hex(&mut norm, json_string(vector, "folded_polynomial"));
        let chi = scalar_hex(json_string(vector, "fusion_challenge"));
        assert_eq!(selected_scalar(norm.challenge(1)), chi);
        norm.append_scalar(chi);

        let mut step = NativeTranscript::new();
        step.append_bytes(b"Purify/BPPP/CandidateAccumStep/v1");
        step.append_bytes(&basis);
        step.append_u64(3);
        step.append_u64(1);
        append_point_hex(&mut step, json_string(vector, "claim_point"));
        append_polynomial_hex(&mut step, json_string(vector, "claim_polynomial"));
        let beta = scalar_hex(json_string(vector, "step_beta"));
        assert_eq!(selected_scalar(step.challenge(0)), beta);
        step.append_scalar(beta);
        append_point_hex(&mut step, json_string(vector, "claim_point"));
        let x = scalar_hex(json_string(vector, "step_x"));
        assert_eq!(selected_scalar(step.challenge(1)), x);
        step.append_scalar(x);
        step.append_scalar(scalar_hex(json_string(vector, "step_y")));
        let step_lanes = json_array(vector, "step_opening_lanes")
            .into_iter()
            .map(scalar_hex)
            .collect::<Vec<_>>();
        assert_eq!(
            step.opening_base_scalar(basis, 2),
            [step_lanes[0], step_lanes[1]],
        );
        assert_eq!(
            selected_scalar([step_lanes[0], step_lanes[1]]),
            scalar_hex(json_string(vector, "step_opening_scalar")),
        );
        append_point_hex(&mut step, json_string(vector, "step_opening"));
        let left = json_array(vector, "step_round_left");
        let right = json_array(vector, "step_round_right");
        let challenge = json_array(vector, "step_round_challenge");
        for round in 0..left.len() {
            append_point_hex(&mut step, left[round]);
            append_point_hex(&mut step, right[round]);
            let expected = scalar_hex(challenge[round]);
            assert_eq!(selected_scalar(step.challenge(2 + round as u64)), expected,);
            step.append_scalar(expected);
        }
    }

    #[test]
    fn byte_word_shape_is_checked() {
        let mut builder = Builder::default();
        let mut transcript = BuilderTranscript::new();
        let one_word = [Expression::constant(Scalar::ONE)];
        assert!(transcript
            .append_byte_words(&mut builder, 32, &one_word)
            .is_err());
    }

    #[test]
    #[ignore = "run explicitly in release mode; transcript backend proof is slow in debug mode"]
    fn transcript_backend_proof_binds_witness_and_output() {
        let value = probe(5);
        let expected = native_probe(&value);
        let (circuit, assignment) =
            build_transcript_relation(&value, expected).expect("transcript relation");
        let statement = b"typed Poseidon transcript foundation";
        let proof = prove(&circuit, &assignment, statement, [0x63; 32]).expect("proof");
        verify(&circuit, statement, &proof).expect("verification");

        let mut changed_output = expected;
        changed_output[0] += Scalar::ONE;
        let (_, false_output) =
            build_transcript_relation(&value, changed_output).expect("changed output");
        let false_proof =
            prove(&circuit, &false_output, statement, [0x64; 32]).expect("false proof");
        assert!(verify(&circuit, statement, &false_proof).is_err());

        let mut changed_witness = value.clone();
        changed_witness.scalar += Scalar::ONE;
        let (_, false_witness) =
            build_transcript_relation(&changed_witness, expected).expect("changed witness");
        let false_proof =
            prove(&circuit, &false_witness, statement, [0x65; 32]).expect("false proof");
        assert!(verify(&circuit, statement, &false_proof).is_err());
    }
}
