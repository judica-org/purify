//! Typed SHA-256 transcript shared by native and constrained parent logic.
//!
//! Each challenge hashes the full 256-bit prior digest, the typed items added
//! since the preceding challenge, and one typed round marker. The resulting
//! digest becomes the next state and pending items are cleared. Challenge
//! scalars use the low 255 digest bits, which are canonical in both secp256k1
//! fields. Native derivation rejects zero; constrained consumers install the
//! inverse-backed nonzero constraint when they convert the scalar image.

use ff::Field;
use sha2::{Digest as _, Sha256};

use crate::relation_builder::Builder;
#[cfg(test)]
use crate::relation_builder::Expression;
use crate::sha256_builder::{self, Byte, Scalar255};
use crate::{ReceiptCycleError, Scalar};

const SUITE_ID: &[u8] = b"Purify/SHA256Transcript/v1";

const FIELD_ITEM: u32 = 0x4649_454c; // FIEL
const SCALAR_ITEM: u32 = 0x5343_414c; // SCAL
const POINT_ITEM: u32 = 0x504f_494e; // POIN
const POINT_PAIR_ITEM: u32 = 0x5041_4952; // PAIR
const BYTES_ITEM: u32 = 0x4259_5445; // BYTE
const U64_ITEM: u32 = 0x5536_3420; // U64<space>
const CHALLENGE_ITEM: u32 = 0x4348_414c; // CHAL
const OPENING_BASE_ITEM: u32 = 0x4f42_4153; // OBAS

const HEADER_SIZE: usize = 12;

fn header(item_type: u32, auxiliary: u64) -> [u8; HEADER_SIZE] {
    let mut encoded = [0u8; HEADER_SIZE];
    encoded[..4].copy_from_slice(&item_type.to_be_bytes());
    encoded[4..].copy_from_slice(&auxiliary.to_be_bytes());
    encoded
}

fn constrained_header(item_type: u32, auxiliary: u64) -> [Byte; HEADER_SIZE] {
    header(item_type, auxiliary).map(Byte::constant)
}

fn constrained_byte_header(item_type: u32, auxiliary: &Byte) -> [Byte; HEADER_SIZE] {
    let mut encoded = constrained_header(item_type, 0);
    encoded[HEADER_SIZE - 1] = auxiliary.clone();
    encoded
}

fn scalar_from_digest(mut digest: [u8; 32]) -> Scalar {
    digest[0] &= 0x7f;
    digest.iter().fold(Scalar::ZERO, |value, byte| {
        value * Scalar::from(256) + Scalar::from(u64::from(*byte))
    })
}

/// One constrained transcript output.
#[derive(Clone, Debug)]
pub(crate) struct BuilderChallenge {
    digest: [Byte; 32],
    scalar: Scalar255,
}

impl BuilderChallenge {
    pub(crate) fn digest(&self) -> &[Byte; 32] {
        &self.digest
    }

    pub(crate) fn digest_value(&self) -> [u8; 32] {
        self.digest.each_ref().map(Byte::value)
    }

    pub(crate) fn scalar(&self) -> &Scalar255 {
        &self.scalar
    }
}

/// Typed SHA-256 transcript over constrained canonical bytes.
#[derive(Clone, Debug)]
pub(crate) struct BuilderTranscript {
    state: [Byte; 32],
    pending: Vec<Byte>,
}

impl BuilderTranscript {
    pub(crate) fn new() -> Self {
        let state: [u8; 32] = Sha256::digest(SUITE_ID).into();
        Self {
            state: state.map(Byte::constant),
            pending: Vec::new(),
        }
    }

    fn append_header(&mut self, item_type: u32, auxiliary: u64) {
        self.pending
            .extend(constrained_header(item_type, auxiliary));
    }

    fn append_byte_header(&mut self, item_type: u32, auxiliary: &Byte) {
        self.pending
            .extend(constrained_byte_header(item_type, auxiliary));
    }

    pub(crate) fn append_field(&mut self, value: &[Byte; 32]) {
        self.append_header(FIELD_ITEM, 0);
        self.pending.extend_from_slice(value);
    }

    pub(crate) fn append_scalar(&mut self, value: &[Byte; 32]) {
        self.append_header(SCALAR_ITEM, 0);
        self.pending.extend_from_slice(value);
    }

    pub(crate) fn append_point(&mut self, prefix: &Byte, x: &[Byte; 32]) {
        self.append_byte_header(POINT_ITEM, prefix);
        self.pending.extend_from_slice(x);
    }

    pub(crate) fn append_point_pair(
        &mut self,
        parity: &Byte,
        first_x: &[Byte; 32],
        second_x: &[Byte; 32],
    ) {
        self.append_byte_header(POINT_PAIR_ITEM, parity);
        self.pending.extend_from_slice(first_x);
        self.pending.extend_from_slice(second_x);
    }

    pub(crate) fn append_bytes(&mut self, value: &[Byte]) -> Result<(), ReceiptCycleError> {
        let length = u64::try_from(value.len())
            .map_err(|_| ReceiptCycleError::Malformed("SHA transcript byte length"))?;
        self.append_header(BYTES_ITEM, length);
        self.pending.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_u64(&mut self, value: u64) {
        self.append_header(U64_ITEM, value);
    }

    /// Advance using the full digest while exposing its low 255-bit scalar.
    pub(crate) fn challenge(
        &mut self,
        builder: &mut Builder,
        round: u64,
    ) -> Result<BuilderChallenge, ReceiptCycleError> {
        let mut message = Vec::with_capacity(
            self.state
                .len()
                .checked_add(self.pending.len())
                .and_then(|length| length.checked_add(HEADER_SIZE))
                .ok_or(ReceiptCycleError::Malformed("SHA transcript length"))?,
        );
        message.extend_from_slice(&self.state);
        message.extend_from_slice(&self.pending);
        message.extend(constrained_header(CHALLENGE_ITEM, round));
        let digest = sha256_builder::hash(builder, &message)?;
        let scalar = digest.scalar_255();
        let digest = digest.bytes().clone();
        self.state = digest.clone();
        self.pending.clear();
        Ok(BuilderChallenge { digest, scalar })
    }

    /// Derive an opening scalar without changing the source transcript.
    pub(crate) fn opening_base_scalar(
        &self,
        builder: &mut Builder,
        basis_digest: [u8; 32],
        role: u64,
    ) -> Result<BuilderChallenge, ReceiptCycleError> {
        let mut fork = self.clone();
        let basis = basis_digest.map(Byte::constant);
        fork.append_bytes(&basis)?;
        fork.pending
            .extend(constrained_header(OPENING_BASE_ITEM, role));
        let mut message = Vec::with_capacity(
            fork.state
                .len()
                .checked_add(fork.pending.len())
                .ok_or(ReceiptCycleError::Malformed("SHA transcript length"))?,
        );
        message.extend_from_slice(&fork.state);
        message.extend_from_slice(&fork.pending);
        let digest = sha256_builder::hash(builder, &message)?;
        let scalar = digest.scalar_255();
        Ok(BuilderChallenge {
            digest: digest.bytes().clone(),
            scalar,
        })
    }
}

/// Native transcript output with the full digest retained for chaining.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeChallenge {
    pub(crate) digest: [u8; 32],
    pub(crate) scalar: Scalar,
}

fn native_challenge_from_digest(digest: [u8; 32]) -> Result<NativeChallenge, ReceiptCycleError> {
    let scalar = scalar_from_digest(digest);
    if scalar == Scalar::ZERO {
        return Err(ReceiptCycleError::Malformed(
            "zero SHA transcript challenge",
        ));
    }
    Ok(NativeChallenge { digest, scalar })
}

/// Native counterpart to [`BuilderTranscript`].
#[derive(Clone, Debug)]
pub(crate) struct NativeTranscript {
    state: [u8; 32],
    pending: Vec<u8>,
}

impl NativeTranscript {
    pub(crate) fn new() -> Self {
        Self {
            state: Sha256::digest(SUITE_ID).into(),
            pending: Vec::new(),
        }
    }

    fn append_header(&mut self, item_type: u32, auxiliary: u64) {
        self.pending.extend(header(item_type, auxiliary));
    }

    pub(crate) fn append_field(&mut self, value: [u8; 32]) {
        self.append_header(FIELD_ITEM, 0);
        self.pending.extend(value);
    }

    pub(crate) fn append_scalar(&mut self, value: [u8; 32]) {
        self.append_header(SCALAR_ITEM, 0);
        self.pending.extend(value);
    }

    pub(crate) fn append_point(
        &mut self,
        prefix: u8,
        x: [u8; 32],
    ) -> Result<(), ReceiptCycleError> {
        if !matches!(prefix, 0 | 2 | 3) {
            return Err(ReceiptCycleError::Malformed("SHA transcript point prefix"));
        }
        if prefix == 0 && x != [0; 32] {
            return Err(ReceiptCycleError::Malformed(
                "SHA transcript point identity",
            ));
        }
        self.append_header(POINT_ITEM, u64::from(prefix));
        self.pending.extend(x);
        Ok(())
    }

    pub(crate) fn append_point_pair(
        &mut self,
        parity: u8,
        first_x: [u8; 32],
        second_x: [u8; 32],
    ) -> Result<(), ReceiptCycleError> {
        if parity > 3 {
            return Err(ReceiptCycleError::Malformed("SHA transcript pair parity"));
        }
        self.append_header(POINT_PAIR_ITEM, u64::from(parity));
        self.pending.extend(first_x);
        self.pending.extend(second_x);
        Ok(())
    }

    pub(crate) fn append_bytes(&mut self, value: &[u8]) -> Result<(), ReceiptCycleError> {
        let length = u64::try_from(value.len())
            .map_err(|_| ReceiptCycleError::Malformed("SHA transcript byte length"))?;
        self.append_header(BYTES_ITEM, length);
        self.pending.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_u64(&mut self, value: u64) {
        self.append_header(U64_ITEM, value);
    }

    pub(crate) fn challenge(&mut self, round: u64) -> Result<NativeChallenge, ReceiptCycleError> {
        let mut hash = Sha256::new();
        hash.update(self.state);
        hash.update(&self.pending);
        hash.update(header(CHALLENGE_ITEM, round));
        let digest = hash.finalize().into();
        let challenge = native_challenge_from_digest(digest)?;
        self.state = digest;
        self.pending.clear();
        Ok(challenge)
    }

    pub(crate) fn opening_base_scalar(
        &self,
        basis_digest: [u8; 32],
        role: u64,
    ) -> Result<NativeChallenge, ReceiptCycleError> {
        let mut hash = Sha256::new();
        hash.update(self.state);
        hash.update(&self.pending);
        hash.update(header(BYTES_ITEM, basis_digest.len() as u64));
        hash.update(basis_digest);
        hash.update(header(OPENING_BASE_ITEM, role));
        let digest = hash.finalize().into();
        native_challenge_from_digest(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bulletproofs_cycle::Cycle;
    use golden_halo2curves::Secq256k1Cycle;

    use crate::{Assignment, Circuit, WireKind};

    fn bytes32_from_u64(value: u64) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    fn native_vector_transcript(seed: u64) -> NativeTranscript {
        let mut transcript = NativeTranscript::new();
        transcript.append_field(bytes32_from_u64(seed + 1));
        transcript.append_scalar(bytes32_from_u64(seed + 2));
        transcript
            .append_point(2 + (seed & 1) as u8, bytes32_from_u64(seed + 3))
            .expect("vector point");
        transcript
            .append_point_pair(
                (seed & 3) as u8,
                bytes32_from_u64(seed + 4),
                bytes32_from_u64(seed + 5),
            )
            .expect("vector pair");
        let raw: Vec<u8> = (0..33).map(|index| (seed + index) as u8).collect();
        transcript.append_bytes(&raw).expect("vector bytes");
        transcript.append_u64(seed + 6);
        transcript
    }

    fn allocated_array(builder: &mut Builder, value: &[u8; 32]) -> [Byte; 32] {
        sha256_builder::allocate_bytes(builder, value)
            .try_into()
            .expect("32 bytes")
    }

    fn builder_vector_transcript_with_u64(
        builder: &mut Builder,
        seed: u64,
        final_u64: u64,
    ) -> BuilderTranscript {
        let mut transcript = BuilderTranscript::new();
        transcript.append_field(&allocated_array(builder, &bytes32_from_u64(seed + 1)));
        transcript.append_scalar(&allocated_array(builder, &bytes32_from_u64(seed + 2)));
        let prefix = sha256_builder::allocate_byte(builder, 2 + (seed & 1) as u8);
        transcript.append_point(
            &prefix,
            &allocated_array(builder, &bytes32_from_u64(seed + 3)),
        );
        let parity = sha256_builder::allocate_byte(builder, (seed & 3) as u8);
        transcript.append_point_pair(
            &parity,
            &allocated_array(builder, &bytes32_from_u64(seed + 4)),
            &allocated_array(builder, &bytes32_from_u64(seed + 5)),
        );
        let raw: Vec<u8> = (0..33).map(|index| (seed + index) as u8).collect();
        let raw = sha256_builder::allocate_bytes(builder, &raw);
        transcript.append_bytes(&raw).expect("vector bytes");
        transcript.append_u64(final_u64);
        transcript
    }

    fn builder_vector_transcript(builder: &mut Builder, seed: u64) -> BuilderTranscript {
        builder_vector_transcript_with_u64(builder, seed, seed + 6)
    }

    fn decode_hex<const SIZE: usize>(value: &str) -> [u8; SIZE] {
        assert_eq!(value.len(), 2 * SIZE);
        std::array::from_fn(|index| {
            u8::from_str_radix(&value[2 * index..2 * index + 2], 16).expect("hex")
        })
    }

    fn scalar_be(value: Scalar) -> [u8; 32] {
        let mut encoded = Secq256k1Cycle::scalar_to_canonical(&value);
        encoded.reverse();
        encoded
    }

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

    fn constrain_digest(builder: &mut Builder, digest: &[Byte; 32], expected: [u8; 32]) {
        for (byte, expected) in digest.iter().zip(expected) {
            for (index, bit) in byte.bits().iter().enumerate() {
                let value = Scalar::from(u64::from((expected >> index) & 1));
                builder.constrain_equal(bit.expression(), &Expression::constant(value));
            }
        }
    }

    type TranscriptVector = (u64, [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

    fn vectors() -> Vec<TranscriptVector> {
        include_str!("../tests/vectors/sha256_transcript_v1.txt")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                assert_eq!(fields[0], "vector");
                (
                    fields[1].parse().expect("seed"),
                    decode_hex(fields[2]),
                    decode_hex(fields[3]),
                    decode_hex(fields[4]),
                    decode_hex(fields[5]),
                    decode_hex(fields[6]),
                )
            })
            .collect()
    }

    #[test]
    fn native_and_builder_match_cross_language_vectors() {
        let vectors = vectors();
        for &(seed, basis, challenge_digest, challenge_scalar, opening_digest, opening_scalar) in
            &vectors
        {
            let mut transcript = native_vector_transcript(seed);
            let challenge = transcript
                .challenge(seed + 7)
                .expect("nonzero vector challenge");
            assert_eq!(challenge.digest, challenge_digest);
            assert_eq!(scalar_be(challenge.scalar), challenge_scalar);
            let opening = native_vector_transcript(seed)
                .opening_base_scalar(basis, 1 + (seed & 1))
                .expect("nonzero vector opening scalar");
            assert_eq!(opening.digest, opening_digest);
            assert_eq!(scalar_be(opening.scalar), opening_scalar);
        }

        let (seed, _, expected_digest, expected_scalar, _, _) = vectors[0];
        let mut builder = Builder::default();
        let mut transcript = builder_vector_transcript(&mut builder, seed);
        let challenge = transcript
            .challenge(&mut builder, seed + 7)
            .expect("builder challenge");
        assert_eq!(challenge.digest_value(), expected_digest);
        assert_eq!(scalar_be(challenge.scalar().value()), expected_scalar);
        let (circuit, assignment) = builder.finish().expect("relation");
        let circuit = Circuit::parse(&circuit).expect("circuit");
        let assignment = Assignment::parse(&assignment).expect("assignment");
        assert_eq!(circuit.gate_count, assignment.gates.len());
    }

    #[test]
    fn challenges_chain_the_full_digest_and_clear_pending() {
        let source = native_vector_transcript(9);
        let (mut transcript, first) = (0..256)
            .find_map(|round| {
                let mut candidate = source.clone();
                let challenge = candidate
                    .challenge(round)
                    .expect("nonzero fixed-round challenge");
                (challenge.digest[0] & 0x80 != 0).then_some((candidate, challenge))
            })
            .expect("one fixed round has a high digest bit");
        let second = transcript.challenge(300).expect("nonzero second challenge");

        let mut expected = Sha256::new();
        expected.update(first.digest);
        expected.update(header(CHALLENGE_ITEM, 300));
        assert_eq!(second.digest, <[u8; 32]>::from(expected.finalize()));

        let mut masked_state = first.digest;
        masked_state[0] &= 0x7f;
        let mut wrong = Sha256::new();
        wrong.update(masked_state);
        wrong.update(header(CHALLENGE_ITEM, 300));
        assert_ne!(second.digest, <[u8; 32]>::from(wrong.finalize()));
    }

    #[test]
    fn constrained_challenges_chain_the_high_digest_bit() {
        let (seed, _, expected_first, _, _, _) = vectors()
            .into_iter()
            .find(|vector| vector.0 == 255)
            .expect("seed-255 transcript vector");
        assert_ne!(expected_first[0] & 0x80, 0);

        let mut native = native_vector_transcript(seed);
        assert_eq!(
            native
                .challenge(seed + 7)
                .expect("nonzero first challenge")
                .digest,
            expected_first
        );
        let expected_second = native
            .challenge(seed + 8)
            .expect("nonzero second challenge")
            .digest;

        let mut masked_state = expected_first;
        masked_state[0] &= 0x7f;
        let mut masked = Sha256::new();
        masked.update(masked_state);
        masked.update(header(CHALLENGE_ITEM, seed + 8));
        let masked_second = <[u8; 32]>::from(masked.finalize());
        assert_ne!(expected_second, masked_second);

        let build = |expected| {
            let mut builder = Builder::default();
            let mut transcript = builder_vector_transcript(&mut builder, seed);
            let first = transcript
                .challenge(&mut builder, seed + 7)
                .expect("first constrained challenge");
            assert_eq!(first.digest_value(), expected_first);
            let second = transcript
                .challenge(&mut builder, seed + 8)
                .expect("second constrained challenge");
            constrain_digest(&mut builder, second.digest(), expected);
            builder.finish().expect("two-challenge relation")
        };

        let (circuit, assignment) = build(expected_second);
        assert!(relation_satisfied(&circuit, &assignment));
        let (masked_circuit, masked_assignment) = build(masked_second);
        assert!(!relation_satisfied(&masked_circuit, &masked_assignment));
    }

    #[test]
    fn opening_derivation_is_a_non_mutating_typed_fork() {
        let mut transcript = native_vector_transcript(23);
        let copy = transcript.clone();
        let basis = [0x42; 32];
        assert_eq!(
            transcript
                .opening_base_scalar(basis, 2)
                .expect("nonzero opening scalar"),
            transcript
                .opening_base_scalar(basis, 2)
                .expect("nonzero opening scalar")
        );
        assert_ne!(
            transcript
                .opening_base_scalar(basis, 2)
                .expect("nonzero opening scalar"),
            transcript
                .opening_base_scalar(basis, 3)
                .expect("nonzero opening scalar")
        );
        assert_eq!(
            transcript.challenge(30).expect("nonzero challenge"),
            copy.clone().challenge(30).expect("nonzero challenge")
        );
    }

    #[test]
    fn typed_items_lengths_and_boundaries_are_distinct() {
        let challenge =
            |mut transcript: NativeTranscript| transcript.challenge(9).expect("nonzero challenge");

        let mut short = NativeTranscript::new();
        short.append_bytes(&[1]).expect("short bytes");
        let mut leading_zero = NativeTranscript::new();
        leading_zero
            .append_bytes(&[0, 1])
            .expect("leading-zero bytes");
        assert_ne!(challenge(short), challenge(leading_zero));

        let mut joined = NativeTranscript::new();
        joined.append_bytes(b"ab").expect("joined bytes");
        let mut split = NativeTranscript::new();
        split.append_bytes(b"a").expect("first split bytes");
        split.append_bytes(b"b").expect("second split bytes");
        assert_ne!(challenge(joined), challenge(split));

        let mut scalar = NativeTranscript::new();
        scalar.append_scalar(bytes32_from_u64(7));
        let mut field = NativeTranscript::new();
        field.append_field(bytes32_from_u64(7));
        assert_ne!(challenge(scalar), challenge(field));
    }

    #[test]
    fn native_points_require_canonical_prefixes() {
        let mut transcript = NativeTranscript::new();
        assert!(transcript.append_point(4, bytes32_from_u64(1)).is_err());
        assert!(transcript.append_point(0, bytes32_from_u64(1)).is_err());
        assert!(transcript.append_point_pair(4, [0; 32], [0; 32]).is_err());
    }

    #[test]
    fn native_challenges_reject_a_zero_low_255_bit_image() {
        assert!(matches!(
            native_challenge_from_digest([0; 32]),
            Err(ReceiptCycleError::Malformed(
                "zero SHA transcript challenge"
            ))
        ));
        let mut high_bit_only = [0; 32];
        high_bit_only[0] = 0x80;
        assert!(matches!(
            native_challenge_from_digest(high_bit_only),
            Err(ReceiptCycleError::Malformed(
                "zero SHA transcript challenge"
            ))
        ));
    }

    #[test]
    fn builder_shape_depends_on_lengths_not_values() {
        let build = |seed| {
            let mut builder = Builder::default();
            let mut transcript = builder_vector_transcript_with_u64(&mut builder, seed, 7);
            let challenge = transcript
                .challenge(&mut builder, 7)
                .expect("builder challenge");
            let digest = challenge.digest_value();
            let (circuit, assignment) = builder.finish().expect("relation");
            (circuit, assignment, digest)
        };
        let first = build(1);
        let second = build(17);
        assert!(first.0 == second.0);
        assert_ne!(first.1, second.1);
        assert_ne!(first.2, second.2);
    }

    #[test]
    fn constrained_headers_can_reuse_existing_boolean_expressions() {
        let mut builder = Builder::default();
        let low = builder.allocate_boolean(true);
        let bits = std::array::from_fn(|index| {
            if index == 0 {
                sha256_builder::Bit::from_constrained_expression(low.clone(), true)
            } else {
                sha256_builder::Bit::from_constrained_expression(
                    Expression::constant(Scalar::ZERO),
                    false,
                )
            }
        });
        let prefix = Byte::from_constrained_bits(bits);
        let before = builder.gate_count();
        let mut transcript = BuilderTranscript::new();
        transcript.append_point(&prefix, &[0u8; 32].map(Byte::constant));
        assert_eq!(builder.gate_count(), before);
    }
}
