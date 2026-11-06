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

use crate::{RelationError, Scalar};

pub(crate) const SUITE_ID: &[u8] = b"Purify/SHA256Transcript/v1";

pub(crate) const FIELD_ITEM: u32 = 0x4649_454c; // FIEL
pub(crate) const SCALAR_ITEM: u32 = 0x5343_414c; // SCAL
pub(crate) const POINT_ITEM: u32 = 0x504f_494e; // POIN
#[cfg(test)]
pub(crate) const POINT_PAIR_ITEM: u32 = 0x5041_4952; // PAIR
pub(crate) const BYTES_ITEM: u32 = 0x4259_5445; // BYTE
pub(crate) const U64_ITEM: u32 = 0x5536_3420; // U64<space>
pub(crate) const CHALLENGE_ITEM: u32 = 0x4348_414c; // CHAL
#[cfg(test)]
pub(crate) const OPENING_BASE_ITEM: u32 = 0x4f42_4153; // OBAS

pub(crate) const HEADER_SIZE: usize = 12;

pub(crate) fn header(item_type: u32, auxiliary: u64) -> [u8; HEADER_SIZE] {
    let mut encoded = [0u8; HEADER_SIZE];
    encoded[..4].copy_from_slice(&item_type.to_be_bytes());
    encoded[4..].copy_from_slice(&auxiliary.to_be_bytes());
    encoded
}

fn scalar_from_digest(mut digest: [u8; 32]) -> Scalar {
    digest[0] &= 0x7f;
    digest.iter().fold(Scalar::ZERO, |value, byte| {
        value * Scalar::from(256) + Scalar::from(u64::from(*byte))
    })
}

/// Native transcript output with the full digest retained for chaining.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeChallenge {
    pub(crate) digest: [u8; 32],
    pub(crate) scalar: Scalar,
}

fn native_challenge_from_digest(digest: [u8; 32]) -> Result<NativeChallenge, RelationError> {
    let scalar = scalar_from_digest(digest);
    if scalar == Scalar::ZERO {
        return Err(RelationError::Malformed("zero SHA transcript challenge"));
    }
    Ok(NativeChallenge { digest, scalar })
}

/// Native transcript over canonical public values.
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

    pub(crate) fn append_point(&mut self, prefix: u8, x: [u8; 32]) -> Result<(), RelationError> {
        if !matches!(prefix, 0 | 2 | 3) {
            return Err(RelationError::Malformed("SHA transcript point prefix"));
        }
        if prefix == 0 && x != [0; 32] {
            return Err(RelationError::Malformed("SHA transcript point identity"));
        }
        self.append_header(POINT_ITEM, u64::from(prefix));
        self.pending.extend(x);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn append_point_pair(
        &mut self,
        parity: u8,
        first_x: [u8; 32],
        second_x: [u8; 32],
    ) -> Result<(), RelationError> {
        if parity > 3 {
            return Err(RelationError::Malformed("SHA transcript pair parity"));
        }
        self.append_header(POINT_PAIR_ITEM, u64::from(parity));
        self.pending.extend(first_x);
        self.pending.extend(second_x);
        Ok(())
    }

    pub(crate) fn append_bytes(&mut self, value: &[u8]) -> Result<(), RelationError> {
        let length = u64::try_from(value.len())
            .map_err(|_| RelationError::Malformed("SHA transcript byte length"))?;
        self.append_header(BYTES_ITEM, length);
        self.pending.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_u64(&mut self, value: u64) {
        self.append_header(U64_ITEM, value);
    }

    pub(crate) fn challenge(&mut self, round: u64) -> Result<NativeChallenge, RelationError> {
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

    #[cfg(test)]
    pub(crate) fn opening_base_scalar(
        &self,
        basis_digest: [u8; 32],
        role: u64,
    ) -> Result<NativeChallenge, RelationError> {
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

    use crate::scalar_to_canonical;

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

    fn decode_hex<const SIZE: usize>(value: &str) -> [u8; SIZE] {
        assert_eq!(value.len(), 2 * SIZE);
        std::array::from_fn(|index| {
            u8::from_str_radix(&value[2 * index..2 * index + 2], 16).expect("hex")
        })
    }

    fn scalar_be(value: Scalar) -> [u8; 32] {
        let mut encoded = scalar_to_canonical(&value);
        encoded.reverse();
        encoded
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
    fn native_transcript_matches_cross_language_vectors() {
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
    fn challenges_chain_the_high_digest_bit() {
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
    }

    #[test]
    fn opening_derivation_is_a_non_mutating_typed_fork() {
        let mut transcript = native_vector_transcript(23);
        let mut copy = transcript.clone();
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
            copy.challenge(30).expect("nonzero challenge")
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
            Err(RelationError::Malformed("zero SHA transcript challenge"))
        ));
        let mut high_bit_only = [0; 32];
        high_bit_only[0] = 0x80;
        assert!(matches!(
            native_challenge_from_digest(high_bit_only),
            Err(RelationError::Malformed("zero SHA transcript challenge"))
        ));
    }
}
