//! Typed transcript constraints built directly on Nova's SHA-256 gadget.
//!
//! Bytes retain the protocol's little-endian bit view. The adapter reverses
//! each byte at the SHA boundary used by Nova's SHA-256 frontend.

use std::array;

use ff::Field;
use nova_snark::frontend::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        num::Num,
        sha256::sha256,
    },
    ConstraintSystem, SynthesisError,
};
use sha2::{Digest as _, Sha256};

use crate::sha256_transcript::{
    header, BYTES_ITEM, CHALLENGE_ITEM, FIELD_ITEM, HEADER_SIZE, OPENING_BASE_ITEM, POINT_ITEM,
    POINT_PAIR_ITEM, SCALAR_ITEM, SUITE_ID, U64_ITEM,
};
use crate::{RelationError, Scalar};

#[derive(Clone, Debug)]
pub(crate) struct NovaByte {
    bits_le: [Boolean; 8],
}

impl NovaByte {
    pub(crate) fn constant(value: u8) -> Self {
        Self {
            bits_le: array::from_fn(|bit| Boolean::constant((value >> bit) & 1 == 1)),
        }
    }

    pub(crate) fn allocate<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        value: u8,
    ) -> Result<Self, SynthesisError> {
        let bits_le = (0..8)
            .map(|bit| {
                AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {bit}")),
                    Some((value >> bit) & 1 == 1),
                )
                .map(Boolean::from)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("a byte has eight bits");
        Ok(Self { bits_le })
    }

    pub(crate) fn from_constrained_bits_le(bits_le: [Boolean; 8]) -> Self {
        Self { bits_le }
    }

    pub(crate) fn value(&self) -> u8 {
        self.bits_le
            .iter()
            .enumerate()
            .fold(0, |value, (bit, input)| {
                value | (u8::from(input.get_value().expect("byte witness")) << bit)
            })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NovaChallenge {
    digest: [NovaByte; 32],
    scalar_bits_le: [Boolean; 255],
    scalar: Num<Scalar>,
}

impl NovaChallenge {
    pub(crate) fn digest_value(&self) -> [u8; 32] {
        self.digest.each_ref().map(NovaByte::value)
    }

    pub(crate) fn scalar_value(&self) -> Scalar {
        self.scalar.get_value().expect("challenge witness")
    }

    pub(crate) fn scalar_bits_le(&self) -> &[Boolean; 255] {
        &self.scalar_bits_le
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NovaTranscript {
    state: [NovaByte; 32],
    pending: Vec<NovaByte>,
}

fn constrained_header(item_type: u32, auxiliary: u64) -> [NovaByte; HEADER_SIZE] {
    header(item_type, auxiliary).map(NovaByte::constant)
}

fn constrained_byte_header(item_type: u32, auxiliary: &NovaByte) -> [NovaByte; HEADER_SIZE] {
    let mut encoded = constrained_header(item_type, 0);
    encoded[HEADER_SIZE - 1] = auxiliary.clone();
    encoded
}

fn hash<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    message: &[NovaByte],
) -> Result<[NovaByte; 32], SynthesisError> {
    let input = message
        .iter()
        .flat_map(|byte| byte.bits_le.iter().rev().cloned())
        .collect::<Vec<_>>();
    let digest = sha256(cs.namespace(|| "SHA-256"), &input)?;
    Ok(digest
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bits_be| NovaByte {
            bits_le: bits_be
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .try_into()
                .expect("SHA-256 output byte"),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("SHA-256 output digest"))
}

fn scalar_255<CS: ConstraintSystem<Scalar>>(
    digest: &[NovaByte; 32],
) -> ([Boolean; 255], Num<Scalar>) {
    let bits_le: [Boolean; 255] = digest
        .iter()
        .rev()
        .flat_map(|byte| byte.bits_le.iter().cloned())
        .take(255)
        .collect::<Vec<_>>()
        .try_into()
        .expect("a SHA-256 digest has 255 low bits");
    let mut scalar = Num::zero();
    let mut coefficient = Scalar::ONE;
    for bit in &bits_le {
        scalar = scalar.add_bool_with_coeff(CS::one(), bit, coefficient);
        coefficient = coefficient + coefficient;
    }
    (bits_le, scalar)
}

impl NovaTranscript {
    pub(crate) fn new() -> Self {
        let state: [u8; 32] = Sha256::digest(SUITE_ID).into();
        Self {
            state: state.map(NovaByte::constant),
            pending: Vec::new(),
        }
    }

    fn append_header(&mut self, item_type: u32, auxiliary: u64) {
        self.pending
            .extend(constrained_header(item_type, auxiliary));
    }

    pub(crate) fn append_field(&mut self, value: &[NovaByte; 32]) {
        self.append_header(FIELD_ITEM, 0);
        self.pending.extend_from_slice(value);
    }

    pub(crate) fn append_scalar(&mut self, value: &[NovaByte; 32]) {
        self.append_header(SCALAR_ITEM, 0);
        self.pending.extend_from_slice(value);
    }

    pub(crate) fn append_point(&mut self, prefix: &NovaByte, x: &[NovaByte; 32]) {
        self.pending
            .extend(constrained_byte_header(POINT_ITEM, prefix));
        self.pending.extend_from_slice(x);
    }

    pub(crate) fn append_point_pair(
        &mut self,
        parity: &NovaByte,
        first_x: &[NovaByte; 32],
        second_x: &[NovaByte; 32],
    ) {
        self.pending
            .extend(constrained_byte_header(POINT_PAIR_ITEM, parity));
        self.pending.extend_from_slice(first_x);
        self.pending.extend_from_slice(second_x);
    }

    pub(crate) fn append_bytes(&mut self, value: &[NovaByte]) -> Result<(), RelationError> {
        let length = u64::try_from(value.len())
            .map_err(|_| RelationError::Malformed("SHA transcript byte length"))?;
        self.append_header(BYTES_ITEM, length);
        self.pending.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn append_u64(&mut self, value: u64) {
        self.append_header(U64_ITEM, value);
    }

    pub(crate) fn challenge<CS: ConstraintSystem<Scalar>>(
        &mut self,
        mut cs: CS,
        round: u64,
    ) -> Result<NovaChallenge, RelationError> {
        let mut message = Vec::with_capacity(
            self.state
                .len()
                .checked_add(self.pending.len())
                .and_then(|length| length.checked_add(HEADER_SIZE))
                .ok_or(RelationError::Malformed("SHA transcript length"))?,
        );
        message.extend_from_slice(&self.state);
        message.extend_from_slice(&self.pending);
        message.extend(constrained_header(CHALLENGE_ITEM, round));
        let digest = hash(cs.namespace(|| format!("challenge {round}")), &message)
            .map_err(|_| RelationError::Malformed("Nova SHA-256 synthesis"))?;
        let (scalar_bits_le, scalar) = scalar_255::<CS::Root>(&digest);
        self.state = digest.clone();
        self.pending.clear();
        Ok(NovaChallenge {
            digest,
            scalar_bits_le,
            scalar,
        })
    }

    pub(crate) fn opening_base_scalar<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        basis_digest: [u8; 32],
        role: u64,
    ) -> Result<NovaChallenge, RelationError> {
        let mut fork = self.clone();
        let basis = basis_digest.map(NovaByte::constant);
        fork.append_bytes(&basis)?;
        fork.pending
            .extend(constrained_header(OPENING_BASE_ITEM, role));
        let mut message = Vec::with_capacity(
            fork.state
                .len()
                .checked_add(fork.pending.len())
                .ok_or(RelationError::Malformed("SHA transcript length"))?,
        );
        message.extend_from_slice(&fork.state);
        message.extend_from_slice(&fork.pending);
        let digest = hash(cs.namespace(|| format!("opening base {role}")), &message)
            .map_err(|_| RelationError::Malformed("Nova SHA-256 synthesis"))?;
        let (scalar_bits_le, scalar) = scalar_255::<CS::Root>(&digest);
        Ok(NovaChallenge {
            digest,
            scalar_bits_le,
            scalar,
        })
    }
}

#[cfg(test)]
mod tests {
    use nova_snark::{
        frontend::{shape_cs::ShapeCS, util_cs::test_cs::TestConstraintSystem},
        provider::Secq256k1Sha256Engine,
    };

    use super::*;
    use crate::sha256_transcript::NativeTranscript;

    fn bytes32_from_u64(value: u64) -> [u8; 32] {
        let mut encoded = [0; 32];
        encoded[24..].copy_from_slice(&value.to_be_bytes());
        encoded
    }

    fn allocate_bytes<CS: ConstraintSystem<Scalar>>(mut cs: CS, value: &[u8]) -> Vec<NovaByte> {
        value
            .iter()
            .enumerate()
            .map(|(index, value)| {
                NovaByte::allocate(cs.namespace(|| format!("byte {index}")), *value)
                    .expect("byte allocation")
            })
            .collect()
    }

    fn allocate_array<CS: ConstraintSystem<Scalar>>(cs: CS, value: &[u8; 32]) -> [NovaByte; 32] {
        allocate_bytes(cs, value).try_into().expect("32 bytes")
    }

    fn constrained_vector<CS: ConstraintSystem<Scalar>>(mut cs: CS, seed: u64) -> NovaTranscript {
        let mut transcript = NovaTranscript::new();
        transcript.append_field(&allocate_array(
            cs.namespace(|| "field"),
            &bytes32_from_u64(seed + 1),
        ));
        transcript.append_scalar(&allocate_array(
            cs.namespace(|| "scalar"),
            &bytes32_from_u64(seed + 2),
        ));
        let prefix = NovaByte::allocate(cs.namespace(|| "point prefix"), 2 + (seed & 1) as u8)
            .expect("prefix");
        transcript.append_point(
            &prefix,
            &allocate_array(cs.namespace(|| "point x"), &bytes32_from_u64(seed + 3)),
        );
        let parity =
            NovaByte::allocate(cs.namespace(|| "pair parity"), (seed & 3) as u8).expect("parity");
        transcript.append_point_pair(
            &parity,
            &allocate_array(cs.namespace(|| "first x"), &bytes32_from_u64(seed + 4)),
            &allocate_array(cs.namespace(|| "second x"), &bytes32_from_u64(seed + 5)),
        );
        let raw = (0..33)
            .map(|index| (seed + index) as u8)
            .collect::<Vec<_>>();
        transcript
            .append_bytes(&allocate_bytes(cs.namespace(|| "raw"), &raw))
            .expect("bytes");
        transcript.append_u64(seed + 6);
        transcript
    }

    #[test]
    fn nova_sha_matches_native_typed_transcript() {
        let seed = 9;
        let mut native = NativeTranscript::new();
        native.append_field(bytes32_from_u64(seed + 1));
        native.append_scalar(bytes32_from_u64(seed + 2));
        native
            .append_point(2 + (seed & 1) as u8, bytes32_from_u64(seed + 3))
            .expect("point");
        native
            .append_point_pair(
                (seed & 3) as u8,
                bytes32_from_u64(seed + 4),
                bytes32_from_u64(seed + 5),
            )
            .expect("point pair");
        let raw = (0..33)
            .map(|index| (seed + index) as u8)
            .collect::<Vec<_>>();
        native.append_bytes(&raw).expect("bytes");
        native.append_u64(seed + 6);

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let mut constrained = constrained_vector(cs.namespace(|| "vector"), seed);

        let expected = native.challenge(17).expect("native challenge");
        let actual = constrained
            .challenge(cs.namespace(|| "typed transcript"), 17)
            .expect("constrained challenge");
        assert_eq!(actual.digest_value(), expected.digest);
        assert_eq!(actual.scalar_value(), expected.scalar);
        assert_eq!(actual.scalar_bits_le().len(), 255);
        assert!(cs.is_satisfied());

        let basis_digest = [42; 32];
        let expected_base = native
            .opening_base_scalar(basis_digest, 3)
            .expect("native opening base");
        let actual_base = constrained
            .opening_base_scalar(cs.namespace(|| "opening base"), basis_digest, 3)
            .expect("constrained opening base");
        assert_eq!(actual_base.digest_value(), expected_base.digest);
        assert_eq!(actual_base.scalar_value(), expected_base.scalar);
        assert!(cs.is_satisfied());

        let mut shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        let mut shaped = constrained_vector(shape.namespace(|| "vector"), seed);
        shaped
            .challenge(shape.namespace(|| "typed transcript"), 17)
            .expect("shape challenge");
        assert_eq!(shape.num_aux(), 126_709);
        assert_eq!(shape.num_constraints(), 126_836);
    }

    #[test]
    fn nova_sha_one_block_shape_is_pinned() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let message = allocate_bytes(cs.namespace(|| "input"), b"input bit");
        let digest = hash(cs.namespace(|| "hash"), &message).expect("SHA-256");
        assert_eq!(
            digest.each_ref().map(NovaByte::value),
            Sha256::digest(b"input bit")[..]
        );
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 24_954);

        let mut shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        let message = allocate_bytes(shape.namespace(|| "input"), b"input bit");
        hash(shape.namespace(|| "hash"), &message).expect("SHA-256 shape");
        assert_eq!(shape.num_aux(), 24_928);
        assert_eq!(shape.num_constraints(), 24_954);
    }
}
