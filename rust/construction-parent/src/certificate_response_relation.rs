//! Fixed-size response data authenticated by every recursive member step.
//!
//! The compact verifier hashes the variable-length accountable context and
//! body. The recursive relation consumes the resulting scalar challenge and
//! binds it, the signing equation, and the complete member record into this
//! fixed-size digest.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::certificate_joined_witness::{
    CertificateJoinedResponseWitness, CertificateJoinedWitness, CertificateLinearJoinedWitness,
};
use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
use crate::secp_native::{canonical_scalar_value, SecpEncodedPointWitness, SecpScalarWitness};
use crate::RelationError;

const ACCOUNTABLE_CHALLENGE_TAG: &[u8] = b"Purify/Accountable/Challenge/v2";
pub(crate) const CERTIFICATE_RECURSIVE_STEP_TAG: &[u8] =
    b"Purify/Accountable/CertificateRecursiveStep/v1";

/// Fixed-size response witness shared by every member of one response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertificateResponseRelationWitness {
    response_ordinal: u64,
    member_ordinal: u32,
    member_count: u32,
    response_binding: [u8; 32],
    signing_key: SecpEncodedPointWitness,
    response: SecpScalarWitness,
    challenge: SecpScalarWitness,
    expected_step_digest: [u8; 32],
}

impl CertificateResponseRelationWitness {
    pub(crate) fn from_joined(
        joined: &CertificateJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
        member_record_digest: [u8; 32],
    ) -> Result<Self, RelationError> {
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
        let response = joined
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed("certificate response ordinal"))?;
        Self::from_response(
            response,
            response_ordinal,
            member_ordinal,
            member_record_digest,
        )
    }

    pub(crate) fn from_linear(
        joined: &CertificateLinearJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
        member_record_digest: [u8; 32],
    ) -> Result<Self, RelationError> {
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
        let response = joined
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed("certificate response ordinal"))?
            .response();
        Self::from_response(
            response,
            response_ordinal,
            member_ordinal,
            member_record_digest,
        )
    }

    fn from_response(
        response: &CertificateJoinedResponseWitness,
        response_ordinal: u64,
        member_ordinal: u32,
        member_record_digest: [u8; 32],
    ) -> Result<Self, RelationError> {
        let boundary = response.boundary();
        if boundary.ordinal() != response_ordinal || member_ordinal >= boundary.member_count() {
            return Err(RelationError::Malformed(
                "certificate response relation boundary",
            ));
        }
        let signing_key = parse_signing_key(response.signing_key())?;
        let challenge = accountable_challenge(response)?;
        let response_scalar = response.response();
        let response_binding = response.response_binding();
        let expected_step_digest = native_step_digest(
            member_record_digest,
            response_binding,
            boundary.member_count(),
            response.signing_key(),
            response_scalar.bytes,
            challenge.bytes,
        );
        Ok(Self {
            response_ordinal,
            member_ordinal,
            member_count: boundary.member_count(),
            response_binding,
            signing_key,
            response: response_scalar,
            challenge,
            expected_step_digest,
        })
    }

    pub(crate) const fn response_ordinal(&self) -> u64 {
        self.response_ordinal
    }

    pub(crate) const fn member_ordinal(&self) -> u32 {
        self.member_ordinal
    }

    pub(crate) const fn member_count(&self) -> u32 {
        self.member_count
    }

    pub(crate) const fn response_binding(&self) -> [u8; 32] {
        self.response_binding
    }

    pub(crate) fn masked_response_binding(&self) -> [u8; 32] {
        let mut binding = self.response_binding;
        binding[0] &= 0x7f;
        binding
    }

    pub(crate) const fn signing_key(&self) -> SecpEncodedPointWitness {
        self.signing_key
    }

    pub(crate) const fn response(&self) -> SecpScalarWitness {
        self.response
    }

    pub(crate) const fn challenge(&self) -> SecpScalarWitness {
        self.challenge
    }

    pub(crate) const fn expected_step_digest(&self) -> [u8; 32] {
        self.expected_step_digest
    }
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest.update(message);
    digest.finalize().into()
}

fn accountable_challenge(
    response: &crate::certificate_joined_witness::CertificateJoinedResponseWitness,
) -> Result<SecpScalarWitness, RelationError> {
    accountable_challenge_scalar(
        response.signing_key(),
        response.host_commitment(),
        response.coalition_core_digest(),
        response.slot(),
        response.canonical_body(),
    )
}

fn accountable_challenge_scalar(
    signing_key: [u8; 32],
    host_commitment: [u8; 32],
    coalition_core_digest: [u8; 32],
    slot: &[u8],
    canonical_body: &[u8],
) -> Result<SecpScalarWitness, RelationError> {
    let slot_length = u64::try_from(slot.len())
        .map_err(|_| RelationError::Malformed("certificate accountable slot length"))?;
    let body_length = u64::try_from(canonical_body.len())
        .map_err(|_| RelationError::Malformed("certificate accountable body length"))?;
    let mut encoded = Vec::with_capacity(32 + 32 + 32 + 8 + slot.len() + 8 + canonical_body.len());
    encoded.extend_from_slice(&signing_key);
    encoded.extend_from_slice(&host_commitment);
    encoded.extend_from_slice(&coalition_core_digest);
    encoded.extend_from_slice(&slot_length.to_be_bytes());
    encoded.extend_from_slice(slot);
    encoded.extend_from_slice(&body_length.to_be_bytes());
    encoded.extend_from_slice(canonical_body);
    let digest = tagged_sha256(ACCOUNTABLE_CHALLENGE_TAG, &encoded);
    let order = BigUint::from_bytes_be(&SECP256K1_SCALAR_ORDER_BE);
    let challenge = BigUint::from_bytes_be(&digest) % order;
    if challenge == BigUint::from(0u8) {
        return Err(RelationError::Malformed(
            "zero certificate accountable challenge",
        ));
    }
    let encoded = challenge.to_bytes_be();
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    let witness = SecpScalarWitness::from_bytes_be(bytes);
    canonical_scalar_value(witness)?;
    Ok(witness)
}

fn parse_signing_key(encoded: [u8; 32]) -> Result<SecpEncodedPointWitness, RelationError> {
    let mut point = [0; 33];
    point[0] = 2;
    point[1..].copy_from_slice(&encoded);
    SecpEncodedPointWitness::parse(point)
}

pub(crate) fn native_step_digest(
    member_record_digest: [u8; 32],
    response_binding: [u8; 32],
    member_count: u32,
    signing_key: [u8; 32],
    response: [u8; 32],
    challenge: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0; 32 + 32 + 4 + 32 + 32 + 32];
    encoded[..32].copy_from_slice(&member_record_digest);
    encoded[32..64].copy_from_slice(&response_binding);
    encoded[64..68].copy_from_slice(&member_count.to_be_bytes());
    encoded[68..100].copy_from_slice(&signing_key);
    encoded[100..132].copy_from_slice(&response);
    encoded[132..].copy_from_slice(&challenge);
    tagged_sha256(CERTIFICATE_RECURSIVE_STEP_TAG, &encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), 2 * N);
        std::array::from_fn(|index| {
            u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16).expect("test vector hex")
        })
    }

    #[test]
    fn recursive_step_digest_matches_cpp_fixture() {
        let digest = native_step_digest(
            decode_hex("2f42294f02933d5b2433b589b75248d0a8a66e4e98bed8944a93f880f81f9324"),
            decode_hex("dc55a5419605986f3a34892b22e9065b01d59b82d4845528644dd78f52e37735"),
            2,
            decode_hex("f1bc4f8667aba3063730ba53f1a4bb69ab70a2e374a219a02fc0dc4bb2f3e8f4"),
            decode_hex("2adf2ca4d5f40b657258cb96f766350491b897d97fc33301e7175f1a3ad28415"),
            decode_hex("c8ee29177efac3570ff32abd505f8b9ab62ce43a7699b1de059f32ecd35f19d7"),
        );
        assert_eq!(
            digest,
            decode_hex("a35626ac841c3d110bd75f062640a9aaed72662a49b0cccbd8b8e0704926c252",),
        );
    }

    #[test]
    fn recursive_step_digest_binds_every_response_field() {
        let expected = native_step_digest(
            [0x11; 32], [0x22; 32], 3, [0x33; 32], [0x44; 32], [0x55; 32],
        );
        assert_eq!(
            expected,
            [
                0x4d, 0xd5, 0xf6, 0x84, 0x60, 0x06, 0xe7, 0x94, 0x69, 0xa1, 0x09, 0x6f, 0xd3, 0xa5,
                0x3e, 0xda, 0xc7, 0x1f, 0x17, 0xaf, 0xf0, 0xc2, 0x3f, 0xab, 0xfe, 0x27, 0x71, 0x8e,
                0x8c, 0xe7, 0x48, 0x7c,
            ],
        );
        let mut inputs = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32]];
        for index in 0..inputs.len() {
            inputs[index][31] ^= 1;
            let actual =
                native_step_digest(inputs[0], inputs[1], 3, inputs[2], inputs[3], inputs[4]);
            assert_ne!(actual, expected);
            inputs[index][31] ^= 1;
        }
        assert_ne!(
            native_step_digest(inputs[0], inputs[1], 4, inputs[2], inputs[3], inputs[4],),
            expected,
        );
    }

    #[test]
    fn masked_response_binding_retains_the_low_255_bits() {
        let witness = CertificateResponseRelationWitness {
            response_ordinal: 0,
            member_ordinal: 0,
            member_count: 1,
            response_binding: [0xff; 32],
            signing_key: SecpEncodedPointWitness::identity(),
            response: SecpScalarWitness::from_u64(1),
            challenge: SecpScalarWitness::from_u64(2),
            expected_step_digest: [0; 32],
        };
        let binding = witness.masked_response_binding();
        assert_eq!(binding[0], 0x7f);
        assert_eq!(&binding[1..], &[0xff; 31]);
    }

    #[test]
    fn accountable_challenge_matches_the_native_vector() {
        let signing_key = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let expected = [
            0xe4, 0x3d, 0x7f, 0xe3, 0x4f, 0xef, 0xb7, 0xc8, 0x72, 0xbd, 0xa3, 0xee, 0x00, 0x51,
            0x15, 0x83, 0x93, 0x2a, 0xbb, 0x6b, 0xd3, 0x3f, 0x9d, 0xa7, 0x26, 0x6d, 0x93, 0x47,
            0x1e, 0x62, 0xa7, 0xbd,
        ];
        let challenge = accountable_challenge_scalar(
            signing_key,
            [0x22; 32],
            [0x33; 32],
            b"accountable-slot\0v2",
            b"canonical-body\0with-framing",
        )
        .expect("accountable challenge");
        assert_eq!(challenge.bytes, expected);
    }
}
