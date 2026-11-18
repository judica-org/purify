//! Native certificate-authorization hashing shared with the recursive relation.

use sha2::{Digest, Sha256};

use crate::certificate_profile::{CERTIFICATE_MAX_RESPONSES, CERTIFICATE_MEMBER_BATCH_CAPACITY};
use crate::RelationError;

const RESPONSE_COMMON_TAG: &[u8] = b"Purify/Accountable/CertificateResponseCommon/v1";
const RESPONSE_STATEMENT_TAG: &[u8] = b"Purify/Accountable/CertificateNonceResponse/v1";
const RESPONSE_AUTHORIZATION_TAG: &[u8] = b"Purify/Accountable/CertificateResponseAuthorization/v1";
const RESPONSE_BINDING_TAG: &[u8] = b"Purify/Accountable/CertificateResponseBinding/v1";
const MEMBER_AUTHORIZATION_TAG: &[u8] = b"Purify/Accountable/CertificateMemberAuthorization/v1";
const MANIFEST_SEED_TAG: &[u8] = b"Purify/Accountable/CertificateAuthorizationManifest/v1/init";
const MANIFEST_STEP_TAG: &[u8] = b"Purify/Accountable/CertificateAuthorizationManifest/v1/member";
const NONCE_PROOF_TAG: &[u8] = b"Purify/Accountable/CertificateNonceProof/v1";

pub(crate) const RESPONSE_MEMBER_DESCRIPTOR_BYTES: usize = 4 + 33 + 32 + 96;

fn tagged_sha256(tag: &[u8], encoded: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest.update(encoded);
    digest.finalize().into()
}

pub(crate) fn response_common_digest(encoded_prefix: &[u8]) -> [u8; 32] {
    tagged_sha256(RESPONSE_COMMON_TAG, encoded_prefix)
}

pub(crate) fn response_statement_digest(encoded: &[u8]) -> [u8; 32] {
    tagged_sha256(RESPONSE_STATEMENT_TAG, encoded)
}

pub(crate) fn response_authorization_digest(encoded: &[u8]) -> [u8; 32] {
    tagged_sha256(RESPONSE_AUTHORIZATION_TAG, encoded)
}

pub(crate) fn response_binding_digest(
    common_digest: [u8; 32],
    response_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoded = [0; 64];
    encoded[..32].copy_from_slice(&common_digest);
    encoded[32..].copy_from_slice(&response_digest);
    tagged_sha256(RESPONSE_BINDING_TAG, &encoded)
}

pub(crate) fn member_authorization_digest(
    response_binding: [u8; 32],
    response_ordinal: u64,
    encoded_member: &[u8; RESPONSE_MEMBER_DESCRIPTOR_BYTES],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 + 8 + encoded_member.len());
    encoded.extend_from_slice(&response_binding);
    encoded.extend_from_slice(&response_ordinal.to_be_bytes());
    encoded.extend_from_slice(encoded_member);
    tagged_sha256(MEMBER_AUTHORIZATION_TAG, &encoded)
}

pub(crate) fn nonce_proof_digest(encoded: &[u8]) -> [u8; 32] {
    tagged_sha256(NONCE_PROOF_TAG, encoded)
}

fn manifest_scalar(tag: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut scalar = tagged_sha256(tag, encoded);
    scalar[0] &= 0x7f;
    scalar
}

pub(crate) fn authorization_manifest_seed(
    certificate_context_digest: [u8; 32],
    total_responses: u64,
) -> Result<[u8; 32], RelationError> {
    if certificate_context_digest == [0; 32]
        || total_responses == 0
        || total_responses > CERTIFICATE_MAX_RESPONSES
    {
        return Err(RelationError::Malformed(
            "certificate authorization manifest seed",
        ));
    }
    let mut encoded = [0; 40];
    encoded[..32].copy_from_slice(&certificate_context_digest);
    encoded[32..].copy_from_slice(&total_responses.to_be_bytes());
    Ok(manifest_scalar(MANIFEST_SEED_TAG, &encoded))
}

pub(crate) fn authorization_manifest_step(
    prior: [u8; 32],
    response_ordinal: u64,
    member_ordinal: u32,
    member_digest: [u8; 32],
) -> Result<[u8; 32], RelationError> {
    if prior[0] & 0x80 != 0 || member_ordinal >= CERTIFICATE_MEMBER_BATCH_CAPACITY {
        return Err(RelationError::Malformed(
            "certificate authorization manifest step",
        ));
    }
    let mut encoded = [0; 32 + 8 + 4 + 32];
    encoded[..32].copy_from_slice(&prior);
    encoded[32..40].copy_from_slice(&response_ordinal.to_be_bytes());
    encoded[40..44].copy_from_slice(&member_ordinal.to_be_bytes());
    encoded[44..].copy_from_slice(&member_digest);
    Ok(manifest_scalar(MANIFEST_STEP_TAG, &encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORIZATION_VECTOR: &str =
        include_str!("../../../tests/vectors/certificate_response_authorization_v1.txt");
    const AUTHORIZATION_DIGEST: [u8; 32] = [
        0x41, 0xcc, 0x2b, 0x53, 0xdb, 0x13, 0xa7, 0x4c, 0x6b, 0x1c, 0xdb, 0x3e, 0xab, 0x90, 0x14,
        0x42, 0xe5, 0x6f, 0x72, 0x85, 0xa2, 0x26, 0x10, 0x5a, 0xe5, 0xde, 0x6c, 0x56, 0x0c, 0x5a,
        0xa0, 0x75,
    ];

    fn decode_hex(encoded: &str) -> Vec<u8> {
        let encoded = encoded.trim();
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| {
                let high = (digits[0] as char).to_digit(16).expect("hex digit");
                let low = (digits[1] as char).to_digit(16).expect("hex digit");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    fn parse_vector() -> (Vec<u8>, usize, [u8; 32], u64, u64, u32) {
        let encoded = decode_hex(AUTHORIZATION_VECTOR);
        let mut offset = 1 + 1 + 4;
        let context = encoded[offset..offset + 32]
            .try_into()
            .expect("context digest");
        offset += 32;
        let total_responses = u64::from_be_bytes(
            encoded[offset..offset + 8]
                .try_into()
                .expect("response count"),
        );
        offset += 8;
        let response_ordinal = u64::from_be_bytes(
            encoded[offset..offset + 8]
                .try_into()
                .expect("response ordinal"),
        );
        offset += 8 + 4 + 8 + 32 + 32 + 32;
        let slot_length = usize::try_from(u64::from_be_bytes(
            encoded[offset..offset + 8].try_into().expect("slot length"),
        ))
        .expect("small slot");
        offset += 8 + slot_length;
        let body_length = usize::try_from(u64::from_be_bytes(
            encoded[offset..offset + 8].try_into().expect("body length"),
        ))
        .expect("small body");
        offset += 8 + body_length + 32 + 32 + 1;
        let member_count = u32::from_be_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .expect("member count"),
        );
        offset += 4;
        (
            encoded,
            offset,
            context,
            total_responses,
            response_ordinal,
            member_count,
        )
    }

    #[test]
    fn matches_cpp_response_authorization_vector() {
        let encoded = decode_hex(AUTHORIZATION_VECTOR);
        assert_eq!(
            response_authorization_digest(&encoded),
            AUTHORIZATION_DIGEST
        );

        let mut changed = encoded;
        changed[0] ^= 1;
        assert_ne!(
            response_authorization_digest(&changed),
            AUTHORIZATION_DIGEST
        );
    }

    #[test]
    fn separates_statement_and_nonce_proof_domains() {
        let encoded = b"certificate witness bytes";
        assert_ne!(
            response_statement_digest(encoded),
            nonce_proof_digest(encoded)
        );
        assert_ne!(
            response_statement_digest(encoded),
            response_statement_digest(b"certificate witness byte")
        );
    }

    #[test]
    fn derives_response_members_and_ordered_manifest() {
        let (encoded, offset, context, total_responses, response_ordinal, member_count) =
            parse_vector();
        assert_eq!(
            encoded.len() - offset,
            usize::try_from(member_count).expect("small member count")
                * RESPONSE_MEMBER_DESCRIPTOR_BYTES
        );

        let common = response_common_digest(&encoded[..offset]);
        let response = response_authorization_digest(&encoded);
        let binding = response_binding_digest(common, response);
        let mut manifest = authorization_manifest_seed(context, total_responses)
            .expect("authorization manifest seed");
        assert_eq!(
            common.as_slice(),
            decode_hex("d750f146aa767afede3d16555fce83bdae722676ea818605b39998fbe51c2802")
        );
        assert_eq!(
            binding.as_slice(),
            decode_hex("dc55a5419605986f3a34892b22e9065b01d59b82d4845528644dd78f52e37735")
        );
        assert_eq!(
            manifest.as_slice(),
            decode_hex("1405c9fdb683b383843eb12ad2fc7d3b3b7c48612fab752f7ab8775652436645")
        );
        let expected_members = [
            decode_hex("79be0a07ab0749bc19cb8d2fd43b4f43fc9485d8e7bb366a6fce34b0bce1792b"),
            decode_hex("7a4190c932372b08527e4106000be274c97327e397bc61a01f4673a7a970eb17"),
        ];
        for member_ordinal in 0..member_count {
            let member_offset = offset
                + usize::try_from(member_ordinal).expect("small member ordinal")
                    * RESPONSE_MEMBER_DESCRIPTOR_BYTES;
            let member: &[u8; RESPONSE_MEMBER_DESCRIPTOR_BYTES] = encoded
                [member_offset..member_offset + RESPONSE_MEMBER_DESCRIPTOR_BYTES]
                .try_into()
                .expect("member descriptor");
            assert_eq!(
                u32::from_be_bytes(member[..4].try_into().expect("member ordinal")),
                member_ordinal
            );
            let member_digest = member_authorization_digest(binding, response_ordinal, member);
            assert_eq!(
                member_digest.as_slice(),
                expected_members[member_ordinal as usize]
            );
            manifest = authorization_manifest_step(
                manifest,
                response_ordinal,
                member_ordinal,
                member_digest,
            )
            .expect("authorization manifest step");
        }
        assert_eq!(
            manifest.as_slice(),
            decode_hex("0685038dab906f66e5ef5c04fc2183049f7fa62e64b604645fc005db3e46aa68")
        );
    }

    #[test]
    fn rejects_noncanonical_manifest_frames() {
        assert!(authorization_manifest_seed([0; 32], 1).is_err());
        assert!(authorization_manifest_seed([1; 32], 0).is_err());
        assert!(authorization_manifest_seed([1; 32], CERTIFICATE_MAX_RESPONSES + 1).is_err());

        let mut noncanonical_prior = [0; 32];
        noncanonical_prior[0] = 0x80;
        assert!(authorization_manifest_step(noncanonical_prior, 0, 0, [1; 32]).is_err());
        assert!(authorization_manifest_step(
            [0; 32],
            0,
            CERTIFICATE_MEMBER_BATCH_CAPACITY,
            [1; 32]
        )
        .is_err());
    }
}
