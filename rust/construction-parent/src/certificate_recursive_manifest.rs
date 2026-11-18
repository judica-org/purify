//! Ordered manifest for certificate records verified by the recursive leaf.

use sha2::{Digest, Sha256};

use crate::certificate_profile::{CERTIFICATE_MAX_RESPONSES, CERTIFICATE_MEMBER_BATCH_CAPACITY};
use crate::RelationError;

const MANIFEST_SEED_TAG: &[u8] = b"Purify/Accountable/CertificateRecursiveManifest/v1/init";
pub(crate) const MANIFEST_STEP_TAG: &[u8] =
    b"Purify/Accountable/CertificateRecursiveManifest/v1/member";

fn manifest_scalar(tag: &[u8], encoded: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest.update(encoded);
    let mut scalar: [u8; 32] = digest.finalize().into();
    scalar[0] &= 0x7f;
    scalar
}

pub(crate) fn recursive_manifest_seed(
    certificate_context_digest: [u8; 32],
    total_responses: u64,
) -> Result<[u8; 32], RelationError> {
    if certificate_context_digest == [0; 32]
        || total_responses == 0
        || total_responses > CERTIFICATE_MAX_RESPONSES
    {
        return Err(RelationError::Malformed(
            "certificate recursive manifest seed",
        ));
    }
    let mut encoded = [0; 40];
    encoded[..32].copy_from_slice(&certificate_context_digest);
    encoded[32..].copy_from_slice(&total_responses.to_be_bytes());
    Ok(manifest_scalar(MANIFEST_SEED_TAG, &encoded))
}

pub(crate) fn recursive_manifest_step(
    prior: [u8; 32],
    response_ordinal: u64,
    member_ordinal: u32,
    record_digest: [u8; 32],
) -> Result<[u8; 32], RelationError> {
    if prior[0] & 0x80 != 0 || member_ordinal >= CERTIFICATE_MEMBER_BATCH_CAPACITY {
        return Err(RelationError::Malformed(
            "certificate recursive manifest step",
        ));
    }
    let mut encoded = [0; 32 + 8 + 4 + 32];
    encoded[..32].copy_from_slice(&prior);
    encoded[32..40].copy_from_slice(&response_ordinal.to_be_bytes());
    encoded[40..44].copy_from_slice(&member_ordinal.to_be_bytes());
    encoded[44..].copy_from_slice(&record_digest);
    Ok(manifest_scalar(MANIFEST_STEP_TAG, &encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn recursive_manifest_is_ordered_and_canonical() {
        let seed = recursive_manifest_seed([0x11; 32], 2).expect("manifest seed");
        let first = recursive_manifest_step(seed, 0, 0, [0x22; 32]).expect("first record");
        let second = recursive_manifest_step(first, 0, 1, [0x33; 32]).expect("second record");
        let reordered = recursive_manifest_step(first, 1, 0, [0x33; 32]).expect("reordered record");
        let alternate_prior =
            recursive_manifest_step(seed, 1, 0, [0x22; 32]).expect("alternate prior");
        let changed_prior =
            recursive_manifest_step(alternate_prior, 0, 1, [0x33; 32]).expect("changed prior");

        assert_eq!(
            encode_hex(&seed),
            "2d0bb6c8254e72de3989292fd006aa7f091fd6b2f3c2a80ce721c6e647cb47e3",
        );
        assert_eq!(
            encode_hex(&first),
            "3a84a6d47d7f6ffb2e103602bf93bf65a18db0733436302a635cecd1a2c9432c",
        );
        assert_eq!(
            encode_hex(&second),
            "4d0d41244c51fab3a31baac488adee3afc287436de90a6c1df0f9a45b6568271",
        );
        assert_eq!(
            encode_hex(&reordered),
            "5ec611346c927e6c0098c98358596f7de9aadbd08483976a67fb51a9a3317e35",
        );
        assert_eq!(seed[0] & 0x80, 0);
        assert_eq!(first[0] & 0x80, 0);
        assert_eq!(second[0] & 0x80, 0);
        assert_ne!(second, reordered);
        assert_ne!(second, changed_prior);
        assert_ne!(first, second);
    }

    #[test]
    fn recursive_manifest_rejects_noncanonical_frames() {
        assert!(recursive_manifest_seed([0; 32], 1).is_err());
        assert!(recursive_manifest_seed([1; 32], 0).is_err());
        assert!(recursive_manifest_seed([1; 32], CERTIFICATE_MAX_RESPONSES + 1).is_err());

        let mut prior = [0; 32];
        prior[0] = 0x80;
        assert!(recursive_manifest_step(prior, 0, 0, [1; 32]).is_err());
        assert!(
            recursive_manifest_step([0; 32], 0, CERTIFICATE_MEMBER_BATCH_CAPACITY, [1; 32],)
                .is_err()
        );
    }
}
