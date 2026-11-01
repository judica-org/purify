//! Authenticated local storage for one selected direct Nova verifier.
//!
//! This is a deployment artifact, not a receipt or consensus-selected
//! parameter format. The caller supplies one locally frozen descriptor, and
//! the complete artifact is authenticated before Serde sees any bytes.

use std::io::{self, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    DirectNovaSessionError, DirectNovaVerifier, DirectVerifierKey, ExpectedDirectNovaSuite,
    SelectedDirectNovaVerifier,
};

const VERIFIER_ARTIFACT_MAGIC: [u8; 16] = *b"Purify/Nova/VK1\0";
const VERIFIER_ARTIFACT_ENCODING_VERSION: u32 = 1;
const VERIFIER_ARTIFACT_DIGEST_TAG: &[u8] = b"Purify/Accountable/DirectNovaVerifierArtifact/v1";
const VERIFIER_ARTIFACT_HEADER_LENGTH: usize = 64;
const MAX_VERIFIER_KEY_PAYLOAD_LENGTH: usize = 2 * 1024 * 1024 * 1024;

const VERSION_OFFSET: usize = 16;
const SUITE_ID_OFFSET: usize = 20;
const ARITY_OFFSET: usize = 52;
const PAYLOAD_LENGTH_OFFSET: usize = 56;

/// The one artifact identity compiled into a future production deployment.
///
/// It is deliberately separate from the semantic suite ID. Receipts never
/// supply this value, and a serialization-only change must replace it without
/// changing the proof statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedDirectNovaVerifierArtifact {
    encoded_length: u64,
    digest: [u8; 32],
}

impl ExpectedDirectNovaVerifierArtifact {
    pub(crate) const fn new(encoded_length: u64, digest: [u8; 32]) -> Self {
        Self {
            encoded_length,
            digest,
        }
    }

    pub(crate) const fn encoded_length(self) -> u64 {
        self.encoded_length
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    pub(crate) fn for_test_bytes(encoded: &[u8]) -> Self {
        Self::new(encoded.len() as u64, tagged_artifact_digest(encoded))
    }
}

#[derive(Debug, Error)]
pub(crate) enum DirectNovaVerifierArtifactError {
    #[error("direct Nova verifier artifact destination is not empty")]
    DestinationNotEmpty,
    #[error("direct Nova verifier artifact length is invalid")]
    Length,
    #[error("direct Nova verifier artifact digest mismatch")]
    Digest,
    #[error("direct Nova verifier artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova verifier artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova verifier artifact encoding failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("direct Nova verifier artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Suite(#[from] DirectNovaSessionError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactHeader {
    suite_id: [u8; 32],
    arity: u32,
    payload_length: u64,
}

impl ArtifactHeader {
    fn new<const ARITY: usize>(
        suite_id: [u8; 32],
        payload_length: u64,
    ) -> Result<Self, DirectNovaVerifierArtifactError> {
        let arity = u32::try_from(ARITY)
            .map_err(|_| DirectNovaVerifierArtifactError::Header("state arity"))?;
        if payload_length > MAX_VERIFIER_KEY_PAYLOAD_LENGTH as u64 {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        Ok(Self {
            suite_id,
            arity,
            payload_length,
        })
    }

    fn encode(self) -> [u8; VERIFIER_ARTIFACT_HEADER_LENGTH] {
        let mut encoded = [0u8; VERIFIER_ARTIFACT_HEADER_LENGTH];
        encoded[..VERSION_OFFSET].copy_from_slice(&VERIFIER_ARTIFACT_MAGIC);
        encoded[VERSION_OFFSET..SUITE_ID_OFFSET]
            .copy_from_slice(&VERIFIER_ARTIFACT_ENCODING_VERSION.to_be_bytes());
        encoded[SUITE_ID_OFFSET..ARITY_OFFSET].copy_from_slice(&self.suite_id);
        encoded[ARITY_OFFSET..PAYLOAD_LENGTH_OFFSET].copy_from_slice(&self.arity.to_be_bytes());
        encoded[PAYLOAD_LENGTH_OFFSET..].copy_from_slice(&self.payload_length.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, DirectNovaVerifierArtifactError> {
        if encoded.len() < VERIFIER_ARTIFACT_HEADER_LENGTH {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        if encoded[..VERSION_OFFSET] != VERIFIER_ARTIFACT_MAGIC {
            return Err(DirectNovaVerifierArtifactError::Header("magic"));
        }
        let version = read_u32(encoded, VERSION_OFFSET);
        if version != VERIFIER_ARTIFACT_ENCODING_VERSION {
            return Err(DirectNovaVerifierArtifactError::Header("encoding version"));
        }
        let suite_id = encoded[SUITE_ID_OFFSET..ARITY_OFFSET]
            .try_into()
            .expect("fixed verifier artifact suite ID slice");
        Ok(Self {
            suite_id,
            arity: read_u32(encoded, ARITY_OFFSET),
            payload_length: read_u64(encoded, PAYLOAD_LENGTH_OFFSET),
        })
    }
}

impl<const ARITY: usize> SelectedDirectNovaVerifier<ARITY> {
    /// Streams this selected verifier into a new empty seekable destination.
    ///
    /// The returned descriptor is qualification output. A production loader
    /// must compile in reviewed constants rather than derive them from the
    /// file it is about to accept.
    pub(crate) fn write_artifact<W>(
        &self,
        destination: &mut W,
    ) -> Result<ExpectedDirectNovaVerifierArtifact, DirectNovaVerifierArtifactError>
    where
        W: Read + Write + Seek,
    {
        let initial_position = destination.stream_position()?;
        let initial_length = destination.seek(SeekFrom::End(0))?;
        if initial_position != 0 || initial_length != 0 {
            return Err(DirectNovaVerifierArtifactError::DestinationNotEmpty);
        }
        destination.seek(SeekFrom::Start(0))?;
        destination.write_all(&[0u8; VERIFIER_ARTIFACT_HEADER_LENGTH])?;

        let payload_length = bincode::serde::encode_into_std_write(
            &self.inner.verifier_key,
            destination,
            bincode::config::legacy()
                .with_little_endian()
                .with_fixed_int_encoding(),
        )?;
        let payload_length =
            u64::try_from(payload_length).map_err(|_| DirectNovaVerifierArtifactError::Length)?;
        let header = ArtifactHeader::new::<ARITY>(*self.expected.suite_id.bytes(), payload_length)?;
        let encoded_length = (VERIFIER_ARTIFACT_HEADER_LENGTH as u64)
            .checked_add(payload_length)
            .ok_or(DirectNovaVerifierArtifactError::Length)?;
        if destination.stream_position()? != encoded_length {
            return Err(DirectNovaVerifierArtifactError::Length);
        }

        destination.seek(SeekFrom::Start(0))?;
        destination.write_all(&header.encode())?;
        destination.flush()?;
        if destination.seek(SeekFrom::End(0))? != encoded_length {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        destination.seek(SeekFrom::Start(0))?;
        let digest = tagged_artifact_digest_reader(destination, encoded_length)?;
        destination.seek(SeekFrom::Start(encoded_length))?;
        Ok(ExpectedDirectNovaVerifierArtifact::new(
            encoded_length,
            digest,
        ))
    }

    /// Loads exactly one locally selected and pre-authenticated verifier.
    ///
    /// Length and digest checks precede header parsing and all Serde work.
    /// The artifact cannot supply suite metadata or proof shape.
    pub(crate) fn from_artifact(
        artifact: &[u8],
        expected_suite: &'static ExpectedDirectNovaSuite,
        expected_artifact: &ExpectedDirectNovaVerifierArtifact,
    ) -> Result<Self, DirectNovaVerifierArtifactError> {
        let expected_length = usize::try_from(expected_artifact.encoded_length)
            .map_err(|_| DirectNovaVerifierArtifactError::Length)?;
        let maximum_length = VERIFIER_ARTIFACT_HEADER_LENGTH
            .checked_add(MAX_VERIFIER_KEY_PAYLOAD_LENGTH)
            .ok_or(DirectNovaVerifierArtifactError::Length)?;
        if artifact.len() != expected_length
            || artifact.len() < VERIFIER_ARTIFACT_HEADER_LENGTH
            || artifact.len() > maximum_length
        {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        if tagged_artifact_digest(artifact) != expected_artifact.digest {
            return Err(DirectNovaVerifierArtifactError::Digest);
        }

        let header = ArtifactHeader::decode(artifact)?;
        if header.suite_id != *expected_suite.suite_id.bytes() {
            return Err(DirectNovaVerifierArtifactError::Header("suite ID"));
        }
        let expected_arity = u32::try_from(ARITY)
            .map_err(|_| DirectNovaVerifierArtifactError::Header("state arity"))?;
        if header.arity != expected_arity {
            return Err(DirectNovaVerifierArtifactError::Header("state arity"));
        }
        let payload = &artifact[VERIFIER_ARTIFACT_HEADER_LENGTH..];
        if header.payload_length != payload.len() as u64 {
            return Err(DirectNovaVerifierArtifactError::Header("payload length"));
        }

        let (metadata, proof_shape) = expected_suite.local_verifier_components::<ARITY>()?;
        let (verifier_key, consumed) =
            bincode::serde::decode_from_slice::<DirectVerifierKey<ARITY>, _>(
                payload,
                bincode::config::legacy()
                    .with_little_endian()
                    .with_fixed_int_encoding()
                    .with_limit::<MAX_VERIFIER_KEY_PAYLOAD_LENGTH>(),
            )?;
        if consumed != payload.len() {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        Ok(Self {
            expected: expected_suite,
            inner: DirectNovaVerifier::from_loaded_key(verifier_key, proof_shape, metadata)?,
        })
    }
}

fn read_u32(encoded: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        encoded[offset..offset + 4]
            .try_into()
            .expect("fixed verifier artifact u32 slice"),
    )
}

fn read_u64(encoded: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        encoded[offset..offset + 8]
            .try_into()
            .expect("fixed verifier artifact u64 slice"),
    )
}

fn tagged_artifact_hasher() -> Sha256 {
    let tag_hash = Sha256::digest(VERIFIER_ARTIFACT_DIGEST_TAG);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

fn tagged_artifact_digest(encoded: &[u8]) -> [u8; 32] {
    let mut digest = tagged_artifact_hasher();
    digest.update(encoded);
    digest.finalize().into()
}

fn tagged_artifact_digest_reader<R: Read>(
    source: &mut R,
    encoded_length: u64,
) -> Result<[u8; 32], io::Error> {
    let mut digest = tagged_artifact_hasher();
    let mut remaining = encoded_length;
    let mut buffer = [0u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("artifact digest buffer length fits usize");
        let read = source.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        digest.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_header_is_exact_and_big_endian() {
        let suite_id = [0xa5; 32];
        let header =
            ArtifactHeader::new::<20>(suite_id, 0x0102_0304).expect("valid artifact header");
        let encoded = header.encode();
        assert_eq!(encoded.len(), 64);
        assert_eq!(&encoded[..16], b"Purify/Nova/VK1\0");
        assert_eq!(&encoded[16..20], &[0, 0, 0, 1]);
        assert_eq!(&encoded[20..52], &suite_id);
        assert_eq!(&encoded[52..56], &[0, 0, 0, 20]);
        assert_eq!(&encoded[56..64], &[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(
            ArtifactHeader::decode(&encoded).expect("decode exact header"),
            header
        );
    }
}
