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
// The SHA-256 production suite is expected to encode below this local-only
// ceiling. Production still accepts exactly one compiled-in length and digest.
const MAX_VERIFIER_KEY_PAYLOAD_LENGTH: usize = 4_000_000_000;

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

        let payload_length = {
            let mut bounded = PayloadWriter::new(destination, MAX_VERIFIER_KEY_PAYLOAD_LENGTH);
            bincode::serde::encode_into_std_write(
                &self.inner.verifier_key,
                &mut bounded,
                bincode::config::legacy()
                    .with_little_endian()
                    .with_fixed_int_encoding(),
            )?
        };
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
    /// The borrowed slice is immutable for the complete load. The artifact
    /// cannot supply suite metadata or proof shape.
    pub(crate) fn from_artifact(
        artifact: &[u8],
        expected_suite: &'static ExpectedDirectNovaSuite,
        expected_artifact: &ExpectedDirectNovaVerifierArtifact,
    ) -> Result<Self, DirectNovaVerifierArtifactError> {
        let mut source = io::Cursor::new(artifact);
        Self::from_artifact_reader(&mut source, expected_suite, expected_artifact)
    }

    /// Loads an artifact from its complete seekable byte source.
    ///
    /// The first pass authenticates the complete source. Only a matching
    /// digest permits the second pass to parse the header or invoke Serde.
    /// The second pass hashes the bytes Serde consumes and rechecks the final
    /// length, so swapped bytes cannot be accepted. A file-backed caller must
    /// still provide an immutable local snapshot: a malicious same-length
    /// mutation can otherwise make Serde allocate before the second digest
    /// rejects it. The slice loader provides the strongest immutable path.
    pub(crate) fn from_artifact_reader<R>(
        source: &mut R,
        expected_suite: &'static ExpectedDirectNovaSuite,
        expected_artifact: &ExpectedDirectNovaVerifierArtifact,
    ) -> Result<Self, DirectNovaVerifierArtifactError>
    where
        R: Read + Seek,
    {
        let maximum_length = (VERIFIER_ARTIFACT_HEADER_LENGTH as u64)
            .checked_add(MAX_VERIFIER_KEY_PAYLOAD_LENGTH as u64)
            .ok_or(DirectNovaVerifierArtifactError::Length)?;
        let actual_length = source.seek(SeekFrom::End(0))?;
        if expected_artifact.encoded_length < VERIFIER_ARTIFACT_HEADER_LENGTH as u64
            || expected_artifact.encoded_length > maximum_length
            || actual_length != expected_artifact.encoded_length
        {
            return Err(DirectNovaVerifierArtifactError::Length);
        }

        source.seek(SeekFrom::Start(0))?;
        let digest = tagged_artifact_digest_reader(source, actual_length)?;
        if digest != expected_artifact.digest {
            return Err(DirectNovaVerifierArtifactError::Digest);
        }
        if source.seek(SeekFrom::End(0))? != actual_length {
            return Err(DirectNovaVerifierArtifactError::Length);
        }

        source.seek(SeekFrom::Start(0))?;
        let mut authenticated_source = ArtifactDigestingReader::new(&mut *source);
        let mut encoded_header = [0u8; VERIFIER_ARTIFACT_HEADER_LENGTH];
        authenticated_source.read_exact(&mut encoded_header)?;
        let header = ArtifactHeader::decode(&encoded_header)?;
        if header.suite_id != *expected_suite.suite_id.bytes() {
            return Err(DirectNovaVerifierArtifactError::Header("suite ID"));
        }
        let expected_arity = u32::try_from(ARITY)
            .map_err(|_| DirectNovaVerifierArtifactError::Header("state arity"))?;
        if header.arity != expected_arity {
            return Err(DirectNovaVerifierArtifactError::Header("state arity"));
        }
        let expected_payload_length = actual_length - VERIFIER_ARTIFACT_HEADER_LENGTH as u64;
        if header.payload_length != expected_payload_length {
            return Err(DirectNovaVerifierArtifactError::Header("payload length"));
        }

        let (metadata, proof_shape) = expected_suite.local_verifier_components::<ARITY>()?;
        let verifier_key = {
            let mut payload = (&mut authenticated_source).take(header.payload_length);
            let verifier_key =
                bincode::serde::decode_from_std_read::<DirectVerifierKey<ARITY>, _, _>(
                    &mut payload,
                    bincode::config::legacy()
                        .with_little_endian()
                        .with_fixed_int_encoding()
                        .with_limit::<MAX_VERIFIER_KEY_PAYLOAD_LENGTH>(),
                )?;
            if payload.limit() != 0 {
                return Err(DirectNovaVerifierArtifactError::Length);
            }
            verifier_key
        };
        if authenticated_source.finalize() != expected_artifact.digest {
            return Err(DirectNovaVerifierArtifactError::Digest);
        }
        if source.seek(SeekFrom::End(0))? != actual_length {
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

struct PayloadWriter<'a, W> {
    destination: &'a mut W,
    remaining: usize,
}

impl<'a, W> PayloadWriter<'a, W> {
    fn new(destination: &'a mut W, limit: usize) -> Self {
        Self {
            destination,
            remaining: limit,
        }
    }
}

impl<W: Write> Write for PayloadWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, io::Error> {
        if buffer.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "direct Nova verifier artifact exceeds payload limit",
            ));
        }
        let written = self.destination.write(buffer)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.destination.flush()
    }
}

struct ArtifactDigestingReader<R> {
    source: R,
    digest: Sha256,
}

impl<R> ArtifactDigestingReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            digest: tagged_artifact_hasher(),
        }
    }

    fn finalize(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}

impl<R: Read> Read for ArtifactDigestingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        let read = self.source.read(buffer)?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(test)]
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
        assert!(
            ArtifactHeader::new::<20>(suite_id, MAX_VERIFIER_KEY_PAYLOAD_LENGTH as u64 + 1)
                .is_err()
        );
    }

    #[test]
    fn payload_writer_rejects_before_crossing_limit() {
        let mut encoded = Vec::new();
        let mut writer = PayloadWriter::new(&mut encoded, 4);
        writer.write_all(&[1, 2, 3]).expect("write within limit");
        let error = writer
            .write_all(&[4, 5])
            .expect_err("reject write crossing limit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(writer.destination.as_slice(), [1, 2, 3]);
        writer.write_all(&[4]).expect("write exactly to limit");
        drop(writer);
        assert_eq!(encoded, [1, 2, 3, 4]);
    }
}
