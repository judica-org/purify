//! Authenticated local storage for one selected direct Nova verifier.
//!
//! This is a deployment artifact, not a receipt or consensus-selected
//! parameter format. The caller supplies one locally frozen descriptor, and
//! the complete artifact is authenticated before Serde sees any bytes.

#[cfg(test)]
use std::io::Write;
use std::io::{self, Read, Seek, SeekFrom};

use nova_snark::traits::circuit::StepCircuit;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    DirectNovaSessionError, ExpectedDirectNovaSuite, NovaVerifier, NovaVerifierKey,
    SelectedNovaVerifier,
};
use crate::nova_types::DirectNovaScalar;

const VERIFIER_ARTIFACT_MAGIC: [u8; 16] = *b"Purify/Nova/VK2\0";
const VERIFIER_ARTIFACT_ENCODING_VERSION: u32 = 2;
const VERIFIER_ARTIFACT_DIGEST_TAG: &[u8] = b"Purify/Accountable/DirectNovaVerifierArtifact/v2";
const VERIFIER_ARTIFACT_HEADER_LENGTH: usize = 72;
#[cfg(test)]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;
const ZSTD_WINDOW_LOG: u32 = 23;
const MAX_COMPRESSED_PAYLOAD_LENGTH: usize = 2_000_000_000;
const MAX_DECODED_PAYLOAD_LENGTH: usize = 4_000_000_000;

const VERSION_OFFSET: usize = 16;
const SUITE_ID_OFFSET: usize = 20;
const ARITY_OFFSET: usize = 52;
const COMPRESSED_LENGTH_OFFSET: usize = 56;
const DECODED_LENGTH_OFFSET: usize = 64;

/// The one artifact identity compiled into the selected library deployment.
///
/// It is deliberately separate from the semantic suite ID. Receipts never
/// supply this value, and a serialization-only change must replace it without
/// changing the proof statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedDirectNovaVerifierArtifact {
    encoded_length: u64,
    decoded_payload_length: u64,
    digest: [u8; 32],
}

impl ExpectedDirectNovaVerifierArtifact {
    pub(crate) const fn new(
        encoded_length: u64,
        decoded_payload_length: u64,
        digest: [u8; 32],
    ) -> Self {
        Self {
            encoded_length,
            decoded_payload_length,
            digest,
        }
    }

    #[cfg(test)]
    pub(crate) const fn encoded_length(self) -> u64 {
        self.encoded_length
    }

    #[cfg(test)]
    pub(crate) const fn decoded_payload_length(self) -> u64 {
        self.decoded_payload_length
    }

    #[cfg(test)]
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    pub(crate) fn for_test_bytes(encoded: &[u8], decoded_payload_length: u64) -> Self {
        Self::new(
            encoded.len() as u64,
            decoded_payload_length,
            tagged_artifact_digest(encoded),
        )
    }
}

/// Authenticated verifier artifact from the mixed SHA-256 qualification.
pub(crate) const QUALIFIED_SHA256_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT:
    ExpectedDirectNovaVerifierArtifact = ExpectedDirectNovaVerifierArtifact::new(
    693_708_278,
    3_206_736_424,
    [
        0x18, 0x4c, 0x33, 0x40, 0xde, 0x8f, 0x00, 0x5a, 0x6e, 0x3a, 0x83, 0x99, 0x7e, 0x90, 0xff,
        0x99, 0x3d, 0x24, 0x50, 0x26, 0xd6, 0xae, 0xc0, 0x48, 0x04, 0xdc, 0xb7, 0x36, 0xf2, 0x9c,
        0xa0, 0xaa,
    ],
);

#[derive(Debug, Error)]
pub(crate) enum DirectNovaVerifierArtifactError {
    #[cfg(test)]
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
    #[cfg(test)]
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
    compressed_payload_length: u64,
    decoded_payload_length: u64,
}

impl ArtifactHeader {
    #[cfg(test)]
    fn new<const ARITY: usize>(
        suite_id: [u8; 32],
        compressed_payload_length: u64,
        decoded_payload_length: u64,
    ) -> Result<Self, DirectNovaVerifierArtifactError> {
        let arity = u32::try_from(ARITY)
            .map_err(|_| DirectNovaVerifierArtifactError::Header("state arity"))?;
        if compressed_payload_length > MAX_COMPRESSED_PAYLOAD_LENGTH as u64
            || decoded_payload_length > MAX_DECODED_PAYLOAD_LENGTH as u64
        {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        Ok(Self {
            suite_id,
            arity,
            compressed_payload_length,
            decoded_payload_length,
        })
    }

    #[cfg(test)]
    fn encode(self) -> [u8; VERIFIER_ARTIFACT_HEADER_LENGTH] {
        let mut encoded = [0u8; VERIFIER_ARTIFACT_HEADER_LENGTH];
        encoded[..VERSION_OFFSET].copy_from_slice(&VERIFIER_ARTIFACT_MAGIC);
        encoded[VERSION_OFFSET..SUITE_ID_OFFSET]
            .copy_from_slice(&VERIFIER_ARTIFACT_ENCODING_VERSION.to_be_bytes());
        encoded[SUITE_ID_OFFSET..ARITY_OFFSET].copy_from_slice(&self.suite_id);
        encoded[ARITY_OFFSET..COMPRESSED_LENGTH_OFFSET].copy_from_slice(&self.arity.to_be_bytes());
        encoded[COMPRESSED_LENGTH_OFFSET..DECODED_LENGTH_OFFSET]
            .copy_from_slice(&self.compressed_payload_length.to_be_bytes());
        encoded[DECODED_LENGTH_OFFSET..]
            .copy_from_slice(&self.decoded_payload_length.to_be_bytes());
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
            compressed_payload_length: read_u64(encoded, COMPRESSED_LENGTH_OFFSET),
            decoded_payload_length: read_u64(encoded, DECODED_LENGTH_OFFSET),
        })
    }
}

impl<const ARITY: usize, C: StepCircuit<DirectNovaScalar>> SelectedNovaVerifier<ARITY, C> {
    /// Streams this selected verifier into a new empty seekable destination.
    ///
    /// The returned descriptor is qualification output. A production loader
    /// must compile in reviewed constants rather than derive them from the
    /// file it is about to accept.
    #[cfg(test)]
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

        let (decoded_payload_length, compressed_payload_length) = {
            let bounded = PayloadWriter::new(destination, MAX_COMPRESSED_PAYLOAD_LENGTH);
            let mut encoder = zstd::stream::write::Encoder::new(bounded, ZSTD_COMPRESSION_LEVEL)?;
            encoder.include_checksum(true)?;
            encoder.window_log(ZSTD_WINDOW_LOG)?;
            let decoded_payload_length = {
                let mut decoded = PayloadWriter::new(&mut encoder, MAX_DECODED_PAYLOAD_LENGTH);
                let decoded_payload_length = bincode::serde::encode_into_std_write(
                    &self.inner.verifier_key,
                    &mut decoded,
                    bincode::config::legacy()
                        .with_little_endian()
                        .with_fixed_int_encoding(),
                )?;
                if decoded_payload_length != decoded.written() {
                    return Err(DirectNovaVerifierArtifactError::Length);
                }
                decoded_payload_length
            };
            let bounded = encoder.finish()?;
            (decoded_payload_length, bounded.written())
        };
        let compressed_payload_length = u64::try_from(compressed_payload_length)
            .map_err(|_| DirectNovaVerifierArtifactError::Length)?;
        let decoded_payload_length = u64::try_from(decoded_payload_length)
            .map_err(|_| DirectNovaVerifierArtifactError::Length)?;
        let header = ArtifactHeader::new::<ARITY>(
            *self.expected.suite_id.bytes(),
            compressed_payload_length,
            decoded_payload_length,
        )?;
        let encoded_length = (VERIFIER_ARTIFACT_HEADER_LENGTH as u64)
            .checked_add(compressed_payload_length)
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
            decoded_payload_length,
            digest,
        ))
    }

    /// Loads exactly one locally selected and pre-authenticated verifier.
    ///
    /// Length and digest checks precede header parsing and all Serde work.
    /// The borrowed slice is immutable for the complete load. The artifact
    /// cannot supply suite metadata or proof shape.
    #[cfg(test)]
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
            .checked_add(MAX_COMPRESSED_PAYLOAD_LENGTH as u64)
            .ok_or(DirectNovaVerifierArtifactError::Length)?;
        let actual_length = source.seek(SeekFrom::End(0))?;
        if expected_artifact.encoded_length < VERIFIER_ARTIFACT_HEADER_LENGTH as u64
            || expected_artifact.encoded_length > maximum_length
            || expected_artifact.decoded_payload_length > MAX_DECODED_PAYLOAD_LENGTH as u64
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
        let expected_compressed_length = actual_length - VERIFIER_ARTIFACT_HEADER_LENGTH as u64;
        if header.compressed_payload_length != expected_compressed_length {
            return Err(DirectNovaVerifierArtifactError::Header(
                "compressed payload length",
            ));
        }
        if header.decoded_payload_length != expected_artifact.decoded_payload_length {
            return Err(DirectNovaVerifierArtifactError::Header(
                "decoded payload length",
            ));
        }
        if header.compressed_payload_length > MAX_COMPRESSED_PAYLOAD_LENGTH as u64
            || header.decoded_payload_length > MAX_DECODED_PAYLOAD_LENGTH as u64
        {
            return Err(DirectNovaVerifierArtifactError::Length);
        }

        let (metadata, proof_shape) = expected_suite.local_verifier_components::<ARITY>()?;
        let compressed = (&mut authenticated_source).take(header.compressed_payload_length);
        let verifier_key = decode_exact_zstd_payload::<NovaVerifierKey<C>, _>(
            compressed,
            header.decoded_payload_length,
        )?;
        if authenticated_source.finalize() != expected_artifact.digest {
            return Err(DirectNovaVerifierArtifactError::Digest);
        }
        if source.seek(SeekFrom::End(0))? != actual_length {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        Ok(Self {
            expected: expected_suite,
            inner: NovaVerifier::from_loaded_key(verifier_key, proof_shape, metadata)?,
        })
    }
}

fn decode_exact_zstd_payload<T, R>(
    compressed: io::Take<R>,
    decoded_payload_length: u64,
) -> Result<T, DirectNovaVerifierArtifactError>
where
    T: serde::de::DeserializeOwned,
    R: Read,
{
    let mut decoder = zstd::stream::read::Decoder::new(compressed)?;
    decoder.window_log_max(ZSTD_WINDOW_LOG)?;
    let mut decoder = decoder.single_frame();
    let value = {
        let mut decoded = (&mut decoder).take(decoded_payload_length);
        let value = bincode::serde::decode_from_std_read::<T, _, _>(
            &mut decoded,
            bincode::config::legacy()
                .with_little_endian()
                .with_fixed_int_encoding()
                .with_limit::<MAX_DECODED_PAYLOAD_LENGTH>(),
        )?;
        if decoded.limit() != 0 {
            return Err(DirectNovaVerifierArtifactError::Length);
        }
        value
    };
    let mut extra = [0u8; 1];
    if decoder.read(&mut extra)? != 0 {
        return Err(DirectNovaVerifierArtifactError::Length);
    }
    decoder.finish_frame()?;
    let compressed = decoder.into_inner();
    if !compressed.buffer().is_empty() || compressed.get_ref().limit() != 0 {
        return Err(DirectNovaVerifierArtifactError::Length);
    }
    Ok(value)
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

#[cfg(test)]
struct PayloadWriter<'a, W> {
    destination: &'a mut W,
    remaining: usize,
    written: usize,
}

#[cfg(test)]
impl<'a, W> PayloadWriter<'a, W> {
    fn new(destination: &'a mut W, limit: usize) -> Self {
        Self {
            destination,
            remaining: limit,
            written: 0,
        }
    }

    fn written(&self) -> usize {
        self.written
    }
}

#[cfg(test)]
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
        self.written += written;
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
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestPayload {
        values: Vec<u64>,
    }

    fn test_payload_bytes(value: &TestPayload) -> Vec<u8> {
        bincode::serde::encode_to_vec(
            value,
            bincode::config::legacy()
                .with_little_endian()
                .with_fixed_int_encoding(),
        )
        .expect("encode test payload")
    }

    fn test_zstd_frame(decoded: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_COMPRESSION_LEVEL)
            .expect("test zstd encoder");
        encoder
            .include_checksum(true)
            .expect("enable test frame checksum");
        encoder
            .window_log(ZSTD_WINDOW_LOG)
            .expect("set test frame window");
        encoder.write_all(decoded).expect("encode test frame");
        encoder.finish().expect("finish test frame")
    }

    fn decode_test_payload(
        compressed: &[u8],
        decoded_length: usize,
    ) -> Result<TestPayload, DirectNovaVerifierArtifactError> {
        let compressed_length =
            u64::try_from(compressed.len()).expect("compressed test payload length fits u64");
        decode_exact_zstd_payload(
            io::Cursor::new(compressed).take(compressed_length),
            u64::try_from(decoded_length).expect("decoded test payload length fits u64"),
        )
    }

    #[test]
    fn artifact_header_is_exact_and_big_endian() {
        let suite_id = [0xa5; 32];
        let header = ArtifactHeader::new::<20>(suite_id, 0x0102_0304, 0x0506_0708)
            .expect("valid artifact header");
        let encoded = header.encode();
        assert_eq!(encoded.len(), 72);
        assert_eq!(&encoded[..16], b"Purify/Nova/VK2\0");
        assert_eq!(&encoded[16..20], &[0, 0, 0, 2]);
        assert_eq!(&encoded[20..52], &suite_id);
        assert_eq!(&encoded[52..56], &[0, 0, 0, 20]);
        assert_eq!(&encoded[56..64], &[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(&encoded[64..72], &[0, 0, 0, 0, 5, 6, 7, 8]);
        assert_eq!(
            ArtifactHeader::decode(&encoded).expect("decode exact header"),
            header
        );
        assert!(
            ArtifactHeader::new::<20>(suite_id, MAX_COMPRESSED_PAYLOAD_LENGTH as u64 + 1, 1,)
                .is_err()
        );
        assert!(
            ArtifactHeader::new::<20>(suite_id, 1, MAX_DECODED_PAYLOAD_LENGTH as u64 + 1,).is_err()
        );
    }

    #[test]
    fn payload_writer_rejects_before_crossing_limit() {
        let mut encoded = Vec::new();
        {
            let mut writer = PayloadWriter::new(&mut encoded, 4);
            writer.write_all(&[1, 2, 3]).expect("write within limit");
            let error = writer
                .write_all(&[4, 5])
                .expect_err("reject write crossing limit");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(writer.destination.as_slice(), [1, 2, 3]);
            assert_eq!(writer.written(), 3);
            writer.write_all(&[4]).expect("write exactly to limit");
            assert_eq!(writer.written(), 4);
        }
        assert_eq!(encoded, [1, 2, 3, 4]);
    }

    #[test]
    fn exact_zstd_payload_rejects_extra_frames_and_decoded_bytes() {
        let expected = TestPayload {
            values: vec![3, 5, 8, 13],
        };
        let decoded = test_payload_bytes(&expected);
        let compressed = test_zstd_frame(&decoded);
        assert_eq!(
            decode_test_payload(&compressed, decoded.len()).expect("decode exact frame"),
            expected
        );

        let mut truncated = compressed.clone();
        truncated.pop();
        assert!(matches!(
            decode_test_payload(&truncated, decoded.len()),
            Err(DirectNovaVerifierArtifactError::Io(_))
                | Err(DirectNovaVerifierArtifactError::Decode(_))
        ));

        let mut bad_checksum = compressed.clone();
        *bad_checksum.last_mut().expect("zstd frame checksum") ^= 1;
        assert!(matches!(
            decode_test_payload(&bad_checksum, decoded.len()),
            Err(DirectNovaVerifierArtifactError::Io(_))
                | Err(DirectNovaVerifierArtifactError::Decode(_))
        ));

        let mut concatenated = compressed;
        concatenated.extend_from_slice(&test_zstd_frame(b"second frame"));
        assert!(matches!(
            decode_test_payload(&concatenated, decoded.len()),
            Err(DirectNovaVerifierArtifactError::Length)
        ));

        let mut excess_decoded = decoded;
        excess_decoded.push(0);
        let excess_frame = test_zstd_frame(&excess_decoded);
        assert!(matches!(
            decode_test_payload(&excess_frame, excess_decoded.len()),
            Err(DirectNovaVerifierArtifactError::Length)
        ));
    }
}
