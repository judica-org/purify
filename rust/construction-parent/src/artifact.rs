//! Shared authenticated framing for direct Nova deployment artifacts.
//!
//! Artifact users provide a frozen format and identity. The complete source
//! is authenticated before header parsing or Serde, and every byte consumed
//! during decoding is hashed again. This module only reads artifacts.

use std::io::{self, Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) const ARTIFACT_HEADER_LENGTH: usize = 72;

pub(crate) const VERSION_OFFSET: usize = 16;
pub(crate) const SUITE_ID_OFFSET: usize = 20;
pub(crate) const ARITY_OFFSET: usize = 52;
pub(crate) const COMPRESSED_LENGTH_OFFSET: usize = 56;
pub(crate) const DECODED_LENGTH_OFFSET: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactFormat {
    pub(crate) magic: [u8; 16],
    pub(crate) encoding_version: u32,
    pub(crate) digest_tag: &'static [u8],
    pub(crate) window_log: u32,
    pub(crate) max_compressed_payload_length: usize,
    pub(crate) max_decoded_payload_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactIdentity {
    encoded_length: u64,
    decoded_payload_length: u64,
    digest: [u8; 32],
}

impl ArtifactIdentity {
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

    pub(crate) const fn encoded_length(self) -> u64 {
        self.encoded_length
    }

    #[cfg(any(test, feature = "prover"))]
    pub(crate) const fn decoded_payload_length(self) -> u64 {
        self.decoded_payload_length
    }

    #[cfg(any(test, feature = "prover"))]
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Debug, Error)]
pub(crate) enum ArtifactCodecError {
    #[error("direct Nova artifact length is invalid")]
    Length,
    #[error("direct Nova artifact digest mismatch")]
    Digest,
    #[error("direct Nova artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

/// Fixed 72-byte artifact header: magic, big-endian encoding version, suite
/// ID, big-endian state arity, and big-endian compressed and decoded payload
/// lengths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactHeader {
    pub(crate) suite_id: [u8; 32],
    pub(crate) arity: u32,
    pub(crate) compressed_payload_length: u64,
    pub(crate) decoded_payload_length: u64,
}

impl ArtifactHeader {
    pub(crate) fn decode(
        format: &ArtifactFormat,
        encoded: &[u8],
    ) -> Result<Self, ArtifactCodecError> {
        if encoded.len() < ARTIFACT_HEADER_LENGTH {
            return Err(ArtifactCodecError::Length);
        }
        if encoded[..VERSION_OFFSET] != format.magic {
            return Err(ArtifactCodecError::Header("magic"));
        }
        let version = read_u32(encoded, VERSION_OFFSET);
        if version != format.encoding_version {
            return Err(ArtifactCodecError::Header("encoding version"));
        }
        let suite_id = encoded[SUITE_ID_OFFSET..ARITY_OFFSET]
            .try_into()
            .expect("fixed direct Nova artifact suite ID slice");
        Ok(Self {
            suite_id,
            arity: read_u32(encoded, ARITY_OFFSET),
            compressed_payload_length: read_u64(encoded, COMPRESSED_LENGTH_OFFSET),
            decoded_payload_length: read_u64(encoded, DECODED_LENGTH_OFFSET),
        })
    }
}

pub(crate) fn read_artifact_payload<T, R, const MAX_DECODED_PAYLOAD_LENGTH: usize>(
    source: &mut R,
    format: &ArtifactFormat,
    expected_suite_id: [u8; 32],
    expected_arity: usize,
    expected_artifact: ArtifactIdentity,
) -> Result<T, ArtifactCodecError>
where
    T: serde::de::DeserializeOwned,
    R: Read + Seek,
{
    // Bincode's allocation limit is a const generic. Require the typed call
    // site to match the same bound carried by the selected artifact format.
    if format.max_decoded_payload_length != MAX_DECODED_PAYLOAD_LENGTH {
        return Err(ArtifactCodecError::Length);
    }
    let maximum_length = (ARTIFACT_HEADER_LENGTH as u64)
        .checked_add(format.max_compressed_payload_length as u64)
        .ok_or(ArtifactCodecError::Length)?;
    let actual_length = source.seek(SeekFrom::End(0))?;
    if expected_artifact.encoded_length < ARTIFACT_HEADER_LENGTH as u64
        || expected_artifact.encoded_length > maximum_length
        || expected_artifact.decoded_payload_length > format.max_decoded_payload_length as u64
        || actual_length != expected_artifact.encoded_length
    {
        return Err(ArtifactCodecError::Length);
    }

    source.seek(SeekFrom::Start(0))?;
    let digest = tagged_artifact_digest_reader(format, source, actual_length)?;
    if digest != expected_artifact.digest {
        return Err(ArtifactCodecError::Digest);
    }
    if source.seek(SeekFrom::End(0))? != actual_length {
        return Err(ArtifactCodecError::Length);
    }

    source.seek(SeekFrom::Start(0))?;
    let mut authenticated_source = ArtifactDigestingReader::new(&mut *source, format.digest_tag);
    let mut encoded_header = [0u8; ARTIFACT_HEADER_LENGTH];
    authenticated_source.read_exact(&mut encoded_header)?;
    let header = ArtifactHeader::decode(format, &encoded_header)?;
    if header.suite_id != expected_suite_id {
        return Err(ArtifactCodecError::Header("suite ID"));
    }
    let expected_arity =
        u32::try_from(expected_arity).map_err(|_| ArtifactCodecError::Header("state arity"))?;
    if header.arity != expected_arity {
        return Err(ArtifactCodecError::Header("state arity"));
    }
    let expected_compressed_length = actual_length - ARTIFACT_HEADER_LENGTH as u64;
    if header.compressed_payload_length != expected_compressed_length {
        return Err(ArtifactCodecError::Header("compressed payload length"));
    }
    if header.decoded_payload_length != expected_artifact.decoded_payload_length {
        return Err(ArtifactCodecError::Header("decoded payload length"));
    }
    if header.compressed_payload_length > format.max_compressed_payload_length as u64
        || header.decoded_payload_length > format.max_decoded_payload_length as u64
    {
        return Err(ArtifactCodecError::Length);
    }

    let compressed = (&mut authenticated_source).take(header.compressed_payload_length);
    let value = decode_exact_zstd_payload::<T, _, MAX_DECODED_PAYLOAD_LENGTH>(
        compressed,
        header.decoded_payload_length,
        format.window_log,
    )?;
    if authenticated_source.finalize() != expected_artifact.digest {
        return Err(ArtifactCodecError::Digest);
    }
    if source.seek(SeekFrom::End(0))? != actual_length {
        return Err(ArtifactCodecError::Length);
    }
    Ok(value)
}

fn decode_exact_zstd_payload<T, R, const MAX_DECODED_PAYLOAD_LENGTH: usize>(
    compressed: io::Take<R>,
    decoded_payload_length: u64,
    window_log: u32,
) -> Result<T, ArtifactCodecError>
where
    T: serde::de::DeserializeOwned,
    R: Read,
{
    let mut decoder = zstd::stream::read::Decoder::new(compressed)?;
    decoder.window_log_max(window_log)?;
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
            return Err(ArtifactCodecError::Length);
        }
        value
    };
    let mut extra = [0u8; 1];
    if decoder.read(&mut extra)? != 0 {
        return Err(ArtifactCodecError::Length);
    }
    decoder.finish_frame()?;
    let compressed = decoder.into_inner();
    if !compressed.buffer().is_empty() || compressed.get_ref().limit() != 0 {
        return Err(ArtifactCodecError::Length);
    }
    Ok(value)
}

fn read_u32(encoded: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        encoded[offset..offset + 4]
            .try_into()
            .expect("fixed direct Nova artifact u32 slice"),
    )
}

fn read_u64(encoded: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        encoded[offset..offset + 8]
            .try_into()
            .expect("fixed direct Nova artifact u64 slice"),
    )
}

fn tagged_artifact_hasher(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

struct ArtifactDigestingReader<R> {
    source: R,
    digest: Sha256,
}

impl<R> ArtifactDigestingReader<R> {
    fn new(source: R, digest_tag: &[u8]) -> Self {
        Self {
            source,
            digest: tagged_artifact_hasher(digest_tag),
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

pub(crate) fn tagged_artifact_digest_reader<R: Read>(
    format: &ArtifactFormat,
    source: &mut R,
    encoded_length: u64,
) -> Result<[u8; 32], io::Error> {
    let mut digest = tagged_artifact_hasher(format.digest_tag);
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
    use std::io::Write;

    use serde::{Deserialize, Serialize};

    use super::*;

    const TEST_FORMAT: ArtifactFormat = ArtifactFormat {
        magic: *b"Purify/Nova/VK2\0",
        encoding_version: 2,
        digest_tag: b"Purify/Accountable/DirectNovaVerifierArtifact/v2",
        window_log: 23,
        max_compressed_payload_length: 2_000_000_000,
        max_decoded_payload_length: 4_000_000_000,
    };
    const ZSTD_COMPRESSION_LEVEL: i32 = 3;
    // Generated by the pre-refactor verifier artifact codec at e410181.
    const PRE_REFACTOR_GOLDEN_ARTIFACT: [u8; 110] = [
        80, 117, 114, 105, 102, 121, 47, 78, 111, 118, 97, 47, 86, 75, 50, 0, 0, 0, 0, 2, 90, 90,
        90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
        90, 90, 90, 90, 90, 90, 90, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 48,
        40, 181, 47, 253, 4, 104, 205, 0, 0, 144, 5, 0, 2, 0, 3, 0, 5, 0, 7, 0, 11, 0, 0, 0, 0, 0,
        0, 0, 5, 84, 2, 0, 3, 1, 78, 193, 86, 178,
    ];
    const PRE_REFACTOR_GOLDEN_IDENTITY: ArtifactIdentity = ArtifactIdentity::new(
        110,
        48,
        [
            104, 10, 165, 116, 156, 202, 179, 68, 244, 27, 130, 58, 194, 118, 217, 58, 198, 33,
            161, 187, 63, 105, 97, 222, 163, 209, 73, 38, 109, 214, 154, 235,
        ],
    );

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
            .window_log(TEST_FORMAT.window_log)
            .expect("set test frame window");
        encoder.write_all(decoded).expect("encode test frame");
        encoder.finish().expect("finish test frame")
    }

    fn decode_test_payload(
        compressed: &[u8],
        decoded_length: usize,
    ) -> Result<TestPayload, ArtifactCodecError> {
        let compressed_length =
            u64::try_from(compressed.len()).expect("compressed test payload length fits u64");
        decode_exact_zstd_payload::<TestPayload, _, 4_000_000_000>(
            io::Cursor::new(compressed).take(compressed_length),
            u64::try_from(decoded_length).expect("decoded test payload length fits u64"),
            TEST_FORMAT.window_log,
        )
    }

    fn read_golden(
        encoded: &[u8],
        suite_id: [u8; 32],
        arity: usize,
        identity: ArtifactIdentity,
    ) -> Result<TestPayload, ArtifactCodecError> {
        let mut reader = io::Cursor::new(encoded);
        read_artifact_payload::<TestPayload, _, 4_000_000_000>(
            &mut reader,
            &TEST_FORMAT,
            suite_id,
            arity,
            identity,
        )
    }

    #[test]
    fn golden_artifact_header_is_exact_and_big_endian() {
        let header = ArtifactHeader::decode(&TEST_FORMAT, &PRE_REFACTOR_GOLDEN_ARTIFACT[..72])
            .expect("decode golden header");
        assert_eq!(
            header,
            ArtifactHeader {
                suite_id: [0x5a; 32],
                arity: 20,
                compressed_payload_length: 38,
                decoded_payload_length: 48,
            }
        );
        assert!(matches!(
            ArtifactHeader::decode(&TEST_FORMAT, &PRE_REFACTOR_GOLDEN_ARTIFACT[..71]),
            Err(ArtifactCodecError::Length)
        ));
    }

    #[test]
    fn golden_artifact_reads_only_under_its_exact_identity() {
        let suite_id = [0x5a; 32];
        assert_eq!(
            read_golden(
                &PRE_REFACTOR_GOLDEN_ARTIFACT,
                suite_id,
                20,
                PRE_REFACTOR_GOLDEN_IDENTITY
            )
            .expect("read authenticated golden artifact"),
            TestPayload {
                values: vec![2, 3, 5, 7, 11],
            }
        );

        let mut corrupted = PRE_REFACTOR_GOLDEN_ARTIFACT;
        corrupted[ARTIFACT_HEADER_LENGTH] ^= 1;
        assert!(matches!(
            read_golden(&corrupted, suite_id, 20, PRE_REFACTOR_GOLDEN_IDENTITY),
            Err(ArtifactCodecError::Digest)
        ));
        assert!(matches!(
            read_golden(
                &PRE_REFACTOR_GOLDEN_ARTIFACT,
                [0xa5; 32],
                20,
                PRE_REFACTOR_GOLDEN_IDENTITY
            ),
            Err(ArtifactCodecError::Header("suite ID"))
        ));
        assert!(matches!(
            read_golden(
                &PRE_REFACTOR_GOLDEN_ARTIFACT,
                suite_id,
                21,
                PRE_REFACTOR_GOLDEN_IDENTITY
            ),
            Err(ArtifactCodecError::Header("state arity"))
        ));
        assert!(matches!(
            read_golden(
                &PRE_REFACTOR_GOLDEN_ARTIFACT[..109],
                suite_id,
                20,
                PRE_REFACTOR_GOLDEN_IDENTITY
            ),
            Err(ArtifactCodecError::Length)
        ));
        let wrong_decoded_length = ArtifactIdentity::new(
            PRE_REFACTOR_GOLDEN_IDENTITY.encoded_length(),
            PRE_REFACTOR_GOLDEN_IDENTITY.decoded_payload_length() + 1,
            PRE_REFACTOR_GOLDEN_IDENTITY.digest(),
        );
        assert!(matches!(
            read_golden(
                &PRE_REFACTOR_GOLDEN_ARTIFACT,
                suite_id,
                20,
                wrong_decoded_length
            ),
            Err(ArtifactCodecError::Header("decoded payload length"))
        ));
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
            Err(ArtifactCodecError::Io(_)) | Err(ArtifactCodecError::Decode(_))
        ));

        let mut bad_checksum = compressed.clone();
        *bad_checksum.last_mut().expect("zstd frame checksum") ^= 1;
        assert!(matches!(
            decode_test_payload(&bad_checksum, decoded.len()),
            Err(ArtifactCodecError::Io(_)) | Err(ArtifactCodecError::Decode(_))
        ));

        let mut concatenated = compressed;
        concatenated.extend_from_slice(&test_zstd_frame(b"second frame"));
        assert!(matches!(
            decode_test_payload(&concatenated, decoded.len()),
            Err(ArtifactCodecError::Length)
        ));

        let mut excess_decoded = decoded;
        excess_decoded.push(0);
        let excess_frame = test_zstd_frame(&excess_decoded);
        assert!(matches!(
            decode_test_payload(&excess_frame, excess_decoded.len()),
            Err(ArtifactCodecError::Length)
        ));
    }
}
