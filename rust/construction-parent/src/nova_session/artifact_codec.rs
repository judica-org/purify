//! Shared authenticated framing for direct Nova deployment artifacts.
//!
//! Artifact users provide a frozen format and identity. The complete source
//! is authenticated before header parsing or Serde, and every byte consumed
//! during decoding is hashed again.

#[cfg(test)]
use std::io::Write;
use std::io::{self, Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) const ARTIFACT_HEADER_LENGTH: usize = 72;

const VERSION_OFFSET: usize = 16;
const SUITE_ID_OFFSET: usize = 20;
const ARITY_OFFSET: usize = 52;
const COMPRESSED_LENGTH_OFFSET: usize = 56;
const DECODED_LENGTH_OFFSET: usize = 64;
#[cfg(test)]
const ZSTD_COMPRESSION_LEVEL: i32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactFormat {
    magic: [u8; 16],
    encoding_version: u32,
    digest_tag: &'static [u8],
    window_log: u32,
    max_compressed_payload_length: usize,
    max_decoded_payload_length: usize,
}

impl ArtifactFormat {
    pub(crate) const fn new(
        magic: [u8; 16],
        encoding_version: u32,
        digest_tag: &'static [u8],
        window_log: u32,
        max_compressed_payload_length: usize,
        max_decoded_payload_length: usize,
    ) -> Self {
        Self {
            magic,
            encoding_version,
            digest_tag,
            window_log,
            max_compressed_payload_length,
            max_decoded_payload_length,
        }
    }
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
    pub(crate) fn for_test_bytes(
        format: &ArtifactFormat,
        encoded: &[u8],
        decoded_payload_length: u64,
    ) -> Self {
        Self::new(
            encoded.len() as u64,
            decoded_payload_length,
            tagged_artifact_digest(format, encoded),
        )
    }
}

#[derive(Debug, Error)]
pub(crate) enum ArtifactCodecError {
    #[cfg(test)]
    #[error("direct Nova artifact destination is not empty")]
    DestinationNotEmpty,
    #[error("direct Nova artifact length is invalid")]
    Length,
    #[error("direct Nova artifact digest mismatch")]
    Digest,
    #[error("direct Nova artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[cfg(test)]
    #[error("direct Nova artifact encoding failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("direct Nova artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
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
    fn new(
        format: &ArtifactFormat,
        suite_id: [u8; 32],
        arity: usize,
        compressed_payload_length: u64,
        decoded_payload_length: u64,
    ) -> Result<Self, ArtifactCodecError> {
        let arity = u32::try_from(arity).map_err(|_| ArtifactCodecError::Header("state arity"))?;
        if compressed_payload_length > format.max_compressed_payload_length as u64
            || decoded_payload_length > format.max_decoded_payload_length as u64
        {
            return Err(ArtifactCodecError::Length);
        }
        Ok(Self {
            suite_id,
            arity,
            compressed_payload_length,
            decoded_payload_length,
        })
    }

    #[cfg(test)]
    fn encode(self, format: &ArtifactFormat) -> [u8; ARTIFACT_HEADER_LENGTH] {
        let mut encoded = [0u8; ARTIFACT_HEADER_LENGTH];
        encoded[..VERSION_OFFSET].copy_from_slice(&format.magic);
        encoded[VERSION_OFFSET..SUITE_ID_OFFSET]
            .copy_from_slice(&format.encoding_version.to_be_bytes());
        encoded[SUITE_ID_OFFSET..ARITY_OFFSET].copy_from_slice(&self.suite_id);
        encoded[ARITY_OFFSET..COMPRESSED_LENGTH_OFFSET].copy_from_slice(&self.arity.to_be_bytes());
        encoded[COMPRESSED_LENGTH_OFFSET..DECODED_LENGTH_OFFSET]
            .copy_from_slice(&self.compressed_payload_length.to_be_bytes());
        encoded[DECODED_LENGTH_OFFSET..]
            .copy_from_slice(&self.decoded_payload_length.to_be_bytes());
        encoded
    }

    fn decode(format: &ArtifactFormat, encoded: &[u8]) -> Result<Self, ArtifactCodecError> {
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

#[cfg(test)]
pub(crate) fn write_artifact_payload<T, W>(
    destination: &mut W,
    format: &ArtifactFormat,
    suite_id: [u8; 32],
    arity: usize,
    payload: &T,
) -> Result<ArtifactIdentity, ArtifactCodecError>
where
    T: serde::Serialize,
    W: Read + Write + Seek,
{
    let initial_position = destination.stream_position()?;
    let initial_length = destination.seek(SeekFrom::End(0))?;
    if initial_position != 0 || initial_length != 0 {
        return Err(ArtifactCodecError::DestinationNotEmpty);
    }
    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&[0u8; ARTIFACT_HEADER_LENGTH])?;

    let (decoded_payload_length, compressed_payload_length) = {
        let bounded = PayloadWriter::new(destination, format.max_compressed_payload_length);
        let mut encoder = zstd::stream::write::Encoder::new(bounded, ZSTD_COMPRESSION_LEVEL)?;
        encoder.include_checksum(true)?;
        encoder.window_log(format.window_log)?;
        let decoded_payload_length = {
            let mut decoded = PayloadWriter::new(&mut encoder, format.max_decoded_payload_length);
            let decoded_payload_length = bincode::serde::encode_into_std_write(
                payload,
                &mut decoded,
                bincode::config::legacy()
                    .with_little_endian()
                    .with_fixed_int_encoding(),
            )?;
            if decoded_payload_length != decoded.written() {
                return Err(ArtifactCodecError::Length);
            }
            decoded_payload_length
        };
        let bounded = encoder.finish()?;
        (decoded_payload_length, bounded.written())
    };
    let compressed_payload_length =
        u64::try_from(compressed_payload_length).map_err(|_| ArtifactCodecError::Length)?;
    let decoded_payload_length =
        u64::try_from(decoded_payload_length).map_err(|_| ArtifactCodecError::Length)?;
    let header = ArtifactHeader::new(
        format,
        suite_id,
        arity,
        compressed_payload_length,
        decoded_payload_length,
    )?;
    let encoded_length = (ARTIFACT_HEADER_LENGTH as u64)
        .checked_add(compressed_payload_length)
        .ok_or(ArtifactCodecError::Length)?;
    if destination.stream_position()? != encoded_length {
        return Err(ArtifactCodecError::Length);
    }

    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&header.encode(format))?;
    destination.flush()?;
    if destination.seek(SeekFrom::End(0))? != encoded_length {
        return Err(ArtifactCodecError::Length);
    }
    destination.seek(SeekFrom::Start(0))?;
    let digest = tagged_artifact_digest_reader(format, destination, encoded_length)?;
    destination.seek(SeekFrom::Start(encoded_length))?;
    Ok(ArtifactIdentity::new(
        encoded_length,
        decoded_payload_length,
        digest,
    ))
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
                "direct Nova artifact exceeds payload limit",
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

#[cfg(test)]
fn tagged_artifact_digest(format: &ArtifactFormat, encoded: &[u8]) -> [u8; 32] {
    let mut digest = tagged_artifact_hasher(format.digest_tag);
    digest.update(encoded);
    digest.finalize().into()
}

fn tagged_artifact_digest_reader<R: Read>(
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
    use serde::{Deserialize, Serialize};

    use super::*;

    const TEST_FORMAT: ArtifactFormat = ArtifactFormat::new(
        *b"Purify/Nova/VK2\0",
        2,
        b"Purify/Accountable/DirectNovaVerifierArtifact/v2",
        23,
        2_000_000_000,
        4_000_000_000,
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

    #[test]
    fn artifact_header_is_exact_and_big_endian() {
        let suite_id = [0xa5; 32];
        let header = ArtifactHeader::new(&TEST_FORMAT, suite_id, 20, 0x0102_0304, 0x0506_0708)
            .expect("valid artifact header");
        let encoded = header.encode(&TEST_FORMAT);
        assert_eq!(encoded.len(), 72);
        assert_eq!(&encoded[..16], b"Purify/Nova/VK2\0");
        assert_eq!(&encoded[16..20], &[0, 0, 0, 2]);
        assert_eq!(&encoded[20..52], &suite_id);
        assert_eq!(&encoded[52..56], &[0, 0, 0, 20]);
        assert_eq!(&encoded[56..64], &[0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(&encoded[64..72], &[0, 0, 0, 0, 5, 6, 7, 8]);
        assert_eq!(
            ArtifactHeader::decode(&TEST_FORMAT, &encoded).expect("decode exact header"),
            header
        );
        assert!(ArtifactHeader::new(
            &TEST_FORMAT,
            suite_id,
            20,
            TEST_FORMAT.max_compressed_payload_length as u64 + 1,
            1,
        )
        .is_err());
        assert!(ArtifactHeader::new(
            &TEST_FORMAT,
            suite_id,
            20,
            1,
            TEST_FORMAT.max_decoded_payload_length as u64 + 1,
        )
        .is_err());
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
    fn artifact_roundtrip_is_deterministic_and_authenticated() {
        let payload = TestPayload {
            values: vec![2, 3, 5, 7, 11],
        };
        let suite_id = [0x5a; 32];
        let mut first = io::Cursor::new(Vec::new());
        let first_identity =
            write_artifact_payload(&mut first, &TEST_FORMAT, suite_id, 20, &payload)
                .expect("write first artifact");
        let first = first.into_inner();
        assert_eq!(first_identity.encoded_length(), first.len() as u64);
        assert_eq!(&first[..16], b"Purify/Nova/VK2\0");

        let mut second = io::Cursor::new(Vec::new());
        let second_identity =
            write_artifact_payload(&mut second, &TEST_FORMAT, suite_id, 20, &payload)
                .expect("write second artifact");
        assert_eq!(first_identity, second_identity);
        assert_eq!(first, second.into_inner());

        let mut reader = io::Cursor::new(first.as_slice());
        let decoded = read_artifact_payload::<TestPayload, _, 4_000_000_000>(
            &mut reader,
            &TEST_FORMAT,
            suite_id,
            20,
            first_identity,
        )
        .expect("read authenticated artifact");
        assert_eq!(decoded, payload);

        let mut corrupted = first;
        corrupted[ARTIFACT_HEADER_LENGTH] ^= 1;
        let mut reader = io::Cursor::new(corrupted);
        assert!(matches!(
            read_artifact_payload::<TestPayload, _, 4_000_000_000>(
                &mut reader,
                &TEST_FORMAT,
                suite_id,
                20,
                first_identity,
            ),
            Err(ArtifactCodecError::Digest)
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
