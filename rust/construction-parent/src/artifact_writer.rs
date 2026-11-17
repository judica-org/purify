//! Authenticated artifact writer for setup qualification.
//!
//! Production code only reads artifacts. Writing one is qualification output:
//! the returned identity must be reviewed and compiled into a loader before
//! anything accepts the file.

use std::io::{self, Read, Seek, SeekFrom, Write};

use thiserror::Error;

use crate::artifact::{
    tagged_artifact_digest_reader, ArtifactFormat, ArtifactHeader, ArtifactIdentity, ARITY_OFFSET,
    ARTIFACT_HEADER_LENGTH, COMPRESSED_LENGTH_OFFSET, DECODED_LENGTH_OFFSET, SUITE_ID_OFFSET,
    VERSION_OFFSET,
};

const ZSTD_COMPRESSION_LEVEL: i32 = 3;

#[derive(Debug, Error)]
pub(crate) enum ArtifactWriteError {
    #[error("direct Nova artifact destination is not empty")]
    DestinationNotEmpty,
    #[error("direct Nova artifact length is invalid")]
    Length,
    #[error("direct Nova artifact header is invalid: {0}")]
    Header(&'static str),
    #[error("direct Nova artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("direct Nova artifact encoding failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
}

fn new_header(
    format: &ArtifactFormat,
    suite_id: [u8; 32],
    arity: usize,
    compressed_payload_length: u64,
    decoded_payload_length: u64,
) -> Result<ArtifactHeader, ArtifactWriteError> {
    let arity = u32::try_from(arity).map_err(|_| ArtifactWriteError::Header("state arity"))?;
    if compressed_payload_length > format.max_compressed_payload_length as u64
        || decoded_payload_length > format.max_decoded_payload_length as u64
    {
        return Err(ArtifactWriteError::Length);
    }
    Ok(ArtifactHeader {
        suite_id,
        arity,
        compressed_payload_length,
        decoded_payload_length,
    })
}

fn encode_header(header: &ArtifactHeader, format: &ArtifactFormat) -> [u8; ARTIFACT_HEADER_LENGTH] {
    let mut encoded = [0u8; ARTIFACT_HEADER_LENGTH];
    encoded[..VERSION_OFFSET].copy_from_slice(&format.magic);
    encoded[VERSION_OFFSET..SUITE_ID_OFFSET]
        .copy_from_slice(&format.encoding_version.to_be_bytes());
    encoded[SUITE_ID_OFFSET..ARITY_OFFSET].copy_from_slice(&header.suite_id);
    encoded[ARITY_OFFSET..COMPRESSED_LENGTH_OFFSET].copy_from_slice(&header.arity.to_be_bytes());
    encoded[COMPRESSED_LENGTH_OFFSET..DECODED_LENGTH_OFFSET]
        .copy_from_slice(&header.compressed_payload_length.to_be_bytes());
    encoded[DECODED_LENGTH_OFFSET..].copy_from_slice(&header.decoded_payload_length.to_be_bytes());
    encoded
}

/// Computes the identity a loader would have to pin to accept `encoded`.
pub(crate) fn identity_of_bytes(
    format: &ArtifactFormat,
    encoded: &[u8],
    decoded_payload_length: u64,
) -> ArtifactIdentity {
    let digest =
        tagged_artifact_digest_reader(format, &mut io::Cursor::new(encoded), encoded.len() as u64)
            .expect("hash in-memory artifact");
    ArtifactIdentity::new(encoded.len() as u64, decoded_payload_length, digest)
}

pub(crate) fn write_artifact_payload<T, W>(
    destination: &mut W,
    format: &ArtifactFormat,
    suite_id: [u8; 32],
    arity: usize,
    payload: &T,
) -> Result<ArtifactIdentity, ArtifactWriteError>
where
    T: serde::Serialize,
    W: Read + Write + Seek,
{
    let initial_position = destination.stream_position()?;
    let initial_length = destination.seek(SeekFrom::End(0))?;
    if initial_position != 0 || initial_length != 0 {
        return Err(ArtifactWriteError::DestinationNotEmpty);
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
                return Err(ArtifactWriteError::Length);
            }
            decoded_payload_length
        };
        let bounded = encoder.finish()?;
        (decoded_payload_length, bounded.written())
    };
    let compressed_payload_length =
        u64::try_from(compressed_payload_length).map_err(|_| ArtifactWriteError::Length)?;
    let decoded_payload_length =
        u64::try_from(decoded_payload_length).map_err(|_| ArtifactWriteError::Length)?;
    let header = new_header(
        format,
        suite_id,
        arity,
        compressed_payload_length,
        decoded_payload_length,
    )?;
    let encoded_length = (ARTIFACT_HEADER_LENGTH as u64)
        .checked_add(compressed_payload_length)
        .ok_or(ArtifactWriteError::Length)?;
    if destination.stream_position()? != encoded_length {
        return Err(ArtifactWriteError::Length);
    }

    destination.seek(SeekFrom::Start(0))?;
    destination.write_all(&encode_header(&header, format))?;
    destination.flush()?;
    if destination.seek(SeekFrom::End(0))? != encoded_length {
        return Err(ArtifactWriteError::Length);
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

struct PayloadWriter<'a, W> {
    destination: &'a mut W,
    remaining: usize,
    written: usize,
}

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

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::artifact::read_artifact_payload;

    const TEST_FORMAT: ArtifactFormat = ArtifactFormat {
        magic: *b"Purify/Nova/VK2\0",
        encoding_version: 2,
        digest_tag: b"Purify/Accountable/DirectNovaVerifierArtifact/v2",
        window_log: 23,
        max_compressed_payload_length: 2_000_000_000,
        max_decoded_payload_length: 4_000_000_000,
    };
    // Generated by the pre-refactor verifier artifact codec at e410181.
    const PRE_REFACTOR_GOLDEN_ARTIFACT: [u8; 110] = [
        80, 117, 114, 105, 102, 121, 47, 78, 111, 118, 97, 47, 86, 75, 50, 0, 0, 0, 0, 2, 90, 90,
        90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
        90, 90, 90, 90, 90, 90, 90, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 0, 0, 0, 48,
        40, 181, 47, 253, 4, 104, 205, 0, 0, 144, 5, 0, 2, 0, 3, 0, 5, 0, 7, 0, 11, 0, 0, 0, 0, 0,
        0, 0, 5, 84, 2, 0, 3, 1, 78, 193, 86, 178,
    ];
    const PRE_REFACTOR_GOLDEN_DIGEST: [u8; 32] = [
        104, 10, 165, 116, 156, 202, 179, 68, 244, 27, 130, 58, 194, 118, 217, 58, 198, 33, 161,
        187, 63, 105, 97, 222, 163, 209, 73, 38, 109, 214, 154, 235,
    ];

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestPayload {
        values: Vec<u64>,
    }

    #[test]
    fn artifact_header_is_exact_and_big_endian() {
        let suite_id = [0xa5; 32];
        let header = new_header(&TEST_FORMAT, suite_id, 20, 0x0102_0304, 0x0506_0708)
            .expect("valid artifact header");
        let encoded = encode_header(&header, &TEST_FORMAT);
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
        assert!(new_header(
            &TEST_FORMAT,
            suite_id,
            20,
            TEST_FORMAT.max_compressed_payload_length as u64 + 1,
            1,
        )
        .is_err());
        assert!(new_header(
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
        assert_eq!(first.as_slice(), PRE_REFACTOR_GOLDEN_ARTIFACT);
        assert_eq!(first_identity.digest(), PRE_REFACTOR_GOLDEN_DIGEST);

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
            Err(crate::artifact::ArtifactCodecError::Digest)
        ));
    }
}
