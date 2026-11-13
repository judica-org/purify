//! Authenticated local storage for one selected direct Nova verifier.
//!
//! This is a deployment artifact, not a receipt or consensus-selected
//! parameter format. The caller supplies one locally frozen descriptor, and
//! the complete artifact is authenticated before Serde sees any bytes.

#[cfg(test)]
use std::io::Write;
use std::io::{self, Read, Seek};

use nova_snark::traits::circuit::StepCircuit;
use thiserror::Error;

#[cfg(test)]
use super::artifact_codec::write_artifact_payload;
use super::artifact_codec::{
    read_artifact_payload, ArtifactCodecError, ArtifactFormat, ArtifactIdentity,
};
use super::{
    DirectNovaSessionError, ExpectedDirectNovaSuite, NovaVerifier, NovaVerifierKey,
    SelectedNovaVerifier,
};
use crate::nova_types::DirectNovaScalar;

const ZSTD_WINDOW_LOG: u32 = 23;
const MAX_COMPRESSED_PAYLOAD_LENGTH: usize = 2_000_000_000;
const MAX_DECODED_PAYLOAD_LENGTH: usize = 4_000_000_000;
const VERIFIER_ARTIFACT_FORMAT: ArtifactFormat = ArtifactFormat::new(
    *b"Purify/Nova/VK2\0",
    2,
    b"Purify/Accountable/DirectNovaVerifierArtifact/v2",
    ZSTD_WINDOW_LOG,
    MAX_COMPRESSED_PAYLOAD_LENGTH,
    MAX_DECODED_PAYLOAD_LENGTH,
);

/// The one artifact identity compiled into the selected library deployment.
///
/// It is deliberately separate from the semantic suite ID. Receipts never
/// supply this value, and a serialization-only change must replace it without
/// changing the proof statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedDirectNovaVerifierArtifact {
    identity: ArtifactIdentity,
}

impl ExpectedDirectNovaVerifierArtifact {
    pub(crate) const fn new(
        encoded_length: u64,
        decoded_payload_length: u64,
        digest: [u8; 32],
    ) -> Self {
        Self {
            identity: ArtifactIdentity::new(encoded_length, decoded_payload_length, digest),
        }
    }

    #[cfg(test)]
    pub(crate) const fn encoded_length(self) -> u64 {
        self.identity.encoded_length()
    }

    #[cfg(test)]
    pub(crate) const fn decoded_payload_length(self) -> u64 {
        self.identity.decoded_payload_length()
    }

    #[cfg(test)]
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.identity.digest()
    }

    #[cfg(test)]
    pub(crate) fn for_test_bytes(encoded: &[u8], decoded_payload_length: u64) -> Self {
        Self {
            identity: ArtifactIdentity::for_test_bytes(
                &VERIFIER_ARTIFACT_FORMAT,
                encoded,
                decoded_payload_length,
            ),
        }
    }

    const fn identity(self) -> ArtifactIdentity {
        self.identity
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
    #[cfg(any(test, feature = "prover"))]
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
    #[cfg(any(test, feature = "prover"))]
    #[error("direct Nova verifier artifact encoding failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("direct Nova verifier artifact decoding failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    Suite(#[from] DirectNovaSessionError),
}

impl From<ArtifactCodecError> for DirectNovaVerifierArtifactError {
    fn from(error: ArtifactCodecError) -> Self {
        match error {
            #[cfg(any(test, feature = "prover"))]
            ArtifactCodecError::DestinationNotEmpty => Self::DestinationNotEmpty,
            ArtifactCodecError::Length => Self::Length,
            ArtifactCodecError::Digest => Self::Digest,
            ArtifactCodecError::Header(context) => Self::Header(context),
            ArtifactCodecError::Io(error) => Self::Io(error),
            #[cfg(any(test, feature = "prover"))]
            ArtifactCodecError::Encode(error) => Self::Encode(error),
            ArtifactCodecError::Decode(error) => Self::Decode(error),
        }
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
        let identity = write_artifact_payload(
            destination,
            &VERIFIER_ARTIFACT_FORMAT,
            *self.expected.suite_id.bytes(),
            ARITY,
            &self.inner.verifier_key,
        )?;
        Ok(ExpectedDirectNovaVerifierArtifact { identity })
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
        let (metadata, proof_shape) = expected_suite.local_verifier_components::<ARITY>()?;
        let verifier_key: NovaVerifierKey<C> =
            read_artifact_payload::<NovaVerifierKey<C>, _, MAX_DECODED_PAYLOAD_LENGTH>(
                source,
                &VERIFIER_ARTIFACT_FORMAT,
                *expected_suite.suite_id.bytes(),
                ARITY,
                expected_artifact.identity(),
            )?;
        Ok(Self {
            expected: expected_suite,
            inner: NovaVerifier::from_loaded_key(verifier_key, proof_shape, metadata)?,
        })
    }
}
