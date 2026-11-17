//! Proof-suite identity and engine types shared by proving and verification.

use nova_snark::provider::{Secp256k1Sha256Engine, Secq256k1Sha256Engine};

#[cfg(any(test, feature = "prover"))]
use crate::Scalar;

/// Canonical encoding of an ordered direct [`StepCircuit`] relation.
///
/// This version is part of both the streamed relation ID and the complete
/// Nova suite ID.
pub(crate) const DIRECT_STEP_RELATION_ENCODING_VERSION: u8 = 1;

pub(crate) type DirectNovaPrimaryEngine = Secq256k1Sha256Engine;
pub(crate) type DirectNovaSecondaryEngine = Secp256k1Sha256Engine;
#[cfg(any(test, feature = "prover"))]
pub(crate) type DirectNovaScalar = Scalar;

#[cfg(any(test, feature = "prover"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectRelationId([u8; 32]);

#[cfg(any(test, feature = "prover"))]
impl DirectRelationId {
    /// This identifies only the ordered direct step relation. The qualified
    /// suite ID additionally binds Nova, both engines, public parameters,
    /// compression, and the canonical proof codec.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstructs an ID only from a locally frozen suite profile.
    pub(crate) const fn from_frozen_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
