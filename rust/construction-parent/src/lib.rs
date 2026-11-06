//! Transparent recursive proofs for Purify construction receipts.
//!
//! The crate exports only the purpose-specific construction-parent verifier
//! through its private C ABI. C++ reconstructs and decides the authenticated
//! pending root before receipt acceptance.

use ff::PrimeField;
use nova_snark::{provider::Secq256k1Sha256Engine, traits::Engine};
use thiserror::Error;

#[cfg(test)]
mod candidate;
#[cfg(test)]
mod circuit_norm;
#[cfg(test)]
mod circuit_transcript;
mod construction_manifest;
mod construction_parent_input;
mod construction_profile;
#[cfg(test)]
mod construction_recurrence;
// This is an internal proof-codec foundation, not a receipt parser.
mod fixed_serde;
// This is an internal fixed-template integration layer, not a receipt API.
mod nova_session;
mod nova_types;
// Production candidate accumulation constraints for qualification.
#[cfg(test)]
mod nova_candidate;
// Production V4 transcript constraints for qualification.
#[cfg(test)]
mod nova_circuit_transcript;
// Production circuit-norm equations for qualification.
#[cfg(test)]
mod nova_circuit_norm_leaf;
// Production coefficient reduction constraints for qualification.
#[cfg(test)]
mod nova_norm_reduction;
// Transcript-derived opening-base constraints for qualification.
#[cfg(test)]
mod nova_opening_base;
// Production construction recurrence constraints for qualification.
#[cfg(test)]
mod nova_construction_recurrence;
// Shared typed transcript framing for direct Nova relations.
#[cfg(test)]
mod nova_protocol_transcript;
// Allocation-bounded identity for direct Nova step relations.
#[cfg(test)]
mod nova_relation_identity;
// Canonical secp256k1 scalar arithmetic for the direct Nova relation.
#[cfg(test)]
mod nova_secp_scalar;
// SHA-256 transcript constraints for the production relation.
#[cfg(test)]
mod nova_sha256_transcript;
// Canonical secp256k1 wrappers for the production relation.
#[cfg(test)]
mod nova_secp;
#[cfg(test)]
mod opening_generators;
mod secp_constants;
mod secp_native;
mod sha256_transcript;

pub(crate) type Scalar = <Secq256k1Sha256Engine as Engine>::Scalar;

pub(crate) fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(Scalar::from_repr(repr))
}

pub(crate) fn scalar_to_canonical(value: &Scalar) -> [u8; 32] {
    value
        .to_repr()
        .as_ref()
        .try_into()
        .expect("Secq256k1 scalar representation is 32 bytes")
}

/// Canonical relation or construction-proof failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub(crate) enum RelationError {
    /// A canonical relation, witness, or proof encoding was malformed.
    #[error("malformed relation encoding: {0}")]
    Malformed(&'static str),
}
