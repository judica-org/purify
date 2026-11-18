//! Transparent recursive proofs for Purify construction receipts.
//!
//! By default the crate exports only the purpose-specific construction-parent
//! verifier through its private C ABI. C++ reconstructs and decides the
//! authenticated pending root before receipt acceptance. The opt-in `prover`
//! feature additionally exposes purpose-specific checked inputs through
//! [`prover`] and [`certificate_parent_prover`].

use ff::PrimeField;
use nova_snark::{provider::Secq256k1Sha256Engine, traits::Engine};
use thiserror::Error;

mod artifact_snapshot;
#[cfg(any(test, feature = "prover"))]
mod candidate;
#[cfg(any(test, feature = "prover"))]
mod certificate_authorization;
#[cfg(any(test, feature = "prover"))]
mod certificate_joined_witness;
#[cfg(any(test, feature = "prover"))]
mod certificate_member_leaf;
#[cfg(any(test, feature = "prover"))]
mod certificate_native_witness;
#[cfg(any(test, feature = "prover"))]
mod certificate_nonce_proof;
mod certificate_parent_input;
// This private ABI returns only a proof-authenticated pending root. The C++
// acceptance boundary must parse and decide that root before exposing success.
mod certificate_parent_ffi;
#[cfg(any(test, feature = "prover"))]
pub mod certificate_parent_prover;
#[cfg(any(test, feature = "prover"))]
mod certificate_parent_prover_binding;
#[cfg(test)]
mod certificate_parent_qualification;
// This authenticates a pending certificate root. Native decide remains
// mandatory before certificate acceptance.
mod certificate_parent_verifier;
mod certificate_profile;
#[cfg(any(test, feature = "prover"))]
mod certificate_recurrence;
mod certificate_recursive_manifest;
#[cfg(any(test, feature = "prover"))]
mod certificate_response_relation;
mod certificate_root;
#[cfg(any(test, feature = "prover"))]
mod circuit_norm;
#[cfg(any(test, feature = "prover"))]
mod circuit_transcript;
mod construction_manifest;
mod construction_parent_input;
#[cfg(any(test, feature = "prover"))]
mod construction_parent_prover_binding;
#[cfg(any(test, feature = "prover"))]
mod construction_parent_prover_fixture;
#[cfg(test)]
mod construction_parent_qualification;
mod construction_profile;
#[cfg(any(test, feature = "prover"))]
mod construction_recurrence;
// This private ABI returns only a proof-authenticated pending root. The C++
// acceptance boundary must parse and decide that root before exposing success.
mod construction_parent_ffi;
// This authenticates a pending construction root. Native decide remains
// mandatory before receipt acceptance.
mod construction_parent_verifier;
// This is an internal proof-codec foundation, not a receipt parser.
mod fixed_serde;
// This is an internal fixed-template integration layer, not a receipt API.
mod nova_session;
mod nova_types;
// Production candidate accumulation constraints for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_candidate;
#[cfg(any(test, feature = "prover"))]
mod nova_candidate_state;
#[cfg(any(test, feature = "prover"))]
mod nova_certificate_recurrence;
// Exact accountable-signature hashes for certificate recurrence steps.
#[cfg(any(test, feature = "prover"))]
mod nova_accountable_hash;
// Production V4 transcript constraints for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_circuit_transcript;
// Production circuit-norm equations for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_circuit_norm_leaf;
// Production coefficient reduction constraints for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_norm_reduction;
// Transcript-derived opening-base constraints for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_opening_base;
// Production construction recurrence constraints for qualification.
#[cfg(any(test, feature = "prover"))]
mod nova_construction_recurrence;
// Shared typed transcript framing for direct Nova relations.
#[cfg(any(test, feature = "prover"))]
mod nova_protocol_transcript;
// Allocation-bounded identity for direct Nova step relations.
#[cfg(any(test, feature = "prover"))]
mod nova_relation_identity;
// Canonical secp256k1 scalar arithmetic for the direct Nova relation.
#[cfg(any(test, feature = "prover"))]
mod nova_secp_scalar;
// SHA-256 transcript constraints for the production relation.
#[cfg(any(test, feature = "prover"))]
mod nova_sha256_transcript;
// Canonical secp256k1 wrappers for the production relation.
#[cfg(any(test, feature = "prover"))]
mod nova_secp;
#[cfg(any(test, feature = "prover"))]
mod opening_generators;
#[cfg(any(test, feature = "prover"))]
pub mod prover;
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
