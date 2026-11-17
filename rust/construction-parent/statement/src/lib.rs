//! Native public statement of one construction-parent proof.
//!
//! This crate holds what a verifier needs to turn fixed-width native values
//! into the public inputs of the recursive proof: the frozen profile,
//! canonical secp256k1 encodings, the typed SHA-256 transcript, the ordered
//! manifest, and public-input parsing. Nothing here verifies a proof, and
//! nothing here can prove one.

#![forbid(unsafe_code)]

use ff::PrimeField;
use nova_snark::provider::{Secp256k1Sha256Engine, Secq256k1Sha256Engine};
use nova_snark::traits::Engine;
use thiserror::Error;

pub mod inputs;
pub mod manifest;
pub mod profile;
pub mod secp;
pub mod transcript;

pub type PrimaryEngine = Secq256k1Sha256Engine;
pub type SecondaryEngine = Secp256k1Sha256Engine;

/// The field every recursive state element and step constraint lives in.
pub type Scalar = <PrimaryEngine as Engine>::Scalar;

/// Canonical encoding of an ordered direct step relation.
///
/// This version is part of both the streamed relation ID and the complete
/// Nova suite ID.
pub const STEP_RELATION_ENCODING_VERSION: u8 = 1;

pub fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Option::from(Scalar::from_repr(repr))
}

pub fn scalar_to_canonical(value: &Scalar) -> [u8; 32] {
    value
        .to_repr()
        .as_ref()
        .try_into()
        .expect("Secq256k1 scalar representation is 32 bytes")
}

/// Canonical relation or construction-proof failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RelationError {
    /// A canonical relation, witness, or proof encoding was malformed.
    #[error("malformed relation encoding: {0}")]
    Malformed(&'static str),
}
