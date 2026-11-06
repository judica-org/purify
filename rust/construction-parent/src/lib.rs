//! Transparent recursive proofs for Purify construction receipts.
//!
//! The crate exports only the purpose-specific construction-parent verifier
//! through its private C ABI. C++ reconstructs and decides the authenticated
//! pending root before receipt acceptance.

use ff::PrimeField;
use nova_snark::{provider::Secq256k1Sha256Engine, traits::Engine};
use thiserror::Error;

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
