//! Constraint building blocks over secp256k1 and SHA-256.

use nova_snark::frontend::SynthesisError;

pub mod ops;
pub mod point;
pub mod scalar;
pub mod sha256;
pub mod transcript;

/// Reports a relation shape or witness that cannot be synthesized.
pub(crate) fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}
