//! Backend-independent circuit-norm leaf inputs.
//!
//! These values describe one verifier-selected statement and its logarithmic
//! coefficient-reduction witness. Constraint backends consume them without
//! owning or reinterpreting their protocol meaning.

use crate::native::circuit_transcript::CircuitTranscriptShapeV4;
use crate::native::secp::{SecpEncodedPointWitness, SecpScalarWitness};

/// Varying public input for one production construction leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestBoundConstructionLeafStatementV4 {
    pub shape: CircuitTranscriptShapeV4,
    pub circuit_binding_digest: [u8; 32],
    pub raw_generator_digest: [u8; 32],
    pub basis_digest: [u8; 32],
}

/// The logarithmic public IPA fields for one coefficient reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateNormReductionProofWitness {
    pub coefficient_evaluation: SecpScalarWitness,
    pub left: Vec<SecpEncodedPointWitness>,
    pub right: Vec<SecpEncodedPointWitness>,
    pub terminal_scalar: SecpScalarWitness,
    pub folded_generator: SecpEncodedPointWitness,
}
