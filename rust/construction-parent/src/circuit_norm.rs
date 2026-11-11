//! Backend-independent circuit-norm leaf inputs.
//!
//! These values describe one verifier-selected statement and its logarithmic
//! coefficient-reduction witness. Constraint backends consume them without
//! owning or reinterpreting their protocol meaning.

use crate::circuit_transcript::CircuitTranscriptShapeV4;
use crate::secp_native::{SecpEncodedPointWitness, SecpScalarWitness};

/// Varying public input for one production public-anchor leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestBoundAnchorLeafStatementV4 {
    pub(crate) shape: CircuitTranscriptShapeV4,
    pub(crate) circuit_binding_digest: [u8; 32],
    pub(crate) raw_generator_digest: [u8; 32],
    pub(crate) basis_digest: [u8; 32],
}

/// The logarithmic public IPA fields for one coefficient reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateNormReductionProofWitness {
    pub(crate) coefficient_evaluation: SecpScalarWitness,
    pub(crate) left: Vec<SecpEncodedPointWitness>,
    pub(crate) right: Vec<SecpEncodedPointWitness>,
    pub(crate) terminal_scalar: SecpScalarWitness,
    pub(crate) folded_generator: SecpEncodedPointWitness,
}
