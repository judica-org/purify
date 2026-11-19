//! Backend-independent candidate accumulation witnesses.

use crate::secp_native::{SecpEncodedPointWitness, SecpScalarWitness};
use crate::RelationError;

pub(crate) const MAX_CANDIDATE_CLAIMS: usize = 1024;
pub(crate) const MAX_CANDIDATE_ROUNDS: usize = 24;

/// One compact public coefficient term in a candidate pending claim.
///
/// It represents `scale * X^offset * product(1 + factor[j] *
/// X^(2^j))`. The candidate step fixes the term shape and treats only the
/// canonical scalar values as private witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidatePolynomialTermWitness {
    /// Canonical term scale modulo the secp256k1 group order.
    pub(crate) scale: SecpScalarWitness,
    /// Public monomial offset fixed by the claim shape.
    pub(crate) offset: usize,
    /// Canonical compact tensor factors.
    pub(crate) factors: Vec<SecpScalarWitness>,
}

/// One candidate accumulation input claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidatePendingClaimWitness {
    /// Exact native `PointBytes` claim point and its y opening.
    pub(crate) point: SecpEncodedPointWitness,
    /// One to three compact public coefficient terms.
    pub(crate) polynomial: Vec<CandidatePolynomialTermWitness>,
}

/// The logarithmic public IPA fields for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateStepProofWitness {
    /// Ordered left round points.
    pub(crate) left: Vec<SecpEncodedPointWitness>,
    /// Ordered right round points.
    pub(crate) right: Vec<SecpEncodedPointWitness>,
    /// Canonical terminal coefficient scalar.
    pub(crate) terminal_scalar: SecpScalarWitness,
    /// Exact folded-generator point returned as the next obligation.
    pub(crate) folded_generator: SecpEncodedPointWitness,
}

/// Public next-claim constants for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateRootClaim {
    /// Exact folded-generator point and its deterministic affine y opening.
    pub(crate) point: SecpEncodedPointWitness,
    /// Compact polynomial scale.
    pub(crate) scale: SecpScalarWitness,
    /// Compact polynomial factors in low-bit-first order.
    pub(crate) factors: Vec<SecpScalarWitness>,
}

pub(crate) fn validate_candidate_step_shape(
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
    root: Option<&CandidateRootClaim>,
) -> Result<(usize, usize), RelationError> {
    if claims.is_empty() || claims.len() > MAX_CANDIDATE_CLAIMS {
        return Err(RelationError::Malformed("candidate claim count"));
    }
    let rounds = proof.left.len();
    if rounds == 0
        || rounds > MAX_CANDIDATE_ROUNDS
        || proof.right.len() != rounds
        || root.is_some_and(|root| root.factors.len() != rounds)
    {
        return Err(RelationError::Malformed("candidate step rounds"));
    }
    let dimension = 1usize
        .checked_shl(rounds as u32)
        .ok_or(RelationError::Malformed("candidate step dimension"))?;
    for claim in claims {
        if claim.polynomial.is_empty() || claim.polynomial.len() > 3 {
            return Err(RelationError::Malformed("candidate polynomial terms"));
        }
        for term in &claim.polynomial {
            if term.factors.len() > rounds {
                return Err(RelationError::Malformed("candidate polynomial factors"));
            }
            let width = 1usize
                .checked_shl(term.factors.len() as u32)
                .ok_or(RelationError::Malformed("candidate polynomial width"))?;
            if term.offset > dimension.saturating_sub(width) {
                return Err(RelationError::Malformed("candidate polynomial degree"));
            }
        }
    }
    Ok((rounds, dimension))
}
