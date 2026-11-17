//! Backend-independent candidate accumulation witnesses.

use crate::native::secp::{SecpEncodedPointWitness, SecpScalarWitness};
use crate::profile::CONSTRUCTION_ROOT_ROUNDS;
use statement::manifest::ConstructionRoot;

pub(crate) const MAX_CANDIDATE_CLAIMS: usize = 1024;
pub(crate) const MAX_CANDIDATE_ROUNDS: usize = 24;

/// The logarithmic public IPA fields for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateStepProofWitness {
    /// Ordered left round points.
    pub left: Vec<SecpEncodedPointWitness>,
    /// Ordered right round points.
    pub right: Vec<SecpEncodedPointWitness>,
    /// Canonical terminal coefficient scalar.
    pub terminal_scalar: SecpScalarWitness,
    /// Exact folded-generator point returned as the next obligation.
    pub folded_generator: SecpEncodedPointWitness,
}

/// Public next-claim constants for one candidate accumulation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRootClaim {
    /// Exact folded-generator point and its deterministic affine y opening.
    pub point: SecpEncodedPointWitness,
    /// Compact polynomial scale.
    pub scale: SecpScalarWitness,
    /// Compact polynomial factors in low-bit-first order.
    pub factors: Vec<SecpScalarWitness>,
}

impl CandidateRootClaim {
    /// Opens one canonical construction root as its native claim witness.
    pub fn from_root(root: &ConstructionRoot) -> Self {
        let encoded = root.canonical_bytes();
        let point =
            SecpEncodedPointWitness::parse(encoded[..33].try_into().expect("fixed point slice"))
                .expect("parsed construction root point remains canonical");
        let scale = SecpScalarWitness::from_bytes_be(
            encoded[33..65].try_into().expect("fixed root scale slice"),
        );
        let factors = (0..CONSTRUCTION_ROOT_ROUNDS)
            .map(|index| {
                let offset = 65 + 32 * index;
                SecpScalarWitness::from_bytes_be(
                    encoded[offset..offset + 32]
                        .try_into()
                        .expect("fixed root factor slice"),
                )
            })
            .collect();
        Self {
            point,
            scale,
            factors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::secp::standard_generator;
    use crate::profile::CONSTRUCTION_ROOT_BYTES;

    fn root_bytes(prefix: u8) -> [u8; CONSTRUCTION_ROOT_BYTES] {
        let generator = SecpEncodedPointWitness::from_point_value(standard_generator());
        let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
        encoded[..33].copy_from_slice(&generator.encoded);
        encoded[0] = prefix;
        encoded[64] = 1;
        for index in 0..CONSTRUCTION_ROOT_ROUNDS {
            encoded[65 + 32 * index + 31] = u8::try_from(index + 2).expect("small factor");
        }
        encoded
    }

    #[test]
    fn root_claim_opens_the_canonical_root_encoding() {
        let generator = SecpEncodedPointWitness::from_point_value(standard_generator());
        assert_eq!(generator.encoded[0], 2);
        let root = ConstructionRoot::parse(&root_bytes(2)).expect("root claim");
        let claim = CandidateRootClaim::from_root(&root);
        assert_eq!(claim.point, generator);
        assert_eq!(claim.scale, SecpScalarWitness::from_u64(1));
        assert_eq!(claim.factors.len(), CONSTRUCTION_ROOT_ROUNDS);
        for (index, factor) in claim.factors.iter().enumerate() {
            assert_eq!(*factor, SecpScalarWitness::from_u64(index as u64 + 2));
        }

        let odd = ConstructionRoot::parse(&root_bytes(3)).expect("odd root point");
        let odd_claim = CandidateRootClaim::from_root(&odd);
        assert_eq!(odd_claim.point.encoded[1..], generator.encoded[1..]);
        assert_eq!(odd_claim.point.y[0] & 1, 1);
    }
}
