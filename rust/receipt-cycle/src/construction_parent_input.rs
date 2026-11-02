//! Canonical public inputs for the selected construction-parent verifier.
//!
//! This boundary accepts only fixed-width native values, checks that the
//! native accumulation profile is the one compiled into the recursive
//! relation, and constructs the typed manifest inputs consumed by proof
//! verification. It does not verify a proof or accept a receipt.

use thiserror::Error;

use crate::anchor_recurrence::{
    CONSTRUCTION_PARENT_BASIS_DIGEST, CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
};
use crate::construction_manifest::{
    ConstructionManifestAnchor, ConstructionManifestSeed, ConstructionRoot,
};
use crate::parent_relation::SecpEncodedPointWitness;
use crate::secp_scalar::SecpScalarWitness;
use crate::ReceiptCycleError;

pub(crate) const CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES: usize = 32 + 32 + 33 + 33;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum ConstructionParentInputError {
    #[error(transparent)]
    State(#[from] ReceiptCycleError),
    #[error("construction parent native basis digest mismatch")]
    BasisDigest,
    #[error("construction parent raw-generator digest mismatch")]
    RawGeneratorDigest,
    #[error("construction parent descriptor size mismatch: expected {expected}, actual {actual}")]
    DescriptorSize { expected: usize, actual: usize },
    #[error("construction parent descriptor count overflow")]
    DescriptorCount,
}

/// Typed, profile-checked public inputs for one recursive construction proof.
pub(crate) struct ConstructionParentInputs {
    seed: ConstructionManifestSeed,
    anchors: Vec<ConstructionManifestAnchor>,
}

impl ConstructionParentInputs {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse(
        construction_statement_digest: [u8; 32],
        resolved_setup_record_digest: [u8; 32],
        canonical_seed_root: &[u8],
        native_basis_digest: [u8; 32],
        native_raw_generator_digest: [u8; 32],
        anchor_count: u32,
        anchor_descriptors: &[u8],
    ) -> Result<Self, ConstructionParentInputError> {
        if native_basis_digest != CONSTRUCTION_PARENT_BASIS_DIGEST {
            return Err(ConstructionParentInputError::BasisDigest);
        }
        if native_raw_generator_digest != CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST {
            return Err(ConstructionParentInputError::RawGeneratorDigest);
        }

        let anchor_count = usize::try_from(anchor_count)
            .map_err(|_| ConstructionParentInputError::DescriptorCount)?;
        let expected_size = anchor_count
            .checked_mul(CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES)
            .ok_or(ConstructionParentInputError::DescriptorCount)?;
        if anchor_descriptors.len() != expected_size {
            return Err(ConstructionParentInputError::DescriptorSize {
                expected: expected_size,
                actual: anchor_descriptors.len(),
            });
        }

        let root = ConstructionRoot::parse(canonical_seed_root)?;
        let seed = ConstructionManifestSeed::new(
            construction_statement_digest,
            resolved_setup_record_digest,
            root,
            u64::try_from(anchor_count).expect("u32 anchor count fits u64"),
        )?;
        let (descriptors, remainder) =
            anchor_descriptors.as_chunks::<CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES>();
        debug_assert!(remainder.is_empty());
        let anchors = descriptors
            .iter()
            .map(parse_anchor_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { seed, anchors })
    }

    pub(crate) fn seed(&self) -> &ConstructionManifestSeed {
        &self.seed
    }

    pub(crate) fn anchors(&self) -> &[ConstructionManifestAnchor] {
        &self.anchors
    }
}

fn parse_anchor_descriptor(
    descriptor: &[u8; CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES],
) -> Result<ConstructionManifestAnchor, ReceiptCycleError> {
    let binding_digest = descriptor[..32]
        .try_into()
        .expect("fixed construction binding digest");
    let precommitment = SecpScalarWitness::from_bytes_be(
        descriptor[32..64]
            .try_into()
            .expect("fixed construction precommitment"),
    );
    let coefficient_commitment = SecpEncodedPointWitness::parse(
        descriptor[64..97]
            .try_into()
            .expect("fixed coefficient commitment"),
    )?;
    let anchored_offset = SecpEncodedPointWitness::parse(
        descriptor[97..130]
            .try_into()
            .expect("fixed anchored offset"),
    )?;
    ConstructionManifestAnchor::new(
        binding_digest,
        precommitment,
        coefficient_commitment,
        anchored_offset,
    )
}

#[cfg(test)]
mod tests;
