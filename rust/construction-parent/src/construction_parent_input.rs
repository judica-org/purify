//! Canonical public inputs for the selected construction-parent verifier.
//!
//! This boundary accepts only fixed-width native values, checks that the
//! native accumulation profile is the one compiled into the recursive
//! relation, and constructs the typed manifest inputs consumed by proof
//! verification. It does not verify a proof or accept a receipt.

use thiserror::Error;

use crate::construction_manifest::{ConstructionManifestLeaf, ConstructionManifestSeed};
use crate::construction_profile::{
    CONSTRUCTION_PARENT_BASIS_DIGEST, CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
    CONSTRUCTION_STATE_ARITY,
};
use crate::{RelationError, Scalar};

pub(crate) const CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES: usize = 32 + 32 + 33 + 33;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum ConstructionParentInputError {
    #[error(transparent)]
    State(#[from] RelationError),
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
    initial_state: [Scalar; CONSTRUCTION_STATE_ARITY],
    expected_suffix: [Scalar; 2],
    step_count: usize,
    #[cfg(test)]
    seed: ConstructionManifestSeed,
    #[cfg(test)]
    leaves: Vec<ConstructionManifestLeaf>,
}

impl ConstructionParentInputs {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse(
        construction_statement_digest: [u8; 32],
        resolved_setup_record_digest: [u8; 32],
        recovery_root: [u8; 64],
        native_basis_digest: [u8; 32],
        native_raw_generator_digest: [u8; 32],
        setup_leaf_count: u32,
        anchor_leaf_count: u32,
        leaf_descriptors: &[u8],
    ) -> Result<Self, ConstructionParentInputError> {
        if native_basis_digest != CONSTRUCTION_PARENT_BASIS_DIGEST {
            return Err(ConstructionParentInputError::BasisDigest);
        }
        if native_raw_generator_digest != CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST {
            return Err(ConstructionParentInputError::RawGeneratorDigest);
        }

        let seed = ConstructionManifestSeed::new(
            construction_statement_digest,
            resolved_setup_record_digest,
            recovery_root,
            setup_leaf_count,
            anchor_leaf_count,
        )?;
        let leaf_count = setup_leaf_count
            .checked_add(anchor_leaf_count)
            .ok_or(ConstructionParentInputError::DescriptorCount)?;
        let leaf_count_usize = usize::try_from(leaf_count)
            .map_err(|_| ConstructionParentInputError::DescriptorCount)?;
        let expected_size = leaf_count_usize
            .checked_mul(CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES)
            .ok_or(ConstructionParentInputError::DescriptorCount)?;
        if leaf_descriptors.len() != expected_size {
            return Err(ConstructionParentInputError::DescriptorSize {
                expected: expected_size,
                actual: leaf_descriptors.len(),
            });
        }

        let (initial_state, mut expected_final) = seed.initial_state_and_manifest()?;
        let (descriptors, remainder) =
            leaf_descriptors.as_chunks::<CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES>();
        debug_assert!(remainder.is_empty());
        #[cfg(test)]
        let mut leaves = Vec::with_capacity(leaf_count_usize);
        for descriptor in descriptors {
            let leaf = parse_leaf_descriptor(descriptor)?;
            expected_final = expected_final.advance(leaf)?;
            #[cfg(test)]
            leaves.push(leaf);
        }
        let expected_suffix = expected_final.state_suffix_fields()?;
        Ok(Self {
            initial_state,
            expected_suffix,
            step_count: leaf_count_usize,
            #[cfg(test)]
            seed,
            #[cfg(test)]
            leaves,
        })
    }

    pub(crate) fn initial_state(&self) -> &[Scalar; CONSTRUCTION_STATE_ARITY] {
        &self.initial_state
    }

    pub(crate) fn expected_suffix(&self) -> [Scalar; 2] {
        self.expected_suffix
    }

    pub(crate) fn step_count(&self) -> usize {
        self.step_count
    }

    #[cfg(test)]
    pub(crate) fn seed(&self) -> &ConstructionManifestSeed {
        &self.seed
    }

    #[cfg(test)]
    pub(crate) fn leaves(&self) -> &[ConstructionManifestLeaf] {
        &self.leaves
    }
}

fn parse_leaf_descriptor(
    descriptor: &[u8; CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES],
) -> Result<ConstructionManifestLeaf, RelationError> {
    let binding_digest = descriptor[..32]
        .try_into()
        .expect("fixed construction binding digest");
    let precommitment = descriptor[32..64]
        .try_into()
        .expect("fixed construction precommitment");
    let coefficient_commitment = descriptor[64..97]
        .try_into()
        .expect("fixed coefficient commitment");
    let anchored_offset = descriptor[97..130]
        .try_into()
        .expect("fixed anchored offset");
    ConstructionManifestLeaf::new(
        binding_digest,
        precommitment,
        coefficient_commitment,
        anchored_offset,
    )
}

#[cfg(test)]
mod tests;
