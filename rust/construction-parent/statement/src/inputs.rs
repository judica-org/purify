//! Canonical public inputs for the selected construction-parent verifier.
//!
//! This boundary accepts only fixed-width native values, checks that the
//! native accumulation profile is the one compiled into the recursive
//! relation, and constructs the typed manifest inputs consumed by proof
//! verification. It does not verify a proof or accept a receipt.

use thiserror::Error;

use crate::manifest::{ConstructionManifestLeaf, ConstructionManifestSeed};
use crate::profile::{
    CONSTRUCTION_PARENT_BASIS_DIGEST, CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
    CONSTRUCTION_STATE_ARITY,
};
use crate::{RelationError, Scalar};

pub const CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES: usize = 32 + 32 + 33 + 33;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConstructionParentInputError {
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
pub struct ConstructionParentInputs {
    initial_state: [Scalar; CONSTRUCTION_STATE_ARITY],
    expected_suffix: [Scalar; 2],
    step_count: usize,
}

/// The raw native values one construction-parent statement is parsed from.
#[derive(Clone, Copy)]
pub struct RawConstructionParentInputs<'a> {
    pub construction_statement_digest: [u8; 32],
    pub resolved_setup_record_digest: [u8; 32],
    pub recovery_root: [u8; 64],
    pub native_basis_digest: [u8; 32],
    pub native_raw_generator_digest: [u8; 32],
    pub setup_leaf_count: u32,
    pub anchor_leaf_count: u32,
    pub leaf_descriptors: &'a [u8],
}

impl ConstructionParentInputs {
    /// Parses and profile-checks one statement, keeping only what proof
    /// verification consumes.
    pub fn parse(
        raw: RawConstructionParentInputs<'_>,
    ) -> Result<Self, ConstructionParentInputError> {
        Self::parse_each_leaf(raw, |_| {}).map(|(inputs, _)| inputs)
    }

    /// Parses one statement and also returns its seed and ordered leaves.
    ///
    /// Provers bind their witness to these typed values. Verification never
    /// needs them and calls [`Self::parse`].
    pub fn parse_with_leaves(
        raw: RawConstructionParentInputs<'_>,
    ) -> Result<
        (
            Self,
            ConstructionManifestSeed,
            Vec<ConstructionManifestLeaf>,
        ),
        ConstructionParentInputError,
    > {
        let mut leaves = Vec::new();
        let (inputs, seed) = Self::parse_each_leaf(raw, |leaf| leaves.push(leaf))?;
        Ok((inputs, seed, leaves))
    }

    fn parse_each_leaf(
        raw: RawConstructionParentInputs<'_>,
        mut visit: impl FnMut(ConstructionManifestLeaf),
    ) -> Result<(Self, ConstructionManifestSeed), ConstructionParentInputError> {
        if raw.native_basis_digest != CONSTRUCTION_PARENT_BASIS_DIGEST {
            return Err(ConstructionParentInputError::BasisDigest);
        }
        if raw.native_raw_generator_digest != CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST {
            return Err(ConstructionParentInputError::RawGeneratorDigest);
        }

        let seed = ConstructionManifestSeed::new(
            raw.construction_statement_digest,
            raw.resolved_setup_record_digest,
            raw.recovery_root,
            raw.setup_leaf_count,
            raw.anchor_leaf_count,
        )?;
        let leaf_count = raw
            .setup_leaf_count
            .checked_add(raw.anchor_leaf_count)
            .ok_or(ConstructionParentInputError::DescriptorCount)?;
        let leaf_count_usize = usize::try_from(leaf_count)
            .map_err(|_| ConstructionParentInputError::DescriptorCount)?;
        let expected_size = leaf_count_usize
            .checked_mul(CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES)
            .ok_or(ConstructionParentInputError::DescriptorCount)?;
        if raw.leaf_descriptors.len() != expected_size {
            return Err(ConstructionParentInputError::DescriptorSize {
                expected: expected_size,
                actual: raw.leaf_descriptors.len(),
            });
        }

        let (initial_state, mut expected_final) = seed.initial_state_and_manifest()?;
        let (descriptors, remainder) = raw
            .leaf_descriptors
            .as_chunks::<CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES>();
        debug_assert!(remainder.is_empty());
        for descriptor in descriptors {
            let leaf = parse_leaf_descriptor(descriptor)?;
            expected_final = expected_final.advance(leaf)?;
            visit(leaf);
        }
        let expected_suffix = expected_final.state_suffix_fields()?;
        Ok((
            Self {
                initial_state,
                expected_suffix,
                step_count: leaf_count_usize,
            },
            seed,
        ))
    }

    pub fn initial_state(&self) -> &[Scalar; CONSTRUCTION_STATE_ARITY] {
        &self.initial_state
    }

    pub fn expected_suffix(&self) -> [Scalar; 2] {
        self.expected_suffix
    }

    pub fn step_count(&self) -> usize {
        self.step_count
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
