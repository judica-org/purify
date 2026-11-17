//! Verifier-derived state and ordered manifest for the construction recurrence.
//!
//! This module derives only the public state expected by the selected
//! homogeneous relation. It does not verify a recursive proof, decide an
//! accumulation root, or expose an acceptance result. In particular, the
//! final root remains part of the recursive proof's authenticated output and
//! is not serialized alongside it.

use ff::Field;

#[cfg(any(test, feature = "prover"))]
use crate::candidate::CandidateRootClaim;
use crate::construction_profile::{
    CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS, CONSTRUCTION_ROOT_STATE_ARITY,
    CONSTRUCTION_STATE_ARITY,
};
#[cfg(test)]
use crate::construction_recurrence::ConstructionRecurrenceStateWitness;
#[cfg(any(test, feature = "prover"))]
use crate::secp_native::SecpEncodedPointWitness;
use crate::secp_native::{
    canonical_encoded_point_value, canonical_scalar_value, coordinate_field_value,
    SecpScalarWitness,
};
use crate::sha256_transcript::NativeTranscript;
use crate::{scalar_to_canonical, RelationError, Scalar};

const CONSTRUCTION_RELATION_VERSION: u64 = 3;
const CONSTRUCTION_INITIAL_MANIFEST_DOMAIN: &[u8] =
    b"Purify/Accountable/ConstructionParentManifest/v3/init";
pub(crate) const CONSTRUCTION_STEP_MANIFEST_DOMAIN: &[u8] =
    b"Purify/Accountable/ConstructionParentManifest/v3/leaf";

/// Canonical pending root for the fixed 32,768-point construction basis.
///
/// This type establishes only the exact one-term encoding shared by the
/// canonical initial claim and proof-authenticated final state. Parsing or constructing
/// one does not verify or decide the represented accumulation obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionRoot {
    encoded: [u8; CONSTRUCTION_ROOT_BYTES],
    state_fields: [Scalar; CONSTRUCTION_ROOT_STATE_ARITY],
}

impl ConstructionRoot {
    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, RelationError> {
        let encoded: [u8; CONSTRUCTION_ROOT_BYTES] = encoded
            .try_into()
            .map_err(|_| RelationError::Malformed("construction root size"))?;
        let point_encoding = encoded[..33].try_into().expect("fixed point slice");
        let point = canonical_encoded_point_value(point_encoding)?;
        let scale = parse_root_scalar(encoded[33..65].try_into().expect("fixed root scale slice"))?;
        let mut state_fields = [Scalar::ZERO; CONSTRUCTION_ROOT_STATE_ARITY];
        state_fields[0] = Scalar::from(u64::from(point_encoding[0]));
        state_fields[1] = point.x;
        state_fields[2] = scale;
        for index in 0..CONSTRUCTION_ROOT_ROUNDS {
            let offset = 65 + 32 * index;
            state_fields[3 + index] = parse_root_scalar(
                encoded[offset..offset + 32]
                    .try_into()
                    .expect("fixed root factor slice"),
            )?;
        }
        Ok(Self {
            encoded,
            state_fields,
        })
    }

    /// Reconstructs the unique root encoding from authenticated state fields.
    pub(crate) fn from_state_fields(
        fields: [Scalar; CONSTRUCTION_ROOT_STATE_ARITY],
    ) -> Result<Self, RelationError> {
        let prefix = if fields[0] == Scalar::ZERO {
            0
        } else if fields[0] == Scalar::from(2) {
            2
        } else if fields[0] == Scalar::from(3) {
            3
        } else {
            return Err(RelationError::Malformed("construction root point prefix"));
        };

        let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
        if prefix == 0 {
            if fields[1] != Scalar::ZERO {
                return Err(RelationError::Malformed("construction root identity point"));
            }
        } else {
            encoded[0] = prefix;
            encoded[1..33].copy_from_slice(&field_to_be(fields[1]));
        }
        encoded[33..65].copy_from_slice(&field_to_be(fields[2]));
        for (index, field) in fields[3..].iter().enumerate() {
            let offset = 65 + 32 * index;
            encoded[offset..offset + 32].copy_from_slice(&field_to_be(*field));
        }
        Self::parse(&encoded)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8; CONSTRUCTION_ROOT_BYTES] {
        &self.encoded
    }

    #[cfg(any(test, feature = "prover"))]
    pub(crate) fn claim(&self) -> CandidateRootClaim {
        let point = SecpEncodedPointWitness::parse(
            self.encoded[..33].try_into().expect("fixed point slice"),
        )
        .expect("parsed construction root point remains canonical");
        let scale = SecpScalarWitness::from_bytes_be(
            self.encoded[33..65]
                .try_into()
                .expect("fixed root scale slice"),
        );
        let factors = (0..CONSTRUCTION_ROOT_ROUNDS)
            .map(|index| {
                let offset = 65 + 32 * index;
                SecpScalarWitness::from_bytes_be(
                    self.encoded[offset..offset + 32]
                        .try_into()
                        .expect("fixed root factor slice"),
                )
            })
            .collect();
        CandidateRootClaim {
            point,
            scale,
            factors,
        }
    }

    /// Converts this root into the recurrence's exact public-state prefix.
    pub(crate) fn state_fields(&self) -> [Scalar; CONSTRUCTION_ROOT_STATE_ARITY] {
        self.state_fields
    }
}

/// Immutable public inputs from which the verifier derives recurrence z0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestSeed {
    construction_statement_digest: [u8; 32],
    resolved_setup_record_digest: [u8; 32],
    recovery_root: [u8; 64],
    root: ConstructionRoot,
    setup_leaf_count: u32,
    anchor_leaf_count: u32,
}

impl ConstructionManifestSeed {
    pub(crate) fn new(
        construction_statement_digest: [u8; 32],
        resolved_setup_record_digest: [u8; 32],
        recovery_root: [u8; 64],
        setup_leaf_count: u32,
        anchor_leaf_count: u32,
    ) -> Result<Self, RelationError> {
        if resolved_setup_record_digest == [0; 32] {
            return Err(RelationError::Malformed(
                "unresolved construction setup record",
            ));
        }
        if recovery_root == [0; 64] {
            return Err(RelationError::Malformed("empty recovery root"));
        }
        if setup_leaf_count == 0 || anchor_leaf_count == 0 {
            return Err(RelationError::Malformed("empty construction phase"));
        }
        setup_leaf_count
            .checked_add(anchor_leaf_count)
            .ok_or(RelationError::Malformed("construction leaf count"))?;
        let root = ConstructionRoot::parse(&[0; CONSTRUCTION_ROOT_BYTES])?;
        Ok(Self {
            construction_statement_digest,
            resolved_setup_record_digest,
            recovery_root,
            root,
            setup_leaf_count,
            anchor_leaf_count,
        })
    }

    fn initial_manifest(&self) -> Result<[u8; 32], RelationError> {
        let mut transcript = NativeTranscript::new();
        transcript
            .append_bytes(CONSTRUCTION_INITIAL_MANIFEST_DOMAIN)
            .expect("fixed manifest domain length fits u64");
        transcript.append_u64(CONSTRUCTION_RELATION_VERSION);
        transcript
            .append_bytes(&self.construction_statement_digest)
            .expect("fixed statement digest length fits u64");
        transcript
            .append_bytes(&self.resolved_setup_record_digest)
            .expect("fixed setup digest length fits u64");
        transcript
            .append_bytes(&self.recovery_root)
            .expect("fixed recovery root length fits u64");
        transcript.append_u64(u64::from(self.setup_leaf_count));
        transcript.append_u64(u64::from(self.anchor_leaf_count));
        Ok(field_to_be(transcript.challenge(0)?.scalar))
    }

    /// Derives the recursive input and matching native manifest state once.
    pub(crate) fn initial_state_and_manifest(
        &self,
    ) -> Result<
        (
            [Scalar; CONSTRUCTION_STATE_ARITY],
            ConstructionManifestState,
        ),
        RelationError,
    > {
        let manifest = self.initial_manifest()?;
        let root = self.root.state_fields();
        let mut state = [Scalar::ZERO; CONSTRUCTION_STATE_ARITY];
        state[..CONSTRUCTION_ROOT_STATE_ARITY].copy_from_slice(&root);
        state[CONSTRUCTION_ROOT_STATE_ARITY] = coordinate_field_value(manifest)?;
        state[CONSTRUCTION_ROOT_STATE_ARITY + 1] = Scalar::ZERO;
        Ok((state, ConstructionManifestState { manifest, index: 0 }))
    }

    /// Returns the only valid initial witness for this verifier-derived seed.
    #[cfg(test)]
    pub(crate) fn initial_recurrence_witness(
        &self,
    ) -> Result<ConstructionRecurrenceStateWitness, RelationError> {
        Ok(ConstructionRecurrenceStateWitness {
            root: self.root.claim(),
            manifest: self.initial_manifest()?,
            index: 0,
        })
    }

    /// Returns the fixed 20-field initial state consumed by recursion.
    #[cfg(test)]
    pub(crate) fn initial_state_fields(
        &self,
    ) -> Result<[Scalar; CONSTRUCTION_STATE_ARITY], RelationError> {
        Ok(self.initial_state_and_manifest()?.0)
    }

    /// Derives the manifest and index expected after the exact ordered payload.
    #[cfg(test)]
    pub(crate) fn derive_expected_final(
        &self,
        leaves: &[ConstructionManifestLeaf],
    ) -> Result<ConstructionManifestState, RelationError> {
        let count = u32::try_from(leaves.len())
            .map_err(|_| RelationError::Malformed("construction leaf count"))?;
        let expected_count = self
            .setup_leaf_count
            .checked_add(self.anchor_leaf_count)
            .ok_or(RelationError::Malformed("construction leaf count"))?;
        if count != expected_count {
            return Err(RelationError::Malformed("construction manifest leaf count"));
        }
        let (_, mut state) = self.initial_state_and_manifest()?;
        for leaf in leaves {
            state = state.advance(*leaf)?;
        }
        Ok(state)
    }
}

/// Verifier-resolved public values bound by one homogeneous construction leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestLeaf {
    binding_digest: [u8; 32],
    precommitment: [u8; 32],
    coefficient_commitment: [u8; 33],
    anchored_offset: [u8; 33],
}

impl ConstructionManifestLeaf {
    pub(crate) fn new(
        binding_digest: [u8; 32],
        precommitment: [u8; 32],
        coefficient_commitment: [u8; 33],
        anchored_offset: [u8; 33],
    ) -> Result<Self, RelationError> {
        if canonical_scalar_value(SecpScalarWitness::from_bytes_be(precommitment))? == Scalar::ZERO
        {
            return Err(RelationError::Malformed("zero construction precommitment"));
        }
        canonical_encoded_point_value(coefficient_commitment)?;
        canonical_encoded_point_value(anchored_offset)?;
        Ok(Self {
            binding_digest,
            precommitment,
            coefficient_commitment,
            anchored_offset,
        })
    }
}

/// Exact native inputs absorbed by one constrained manifest transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestStepInput {
    prior_manifest: [u8; 32],
    zero_based_index: u32,
    binding_digest: [u8; 32],
    precommitment: [u8; 32],
    coefficient_commitment: [u8; 33],
    anchored_offset: [u8; 33],
}

impl ConstructionManifestStepInput {
    pub(crate) fn new(
        prior_manifest: [u8; 32],
        zero_based_index: u32,
        leaf: ConstructionManifestLeaf,
    ) -> Result<Self, RelationError> {
        coordinate_field_value(prior_manifest)?;
        Ok(Self {
            prior_manifest,
            zero_based_index,
            binding_digest: leaf.binding_digest,
            precommitment: leaf.precommitment,
            coefficient_commitment: leaf.coefficient_commitment,
            anchored_offset: leaf.anchored_offset,
        })
    }
}

/// Expected non-root portion of one authenticated recurrence state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestState {
    manifest: [u8; 32],
    index: u32,
}

impl ConstructionManifestState {
    #[cfg(test)]
    pub(crate) fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    #[cfg(test)]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// Returns the manifest and index fields expected at the end of recursion.
    pub(crate) fn state_suffix_fields(&self) -> Result<[Scalar; 2], RelationError> {
        Ok([
            coordinate_field_value(self.manifest)?,
            Scalar::from(u64::from(self.index)),
        ])
    }

    pub(crate) fn advance(self, leaf: ConstructionManifestLeaf) -> Result<Self, RelationError> {
        let next_index = self
            .index
            .checked_add(1)
            .ok_or(RelationError::Malformed("construction manifest index"))?;
        let input = ConstructionManifestStepInput::new(self.manifest, self.index, leaf)?;
        Ok(Self {
            manifest: derive_step_manifest(&input)?,
            index: next_index,
        })
    }
}

/// Replays the native transcript constrained by one recurrence step.
pub(crate) fn derive_step_manifest(
    input: &ConstructionManifestStepInput,
) -> Result<[u8; 32], RelationError> {
    let mut transcript = NativeTranscript::new();
    transcript.append_bytes(CONSTRUCTION_STEP_MANIFEST_DOMAIN)?;
    transcript.append_field(input.prior_manifest);
    transcript.append_field(field_to_be(Scalar::from(u64::from(input.zero_based_index))));
    transcript.append_bytes(&input.binding_digest)?;
    transcript.append_scalar(input.precommitment);
    transcript.append_point(
        input.coefficient_commitment[0],
        input.coefficient_commitment[1..]
            .try_into()
            .expect("fixed coefficient commitment x"),
    )?;
    transcript.append_point(
        input.anchored_offset[0],
        input.anchored_offset[1..]
            .try_into()
            .expect("fixed anchored offset x"),
    )?;
    Ok(field_to_be(transcript.challenge(0)?.scalar))
}

fn parse_root_scalar(bytes: [u8; 32]) -> Result<Scalar, RelationError> {
    let witness = SecpScalarWitness::from_bytes_be(bytes);
    canonical_scalar_value(witness)
}

fn field_to_be(value: Scalar) -> [u8; 32] {
    let mut encoded = scalar_to_canonical(&value);
    encoded.reverse();
    encoded
}

#[cfg(test)]
mod tests;
