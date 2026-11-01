//! Verifier-derived state and ordered manifest for the construction recurrence.
//!
//! This module derives only the public state expected by the selected
//! homogeneous relation. It does not verify a recursive proof, decide an
//! accumulation root, or expose an acceptance result. In particular, the
//! final root remains part of the recursive proof's authenticated output and
//! is not serialized alongside it.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;

use crate::algebraic_transcript::NativeTranscript;
use crate::anchor_recurrence::AnchorRecurrenceStateWitness;
use crate::parent_relation::{encoded_point_value, CandidateRootClaim, SecpEncodedPointWitness};
use crate::secp_scalar::{canonical_scalar_value, coordinate_field_value, SecpScalarWitness};
use crate::{ReceiptCycleError, Scalar};

pub(crate) const CONSTRUCTION_ROOT_ROUNDS: usize = 15;
pub(crate) const CONSTRUCTION_ROOT_STATE_ARITY: usize = 3 + CONSTRUCTION_ROOT_ROUNDS;
pub(crate) const CONSTRUCTION_STATE_ARITY: usize = CONSTRUCTION_ROOT_STATE_ARITY + 2;
pub(crate) const CONSTRUCTION_SEED_ROOT_BYTES: usize = 33 + 32 + 32 * CONSTRUCTION_ROOT_ROUNDS;
const CONSTRUCTION_RELATION_VERSION: u64 = 2;
const CONSTRUCTION_INITIAL_MANIFEST_DOMAIN: &[u8] =
    b"Purify/Accountable/ConstructionParentManifest/v2/init";
pub(crate) const CONSTRUCTION_STEP_MANIFEST_DOMAIN: &[u8] =
    b"Purify/Accountable/ConstructionParentManifest/v2/anchor";

/// Canonical registry seed for the fixed 32,768-point construction basis.
///
/// Registration is responsible for verifying and deciding this root. This
/// type establishes only its exact one-term encoding and state conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionRegistrySeedRoot {
    encoded: [u8; CONSTRUCTION_SEED_ROOT_BYTES],
    claim: CandidateRootClaim,
}

impl ConstructionRegistrySeedRoot {
    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, ReceiptCycleError> {
        let encoded: [u8; CONSTRUCTION_SEED_ROOT_BYTES] = encoded
            .try_into()
            .map_err(|_| ReceiptCycleError::Malformed("construction seed root size"))?;
        let point = decode_seed_point(encoded[..33].try_into().expect("fixed point slice"))?;
        let scale = parse_seed_scalar(encoded[33..65].try_into().expect("fixed root scale slice"))?;
        let mut factors = Vec::with_capacity(CONSTRUCTION_ROOT_ROUNDS);
        for index in 0..CONSTRUCTION_ROOT_ROUNDS {
            let offset = 65 + 32 * index;
            factors.push(parse_seed_scalar(
                encoded[offset..offset + 32]
                    .try_into()
                    .expect("fixed root factor slice"),
            )?);
        }
        let claim = CandidateRootClaim {
            point,
            scale,
            factors,
        };
        Ok(Self { encoded, claim })
    }

    fn canonical_bytes(&self) -> &[u8; CONSTRUCTION_SEED_ROOT_BYTES] {
        &self.encoded
    }

    fn claim(&self) -> CandidateRootClaim {
        self.claim.clone()
    }

    /// Converts the registry seed into the recurrence's exact root prefix.
    ///
    /// This deliberately has no inverse final-root serializer. Compressed
    /// proof verification owns the final state and passes its root directly
    /// to the native decision path.
    pub(crate) fn state_fields(
        &self,
    ) -> Result<[Scalar; CONSTRUCTION_ROOT_STATE_ARITY], ReceiptCycleError> {
        let point = encoded_point_value(self.claim.point)?;
        let mut fields = [Scalar::ZERO; CONSTRUCTION_ROOT_STATE_ARITY];
        fields[0] = Scalar::from(u64::from(self.claim.point.encoded[0]));
        fields[1] = point.x;
        fields[2] = canonical_scalar_value(self.claim.scale)?;
        for (index, factor) in self.claim.factors.iter().enumerate() {
            fields[3 + index] = canonical_scalar_value(*factor)?;
        }
        Ok(fields)
    }
}

/// Immutable public inputs from which the verifier derives recurrence z0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestSeed {
    construction_statement_digest: [u8; 32],
    resolved_setup_record_digest: [u8; 32],
    root: ConstructionRegistrySeedRoot,
    payload_anchor_count: u32,
}

impl ConstructionManifestSeed {
    pub(crate) fn new(
        construction_statement_digest: [u8; 32],
        resolved_setup_record_digest: [u8; 32],
        root: ConstructionRegistrySeedRoot,
        payload_anchor_count: u64,
    ) -> Result<Self, ReceiptCycleError> {
        if resolved_setup_record_digest == [0; 32] {
            return Err(ReceiptCycleError::Malformed(
                "unresolved construction setup record",
            ));
        }
        let payload_anchor_count = u32::try_from(payload_anchor_count)
            .map_err(|_| ReceiptCycleError::Malformed("construction anchor count"))?;
        if payload_anchor_count == 0 {
            return Err(ReceiptCycleError::Malformed("empty construction payload"));
        }
        Ok(Self {
            construction_statement_digest,
            resolved_setup_record_digest,
            root,
            payload_anchor_count,
        })
    }

    fn initial_manifest(&self) -> [u8; 32] {
        let mut transcript = NativeTranscript::new();
        transcript.append_bytes(CONSTRUCTION_INITIAL_MANIFEST_DOMAIN);
        transcript.append_u64(CONSTRUCTION_RELATION_VERSION);
        transcript.append_bytes(&self.construction_statement_digest);
        transcript.append_bytes(&self.resolved_setup_record_digest);
        transcript.append_bytes(self.root.canonical_bytes());
        transcript.append_u64(u64::from(self.payload_anchor_count));
        field_to_be(transcript.challenge(0)[0])
    }

    /// Returns the only valid initial witness for this verifier-derived seed.
    pub(crate) fn initial_recurrence_witness(&self) -> AnchorRecurrenceStateWitness {
        AnchorRecurrenceStateWitness {
            root: self.root.claim(),
            manifest: self.initial_manifest(),
            index: 0,
        }
    }

    /// Returns the fixed 20-field initial state consumed by recursion.
    pub(crate) fn initial_state_fields(
        &self,
    ) -> Result<[Scalar; CONSTRUCTION_STATE_ARITY], ReceiptCycleError> {
        let root = self.root.state_fields()?;
        let mut state = [Scalar::ZERO; CONSTRUCTION_STATE_ARITY];
        state[..CONSTRUCTION_ROOT_STATE_ARITY].copy_from_slice(&root);
        state[CONSTRUCTION_ROOT_STATE_ARITY] = coordinate_field_value(self.initial_manifest())?;
        state[CONSTRUCTION_ROOT_STATE_ARITY + 1] = Scalar::ZERO;
        Ok(state)
    }

    /// Derives the manifest and index expected after the exact ordered payload.
    pub(crate) fn derive_expected_final(
        &self,
        anchors: &[ConstructionManifestAnchor],
    ) -> Result<ConstructionManifestState, ReceiptCycleError> {
        let count = u32::try_from(anchors.len())
            .map_err(|_| ReceiptCycleError::Malformed("construction anchor count"))?;
        if count != self.payload_anchor_count {
            return Err(ReceiptCycleError::Malformed(
                "construction manifest anchor count",
            ));
        }
        let mut state = ConstructionManifestState {
            manifest: self.initial_manifest(),
            index: 0,
        };
        for anchor in anchors {
            state = state.advance(*anchor)?;
        }
        Ok(state)
    }
}

/// Verifier-resolved public values bound by one homogeneous anchor step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionManifestAnchor {
    binding_digest: [u8; 32],
    precommitment: SecpScalarWitness,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
}

impl ConstructionManifestAnchor {
    pub(crate) fn new(
        binding_digest: [u8; 32],
        precommitment: SecpScalarWitness,
        coefficient_commitment: SecpEncodedPointWitness,
        anchored_offset: SecpEncodedPointWitness,
    ) -> Result<Self, ReceiptCycleError> {
        if canonical_scalar_value(precommitment)? == Scalar::ZERO {
            return Err(ReceiptCycleError::Malformed(
                "zero construction precommitment",
            ));
        }
        encoded_point_value(coefficient_commitment)?;
        encoded_point_value(anchored_offset)?;
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
    precommitment: SecpScalarWitness,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
}

impl ConstructionManifestStepInput {
    pub(crate) fn new(
        prior_manifest: [u8; 32],
        zero_based_index: u32,
        anchor: ConstructionManifestAnchor,
    ) -> Result<Self, ReceiptCycleError> {
        coordinate_field_value(prior_manifest)?;
        Ok(Self {
            prior_manifest,
            zero_based_index,
            binding_digest: anchor.binding_digest,
            precommitment: anchor.precommitment,
            coefficient_commitment: anchor.coefficient_commitment,
            anchored_offset: anchor.anchored_offset,
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
    pub(crate) fn manifest(&self) -> [u8; 32] {
        self.manifest
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// Returns the manifest and index fields expected at the end of recursion.
    pub(crate) fn state_suffix_fields(&self) -> Result<[Scalar; 2], ReceiptCycleError> {
        Ok([
            coordinate_field_value(self.manifest)?,
            Scalar::from(u64::from(self.index)),
        ])
    }

    fn advance(self, anchor: ConstructionManifestAnchor) -> Result<Self, ReceiptCycleError> {
        let next_index = self
            .index
            .checked_add(1)
            .ok_or(ReceiptCycleError::Malformed("construction manifest index"))?;
        let input = ConstructionManifestStepInput::new(self.manifest, self.index, anchor)?;
        Ok(Self {
            manifest: derive_step_manifest(&input)?,
            index: next_index,
        })
    }
}

/// Replays the native transcript constrained by one recurrence step.
pub(crate) fn derive_step_manifest(
    input: &ConstructionManifestStepInput,
) -> Result<[u8; 32], ReceiptCycleError> {
    let prior_manifest = coordinate_field_value(input.prior_manifest)?;
    let precommitment = canonical_scalar_value(input.precommitment)?;
    if precommitment == Scalar::ZERO {
        return Err(ReceiptCycleError::Malformed(
            "zero construction precommitment",
        ));
    }
    let coefficient_commitment = encoded_point_value(input.coefficient_commitment)?;
    let anchored_offset = encoded_point_value(input.anchored_offset)?;

    let mut transcript = NativeTranscript::new();
    transcript.append_bytes(CONSTRUCTION_STEP_MANIFEST_DOMAIN);
    transcript.append_field(prior_manifest);
    transcript.append_field(Scalar::from(u64::from(input.zero_based_index)));
    transcript.append_bytes(&input.binding_digest);
    transcript.append_scalar(precommitment);
    transcript.append_point(
        input.coefficient_commitment.encoded[0],
        coefficient_commitment.x,
    );
    transcript.append_point(input.anchored_offset.encoded[0], anchored_offset.x);
    Ok(field_to_be(transcript.challenge(0)[0]))
}

fn decode_seed_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    if encoded == [0; 33] {
        return Ok(SecpEncodedPointWitness::identity());
    }
    if encoded[0] != 2 && encoded[0] != 3 {
        return Err(ReceiptCycleError::Malformed(
            "construction seed point prefix",
        ));
    }
    let x = coordinate_field_value(encoded[1..].try_into().expect("fixed x slice"))?;
    let rhs = x.square() * x + Scalar::from(7);
    let mut y = Option::<Scalar>::from(rhs.sqrt())
        .ok_or(ReceiptCycleError::Malformed("construction seed point"))?;
    let want_odd = encoded[0] & 1;
    if Secq256k1Cycle::scalar_to_canonical(&y)[0] & 1 != want_odd {
        y = -y;
    }
    let y = Secq256k1Cycle::scalar_to_canonical(&y);
    if y[0] & 1 != want_odd {
        return Err(ReceiptCycleError::Malformed(
            "construction seed point parity",
        ));
    }
    let point = SecpEncodedPointWitness { encoded, y };
    encoded_point_value(point)?;
    Ok(point)
}

fn parse_seed_scalar(bytes: [u8; 32]) -> Result<SecpScalarWitness, ReceiptCycleError> {
    let witness = SecpScalarWitness::from_bytes_be(bytes);
    canonical_scalar_value(witness)?;
    Ok(witness)
}

fn field_to_be(value: Scalar) -> [u8; 32] {
    let mut encoded = Secq256k1Cycle::scalar_to_canonical(&value);
    encoded.reverse();
    encoded
}

#[cfg(test)]
mod tests;
