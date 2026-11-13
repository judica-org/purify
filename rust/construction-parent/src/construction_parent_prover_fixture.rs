//! Strict test-tool decoder for the native construction prover fixture.
//!
//! The C++ slashability fixture exports only public proof data. This decoder
//! fixes the production suite locally, derives every affine point opening,
//! and reconstructs transcript-dependent points rather than trusting extra
//! witness data from the file.

use num_bigint::BigUint;
use thiserror::Error;

use crate::candidate::CandidateStepProofWitness;
use crate::circuit_norm::{
    CandidateNormReductionProofWitness, ManifestBoundConstructionLeafStatementV4,
};
use crate::circuit_transcript::{
    replay_circuit_transcript_v4, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
    CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
};
use crate::construction_manifest::{ConstructionManifestLeaf, ConstructionRoot};
use crate::construction_parent_input::{
    ConstructionParentInputError, ConstructionParentInputs,
    CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES,
};
use crate::construction_profile::{
    CONSTRUCTION_LEAF_GATE_COUNT, CONSTRUCTION_LEAF_NORM_LENGTH, CONSTRUCTION_LEAF_ROUNDS,
    CONSTRUCTION_PARENT_BASIS_DIGEST, CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
    CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS,
};
use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE as SECP_ORDER;
use crate::secp_native::{
    add_point_values, canonical_scalar_value, encoded_point_value, scale_point_value,
    standard_generator, SecpEncodedPointWitness, SecpScalarWitness,
};
use crate::RelationError;

const MAGIC: &[u8; 16] = b"Purify/Nova/Wit3";
const RECOVERY_ROOT_BYTES: usize = 64;
const HEADER_BYTES: usize = MAGIC.len() + 32 + 32 + RECOVERY_ROOT_BYTES + 4 + 4;
const PUBLIC_COMMITMENT_BYTES: usize = 33;
const SETUP_RECORD_BYTES: usize = 1_203;
const ANCHOR_RECORD_BYTES: usize = 1_233;
const REDUCTION_PROOF_BYTES: usize = 1_022;
const STEP_PROOF_BYTES: usize = 1_056;
const SETUP_BYTES: usize = CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES
    + PUBLIC_COMMITMENT_BYTES
    + SETUP_RECORD_BYTES
    + REDUCTION_PROOF_BYTES
    + STEP_PROOF_BYTES;
const ANCHOR_BYTES: usize = CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES
    + PUBLIC_COMMITMENT_BYTES
    + ANCHOR_RECORD_BYTES
    + REDUCTION_PROOF_BYTES
    + STEP_PROOF_BYTES;
const SETUP_RECORD_VERSION: u8 = 1;
const ANCHOR_RECORD_VERSION: u8 = 4;
const REDUCTION_VERSION: u8 = 2;
const STEP_VERSION: u8 = 2;

const SETUP_RECORD_RAW_OFFSET: usize = 67;
const ANCHOR_RECORD_RAW_OFFSET: usize = 97;

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum ConstructionParentProverFixtureError {
    #[error(transparent)]
    Input(#[from] ConstructionParentInputError),
    #[error(transparent)]
    State(#[from] RelationError),
}

pub(crate) struct ConstructionParentProverLeaf {
    pub(crate) statement: ManifestBoundConstructionLeafStatementV4,
    pub(crate) transcript: CircuitProofTranscriptWitnessV4,
    pub(crate) reduction: CandidateNormReductionProofWitness,
    pub(crate) step: CandidateStepProofWitness,
    manifest_leaf: ConstructionManifestLeaf,
}

pub(crate) struct ConstructionParentProverFixture {
    pub(crate) inputs: ConstructionParentInputs,
    pub(crate) setup_leaf_count: usize,
    pub(crate) anchor_leaf_count: usize,
    pub(crate) leaves: Vec<ConstructionParentProverLeaf>,
    pub(crate) expected_root: ConstructionRoot,
}

impl ConstructionParentProverFixture {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ConstructionParentProverFixtureError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.array::<16>()? != *MAGIC {
            return Err(RelationError::Malformed("construction prover fixture magic").into());
        }
        let statement_digest = cursor.array::<32>()?;
        let setup_digest = cursor.array::<32>()?;
        let recovery_root = cursor.array::<RECOVERY_ROOT_BYTES>()?;
        let setup_count = u32::from_be_bytes(cursor.array::<4>()?);
        let anchor_count = u32::from_be_bytes(cursor.array::<4>()?);
        if setup_count == 0 || anchor_count == 0 {
            return Err(RelationError::Malformed("empty construction prover fixture").into());
        }
        let setup_count_usize = usize::try_from(setup_count)
            .map_err(|_| RelationError::Malformed("construction prover fixture count"))?;
        let anchor_count_usize = usize::try_from(anchor_count)
            .map_err(|_| RelationError::Malformed("construction prover fixture count"))?;
        let leaf_count =
            setup_count_usize
                .checked_add(anchor_count_usize)
                .ok_or(RelationError::Malformed(
                    "construction prover fixture count",
                ))?;
        let expected_len = setup_count_usize
            .checked_mul(SETUP_BYTES)
            .and_then(|setup| {
                anchor_count_usize
                    .checked_mul(ANCHOR_BYTES)
                    .and_then(|anchors| setup.checked_add(anchors))
            })
            .and_then(|leaves| HEADER_BYTES.checked_add(leaves))
            .and_then(|prefix| prefix.checked_add(CONSTRUCTION_ROOT_BYTES))
            .ok_or(RelationError::Malformed(
                "construction prover fixture length",
            ))?;
        if bytes.len() != expected_len {
            return Err(RelationError::Malformed("construction prover fixture length").into());
        }

        let descriptor_capacity = leaf_count
            .checked_mul(CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES)
            .ok_or(RelationError::Malformed(
                "construction prover fixture count",
            ))?;
        let mut descriptor_bytes = Vec::with_capacity(descriptor_capacity);
        let mut leaves = Vec::with_capacity(leaf_count);
        for _ in 0..setup_count_usize {
            let descriptor = cursor.array::<CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES>()?;
            descriptor_bytes.extend_from_slice(&descriptor);
            let output = parse_finite_point(cursor.array::<PUBLIC_COMMITMENT_BYTES>()?)?;
            let record = cursor.array::<SETUP_RECORD_BYTES>()?;
            let reduction = parse_reduction(cursor.array::<REDUCTION_PROOF_BYTES>()?)?;
            let step = parse_step(cursor.array::<STEP_PROOF_BYTES>()?)?;
            leaves.push(parse_leaf(
                descriptor,
                output,
                &record,
                RecordLayout {
                    version: SETUP_RECORD_VERSION,
                    raw_offset: SETUP_RECORD_RAW_OFFSET,
                },
                reduction,
                step,
            )?);
        }
        for _ in 0..anchor_count_usize {
            let descriptor = cursor.array::<CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES>()?;
            descriptor_bytes.extend_from_slice(&descriptor);
            let punishment = parse_even_finite_point(cursor.array::<PUBLIC_COMMITMENT_BYTES>()?)?;
            let record = cursor.array::<ANCHOR_RECORD_BYTES>()?;
            let reduction = parse_reduction(cursor.array::<REDUCTION_PROOF_BYTES>()?)?;
            let step = parse_step(cursor.array::<STEP_PROOF_BYTES>()?)?;
            leaves.push(parse_leaf(
                descriptor,
                punishment,
                &record,
                RecordLayout {
                    version: ANCHOR_RECORD_VERSION,
                    raw_offset: ANCHOR_RECORD_RAW_OFFSET,
                },
                reduction,
                step,
            )?);
        }
        let expected_root = ConstructionRoot::parse(&cursor.array::<CONSTRUCTION_ROOT_BYTES>()?)?;
        cursor.finish()?;

        let inputs = ConstructionParentInputs::parse(
            statement_digest,
            setup_digest,
            recovery_root,
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            setup_count,
            anchor_count,
            &descriptor_bytes,
        )?;
        if leaves
            .iter()
            .map(|leaf| leaf.manifest_leaf)
            .ne(inputs.leaves().iter().copied())
        {
            return Err(RelationError::Malformed("construction prover fixture descriptors").into());
        }
        Ok(Self {
            inputs,
            setup_leaf_count: setup_count_usize,
            anchor_leaf_count: anchor_count_usize,
            leaves,
            expected_root,
        })
    }
}

fn production_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: CONSTRUCTION_LEAF_GATE_COUNT,
        commitment_count: 1,
        n_vec_len: CONSTRUCTION_LEAF_NORM_LENGTH,
        l_vec_len: CONSTRUCTION_LEAF_NORM_LENGTH,
    }
}

fn parse_leaf(
    descriptor: [u8; CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES],
    public_commitment: SecpEncodedPointWitness,
    record: &[u8],
    layout: RecordLayout,
    reduction: CandidateNormReductionProofWitness,
    step: CandidateStepProofWitness,
) -> Result<ConstructionParentProverLeaf, RelationError> {
    let binding_digest = descriptor[..32].try_into().expect("fixed binding digest");
    let precommitment = parse_scalar(descriptor[32..64].try_into().expect("fixed precommitment"))?;
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
    let manifest_leaf = ConstructionManifestLeaf::new(
        binding_digest,
        precommitment.bytes,
        coefficient_commitment.encoded,
        anchored_offset.encoded,
    )?;
    let statement = ManifestBoundConstructionLeafStatementV4 {
        shape: production_shape(),
        circuit_binding_digest: binding_digest,
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
    };
    let transcript = parse_record(
        record,
        public_commitment,
        layout,
        coefficient_commitment,
        anchored_offset,
        precommitment,
        statement,
    )?;
    Ok(ConstructionParentProverLeaf {
        statement,
        transcript,
        reduction,
        step,
        manifest_leaf,
    })
}

#[derive(Clone, Copy)]
struct RecordLayout {
    version: u8,
    raw_offset: usize,
}

fn parse_record(
    record: &[u8],
    public_commitment: SecpEncodedPointWitness,
    layout: RecordLayout,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
    expected_precommitment: SecpScalarWitness,
    statement: ManifestBoundConstructionLeafStatementV4,
) -> Result<CircuitProofTranscriptWitnessV4, RelationError> {
    if record.first().copied() != Some(layout.version) {
        return Err(RelationError::Malformed("construction leaf record version"));
    }
    let mask_offset = layout.raw_offset + 33;
    let t2_offset = mask_offset + 33;
    let nonce_offset = t2_offset + 32;
    let response_offset = nonce_offset + 32;
    let rounds_offset = response_offset + 32;
    let terminal_n_offset = rounds_offset + 65 * CONSTRUCTION_LEAF_ROUNDS;
    let terminal_l_offset = terminal_n_offset + 32;
    if terminal_l_offset.checked_add(32) != Some(record.len()) {
        return Err(RelationError::Malformed("construction leaf record length"));
    }
    let raw_commitment = parse_finite_point(
        record[layout.raw_offset..mask_offset]
            .try_into()
            .expect("fixed raw commitment"),
    )?;
    let mask_commitment = parse_finite_point(
        record[mask_offset..t2_offset]
            .try_into()
            .expect("fixed mask commitment"),
    )?;
    let t2 = parse_scalar(
        record[t2_offset..nonce_offset]
            .try_into()
            .expect("fixed t2"),
    )?;
    let mut nonce = [0; 33];
    nonce[0] = 2;
    nonce[1..].copy_from_slice(&record[nonce_offset..response_offset]);
    let dlog_nonce = parse_even_finite_point(nonce)?;
    let dlog_response = parse_nonzero_scalar(
        record[response_offset..rounds_offset]
            .try_into()
            .expect("fixed DLog response"),
    )?;
    let mut rounds = Vec::with_capacity(CONSTRUCTION_LEAF_ROUNDS);
    for index in 0..CONSTRUCTION_LEAF_ROUNDS {
        let offset = rounds_offset + index * 65;
        rounds.push(parse_pair(
            record[offset..offset + 65]
                .try_into()
                .expect("fixed norm pair"),
        )?);
    }
    let terminal_n = parse_scalar(
        record[terminal_n_offset..terminal_l_offset]
            .try_into()
            .expect("fixed terminal n"),
    )?;
    let terminal_l = parse_scalar(
        record[terminal_l_offset..]
            .try_into()
            .expect("fixed terminal l"),
    )?;
    let anchored_commitment = SecpEncodedPointWitness::from_point_value(add_point_values(
        encoded_point_value(raw_commitment)?,
        encoded_point_value(anchored_offset)?,
    ));
    if anchored_commitment.encoded == [0; 33] {
        return Err(RelationError::Malformed("identity anchored commitment"));
    }

    let mut transcript = CircuitProofTranscriptWitnessV4 {
        public_commitments: vec![public_commitment],
        raw_commitment,
        coefficient_commitment,
        anchored_offset,
        anchored_commitment,
        batched_public_commitment: public_commitment,
        dlog_nonce,
        dlog_response,
        mask_commitment,
        t2,
        combined_commitment: SecpEncodedPointWitness::identity(),
        rounds,
        terminal_n,
        terminal_l,
    };
    let derived = replay_circuit_transcript_v4(
        statement.shape,
        statement.circuit_binding_digest,
        statement.raw_generator_digest,
        &transcript,
    )?;
    if derived.precommitment != expected_precommitment {
        return Err(RelationError::Malformed(
            "construction prover precommitment",
        ));
    }
    let order = BigUint::from_bytes_be(&SECP_ORDER);
    let alpha = BigUint::from_bytes_be(&derived.alpha.bytes);
    let t2_integer = BigUint::from_bytes_be(&t2.bytes);
    let t2_scale = ((&alpha * &alpha) % &order * t2_integer) % &order;
    let anchored = encoded_point_value(anchored_commitment)?;
    let masked = scale_point_value(encoded_point_value(mask_commitment)?, &alpha);
    let t2_generator = scale_point_value(standard_generator(), &t2_scale);
    transcript.combined_commitment = SecpEncodedPointWitness::from_point_value(add_point_values(
        add_point_values(anchored, masked),
        t2_generator,
    ));
    if transcript.combined_commitment.encoded == [0; 33] {
        return Err(RelationError::Malformed("identity combined commitment"));
    }
    Ok(transcript)
}

fn parse_reduction(
    encoded: [u8; REDUCTION_PROOF_BYTES],
) -> Result<CandidateNormReductionProofWitness, RelationError> {
    if encoded[0] != REDUCTION_VERSION {
        return Err(RelationError::Malformed("construction reduction version"));
    }
    let coefficient_evaluation = parse_scalar(
        encoded[1..33]
            .try_into()
            .expect("fixed reduction evaluation"),
    )?;
    let mut left = Vec::with_capacity(CONSTRUCTION_LEAF_ROUNDS);
    let mut right = Vec::with_capacity(CONSTRUCTION_LEAF_ROUNDS);
    let mut offset = 33;
    for _ in 0..CONSTRUCTION_LEAF_ROUNDS {
        left.push(SecpEncodedPointWitness::parse(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed reduction left"),
        )?);
        offset += 33;
        right.push(SecpEncodedPointWitness::parse(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed reduction right"),
        )?);
        offset += 33;
    }
    let terminal_scalar = parse_scalar(
        encoded[offset..offset + 32]
            .try_into()
            .expect("fixed reduction terminal"),
    )?;
    offset += 32;
    let folded_generator = SecpEncodedPointWitness::parse(
        encoded[offset..offset + 33]
            .try_into()
            .expect("fixed reduction generator"),
    )?;
    Ok(CandidateNormReductionProofWitness {
        coefficient_evaluation,
        left,
        right,
        terminal_scalar,
        folded_generator,
    })
}

fn parse_step(encoded: [u8; STEP_PROOF_BYTES]) -> Result<CandidateStepProofWitness, RelationError> {
    if encoded[0] != STEP_VERSION {
        return Err(RelationError::Malformed("construction parent step version"));
    }
    let mut left = Vec::with_capacity(CONSTRUCTION_ROOT_ROUNDS);
    let mut right = Vec::with_capacity(CONSTRUCTION_ROOT_ROUNDS);
    let mut offset = 1;
    for _ in 0..CONSTRUCTION_ROOT_ROUNDS {
        left.push(SecpEncodedPointWitness::parse(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed step left"),
        )?);
        offset += 33;
        right.push(SecpEncodedPointWitness::parse(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed step right"),
        )?);
        offset += 33;
    }
    let terminal_scalar = parse_scalar(
        encoded[offset..offset + 32]
            .try_into()
            .expect("fixed step terminal"),
    )?;
    offset += 32;
    let folded_generator = SecpEncodedPointWitness::parse(
        encoded[offset..offset + 33]
            .try_into()
            .expect("fixed step generator"),
    )?;
    Ok(CandidateStepProofWitness {
        left,
        right,
        terminal_scalar,
        folded_generator,
    })
}

fn parse_pair(encoded: [u8; 65]) -> Result<CircuitPointPairWitnessV4, RelationError> {
    if encoded[0] > 3 {
        return Err(RelationError::Malformed("V4 point pair"));
    }
    let first = parse_pair_point(&encoded, 0)?;
    let second = parse_pair_point(&encoded, 1)?;
    Ok(CircuitPointPairWitnessV4 {
        encoded,
        first_y: first.y,
        second_y: second.y,
    })
}

fn parse_pair_point(
    pair: &[u8; 65],
    index: usize,
) -> Result<SecpEncodedPointWitness, RelationError> {
    let offset = 1 + index * 32;
    let x = &pair[offset..offset + 32];
    let mask = 2u8 >> index;
    if x.iter().all(|byte| *byte == 0) {
        if pair[0] & mask != 0 {
            return Err(RelationError::Malformed("signed pair identity"));
        }
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair[0] & mask != 0);
    encoded[1..].copy_from_slice(x);
    SecpEncodedPointWitness::parse(encoded)
}

fn parse_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, RelationError> {
    let witness = SecpScalarWitness::from_bytes_be(encoded);
    canonical_scalar_value(witness)?;
    Ok(witness)
}

fn parse_nonzero_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, RelationError> {
    let witness = parse_scalar(encoded)?;
    if witness.bytes == [0; 32] {
        return Err(RelationError::Malformed("zero DLog response"));
    }
    Ok(witness)
}

fn parse_finite_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, RelationError> {
    let point = SecpEncodedPointWitness::parse(encoded)?;
    if point.encoded == [0; 33] {
        return Err(RelationError::Malformed("identity proof point"));
    }
    Ok(point)
}

fn parse_even_finite_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, RelationError> {
    if encoded[0] != 2 {
        return Err(RelationError::Malformed("non-even proof point"));
    }
    parse_finite_point(encoded)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        let end = self.offset.checked_add(N).ok_or(RelationError::Malformed(
            "construction prover fixture overflow",
        ))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RelationError::Malformed(
                "truncated construction prover fixture",
            ))?;
        self.offset = end;
        Ok(bytes.try_into().expect("fixed cursor slice"))
    }

    fn finish(self) -> Result<(), RelationError> {
        if self.offset != self.bytes.len() {
            return Err(RelationError::Malformed(
                "trailing construction prover fixture bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_frame_rejects_truncation_and_wrong_magic() {
        assert_eq!(
            ConstructionParentProverFixture::parse(&[])
                .err()
                .expect("empty fixture rejects"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "truncated construction prover fixture"
            ))
        );
        let mut wrong_magic = *MAGIC;
        wrong_magic[0] ^= 1;
        assert_eq!(
            ConstructionParentProverFixture::parse(&wrong_magic)
                .err()
                .expect("wrong magic rejects"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "construction prover fixture magic"
            ))
        );
        assert_eq!(
            ConstructionParentProverFixture::parse(b"Purify/Nova/Wit1")
                .err()
                .expect("legacy magic rejects"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "construction prover fixture magic"
            ))
        );
        assert_eq!(
            ConstructionParentProverFixture::parse(b"Purify/Nova/Wit2")
                .err()
                .expect("prior fixture magic rejects"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "construction prover fixture magic"
            ))
        );
    }

    #[test]
    fn fixture_frame_requires_both_typed_leaf_counts() {
        assert_eq!(SETUP_BYTES, 3_444);
        assert_eq!(ANCHOR_BYTES, 3_474);
        assert_eq!(HEADER_BYTES, 152);

        let mut encoded = vec![0; HEADER_BYTES];
        encoded[..MAGIC.len()].copy_from_slice(MAGIC);
        assert_eq!(
            ConstructionParentProverFixture::parse(&encoded)
                .err()
                .expect("empty phases reject"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "empty construction prover fixture"
            ))
        );

        let setup_count_offset = MAGIC.len() + 32 + 32 + RECOVERY_ROOT_BYTES;
        encoded[setup_count_offset + 3] = 1;
        encoded[setup_count_offset + 7] = 1;
        assert_eq!(
            ConstructionParentProverFixture::parse(&encoded)
                .err()
                .expect("missing typed leaves reject"),
            ConstructionParentProverFixtureError::State(RelationError::Malformed(
                "construction prover fixture length"
            ))
        );
    }

    #[test]
    fn checked_fixtures_parse_without_private_openings() {
        let accepted = ConstructionParentProverFixture::parse(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("parse accepted construction prover fixture");
        let nondeciding = ConstructionParentProverFixture::parse(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_nondeciding.wit3"
        ))
        .expect("parse nondeciding construction prover fixture");
        assert_ne!(accepted.setup_leaf_count, 0);
        assert_ne!(accepted.anchor_leaf_count, 0);
        assert_eq!(accepted.setup_leaf_count, nondeciding.setup_leaf_count);
        assert_eq!(accepted.anchor_leaf_count, nondeciding.anchor_leaf_count);
        assert_eq!(nondeciding.leaves.len(), accepted.leaves.len());
        assert_eq!(accepted.inputs.leaves(), nondeciding.inputs.leaves());
        assert_eq!(
            accepted.expected_root.canonical_bytes().len(),
            CONSTRUCTION_ROOT_BYTES
        );
        assert_ne!(
            accepted.expected_root.canonical_bytes(),
            nondeciding.expected_root.canonical_bytes()
        );
    }
}
