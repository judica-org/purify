//! Strict test-tool decoder for the native construction prover fixture.
//!
//! The C++ slashability fixture exports only public proof data. This decoder
//! fixes the production suite locally, derives every affine point opening,
//! and reconstructs transcript-dependent points rather than trusting extra
//! witness data from the file.

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use num_bigint::BigUint;
use thiserror::Error;

use crate::anchor_recurrence::{
    ANCHOR_GATE_COUNT, ANCHOR_LEAF_ROUNDS, ANCHOR_NORM_LENGTH, CONSTRUCTION_PARENT_BASIS_DIGEST,
    CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
};
use crate::circuit_norm_leaf::ManifestBoundAnchorLeafStatementV4;
use crate::construction_manifest::{
    ConstructionManifestAnchor, ConstructionRoot, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS,
};
use crate::construction_parent_input::{
    ConstructionParentInputError, ConstructionParentInputs,
    CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES,
};
use crate::norm_reduction::CandidateNormReductionProofWitness;
use crate::parent_relation::{
    add_point_values, encoded_point_value, standard_generator, CandidateStepProofWitness,
    PointValue, SecpEncodedPointWitness,
};
use crate::relation_builder::Builder;
use crate::secp_scalar::{canonical_scalar_value, SecpScalarWitness};
use crate::sha256_circuit_transcript::{
    install_transcript, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
    CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
};
use crate::{ReceiptCycleError, Scalar};

const MAGIC: &[u8; 16] = b"Purify/Nova/Wit1";
const HEADER_BYTES: usize = MAGIC.len() + 32 + 32 + CONSTRUCTION_ROOT_BYTES + 4;
const PUNISHMENT_POINT_BYTES: usize = 33;
const ANCHOR_RECORD_BYTES: usize = 1_329;
const REDUCTION_PROOF_BYTES: usize = 1_022;
const STEP_PROOF_BYTES: usize = 1_056;
const ANCHOR_BYTES: usize = CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES
    + PUNISHMENT_POINT_BYTES
    + ANCHOR_RECORD_BYTES
    + REDUCTION_PROOF_BYTES
    + STEP_PROOF_BYTES;
const RECORD_VERSION: u8 = 3;
const REDUCTION_VERSION: u8 = 2;
const STEP_VERSION: u8 = 2;

const RECORD_RAW_OFFSET: usize = 193;
const RECORD_MASK_OFFSET: usize = RECORD_RAW_OFFSET + 33;
const RECORD_T2_OFFSET: usize = RECORD_MASK_OFFSET + 33;
const RECORD_NONCE_OFFSET: usize = RECORD_T2_OFFSET + 32;
const RECORD_RESPONSE_OFFSET: usize = RECORD_NONCE_OFFSET + 32;
const RECORD_ROUNDS_OFFSET: usize = RECORD_RESPONSE_OFFSET + 32;
const RECORD_TERMINAL_N_OFFSET: usize = RECORD_ROUNDS_OFFSET + 65 * ANCHOR_LEAF_ROUNDS;
const RECORD_TERMINAL_L_OFFSET: usize = RECORD_TERMINAL_N_OFFSET + 32;

const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub(crate) const QUALIFIED_PROVER_FIXTURE_SHA256: [u8; 32] = [
    0x7c, 0x81, 0x92, 0x22, 0x67, 0x9a, 0x52, 0xbf, 0xa2, 0x16, 0xed, 0x75, 0x26, 0x2b, 0x5c, 0xa8,
    0x37, 0xd7, 0xf5, 0x03, 0x2a, 0x15, 0xa6, 0x7d, 0xea, 0x4e, 0xb1, 0x84, 0x43, 0x03, 0x2b, 0xb5,
];
pub(crate) const NONDECIDING_PROVER_FIXTURE_SHA256: [u8; 32] = [
    0xf2, 0x29, 0x9a, 0x76, 0xe0, 0x84, 0xe6, 0x6e, 0x91, 0x85, 0xbf, 0x47, 0x44, 0x56, 0x39, 0xf4,
    0x73, 0x67, 0xc1, 0xdc, 0x14, 0x30, 0x61, 0xc3, 0x16, 0x82, 0xdf, 0xad, 0x83, 0xde, 0x26, 0xec,
];

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum ConstructionParentProverFixtureError {
    #[error(transparent)]
    Input(#[from] ConstructionParentInputError),
    #[error(transparent)]
    State(#[from] ReceiptCycleError),
}

pub(crate) struct ConstructionParentProverAnchor {
    pub(crate) statement: ManifestBoundAnchorLeafStatementV4,
    pub(crate) transcript: CircuitProofTranscriptWitnessV4,
    pub(crate) reduction: CandidateNormReductionProofWitness,
    pub(crate) step: CandidateStepProofWitness,
    manifest_anchor: ConstructionManifestAnchor,
}

pub(crate) struct ConstructionParentProverFixture {
    pub(crate) inputs: ConstructionParentInputs,
    pub(crate) anchors: Vec<ConstructionParentProverAnchor>,
    pub(crate) expected_root: ConstructionRoot,
}

impl ConstructionParentProverFixture {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ConstructionParentProverFixtureError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.array::<16>()? != *MAGIC {
            return Err(ReceiptCycleError::Malformed("construction prover fixture magic").into());
        }
        let statement_digest = cursor.array::<32>()?;
        let setup_digest = cursor.array::<32>()?;
        let seed_root = cursor.array::<CONSTRUCTION_ROOT_BYTES>()?;
        let anchor_count = u32::from_be_bytes(cursor.array::<4>()?);
        if anchor_count == 0 {
            return Err(ReceiptCycleError::Malformed("empty construction prover fixture").into());
        }
        let anchor_count_usize = usize::try_from(anchor_count)
            .map_err(|_| ReceiptCycleError::Malformed("construction prover fixture count"))?;
        let expected_len = anchor_count_usize
            .checked_mul(ANCHOR_BYTES)
            .and_then(|anchors| HEADER_BYTES.checked_add(anchors))
            .and_then(|prefix| prefix.checked_add(CONSTRUCTION_ROOT_BYTES))
            .ok_or(ReceiptCycleError::Malformed(
                "construction prover fixture length",
            ))?;
        if bytes.len() != expected_len {
            return Err(ReceiptCycleError::Malformed("construction prover fixture length").into());
        }

        let mut descriptor_bytes =
            Vec::with_capacity(anchor_count_usize * CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES);
        let mut anchors = Vec::with_capacity(anchor_count_usize);
        for _ in 0..anchor_count_usize {
            let descriptor = cursor.array::<CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES>()?;
            descriptor_bytes.extend_from_slice(&descriptor);
            let punishment = parse_even_finite_point(cursor.array::<PUNISHMENT_POINT_BYTES>()?)?;
            let record = cursor.array::<ANCHOR_RECORD_BYTES>()?;
            let reduction = parse_reduction(cursor.array::<REDUCTION_PROOF_BYTES>()?)?;
            let step = parse_step(cursor.array::<STEP_PROOF_BYTES>()?)?;
            anchors.push(parse_anchor(
                descriptor, punishment, record, reduction, step,
            )?);
        }
        let expected_root = ConstructionRoot::parse(&cursor.array::<CONSTRUCTION_ROOT_BYTES>()?)?;
        cursor.finish()?;

        let inputs = ConstructionParentInputs::parse(
            statement_digest,
            setup_digest,
            &seed_root,
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            anchor_count,
            &descriptor_bytes,
        )?;
        if anchors
            .iter()
            .map(|anchor| anchor.manifest_anchor)
            .ne(inputs.anchors().iter().copied())
        {
            return Err(
                ReceiptCycleError::Malformed("construction prover fixture descriptors").into(),
            );
        }
        Ok(Self {
            inputs,
            anchors,
            expected_root,
        })
    }
}

fn production_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: ANCHOR_GATE_COUNT,
        commitment_count: 1,
        n_vec_len: ANCHOR_NORM_LENGTH,
        l_vec_len: ANCHOR_NORM_LENGTH,
    }
}

fn parse_anchor(
    descriptor: [u8; CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES],
    punishment: SecpEncodedPointWitness,
    record: [u8; ANCHOR_RECORD_BYTES],
    reduction: CandidateNormReductionProofWitness,
    step: CandidateStepProofWitness,
) -> Result<ConstructionParentProverAnchor, ReceiptCycleError> {
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
    let manifest_anchor = ConstructionManifestAnchor::new(
        binding_digest,
        precommitment,
        coefficient_commitment,
        anchored_offset,
    )?;
    let statement = ManifestBoundAnchorLeafStatementV4 {
        shape: production_shape(),
        circuit_binding_digest: binding_digest,
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
    };
    let transcript = parse_record(
        record,
        punishment,
        coefficient_commitment,
        anchored_offset,
        precommitment,
        statement,
    )?;
    Ok(ConstructionParentProverAnchor {
        statement,
        transcript,
        reduction,
        step,
        manifest_anchor,
    })
}

fn parse_record(
    record: [u8; ANCHOR_RECORD_BYTES],
    punishment: SecpEncodedPointWitness,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
    expected_precommitment: SecpScalarWitness,
    statement: ManifestBoundAnchorLeafStatementV4,
) -> Result<CircuitProofTranscriptWitnessV4, ReceiptCycleError> {
    if record[0] != RECORD_VERSION {
        return Err(ReceiptCycleError::Malformed("anchor escrow record version"));
    }
    let raw_commitment = parse_finite_point(
        record[RECORD_RAW_OFFSET..RECORD_MASK_OFFSET]
            .try_into()
            .expect("fixed raw commitment"),
    )?;
    let mask_commitment = parse_finite_point(
        record[RECORD_MASK_OFFSET..RECORD_T2_OFFSET]
            .try_into()
            .expect("fixed mask commitment"),
    )?;
    let t2 = parse_scalar(
        record[RECORD_T2_OFFSET..RECORD_NONCE_OFFSET]
            .try_into()
            .expect("fixed t2"),
    )?;
    let mut nonce = [0; 33];
    nonce[0] = 2;
    nonce[1..].copy_from_slice(&record[RECORD_NONCE_OFFSET..RECORD_RESPONSE_OFFSET]);
    let dlog_nonce = parse_even_finite_point(nonce)?;
    let dlog_response = parse_nonzero_scalar(
        record[RECORD_RESPONSE_OFFSET..RECORD_ROUNDS_OFFSET]
            .try_into()
            .expect("fixed DLog response"),
    )?;
    let mut rounds = Vec::with_capacity(ANCHOR_LEAF_ROUNDS);
    for index in 0..ANCHOR_LEAF_ROUNDS {
        let offset = RECORD_ROUNDS_OFFSET + index * 65;
        rounds.push(parse_pair(
            record[offset..offset + 65]
                .try_into()
                .expect("fixed norm pair"),
        )?);
    }
    let terminal_n = parse_scalar(
        record[RECORD_TERMINAL_N_OFFSET..RECORD_TERMINAL_L_OFFSET]
            .try_into()
            .expect("fixed terminal n"),
    )?;
    let terminal_l = parse_scalar(
        record[RECORD_TERMINAL_L_OFFSET..]
            .try_into()
            .expect("fixed terminal l"),
    )?;
    let anchored_commitment = encoded_value(add_point_values(
        encoded_point_value(raw_commitment)?,
        encoded_point_value(anchored_offset)?,
    ));
    if anchored_commitment.encoded == [0; 33] {
        return Err(ReceiptCycleError::Malformed("identity anchored commitment"));
    }

    let mut transcript = CircuitProofTranscriptWitnessV4 {
        public_commitments: vec![punishment],
        raw_commitment,
        coefficient_commitment,
        anchored_offset,
        anchored_commitment,
        batched_public_commitment: punishment,
        dlog_nonce,
        dlog_response,
        mask_commitment,
        t2,
        combined_commitment: SecpEncodedPointWitness::identity(),
        rounds,
        terminal_n,
        terminal_l,
    };
    let derived = install_transcript(
        &mut Builder::default(),
        statement.shape,
        statement.circuit_binding_digest,
        statement.raw_generator_digest,
        &transcript,
    )?;
    if scalar_witness(derived.precommitment.integer()) != expected_precommitment {
        return Err(ReceiptCycleError::Malformed(
            "construction prover precommitment",
        ));
    }
    let order = BigUint::from_bytes_be(&SECP_ORDER);
    let alpha = derived.alpha.integer();
    let t2_integer = BigUint::from_bytes_be(&t2.bytes);
    let t2_scale = ((alpha * alpha) % &order * t2_integer) % &order;
    let anchored = encoded_point_value(anchored_commitment)?;
    let masked = scale_value(encoded_point_value(mask_commitment)?, alpha);
    let t2_generator = scale_value(standard_generator(), &t2_scale);
    transcript.combined_commitment = encoded_value(add_point_values(
        add_point_values(anchored, masked),
        t2_generator,
    ));
    if transcript.combined_commitment.encoded == [0; 33] {
        return Err(ReceiptCycleError::Malformed("identity combined commitment"));
    }
    Ok(transcript)
}

fn parse_reduction(
    encoded: [u8; REDUCTION_PROOF_BYTES],
) -> Result<CandidateNormReductionProofWitness, ReceiptCycleError> {
    if encoded[0] != REDUCTION_VERSION {
        return Err(ReceiptCycleError::Malformed(
            "construction reduction version",
        ));
    }
    let coefficient_evaluation = parse_scalar(
        encoded[1..33]
            .try_into()
            .expect("fixed reduction evaluation"),
    )?;
    let mut left = Vec::with_capacity(ANCHOR_LEAF_ROUNDS);
    let mut right = Vec::with_capacity(ANCHOR_LEAF_ROUNDS);
    let mut offset = 33;
    for _ in 0..ANCHOR_LEAF_ROUNDS {
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

fn parse_step(
    encoded: [u8; STEP_PROOF_BYTES],
) -> Result<CandidateStepProofWitness, ReceiptCycleError> {
    if encoded[0] != STEP_VERSION {
        return Err(ReceiptCycleError::Malformed(
            "construction parent step version",
        ));
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

fn parse_pair(encoded: [u8; 65]) -> Result<CircuitPointPairWitnessV4, ReceiptCycleError> {
    if encoded[0] > 3 {
        return Err(ReceiptCycleError::Malformed("V4 point pair"));
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
) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    let offset = 1 + index * 32;
    let x = &pair[offset..offset + 32];
    let mask = 2u8 >> index;
    if x.iter().all(|byte| *byte == 0) {
        if pair[0] & mask != 0 {
            return Err(ReceiptCycleError::Malformed("signed pair identity"));
        }
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair[0] & mask != 0);
    encoded[1..].copy_from_slice(x);
    SecpEncodedPointWitness::parse(encoded)
}

fn parse_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, ReceiptCycleError> {
    let witness = SecpScalarWitness::from_bytes_be(encoded);
    canonical_scalar_value(witness)?;
    Ok(witness)
}

fn parse_nonzero_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, ReceiptCycleError> {
    let witness = parse_scalar(encoded)?;
    if witness.bytes == [0; 32] {
        return Err(ReceiptCycleError::Malformed("zero DLog response"));
    }
    Ok(witness)
}

fn parse_finite_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    let point = SecpEncodedPointWitness::parse(encoded)?;
    if point.encoded == [0; 33] {
        return Err(ReceiptCycleError::Malformed("identity proof point"));
    }
    Ok(point)
}

fn parse_even_finite_point(
    encoded: [u8; 33],
) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    if encoded[0] != 2 {
        return Err(ReceiptCycleError::Malformed("non-even proof point"));
    }
    parse_finite_point(encoded)
}

fn encoded_value(point: PointValue) -> SecpEncodedPointWitness {
    if point.identity {
        return SecpEncodedPointWitness::identity();
    }
    let mut x = Secq256k1Cycle::scalar_to_canonical(&point.x);
    let y = Secq256k1Cycle::scalar_to_canonical(&point.y);
    x.reverse();
    let mut encoded = [0; 33];
    encoded[0] = if y[0] & 1 == 0 { 2 } else { 3 };
    encoded[1..].copy_from_slice(&x);
    SecpEncodedPointWitness { encoded, y }
}

fn scale_value(point: PointValue, scalar: &BigUint) -> PointValue {
    let mut accumulator = PointValue {
        x: Scalar::ZERO,
        y: Scalar::ZERO,
        identity: true,
    };
    let mut addend = point;
    for bit in 0..256 {
        if scalar.bit(bit) {
            accumulator = add_point_values(accumulator, addend);
        }
        addend = add_point_values(addend, addend);
    }
    accumulator
}

fn scalar_witness(value: &BigUint) -> SecpScalarWitness {
    let encoded = value.to_bytes_be();
    assert!(encoded.len() <= 32);
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    SecpScalarWitness::from_bytes_be(bytes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReceiptCycleError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(ReceiptCycleError::Malformed(
                "construction prover fixture overflow",
            ))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ReceiptCycleError::Malformed(
                "truncated construction prover fixture",
            ))?;
        self.offset = end;
        Ok(bytes.try_into().expect("fixed cursor slice"))
    }

    fn finish(self) -> Result<(), ReceiptCycleError> {
        if self.offset != self.bytes.len() {
            return Err(ReceiptCycleError::Malformed(
                "trailing construction prover fixture bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn fixture_frame_rejects_truncation_and_wrong_magic() {
        assert_eq!(
            ConstructionParentProverFixture::parse(&[])
                .err()
                .expect("empty fixture rejects"),
            ConstructionParentProverFixtureError::State(ReceiptCycleError::Malformed(
                "truncated construction prover fixture"
            ))
        );
        let mut wrong_magic = *MAGIC;
        wrong_magic[0] ^= 1;
        assert_eq!(
            ConstructionParentProverFixture::parse(&wrong_magic)
                .err()
                .expect("wrong magic rejects"),
            ConstructionParentProverFixtureError::State(ReceiptCycleError::Malformed(
                "construction prover fixture magic"
            ))
        );
    }

    #[test]
    #[ignore = "requires both deterministic C++ slashability fixtures"]
    fn exported_fixtures_parse_without_private_openings() {
        let parse = |environment, expected_sha256| {
            let path = std::env::var_os(environment).unwrap_or_else(|| panic!("set {environment}"));
            let bytes = std::fs::read(path).expect("read construction prover fixture");
            assert_eq!(bytes.len(), 8_314);
            assert_eq!(Sha256::digest(&bytes).as_slice(), expected_sha256);
            ConstructionParentProverFixture::parse(&bytes)
                .expect("parse deterministic construction prover fixture")
        };
        let accepted = parse(
            "PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE",
            QUALIFIED_PROVER_FIXTURE_SHA256,
        );
        let nondeciding = parse(
            "PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE",
            NONDECIDING_PROVER_FIXTURE_SHA256,
        );
        assert_eq!(accepted.anchors.len(), 2);
        assert_eq!(nondeciding.anchors.len(), accepted.anchors.len());
        assert_eq!(accepted.inputs.anchors(), nondeciding.inputs.anchors());
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
