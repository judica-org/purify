//! Backend-independent V4 circuit-proof transcript inputs.
//!
//! These values define protocol shape and witnesses only. Constraint-system
//! implementations consume them without owning or reinterpreting the wire
//! format.

use crate::secp_native::{SecpEncodedPointWitness, SecpScalarWitness};
use crate::sha256_transcript::NativeTranscript;
use crate::{scalar_to_canonical, RelationError};

pub(crate) const CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4: &[u8] =
    b"Purify/BPPP/CircuitNormArg/v4/precommit";
pub(crate) const CIRCUIT_NORM_PROOF_DOMAIN_V4: &[u8] = b"Purify/BPPP/CircuitNormArg/v4/proof";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CircuitCommitmentModeV4 {
    Hidden,
    Public,
}

impl CircuitCommitmentModeV4 {
    pub(crate) const fn as_u64(self) -> u64 {
        match self {
            Self::Hidden => 0,
            Self::Public => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CircuitTranscriptShapeV4 {
    pub(crate) mode: CircuitCommitmentModeV4,
    pub(crate) gate_count: usize,
    pub(crate) commitment_count: usize,
    pub(crate) n_vec_len: usize,
    pub(crate) l_vec_len: usize,
}

impl CircuitTranscriptShapeV4 {
    pub(crate) fn validate(self) -> Result<(), RelationError> {
        let expected_n = self
            .gate_count
            .checked_mul(2)
            .ok_or(RelationError::Malformed("V4 gate count"))?;
        if !self.gate_count.is_power_of_two()
            || (self.mode == CircuitCommitmentModeV4::Hidden
                && self.commitment_count >= self.gate_count)
            || self.n_vec_len != expected_n
            || self.l_vec_len != self.n_vec_len
            || (self.mode == CircuitCommitmentModeV4::Public && self.commitment_count == 0)
        {
            return Err(RelationError::Malformed("V4 circuit shape"));
        }
        for value in [
            self.gate_count,
            self.commitment_count,
            self.n_vec_len,
            self.l_vec_len,
        ] {
            u64::try_from(value).map_err(|_| RelationError::Malformed("V4 circuit size"))?;
        }
        Ok(())
    }

    pub(crate) const fn public_commitment_count(self) -> usize {
        match self.mode {
            CircuitCommitmentModeV4::Hidden => 0,
            CircuitCommitmentModeV4::Public => self.commitment_count,
        }
    }

    pub(crate) fn round_count(self) -> usize {
        self.n_vec_len.trailing_zeros() as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CircuitPointPairWitnessV4 {
    pub(crate) encoded: [u8; 65],
    pub(crate) first_y: [u8; 32],
    pub(crate) second_y: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CircuitProofTranscriptWitnessV4 {
    pub(crate) public_commitments: Vec<SecpEncodedPointWitness>,
    pub(crate) raw_commitment: SecpEncodedPointWitness,
    pub(crate) coefficient_commitment: SecpEncodedPointWitness,
    pub(crate) anchored_offset: SecpEncodedPointWitness,
    pub(crate) anchored_commitment: SecpEncodedPointWitness,
    pub(crate) batched_public_commitment: SecpEncodedPointWitness,
    pub(crate) dlog_nonce: SecpEncodedPointWitness,
    pub(crate) dlog_response: SecpScalarWitness,
    pub(crate) mask_commitment: SecpEncodedPointWitness,
    pub(crate) t2: SecpScalarWitness,
    pub(crate) combined_commitment: SecpEncodedPointWitness,
    pub(crate) rounds: Vec<CircuitPointPairWitnessV4>,
    pub(crate) terminal_n: SecpScalarWitness,
    pub(crate) terminal_l: SecpScalarWitness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CircuitTranscriptChallengesV4 {
    pub(crate) precommitment: SecpScalarWitness,
    pub(crate) rho: SecpScalarWitness,
    pub(crate) mul_scale: SecpScalarWitness,
    pub(crate) mul_ratio: SecpScalarWitness,
    pub(crate) row_ratio: SecpScalarWitness,
    pub(crate) eta: SecpScalarWitness,
    pub(crate) dlog_challenge: SecpScalarWitness,
    pub(crate) alpha: SecpScalarWitness,
    pub(crate) gammas: Vec<SecpScalarWitness>,
    pub(crate) prepared_binding: SecpScalarWitness,
}

fn append_shape(
    transcript: &mut NativeTranscript,
    shape: CircuitTranscriptShapeV4,
) -> Result<(), RelationError> {
    shape.validate()?;
    transcript.append_u64(shape.mode.as_u64());
    for value in [
        shape.gate_count,
        shape.commitment_count,
        shape.n_vec_len,
        shape.l_vec_len,
        shape.public_commitment_count(),
    ] {
        transcript.append_u64(
            u64::try_from(value).map_err(|_| RelationError::Malformed("V4 transcript size"))?,
        );
    }
    Ok(())
}

fn append_point(
    transcript: &mut NativeTranscript,
    point: SecpEncodedPointWitness,
) -> Result<(), RelationError> {
    transcript.append_point(
        point.encoded[0],
        point.encoded[1..]
            .try_into()
            .expect("encoded point x is 32 bytes"),
    )
}

fn append_pair(
    transcript: &mut NativeTranscript,
    pair: &CircuitPointPairWitnessV4,
) -> Result<(), RelationError> {
    if pair.encoded[0] > 3 {
        return Err(RelationError::Malformed("V4 point pair"));
    }
    let first_x: [u8; 32] = pair.encoded[1..33]
        .try_into()
        .expect("first pair x is 32 bytes");
    let second_x: [u8; 32] = pair.encoded[33..]
        .try_into()
        .expect("second pair x is 32 bytes");
    if (first_x == [0; 32] && pair.encoded[0] & 2 != 0)
        || (second_x == [0; 32] && pair.encoded[0] & 1 != 0)
    {
        return Err(RelationError::Malformed("V4 signed pair identity"));
    }
    transcript.append_point_pair(pair.encoded[0], first_x, second_x)
}

fn challenge(
    transcript: &mut NativeTranscript,
    round: u64,
) -> Result<SecpScalarWitness, RelationError> {
    let mut encoded = scalar_to_canonical(&transcript.challenge(round)?.scalar);
    encoded.reverse();
    Ok(SecpScalarWitness::from_bytes_be(encoded))
}

/// Replay the exact V4 typed transcript without building a constraint system.
pub(crate) fn replay_circuit_transcript_v4(
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: [u8; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<CircuitTranscriptChallengesV4, RelationError> {
    shape.validate()?;
    if witness.public_commitments.len() != shape.public_commitment_count()
        || witness.rounds.len() != shape.round_count()
    {
        return Err(RelationError::Malformed("V4 transcript witness shape"));
    }

    let mut precommit = NativeTranscript::new();
    precommit.append_bytes(CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4)?;
    precommit.append_bytes(&circuit_binding_digest)?;
    append_shape(&mut precommit, shape)?;
    for point in witness.public_commitments.iter().copied() {
        append_point(&mut precommit, point)?;
    }
    append_point(&mut precommit, witness.raw_commitment)?;
    let precommitment = challenge(&mut precommit, 0)?;

    let mut proof = NativeTranscript::new();
    proof.append_bytes(CIRCUIT_NORM_PROOF_DOMAIN_V4)?;
    proof.append_scalar(precommitment.bytes);
    proof.append_bytes(&raw_generator_digest)?;
    append_shape(&mut proof, shape)?;
    let rho = challenge(&mut proof, 0)?;
    let mul_scale = challenge(&mut proof, 1)?;
    let mul_ratio = challenge(&mut proof, 2)?;
    let row_ratio = challenge(&mut proof, 3)?;

    append_point(&mut proof, witness.coefficient_commitment)?;
    append_point(&mut proof, witness.anchored_offset)?;
    append_point(&mut proof, witness.anchored_commitment)?;
    let eta = challenge(&mut proof, 4)?;
    append_point(&mut proof, witness.batched_public_commitment)?;
    proof.append_bytes(&witness.dlog_nonce.encoded[1..])?;
    let dlog_challenge = challenge(&mut proof, 5)?;
    proof.append_scalar(witness.dlog_response.bytes);
    append_point(&mut proof, witness.mask_commitment)?;
    proof.append_scalar(witness.t2.bytes);
    let alpha = challenge(&mut proof, 6)?;
    append_point(&mut proof, witness.combined_commitment)?;

    let mut gammas = Vec::with_capacity(witness.rounds.len());
    for (round, pair) in witness.rounds.iter().enumerate() {
        append_pair(&mut proof, pair)?;
        let round =
            u64::try_from(round).map_err(|_| RelationError::Malformed("V4 transcript round"))?;
        gammas.push(challenge(&mut proof, 7 + round)?);
    }
    proof.append_scalar(witness.terminal_n.bytes);
    proof.append_scalar(witness.terminal_l.bytes);
    let prepared_round = 7 + u64::try_from(witness.rounds.len())
        .map_err(|_| RelationError::Malformed("V4 transcript rounds"))?;
    let prepared_binding = challenge(&mut proof, prepared_round)?;

    Ok(CircuitTranscriptChallengesV4 {
        precommitment,
        rho,
        mul_scale,
        mul_ratio,
        row_ratio,
        eta,
        dlog_challenge,
        alpha,
        gammas,
        prepared_binding,
    })
}
