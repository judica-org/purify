//! Constrained V4 circuit-proof transcript replay.
//!
//! This module authenticates transcript fields only. It does not check the
//! circuit, Schnorr, or norm equations and exposes no receipt acceptance API.

use ff::Field;

use crate::algebraic_transcript::BuilderTranscript;
#[cfg(test)]
use crate::parent_relation::constrain_scalar_constant;
use crate::parent_relation::{
    allocate_encoded_point, append_constant_bytes, append_encoded_point, append_scalar,
    canonical_field_bits, EncodedSecpPoint, SecpEncodedPointWitness,
};
use crate::relation_builder::{Builder, Expression};
use crate::secp_scalar::{
    allocate_canonical_scalar, embedded_integer, select_challenge_lanes, SecpScalarVar,
    SecpScalarWitness,
};
use crate::{ReceiptCycleError, Scalar};

const PRECOMMIT_DOMAIN: &[u8] = b"Purify/BPPP/CircuitNormArg/v4/precommit";
const PROOF_DOMAIN: &[u8] = b"Purify/BPPP/CircuitNormArg/v4/proof";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CircuitCommitmentModeV4 {
    Hidden,
    Public,
}

impl CircuitCommitmentModeV4 {
    fn as_u64(self) -> u64 {
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
    pub(crate) fn validate(self) -> Result<(), ReceiptCycleError> {
        let expected_n = self
            .gate_count
            .checked_mul(2)
            .ok_or(ReceiptCycleError::Malformed("V4 gate count"))?;
        if !self.gate_count.is_power_of_two()
            || self.n_vec_len != expected_n
            || self.l_vec_len != self.n_vec_len
            || (self.mode == CircuitCommitmentModeV4::Public && self.commitment_count == 0)
        {
            return Err(ReceiptCycleError::Malformed("V4 circuit shape"));
        }
        for value in [
            self.gate_count,
            self.commitment_count,
            self.n_vec_len,
            self.l_vec_len,
        ] {
            u64::try_from(value).map_err(|_| ReceiptCycleError::Malformed("V4 circuit size"))?;
        }
        Ok(())
    }

    fn public_commitment_count(self) -> usize {
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
#[cfg(test)]
pub(crate) struct CircuitTranscriptExpectedV4 {
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

pub(crate) struct CircuitPointPairV4 {
    pub(crate) first: EncodedSecpPoint,
    pub(crate) second: EncodedSecpPoint,
}

pub(crate) struct CircuitTranscriptResultV4 {
    pub(crate) public_commitments: Vec<EncodedSecpPoint>,
    pub(crate) raw_commitment: EncodedSecpPoint,
    pub(crate) coefficient_commitment: EncodedSecpPoint,
    pub(crate) anchored_offset: EncodedSecpPoint,
    pub(crate) anchored_commitment: EncodedSecpPoint,
    pub(crate) batched_public_commitment: EncodedSecpPoint,
    pub(crate) dlog_nonce: EncodedSecpPoint,
    pub(crate) dlog_response: SecpScalarVar,
    pub(crate) mask_commitment: EncodedSecpPoint,
    pub(crate) t2: SecpScalarVar,
    pub(crate) combined_commitment: EncodedSecpPoint,
    pub(crate) rounds: Vec<CircuitPointPairV4>,
    pub(crate) terminal_n: SecpScalarVar,
    pub(crate) terminal_l: SecpScalarVar,
    pub(crate) precommitment: SecpScalarVar,
    pub(crate) rho: SecpScalarVar,
    pub(crate) mul_scale: SecpScalarVar,
    pub(crate) mul_ratio: SecpScalarVar,
    pub(crate) row_ratio: SecpScalarVar,
    pub(crate) eta: SecpScalarVar,
    pub(crate) dlog_challenge: SecpScalarVar,
    pub(crate) alpha: SecpScalarVar,
    pub(crate) gammas: Vec<SecpScalarVar>,
    pub(crate) prepared_binding: SecpScalarVar,
}

fn append_shape(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    shape: CircuitTranscriptShapeV4,
) -> Result<(), ReceiptCycleError> {
    shape.validate()?;
    transcript.append_u64(builder, shape.mode.as_u64());
    transcript.append_u64(
        builder,
        u64::try_from(shape.gate_count)
            .map_err(|_| ReceiptCycleError::Malformed("V4 gate count"))?,
    );
    transcript.append_u64(
        builder,
        u64::try_from(shape.commitment_count)
            .map_err(|_| ReceiptCycleError::Malformed("V4 commitment count"))?,
    );
    transcript.append_u64(
        builder,
        u64::try_from(shape.n_vec_len).map_err(|_| ReceiptCycleError::Malformed("V4 n vector"))?,
    );
    transcript.append_u64(
        builder,
        u64::try_from(shape.l_vec_len).map_err(|_| ReceiptCycleError::Malformed("V4 l vector"))?,
    );
    transcript.append_u64(
        builder,
        u64::try_from(shape.public_commitment_count())
            .map_err(|_| ReceiptCycleError::Malformed("V4 public count"))?,
    );
    Ok(())
}

fn challenge(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    index: u64,
) -> SecpScalarVar {
    let lanes = transcript.challenge(builder, index);
    let selected = select_challenge_lanes(builder, &lanes[0], &lanes[1]);
    append_scalar(transcript, builder, &selected);
    selected
}

fn coordinate_byte_words(builder: &mut Builder, x: &Expression) -> [Expression; 2] {
    let bits = canonical_field_bits(builder, x);
    let pack = |start: usize, end: usize| {
        let mut value = Expression::constant(Scalar::ZERO);
        let mut coefficient = Scalar::ONE;
        for bit in &bits[start..end] {
            value = value.add(&bit.clone().scale(coefficient));
            coefficient = coefficient + coefficient;
        }
        value
    };
    [pack(8, 256), pack(0, 8)]
}

fn append_nonce_bytes(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    nonce: &EncodedSecpPoint,
) -> Result<(), ReceiptCycleError> {
    let words = coordinate_byte_words(builder, &nonce.point.x);
    transcript.append_byte_words(builder, 32, &words)
}

fn allocate_point_v4(
    builder: &mut Builder,
    witness: SecpEncodedPointWitness,
) -> Result<EncodedSecpPoint, ReceiptCycleError> {
    let identity = witness.encoded == [0; 33];
    if (!identity && !matches!(witness.encoded[0], 2 | 3)) || (identity && witness.y != [0; 32]) {
        return Err(ReceiptCycleError::Malformed("V4 encoded point"));
    }
    allocate_encoded_point(builder, witness)
}

fn pair_point(
    pair: &CircuitPointPairWitnessV4,
    index: usize,
) -> Result<SecpEncodedPointWitness, ReceiptCycleError> {
    if pair.encoded[0] > 3 || index > 1 {
        return Err(ReceiptCycleError::Malformed("V4 point pair"));
    }
    let offset = 1 + 32 * index;
    let x = &pair.encoded[offset..offset + 32];
    let mask = 2u8 >> index;
    if x.iter().all(|byte| *byte == 0) {
        if pair.encoded[0] & mask != 0 {
            return Err(ReceiptCycleError::Malformed("V4 signed pair identity"));
        }
        let y = if index == 0 {
            pair.first_y
        } else {
            pair.second_y
        };
        return Ok(SecpEncodedPointWitness {
            encoded: [0; 33],
            y,
        });
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair.encoded[0] & mask != 0);
    encoded[1..].copy_from_slice(x);
    Ok(SecpEncodedPointWitness {
        encoded,
        y: if index == 0 {
            pair.first_y
        } else {
            pair.second_y
        },
    })
}

fn append_pair(
    transcript: &mut BuilderTranscript,
    builder: &mut Builder,
    witness: &CircuitPointPairWitnessV4,
) -> Result<CircuitPointPairV4, ReceiptCycleError> {
    let first = allocate_point_v4(builder, pair_point(witness, 0)?)?;
    let second = allocate_point_v4(builder, pair_point(witness, 1)?)?;
    let parity = first.odd.clone().scale(Scalar::from(2)).add(&second.odd);
    transcript.append_point_pair(
        builder,
        parity,
        first.point.x.clone(),
        second.point.x.clone(),
    );
    Ok(CircuitPointPairV4 { first, second })
}

fn require_identity(builder: &mut Builder, point: &EncodedSecpPoint) {
    builder.constrain_equal(&point.point.identity, &Expression::constant(Scalar::ONE));
}

fn require_finite_even(builder: &mut Builder, point: &EncodedSecpPoint) {
    builder.constrain_zero(point.point.identity.clone());
    builder.constrain_zero(point.odd.clone());
}

pub(crate) fn install_transcript(
    builder: &mut Builder,
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: [u8; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<CircuitTranscriptResultV4, ReceiptCycleError> {
    shape.validate()?;
    if witness.public_commitments.len() != shape.public_commitment_count()
        || witness.rounds.len() != shape.round_count()
    {
        return Err(ReceiptCycleError::Malformed("V4 transcript shape"));
    }

    let mut precommit = BuilderTranscript::new();
    append_constant_bytes(&mut precommit, builder, PRECOMMIT_DOMAIN)?;
    append_constant_bytes(&mut precommit, builder, &circuit_binding_digest)?;
    append_shape(&mut precommit, builder, shape)?;
    let mut public_commitments = Vec::with_capacity(witness.public_commitments.len());
    for point in &witness.public_commitments {
        let point = allocate_point_v4(builder, *point)?;
        append_encoded_point(&mut precommit, builder, &point);
        public_commitments.push(point);
    }
    let raw_commitment = allocate_point_v4(builder, witness.raw_commitment)?;
    append_encoded_point(&mut precommit, builder, &raw_commitment);
    let precommitment_lanes = precommit.challenge(builder, 0);
    let precommitment =
        select_challenge_lanes(builder, &precommitment_lanes[0], &precommitment_lanes[1]);

    let mut proof = BuilderTranscript::new();
    append_constant_bytes(&mut proof, builder, PROOF_DOMAIN)?;
    append_scalar(&mut proof, builder, &precommitment);
    append_constant_bytes(&mut proof, builder, &raw_generator_digest)?;
    append_shape(&mut proof, builder, shape)?;
    let rho = challenge(&mut proof, builder, 0);
    let mul_scale = challenge(&mut proof, builder, 1);
    let mul_ratio = challenge(&mut proof, builder, 2);
    let row_ratio = challenge(&mut proof, builder, 3);

    let coefficient_commitment = allocate_point_v4(builder, witness.coefficient_commitment)?;
    append_encoded_point(&mut proof, builder, &coefficient_commitment);
    let anchored_offset = allocate_point_v4(builder, witness.anchored_offset)?;
    append_encoded_point(&mut proof, builder, &anchored_offset);
    let anchored_commitment = allocate_point_v4(builder, witness.anchored_commitment)?;
    append_encoded_point(&mut proof, builder, &anchored_commitment);
    let eta = challenge(&mut proof, builder, 4);
    let batched = allocate_point_v4(builder, witness.batched_public_commitment)?;
    append_encoded_point(&mut proof, builder, &batched);
    let nonce = allocate_point_v4(builder, witness.dlog_nonce)?;
    match shape.mode {
        CircuitCommitmentModeV4::Hidden => {
            require_identity(builder, &batched);
            require_identity(builder, &nonce);
        }
        CircuitCommitmentModeV4::Public => {
            require_finite_even(builder, &nonce);
        }
    }
    append_nonce_bytes(&mut proof, builder, &nonce)?;
    let dlog_challenge = challenge(&mut proof, builder, 5);
    let dlog_response = allocate_canonical_scalar(builder, witness.dlog_response)?;
    if shape.mode == CircuitCommitmentModeV4::Hidden {
        builder.constrain_zero(embedded_integer(&dlog_response));
    }
    append_scalar(&mut proof, builder, &dlog_response);

    let mask = allocate_point_v4(builder, witness.mask_commitment)?;
    append_encoded_point(&mut proof, builder, &mask);
    let t2 = allocate_canonical_scalar(builder, witness.t2)?;
    append_scalar(&mut proof, builder, &t2);
    let alpha = challenge(&mut proof, builder, 6);
    let combined = allocate_point_v4(builder, witness.combined_commitment)?;
    append_encoded_point(&mut proof, builder, &combined);

    let mut rounds = Vec::with_capacity(witness.rounds.len());
    let mut gammas = Vec::with_capacity(witness.rounds.len());
    for (round, pair) in witness.rounds.iter().enumerate() {
        rounds.push(append_pair(&mut proof, builder, pair)?);
        gammas.push(challenge(
            &mut proof,
            builder,
            7 + u64::try_from(round).map_err(|_| ReceiptCycleError::Malformed("V4 round"))?,
        ));
    }
    let terminal_n = allocate_canonical_scalar(builder, witness.terminal_n)?;
    let terminal_l = allocate_canonical_scalar(builder, witness.terminal_l)?;
    append_scalar(&mut proof, builder, &terminal_n);
    append_scalar(&mut proof, builder, &terminal_l);
    let prepared_lanes = proof.challenge(
        builder,
        7 + u64::try_from(witness.rounds.len())
            .map_err(|_| ReceiptCycleError::Malformed("V4 rounds"))?,
    );
    let prepared_binding = select_challenge_lanes(builder, &prepared_lanes[0], &prepared_lanes[1]);
    Ok(CircuitTranscriptResultV4 {
        public_commitments,
        raw_commitment,
        coefficient_commitment,
        anchored_offset,
        anchored_commitment,
        batched_public_commitment: batched,
        dlog_nonce: nonce,
        dlog_response,
        mask_commitment: mask,
        t2,
        combined_commitment: combined,
        rounds,
        terminal_n,
        terminal_l,
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

#[cfg(test)]
pub(crate) fn build_candidate_circuit_transcript_v4_relation(
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: [u8; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
    expected: &CircuitTranscriptExpectedV4,
) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
    if expected.gammas.len() != shape.round_count() {
        return Err(ReceiptCycleError::Malformed("V4 expected gammas"));
    }
    let mut builder = Builder::default();
    let result = install_transcript(
        &mut builder,
        shape,
        circuit_binding_digest,
        raw_generator_digest,
        witness,
    )?;
    for (actual, expected) in [
        (&result.precommitment, expected.precommitment),
        (&result.rho, expected.rho),
        (&result.mul_scale, expected.mul_scale),
        (&result.mul_ratio, expected.mul_ratio),
        (&result.row_ratio, expected.row_ratio),
        (&result.eta, expected.eta),
        (&result.dlog_challenge, expected.dlog_challenge),
        (&result.alpha, expected.alpha),
        (&result.prepared_binding, expected.prepared_binding),
    ] {
        constrain_scalar_constant(&mut builder, actual, expected)?;
    }
    for (actual, &expected) in result.gammas.iter().zip(&expected.gammas) {
        constrain_scalar_constant(&mut builder, actual, expected)?;
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bulletproofs_cycle::Cycle;
    use golden_halo2curves::Secq256k1Cycle;

    use crate::{proof_wire_len, prove, verify};

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        assert_eq!(value.len() & 1, 0);
        (0..value.len() / 2)
            .map(|index| u8::from_str_radix(&value[2 * index..2 * index + 2], 16).expect("hex"))
            .collect()
    }

    fn decode_hex<const SIZE: usize>(value: &str) -> [u8; SIZE] {
        decode_hex_vec(value).try_into().expect("fixed hex")
    }

    fn json_string<'a>(json: &'a str, key: &str) -> &'a str {
        let needle = format!("\"{key}\": \"");
        let start = json.find(&needle).expect("JSON key") + needle.len();
        let rest = &json[start..];
        &rest[..rest.find('"').expect("JSON string")]
    }

    fn json_u64(json: &str, key: &str) -> u64 {
        let needle = format!("\"{key}\": ");
        let start = json.find(&needle).expect("JSON integer key") + needle.len();
        let rest = &json[start..];
        let end = rest
            .find(|character: char| !character.is_ascii_digit())
            .expect("JSON integer end");
        rest[..end].parse().expect("JSON integer")
    }

    fn json_array<'a>(json: &'a str, key: &str) -> Vec<&'a str> {
        let needle = format!("\"{key}\": [");
        let start = json.find(&needle).expect("JSON array key") + needle.len();
        let rest = &json[start..];
        let array = &rest[..rest.find(']').expect("JSON array")];
        let mut values = Vec::new();
        let mut cursor = array;
        while let Some(start) = cursor.find('"') {
            cursor = &cursor[start + 1..];
            let end = cursor.find('"').expect("JSON array string");
            values.push(&cursor[..end]);
            cursor = &cursor[end + 1..];
        }
        values
    }

    fn point_witness(encoded: [u8; 33]) -> SecpEncodedPointWitness {
        if encoded == [0; 33] {
            return SecpEncodedPointWitness::identity();
        }
        assert!(matches!(encoded[0], 2 | 3));
        let mut x = [0; 32];
        x.copy_from_slice(&encoded[1..]);
        x.reverse();
        let x = Secq256k1Cycle::scalar_from_canonical(&x).expect("canonical point x");
        let rhs = x.square() * x + Scalar::from(7);
        let mut y = Option::<Scalar>::from(rhs.sqrt()).expect("fixture point lifts");
        let mut y_bytes = Secq256k1Cycle::scalar_to_canonical(&y);
        if (y_bytes[0] & 1 != 0) != (encoded[0] == 3) {
            y = -y;
            y_bytes = Secq256k1Cycle::scalar_to_canonical(&y);
        }
        SecpEncodedPointWitness {
            encoded,
            y: y_bytes,
        }
    }

    fn point_hex(value: &str) -> SecpEncodedPointWitness {
        point_witness(decode_hex(value))
    }

    fn nonce_hex(value: &str) -> SecpEncodedPointWitness {
        let mut encoded = [0; 33];
        encoded[0] = 2;
        encoded[1..].copy_from_slice(&decode_hex::<32>(value));
        point_witness(encoded)
    }

    fn pair_hex(value: &str) -> CircuitPointPairWitnessV4 {
        let encoded = decode_hex::<65>(value);
        let point = |index: usize| {
            let offset = 1 + 32 * index;
            if encoded[offset..offset + 32].iter().all(|byte| *byte == 0) {
                return SecpEncodedPointWitness::identity();
            }
            let mut point = [0; 33];
            point[0] = 2 + u8::from(encoded[0] & (2u8 >> index) != 0);
            point[1..].copy_from_slice(&encoded[offset..offset + 32]);
            point_witness(point)
        };
        CircuitPointPairWitnessV4 {
            encoded,
            first_y: point(0).y,
            second_y: point(1).y,
        }
    }

    fn scalar_hex(value: &str) -> SecpScalarWitness {
        SecpScalarWitness::from_bytes_be(decode_hex(value))
    }

    fn scalar_value(witness: SecpScalarWitness) -> Scalar {
        let mut bytes = witness.bytes;
        bytes.reverse();
        Secq256k1Cycle::scalar_from_canonical(&bytes).expect("canonical fixture scalar")
    }

    fn fixture() -> (
        CircuitTranscriptShapeV4,
        [u8; 32],
        [u8; 32],
        CircuitProofTranscriptWitnessV4,
        CircuitTranscriptExpectedV4,
    ) {
        let vector = include_str!("../tests/vectors/algebraic_circuit_v4.json");
        let shape = CircuitTranscriptShapeV4 {
            mode: match json_u64(vector, "mode") {
                0 => CircuitCommitmentModeV4::Hidden,
                1 => CircuitCommitmentModeV4::Public,
                _ => panic!("fixture mode"),
            },
            gate_count: json_u64(vector, "gate_count") as usize,
            commitment_count: json_u64(vector, "commitment_count") as usize,
            n_vec_len: json_u64(vector, "n_vec_len") as usize,
            l_vec_len: json_u64(vector, "l_vec_len") as usize,
        };
        let public_commitments = json_array(vector, "public_commitments")
            .into_iter()
            .map(point_hex)
            .collect();
        let witness = CircuitProofTranscriptWitnessV4 {
            public_commitments,
            raw_commitment: point_hex(json_string(vector, "raw_commitment")),
            coefficient_commitment: point_hex(json_string(vector, "coefficient_commitment")),
            anchored_offset: point_hex(json_string(vector, "anchored_offset")),
            anchored_commitment: point_hex(json_string(vector, "anchored_commitment")),
            batched_public_commitment: point_hex(json_string(vector, "batched_public_commitment")),
            dlog_nonce: nonce_hex(json_string(vector, "dlog_nonce")),
            dlog_response: scalar_hex(json_string(vector, "dlog_response")),
            mask_commitment: point_hex(json_string(vector, "mask_commitment")),
            t2: scalar_hex(json_string(vector, "t2")),
            combined_commitment: point_hex(json_string(vector, "combined_commitment")),
            rounds: json_array(vector, "round_pairs")
                .into_iter()
                .map(pair_hex)
                .collect(),
            terminal_n: scalar_hex(json_string(vector, "terminal_n")),
            terminal_l: scalar_hex(json_string(vector, "terminal_l")),
        };
        let expected = CircuitTranscriptExpectedV4 {
            precommitment: scalar_hex(json_string(vector, "precommitment_digest")),
            rho: scalar_hex(json_string(vector, "rho")),
            mul_scale: scalar_hex(json_string(vector, "mul_scale")),
            mul_ratio: scalar_hex(json_string(vector, "mul_ratio")),
            row_ratio: scalar_hex(json_string(vector, "row_ratio")),
            eta: scalar_hex(json_string(vector, "eta")),
            dlog_challenge: scalar_hex(json_string(vector, "dlog_challenge")),
            alpha: scalar_hex(json_string(vector, "alpha")),
            gammas: json_array(vector, "gammas")
                .into_iter()
                .map(scalar_hex)
                .collect(),
            prepared_binding: scalar_hex(json_string(vector, "prepared_binding")),
        };
        (
            shape,
            decode_hex(json_string(vector, "circuit_binding_digest")),
            decode_hex(json_string(vector, "raw_generator_digest")),
            witness,
            expected,
        )
    }

    #[test]
    fn shared_vector_builds_one_secret_independent_shape() {
        let (shape, binding, generators, witness, expected) = fixture();
        let mut transcript_builder = Builder::default();
        let result = install_transcript(
            &mut transcript_builder,
            shape,
            binding,
            generators,
            &witness,
        )
        .expect("shared V4 transcript");
        for (actual, expected) in [
            (&result.precommitment, expected.precommitment),
            (&result.rho, expected.rho),
            (&result.mul_scale, expected.mul_scale),
            (&result.mul_ratio, expected.mul_ratio),
            (&result.row_ratio, expected.row_ratio),
            (&result.eta, expected.eta),
            (&result.dlog_challenge, expected.dlog_challenge),
            (&result.alpha, expected.alpha),
            (&result.prepared_binding, expected.prepared_binding),
        ] {
            assert_eq!(embedded_integer(actual).value(), scalar_value(expected));
        }
        for (actual, &expected) in result.gammas.iter().zip(&expected.gammas) {
            assert_eq!(embedded_integer(actual).value(), scalar_value(expected));
        }
        assert_eq!(
            result.public_commitments.len(),
            witness.public_commitments.len()
        );
        assert_eq!(result.rounds.len(), witness.rounds.len());
        drop(result);
        drop(transcript_builder);

        let mut changed = witness.clone();
        changed.terminal_n = SecpScalarWitness::from_u64(18);
        let mut changed_builder = Builder::default();
        let changed_result =
            install_transcript(&mut changed_builder, shape, binding, generators, &changed)
                .expect("changed V4 transcript");
        assert_ne!(
            embedded_integer(&changed_result.prepared_binding).value(),
            scalar_value(expected.prepared_binding),
        );
        drop(changed_result);
        drop(changed_builder);

        let (circuit, _) = build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &witness, &expected,
        )
        .expect("shared V4 relation");
        let (changed_circuit, _) = build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &changed, &expected,
        )
        .expect("changed V4 relation");
        assert_eq!(circuit, changed_circuit);
        assert_eq!(
            proof_wire_len(&circuit).expect("V4 proof length"),
            proof_wire_len(&changed_circuit).expect("changed V4 proof length"),
        );
    }

    #[test]
    fn malformed_shape_and_pair_reject_before_proving() {
        let (mut shape, binding, generators, mut witness, expected) = fixture();
        shape.gate_count = 7;
        assert!(build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &witness, &expected,
        )
        .is_err());

        let (shape, _, _, _, _) = fixture();
        witness.rounds[0].encoded[0] |= 2;
        assert!(build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &witness, &expected,
        )
        .is_err());

        let (shape, binding, generators, mut witness, expected) = fixture();
        witness.raw_commitment.encoded[0] = 0;
        assert!(build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &witness, &expected,
        )
        .is_err());
    }

    #[test]
    #[ignore = "run explicitly in release mode; V4 transcript proof is large"]
    fn shared_vector_proves_and_reports_size() {
        let (shape, binding, generators, witness, expected) = fixture();
        let (circuit, assignment) = build_candidate_circuit_transcript_v4_relation(
            shape, binding, generators, &witness, &expected,
        )
        .expect("shared V4 relation");
        let statement = b"candidate algebraic circuit transcript V4";
        let proof = prove(&circuit, &assignment, statement, [0xa4; 32]).expect("shared V4 proof");
        drop(assignment);
        verify(&circuit, statement, &proof).expect("shared V4 verification");
        let gates = u32::from_le_bytes(circuit[1..5].try_into().expect("V4 gate count"));
        eprintln!(
            "algebraic_circuit_v4_gates={gates} proof_bytes={}",
            proof.len(),
        );
    }
}
