//! Exact V4 certificate nonce-proof witness reconstruction.
//!
//! The wire proof omits verifier-derived transcript points. This module
//! reconstructs those points from the exact parent constants before a Nova
//! relation consumes the witness. Parsing and reconstruction are not proof
//! acceptance.

use num_bigint::BigUint;

use crate::certificate_profile::{
    CERTIFICATE_LEAF_GATE_COUNT, CERTIFICATE_LEAF_NORM_LENGTH, CERTIFICATE_LEAF_ROUNDS,
    CERTIFICATE_NONCE_PROOF_BYTES,
};
use crate::circuit_transcript::{
    replay_circuit_transcript_v4, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
    CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
};
use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
use crate::secp_native::{
    add_point_values, canonical_scalar_value, encoded_point_value, scale_point_value,
    standard_generator, SecpEncodedPointWitness, SecpScalarWitness,
};
use crate::RelationError;

const NONCE_PROOF_VERSION: u8 = 4;

/// Variable verifier constants for one certificate nonce leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertificateLeafParentConstantsWitness {
    pub(crate) circuit_binding_digest: [u8; 32],
    pub(crate) coefficient_commitment: SecpEncodedPointWitness,
    pub(crate) anchored_offset: SecpEncodedPointWitness,
}

/// Canonical raw V4 fields before verifier-derived point reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateNonceProofWitnessV4 {
    commitment: SecpEncodedPointWitness,
    raw_commitment: SecpEncodedPointWitness,
    mask_commitment: SecpEncodedPointWitness,
    t2: SecpScalarWitness,
    dlog_nonce: SecpEncodedPointWitness,
    dlog_response: SecpScalarWitness,
    rounds: Vec<CircuitPointPairWitnessV4>,
    terminal_n: SecpScalarWitness,
    terminal_l: SecpScalarWitness,
}

impl CertificateNonceProofWitnessV4 {
    pub(crate) fn parse(
        encoded: [u8; CERTIFICATE_NONCE_PROOF_BYTES],
    ) -> Result<Self, RelationError> {
        if encoded[0] != NONCE_PROOF_VERSION {
            return Err(RelationError::Malformed("certificate nonce proof version"));
        }
        let nonce_x: [u8; 32] = encoded[1..33]
            .try_into()
            .expect("fixed certificate nonce x");
        parse_xonly(nonce_x)?;
        let commitment = parse_finite_point(
            encoded[33..66]
                .try_into()
                .expect("fixed certificate nonce commitment"),
        )?;
        if commitment.encoded[1..] != nonce_x {
            return Err(RelationError::Malformed(
                "certificate nonce proof commitment",
            ));
        }
        let raw_commitment = parse_finite_point(
            encoded[66..99]
                .try_into()
                .expect("fixed certificate raw commitment"),
        )?;
        let mask_commitment = parse_finite_point(
            encoded[99..132]
                .try_into()
                .expect("fixed certificate mask commitment"),
        )?;
        let t2 = parse_scalar(
            encoded[132..164]
                .try_into()
                .expect("fixed certificate t2 scalar"),
        )?;
        let dlog_nonce = parse_xonly(
            encoded[164..196]
                .try_into()
                .expect("fixed certificate DLog nonce"),
        )?;
        let dlog_response = parse_nonzero_scalar(
            encoded[196..228]
                .try_into()
                .expect("fixed certificate DLog response"),
            "zero certificate DLog response",
        )?;

        let mut offset = 228;
        let mut rounds = Vec::with_capacity(CERTIFICATE_LEAF_ROUNDS);
        for _ in 0..CERTIFICATE_LEAF_ROUNDS {
            rounds.push(parse_pair(
                encoded[offset..offset + 65]
                    .try_into()
                    .expect("fixed certificate norm pair"),
            )?);
            offset += 65;
        }
        let terminal_n = parse_scalar(
            encoded[offset..offset + 32]
                .try_into()
                .expect("fixed certificate terminal n"),
        )?;
        offset += 32;
        let terminal_l = parse_scalar(
            encoded[offset..offset + 32]
                .try_into()
                .expect("fixed certificate terminal l"),
        )?;
        offset += 32;
        if offset != encoded.len() {
            return Err(RelationError::Malformed("certificate nonce proof length"));
        }

        Ok(Self {
            commitment,
            raw_commitment,
            mask_commitment,
            t2,
            dlog_nonce,
            dlog_response,
            rounds,
            terminal_n,
            terminal_l,
        })
    }

    /// Reconstruct the exact V4 transcript witness under verifier constants.
    pub(crate) fn transcript(
        &self,
        constants: CertificateLeafParentConstantsWitness,
        expected_precommitment: SecpScalarWitness,
    ) -> Result<CircuitProofTranscriptWitnessV4, RelationError> {
        parse_nonzero_scalar(
            expected_precommitment.bytes,
            "zero certificate circuit precommitment",
        )?;
        let anchored_commitment =
            add_witness_points(self.raw_commitment, constants.anchored_offset)?;
        let mut transcript = CircuitProofTranscriptWitnessV4 {
            public_commitments: vec![self.commitment],
            raw_commitment: self.raw_commitment,
            coefficient_commitment: constants.coefficient_commitment,
            anchored_offset: constants.anchored_offset,
            anchored_commitment,
            batched_public_commitment: self.commitment,
            dlog_nonce: self.dlog_nonce,
            dlog_response: self.dlog_response,
            mask_commitment: self.mask_commitment,
            t2: self.t2,
            // Alpha is derived before this point enters the transcript. A
            // finite placeholder therefore suffices for the first replay.
            combined_commitment: SecpEncodedPointWitness::from_point_value(standard_generator()),
            rounds: self.rounds.clone(),
            terminal_n: self.terminal_n,
            terminal_l: self.terminal_l,
        };
        let provisional = replay_circuit_transcript_v4(
            certificate_leaf_shape(),
            constants.circuit_binding_digest,
            crate::certificate_profile::CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
            &transcript,
        )?;
        transcript.combined_commitment = combined_commitment(
            anchored_commitment,
            self.mask_commitment,
            self.t2,
            provisional.alpha,
        )?;
        let replayed = replay_circuit_transcript_v4(
            certificate_leaf_shape(),
            constants.circuit_binding_digest,
            crate::certificate_profile::CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
            &transcript,
        )?;
        if replayed.precommitment != expected_precommitment {
            return Err(RelationError::Malformed(
                "certificate circuit precommitment mismatch",
            ));
        }
        Ok(transcript)
    }
}

pub(crate) const fn certificate_leaf_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: CERTIFICATE_LEAF_GATE_COUNT,
        commitment_count: 1,
        n_vec_len: CERTIFICATE_LEAF_NORM_LENGTH,
        l_vec_len: CERTIFICATE_LEAF_NORM_LENGTH,
    }
}

fn add_witness_points(
    left: SecpEncodedPointWitness,
    right: SecpEncodedPointWitness,
) -> Result<SecpEncodedPointWitness, RelationError> {
    Ok(SecpEncodedPointWitness::from_point_value(add_point_values(
        encoded_point_value(left)?,
        encoded_point_value(right)?,
    )))
}

fn scale_witness_point(
    point: SecpEncodedPointWitness,
    scalar: &BigUint,
) -> Result<SecpEncodedPointWitness, RelationError> {
    Ok(SecpEncodedPointWitness::from_point_value(
        scale_point_value(encoded_point_value(point)?, scalar),
    ))
}

fn combined_commitment(
    anchored: SecpEncodedPointWitness,
    mask: SecpEncodedPointWitness,
    t2: SecpScalarWitness,
    alpha: SecpScalarWitness,
) -> Result<SecpEncodedPointWitness, RelationError> {
    let order = BigUint::from_bytes_be(&SECP256K1_SCALAR_ORDER_BE);
    let alpha_value = BigUint::from_bytes_be(&alpha.bytes);
    let t2_value = BigUint::from_bytes_be(&t2.bytes);
    let alpha_squared = (&alpha_value * &alpha_value) % &order;
    let t2_scale = (&alpha_squared * t2_value) % &order;
    let masked = add_witness_points(anchored, scale_witness_point(mask, &alpha_value)?)?;
    add_witness_points(
        masked,
        SecpEncodedPointWitness::from_point_value(scale_point_value(
            standard_generator(),
            &t2_scale,
        )),
    )
}

fn parse_pair(encoded: [u8; 65]) -> Result<CircuitPointPairWitnessV4, RelationError> {
    if encoded[0] > 3 {
        return Err(RelationError::Malformed("certificate V4 point pair"));
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
    let parity_mask = 2u8 >> index;
    if x == [0; 32] {
        if pair[0] & parity_mask != 0 {
            return Err(RelationError::Malformed("signed certificate pair identity"));
        }
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair[0] & parity_mask != 0);
    encoded[1..].copy_from_slice(x);
    SecpEncodedPointWitness::parse(encoded)
}

fn parse_xonly(encoded: [u8; 32]) -> Result<SecpEncodedPointWitness, RelationError> {
    let mut point = [0; 33];
    point[0] = 2;
    point[1..].copy_from_slice(&encoded);
    parse_finite_point(point)
}

fn parse_finite_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, RelationError> {
    let point = SecpEncodedPointWitness::parse(encoded)?;
    if point.encoded == [0; 33] {
        return Err(RelationError::Malformed("identity certificate point"));
    }
    Ok(point)
}

fn parse_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, RelationError> {
    let scalar = SecpScalarWitness::from_bytes_be(encoded);
    canonical_scalar_value(scalar)?;
    Ok(scalar)
}

fn parse_nonzero_scalar(
    encoded: [u8; 32],
    label: &'static str,
) -> Result<SecpScalarWitness, RelationError> {
    let scalar = parse_scalar(encoded)?;
    if scalar.bytes == [0; 32] {
        return Err(RelationError::Malformed(label));
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn generator() -> SecpEncodedPointWitness {
        SecpEncodedPointWitness::from_point_value(standard_generator())
    }

    fn scalar(value: u8) -> [u8; 32] {
        let mut encoded = [0; 32];
        encoded[31] = value;
        encoded
    }

    fn encoded_proof() -> [u8; CERTIFICATE_NONCE_PROOF_BYTES] {
        let mut encoded = [0; CERTIFICATE_NONCE_PROOF_BYTES];
        encoded[0] = NONCE_PROOF_VERSION;
        encoded[1..33].copy_from_slice(&GENERATOR_X);
        encoded[33..66].copy_from_slice(&generator().encoded);
        encoded[66..99].copy_from_slice(&generator().encoded);
        encoded[99..132].copy_from_slice(&generator().encoded);
        encoded[164..196].copy_from_slice(&GENERATOR_X);
        encoded[196..228].copy_from_slice(&scalar(1));
        encoded
    }

    fn constants() -> CertificateLeafParentConstantsWitness {
        CertificateLeafParentConstantsWitness {
            circuit_binding_digest: [0x31; 32],
            coefficient_commitment: generator(),
            anchored_offset: SecpEncodedPointWitness::identity(),
        }
    }

    fn expected_precommitment(
        proof: &CertificateNonceProofWitnessV4,
        constants: CertificateLeafParentConstantsWitness,
    ) -> SecpScalarWitness {
        let anchored = add_witness_points(proof.raw_commitment, constants.anchored_offset)
            .expect("anchored commitment");
        let witness = CircuitProofTranscriptWitnessV4 {
            public_commitments: vec![proof.commitment],
            raw_commitment: proof.raw_commitment,
            coefficient_commitment: constants.coefficient_commitment,
            anchored_offset: constants.anchored_offset,
            anchored_commitment: anchored,
            batched_public_commitment: proof.commitment,
            dlog_nonce: proof.dlog_nonce,
            dlog_response: proof.dlog_response,
            mask_commitment: proof.mask_commitment,
            t2: proof.t2,
            combined_commitment: generator(),
            rounds: proof.rounds.clone(),
            terminal_n: proof.terminal_n,
            terminal_l: proof.terminal_l,
        };
        replay_circuit_transcript_v4(
            certificate_leaf_shape(),
            constants.circuit_binding_digest,
            crate::certificate_profile::CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
            &witness,
        )
        .expect("certificate transcript")
        .precommitment
    }

    #[test]
    fn parses_and_reconstructs_the_exact_v4_transcript() {
        let proof = CertificateNonceProofWitnessV4::parse(encoded_proof())
            .expect("certificate nonce proof");
        let constants = constants();
        let expected = expected_precommitment(&proof, constants);
        let transcript = proof
            .transcript(constants, expected)
            .expect("reconstructed transcript");

        assert_eq!(transcript.public_commitments, vec![generator()]);
        assert_eq!(transcript.batched_public_commitment, generator());
        assert_eq!(transcript.coefficient_commitment, generator());
        assert_eq!(
            transcript.anchored_offset,
            SecpEncodedPointWitness::identity(),
        );
        assert_eq!(transcript.anchored_commitment, generator());
        assert_eq!(
            replay_circuit_transcript_v4(
                certificate_leaf_shape(),
                constants.circuit_binding_digest,
                crate::certificate_profile::CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
                &transcript,
            )
            .expect("replayed transcript")
            .precommitment,
            expected,
        );
    }

    #[test]
    fn rejects_malformed_proofs_and_wrong_precommitments() {
        let mut wrong_version = encoded_proof();
        wrong_version[0] ^= 1;
        assert!(CertificateNonceProofWitnessV4::parse(wrong_version,).is_err());

        let mut wrong_nonce = encoded_proof();
        wrong_nonce[1] ^= 1;
        assert!(CertificateNonceProofWitnessV4::parse(wrong_nonce).is_err());

        let mut wrong_point = encoded_proof();
        wrong_point[66] = 4;
        assert!(CertificateNonceProofWitnessV4::parse(wrong_point).is_err());

        let proof = CertificateNonceProofWitnessV4::parse(encoded_proof())
            .expect("certificate nonce proof");
        let mut wrong_precommitment = expected_precommitment(&proof, constants());
        wrong_precommitment.bytes[31] ^= 1;
        assert!(proof.transcript(constants(), wrong_precommitment).is_err());
    }
}
