//! Direct Nova replay of the V4 circuit-proof transcript.
//!
//! Protocol bytes are shared with the native transcript. Nova supplies the
//! SHA-256 and curve gadgets; this module only orders typed fields and applies
//! the V4 hidden/public branch constraints.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::circuit_transcript::{
    CircuitCommitmentModeV4, CircuitPointPairWitnessV4, CircuitProofTranscriptWitnessV4,
    CircuitTranscriptShapeV4, CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4, CIRCUIT_NORM_PROOF_DOMAIN_V4,
};
use crate::nova_protocol_transcript::{
    append_bytes, append_constant_bytes, append_point, append_scalar, challenge,
};
use crate::nova_secp::{allocate_encoded_point, DirectEncodedSecpPoint};
use crate::nova_secp_scalar::{allocate_canonical_scalar, CanonicalSecpScalar};
use crate::nova_sha256_transcript::{NovaByte, NovaTranscript};
use crate::secp_native::SecpEncodedPointWitness;
use crate::Scalar;

pub(crate) struct DirectCircuitPointPairV4 {
    pub(crate) first: DirectEncodedSecpPoint,
    pub(crate) second: DirectEncodedSecpPoint,
}

pub(crate) struct DirectCircuitTranscriptResultV4 {
    pub(crate) public_commitments: Vec<DirectEncodedSecpPoint>,
    pub(crate) raw_commitment: DirectEncodedSecpPoint,
    pub(crate) coefficient_commitment: DirectEncodedSecpPoint,
    pub(crate) anchored_offset: DirectEncodedSecpPoint,
    pub(crate) anchored_commitment: DirectEncodedSecpPoint,
    pub(crate) batched_public_commitment: DirectEncodedSecpPoint,
    pub(crate) dlog_nonce: DirectEncodedSecpPoint,
    pub(crate) dlog_response: CanonicalSecpScalar,
    pub(crate) mask_commitment: DirectEncodedSecpPoint,
    pub(crate) t2: CanonicalSecpScalar,
    pub(crate) combined_commitment: DirectEncodedSecpPoint,
    pub(crate) rounds: Vec<DirectCircuitPointPairV4>,
    pub(crate) terminal_n: CanonicalSecpScalar,
    pub(crate) terminal_l: CanonicalSecpScalar,
    pub(crate) precommitment: CanonicalSecpScalar,
    pub(crate) rho: CanonicalSecpScalar,
    pub(crate) mul_scale: CanonicalSecpScalar,
    pub(crate) mul_ratio: CanonicalSecpScalar,
    pub(crate) row_ratio: CanonicalSecpScalar,
    pub(crate) eta: CanonicalSecpScalar,
    pub(crate) dlog_challenge: CanonicalSecpScalar,
    pub(crate) alpha: CanonicalSecpScalar,
    pub(crate) gammas: Vec<CanonicalSecpScalar>,
    pub(crate) prepared_binding: CanonicalSecpScalar,
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn append_shape(
    transcript: &mut NovaTranscript,
    shape: CircuitTranscriptShapeV4,
) -> Result<(), SynthesisError> {
    transcript.append_u64(shape.mode.as_u64());
    for value in [
        shape.gate_count,
        shape.commitment_count,
        shape.n_vec_len,
        shape.l_vec_len,
        shape.public_commitment_count(),
    ] {
        transcript.append_u64(
            u64::try_from(value).map_err(|_| synthesis_error("V4 transcript shape size"))?,
        );
    }
    Ok(())
}

fn pair_point(
    pair: &CircuitPointPairWitnessV4,
    index: usize,
) -> Result<SecpEncodedPointWitness, SynthesisError> {
    if pair.encoded[0] > 3 || index > 1 {
        return Err(synthesis_error("V4 point pair"));
    }
    let offset = 1 + 32 * index;
    let x = &pair.encoded[offset..offset + 32];
    let mask = 2u8 >> index;
    let y = if index == 0 {
        pair.first_y
    } else {
        pair.second_y
    };
    if x.iter().all(|byte| *byte == 0) {
        if pair.encoded[0] & mask != 0 {
            return Err(synthesis_error("V4 signed pair identity"));
        }
        return Ok(SecpEncodedPointWitness {
            encoded: [0; 33],
            y,
        });
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair.encoded[0] & mask != 0);
    encoded[1..].copy_from_slice(x);
    Ok(SecpEncodedPointWitness { encoded, y })
}

fn append_pair<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &mut NovaTranscript,
    witness: &CircuitPointPairWitnessV4,
) -> Result<DirectCircuitPointPairV4, SynthesisError> {
    let first = allocate_encoded_point(cs.namespace(|| "first point"), pair_point(witness, 0)?)?;
    let second = allocate_encoded_point(cs.namespace(|| "second point"), pair_point(witness, 1)?)?;
    let parity = NovaByte::from_constrained_bits_le([
        second.odd().clone(),
        first.odd().clone(),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
        Boolean::constant(false),
    ]);
    transcript.append_point_pair(&parity, first.x_bytes(), second.x_bytes());
    Ok(DirectCircuitPointPairV4 { first, second })
}

fn require_identity<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    point: &DirectEncodedSecpPoint,
) -> Result<(), SynthesisError> {
    Boolean::enforce_equal(cs, &point.point().is_identity(), &Boolean::constant(true))
}

fn require_finite_even<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &DirectEncodedSecpPoint,
) -> Result<(), SynthesisError> {
    Boolean::enforce_equal(
        cs.namespace(|| "finite"),
        &point.point().is_identity(),
        &Boolean::constant(false),
    )?;
    Boolean::enforce_equal(
        cs.namespace(|| "even"),
        point.odd(),
        &Boolean::constant(false),
    )
}

fn require_zero_scalar<CS: ConstraintSystem<Scalar>>(mut cs: CS, value: &CanonicalSecpScalar) {
    let embedded = value.embedded();
    cs.enforce(|| "zero scalar", |_| embedded, |lc| lc + CS::one(), |lc| lc);
}

fn install_transcript_with_binding<CS, F>(
    mut cs: CS,
    shape: CircuitTranscriptShapeV4,
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
    append_binding: F,
) -> Result<DirectCircuitTranscriptResultV4, SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
    F: FnOnce(&mut NovaTranscript) -> Result<(), SynthesisError>,
{
    shape
        .validate()
        .map_err(|_| synthesis_error("V4 transcript shape"))?;
    if witness.public_commitments.len() != shape.public_commitment_count()
        || witness.rounds.len() != shape.round_count()
    {
        return Err(synthesis_error("V4 transcript witness shape"));
    }

    let mut precommit = NovaTranscript::new();
    append_constant_bytes(&mut precommit, CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4)?;
    append_binding(&mut precommit)?;
    append_shape(&mut precommit, shape)?;
    let mut public_commitments = Vec::with_capacity(witness.public_commitments.len());
    for (index, point) in witness.public_commitments.iter().copied().enumerate() {
        let point =
            allocate_encoded_point(cs.namespace(|| format!("public commitment {index}")), point)?;
        append_point(&mut precommit, &point);
        public_commitments.push(point);
    }
    let raw_commitment =
        allocate_encoded_point(cs.namespace(|| "raw commitment"), witness.raw_commitment)?;
    append_point(&mut precommit, &raw_commitment);
    let precommitment = challenge(cs.namespace(|| "precommitment"), &mut precommit, 0)?;

    let mut proof = NovaTranscript::new();
    append_constant_bytes(&mut proof, CIRCUIT_NORM_PROOF_DOMAIN_V4)?;
    append_scalar(&mut proof, &precommitment)?;
    append_constant_bytes(&mut proof, &raw_generator_digest)?;
    append_shape(&mut proof, shape)?;
    let rho = challenge(cs.namespace(|| "rho"), &mut proof, 0)?;
    let mul_scale = challenge(cs.namespace(|| "mul scale"), &mut proof, 1)?;
    let mul_ratio = challenge(cs.namespace(|| "mul ratio"), &mut proof, 2)?;
    let row_ratio = challenge(cs.namespace(|| "row ratio"), &mut proof, 3)?;

    let coefficient_commitment = allocate_encoded_point(
        cs.namespace(|| "coefficient commitment"),
        witness.coefficient_commitment,
    )?;
    append_point(&mut proof, &coefficient_commitment);
    let anchored_offset =
        allocate_encoded_point(cs.namespace(|| "anchored offset"), witness.anchored_offset)?;
    append_point(&mut proof, &anchored_offset);
    let anchored_commitment = allocate_encoded_point(
        cs.namespace(|| "anchored commitment"),
        witness.anchored_commitment,
    )?;
    append_point(&mut proof, &anchored_commitment);
    let eta = challenge(cs.namespace(|| "eta"), &mut proof, 4)?;
    let batched_public_commitment = allocate_encoded_point(
        cs.namespace(|| "batched public commitment"),
        witness.batched_public_commitment,
    )?;
    append_point(&mut proof, &batched_public_commitment);
    let dlog_nonce = allocate_encoded_point(cs.namespace(|| "dlog nonce"), witness.dlog_nonce)?;
    match shape.mode {
        CircuitCommitmentModeV4::Hidden => {
            require_identity(
                cs.namespace(|| "hidden batched commitment"),
                &batched_public_commitment,
            )?;
            require_identity(cs.namespace(|| "hidden dlog nonce"), &dlog_nonce)?;
        }
        CircuitCommitmentModeV4::Public => {
            require_finite_even(cs.namespace(|| "public dlog nonce"), &dlog_nonce)?;
        }
    }
    append_bytes(&mut proof, dlog_nonce.x_bytes())?;
    let dlog_challenge = challenge(cs.namespace(|| "dlog challenge"), &mut proof, 5)?;
    let dlog_response =
        allocate_canonical_scalar(cs.namespace(|| "dlog response"), witness.dlog_response)?;
    if shape.mode == CircuitCommitmentModeV4::Hidden {
        require_zero_scalar(cs.namespace(|| "hidden dlog response"), &dlog_response);
    }
    append_scalar(&mut proof, &dlog_response)?;

    let mask_commitment =
        allocate_encoded_point(cs.namespace(|| "mask commitment"), witness.mask_commitment)?;
    append_point(&mut proof, &mask_commitment);
    let t2 = allocate_canonical_scalar(cs.namespace(|| "t2"), witness.t2)?;
    append_scalar(&mut proof, &t2)?;
    let alpha = challenge(cs.namespace(|| "alpha"), &mut proof, 6)?;
    let combined_commitment = allocate_encoded_point(
        cs.namespace(|| "combined commitment"),
        witness.combined_commitment,
    )?;
    append_point(&mut proof, &combined_commitment);

    let mut rounds = Vec::with_capacity(witness.rounds.len());
    let mut gammas = Vec::with_capacity(witness.rounds.len());
    for (round, pair) in witness.rounds.iter().enumerate() {
        rounds.push(append_pair(
            cs.namespace(|| format!("round pair {round}")),
            &mut proof,
            pair,
        )?);
        let round = u64::try_from(round).map_err(|_| synthesis_error("V4 round"))?;
        gammas.push(challenge(
            cs.namespace(|| format!("gamma {round}")),
            &mut proof,
            7 + round,
        )?);
    }
    let terminal_n = allocate_canonical_scalar(cs.namespace(|| "terminal n"), witness.terminal_n)?;
    let terminal_l = allocate_canonical_scalar(cs.namespace(|| "terminal l"), witness.terminal_l)?;
    append_scalar(&mut proof, &terminal_n)?;
    append_scalar(&mut proof, &terminal_l)?;
    let prepared_round = 7 + u64::try_from(witness.rounds.len())
        .map_err(|_| synthesis_error("V4 transcript rounds"))?;
    let prepared_binding = challenge(
        cs.namespace(|| "prepared binding"),
        &mut proof,
        prepared_round,
    )?;

    Ok(DirectCircuitTranscriptResultV4 {
        public_commitments,
        raw_commitment,
        coefficient_commitment,
        anchored_offset,
        anchored_commitment,
        batched_public_commitment,
        dlog_nonce,
        dlog_response,
        mask_commitment,
        t2,
        combined_commitment,
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

pub(crate) fn install_transcript<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: [u8; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<DirectCircuitTranscriptResultV4, SynthesisError> {
    install_transcript_with_binding(cs, shape, raw_generator_digest, witness, |transcript| {
        append_constant_bytes(transcript, &circuit_binding_digest)
    })
}

pub(crate) fn install_transcript_with_constrained_binding<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: &[NovaByte; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<DirectCircuitTranscriptResultV4, SynthesisError> {
    install_transcript_with_binding(cs, shape, raw_generator_digest, witness, |transcript| {
        append_bytes(transcript, circuit_binding_digest)
    })
}

#[cfg(test)]
mod tests {
    use std::array;

    use nova_snark::frontend::{
        shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem,
    };
    use num_bigint::{BigInt, Sign};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::circuit_transcript::replay_circuit_transcript_v4;
    use crate::nova_types::DirectNovaPrimaryEngine;
    use crate::secp_native::SecpScalarWitness;

    const BINDING_DIGEST: [u8; 32] = [0x31; 32];
    const GENERATOR_DIGEST: [u8; 32] = [0x52; 32];
    const HIDDEN_CHALLENGE_DIGEST: [u8; 32] = [
        0x18, 0x74, 0x23, 0x17, 0x9a, 0x90, 0x31, 0x1e, 0xf9, 0x69, 0xc0, 0x1c, 0xa0, 0x11, 0x23,
        0x06, 0xc7, 0x09, 0xe9, 0x4c, 0x82, 0xf5, 0x56, 0xf5, 0x5d, 0x10, 0x17, 0xc8, 0x4a, 0xba,
        0x73, 0x6a,
    ];
    const PUBLIC_CHALLENGE_DIGEST: [u8; 32] = [
        0x35, 0x58, 0x5c, 0x63, 0x91, 0x26, 0x9a, 0xa9, 0x34, 0x61, 0x93, 0x29, 0xaf, 0x20, 0xe9,
        0xa0, 0xc0, 0x26, 0xe4, 0xb2, 0x07, 0xe0, 0x06, 0x10, 0x2e, 0xc2, 0x66, 0xaa, 0x96, 0x70,
        0xde, 0x96,
    ];
    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn generator(prefix: u8) -> SecpEncodedPointWitness {
        let mut encoded = [0u8; 33];
        encoded[0] = prefix;
        encoded[1..].copy_from_slice(&GENERATOR_X);
        SecpEncodedPointWitness::parse(encoded).expect("generator point")
    }

    fn finite_pair() -> CircuitPointPairWitnessV4 {
        let first = generator(2);
        let second = generator(3);
        let mut encoded = [0u8; 65];
        // First is even and second is odd: bit zero carries second parity.
        encoded[0] = 1;
        encoded[1..33].copy_from_slice(&GENERATOR_X);
        encoded[33..].copy_from_slice(&GENERATOR_X);
        CircuitPointPairWitnessV4 {
            encoded,
            first_y: first.y,
            second_y: second.y,
        }
    }

    fn shape(mode: CircuitCommitmentModeV4) -> CircuitTranscriptShapeV4 {
        CircuitTranscriptShapeV4 {
            mode,
            gate_count: 8,
            commitment_count: 1,
            n_vec_len: 16,
            l_vec_len: 16,
        }
    }

    fn witness(mode: CircuitCommitmentModeV4) -> CircuitProofTranscriptWitnessV4 {
        let even = generator(2);
        let odd = generator(3);
        let identity = SecpEncodedPointWitness::identity();
        CircuitProofTranscriptWitnessV4 {
            public_commitments: match mode {
                CircuitCommitmentModeV4::Hidden => Vec::new(),
                CircuitCommitmentModeV4::Public => vec![even],
            },
            raw_commitment: even,
            coefficient_commitment: odd,
            anchored_offset: identity,
            anchored_commitment: even,
            batched_public_commitment: match mode {
                CircuitCommitmentModeV4::Hidden => identity,
                CircuitCommitmentModeV4::Public => even,
            },
            dlog_nonce: match mode {
                CircuitCommitmentModeV4::Hidden => identity,
                CircuitCommitmentModeV4::Public => even,
            },
            dlog_response: SecpScalarWitness::from_u64(match mode {
                CircuitCommitmentModeV4::Hidden => 0,
                CircuitCommitmentModeV4::Public => 7,
            }),
            mask_commitment: odd,
            t2: SecpScalarWitness::from_u64(8),
            combined_commitment: even,
            rounds: vec![finite_pair(); shape(mode).round_count()],
            terminal_n: SecpScalarWitness::from_u64(9),
            terminal_l: SecpScalarWitness::from_u64(10),
        }
    }

    fn direct_integer(value: &CanonicalSecpScalar) -> BigInt {
        value.integer().expect("direct scalar witness").clone()
    }

    fn witness_integer(value: SecpScalarWitness) -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, &value.bytes)
    }

    fn direct_scalars(result: &DirectCircuitTranscriptResultV4) -> Vec<BigInt> {
        let mut values = vec![
            direct_integer(&result.dlog_response),
            direct_integer(&result.t2),
            direct_integer(&result.terminal_n),
            direct_integer(&result.terminal_l),
            direct_integer(&result.precommitment),
            direct_integer(&result.rho),
            direct_integer(&result.mul_scale),
            direct_integer(&result.mul_ratio),
            direct_integer(&result.row_ratio),
            direct_integer(&result.eta),
            direct_integer(&result.dlog_challenge),
            direct_integer(&result.alpha),
            direct_integer(&result.prepared_binding),
        ];
        values.extend(result.gammas.iter().map(direct_integer));
        values
    }

    fn native_values(
        mode: CircuitCommitmentModeV4,
        witness: &CircuitProofTranscriptWitnessV4,
    ) -> Vec<BigInt> {
        let mut values = vec![
            witness_integer(witness.dlog_response),
            witness_integer(witness.t2),
            witness_integer(witness.terminal_n),
            witness_integer(witness.terminal_l),
        ];
        values.extend(native_challenges(mode, witness));
        values
    }

    fn native_challenges(
        mode: CircuitCommitmentModeV4,
        witness: &CircuitProofTranscriptWitnessV4,
    ) -> Vec<BigInt> {
        let replay =
            replay_circuit_transcript_v4(shape(mode), BINDING_DIGEST, GENERATOR_DIGEST, witness)
                .expect("native V4 transcript");
        let mut challenges = vec![
            replay.precommitment,
            replay.rho,
            replay.mul_scale,
            replay.mul_ratio,
            replay.row_ratio,
            replay.eta,
            replay.dlog_challenge,
            replay.alpha,
            replay.prepared_binding,
        ]
        .into_iter()
        .map(witness_integer)
        .collect::<Vec<_>>();
        challenges.extend(replay.gammas.into_iter().map(witness_integer));
        challenges
    }

    fn scalar_vector_digest(values: &[BigInt]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(
            u64::try_from(values.len())
                .expect("challenge count fits in u64")
                .to_be_bytes(),
        );
        for value in values {
            let (sign, bytes) = value.to_bytes_be();
            assert_ne!(sign, Sign::Minus);
            assert!(bytes.len() <= 32);
            let mut encoded = [0u8; 32];
            encoded[32 - bytes.len()..].copy_from_slice(&bytes);
            digest.update(encoded);
        }
        digest.finalize().into()
    }

    fn direct_challenges(result: &DirectCircuitTranscriptResultV4) -> Vec<BigInt> {
        let mut challenges = vec![
            direct_integer(&result.precommitment),
            direct_integer(&result.rho),
            direct_integer(&result.mul_scale),
            direct_integer(&result.mul_ratio),
            direct_integer(&result.row_ratio),
            direct_integer(&result.eta),
            direct_integer(&result.dlog_challenge),
            direct_integer(&result.alpha),
            direct_integer(&result.prepared_binding),
        ];
        challenges.extend(result.gammas.iter().map(direct_integer));
        challenges
    }

    fn assert_point_witnesses(result: &DirectCircuitTranscriptResultV4) {
        let points = [
            &result.raw_commitment,
            &result.coefficient_commitment,
            &result.anchored_offset,
            &result.anchored_commitment,
            &result.batched_public_commitment,
            &result.dlog_nonce,
            &result.mask_commitment,
            &result.combined_commitment,
        ];
        assert!(points
            .iter()
            .all(|point| point.prefix().get_value().is_some()));
        assert!(result
            .public_commitments
            .iter()
            .all(|point| point.prefix().get_value().is_some()));
        assert!(result.rounds.iter().all(|pair| {
            pair.first.prefix().get_value().is_some() && pair.second.prefix().get_value().is_some()
        }));
    }

    #[test]
    fn direct_replay_matches_native_vectors_for_hidden_and_public_modes() {
        for mode in [
            CircuitCommitmentModeV4::Hidden,
            CircuitCommitmentModeV4::Public,
        ] {
            let witness = witness(mode);
            let expected = native_values(mode, &witness);
            let expected_digest = match mode {
                CircuitCommitmentModeV4::Hidden => HIDDEN_CHALLENGE_DIGEST,
                CircuitCommitmentModeV4::Public => PUBLIC_CHALLENGE_DIGEST,
            };
            assert_eq!(
                scalar_vector_digest(&native_challenges(mode, &witness)),
                expected_digest
            );
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = install_transcript(
                cs.namespace(|| "direct transcript"),
                shape(mode),
                BINDING_DIGEST,
                GENERATOR_DIGEST,
                &witness,
            )
            .expect("direct transcript");
            assert_eq!(direct_scalars(&result), expected);
            assert_eq!(
                direct_challenges(&result),
                native_challenges(mode, &witness)
            );
            assert_point_witnesses(&result);
            assert!(cs.is_satisfied(), "{:?}", cs.which_is_unsatisfied());
        }
    }

    #[test]
    fn constrained_binding_matches_constant_binding() {
        let mode = CircuitCommitmentModeV4::Public;
        let witness = witness(mode);
        let mut constant_cs = TestConstraintSystem::<Scalar>::new();
        let constant = install_transcript(
            constant_cs.namespace(|| "constant binding"),
            shape(mode),
            BINDING_DIGEST,
            GENERATOR_DIGEST,
            &witness,
        )
        .expect("constant binding transcript");

        let mut constrained_cs = TestConstraintSystem::<Scalar>::new();
        let constrained_binding = array::from_fn(|index| {
            NovaByte::allocate(
                constrained_cs.namespace(|| format!("binding byte {index}")),
                BINDING_DIGEST[index],
            )
            .expect("binding byte")
        });
        let constrained = install_transcript_with_constrained_binding(
            constrained_cs.namespace(|| "constrained binding"),
            shape(mode),
            &constrained_binding,
            GENERATOR_DIGEST,
            &witness,
        )
        .expect("constrained binding transcript");
        assert_eq!(direct_scalars(&constant), direct_scalars(&constrained));
        assert!(constant_cs.is_satisfied());
        assert!(constrained_cs.is_satisfied());
    }

    fn synthesize_shape(
        mode: CircuitCommitmentModeV4,
        witness: &CircuitProofTranscriptWitnessV4,
    ) -> ShapeCS<DirectNovaPrimaryEngine> {
        let mut cs = ShapeCS::<DirectNovaPrimaryEngine>::new();
        install_transcript(
            cs.namespace(|| "direct transcript"),
            shape(mode),
            BINDING_DIGEST,
            GENERATOR_DIGEST,
            witness,
        )
        .expect("shape synthesis");
        cs
    }

    #[test]
    fn direct_replay_shape_excludes_point_and_scalar_witnesses() {
        let mode = CircuitCommitmentModeV4::Public;
        let first_witness = witness(mode);
        let mut second_witness = first_witness.clone();
        second_witness.raw_commitment = SecpEncodedPointWitness::identity();
        second_witness.terminal_n = SecpScalarWitness::from_u64(12345);
        let first = synthesize_shape(mode, &first_witness);
        let second = synthesize_shape(mode, &second_witness);
        assert_eq!(first.num_inputs(), 1);
        assert_eq!(first.num_aux(), 808_304);
        assert_eq!(first.num_constraints(), 809_425);
        assert_eq!(first.num_inputs(), second.num_inputs());
        assert_eq!(first.num_aux(), second.num_aux());
        assert_eq!(first.constraints, second.constraints);
    }

    #[test]
    fn direct_replay_rejects_branch_and_pair_violations() {
        let hidden_mode = CircuitCommitmentModeV4::Hidden;
        let mut nonzero_response = witness(hidden_mode);
        nonzero_response.dlog_response = SecpScalarWitness::from_u64(1);
        let mut hidden_cs = TestConstraintSystem::<Scalar>::new();
        install_transcript(
            hidden_cs.namespace(|| "hidden transcript"),
            shape(hidden_mode),
            BINDING_DIGEST,
            GENERATOR_DIGEST,
            &nonzero_response,
        )
        .expect("hidden transcript shape");
        assert!(!hidden_cs.is_satisfied());

        let public_mode = CircuitCommitmentModeV4::Public;
        let mut odd_nonce = witness(public_mode);
        odd_nonce.dlog_nonce = generator(3);
        let mut public_cs = TestConstraintSystem::<Scalar>::new();
        install_transcript(
            public_cs.namespace(|| "public transcript"),
            shape(public_mode),
            BINDING_DIGEST,
            GENERATOR_DIGEST,
            &odd_nonce,
        )
        .expect("public transcript shape");
        assert!(!public_cs.is_satisfied());

        let mut malformed_pair = witness(public_mode);
        malformed_pair.rounds[0].encoded[0] = 4;
        assert!(install_transcript(
            TestConstraintSystem::<Scalar>::new(),
            shape(public_mode),
            BINDING_DIGEST,
            GENERATOR_DIGEST,
            &malformed_pair,
        )
        .is_err());
    }
}
