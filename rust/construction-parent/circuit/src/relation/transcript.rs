//! The V4 circuit-proof transcript inside the relation.
//!
//! The schedule is `native::circuit_transcript::replay_v4`, shared with the
//! native replay. This module supplies its constrained backend: each witness
//! value is allocated where the schedule first names it, the hidden/public
//! mode rules become constraints, and Nova supplies SHA-256 and the curve.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::gadgets::ops::Ops;
use crate::gadgets::point::EncodedPoint;
use crate::gadgets::scalar::CanonicalScalar;
use crate::gadgets::sha256::{Byte, Transcript};
use crate::gadgets::synthesis_error;
use crate::gadgets::transcript::{
    append_bytes, append_constant_bytes, append_point, append_scalar,
};
use crate::native::circuit_transcript::{
    replay_v4, CircuitPointPair, CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
    CircuitTranscriptV4, TranscriptBackend,
};
use crate::native::secp::{SecpEncodedPointWitness, SecpScalarWitness};
use statement::{RelationError, Scalar};

pub(crate) type CircuitPointPairV4 = CircuitPointPair<EncodedPoint>;
pub(crate) type CircuitTranscriptResultV4 = CircuitTranscriptV4<EncodedPoint, CanonicalScalar>;

/// The constrained backend of the V4 schedule.
struct Constrained<CS> {
    ops: Ops<CS>,
}

impl<CS: ConstraintSystem<Scalar>> TranscriptBackend for Constrained<CS> {
    type Transcript = Transcript;
    type Digest = [Byte; 32];
    type Point = EncodedPoint;
    type Scalar = CanonicalScalar;
    type Error = SynthesisError;

    fn malformed(error: RelationError) -> SynthesisError {
        let RelationError::Malformed(label) = error;
        synthesis_error(label)
    }

    fn new_transcript() -> Transcript {
        Transcript::new()
    }

    #[track_caller]
    fn point(&mut self, witness: SecpEncodedPointWitness) -> Result<EncodedPoint, SynthesisError> {
        self.ops.point(witness)
    }

    #[track_caller]
    fn scalar(&mut self, witness: SecpScalarWitness) -> Result<CanonicalScalar, SynthesisError> {
        self.ops.scalar(witness)
    }

    #[track_caller]
    fn challenge(
        &mut self,
        transcript: &mut Transcript,
        round: u64,
    ) -> Result<CanonicalScalar, SynthesisError> {
        self.ops.challenge(transcript, round)
    }

    fn append_constant(transcript: &mut Transcript, bytes: &[u8]) -> Result<(), SynthesisError> {
        append_constant_bytes(transcript, bytes)
    }

    fn append_digest(
        transcript: &mut Transcript,
        digest: &[Byte; 32],
    ) -> Result<(), SynthesisError> {
        append_bytes(transcript, digest)
    }

    fn append_u64(transcript: &mut Transcript, value: u64) {
        transcript.append_u64(value);
    }

    fn append_scalar(
        transcript: &mut Transcript,
        scalar: &CanonicalScalar,
    ) -> Result<(), SynthesisError> {
        append_scalar(transcript, scalar)
    }

    fn append_point(
        transcript: &mut Transcript,
        point: &EncodedPoint,
    ) -> Result<(), SynthesisError> {
        append_point(transcript, point);
        Ok(())
    }

    fn append_point_x(
        transcript: &mut Transcript,
        point: &EncodedPoint,
    ) -> Result<(), SynthesisError> {
        append_bytes(transcript, point.x_bytes())
    }

    fn append_point_pair(
        transcript: &mut Transcript,
        pair: &CircuitPointPairV4,
    ) -> Result<(), SynthesisError> {
        let parity = Byte::from_constrained_bits_le([
            pair.second.odd().clone(),
            pair.first.odd().clone(),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
        ]);
        transcript.append_point_pair(&parity, pair.first.x_bytes(), pair.second.x_bytes());
        Ok(())
    }

    #[track_caller]
    fn require_identity(&mut self, point: &EncodedPoint) -> Result<(), SynthesisError> {
        self.ops.require_identity(point.point())
    }

    #[track_caller]
    fn require_finite_even(&mut self, point: &EncodedPoint) -> Result<(), SynthesisError> {
        self.ops.require_finite(point.point())?;
        self.ops.require_even(point)
    }

    #[track_caller]
    fn require_zero(&mut self, scalar: &CanonicalScalar) -> Result<(), SynthesisError> {
        self.ops.require_zero(scalar);
        Ok(())
    }
}

/// Replays the V4 transcript inside the relation, bound to a constrained
/// statement digest.
pub(crate) fn install_transcript_with_constrained_binding<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: &[Byte; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<CircuitTranscriptResultV4, SynthesisError> {
    shape
        .validate()
        .map_err(|_| synthesis_error("V4 transcript shape"))?;
    if witness.public_commitments.len() != shape.public_commitment_count()
        || witness.rounds.len() != shape.round_count()
    {
        return Err(synthesis_error("V4 transcript witness shape"));
    }
    replay_v4(
        &mut Constrained { ops: Ops::new(cs) },
        shape,
        circuit_binding_digest,
        raw_generator_digest,
        witness,
    )
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
    use crate::native::circuit_transcript::{
        replay_circuit_transcript_v4, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
    };
    use crate::native::secp::SecpScalarWitness;
    use statement::PrimaryEngine;

    pub(crate) fn install_transcript<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        shape: CircuitTranscriptShapeV4,
        circuit_binding_digest: [u8; 32],
        raw_generator_digest: [u8; 32],
        witness: &CircuitProofTranscriptWitnessV4,
    ) -> Result<CircuitTranscriptResultV4, SynthesisError> {
        install_transcript_with_constrained_binding(
            cs,
            shape,
            &circuit_binding_digest.map(Byte::constant),
            raw_generator_digest,
            witness,
        )
    }

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

    fn constrained_integer(value: &CanonicalScalar) -> BigInt {
        value.integer().expect("direct scalar witness").clone()
    }

    fn witness_integer(value: SecpScalarWitness) -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, &value.bytes)
    }

    fn constrained_scalars(result: &CircuitTranscriptResultV4) -> Vec<BigInt> {
        let mut values = vec![
            constrained_integer(&result.dlog_response),
            constrained_integer(&result.t2),
            constrained_integer(&result.terminal_n),
            constrained_integer(&result.terminal_l),
            constrained_integer(&result.precommitment),
            constrained_integer(&result.rho),
            constrained_integer(&result.mul_scale),
            constrained_integer(&result.mul_ratio),
            constrained_integer(&result.row_ratio),
            constrained_integer(&result.eta),
            constrained_integer(&result.dlog_challenge),
            constrained_integer(&result.alpha),
            constrained_integer(&result.prepared_binding),
        ];
        values.extend(result.gammas.iter().map(constrained_integer));
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

    fn constrained_challenges(result: &CircuitTranscriptResultV4) -> Vec<BigInt> {
        let mut challenges = vec![
            constrained_integer(&result.precommitment),
            constrained_integer(&result.rho),
            constrained_integer(&result.mul_scale),
            constrained_integer(&result.mul_ratio),
            constrained_integer(&result.row_ratio),
            constrained_integer(&result.eta),
            constrained_integer(&result.dlog_challenge),
            constrained_integer(&result.alpha),
            constrained_integer(&result.prepared_binding),
        ];
        challenges.extend(result.gammas.iter().map(constrained_integer));
        challenges
    }

    fn assert_point_witnesses(result: &CircuitTranscriptResultV4) {
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
    fn constrained_replay_matches_native_vectors_for_hidden_and_public_modes() {
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
            assert_eq!(constrained_scalars(&result), expected);
            assert_eq!(
                constrained_challenges(&result),
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
            Byte::allocate(
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
        assert_eq!(
            constrained_scalars(&constant),
            constrained_scalars(&constrained)
        );
        assert!(constant_cs.is_satisfied());
        assert!(constrained_cs.is_satisfied());
    }

    fn synthesize_shape(
        mode: CircuitCommitmentModeV4,
        witness: &CircuitProofTranscriptWitnessV4,
    ) -> ShapeCS<PrimaryEngine> {
        let mut cs = ShapeCS::<PrimaryEngine>::new();
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
    fn constrained_replay_shape_excludes_point_and_scalar_witnesses() {
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
    fn constrained_replay_rejects_branch_and_pair_violations() {
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
