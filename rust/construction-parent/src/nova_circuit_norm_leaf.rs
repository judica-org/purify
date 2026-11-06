//! Direct Nova equations for one manifest-bound circuit-norm leaf.
//!
//! Transcript replay and coefficient reduction remain separate boundaries.
//! This module checks the outer proof equations and prepares the exact short
//! norm obligation consumed by the reduction.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::circuit_norm::{CandidateNormReductionProofWitness, ManifestBoundAnchorLeafStatementV4};
use crate::circuit_transcript::{
    CircuitCommitmentModeV4, CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
};
use crate::nova_candidate::{DirectPendingClaim, DirectPolynomialTerm};
use crate::nova_circuit_transcript::{
    install_transcript_with_constrained_binding, DirectCircuitTranscriptResultV4,
};
use crate::nova_norm_reduction::constrain_candidate_norm_reduction;
use crate::nova_secp::{
    add_points, allocate_constant_point, encode_computed_point, scale_point,
    DirectEncodedSecpPoint, DirectSecpPoint,
};
use crate::nova_secp_scalar::{
    constant_scalar, invert_scalar, multiply_scalars, subtract_scalars, CanonicalSecpScalar,
};
use crate::nova_sha256_transcript::NovaByte;
use crate::secp_native::{standard_generator, SecpScalarWitness};
use crate::Scalar;

// Inverse of the protocol's fixed even square root of minus one modulo the
// secp256k1 group order.
const SQRT_MINUS_ONE_INVERSE: SecpScalarWitness = SecpScalarWitness::from_bytes_be([
    0x8f, 0x52, 0xb6, 0x51, 0x80, 0x7a, 0x8b, 0x13, 0x54, 0x9b, 0xe5, 0xbd, 0x4c, 0x5d, 0xb0, 0xdb,
    0xe4, 0x77, 0x9c, 0xc3, 0x1a, 0xfb, 0xd9, 0xd6, 0x19, 0x15, 0xaf, 0xdb, 0xdc, 0xba, 0x81, 0xc9,
]);

pub(crate) struct DirectPreparedNorm {
    pub(crate) prepared_binding: CanonicalSecpScalar,
    pub(crate) coefficient_commitment: DirectEncodedSecpPoint,
    pub(crate) residual: DirectEncodedSecpPoint,
    pub(crate) polynomial: Vec<DirectPolynomialTerm>,
}

pub(crate) struct DirectManifestBoundAnchorLeaf {
    pub(crate) claim: DirectPendingClaim,
    pub(crate) circuit_binding_digest: [NovaByte; 32],
    pub(crate) precommitment: CanonicalSecpScalar,
    pub(crate) coefficient_commitment: DirectEncodedSecpPoint,
    pub(crate) anchored_offset: DirectEncodedSecpPoint,
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn small_constant<CS: ConstraintSystem<Scalar>>(
    value: u64,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    constant_scalar::<CS>(SecpScalarWitness::from_u64(value))
}

fn require_finite<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    point: &DirectSecpPoint,
) -> Result<(), SynthesisError> {
    Boolean::enforce_equal(cs, &point.is_identity(), &Boolean::constant(false))
}

fn scale<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &DirectSecpPoint,
    scalar: &CanonicalSecpScalar,
) -> Result<DirectSecpPoint, SynthesisError> {
    let bits = scalar.allocated_bits_le(cs.namespace(|| "scalar bits"))?;
    scale_point(cs.namespace(|| "scalar multiplication"), point, &bits)
}

fn square_repeatedly<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &CanonicalSecpScalar,
    count: usize,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let mut result = value.clone();
    for round in 0..count {
        result = multiply_scalars(cs.namespace(|| format!("square {round}")), &result, &result)?;
    }
    Ok(result)
}

fn constrain_anchor_and_mask<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &DirectCircuitTranscriptResultV4,
    generator: &DirectSecpPoint,
) -> Result<(), SynthesisError> {
    require_finite(
        cs.namespace(|| "raw commitment is finite"),
        transcript.raw_commitment.point(),
    )?;
    require_finite(
        cs.namespace(|| "mask commitment is finite"),
        transcript.mask_commitment.point(),
    )?;
    let anchored = add_points(
        cs.namespace(|| "anchored commitment"),
        transcript.raw_commitment.point(),
        transcript.anchored_offset.point(),
    )?;
    require_finite(cs.namespace(|| "anchor is finite"), &anchored)?;
    anchored.enforce_equal(
        cs.namespace(|| "anchor equality"),
        transcript.anchored_commitment.point(),
    )?;

    let alpha_squared = multiply_scalars(
        cs.namespace(|| "alpha squared"),
        &transcript.alpha,
        &transcript.alpha,
    )?;
    let t2_scale = multiply_scalars(cs.namespace(|| "t2 scale"), &alpha_squared, &transcript.t2)?;
    let scaled_mask = scale(
        cs.namespace(|| "scaled mask"),
        transcript.mask_commitment.point(),
        &transcript.alpha,
    )?;
    let masked = add_points(
        cs.namespace(|| "masked commitment"),
        transcript.anchored_commitment.point(),
        &scaled_mask,
    )?;
    let t2_point = scale(cs.namespace(|| "t2 point"), generator, &t2_scale)?;
    let combined = add_points(cs.namespace(|| "combined commitment"), &masked, &t2_point)?;
    require_finite(cs.namespace(|| "combined is finite"), &combined)?;
    combined.enforce_equal(
        cs.namespace(|| "combined equality"),
        transcript.combined_commitment.point(),
    )
}

fn constrain_public_commitment_batch<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &DirectCircuitTranscriptResultV4,
) -> Result<(), SynthesisError> {
    let (first, rest) = transcript
        .public_commitments
        .split_first()
        .ok_or_else(|| synthesis_error("public V4 circuit norm commitments"))?;
    require_finite(
        cs.namespace(|| "public commitment 0 is finite"),
        first.point(),
    )?;
    let mut batched = first.point().clone();
    let mut weight = transcript.eta.clone();
    for (index, point) in rest.iter().enumerate() {
        require_finite(
            cs.namespace(|| format!("public commitment {} is finite", index + 1)),
            point.point(),
        )?;
        let term = scale(
            cs.namespace(|| format!("public commitment {} scale", index + 1)),
            point.point(),
            &weight,
        )?;
        batched = add_points(
            cs.namespace(|| format!("public commitment {} sum", index + 1)),
            &batched,
            &term,
        )?;
        if index + 1 != rest.len() {
            weight = multiply_scalars(
                cs.namespace(|| format!("public commitment {} weight", index + 1)),
                &weight,
                &transcript.eta,
            )?;
        }
    }
    require_finite(cs.namespace(|| "batched commitment is finite"), &batched)?;
    batched.enforce_equal(
        cs.namespace(|| "batched commitment equality"),
        transcript.batched_public_commitment.point(),
    )
}

/// Check the public commitment batch and its Schnorr response.
pub(crate) fn constrain_manifest_bound_public_dlog<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &DirectCircuitTranscriptResultV4,
    generator: &DirectSecpPoint,
) -> Result<(), SynthesisError> {
    if transcript.public_commitments.len() != 1 {
        return Err(synthesis_error("manifest-bound V4 anchor commitment count"));
    }
    constrain_public_commitment_batch(cs.namespace(|| "public commitment batch"), transcript)?;
    Boolean::enforce_equal(
        cs.namespace(|| "public commitment is even"),
        transcript.public_commitments[0].odd(),
        &Boolean::constant(false),
    )?;
    let scaled = scale(
        cs.namespace(|| "scaled public commitment"),
        transcript.batched_public_commitment.point(),
        &transcript.dlog_challenge,
    )?;
    let _response_inverse = invert_scalar(
        cs.namespace(|| "nonzero dlog response"),
        &transcript.dlog_response,
    )?;
    let lhs = scale(
        cs.namespace(|| "dlog response point"),
        generator,
        &transcript.dlog_response,
    )?;
    let rhs = add_points(
        cs.namespace(|| "dlog response equation"),
        transcript.dlog_nonce.point(),
        &scaled,
    )?;
    lhs.enforce_equal(cs.namespace(|| "dlog response equality"), &rhs)
}

/// Check the outer norm equations and prepare the short reduction claim.
pub(crate) fn prepare_norm<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    shape: CircuitTranscriptShapeV4,
    transcript: &DirectCircuitTranscriptResultV4,
    generator: &DirectSecpPoint,
) -> Result<DirectPreparedNorm, SynthesisError> {
    if transcript.rounds.len() != shape.round_count()
        || transcript.gammas.len() != shape.round_count()
        || transcript.gammas.is_empty()
    {
        return Err(synthesis_error("V4 prepared norm shape"));
    }
    constrain_anchor_and_mask(cs.namespace(|| "anchor and mask"), transcript, generator)?;

    let rounds = shape.round_count();
    let rho_to_n = square_repeatedly(cs.namespace(|| "rho power"), &transcript.rho, rounds)?;
    let rho_to_two_n = multiply_scalars(cs.namespace(|| "rho to two n"), &rho_to_n, &rho_to_n)?;
    let terminal_n_squared = multiply_scalars(
        cs.namespace(|| "terminal n squared"),
        &transcript.terminal_n,
        &transcript.terminal_n,
    )?;
    let norm_scale = multiply_scalars(
        cs.namespace(|| "norm scale"),
        &terminal_n_squared,
        &rho_to_two_n,
    )?;
    let negative_norm_scale = subtract_scalars(
        cs.namespace(|| "negative norm scale"),
        &small_constant::<CS::Root>(0)?,
        &norm_scale,
    )?;

    let mut short = transcript.combined_commitment.point().clone();
    for (round, (pair, gamma)) in transcript.rounds.iter().zip(&transcript.gammas).enumerate() {
        let gamma_squared = multiply_scalars(
            cs.namespace(|| format!("gamma {round} squared")),
            gamma,
            gamma,
        )?;
        let gamma_squared_minus_one = subtract_scalars(
            cs.namespace(|| format!("gamma {round} squared minus one")),
            &gamma_squared,
            &small_constant::<CS::Root>(1)?,
        )?;
        let first = scale(
            cs.namespace(|| format!("round {round} first")),
            pair.first.point(),
            gamma,
        )?;
        short = add_points(
            cs.namespace(|| format!("round {round} first sum")),
            &short,
            &first,
        )?;
        let second = scale(
            cs.namespace(|| format!("round {round} second")),
            pair.second.point(),
            &gamma_squared_minus_one,
        )?;
        short = add_points(
            cs.namespace(|| format!("round {round} second sum")),
            &short,
            &second,
        )?;
    }
    let norm_base = scale(
        cs.namespace(|| "negative norm point"),
        generator,
        &negative_norm_scale,
    )?;
    let residual_point = add_points(cs.namespace(|| "norm residual"), &short, &norm_base)?;
    let residual = encode_computed_point(cs.namespace(|| "encoded norm residual"), residual_point)?;

    let mul_scale_inverse =
        invert_scalar(cs.namespace(|| "mul scale inverse"), &transcript.mul_scale)?;
    let n_rho = multiply_scalars(
        cs.namespace(|| "terminal n rho"),
        &transcript.terminal_n,
        &rho_to_n,
    )?;
    let g_scale = multiply_scalars(cs.namespace(|| "g scale"), &n_rho, &mul_scale_inverse)?;
    let sqrt_minus_one_inverse = constant_scalar::<CS::Root>(SQRT_MINUS_ONE_INVERSE)?;
    let mut g_factors = Vec::with_capacity(rounds);
    g_factors.push(multiply_scalars(
        cs.namespace(|| "first g factor"),
        &transcript.gammas[0],
        &sqrt_minus_one_inverse,
    )?);
    let mut ratio_inverse_power =
        invert_scalar(cs.namespace(|| "ratio inverse"), &transcript.mul_ratio)?;
    for (round, gamma) in transcript.gammas.iter().enumerate().skip(1) {
        g_factors.push(multiply_scalars(
            cs.namespace(|| format!("g factor {round}")),
            gamma,
            &ratio_inverse_power,
        )?);
        ratio_inverse_power = multiply_scalars(
            cs.namespace(|| format!("ratio inverse power {round}")),
            &ratio_inverse_power,
            &ratio_inverse_power,
        )?;
    }

    Ok(DirectPreparedNorm {
        prepared_binding: transcript.prepared_binding.clone(),
        coefficient_commitment: transcript.coefficient_commitment.clone(),
        residual,
        polynomial: vec![
            DirectPolynomialTerm {
                scale: g_scale,
                offset: 0,
                factors: g_factors,
            },
            DirectPolynomialTerm {
                scale: transcript.terminal_l.clone(),
                offset: shape.n_vec_len,
                factors: transcript.gammas.clone(),
            },
        ],
    })
}

pub(crate) fn allocate_standard_generator<CS: ConstraintSystem<Scalar>>(
    cs: CS,
) -> Result<DirectSecpPoint, SynthesisError> {
    allocate_constant_point(cs, standard_generator())
}

/// Constrain one public anchor leaf and reduce it to a pending claim.
pub(crate) fn constrain_manifest_bound_anchor_leaf<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<DirectManifestBoundAnchorLeaf, SynthesisError> {
    if statement.shape.mode != CircuitCommitmentModeV4::Public
        || statement.shape.commitment_count != 1
    {
        return Err(synthesis_error("manifest-bound V4 anchor mode"));
    }
    let circuit_binding_digest = statement
        .circuit_binding_digest
        .into_iter()
        .enumerate()
        .map(|(index, byte)| {
            NovaByte::allocate(
                cs.namespace(|| format!("circuit binding byte {index}")),
                byte,
            )
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("a circuit binding digest has 32 bytes");
    let transcript = install_transcript_with_constrained_binding(
        cs.namespace(|| "V4 transcript"),
        statement.shape,
        &circuit_binding_digest,
        statement.raw_generator_digest,
        transcript_witness,
    )?;
    let generator = allocate_standard_generator(cs.namespace(|| "standard generator"))?;
    constrain_manifest_bound_public_dlog(cs.namespace(|| "public DLog"), &transcript, &generator)?;
    let prepared = prepare_norm(
        cs.namespace(|| "prepared norm"),
        statement.shape,
        &transcript,
        &generator,
    )?;
    let claim = constrain_candidate_norm_reduction(
        cs.namespace(|| "coefficient reduction"),
        statement.basis_digest,
        statement.shape.n_vec_len,
        &prepared,
        reduction_proof,
        &generator,
    )?;
    Ok(DirectManifestBoundAnchorLeaf {
        claim,
        circuit_binding_digest,
        precommitment: transcript.precommitment,
        coefficient_commitment: transcript.coefficient_commitment,
        anchored_offset: transcript.anchored_offset,
    })
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use nova_snark::frontend::{
        shape_cs::ShapeCS, test_cs::TestConstraintSystem, util_cs::witness_cs::WitnessCS,
        ConstraintSystem,
    };
    use num_bigint::{BigInt, BigUint, Sign};

    use super::*;
    use crate::circuit_transcript::{
        replay_circuit_transcript_v4, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
        CircuitTranscriptShapeV4,
    };
    use crate::nova_circuit_transcript::{
        DirectCircuitPointPairV4, DirectCircuitTranscriptResultV4,
    };
    use crate::nova_secp::allocate_encoded_point;
    use crate::nova_secp_scalar::allocate_canonical_scalar;
    use crate::nova_types::DirectNovaPrimaryEngine;
    use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
    use crate::secp_native::{
        add_point_values, encoded_point_value, scale_point_value, SecpEncodedPointWitness,
        SecpScalarWitness,
    };

    fn scalar<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: u64,
    ) -> Result<CanonicalSecpScalar, SynthesisError> {
        allocate_canonical_scalar(cs, SecpScalarWitness::from_u64(value))
    }

    fn point<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: crate::secp_native::PointValue,
    ) -> Result<DirectEncodedSecpPoint, SynthesisError> {
        allocate_encoded_point(cs, SecpEncodedPointWitness::from_point_value(value))
    }

    fn scalar_value(value: &CanonicalSecpScalar) -> BigInt {
        value.integer().cloned().expect("scalar witness")
    }

    fn assert_point_value(
        actual: &DirectEncodedSecpPoint,
        expected: crate::secp_native::PointValue,
    ) {
        assert_eq!(actual.point().x().get_value(), Some(expected.x));
        assert_eq!(actual.point().y().get_value(), Some(expected.y));
        assert_eq!(
            actual.point().identity_num().get_value(),
            Some(Scalar::from(u64::from(expected.identity)))
        );
    }

    fn synthetic_transcript<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        wrong_combined: bool,
    ) -> Result<DirectCircuitTranscriptResultV4, SynthesisError> {
        let generator = standard_generator();
        let twice = add_point_values(generator, generator);
        let thrice = add_point_values(twice, generator);
        let g = point(cs.namespace(|| "generator"), generator)?;
        let two_g = point(cs.namespace(|| "twice generator"), twice)?;
        let combined = point(
            cs.namespace(|| "combined commitment"),
            if wrong_combined { twice } else { thrice },
        )?;
        let identity = point(
            cs.namespace(|| "identity"),
            crate::secp_native::PointValue {
                x: Scalar::ZERO,
                y: Scalar::ZERO,
                identity: true,
            },
        )?;
        let zero = scalar(cs.namespace(|| "zero"), 0)?;
        let one = scalar(cs.namespace(|| "one"), 1)?;
        let two = scalar(cs.namespace(|| "two"), 2)?;
        let rounds = (0..2)
            .map(|_| DirectCircuitPointPairV4 {
                first: identity.clone(),
                second: identity.clone(),
            })
            .collect();
        Ok(DirectCircuitTranscriptResultV4 {
            public_commitments: vec![g.clone()],
            raw_commitment: g.clone(),
            coefficient_commitment: g.clone(),
            anchored_offset: g.clone(),
            anchored_commitment: two_g.clone(),
            batched_public_commitment: g.clone(),
            dlog_nonce: g.clone(),
            dlog_response: two,
            mask_commitment: g.clone(),
            t2: zero.clone(),
            combined_commitment: combined,
            rounds,
            terminal_n: zero,
            terminal_l: one.clone(),
            precommitment: one.clone(),
            rho: one.clone(),
            mul_scale: one.clone(),
            mul_ratio: one.clone(),
            row_ratio: one.clone(),
            eta: one.clone(),
            dlog_challenge: one.clone(),
            alpha: one.clone(),
            gammas: vec![one.clone(), one.clone()],
            prepared_binding: one,
        })
    }

    fn synthesize_equations<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        wrong_combined: bool,
    ) -> Result<DirectPreparedNorm, SynthesisError> {
        let transcript = synthetic_transcript(cs.namespace(|| "transcript"), wrong_combined)?;
        let generator = allocate_standard_generator(cs.namespace(|| "standard generator"))?;
        constrain_manifest_bound_public_dlog(
            cs.namespace(|| "public dlog"),
            &transcript,
            &generator,
        )?;
        prepare_norm(
            cs.namespace(|| "prepared norm"),
            CircuitTranscriptShapeV4 {
                mode: CircuitCommitmentModeV4::Public,
                gate_count: 2,
                commitment_count: 1,
                n_vec_len: 4,
                l_vec_len: 4,
            },
            &transcript,
            &generator,
        )
    }

    const TEST_BINDING: [u8; 32] = [0x31; 32];
    const TEST_GENERATORS: [u8; 32] = [0x52; 32];
    const TEST_BASIS: [u8; 32] = [0x73; 32];

    fn leaf_shape() -> CircuitTranscriptShapeV4 {
        CircuitTranscriptShapeV4 {
            mode: CircuitCommitmentModeV4::Public,
            gate_count: 2,
            commitment_count: 1,
            n_vec_len: 4,
            l_vec_len: 4,
        }
    }

    fn identity_pair() -> CircuitPointPairWitnessV4 {
        CircuitPointPairWitnessV4 {
            encoded: [0; 65],
            first_y: [0; 32],
            second_y: [0; 32],
        }
    }

    fn zero_reduction() -> CandidateNormReductionProofWitness {
        let rounds = leaf_shape().round_count();
        CandidateNormReductionProofWitness {
            coefficient_evaluation: SecpScalarWitness::from_u64(0),
            left: vec![SecpEncodedPointWitness::identity(); rounds],
            right: vec![SecpEncodedPointWitness::identity(); rounds],
            terminal_scalar: SecpScalarWitness::from_u64(0),
            folded_generator: SecpEncodedPointWitness::identity(),
        }
    }

    fn leaf_statement(binding: [u8; 32]) -> ManifestBoundAnchorLeafStatementV4 {
        ManifestBoundAnchorLeafStatementV4 {
            shape: leaf_shape(),
            circuit_binding_digest: binding,
            raw_generator_digest: TEST_GENERATORS,
            basis_digest: TEST_BASIS,
        }
    }

    fn leaf_witness(binding: [u8; 32], public_secret: u64) -> CircuitProofTranscriptWitnessV4 {
        let shape = leaf_shape();
        let generator = standard_generator();
        let generator_witness = SecpEncodedPointWitness::from_point_value(generator);
        let identity = SecpEncodedPointWitness::identity();
        let public = SecpEncodedPointWitness::from_point_value(scale_point_value(
            generator,
            &BigUint::from(public_secret),
        ));
        let mut witness = CircuitProofTranscriptWitnessV4 {
            public_commitments: vec![public],
            raw_commitment: generator_witness,
            coefficient_commitment: identity,
            anchored_offset: identity,
            anchored_commitment: generator_witness,
            batched_public_commitment: public,
            dlog_nonce: generator_witness,
            dlog_response: SecpScalarWitness::from_u64(0),
            mask_commitment: generator_witness,
            t2: SecpScalarWitness::from_u64(0),
            combined_commitment: identity,
            rounds: vec![identity_pair(); shape.round_count()],
            terminal_n: SecpScalarWitness::from_u64(0),
            terminal_l: SecpScalarWitness::from_u64(0),
        };
        let order = BigUint::from_bytes_be(&SECP256K1_SCALAR_ORDER_BE);
        let transcript = replay_circuit_transcript_v4(shape, binding, TEST_GENERATORS, &witness)
            .expect("DLog challenge");
        let response = (BigUint::from_bytes_be(&transcript.dlog_challenge.bytes)
            * BigUint::from(public_secret)
            + BigUint::from(1u8))
            % &order;
        witness.dlog_response = SecpScalarWitness::from_biguint(&response);

        let transcript = replay_circuit_transcript_v4(shape, binding, TEST_GENERATORS, &witness)
            .expect("mask challenge");
        let combined_scalar =
            (BigUint::from_bytes_be(&transcript.alpha.bytes) + BigUint::from(1u8)) % order;
        witness.combined_commitment = SecpEncodedPointWitness::from_point_value(scale_point_value(
            generator,
            &combined_scalar,
        ));
        witness
    }

    fn decimal(value: &str) -> BigInt {
        BigInt::parse_bytes(value.as_bytes(), 10).expect("decimal scalar")
    }

    fn assert_term_value(
        actual: &DirectPolynomialTerm,
        offset: usize,
        scale: &str,
        factors: &[&str],
    ) {
        assert_eq!(actual.offset, offset);
        assert_eq!(scalar_value(&actual.scale), decimal(scale));
        assert_eq!(actual.factors.len(), factors.len());
        for (actual, expected) in actual.factors.iter().zip(factors) {
            assert_eq!(scalar_value(actual), decimal(expected));
        }
    }

    fn assert_leaf_matches_reference(
        direct: &DirectManifestBoundAnchorLeaf,
        witness: &CircuitProofTranscriptWitnessV4,
    ) {
        assert_eq!(
            direct
                .circuit_binding_digest
                .each_ref()
                .map(NovaByte::value),
            TEST_BINDING
        );
        let transcript =
            replay_circuit_transcript_v4(leaf_shape(), TEST_BINDING, TEST_GENERATORS, witness)
                .expect("native transcript replay");
        assert_eq!(
            scalar_value(&direct.precommitment),
            BigInt::from_bytes_be(Sign::Plus, &transcript.precommitment.bytes)
        );
        assert_point_value(
            &direct.coefficient_commitment,
            encoded_point_value(witness.coefficient_commitment).expect("coefficient point"),
        );
        assert_eq!(
            direct.coefficient_commitment.prefix().get_value(),
            Some(Scalar::from(u64::from(
                witness.coefficient_commitment.encoded[0]
            )))
        );
        assert_point_value(
            &direct.anchored_offset,
            encoded_point_value(witness.anchored_offset).expect("anchored offset"),
        );
        assert_eq!(
            direct.anchored_offset.prefix().get_value(),
            Some(Scalar::from(u64::from(witness.anchored_offset.encoded[0])))
        );
        assert_point_value(
            &direct.claim.point,
            encoded_point_value(
                SecpEncodedPointWitness::parse([
                    0x03, 0x47, 0xad, 0x96, 0x72, 0x67, 0x81, 0xab, 0xdf, 0x3f, 0x30, 0xf9, 0xe8,
                    0x4e, 0xf4, 0xef, 0x48, 0xf3, 0x52, 0xef, 0x3f, 0xff, 0x23, 0xca, 0xa6, 0x3c,
                    0x5c, 0x2c, 0x2c, 0x49, 0x22, 0x71, 0xa8,
                ])
                .expect("reference leaf claim"),
            )
            .expect("reference leaf claim point"),
        );
        assert_eq!(
            direct.claim.point.prefix().get_value(),
            Some(Scalar::from(3u64))
        );
        assert_eq!(direct.claim.polynomial.len(), 3);
        assert_term_value(
            &direct.claim.polynomial[0],
            0,
            "0",
            &[
                "96472575357434127403452087478432697540229024419678898669627838184152381380744",
                "12525682640557988548520279796387227805534927186977202175782519450943741004585",
            ],
        );
        assert_term_value(
            &direct.claim.polynomial[1],
            4,
            "0",
            &[
                "7273348074603764980727967229644113487056712139029028138001561355210384475755",
                "15327562160910372180930640418503057844223853218422066183373656845016941493122",
            ],
        );
        assert_term_value(
            &direct.claim.polynomial[2],
            4,
            "62179708294710770898306232406053259504552606387869667994639842056086225323492",
            &[
                "41087891265995131219429115556388515091746110462066570342963116063834025866661",
                "100629698165764552939517767160162913678637647294857645944667018095849680228120",
            ],
        );
    }

    #[test]
    fn direct_leaf_equations_bind_outer_points_and_have_fixed_shape() {
        let mut valid = TestConstraintSystem::<Scalar>::new();
        let prepared = synthesize_equations(&mut valid, false).expect("valid equations");
        assert_eq!(prepared.polynomial.len(), 2);
        assert_eq!(prepared.polynomial[0].offset, 0);
        assert_eq!(prepared.polynomial[0].factors.len(), 2);
        assert_eq!(prepared.polynomial[1].offset, 4);
        assert_eq!(prepared.polynomial[1].factors.len(), 2);
        assert_eq!(scalar_value(&prepared.prepared_binding), BigInt::from(1));
        assert_point_value(&prepared.coefficient_commitment, standard_generator());
        let twice = add_point_values(standard_generator(), standard_generator());
        assert_point_value(
            &prepared.residual,
            add_point_values(twice, standard_generator()),
        );
        assert_eq!(scalar_value(&prepared.polynomial[0].scale), BigInt::from(0));
        assert_eq!(
            scalar_value(&prepared.polynomial[0].factors[0]),
            BigInt::from_bytes_be(Sign::Plus, &SQRT_MINUS_ONE_INVERSE.bytes)
        );
        assert_eq!(
            scalar_value(&prepared.polynomial[0].factors[1]),
            BigInt::from(1)
        );
        assert_eq!(scalar_value(&prepared.polynomial[1].scale), BigInt::from(1));
        assert!(prepared.polynomial[1]
            .factors
            .iter()
            .all(|factor| scalar_value(factor) == BigInt::from(1)));
        assert!(valid.is_satisfied());

        let mut invalid = TestConstraintSystem::<Scalar>::new();
        synthesize_equations(&mut invalid, true).expect("wrong point relation");
        assert!(!invalid.is_satisfied());
        assert_eq!(valid.num_constraints(), invalid.num_constraints());

        let mut first = ShapeCS::<DirectNovaPrimaryEngine>::new();
        synthesize_equations(&mut first, false).expect("first shape");
        let mut second = ShapeCS::<DirectNovaPrimaryEngine>::new();
        synthesize_equations(&mut second, true).expect("second shape");
        assert_eq!(first.num_inputs(), 1);
        assert_eq!(first.num_aux(), 52_370);
        assert_eq!(first.num_constraints(), 54_112);
        assert_eq!(first.num_aux(), second.num_aux());
        assert_eq!(first.constraints, second.constraints);
    }

    #[test]
    fn direct_manifest_leaf_matches_reference_and_rejects_hidden_mode() {
        let statement = leaf_statement(TEST_BINDING);
        let witness = leaf_witness(TEST_BINDING, 1);
        let reduction = zero_reduction();
        let mut direct_cs = WitnessCS::<Scalar>::with_capacity(0, 0);
        let direct =
            constrain_manifest_bound_anchor_leaf(&mut direct_cs, statement, &witness, &reduction)
                .expect("direct manifest leaf");

        assert_leaf_matches_reference(&direct, &witness);

        let mut hidden = statement;
        hidden.shape.mode = CircuitCommitmentModeV4::Hidden;
        assert!(constrain_manifest_bound_anchor_leaf(
            WitnessCS::<Scalar>::with_capacity(0, 0),
            hidden,
            &witness,
            &reduction,
        )
        .is_err());
    }

    #[test]
    #[ignore = "run explicitly in release mode; composed leaf shape is large"]
    fn direct_manifest_leaf_shape_is_witness_independent() {
        let mut first = ShapeCS::<DirectNovaPrimaryEngine>::new();
        constrain_manifest_bound_anchor_leaf(
            &mut first,
            leaf_statement(TEST_BINDING),
            &leaf_witness(TEST_BINDING, 1),
            &zero_reduction(),
        )
        .expect("first manifest leaf shape");
        let metrics = (first.num_inputs(), first.num_aux(), first.num_constraints());
        assert_eq!(metrics, (1, 1_503_971, 1_508_966));
        drop(first);

        let second_binding = [0x32; 32];
        let mut second = ShapeCS::<DirectNovaPrimaryEngine>::new();
        constrain_manifest_bound_anchor_leaf(
            &mut second,
            leaf_statement(second_binding),
            &leaf_witness(second_binding, 2),
            &zero_reduction(),
        )
        .expect("second manifest leaf shape");
        assert_eq!(
            metrics,
            (
                second.num_inputs(),
                second.num_aux(),
                second.num_constraints()
            )
        );
    }
}
