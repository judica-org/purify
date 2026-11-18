//! Direct Nova equations for one manifest-bound circuit-norm leaf.
//!
//! Transcript replay and coefficient reduction remain separate boundaries.
//! This module checks the outer proof equations and prepares the exact short
//! norm obligation consumed by the reduction.

use nova_snark::frontend::{ConstraintSystem, SynthesisError};

use crate::gadgets::ops::Ops;
use crate::gadgets::point::{allocate_constant_point, EncodedPoint, Point};
use crate::gadgets::scalar::CanonicalScalar;
use crate::gadgets::sha256::Byte;
use crate::gadgets::synthesis_error;
use crate::native::circuit_norm::{
    CandidateNormReductionProofWitness, ManifestBoundConstructionLeafStatementV4,
};
use crate::native::circuit_transcript::{
    CircuitCommitmentModeV4, CircuitProofTranscriptWitnessV4, CircuitTranscriptShapeV4,
};
use crate::native::secp::{standard_generator, SecpScalarWitness};
use crate::relation::candidate::{PendingClaim, PolynomialTerm};
use crate::relation::norm_reduction::constrain_candidate_norm_reduction;
use crate::relation::transcript::{
    install_transcript_with_constrained_binding, CircuitTranscriptResultV4,
};
use statement::Scalar;

// Inverse of the protocol's fixed even square root of minus one modulo the
// secp256k1 group order.
const SQRT_MINUS_ONE_INVERSE: SecpScalarWitness = SecpScalarWitness::from_bytes_be([
    0x8f, 0x52, 0xb6, 0x51, 0x80, 0x7a, 0x8b, 0x13, 0x54, 0x9b, 0xe5, 0xbd, 0x4c, 0x5d, 0xb0, 0xdb,
    0xe4, 0x77, 0x9c, 0xc3, 0x1a, 0xfb, 0xd9, 0xd6, 0x19, 0x15, 0xaf, 0xdb, 0xdc, 0xba, 0x81, 0xc9,
]);

pub(crate) struct PreparedNorm {
    pub(crate) prepared_binding: CanonicalScalar,
    pub(crate) coefficient_commitment: EncodedPoint,
    pub(crate) residual: EncodedPoint,
    pub(crate) polynomial: Vec<PolynomialTerm>,
}

pub(crate) struct ManifestBoundConstructionLeaf {
    pub(crate) claim: PendingClaim,
    pub(crate) circuit_binding_digest: [Byte; 32],
    pub(crate) precommitment: CanonicalScalar,
    pub(crate) coefficient_commitment: EncodedPoint,
    pub(crate) anchored_offset: EncodedPoint,
}

/// `anchored = raw + offset` and `combined = anchored + alpha mask + alpha^2 t2 G`.
fn constrain_anchor_and_mask<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    transcript: &CircuitTranscriptResultV4,
    generator: &Point,
) -> Result<(), SynthesisError> {
    let mut ops = Ops::new(cs);
    ops.require_finite(transcript.raw_commitment.point())?;
    ops.require_finite(transcript.mask_commitment.point())?;
    let anchored = ops.add_points(
        transcript.raw_commitment.point(),
        transcript.anchored_offset.point(),
    )?;
    ops.require_finite(&anchored)?;
    ops.require_equal_points(&anchored, transcript.anchored_commitment.point())?;

    let alpha_squared = ops.square(&transcript.alpha)?;
    let t2_scale = ops.mul(&alpha_squared, &transcript.t2)?;
    let masked = ops.add_scaled(
        transcript.anchored_commitment.point(),
        transcript.mask_commitment.point(),
        &transcript.alpha,
    )?;
    let combined = ops.add_scaled(&masked, generator, &t2_scale)?;
    ops.require_finite(&combined)?;
    ops.require_equal_points(&combined, transcript.combined_commitment.point())
}

/// `batched = sum_i eta^i public_i`, with every term and the sum finite.
fn constrain_public_commitment_batch<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    transcript: &CircuitTranscriptResultV4,
) -> Result<(), SynthesisError> {
    let mut ops = Ops::new(cs);
    let (first, rest) = transcript
        .public_commitments
        .split_first()
        .ok_or_else(|| synthesis_error("public V4 circuit norm commitments"))?;
    ops.require_finite(first.point())?;
    let mut batched = first.point().clone();
    let mut weight = transcript.eta.clone();
    for (index, point) in rest.iter().enumerate() {
        ops.require_finite(point.point())?;
        batched = ops.add_scaled(&batched, point.point(), &weight)?;
        if index + 1 != rest.len() {
            weight = ops.mul(&weight, &transcript.eta)?;
        }
    }
    ops.require_finite(&batched)?;
    ops.require_equal_points(&batched, transcript.batched_public_commitment.point())
}

/// Check the public commitment batch and its Schnorr response:
/// `response G = nonce + challenge batched`, with a nonzero response.
pub(crate) fn constrain_manifest_bound_public_dlog<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    transcript: &CircuitTranscriptResultV4,
    generator: &Point,
) -> Result<(), SynthesisError> {
    if transcript.public_commitments.len() != 1 {
        return Err(synthesis_error(
            "manifest-bound V4 construction leaf commitment count",
        ));
    }
    let mut ops = Ops::new(cs);
    constrain_public_commitment_batch(ops.scope("public commitment batch"), transcript)?;
    let scaled = ops.scale(
        transcript.batched_public_commitment.point(),
        &transcript.dlog_challenge,
    )?;
    ops.require_nonzero(&transcript.dlog_response)?;
    let lhs = ops.scale(generator, &transcript.dlog_response)?;
    let rhs = ops.add_points(transcript.dlog_nonce.point(), &scaled)?;
    ops.require_equal_points(&lhs, &rhs)
}

/// Check the outer norm equations and prepare the short reduction claim.
pub(crate) fn prepare_norm<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    shape: CircuitTranscriptShapeV4,
    transcript: &CircuitTranscriptResultV4,
    generator: &Point,
) -> Result<PreparedNorm, SynthesisError> {
    if transcript.rounds.len() != shape.round_count()
        || transcript.gammas.len() != shape.round_count()
        || transcript.gammas.is_empty()
    {
        return Err(synthesis_error("V4 prepared norm shape"));
    }
    let mut ops = Ops::new(cs);
    constrain_anchor_and_mask(ops.scope("anchor and mask"), transcript, generator)?;
    let zero = ops.constant(0)?;
    let one = ops.constant(1)?;

    // norm_scale = terminal_n^2 rho^(2n), with rho^n by repeated squaring.
    let rounds = shape.round_count();
    let mut rho_to_n = transcript.rho.clone();
    for _ in 0..rounds {
        rho_to_n = ops.square(&rho_to_n)?;
    }
    let rho_to_two_n = ops.square(&rho_to_n)?;
    let terminal_n_squared = ops.square(&transcript.terminal_n)?;
    let norm_scale = ops.mul(&terminal_n_squared, &rho_to_two_n)?;
    let negative_norm_scale = ops.sub(&zero, &norm_scale)?;

    // residual = combined + sum_r (gamma_r first_r + (gamma_r^2 - 1) second_r)
    //            - norm_scale G
    let mut short = transcript.combined_commitment.point().clone();
    for (pair, gamma) in transcript.rounds.iter().zip(&transcript.gammas) {
        let gamma_squared = ops.square(gamma)?;
        let gamma_squared_minus_one = ops.sub(&gamma_squared, &one)?;
        short = ops.add_scaled(&short, pair.first.point(), gamma)?;
        short = ops.add_scaled(&short, pair.second.point(), &gamma_squared_minus_one)?;
    }
    let residual_point = ops.add_scaled(&short, generator, &negative_norm_scale)?;
    let residual = ops.encode(residual_point)?;

    // g(X) = (terminal_n rho^n / mul_scale) prod_r (1 + g_factor_r X^(2^r)),
    // g_factor_0 = gamma_0 / sqrt(-1), g_factor_r = gamma_r / mul_ratio^(2^(r-1)).
    let mul_scale_inverse = ops.invert(&transcript.mul_scale)?;
    let n_rho = ops.mul(&transcript.terminal_n, &rho_to_n)?;
    let g_scale = ops.mul(&n_rho, &mul_scale_inverse)?;
    let sqrt_minus_one_inverse = ops.constant_scalar(SQRT_MINUS_ONE_INVERSE)?;
    let mut g_factors = Vec::with_capacity(rounds);
    g_factors.push(ops.mul(&transcript.gammas[0], &sqrt_minus_one_inverse)?);
    let mut ratio_inverse_power = ops.invert(&transcript.mul_ratio)?;
    for gamma in transcript.gammas.iter().skip(1) {
        g_factors.push(ops.mul(gamma, &ratio_inverse_power)?);
        ratio_inverse_power = ops.square(&ratio_inverse_power)?;
    }

    Ok(PreparedNorm {
        prepared_binding: transcript.prepared_binding.clone(),
        coefficient_commitment: transcript.coefficient_commitment.clone(),
        residual,
        polynomial: vec![
            PolynomialTerm {
                scale: g_scale,
                offset: 0,
                factors: g_factors,
            },
            PolynomialTerm {
                scale: transcript.terminal_l.clone(),
                offset: shape.n_vec_len,
                factors: transcript.gammas.clone(),
            },
        ],
    })
}

pub(crate) fn allocate_standard_generator<CS: ConstraintSystem<Scalar>>(
    cs: CS,
) -> Result<Point, SynthesisError> {
    allocate_constant_point(cs, standard_generator())
}

/// Constrain one public construction leaf and reduce it to a pending claim.
pub(crate) fn constrain_manifest_bound_construction_leaf<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    statement: ManifestBoundConstructionLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ManifestBoundConstructionLeaf, SynthesisError> {
    if statement.shape.mode != CircuitCommitmentModeV4::Public
        || statement.shape.commitment_count != 1
    {
        return Err(synthesis_error("manifest-bound V4 construction leaf mode"));
    }
    let mut ops = Ops::new(cs);
    let circuit_binding_digest = ops.bytes(statement.circuit_binding_digest)?;
    let transcript = install_transcript_with_constrained_binding(
        ops.scope("V4 transcript"),
        statement.shape,
        &circuit_binding_digest,
        statement.raw_generator_digest,
        transcript_witness,
    )?;
    let generator = allocate_standard_generator(ops.scope("standard generator"))?;
    constrain_manifest_bound_public_dlog(ops.scope("public DLog"), &transcript, &generator)?;
    let prepared = prepare_norm(
        ops.scope("prepared norm"),
        statement.shape,
        &transcript,
        &generator,
    )?;
    let claim = constrain_candidate_norm_reduction(
        ops.scope("coefficient reduction"),
        statement.basis_digest,
        statement.shape.n_vec_len,
        &prepared,
        reduction_proof,
        &generator,
    )?;
    Ok(ManifestBoundConstructionLeaf {
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
    use crate::gadgets::point::allocate_encoded_point;
    use crate::gadgets::scalar::allocate_canonical_scalar;
    use crate::native::circuit_transcript::{
        replay_circuit_transcript_v4, CircuitCommitmentModeV4, CircuitPointPairWitnessV4,
        CircuitTranscriptShapeV4,
    };
    use crate::native::secp::scalar_witness_from_biguint;
    use crate::native::secp::SECP256K1_SCALAR_ORDER_BE;
    use crate::native::secp::{
        add_point_values, encoded_point_value, scale_point_value, SecpEncodedPointWitness,
        SecpScalarWitness,
    };
    use crate::relation::transcript::{CircuitPointPairV4, CircuitTranscriptResultV4};
    use statement::PrimaryEngine;

    fn scalar<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: u64,
    ) -> Result<CanonicalScalar, SynthesisError> {
        allocate_canonical_scalar(cs, SecpScalarWitness::from_u64(value))
    }

    fn point<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: crate::native::secp::PointValue,
    ) -> Result<EncodedPoint, SynthesisError> {
        allocate_encoded_point(cs, SecpEncodedPointWitness::from_point_value(value))
    }

    fn scalar_value(value: &CanonicalScalar) -> BigInt {
        value.integer().cloned().expect("scalar witness")
    }

    fn assert_point_value(actual: &EncodedPoint, expected: crate::native::secp::PointValue) {
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
    ) -> Result<CircuitTranscriptResultV4, SynthesisError> {
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
            crate::native::secp::PointValue {
                x: Scalar::ZERO,
                y: Scalar::ZERO,
                identity: true,
            },
        )?;
        let zero = scalar(cs.namespace(|| "zero"), 0)?;
        let one = scalar(cs.namespace(|| "one"), 1)?;
        let two = scalar(cs.namespace(|| "two"), 2)?;
        let rounds = (0..2)
            .map(|_| CircuitPointPairV4 {
                first: identity.clone(),
                second: identity.clone(),
            })
            .collect();
        Ok(CircuitTranscriptResultV4 {
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

    fn synthetic_odd_public_transcript<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
    ) -> Result<CircuitTranscriptResultV4, SynthesisError> {
        let mut transcript = synthetic_transcript(cs.namespace(|| "base transcript"), false)?;
        let order = BigUint::from_bytes_be(&SECP256K1_SCALAR_ORDER_BE);
        let minus_one = &order - BigUint::from(1u8);
        let odd_value = scale_point_value(standard_generator(), &minus_one);
        let odd = point(cs.namespace(|| "odd public commitment"), odd_value)?;
        transcript.public_commitments = vec![odd.clone()];
        transcript.batched_public_commitment = odd;
        transcript.dlog_nonce = point(
            cs.namespace(|| "odd proof nonce"),
            add_point_values(standard_generator(), standard_generator()),
        )?;
        transcript.dlog_response = scalar(cs.namespace(|| "odd response"), 1)?;
        Ok(transcript)
    }

    fn synthesize_equations<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        wrong_combined: bool,
    ) -> Result<PreparedNorm, SynthesisError> {
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

    fn leaf_statement(binding: [u8; 32]) -> ManifestBoundConstructionLeafStatementV4 {
        ManifestBoundConstructionLeafStatementV4 {
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
        witness.dlog_response = scalar_witness_from_biguint(&response);

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

    fn assert_term_value(actual: &PolynomialTerm, offset: usize, scale: &str, factors: &[&str]) {
        assert_eq!(actual.offset, offset);
        assert_eq!(scalar_value(&actual.scale), decimal(scale));
        assert_eq!(actual.factors.len(), factors.len());
        for (actual, expected) in actual.factors.iter().zip(factors) {
            assert_eq!(scalar_value(actual), decimal(expected));
        }
    }

    fn assert_leaf_matches_reference(
        direct: &ManifestBoundConstructionLeaf,
        witness: &CircuitProofTranscriptWitnessV4,
    ) {
        assert_eq!(
            direct.circuit_binding_digest.each_ref().map(Byte::value),
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
    fn constrained_leaf_equations_bind_outer_points_and_have_fixed_shape() {
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

        let mut first = ShapeCS::<PrimaryEngine>::new();
        synthesize_equations(&mut first, false).expect("first shape");
        let mut second = ShapeCS::<PrimaryEngine>::new();
        synthesize_equations(&mut second, true).expect("second shape");
        assert_eq!(first.num_inputs(), 1);
        assert_eq!(first.num_aux(), 52_370);
        assert_eq!(first.num_constraints(), 54_111);
        assert_eq!(first.num_aux(), second.num_aux());
        assert_eq!(first.constraints, second.constraints);
    }

    #[test]
    fn public_dlog_accepts_an_exact_odd_commitment() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let transcript = synthetic_odd_public_transcript(cs.namespace(|| "odd transcript"))
            .expect("odd public transcript");
        let generator = allocate_standard_generator(cs.namespace(|| "standard generator"))
            .expect("standard generator");
        constrain_manifest_bound_public_dlog(
            cs.namespace(|| "public dlog"),
            &transcript,
            &generator,
        )
        .expect("odd public DLog relation");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn constrained_manifest_leaf_matches_reference_and_rejects_hidden_mode() {
        let statement = leaf_statement(TEST_BINDING);
        let witness = leaf_witness(TEST_BINDING, 1);
        let reduction = zero_reduction();
        let mut direct_cs = WitnessCS::<Scalar>::with_capacity(0, 0);
        let direct = constrain_manifest_bound_construction_leaf(
            &mut direct_cs,
            statement,
            &witness,
            &reduction,
        )
        .expect("direct manifest leaf");

        assert_leaf_matches_reference(&direct, &witness);

        let mut hidden = statement;
        hidden.shape.mode = CircuitCommitmentModeV4::Hidden;
        assert!(constrain_manifest_bound_construction_leaf(
            WitnessCS::<Scalar>::with_capacity(0, 0),
            hidden,
            &witness,
            &reduction,
        )
        .is_err());
    }

    #[test]
    #[ignore = "run explicitly in release mode; composed leaf shape is large"]
    fn constrained_manifest_leaf_shape_is_witness_independent() {
        let mut first = ShapeCS::<PrimaryEngine>::new();
        constrain_manifest_bound_construction_leaf(
            &mut first,
            leaf_statement(TEST_BINDING),
            &leaf_witness(TEST_BINDING, 1),
            &zero_reduction(),
        )
        .expect("first manifest leaf shape");
        let metrics = (first.num_inputs(), first.num_aux(), first.num_constraints());
        assert_eq!(metrics, (1, 1_503_971, 1_508_965));
        drop(first);

        let second_binding = [0x32; 32];
        let mut second = ShapeCS::<PrimaryEngine>::new();
        constrain_manifest_bound_construction_leaf(
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
