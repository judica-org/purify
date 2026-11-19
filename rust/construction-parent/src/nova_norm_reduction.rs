//! Direct Nova coefficient reduction for one prepared norm.
//!
//! This layer owns the reduction transcript and opening equation. It consumes
//! an already constrained norm and returns one pending candidate claim.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::circuit_norm::CandidateNormReductionProofWitness;
use crate::nova_candidate::{append_polynomial, DirectPendingClaim, DirectPolynomialTerm};
use crate::nova_circuit_norm_leaf::DirectPreparedNorm;
use crate::nova_opening_base::constrain_transcript_opening_base;
use crate::nova_protocol_transcript::{
    append_constant_bytes, append_point, append_scalar, challenge,
};
use crate::nova_secp::{
    add_points, allocate_encoded_point, encode_computed_point, scale_point, DirectSecpPoint,
};
use crate::nova_secp_scalar::{
    add_scalars, allocate_canonical_scalar, constant_scalar, invert_scalar, multiply_scalars,
    subtract_scalars, CanonicalSecpScalar,
};
use crate::nova_sha256_transcript::NovaTranscript;
use crate::opening_generators::REDUCTION_OPENING_BASE_ROLE;
use crate::secp_native::SecpScalarWitness;
use crate::Scalar;

const NORM_REDUCTION_DOMAIN: &[u8] = b"Purify/BPPP/CandidateNormReduction/v2";
const MAX_REDUCTION_ROUNDS: usize = 24;

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn small_constant<CS: ConstraintSystem<Scalar>>(
    value: u64,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    constant_scalar::<CS>(SecpScalarWitness::from_u64(value))
}

fn scale<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &DirectSecpPoint,
    scalar: &CanonicalSecpScalar,
) -> Result<DirectSecpPoint, SynthesisError> {
    let bits = scalar.allocated_bits_le(cs.namespace(|| "scalar bits"))?;
    scale_point(cs.namespace(|| "scalar multiplication"), point, &bits)
}

fn add_scaled<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    sum: &DirectSecpPoint,
    point: &DirectSecpPoint,
    scalar: &CanonicalSecpScalar,
) -> Result<DirectSecpPoint, SynthesisError> {
    let term = scale(cs.namespace(|| "scaled term"), point, scalar)?;
    add_points(cs.namespace(|| "term sum"), sum, &term)
}

fn validate_shape(
    n_vec_len: usize,
    prepared: &DirectPreparedNorm,
    proof: &CandidateNormReductionProofWitness,
) -> Result<usize, SynthesisError> {
    let rounds = proof.left.len();
    if !n_vec_len.is_power_of_two()
        || rounds > MAX_REDUCTION_ROUNDS
        || proof.right.len() != rounds
        || prepared.polynomial.len() != 2
    {
        return Err(synthesis_error("candidate norm reduction shape"));
    }
    let l_vec_len = 1usize
        .checked_shl(rounds as u32)
        .ok_or_else(|| synthesis_error("candidate norm reduction width"))?;
    if l_vec_len > n_vec_len {
        return Err(synthesis_error("candidate norm reduction width"));
    }
    let g = &prepared.polynomial[0];
    let h = &prepared.polynomial[1];
    if g.offset != 0
        || g.factors.len() != n_vec_len.trailing_zeros() as usize
        || h.offset != n_vec_len
        || h.factors.len() != rounds
    {
        return Err(synthesis_error("candidate prepared norm polynomial"));
    }
    Ok(rounds)
}

/// Reduce one already constrained norm to a pending candidate claim.
pub(crate) fn constrain_candidate_norm_reduction<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    basis_digest: [u8; 32],
    n_vec_len: usize,
    prepared: &DirectPreparedNorm,
    proof: &CandidateNormReductionProofWitness,
    generator: &DirectSecpPoint,
) -> Result<DirectPendingClaim, SynthesisError> {
    let rounds = validate_shape(n_vec_len, prepared, proof)?;
    let zero = small_constant::<CS::Root>(0)?;
    let one = small_constant::<CS::Root>(1)?;
    let mut transcript = NovaTranscript::new();
    append_constant_bytes(&mut transcript, NORM_REDUCTION_DOMAIN)?;
    append_constant_bytes(&mut transcript, &basis_digest)?;
    transcript.append_u64(rounds as u64);
    let _binding_inverse = invert_scalar(
        cs.namespace(|| "nonzero prepared binding"),
        &prepared.prepared_binding,
    )?;
    append_scalar(&mut transcript, &prepared.prepared_binding)?;
    append_point(&mut transcript, &prepared.coefficient_commitment);

    let weights = DirectPolynomialTerm {
        scale: one.clone(),
        offset: 0,
        factors: prepared.polynomial[1].factors.clone(),
    };
    append_polynomial(&mut transcript, std::slice::from_ref(&weights))?;
    let evaluation = allocate_canonical_scalar(
        cs.namespace(|| "coefficient evaluation"),
        proof.coefficient_evaluation,
    )?;
    append_scalar(&mut transcript, &evaluation)?;

    let opening_base = constrain_transcript_opening_base(
        cs.namespace(|| "opening base"),
        &transcript,
        basis_digest,
        REDUCTION_OPENING_BASE_ROLE,
    )?;
    let encoded_opening_base =
        encode_computed_point(cs.namespace(|| "encoded opening base"), opening_base)?;
    append_point(&mut transcript, &encoded_opening_base);

    let mut opening_residual = prepared.coefficient_commitment.point().clone();
    let mut folded_scale = one.clone();
    let mut folded_factors = vec![zero.clone(); rounds];
    for round in 0..rounds {
        let left = allocate_encoded_point(
            cs.namespace(|| format!("round {round} left")),
            proof.left[round],
        )?;
        let right = allocate_encoded_point(
            cs.namespace(|| format!("round {round} right")),
            proof.right[round],
        )?;
        append_point(&mut transcript, &left);
        append_point(&mut transcript, &right);
        let round_challenge = challenge(
            cs.namespace(|| format!("round {round} challenge")),
            &mut transcript,
            round as u64,
        )?;
        let inverse = invert_scalar(
            cs.namespace(|| format!("round {round} inverse")),
            &round_challenge,
        )?;
        let squared = multiply_scalars(
            cs.namespace(|| format!("round {round} squared")),
            &round_challenge,
            &round_challenge,
        )?;
        let inverse_squared = multiply_scalars(
            cs.namespace(|| format!("round {round} inverse squared")),
            &inverse,
            &inverse,
        )?;
        folded_scale = multiply_scalars(
            cs.namespace(|| format!("round {round} folded scale")),
            &folded_scale,
            &inverse,
        )?;
        folded_factors[rounds - 1 - round] = squared.clone();
        opening_residual = add_scaled(
            cs.namespace(|| format!("round {round} left term")),
            &opening_residual,
            left.point(),
            &squared,
        )?;
        opening_residual = add_scaled(
            cs.namespace(|| format!("round {round} right term")),
            &opening_residual,
            right.point(),
            &inverse_squared,
        )?;
    }

    let terminal =
        allocate_canonical_scalar(cs.namespace(|| "terminal scalar"), proof.terminal_scalar)?;
    let mut b_final = folded_scale.clone();
    for (round, (weight, factor)) in weights.factors.iter().zip(&folded_factors).enumerate() {
        let product = multiply_scalars(
            cs.namespace(|| format!("weight product {round}")),
            weight,
            factor,
        )?;
        let one_plus_product = add_scalars(
            cs.namespace(|| format!("one plus product {round}")),
            &one,
            &product,
        )?;
        b_final = multiply_scalars(
            cs.namespace(|| format!("b final {round}")),
            &b_final,
            &one_plus_product,
        )?;
    }
    let terminal_evaluation =
        multiply_scalars(cs.namespace(|| "terminal evaluation"), &terminal, &b_final)?;
    let opening_scalar = subtract_scalars(
        cs.namespace(|| "opening scalar"),
        &evaluation,
        &terminal_evaluation,
    )?;
    opening_residual = add_scaled(
        cs.namespace(|| "opening-base term"),
        &opening_residual,
        encoded_opening_base.point(),
        &opening_scalar,
    )?;

    let folded_generator =
        allocate_encoded_point(cs.namespace(|| "folded generator"), proof.folded_generator)?;
    let negative_terminal =
        subtract_scalars(cs.namespace(|| "negative terminal"), &zero, &terminal)?;
    opening_residual = add_scaled(
        cs.namespace(|| "folded-generator term"),
        &opening_residual,
        folded_generator.point(),
        &negative_terminal,
    )?;
    Boolean::enforce_equal(
        cs.namespace(|| "opening equation identity"),
        &opening_residual.is_identity(),
        &Boolean::constant(true),
    )?;

    let norm_shift = multiply_scalars(
        cs.namespace(|| "norm shift"),
        &prepared.polynomial[1].scale,
        &evaluation,
    )?;
    let negative_shift =
        subtract_scalars(cs.namespace(|| "negative norm shift"), &zero, &norm_shift)?;
    let shifted_generator = scale(
        cs.namespace(|| "shifted generator"),
        generator,
        &negative_shift,
    )?;
    let norm_point = add_points(
        cs.namespace(|| "norm point"),
        prepared.residual.point(),
        &shifted_generator,
    )?;
    let encoded_norm_point =
        encode_computed_point(cs.namespace(|| "encoded norm point"), norm_point)?;

    let folded = DirectPolynomialTerm {
        scale: folded_scale,
        offset: n_vec_len,
        factors: folded_factors,
    };
    append_scalar(&mut transcript, &terminal)?;
    append_point(&mut transcript, &folded_generator);
    append_point(&mut transcript, &encoded_norm_point);
    append_polynomial(&mut transcript, &prepared.polynomial)?;
    append_polynomial(&mut transcript, std::slice::from_ref(&folded))?;
    let fusion = challenge(
        cs.namespace(|| "fusion challenge"),
        &mut transcript,
        rounds as u64,
    )?;
    let scaled_folded = scale(
        cs.namespace(|| "fused folded generator"),
        folded_generator.point(),
        &fusion,
    )?;
    let combined = add_points(
        cs.namespace(|| "combined norm claim"),
        encoded_norm_point.point(),
        &scaled_folded,
    )?;
    let point = encode_computed_point(cs.namespace(|| "encoded norm claim"), combined)?;
    let mut polynomial = prepared.polynomial.clone();
    polynomial.push(DirectPolynomialTerm {
        scale: multiply_scalars(
            cs.namespace(|| "fused folded scale"),
            &folded.scale,
            &fusion,
        )?,
        offset: folded.offset,
        factors: folded.factors,
    });
    Ok(DirectPendingClaim { point, polynomial })
}

#[cfg(test)]
mod tests {
    use nova_snark::frontend::{
        shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem,
    };
    use num_bigint::BigUint;

    use super::*;
    use crate::nova_circuit_norm_leaf::allocate_standard_generator;
    use crate::nova_secp::{
        allocate_encoded_point as allocate_direct_point, DirectEncodedSecpPoint,
    };
    use crate::nova_secp_scalar::allocate_canonical_scalar as allocate_direct_scalar;
    use crate::nova_types::DirectNovaPrimaryEngine;
    use crate::secp_native::{encoded_point_value, standard_generator, SecpEncodedPointWitness};

    const BASIS: [u8; 32] = [0x42; 32];
    const N_VEC_LEN: usize = 2;

    fn allocate_direct_test_scalar<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: u64,
    ) -> Result<CanonicalSecpScalar, SynthesisError> {
        allocate_direct_scalar(cs, SecpScalarWitness::from_u64(value))
    }

    fn reduction_proof(terminal: u64) -> CandidateNormReductionProofWitness {
        CandidateNormReductionProofWitness {
            coefficient_evaluation: SecpScalarWitness::from_u64(0),
            left: vec![SecpEncodedPointWitness::identity()],
            right: vec![SecpEncodedPointWitness::identity()],
            terminal_scalar: SecpScalarWitness::from_u64(terminal),
            folded_generator: SecpEncodedPointWitness::from_point_value(standard_generator()),
        }
    }

    fn allocate_direct_prepared<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
    ) -> Result<DirectPreparedNorm, SynthesisError> {
        let identity = allocate_direct_point(
            cs.namespace(|| "coefficient commitment"),
            SecpEncodedPointWitness::identity(),
        )?;
        let residual = allocate_direct_point(
            cs.namespace(|| "residual"),
            SecpEncodedPointWitness::from_point_value(standard_generator()),
        )?;
        Ok(DirectPreparedNorm {
            prepared_binding: allocate_direct_test_scalar(cs.namespace(|| "binding"), 1)?,
            coefficient_commitment: identity,
            residual,
            polynomial: vec![
                DirectPolynomialTerm {
                    scale: allocate_direct_test_scalar(cs.namespace(|| "g scale"), 1)?,
                    offset: 0,
                    factors: vec![allocate_direct_test_scalar(cs.namespace(|| "g factor"), 1)?],
                },
                DirectPolynomialTerm {
                    scale: allocate_direct_test_scalar(cs.namespace(|| "h scale"), 0)?,
                    offset: N_VEC_LEN,
                    factors: vec![allocate_direct_test_scalar(cs.namespace(|| "h factor"), 1)?],
                },
            ],
        })
    }

    fn synthesize_direct<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        terminal: u64,
    ) -> Result<DirectPendingClaim, SynthesisError> {
        let prepared = allocate_direct_prepared(cs.namespace(|| "prepared norm"))?;
        let generator = allocate_standard_generator(cs.namespace(|| "standard generator"))?;
        constrain_candidate_norm_reduction(
            cs.namespace(|| "norm reduction"),
            BASIS,
            N_VEC_LEN,
            &prepared,
            &reduction_proof(terminal),
            &generator,
        )
    }

    fn scalar_value(value: &CanonicalSecpScalar) -> BigUint {
        let value = value.integer().cloned().expect("direct scalar witness");
        let (_, bytes) = value.to_bytes_be();
        BigUint::from_bytes_be(&bytes)
    }

    fn decimal(value: &str) -> BigUint {
        BigUint::parse_bytes(value.as_bytes(), 10).expect("decimal scalar")
    }

    fn assert_point_value(direct: &DirectEncodedSecpPoint, expected: SecpEncodedPointWitness) {
        let point = encoded_point_value(expected).expect("fixed point");
        assert_eq!(direct.point().x().get_value(), Some(point.x));
        assert_eq!(direct.point().y().get_value(), Some(point.y));
        assert_eq!(
            direct.point().identity_num().get_value(),
            Some(Scalar::from(u64::from(point.identity)))
        );
        assert_eq!(
            direct.prefix().get_value(),
            Some(Scalar::from(u64::from(expected.encoded[0])))
        );
    }

    #[test]
    fn direct_reduction_matches_reference_vector_and_rejects_false_equation() {
        let mut direct_cs = TestConstraintSystem::<Scalar>::new();
        let direct = synthesize_direct(&mut direct_cs, 0).expect("direct norm reduction");
        assert!(direct_cs.is_satisfied());

        assert_point_value(
            &direct.point,
            SecpEncodedPointWitness::parse([
                0x02, 0xab, 0x1b, 0xcb, 0xac, 0x2b, 0x0c, 0x81, 0x70, 0xd3, 0x04, 0x7f, 0x9e, 0x3c,
                0xfa, 0xbf, 0x93, 0x4f, 0x19, 0x8a, 0x55, 0x5c, 0x83, 0x20, 0xfd, 0xb5, 0xf5, 0x74,
                0x7b, 0xfe, 0x3d, 0x23, 0xc5,
            ])
            .expect("reference claim point"),
        );
        assert_eq!(direct.polynomial.len(), 3);
        assert_eq!(direct.polynomial[0].offset, 0);
        assert_eq!(
            scalar_value(&direct.polynomial[0].scale),
            BigUint::from(1u8)
        );
        assert_eq!(
            scalar_value(&direct.polynomial[0].factors[0]),
            BigUint::from(1u8)
        );
        assert_eq!(direct.polynomial[1].offset, N_VEC_LEN);
        assert_eq!(
            scalar_value(&direct.polynomial[1].scale),
            BigUint::from(0u8)
        );
        assert_eq!(
            scalar_value(&direct.polynomial[1].factors[0]),
            BigUint::from(1u8)
        );
        assert_eq!(direct.polynomial[2].offset, N_VEC_LEN);
        assert_eq!(
            scalar_value(&direct.polynomial[2].scale),
            decimal(
                "41714680874141315438122792739259685834026589319420274763082776406568500954335"
            )
        );
        assert_eq!(direct.polynomial[2].factors.len(), 1);
        assert_eq!(
            scalar_value(&direct.polynomial[2].factors[0]),
            decimal(
                "43331756306731222684854570967364175767855055185305307474018807833125165109156"
            )
        );

        let mut wrong_cs = TestConstraintSystem::<Scalar>::new();
        synthesize_direct(&mut wrong_cs, 1).expect("well-shaped false reduction");
        assert!(!wrong_cs.is_satisfied());
        assert_eq!(direct_cs.num_constraints(), wrong_cs.num_constraints());
    }

    #[test]
    fn direct_reduction_shape_is_witness_independent_and_pinned() {
        let mut first = ShapeCS::<DirectNovaPrimaryEngine>::new();
        synthesize_direct(&mut first, 0).expect("first reduction shape");
        let mut second = ShapeCS::<DirectNovaPrimaryEngine>::new();
        synthesize_direct(&mut second, 1).expect("second reduction shape");

        assert_eq!(first.num_inputs(), 1);
        assert_eq!(
            (first.num_aux(), first.num_constraints()),
            (597_064, 599_168)
        );
        assert_eq!(first.num_aux(), second.num_aux());
        assert_eq!(first.num_constraints(), second.num_constraints());
        assert_eq!(first.constraints, second.constraints);
    }

    #[test]
    fn direct_reduction_rejects_malformed_shape() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let prepared =
            allocate_direct_prepared(cs.namespace(|| "prepared norm")).expect("prepared norm");
        let generator = allocate_standard_generator(cs.namespace(|| "standard generator"))
            .expect("standard generator");
        let mut proof = reduction_proof(0);
        proof.right.clear();
        assert!(constrain_candidate_norm_reduction(
            cs.namespace(|| "norm reduction"),
            BASIS,
            N_VEC_LEN,
            &prepared,
            &proof,
            &generator,
        )
        .is_err());
    }
}
