//! Direct Nova coefficient reduction for one prepared norm.
//!
//! This layer owns the reduction transcript and opening equation. It consumes
//! an already constrained norm and returns one pending candidate claim.

use nova_snark::frontend::{ConstraintSystem, SynthesisError};

use crate::gadgets::ops::Ops;
use crate::gadgets::point::Point;
use crate::gadgets::sha256::Transcript;
use crate::gadgets::synthesis_error;
use crate::gadgets::transcript::{append_constant_bytes, append_point, append_scalar};
use crate::native::circuit_norm::CandidateNormReductionProofWitness;
use crate::native::opening_generators::REDUCTION_OPENING_BASE_ROLE;
use crate::relation::candidate::{
    append_polynomial, evaluate_tensor, fold_opening_rounds, PendingClaim, PolynomialTerm,
};
use crate::relation::norm_leaf::PreparedNorm;
use crate::relation::opening_base::constrain_transcript_opening_base;
use statement::Scalar;

const NORM_REDUCTION_DOMAIN: &[u8] = b"Purify/BPPP/CandidateNormReduction/v2";
const MAX_REDUCTION_ROUNDS: usize = 24;

fn validate_shape(
    n_vec_len: usize,
    prepared: &PreparedNorm,
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
    cs: CS,
    basis_digest: [u8; 32],
    n_vec_len: usize,
    prepared: &PreparedNorm,
    proof: &CandidateNormReductionProofWitness,
    generator: &Point,
) -> Result<PendingClaim, SynthesisError> {
    let rounds = validate_shape(n_vec_len, prepared, proof)?;
    let mut ops = Ops::new(cs);
    let zero = ops.constant(0)?;
    let one = ops.constant(1)?;
    let mut transcript = Transcript::new();
    append_constant_bytes(&mut transcript, NORM_REDUCTION_DOMAIN)?;
    append_constant_bytes(&mut transcript, &basis_digest)?;
    transcript.append_u64(rounds as u64);
    ops.require_nonzero(&prepared.prepared_binding)?;
    append_scalar(&mut transcript, &prepared.prepared_binding)?;
    append_point(&mut transcript, &prepared.coefficient_commitment);

    let weights = PolynomialTerm {
        scale: one.clone(),
        offset: 0,
        factors: prepared.polynomial[1].factors.clone(),
    };
    append_polynomial(&mut transcript, std::slice::from_ref(&weights))?;
    let evaluation = ops.scalar(proof.coefficient_evaluation)?;
    append_scalar(&mut transcript, &evaluation)?;

    let opening_base = constrain_transcript_opening_base(
        ops.scope("opening base"),
        &transcript,
        basis_digest,
        REDUCTION_OPENING_BASE_ROLE,
    )?;
    let opening_base = ops.encode(opening_base)?;
    append_point(&mut transcript, &opening_base);

    // Opening equation, with b = folded_scale prod_r (1 + weight_r folded_factor_r):
    //   folded residual + (evaluation - terminal b) opening_base
    //     - terminal folded_generator = 0
    let folded = fold_opening_rounds(
        &mut ops,
        &mut transcript,
        prepared.coefficient_commitment.point().clone(),
        &proof.left,
        &proof.right,
        0,
    )?;
    let terminal = ops.scalar(proof.terminal_scalar)?;
    let b_final = evaluate_tensor(&mut ops, &folded.scale, &weights.factors, &folded.factors)?;
    let terminal_evaluation = ops.mul(&terminal, &b_final)?;
    let opening_scalar = ops.sub(&evaluation, &terminal_evaluation)?;
    let opening_residual =
        ops.add_scaled(&folded.residual, opening_base.point(), &opening_scalar)?;

    let folded_generator = ops.point(proof.folded_generator)?;
    let negative_terminal = ops.sub(&zero, &terminal)?;
    let opening_residual = ops.add_scaled(
        &opening_residual,
        folded_generator.point(),
        &negative_terminal,
    )?;
    ops.require_identity(&opening_residual)?;

    // norm_point = residual - (terminal_l evaluation) G
    let norm_shift = ops.mul(&prepared.polynomial[1].scale, &evaluation)?;
    let negative_shift = ops.sub(&zero, &norm_shift)?;
    let shifted_generator = ops.scale(generator, &negative_shift)?;
    let norm_point = ops.add_points(prepared.residual.point(), &shifted_generator)?;
    let norm_point = ops.encode(norm_point)?;

    // The pending claim fuses the norm point with the folded opening.
    let folded = PolynomialTerm {
        scale: folded.scale,
        offset: n_vec_len,
        factors: folded.factors,
    };
    append_scalar(&mut transcript, &terminal)?;
    append_point(&mut transcript, &folded_generator);
    append_point(&mut transcript, &norm_point);
    append_polynomial(&mut transcript, &prepared.polynomial)?;
    append_polynomial(&mut transcript, std::slice::from_ref(&folded))?;
    let fusion = ops.challenge(&mut transcript, rounds as u64)?;
    let scaled_folded = ops.scale(folded_generator.point(), &fusion)?;
    let combined = ops.add_points(norm_point.point(), &scaled_folded)?;
    let point = ops.encode(combined)?;
    let mut polynomial = prepared.polynomial.clone();
    polynomial.push(PolynomialTerm {
        scale: ops.mul(&folded.scale, &fusion)?,
        offset: folded.offset,
        factors: folded.factors,
    });
    Ok(PendingClaim { point, polynomial })
}

#[cfg(test)]
mod tests {
    use nova_snark::frontend::{
        shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem,
    };
    use num_bigint::BigUint;

    use super::*;
    use crate::gadgets::point::{allocate_encoded_point as allocate_direct_point, EncodedPoint};
    use crate::gadgets::scalar::{
        allocate_canonical_scalar as allocate_test_scalar, CanonicalScalar,
    };
    use crate::native::secp::SecpScalarWitness;
    use crate::native::secp::{encoded_point_value, standard_generator, SecpEncodedPointWitness};
    use crate::relation::norm_leaf::allocate_standard_generator;
    use statement::PrimaryEngine;

    const BASIS: [u8; 32] = [0x42; 32];
    const N_VEC_LEN: usize = 2;

    fn allocate_direct_test_scalar<CS: ConstraintSystem<Scalar>>(
        cs: CS,
        value: u64,
    ) -> Result<CanonicalScalar, SynthesisError> {
        allocate_test_scalar(cs, SecpScalarWitness::from_u64(value))
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
    ) -> Result<PreparedNorm, SynthesisError> {
        let identity = allocate_direct_point(
            cs.namespace(|| "coefficient commitment"),
            SecpEncodedPointWitness::identity(),
        )?;
        let residual = allocate_direct_point(
            cs.namespace(|| "residual"),
            SecpEncodedPointWitness::from_point_value(standard_generator()),
        )?;
        Ok(PreparedNorm {
            prepared_binding: allocate_direct_test_scalar(cs.namespace(|| "binding"), 1)?,
            coefficient_commitment: identity,
            residual,
            polynomial: vec![
                PolynomialTerm {
                    scale: allocate_direct_test_scalar(cs.namespace(|| "g scale"), 1)?,
                    offset: 0,
                    factors: vec![allocate_direct_test_scalar(cs.namespace(|| "g factor"), 1)?],
                },
                PolynomialTerm {
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
    ) -> Result<PendingClaim, SynthesisError> {
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

    fn scalar_value(value: &CanonicalScalar) -> BigUint {
        let value = value.integer().cloned().expect("direct scalar witness");
        let (_, bytes) = value.to_bytes_be();
        BigUint::from_bytes_be(&bytes)
    }

    fn decimal(value: &str) -> BigUint {
        BigUint::parse_bytes(value.as_bytes(), 10).expect("decimal scalar")
    }

    fn assert_point_value(direct: &EncodedPoint, expected: SecpEncodedPointWitness) {
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
    fn constrained_reduction_matches_reference_vector_and_rejects_false_equation() {
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
    fn constrained_reduction_shape_is_witness_independent_and_pinned() {
        let mut first = ShapeCS::<PrimaryEngine>::new();
        synthesize_direct(&mut first, 0).expect("first reduction shape");
        let mut second = ShapeCS::<PrimaryEngine>::new();
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
    fn constrained_reduction_rejects_malformed_shape() {
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
