//! Internal typed-Poseidon coefficient-reduction relation.
//!
//! This module turns an already constrained prepared norm into one constrained
//! pending claim. It does not authenticate a child proof by itself and exposes
//! no receipt acceptance API.

use ff::Field;

use crate::algebraic_transcript::BuilderTranscript;
use crate::opening_base::{constrain_transcript_opening_base, REDUCTION_OPENING_BASE_ROLE};
use crate::parent_relation::{
    add_points, allocate_encoded_point, append_challenge, append_computed_point,
    append_constant_bytes, append_constrained_polynomial, append_encoded_point, append_scalar,
    derived_inverse, derived_multiply, derived_subtract, encode_computed_point, msm_points,
    scale_constant_point, standard_generator, ConstrainedPendingClaim, ConstrainedPolynomialTerm,
    EncodedSecpPoint, SecpEncodedPointWitness,
};
use crate::relation_builder::{Builder, Expression};
use crate::secp_scalar::{
    allocate_canonical_scalar, constant_scalar, SecpScalarVar, SecpScalarWitness,
};
use crate::{ReceiptCycleError, Scalar};

const NORM_REDUCTION_DOMAIN: &[u8] = b"Purify/BPPP/CandidateNormReduction/v2";
const MAX_REDUCTION_ROUNDS: usize = 24;

pub(crate) struct ConstrainedPreparedNorm {
    pub(crate) prepared_binding: SecpScalarVar,
    pub(crate) coefficient_commitment: EncodedSecpPoint,
    pub(crate) residual: EncodedSecpPoint,
    pub(crate) polynomial: Vec<ConstrainedPolynomialTerm>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateNormReductionProofWitness {
    pub(crate) coefficient_evaluation: SecpScalarWitness,
    pub(crate) left: Vec<SecpEncodedPointWitness>,
    pub(crate) right: Vec<SecpEncodedPointWitness>,
    pub(crate) terminal_scalar: SecpScalarWitness,
    pub(crate) folded_generator: SecpEncodedPointWitness,
}

fn validate_shape(
    n_vec_len: usize,
    prepared: &ConstrainedPreparedNorm,
    proof: &CandidateNormReductionProofWitness,
) -> Result<usize, ReceiptCycleError> {
    let rounds = proof.left.len();
    if !n_vec_len.is_power_of_two()
        || rounds > MAX_REDUCTION_ROUNDS
        || proof.right.len() != rounds
        || prepared.polynomial.len() != 2
    {
        return Err(ReceiptCycleError::Malformed(
            "candidate norm reduction shape",
        ));
    }
    let l_vec_len = 1usize
        .checked_shl(rounds as u32)
        .ok_or(ReceiptCycleError::Malformed(
            "candidate norm reduction width",
        ))?;
    if l_vec_len > n_vec_len {
        return Err(ReceiptCycleError::Malformed(
            "candidate norm reduction width",
        ));
    }
    let g = &prepared.polynomial[0];
    let h = &prepared.polynomial[1];
    if g.offset != 0
        || g.factors.len() != n_vec_len.trailing_zeros() as usize
        || h.offset != n_vec_len
        || h.factors.len() != rounds
    {
        return Err(ReceiptCycleError::Malformed(
            "candidate prepared norm polynomial",
        ));
    }
    Ok(rounds)
}

pub(crate) fn install_candidate_norm_reduction(
    builder: &mut Builder,
    basis_digest: [u8; 32],
    n_vec_len: usize,
    prepared: &ConstrainedPreparedNorm,
    proof: &CandidateNormReductionProofWitness,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    let rounds = validate_shape(n_vec_len, prepared, proof)?;
    let mut transcript = BuilderTranscript::new();
    append_constant_bytes(&mut transcript, builder, NORM_REDUCTION_DOMAIN)?;
    append_constant_bytes(&mut transcript, builder, &basis_digest)?;
    transcript.append_u64(builder, rounds as u64);
    // The child transcript selects a canonical nonzero binding. Requiring an
    // inverse preserves that invariant even before the leaf relation lands.
    let _binding_inverse = derived_inverse(builder, &prepared.prepared_binding)?;
    append_scalar(&mut transcript, builder, &prepared.prepared_binding);
    append_encoded_point(&mut transcript, builder, &prepared.coefficient_commitment);

    let weights = ConstrainedPolynomialTerm {
        scale: constant_scalar(1),
        offset: 0,
        factors: prepared.polynomial[1].factors.clone(),
    };
    append_constrained_polynomial(&mut transcript, builder, std::slice::from_ref(&weights));
    let evaluation = allocate_canonical_scalar(builder, proof.coefficient_evaluation)?;
    append_scalar(&mut transcript, builder, &evaluation);

    let opening_base = constrain_transcript_opening_base(
        builder,
        &transcript,
        basis_digest,
        REDUCTION_OPENING_BASE_ROLE,
    )?;
    append_computed_point(&mut transcript, builder, &opening_base);

    let mut equation_points = vec![prepared.coefficient_commitment.point.clone()];
    let mut equation_scalars = vec![constant_scalar(1)];
    let mut folded_scale = constant_scalar(1);
    let mut folded_factors = vec![constant_scalar(0); rounds];
    for round in 0..rounds {
        let left = allocate_encoded_point(builder, proof.left[round])?;
        let right = allocate_encoded_point(builder, proof.right[round])?;
        append_encoded_point(&mut transcript, builder, &left);
        append_encoded_point(&mut transcript, builder, &right);
        let challenge = append_challenge(&mut transcript, builder, round as u64);
        let inverse = derived_inverse(builder, &challenge)?;
        let squared = derived_multiply(builder, &challenge, &challenge)?;
        let inverse_squared = derived_multiply(builder, &inverse, &inverse)?;
        folded_scale = derived_multiply(builder, &folded_scale, &inverse)?;
        folded_factors[rounds - 1 - round] = squared.clone();
        equation_points.push(left.point);
        equation_scalars.push(squared);
        equation_points.push(right.point);
        equation_scalars.push(inverse_squared);
    }

    let terminal = allocate_canonical_scalar(builder, proof.terminal_scalar)?;
    let mut b_final = folded_scale.clone();
    for (weight, factor) in weights.factors.iter().zip(&folded_factors) {
        let product = derived_multiply(builder, weight, factor)?;
        let one_plus_product =
            crate::parent_relation::derived_add(builder, &constant_scalar(1), &product)?;
        b_final = derived_multiply(builder, &b_final, &one_plus_product)?;
    }
    let terminal_evaluation = derived_multiply(builder, &terminal, &b_final)?;
    let opening_scalar = derived_subtract(builder, &evaluation, &terminal_evaluation)?;
    equation_points.push(opening_base);
    equation_scalars.push(opening_scalar);

    let folded_generator = allocate_encoded_point(builder, proof.folded_generator)?;
    equation_points.push(folded_generator.point.clone());
    equation_scalars.push(derived_subtract(builder, &constant_scalar(0), &terminal)?);
    let opening_residual = msm_points(builder, &equation_points, &equation_scalars)?;
    builder.constrain_zero(opening_residual.x);
    builder.constrain_zero(opening_residual.y);
    builder.constrain_equal(
        &opening_residual.identity,
        &Expression::constant(Scalar::ONE),
    );

    let norm_shift = derived_multiply(builder, &prepared.polynomial[1].scale, &evaluation)?;
    let negative_shift = derived_subtract(builder, &constant_scalar(0), &norm_shift)?;
    let shifted_generator = scale_constant_point(builder, standard_generator(), &negative_shift)?;
    let norm_point = add_points(builder, &prepared.residual.point, &shifted_generator);

    let folded = ConstrainedPolynomialTerm {
        scale: folded_scale,
        offset: n_vec_len,
        factors: folded_factors,
    };
    append_scalar(&mut transcript, builder, &terminal);
    append_encoded_point(&mut transcript, builder, &folded_generator);
    append_computed_point(&mut transcript, builder, &norm_point);
    append_constrained_polynomial(&mut transcript, builder, &prepared.polynomial);
    append_constrained_polynomial(&mut transcript, builder, std::slice::from_ref(&folded));
    let fusion = append_challenge(&mut transcript, builder, rounds as u64);

    let combined = msm_points(
        builder,
        &[norm_point, folded_generator.point],
        &[constant_scalar(1), fusion.clone()],
    )?;
    let point = encode_computed_point(builder, &combined);
    let mut polynomial = prepared.polynomial.clone();
    polynomial.push(ConstrainedPolynomialTerm {
        scale: derived_multiply(builder, &folded.scale, &fusion)?,
        offset: folded.offset,
        factors: folded.factors,
    });
    Ok(ConstrainedPendingClaim { point, polynomial })
}

#[cfg(test)]
mod tests;
