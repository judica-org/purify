//! Composed constrained V4 circuit-norm leaf relation.
//!
//! This module consumes the exact variables allocated by the V4 transcript,
//! checks the outer circuit-proof equations, prepares the short inner norm
//! obligation, and immediately reduces it to one pending claim. It does not
//! expose a receipt-acceptance API.

use crate::algebraic_circuit_transcript::{
    install_transcript, install_transcript_with_constrained_binding, CircuitCommitmentModeV4,
    CircuitProofTranscriptWitnessV4, CircuitTranscriptResultV4, CircuitTranscriptShapeV4,
};
use crate::algebraic_transcript::ConstrainedBytes32;
use crate::norm_reduction::{
    install_candidate_norm_reduction, CandidateNormReductionProofWitness, ConstrainedPreparedNorm,
};
use crate::parent_relation::{
    add_points, constrain_encoded_point_constant, derived_multiply, derived_subtract,
    encode_computed_point, encoded_point_value, msm_points, scale_constant_point,
    standard_generator, ConstrainedPendingClaim, ConstrainedPolynomialTerm, EncodedSecpPoint,
    SecpEncodedPointWitness, SecpPoint,
};
use crate::relation_builder::Builder;
use crate::secp_scalar::{
    constant_scalar, constant_scalar_witness, constrain_scalar_equal, SecpScalarVar,
    SecpScalarWitness,
};
use crate::ReceiptCycleError;

// Inverse of the native protocol's fixed even square root of minus one,
// 70ad49ae7f8574ecab641a42b3a24f22d6374023944cc665a6bcaeb0f37bbf78,
// modulo the secp256k1 group order.
const SQRT_MINUS_ONE_INVERSE: SecpScalarWitness = SecpScalarWitness::from_bytes_be([
    0x8f, 0x52, 0xb6, 0x51, 0x80, 0x7a, 0x8b, 0x13, 0x54, 0x9b, 0xe5, 0xbd, 0x4c, 0x5d, 0xb0, 0xdb,
    0xe4, 0x77, 0x9c, 0xc3, 0x1a, 0xfb, 0xd9, 0xd6, 0x19, 0x15, 0xaf, 0xdb, 0xdc, 0xba, 0x81, 0xc9,
]);

/// Verifier-precomputed constants for one V4 child.
///
/// The native verifier must derive these from the authenticated circuit,
/// public commitments, and raw accumulation basis. They are circuit constants,
/// never prover-selected replacement witnesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CircuitNormLeafConstantsV4 {
    pub(crate) precommitment: SecpScalarWitness,
    pub(crate) coefficient_commitment: SecpEncodedPointWitness,
    pub(crate) anchored_offset: SecpEncodedPointWitness,
}

/// Public statement fixed when regenerating one leaf circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CircuitNormLeafStatementV4 {
    pub(crate) shape: CircuitTranscriptShapeV4,
    pub(crate) circuit_binding_digest: [u8; 32],
    pub(crate) raw_generator_digest: [u8; 32],
    pub(crate) basis_digest: [u8; 32],
    pub(crate) constants: CircuitNormLeafConstantsV4,
}

/// Public setup statement with its exact ordered output commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicCircuitNormLeafStatementV4 {
    pub(crate) leaf: CircuitNormLeafStatementV4,
    pub(crate) public_commitments: Vec<SecpEncodedPointWitness>,
}

/// Varying public input for one production hidden-anchor leaf.
///
/// Shape and basis values still select one fixed relation. The binding digest
/// is allocated as canonical bytes so its value lives only in the assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestBoundAnchorLeafStatementV4 {
    pub(crate) shape: CircuitTranscriptShapeV4,
    pub(crate) circuit_binding_digest: [u8; 32],
    pub(crate) raw_generator_digest: [u8; 32],
    pub(crate) basis_digest: [u8; 32],
}

/// One hidden-anchor claim together with the exact variables that authenticate
/// its verifier-precomputed public data in a construction manifest.
pub(crate) struct ManifestBoundAnchorLeaf {
    pub(crate) claim: ConstrainedPendingClaim,
    pub(crate) circuit_binding_digest: ConstrainedBytes32,
    pub(crate) precommitment: SecpScalarVar,
    pub(crate) coefficient_commitment: EncodedSecpPoint,
    pub(crate) anchored_offset: EncodedSecpPoint,
}

fn constrain_point_equal(builder: &mut Builder, left: &SecpPoint, right: &SecpPoint) {
    builder.constrain_equal(&left.x, &right.x);
    builder.constrain_equal(&left.y, &right.y);
    builder.constrain_equal(&left.identity, &right.identity);
}

fn square_repeatedly(
    builder: &mut Builder,
    value: &SecpScalarVar,
    count: usize,
) -> Result<SecpScalarVar, ReceiptCycleError> {
    let mut result = value.clone();
    for _ in 0..count {
        result = derived_multiply(builder, &result, &result)?;
    }
    Ok(result)
}

fn constrain_public_constants(
    builder: &mut Builder,
    transcript: &CircuitTranscriptResultV4,
    expected: CircuitNormLeafConstantsV4,
) -> Result<(), ReceiptCycleError> {
    let expected_precommitment = constant_scalar_witness(expected.precommitment)?;
    constrain_scalar_equal(builder, &transcript.precommitment, &expected_precommitment);
    constrain_encoded_point_constant(
        builder,
        &transcript.coefficient_commitment,
        expected.coefficient_commitment,
    )?;
    constrain_encoded_point_constant(
        builder,
        &transcript.anchored_offset,
        expected.anchored_offset,
    )
}

fn constrain_anchor_and_mask(
    builder: &mut Builder,
    transcript: &CircuitTranscriptResultV4,
) -> Result<(), ReceiptCycleError> {
    builder.constrain_zero(transcript.raw_commitment.point.identity.clone());
    builder.constrain_zero(transcript.mask_commitment.point.identity.clone());
    let anchored = add_points(
        builder,
        &transcript.raw_commitment.point,
        &transcript.anchored_offset.point,
    );
    builder.constrain_zero(anchored.identity.clone());
    constrain_point_equal(builder, &anchored, &transcript.anchored_commitment.point);

    let alpha_squared = derived_multiply(builder, &transcript.alpha, &transcript.alpha)?;
    let t2_scale = derived_multiply(builder, &alpha_squared, &transcript.t2)?;
    let masked = msm_points(
        builder,
        &[
            transcript.anchored_commitment.point.clone(),
            transcript.mask_commitment.point.clone(),
        ],
        &[constant_scalar(1), transcript.alpha.clone()],
    )?;
    let t2_point = scale_constant_point(builder, standard_generator(), &t2_scale)?;
    let combined = add_points(builder, &masked, &t2_point);
    builder.constrain_zero(combined.identity.clone());
    constrain_point_equal(builder, &combined, &transcript.combined_commitment.point);
    Ok(())
}

fn constrain_public_dlog(
    builder: &mut Builder,
    transcript: &CircuitTranscriptResultV4,
    public_commitments: &[SecpEncodedPointWitness],
) -> Result<(), ReceiptCycleError> {
    if public_commitments.is_empty()
        || public_commitments.len() != transcript.public_commitments.len()
    {
        return Err(ReceiptCycleError::Malformed(
            "public V4 circuit norm commitments",
        ));
    }
    for (actual, &expected) in transcript.public_commitments.iter().zip(public_commitments) {
        builder.constrain_zero(actual.point.identity.clone());
        constrain_encoded_point_constant(builder, actual, expected)?;
    }
    let mut weights = Vec::with_capacity(transcript.public_commitments.len());
    weights.push(constant_scalar(1));
    let mut weight = transcript.eta.clone();
    for index in 1..transcript.public_commitments.len() {
        weights.push(weight.clone());
        if index + 1 != transcript.public_commitments.len() {
            weight = derived_multiply(builder, &weight, &transcript.eta)?;
        }
    }
    let batched = if transcript.public_commitments.len() == 1 {
        transcript.public_commitments[0].point.clone()
    } else {
        let points = transcript
            .public_commitments
            .iter()
            .map(|point| point.point.clone())
            .collect::<Vec<_>>();
        msm_points(builder, &points, &weights)?
    };
    builder.constrain_zero(batched.identity.clone());
    constrain_point_equal(
        builder,
        &batched,
        &transcript.batched_public_commitment.point,
    );

    let mut scaled_commitments = Vec::with_capacity(public_commitments.len());
    for (index, (&point, weight)) in public_commitments.iter().zip(&weights).enumerate() {
        let scale = if index == 0 {
            transcript.dlog_challenge.clone()
        } else {
            derived_multiply(builder, &transcript.dlog_challenge, weight)?
        };
        scaled_commitments.push(scale_constant_point(
            builder,
            encoded_point_value(point)?,
            &scale,
        )?);
    }
    let mut scaled_batch = scaled_commitments[0].clone();
    for term in &scaled_commitments[1..] {
        scaled_batch = add_points(builder, &scaled_batch, term);
    }
    let _response_inverse =
        crate::parent_relation::derived_inverse(builder, &transcript.dlog_response)?;
    let lhs = scale_constant_point(builder, standard_generator(), &transcript.dlog_response)?;
    let rhs = add_points(builder, &transcript.dlog_nonce.point, &scaled_batch);
    constrain_point_equal(builder, &lhs, &rhs);
    Ok(())
}

fn prepare_norm(
    builder: &mut Builder,
    shape: CircuitTranscriptShapeV4,
    transcript: &CircuitTranscriptResultV4,
) -> Result<ConstrainedPreparedNorm, ReceiptCycleError> {
    constrain_anchor_and_mask(builder, transcript)?;

    let rounds = shape.round_count();
    let rho_to_n = square_repeatedly(builder, &transcript.rho, rounds)?;
    let rho_to_two_n = derived_multiply(builder, &rho_to_n, &rho_to_n)?;
    let terminal_n_squared =
        derived_multiply(builder, &transcript.terminal_n, &transcript.terminal_n)?;
    let norm_scale = derived_multiply(builder, &terminal_n_squared, &rho_to_two_n)?;
    let negative_norm_scale = derived_subtract(builder, &constant_scalar(0), &norm_scale)?;

    let mut residual_points = Vec::with_capacity(1 + 2 * rounds);
    let mut residual_scalars = Vec::with_capacity(1 + 2 * rounds);
    residual_points.push(transcript.combined_commitment.point.clone());
    residual_scalars.push(constant_scalar(1));
    for (pair, gamma) in transcript.rounds.iter().zip(&transcript.gammas) {
        let gamma_squared = derived_multiply(builder, gamma, gamma)?;
        let gamma_squared_minus_one =
            derived_subtract(builder, &gamma_squared, &constant_scalar(1))?;
        // The native BP++ callback parses the first packed point as X and the
        // second as R: gamma*X + (gamma^2 - 1)*R.
        residual_points.push(pair.first.point.clone());
        residual_scalars.push(gamma.clone());
        residual_points.push(pair.second.point.clone());
        residual_scalars.push(gamma_squared_minus_one);
    }
    let short = msm_points(builder, &residual_points, &residual_scalars)?;
    let norm_base = scale_constant_point(builder, standard_generator(), &negative_norm_scale)?;
    let residual_point = add_points(builder, &short, &norm_base);
    let residual = encode_computed_point(builder, &residual_point);

    let mul_scale_inverse =
        crate::parent_relation::derived_inverse(builder, &transcript.mul_scale)?;
    let n_rho = derived_multiply(builder, &transcript.terminal_n, &rho_to_n)?;
    let g_scale = derived_multiply(builder, &n_rho, &mul_scale_inverse)?;
    let sqrt_minus_one_inverse = constant_scalar_witness(SQRT_MINUS_ONE_INVERSE)?;
    let mut g_factors = Vec::with_capacity(rounds);
    g_factors.push(derived_multiply(
        builder,
        &transcript.gammas[0],
        &sqrt_minus_one_inverse,
    )?);
    let mut ratio_inverse_power =
        crate::parent_relation::derived_inverse(builder, &transcript.mul_ratio)?;
    for gamma in transcript.gammas.iter().skip(1) {
        g_factors.push(derived_multiply(builder, gamma, &ratio_inverse_power)?);
        ratio_inverse_power =
            derived_multiply(builder, &ratio_inverse_power, &ratio_inverse_power)?;
    }

    let h_factors = transcript.gammas.clone();
    Ok(ConstrainedPreparedNorm {
        prepared_binding: transcript.prepared_binding.clone(),
        coefficient_commitment: transcript.coefficient_commitment.clone(),
        residual,
        polynomial: vec![
            ConstrainedPolynomialTerm {
                scale: g_scale,
                offset: 0,
                factors: g_factors,
            },
            ConstrainedPolynomialTerm {
                scale: transcript.terminal_l.clone(),
                offset: shape.n_vec_len,
                factors: h_factors,
            },
        ],
    })
}

fn finish_circuit_norm_leaf(
    builder: &mut Builder,
    shape: CircuitTranscriptShapeV4,
    basis_digest: [u8; 32],
    public_commitments: Option<&[SecpEncodedPointWitness]>,
    transcript: &CircuitTranscriptResultV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    match (shape.mode, public_commitments) {
        (CircuitCommitmentModeV4::Hidden, None) => {}
        (CircuitCommitmentModeV4::Public, Some(public_commitments)) => {
            if public_commitments.len() != shape.commitment_count {
                return Err(ReceiptCycleError::Malformed(
                    "public V4 circuit norm statement commitments",
                ));
            }
            constrain_public_dlog(builder, transcript, public_commitments)?;
        }
        _ => {
            return Err(ReceiptCycleError::Malformed(
                "V4 circuit norm statement mode",
            ));
        }
    }
    let prepared = prepare_norm(builder, shape, transcript)?;
    install_candidate_norm_reduction(
        builder,
        basis_digest,
        shape.n_vec_len,
        &prepared,
        reduction_proof,
    )
}

fn install_constant_bound_circuit_norm_leaf(
    builder: &mut Builder,
    statement: CircuitNormLeafStatementV4,
    public_commitments: Option<&[SecpEncodedPointWitness]>,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    let transcript = install_transcript(
        builder,
        statement.shape,
        statement.circuit_binding_digest,
        statement.raw_generator_digest,
        transcript_witness,
    )?;
    constrain_public_constants(builder, &transcript, statement.constants)?;
    finish_circuit_norm_leaf(
        builder,
        statement.shape,
        statement.basis_digest,
        public_commitments,
        &transcript,
        reduction_proof,
    )
}

/// Installs one hidden-commitment anchor leaf and returns its sole pending
/// accumulation claim.
pub(crate) fn install_hidden_circuit_norm_leaf(
    builder: &mut Builder,
    statement: CircuitNormLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    if statement.shape.mode != CircuitCommitmentModeV4::Hidden {
        return Err(ReceiptCycleError::Malformed(
            "hidden V4 circuit norm leaf mode",
        ));
    }
    install_constant_bound_circuit_norm_leaf(
        builder,
        statement,
        None,
        transcript_witness,
        reduction_proof,
    )
}

/// Installs one public-commitment setup leaf and returns its sole pending
/// accumulation claim.
pub(crate) fn install_public_circuit_norm_leaf(
    builder: &mut Builder,
    statement: &PublicCircuitNormLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ConstrainedPendingClaim, ReceiptCycleError> {
    if statement.leaf.shape.mode != CircuitCommitmentModeV4::Public {
        return Err(ReceiptCycleError::Malformed(
            "public V4 circuit norm leaf mode",
        ));
    }
    install_constant_bound_circuit_norm_leaf(
        builder,
        statement.leaf,
        Some(&statement.public_commitments),
        transcript_witness,
        reduction_proof,
    )
}

/// Installs one production hidden-anchor leaf whose varying verifier constants
/// must be consumed by the construction manifest.
///
/// There is deliberately no constructor returning only the pending claim from
/// this path. The transcript-derived values used by the leaf equations are the
/// same variables returned for manifest authentication.
pub(crate) fn install_manifest_bound_anchor_leaf(
    builder: &mut Builder,
    statement: ManifestBoundAnchorLeafStatementV4,
    transcript_witness: &CircuitProofTranscriptWitnessV4,
    reduction_proof: &CandidateNormReductionProofWitness,
) -> Result<ManifestBoundAnchorLeaf, ReceiptCycleError> {
    if statement.shape.mode != CircuitCommitmentModeV4::Hidden {
        return Err(ReceiptCycleError::Malformed(
            "manifest-bound V4 anchor mode",
        ));
    }
    let circuit_binding_digest =
        ConstrainedBytes32::allocate(builder, statement.circuit_binding_digest);
    let transcript = install_transcript_with_constrained_binding(
        builder,
        statement.shape,
        &circuit_binding_digest,
        statement.raw_generator_digest,
        transcript_witness,
    )?;
    let precommitment = transcript.precommitment.clone();
    let coefficient_commitment = transcript.coefficient_commitment.clone();
    let anchored_offset = transcript.anchored_offset.clone();
    let claim = finish_circuit_norm_leaf(
        builder,
        statement.shape,
        statement.basis_digest,
        None,
        &transcript,
        reduction_proof,
    )?;
    Ok(ManifestBoundAnchorLeaf {
        claim,
        circuit_binding_digest,
        precommitment,
        coefficient_commitment,
        anchored_offset,
    })
}

#[cfg(test)]
mod tests;
