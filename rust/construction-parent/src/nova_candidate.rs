//! Candidate accumulation arithmetic on Nova's constraint frontend.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::candidate::{
    validate_candidate_step_shape, CandidatePendingClaimWitness, CandidateStepProofWitness,
    MAX_CANDIDATE_CLAIMS, MAX_CANDIDATE_ROUNDS,
};
use crate::nova_opening_base::constrain_transcript_opening_base;
use crate::nova_protocol_transcript::{
    append_constant_bytes, append_point, append_scalar, challenge,
};
use crate::nova_secp::{
    add_points, allocate_encoded_point, encode_computed_point, scale_point, DirectEncodedSecpPoint,
    DirectSecpPoint,
};
use crate::nova_secp_scalar::{
    add_scalars, allocate_canonical_scalar, constant_scalar, invert_scalar, multiply_scalars,
    subtract_scalars, CanonicalSecpScalar,
};
use crate::nova_sha256_transcript::NovaTranscript;
use crate::opening_generators::ACCUMULATION_OPENING_BASE_ROLE;
use crate::secp_native::SecpScalarWitness;
use crate::Scalar;

const CANDIDATE_STEP_DOMAIN: &[u8] = b"Purify/BPPP/CandidateAccumStep/v1";

#[derive(Clone)]
pub(crate) struct DirectPolynomialTerm {
    pub(crate) scale: CanonicalSecpScalar,
    pub(crate) offset: usize,
    pub(crate) factors: Vec<CanonicalSecpScalar>,
}

#[derive(Clone)]
pub(crate) struct DirectPendingClaim {
    pub(crate) point: DirectEncodedSecpPoint,
    pub(crate) polynomial: Vec<DirectPolynomialTerm>,
}

pub(crate) struct DirectCandidateRoot {
    pub(crate) point: DirectEncodedSecpPoint,
    pub(crate) scale: CanonicalSecpScalar,
    pub(crate) factors: Vec<CanonicalSecpScalar>,
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn constant_u64<CS: ConstraintSystem<Scalar>>(
    value: u64,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    constant_scalar::<CS>(SecpScalarWitness::from_u64(value))
}

pub(crate) fn allocate_candidate_claims<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    claims: &[CandidatePendingClaimWitness],
) -> Result<Vec<DirectPendingClaim>, SynthesisError> {
    let mut allocated = Vec::with_capacity(claims.len());
    for (claim_index, claim) in claims.iter().enumerate() {
        let mut claim_cs = cs.namespace(|| format!("claim {claim_index}"));
        let point = allocate_encoded_point(claim_cs.namespace(|| "point"), claim.point)?;
        let mut polynomial = Vec::with_capacity(claim.polynomial.len());
        for (term_index, term) in claim.polynomial.iter().enumerate() {
            let mut term_cs = claim_cs.namespace(|| format!("term {term_index}"));
            let scale = allocate_canonical_scalar(term_cs.namespace(|| "scale"), term.scale)?;
            let factors = term
                .factors
                .iter()
                .enumerate()
                .map(|(factor_index, factor)| {
                    allocate_canonical_scalar(
                        term_cs.namespace(|| format!("factor {factor_index}")),
                        *factor,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            polynomial.push(DirectPolynomialTerm {
                scale,
                offset: term.offset,
                factors,
            });
        }
        allocated.push(DirectPendingClaim { point, polynomial });
    }
    Ok(allocated)
}

pub(crate) fn candidate_power_ladder<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &CanonicalSecpScalar,
    rounds: usize,
) -> Result<Vec<CanonicalSecpScalar>, SynthesisError> {
    if rounds == 0 {
        return Err(synthesis_error("candidate power ladder"));
    }
    let mut powers = Vec::with_capacity(rounds);
    powers.push(value.clone());
    for round in 1..rounds {
        let previous = powers.last().expect("nonempty power ladder");
        powers.push(multiply_scalars(
            cs.namespace(|| format!("power {round}")),
            previous,
            previous,
        )?);
    }
    Ok(powers)
}

fn candidate_offset_power<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    powers: &[CanonicalSecpScalar],
    offset: usize,
) -> Result<Option<CanonicalSecpScalar>, SynthesisError> {
    if offset == 0 {
        return Ok(None);
    }
    if offset >> powers.len() != 0 {
        return Err(synthesis_error("candidate term offset"));
    }
    let mut selected = None;
    for (index, power) in powers.iter().enumerate() {
        if offset & (1usize << index) != 0 {
            selected = Some(match selected {
                None => power.clone(),
                Some(value) => multiply_scalars(
                    cs.namespace(|| format!("offset bit {index}")),
                    &value,
                    power,
                )?,
            });
        }
    }
    Ok(selected)
}

pub(crate) fn evaluate_candidate_term<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    term: &DirectPolynomialTerm,
    powers: &[CanonicalSecpScalar],
) -> Result<CanonicalSecpScalar, SynthesisError> {
    if term.factors.len() > powers.len() {
        return Err(synthesis_error("candidate term factors"));
    }
    let mut value = match candidate_offset_power(cs.namespace(|| "offset"), powers, term.offset)? {
        Some(offset) => multiply_scalars(cs.namespace(|| "scale offset"), &term.scale, &offset)?,
        None => term.scale.clone(),
    };
    let one = constant_scalar::<CS::Root>(SecpScalarWitness::from_u64(1))?;
    for (index, (factor, power)) in term.factors.iter().zip(powers).enumerate() {
        let product = multiply_scalars(
            cs.namespace(|| format!("factor product {index}")),
            factor,
            power,
        )?;
        let one_plus = add_scalars(
            cs.namespace(|| format!("one plus factor {index}")),
            &one,
            &product,
        )?;
        value = multiply_scalars(
            cs.namespace(|| format!("term product {index}")),
            &value,
            &one_plus,
        )?;
    }
    Ok(value)
}

pub(crate) fn append_polynomial(
    transcript: &mut NovaTranscript,
    polynomial: &[DirectPolynomialTerm],
) -> Result<(), SynthesisError> {
    transcript.append_u64(polynomial.len() as u64);
    for term in polynomial {
        append_scalar(transcript, &term.scale)?;
        transcript.append_u64(term.offset as u64);
        transcript.append_u64(term.factors.len() as u64);
        for factor in &term.factors {
            append_scalar(transcript, factor)?;
        }
    }
    Ok(())
}

fn append_claims(
    transcript: &mut NovaTranscript,
    claims: &[DirectPendingClaim],
) -> Result<(), SynthesisError> {
    transcript.append_u64(claims.len() as u64);
    for claim in claims {
        append_point(transcript, &claim.point);
        append_polynomial(transcript, &claim.polynomial)?;
    }
    Ok(())
}

fn append_computed_point<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    transcript: &mut NovaTranscript,
    point: DirectSecpPoint,
) -> Result<DirectEncodedSecpPoint, SynthesisError> {
    let encoded = encode_computed_point(cs, point)?;
    append_point(transcript, &encoded);
    Ok(encoded)
}

fn add_scaled<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    accumulator: &DirectSecpPoint,
    point: &DirectSecpPoint,
    scalar: &CanonicalSecpScalar,
) -> Result<DirectSecpPoint, SynthesisError> {
    let bits = scalar.allocated_bits_le(cs.namespace(|| "scalar bits"))?;
    let term = scale_point(cs.namespace(|| "scaled point"), point, &bits)?;
    add_points(cs.namespace(|| "point sum"), accumulator, &term)
}

fn validate_constrained_shape(
    claims: &[DirectPendingClaim],
    proof: &CandidateStepProofWitness,
) -> Result<usize, SynthesisError> {
    let rounds = proof.left.len();
    if claims.is_empty()
        || claims.len() > MAX_CANDIDATE_CLAIMS
        || rounds == 0
        || rounds > MAX_CANDIDATE_ROUNDS
        || proof.right.len() != rounds
    {
        return Err(synthesis_error("candidate step shape"));
    }
    let dimension = 1usize
        .checked_shl(rounds as u32)
        .ok_or_else(|| synthesis_error("candidate step dimension"))?;
    for claim in claims {
        if claim.polynomial.is_empty() || claim.polynomial.len() > 3 {
            return Err(synthesis_error("candidate polynomial terms"));
        }
        for term in &claim.polynomial {
            if term.factors.len() > rounds {
                return Err(synthesis_error("candidate polynomial factors"));
            }
            let width = 1usize
                .checked_shl(term.factors.len() as u32)
                .ok_or_else(|| synthesis_error("candidate polynomial width"))?;
            if term.offset > dimension.saturating_sub(width) {
                return Err(synthesis_error("candidate polynomial degree"));
            }
        }
    }
    Ok(rounds)
}

pub(crate) fn install_candidate_step<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    basis_digest: [u8; 32],
    claims: &[CandidatePendingClaimWitness],
    proof: &CandidateStepProofWitness,
) -> Result<DirectCandidateRoot, SynthesisError> {
    validate_candidate_step_shape(claims, proof, None)
        .map_err(|_| synthesis_error("candidate witness shape"))?;
    let claims = allocate_candidate_claims(cs.namespace(|| "claims"), claims)?;
    install_constrained_candidate_step(
        cs.namespace(|| "candidate step"),
        basis_digest,
        &claims,
        proof,
    )
}

pub(crate) fn install_constrained_candidate_step<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    basis_digest: [u8; 32],
    claims: &[DirectPendingClaim],
    proof: &CandidateStepProofWitness,
) -> Result<DirectCandidateRoot, SynthesisError> {
    let rounds = validate_constrained_shape(claims, proof)?;
    let mut transcript = NovaTranscript::new();
    append_constant_bytes(&mut transcript, CANDIDATE_STEP_DOMAIN)?;
    append_constant_bytes(&mut transcript, &basis_digest)?;
    transcript.append_u64(rounds as u64);
    append_claims(&mut transcript, claims)?;

    let beta = challenge(cs.namespace(|| "beta"), &mut transcript, 0)?;
    let mut claim_weights = Vec::with_capacity(claims.len());
    claim_weights.push(constant_u64::<CS::Root>(1)?);
    for index in 1..claims.len() {
        let next = multiply_scalars(
            cs.namespace(|| format!("claim weight {index}")),
            claim_weights.last().expect("nonempty claim weights"),
            &beta,
        )?;
        claim_weights.push(next);
    }
    let mut commitment = claims[0].point.point().clone();
    for index in 1..claims.len() {
        commitment = add_scaled(
            cs.namespace(|| format!("commitment term {index}")),
            &commitment,
            claims[index].point.point(),
            &claim_weights[index],
        )?;
    }
    append_computed_point(
        cs.namespace(|| "commitment encoding"),
        &mut transcript,
        commitment.clone(),
    )?;

    let x = challenge(cs.namespace(|| "evaluation point"), &mut transcript, 1)?;
    let powers = candidate_power_ladder(cs.namespace(|| "evaluation powers"), &x, rounds)?;
    let mut y = None;
    for (claim_index, (claim, weight)) in claims.iter().zip(&claim_weights).enumerate() {
        let mut terms = claim.polynomial.iter().enumerate();
        let (term_index, first) = terms.next().expect("nonempty candidate polynomial");
        let mut evaluation = evaluate_candidate_term(
            cs.namespace(|| format!("claim {claim_index} term {term_index}")),
            first,
            &powers,
        )?;
        for (term_index, term) in terms {
            let term = evaluate_candidate_term(
                cs.namespace(|| format!("claim {claim_index} term {term_index}")),
                term,
                &powers,
            )?;
            evaluation = add_scalars(
                cs.namespace(|| format!("claim {claim_index} term sum {term_index}")),
                &evaluation,
                &term,
            )?;
        }
        let weighted = if claim_index == 0 {
            evaluation
        } else {
            multiply_scalars(
                cs.namespace(|| format!("weighted claim {claim_index}")),
                weight,
                &evaluation,
            )?
        };
        y = Some(match y {
            None => weighted,
            Some(value) => add_scalars(
                cs.namespace(|| format!("claim sum {claim_index}")),
                &value,
                &weighted,
            )?,
        });
    }
    let y = y.expect("nonempty candidate claims");
    append_scalar(&mut transcript, &y)?;

    let opening = constrain_transcript_opening_base(
        cs.namespace(|| "opening base"),
        &transcript,
        basis_digest,
        ACCUMULATION_OPENING_BASE_ROLE,
    )?;
    append_computed_point(
        cs.namespace(|| "opening encoding"),
        &mut transcript,
        opening.clone(),
    )?;

    let mut residual = commitment;
    let mut folded_scale = constant_u64::<CS::Root>(1)?;
    let mut folded_factors = (0..rounds)
        .map(|_| constant_u64::<CS::Root>(0))
        .collect::<Result<Vec<_>, _>>()?;
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
            2 + round as u64,
        )?;
        let inverse = invert_scalar(
            cs.namespace(|| format!("round {round} inverse")),
            &round_challenge,
        )?;
        let squared = multiply_scalars(
            cs.namespace(|| format!("round {round} square")),
            &round_challenge,
            &round_challenge,
        )?;
        let inverse_squared = multiply_scalars(
            cs.namespace(|| format!("round {round} inverse square")),
            &inverse,
            &inverse,
        )?;
        folded_scale = multiply_scalars(
            cs.namespace(|| format!("round {round} folded scale")),
            &folded_scale,
            &inverse,
        )?;
        folded_factors[rounds - 1 - round] = squared.clone();
        residual = add_scaled(
            cs.namespace(|| format!("round {round} left residual")),
            &residual,
            left.point(),
            &squared,
        )?;
        residual = add_scaled(
            cs.namespace(|| format!("round {round} right residual")),
            &residual,
            right.point(),
            &inverse_squared,
        )?;
    }

    let terminal =
        allocate_canonical_scalar(cs.namespace(|| "terminal scalar"), proof.terminal_scalar)?;
    let mut final_evaluation = folded_scale.clone();
    for (index, (factor, power)) in folded_factors.iter().zip(&powers).enumerate() {
        let product = multiply_scalars(
            cs.namespace(|| format!("terminal factor {index}")),
            factor,
            power,
        )?;
        let one = constant_u64::<CS::Root>(1)?;
        let one_plus = add_scalars(
            cs.namespace(|| format!("terminal one plus {index}")),
            &one,
            &product,
        )?;
        final_evaluation = multiply_scalars(
            cs.namespace(|| format!("terminal evaluation {index}")),
            &final_evaluation,
            &one_plus,
        )?;
    }
    let terminal_evaluation = multiply_scalars(
        cs.namespace(|| "terminal product"),
        &terminal,
        &final_evaluation,
    )?;
    let opening_scalar =
        subtract_scalars(cs.namespace(|| "opening scalar"), &y, &terminal_evaluation)?;
    let zero = constant_u64::<CS::Root>(0)?;
    let negative_terminal =
        subtract_scalars(cs.namespace(|| "negative terminal"), &zero, &terminal)?;
    residual = add_scaled(
        cs.namespace(|| "opening residual"),
        &residual,
        &opening,
        &opening_scalar,
    )?;

    let folded_generator =
        allocate_encoded_point(cs.namespace(|| "folded generator"), proof.folded_generator)?;
    residual = add_scaled(
        cs.namespace(|| "folded residual"),
        &residual,
        folded_generator.point(),
        &negative_terminal,
    )?;
    Boolean::enforce_equal(
        cs.namespace(|| "candidate equation"),
        &residual.is_identity(),
        &Boolean::constant(true),
    )?;

    Ok(DirectCandidateRoot {
        point: folded_generator,
        scale: folded_scale,
        factors: folded_factors,
    })
}

#[cfg(test)]
mod tests {
    use nova_snark::{
        frontend::{shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem},
        provider::Secq256k1Sha256Engine,
    };
    use num_bigint::{BigInt, Sign};

    use super::*;
    use crate::candidate::{
        CandidatePendingClaimWitness, CandidatePolynomialTermWitness, CandidateRootClaim,
        CandidateStepProofWitness,
    };
    use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
    use crate::secp_native::{
        encoded_point_value, standard_generator, SecpEncodedPointWitness, SecpScalarWitness,
    };

    fn fixture(
        scale: SecpScalarWitness,
    ) -> (
        [u8; 32],
        Vec<CandidatePendingClaimWitness>,
        CandidateStepProofWitness,
        CandidateRootClaim,
    ) {
        let basis = [0x42; 32];
        let claims = vec![CandidatePendingClaimWitness {
            point: SecpEncodedPointWitness::from_point_value(standard_generator()),
            polynomial: vec![CandidatePolynomialTermWitness {
                scale,
                offset: 0,
                factors: vec![],
            }],
        }];
        let proof = CandidateStepProofWitness {
            left: vec![SecpEncodedPointWitness::identity()],
            right: vec![SecpEncodedPointWitness::identity()],
            terminal_scalar: SecpScalarWitness::from_u64(1),
            folded_generator: SecpEncodedPointWitness::parse([
                0x02, 0x71, 0x73, 0x23, 0xf4, 0x6f, 0x77, 0x4c, 0x77, 0xe2, 0x0a, 0xc1, 0x71, 0xeb,
                0x8f, 0x6c, 0xdf, 0x52, 0x18, 0xe0, 0xe7, 0x1e, 0x6f, 0xb5, 0xfb, 0x94, 0x02, 0x2f,
                0x4b, 0x4b, 0x61, 0x11, 0x41,
            ])
            .expect("fixed folded generator"),
        };
        let root = CandidateRootClaim {
            point: proof.folded_generator,
            scale: SecpScalarWitness::from_bytes_be([
                0xf7, 0x60, 0x40, 0x29, 0x0c, 0x88, 0x29, 0x96, 0x13, 0x5a, 0xce, 0xe5, 0x6e, 0x0d,
                0xbb, 0x99, 0x95, 0x58, 0xc4, 0x9a, 0x83, 0x1f, 0x2d, 0xd4, 0x35, 0x61, 0xd1, 0xb5,
                0xb9, 0x75, 0x40, 0x0c,
            ]),
            factors: vec![SecpScalarWitness::from_bytes_be([
                0x69, 0xfa, 0x5c, 0x39, 0xd5, 0xc4, 0xec, 0xac, 0x06, 0x78, 0xfe, 0xdc, 0x69, 0xbe,
                0x03, 0x56, 0x3a, 0xdf, 0xf6, 0x2e, 0x66, 0xfd, 0xd6, 0x70, 0x14, 0x6a, 0x9c, 0x31,
                0x8e, 0x61, 0x5f, 0x1a,
            ])],
        };
        (basis, claims, proof, root)
    }

    fn scalar_integer(value: SecpScalarWitness) -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, &value.bytes)
    }

    #[test]
    fn direct_candidate_term_matches_reference() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let x = allocate_canonical_scalar(cs.namespace(|| "x"), SecpScalarWitness::from_u64(11))
            .expect("x");
        let powers =
            candidate_power_ladder(cs.namespace(|| "powers"), &x, 3).expect("power ladder");
        let term = DirectPolynomialTerm {
            scale: allocate_canonical_scalar(
                cs.namespace(|| "scale"),
                SecpScalarWitness::from_u64(7),
            )
            .expect("scale"),
            offset: 5,
            factors: [3, 4, 5]
                .map(|value| {
                    allocate_canonical_scalar(
                        cs.namespace(|| format!("factor {value}")),
                        SecpScalarWitness::from_u64(value),
                    )
                    .expect("factor")
                })
                .into(),
        };
        let actual = evaluate_candidate_term(cs.namespace(|| "term"), &term, &powers)
            .expect("term evaluation");
        let modulus = BigInt::from_bytes_be(
            Sign::Plus,
            &crate::secp_constants::SECP256K1_SCALAR_ORDER_BE,
        );
        let x = BigInt::from(11u8);
        let expected = [3u8, 4, 5].into_iter().enumerate().fold(
            BigInt::from(7u8) * x.modpow(&BigInt::from(5u8), &modulus),
            |value, (index, factor)| {
                let power = x.modpow(&(BigInt::from(1u8) << index), &modulus);
                value * (BigInt::from(1u8) + BigInt::from(factor) * power) % &modulus
            },
        ) % modulus;
        assert_eq!(actual.integer(), Some(&expected));
        assert!(cs.is_satisfied());
    }

    #[test]
    fn direct_candidate_step_matches_reference_vector_and_rejects_wrong_root() {
        let mut maximum = SECP256K1_SCALAR_ORDER_BE;
        for byte in maximum.iter_mut().rev() {
            if *byte != 0 {
                *byte -= 1;
                break;
            }
            *byte = u8::MAX;
        }
        let (basis, claims, proof, expected) = fixture(SecpScalarWitness::from_bytes_be(maximum));
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let actual =
            install_candidate_step(cs.namespace(|| "candidate step"), basis, &claims, &proof)
                .expect("direct candidate step");
        let expected_point = encoded_point_value(expected.point).expect("expected point");
        assert_eq!(
            actual.point.prefix().get_value(),
            Some(Scalar::from(u64::from(expected.point.encoded[0])))
        );
        assert_eq!(actual.point.point().x().get_value(), Some(expected_point.x));
        assert_eq!(actual.point.point().y().get_value(), Some(expected_point.y));
        assert_eq!(
            actual.point.point().identity_num().get_value(),
            Some(Scalar::from(u64::from(expected_point.identity)))
        );
        assert_eq!(
            actual.scale.integer(),
            Some(&scalar_integer(expected.scale))
        );
        assert_eq!(actual.factors.len(), expected.factors.len());
        for (actual, expected) in actual.factors.iter().zip(expected.factors) {
            assert_eq!(actual.integer(), Some(&scalar_integer(expected)));
        }
        assert!(cs.is_satisfied());

        let mut wrong = proof.clone();
        wrong.folded_generator = SecpEncodedPointWitness::from_point_value(standard_generator());
        let mut wrong_cs = TestConstraintSystem::<Scalar>::new();
        install_candidate_step(
            wrong_cs.namespace(|| "candidate step"),
            basis,
            &claims,
            &wrong,
        )
        .expect("well-shaped wrong step");
        assert!(!wrong_cs.is_satisfied());
    }

    #[test]
    fn direct_candidate_step_has_fixed_shape() {
        let first = fixture(SecpScalarWitness::from_u64(3));
        let second = fixture(SecpScalarWitness::from_u64(7));
        let mut first_shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        install_candidate_step(&mut first_shape, first.0, &first.1, &first.2)
            .expect("first candidate shape");
        let mut second_shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        install_candidate_step(&mut second_shape, second.0, &second.1, &second.2)
            .expect("second candidate shape");

        assert_eq!(first_shape.constraints, second_shape.constraints);
        assert_eq!(first_shape.num_aux(), second_shape.num_aux());
        assert_eq!(
            (first_shape.num_aux(), first_shape.num_constraints()),
            (322_101, 323_306)
        );
    }

    #[test]
    fn direct_candidate_step_rejects_bad_shapes() {
        let (basis, claims, mut proof, _) = fixture(SecpScalarWitness::from_u64(3));
        let mut cs = TestConstraintSystem::<Scalar>::new();
        assert!(
            install_candidate_step(cs.namespace(|| "empty claims"), basis, &[], &proof,).is_err()
        );
        proof.right.clear();
        assert!(install_candidate_step(
            cs.namespace(|| "mismatched rounds"),
            basis,
            &claims,
            &proof,
        )
        .is_err());
        assert_eq!(cs.num_constraints(), 0);
    }
}
