//! Shared public-state binding for one candidate accumulation root.

use ff::PrimeField;
use nova_snark::frontend::{
    gadgets::num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError,
};

use crate::candidate::CandidateRootClaim;
use crate::nova_candidate::{DirectCandidateRoot, DirectPendingClaim, DirectPolynomialTerm};
use crate::nova_secp::allocate_encoded_point;
use crate::nova_secp_scalar::{allocate_canonical_scalar, CanonicalSecpScalar};
use crate::Scalar;

const ROOT_PREFIX_INDEX: usize = 0;
const ROOT_X_INDEX: usize = 1;
const ROOT_SCALE_INDEX: usize = 2;
const ROOT_FACTORS_START: usize = 3;

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn enforce_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
    expected: LinearCombination<Scalar>,
) {
    cs.enforce(
        || "state field binding",
        |linear| linear + value.get_variable(),
        |linear| linear + CS::one(),
        |_| expected,
    );
}

fn bind_scalar<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &AllocatedNum<Scalar>,
    witness: crate::secp_native::SecpScalarWitness,
) -> Result<CanonicalSecpScalar, SynthesisError> {
    let scalar = allocate_canonical_scalar(cs.namespace(|| "canonical scalar"), witness)?;
    enforce_equal(cs.namespace(|| "embedded scalar"), state, scalar.embedded());
    Ok(scalar)
}

/// Bind the fixed root prefix of a recurrence state to one pending claim.
pub(crate) fn bind_candidate_root_state<CS: ConstraintSystem<Scalar>, const ROUNDS: usize>(
    cs: &mut CS,
    state: &[AllocatedNum<Scalar>],
    witness: &CandidateRootClaim,
) -> Result<DirectPendingClaim, SynthesisError> {
    if state.len() != ROOT_FACTORS_START + ROUNDS || witness.factors.len() != ROUNDS {
        return Err(synthesis_error("candidate root state shape"));
    }

    let point = allocate_encoded_point(cs.namespace(|| "root point"), witness.point)?;
    enforce_equal(
        cs.namespace(|| "root prefix"),
        &state[ROOT_PREFIX_INDEX],
        LinearCombination::zero() + point.prefix().get_variable(),
    );
    enforce_equal(
        cs.namespace(|| "root x"),
        &state[ROOT_X_INDEX],
        LinearCombination::zero() + point.point().x().get_variable(),
    );
    let scale = bind_scalar(
        cs.namespace(|| "root scale"),
        &state[ROOT_SCALE_INDEX],
        witness.scale,
    )?;
    let factors = witness
        .factors
        .iter()
        .copied()
        .enumerate()
        .map(|(index, factor)| {
            bind_scalar(
                cs.namespace(|| format!("root factor {index}")),
                &state[ROOT_FACTORS_START + index],
                factor,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DirectPendingClaim {
        point,
        polynomial: vec![DirectPolynomialTerm {
            scale,
            offset: 0,
            factors,
        }],
    })
}

fn scalar_assignment(value: &CanonicalSecpScalar) -> Result<Option<Scalar>, SynthesisError> {
    value
        .integer()
        .map(|value| {
            Scalar::from_str_vartime(&value.to_string())
                .ok_or_else(|| synthesis_error("candidate scalar embedding"))
        })
        .transpose()
}

pub(crate) fn materialize_scalar<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &CanonicalSecpScalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let output = AllocatedNum::alloc(cs.namespace(|| "state output"), || {
        scalar_assignment(value)?.ok_or(SynthesisError::AssignmentMissing)
    })?;
    enforce_equal(
        cs.namespace(|| "state output binding"),
        &output,
        value.embedded(),
    );
    Ok(output)
}

/// Materialize the fixed candidate-root prefix of a recurrence output.
pub(crate) fn candidate_root_output_fields<CS: ConstraintSystem<Scalar>, const ROUNDS: usize>(
    cs: &mut CS,
    root: &DirectCandidateRoot,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    if root.factors.len() != ROUNDS {
        return Err(synthesis_error("candidate output root shape"));
    }
    let mut output = Vec::with_capacity(ROOT_FACTORS_START + ROUNDS);
    output.push(root.point.prefix().clone());
    output.push(root.point.point().x().clone());
    output.push(materialize_scalar(
        cs.namespace(|| "root scale"),
        &root.scale,
    )?);
    for (index, factor) in root.factors.iter().enumerate() {
        output.push(materialize_scalar(
            cs.namespace(|| format!("root factor {index}")),
            factor,
        )?);
    }
    debug_assert_eq!(output.len(), ROOT_FACTORS_START + ROUNDS);
    Ok(output)
}
