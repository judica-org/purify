//! Shared typed-transcript framing for direct Nova protocol relations.

use std::array;

use nova_snark::frontend::{ConstraintSystem, SynthesisError};

use crate::gadgets::point::EncodedPoint;
use crate::gadgets::scalar::{nonzero_scalar_from_sha255, CanonicalScalar};
use crate::gadgets::sha256::{Byte, Transcript};
use crate::gadgets::synthesis_error;
use statement::Scalar;

const SCALAR_BITS: usize = 256;

pub(crate) fn append_bytes(
    transcript: &mut Transcript,
    value: &[Byte],
) -> Result<(), SynthesisError> {
    transcript
        .append_bytes(value)
        .map_err(|_| synthesis_error("Nova transcript byte length"))
}

pub(crate) fn append_constant_bytes(
    transcript: &mut Transcript,
    value: &[u8],
) -> Result<(), SynthesisError> {
    append_bytes(
        transcript,
        &value
            .iter()
            .copied()
            .map(Byte::constant)
            .collect::<Vec<_>>(),
    )
}

fn scalar_bytes(value: &CanonicalScalar) -> Result<[Byte; 32], SynthesisError> {
    if value.bits_le().len() != SCALAR_BITS {
        return Err(synthesis_error("Nova scalar bit width"));
    }
    Ok(array::from_fn(|byte| {
        let offset = (31 - byte) * 8;
        Byte::from_constrained_bits_le(array::from_fn(|bit| value.bits_le()[offset + bit].clone()))
    }))
}

pub(crate) fn append_scalar(
    transcript: &mut Transcript,
    value: &CanonicalScalar,
) -> Result<(), SynthesisError> {
    transcript.append_scalar(&scalar_bytes(value)?);
    Ok(())
}

pub(crate) fn append_point(transcript: &mut Transcript, point: &EncodedPoint) {
    transcript.append_point(point.prefix_byte(), point.x_bytes());
}

pub(crate) fn challenge<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &mut Transcript,
    round: u64,
) -> Result<CanonicalScalar, SynthesisError> {
    let challenge = transcript
        .challenge(cs.namespace(|| format!("challenge {round}")), round)
        .map_err(|_| synthesis_error("Nova transcript challenge"))?;
    nonzero_scalar_from_sha255(
        cs.namespace(|| format!("nonzero challenge {round}")),
        challenge.scalar_bits_le(),
    )
}
