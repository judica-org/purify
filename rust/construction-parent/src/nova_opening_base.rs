//! Direct Nova opening-base derivation from trusted native constants.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};

use crate::nova_secp::{add_points, allocate_constant_point, scale_point, DirectSecpPoint};
use crate::nova_secp_scalar::nonzero_scalar_from_sha255;
use crate::nova_sha256_transcript::NovaTranscript;
use crate::opening_generators::opening_generator_pair;
use crate::Scalar;

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

/// Constrain `U = U0 + u U1` for one typed transcript and role.
///
/// Hash-to-curve runs natively over fixed public inputs. The circuit allocates
/// the resulting trusted constants and proves only the transcript-selected
/// linear combination.
pub(crate) fn constrain_transcript_opening_base<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    transcript: &NovaTranscript,
    basis_digest: [u8; 32],
    role: u64,
) -> Result<DirectSecpPoint, SynthesisError> {
    let challenge = transcript
        .opening_base_scalar(
            cs.namespace(|| "opening-base challenge"),
            basis_digest,
            role,
        )
        .map_err(|_| synthesis_error("opening-base transcript"))?;
    let scalar = nonzero_scalar_from_sha255(
        cs.namespace(|| "opening-base scalar"),
        challenge.scalar_bits_le(),
    )?;
    let [first, second] = opening_generator_pair(basis_digest, role)
        .map_err(|_| synthesis_error("opening-base generators"))?;
    let first = allocate_constant_point(cs.namespace(|| "first generator"), first)?;
    let second = allocate_constant_point(cs.namespace(|| "second generator"), second)?;
    let bits = scalar.allocated_bits_le(cs.namespace(|| "opening-base bits"))?;
    let scaled = scale_point(cs.namespace(|| "scaled generator"), &second, &bits)?;
    let output = add_points(cs.namespace(|| "opening-base sum"), &first, &scaled)?;
    Boolean::enforce_equal(
        cs.namespace(|| "opening base is finite"),
        &output.is_identity(),
        &Boolean::constant(false),
    )?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use nova_snark::{
        frontend::{shape_cs::ShapeCS, test_cs::TestConstraintSystem, ConstraintSystem},
        provider::Secq256k1Sha256Engine,
    };
    use num_bigint::BigUint;

    use super::*;
    use crate::nova_sha256_transcript::NovaByte;
    use crate::opening_generators::{opening_generator_pair, ACCUMULATION_OPENING_BASE_ROLE};
    use crate::secp_native::{add_point_values, scale_point_value};
    use crate::sha256_transcript::NativeTranscript;
    use crate::{scalar_to_canonical, Scalar};

    fn field_bytes(value: Scalar) -> [u8; 32] {
        let mut bytes = scalar_to_canonical(&value);
        bytes.reverse();
        bytes
    }

    fn transcript<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        fields: [Scalar; 2],
    ) -> Result<NovaTranscript, SynthesisError> {
        let mut transcript = NovaTranscript::new();
        for (index, field) in fields.into_iter().enumerate() {
            let bytes = field_bytes(field)
                .iter()
                .enumerate()
                .map(|(byte, value)| {
                    NovaByte::allocate(
                        cs.namespace(|| format!("field {index} byte {byte}")),
                        *value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .expect("field has 32 bytes");
            transcript.append_field(&bytes);
        }
        Ok(transcript)
    }

    #[test]
    fn opening_base_matches_native_and_has_fixed_shape() {
        let fields = [Scalar::from(11), Scalar::from(29)];
        let basis = [0x42; 32];
        let role = ACCUMULATION_OPENING_BASE_ROLE;
        let mut native = NativeTranscript::new();
        for field in fields {
            native.append_field(field_bytes(field));
        }
        let challenge = native
            .opening_base_scalar(basis, role)
            .expect("native opening challenge");
        let [first, second] = opening_generator_pair(basis, role).expect("opening pair");
        let scalar = BigUint::from_bytes_le(&scalar_to_canonical(&challenge.scalar));
        let expected = add_point_values(first, scale_point_value(second, &scalar));

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let circuit_transcript =
            transcript(cs.namespace(|| "transcript"), fields).expect("transcript");
        let actual = constrain_transcript_opening_base(
            cs.namespace(|| "opening base"),
            &circuit_transcript,
            basis,
            role,
        )
        .expect("direct opening base");
        assert_eq!(actual.x().get_value(), Some(expected.x));
        assert_eq!(actual.y().get_value(), Some(expected.y));
        assert_eq!(actual.identity_num().get_value(), Some(Scalar::ZERO));
        assert!(cs.is_satisfied());

        let mut shape = ShapeCS::<Secq256k1Sha256Engine>::new();
        let circuit_transcript = transcript(&mut shape, fields).expect("shape transcript");
        constrain_transcript_opening_base(&mut shape, &circuit_transcript, basis, role)
            .expect("opening-base shape");
        assert_eq!(shape.num_aux(), 69_693);
        assert_eq!(shape.num_constraints(), 69_772);
        assert_eq!(shape.num_constraints(), cs.num_constraints());
    }

    #[test]
    fn opening_base_rejects_unknown_role() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let transcript =
            transcript(cs.namespace(|| "transcript"), [Scalar::ONE; 2]).expect("transcript");
        assert!(constrain_transcript_opening_base(
            cs.namespace(|| "opening base"),
            &transcript,
            [0x42; 32],
            0,
        )
        .is_err());
    }
}
