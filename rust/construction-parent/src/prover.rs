//! Checked construction-parent prover inputs.
//!
//! Decoding accepts only the fixed Wit3 framing and canonical native proof
//! values. Binding is a separate, deliberately expensive boundary: it
//! executes every production constraint, derives the complete state chain,
//! and returns an opaque input that later prover APIs can consume.

use thiserror::Error;

pub use crate::construction_parent_prover_binding::ConstructionParentWitnessBindingError;

use crate::construction_parent_prover_binding::BoundConstructionParentWitness;
use crate::construction_parent_prover_fixture::ConstructionParentProverFixture;

/// Failure while decoding the canonical Wit3 framing or native proof values.
#[derive(Debug, Error)]
#[error("invalid construction parent Wit3 witness: {detail}")]
pub struct ConstructionParentWitnessDecodeError {
    detail: String,
}

/// Canonically decoded Wit3 data that has not yet executed the Nova relation.
pub struct ConstructionParentWitness {
    fixture: ConstructionParentProverFixture,
}

impl ConstructionParentWitness {
    /// Decode and canonically validate one complete Wit3 byte string.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConstructionParentWitnessDecodeError> {
        let fixture = ConstructionParentProverFixture::parse(bytes).map_err(|error| {
            ConstructionParentWitnessDecodeError {
                detail: error.to_string(),
            }
        })?;
        Ok(Self { fixture })
    }

    /// Return the authenticated number of ordered recurrence steps.
    pub fn step_count(&self) -> usize {
        self.fixture.inputs.step_count()
    }

    /// Execute every production constraint and bind the exact state chain.
    pub fn bind(
        self,
    ) -> Result<CheckedConstructionParentWitness, ConstructionParentWitnessBindingError> {
        Ok(CheckedConstructionParentWitness {
            inner: self.fixture.bind()?,
        })
    }
}

/// Opaque construction-parent input after complete relation validation.
pub struct CheckedConstructionParentWitness {
    inner: BoundConstructionParentWitness,
}

impl CheckedConstructionParentWitness {
    /// Return the number of checked, ordered recurrence steps.
    pub fn step_count(&self) -> usize {
        self.inner.steps().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_decoder_rejects_truncated_wit3() {
        let error = ConstructionParentWitness::decode(&[])
            .err()
            .expect("empty witness rejects");
        assert!(error
            .to_string()
            .contains("truncated construction prover fixture"));
    }

    #[test]
    fn public_decoder_accepts_checked_wit3_without_binding() {
        let witness = ConstructionParentWitness::decode(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("decode accepted construction parent witness");
        assert_eq!(witness.step_count(), 5);
    }

    #[test]
    #[ignore = "executes every constraint in five production recurrences"]
    fn public_binder_executes_the_complete_checked_witness() {
        let witness = ConstructionParentWitness::decode(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("decode accepted construction parent witness");
        let checked = witness.bind().expect("bind accepted witness state chain");
        assert_eq!(checked.step_count(), 5);
    }
}
