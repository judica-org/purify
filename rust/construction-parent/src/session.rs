//! Serialized one-thread Nova proving for one exact direct relation.
//!
//! Production proving loads its public parameters and prover key from an
//! authenticated artifact. Transparent setup compiles only for tests, so a
//! production binary can never derive parameters from caller input.

use std::sync::Mutex;

use ff::PrimeField;
use nova_snark::{
    errors::NovaError,
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK},
    traits::circuit::StepCircuit,
};
use rayon::ThreadPool;
use thiserror::Error;

use crate::fixed_serde::{FixedSerdeError, NovaCompressedProofShape};
use crate::nova::{PrimarySnark, SecondarySnark};
use crate::nova_types::{
    DirectNovaPrimaryEngine, DirectNovaScalar, DirectNovaSecondaryEngine, DirectRelationId,
};
use crate::suite::{Suite, SuiteError};

#[cfg(all(feature = "prover", not(target_pointer_width = "64")))]
compile_error!("the construction-parent prover supports only 64-bit targets");
#[cfg(target_pointer_width = "64")]
pub(crate) mod prover_artifact;
#[cfg(test)]
pub(crate) mod setup;

type NovaPublicParams<C> = PublicParams<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C>;
type NovaRecursiveSnark<C> = RecursiveSNARK<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C>;
type NovaCompressedSnark<C> = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    C,
    PrimarySnark,
    SecondarySnark,
>;
type NovaProverKey<C> =
    ProverKey<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, C, PrimarySnark, SecondarySnark>;

pub(crate) trait NovaSessionStep<const ARITY: usize>: StepCircuit<DirectNovaScalar> {
    fn relation_id(&self) -> DirectRelationId;
    fn input_state(&self) -> &[DirectNovaScalar; ARITY];
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum DirectNovaSessionError {
    #[error(transparent)]
    Nova(#[from] NovaError),
    #[error(transparent)]
    Codec(#[from] FixedSerdeError),
    #[error(transparent)]
    Suite(#[from] SuiteError),
    #[error("direct Nova suite setup failed: {0}")]
    Setup(&'static str),
    #[error("direct Nova step relation mismatch")]
    StepRelation,
    #[error("direct Nova state continuity mismatch")]
    StateContinuity,
    #[error("direct Nova verified final state mismatch")]
    FinalState,
    #[error("direct Nova step count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
}

/// Suite values measured from one concrete set of public parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectNovaSuiteMetadata {
    pub(crate) relation_id: DirectRelationId,
    pub(crate) public_parameter_digest: [u8; 32],
    pub(crate) primary_constraints: usize,
    pub(crate) secondary_constraints: usize,
    pub(crate) primary_variables: usize,
    pub(crate) secondary_variables: usize,
    pub(crate) proof_length: usize,
    pub(crate) codec_sequence_count: usize,
}

impl DirectNovaSuiteMetadata {
    /// Measures the parameter digest and augmented dimensions.
    ///
    /// `relation_id` is the step relation the parameters were generated or
    /// selected for; public parameters do not carry it.
    fn measure<const ARITY: usize, C: NovaSessionStep<ARITY>>(
        relation_id: DirectRelationId,
        public_params: &NovaPublicParams<C>,
        proof_shape: &NovaCompressedProofShape,
    ) -> Result<Self, DirectNovaSessionError> {
        let digest_repr = public_params.digest().to_repr();
        let public_parameter_digest = digest_repr
            .as_ref()
            .try_into()
            .map_err(|_| DirectNovaSessionError::Setup("public-parameter digest width"))?;
        let (primary_constraints, secondary_constraints) = public_params.num_constraints();
        let (primary_variables, secondary_variables) = public_params.num_variables();
        Ok(Self {
            relation_id,
            public_parameter_digest,
            primary_constraints,
            secondary_constraints,
            primary_variables,
            secondary_variables,
            proof_length: proof_shape.encoded_len(),
            codec_sequence_count: proof_shape.sequence_count(),
        })
    }

    /// Checks the measured parameter digest and dimensions against one pinned
    /// profile.
    ///
    /// The profile's proof length, codec schedule, and suite ID are functions
    /// of the values compared here, and [`Suite::proof_shape`] checks them
    /// against their pins. The returned shape is the pinned profile's.
    pub(crate) fn validate_parameters<const ARITY: usize>(
        &self,
        expected: &Suite,
    ) -> Result<NovaCompressedProofShape, DirectNovaSessionError> {
        let pinned = &expected.parameters;
        if usize::try_from(pinned.state_arity) != Ok(ARITY) {
            return Err(SuiteError::Mismatch("state arity").into());
        }
        if self.public_parameter_digest != pinned.public_parameter_digest {
            return Err(SuiteError::Mismatch("public-parameter digest").into());
        }
        for (actual, expected, label) in [
            (
                self.primary_constraints,
                pinned.primary.constraints,
                "primary constraints",
            ),
            (
                self.secondary_constraints,
                pinned.secondary.constraints,
                "secondary constraints",
            ),
            (
                self.primary_variables,
                pinned.primary.variables,
                "primary variables",
            ),
            (
                self.secondary_variables,
                pinned.secondary.variables,
                "secondary variables",
            ),
        ] {
            if u64::try_from(actual) != Ok(expected) {
                return Err(SuiteError::Mismatch(label).into());
            }
        }
        Ok(expected.proof_shape()?)
    }
}

/// Proving-only state for one fixed direct Nova suite.
///
/// This type owns the transparent public parameters and compression prover
/// key. It deliberately cannot verify receipts and cannot select its own
/// suite identity.
pub(crate) struct NovaProver<const ARITY: usize, C: NovaSessionStep<ARITY>> {
    public_params: NovaPublicParams<C>,
    prover_key: NovaProverKey<C>,
    proof_shape: NovaCompressedProofShape,
    pool: ThreadPool,
    operation: Mutex<()>,
}

/// A proving context promoted through one exact local profile.
pub(crate) struct SelectedNovaProver<const ARITY: usize, C: NovaSessionStep<ARITY>> {
    expected: &'static Suite,
    inner: NovaProver<ARITY, C>,
}

impl<const ARITY: usize, C: NovaSessionStep<ARITY>> NovaProver<ARITY, C> {
    fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
        relation_id: DirectRelationId,
    ) -> Result<NovaProverSession<'_, ARITY, C>, DirectNovaSessionError> {
        if expected_steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        Ok(NovaProverSession {
            prover: self,
            relation_id,
            initial_state,
            current_state: initial_state,
            expected_steps,
            completed_steps: 0,
            recursive: None,
        })
    }

    fn serialized<T: Send>(
        &self,
        operation: impl FnOnce() -> Result<T, DirectNovaSessionError> + Send,
    ) -> Result<T, DirectNovaSessionError> {
        let _guard = self
            .operation
            .lock()
            .expect("direct Nova prover operation mutex poisoned");
        self.pool.install(operation)
    }
}

impl<const ARITY: usize, C: NovaSessionStep<ARITY>> SelectedNovaProver<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static Suite {
        self.expected
    }

    pub(crate) fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
    ) -> Result<NovaProverSession<'_, ARITY, C>, DirectNovaSessionError> {
        self.inner.start(
            initial_state,
            expected_steps,
            DirectRelationId::from_frozen_bytes(self.expected.parameters.relation_id),
        )
    }
}

pub(crate) struct NovaProverSession<'suite, const ARITY: usize, C: NovaSessionStep<ARITY>> {
    prover: &'suite NovaProver<ARITY, C>,
    relation_id: DirectRelationId,
    initial_state: [DirectNovaScalar; ARITY],
    current_state: [DirectNovaScalar; ARITY],
    expected_steps: usize,
    completed_steps: usize,
    recursive: Option<NovaRecursiveSnark<C>>,
}

fn validate_step_relation<const ARITY: usize, C: NovaSessionStep<ARITY>>(
    expected: DirectRelationId,
    step: &C,
) -> Result<(), DirectNovaSessionError> {
    if step.relation_id() != expected {
        return Err(DirectNovaSessionError::StepRelation);
    }
    Ok(())
}

impl<const ARITY: usize, C: NovaSessionStep<ARITY>> NovaProverSession<'_, ARITY, C> {
    /// Consumes the session on both success and failure, so a partially
    /// mutated Nova proof can never be retried as if the fold were atomic.
    pub(crate) fn add_step(mut self, step: C) -> Result<Self, DirectNovaSessionError> {
        if self.completed_steps >= self.expected_steps {
            return Err(DirectNovaSessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps + 1,
            });
        }
        validate_step_relation(self.relation_id, &step)?;
        if step.input_state() != &self.current_state {
            return Err(DirectNovaSessionError::StateContinuity);
        }

        let recursive = &mut self.recursive;
        self.prover.serialized(|| {
            if let Some(recursive) = recursive.as_mut() {
                recursive.prove_step(&self.prover.public_params, &step)?;
            } else {
                let mut first = NovaRecursiveSnark::<C>::new(
                    &self.prover.public_params,
                    &step,
                    &self.initial_state,
                )?;
                // `new` executes the first circuit with internal `i = 0`.
                // The first prove call advances the counter to one without
                // executing the circuit a second time.
                first.prove_step(&self.prover.public_params, &step)?;
                if first.num_steps() != 1 {
                    return Err(DirectNovaSessionError::StepCount {
                        expected: 1,
                        actual: first.num_steps(),
                    });
                }
                *recursive = Some(first);
            }
            Ok(())
        })?;

        self.current_state = self
            .recursive
            .as_ref()
            .ok_or(DirectNovaSessionError::FinalState)?
            .outputs()
            .try_into()
            .map_err(|_| DirectNovaSessionError::FinalState)?;
        self.completed_steps += 1;
        Ok(self)
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, DirectNovaSessionError> {
        if self.completed_steps != self.expected_steps {
            return Err(DirectNovaSessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps,
            });
        }
        let recursive = self.recursive.ok_or(DirectNovaSessionError::StepCount {
            expected: self.expected_steps,
            actual: 0,
        })?;

        self.prover.serialized(|| {
            let verified = recursive.verify(
                &self.prover.public_params,
                self.completed_steps,
                &self.initial_state,
            )?;
            if verified.as_slice() != self.current_state {
                return Err(DirectNovaSessionError::FinalState);
            }
            let compressed = NovaCompressedSnark::<C>::prove_owned(
                &self.prover.public_params,
                &self.prover.prover_key,
                recursive,
            )?;
            Ok(self
                .prover
                .proof_shape
                .as_fixed_serde_shape()
                .encode(&compressed)?)
        })
    }
}

#[cfg(test)]
mod tests;
