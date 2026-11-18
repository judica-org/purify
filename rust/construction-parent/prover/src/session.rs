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

use circuit::profile::STATE_ARITY;
use circuit::relation::identity::RelationId;
use circuit::relation::recurrence::ConstructionParentStep;
use statement::{PrimaryEngine, Scalar, SecondaryEngine};
use verifier::codec::{FixedSerdeError, ProofShape};
use verifier::nova::{PrimarySnark, SecondarySnark};
use verifier::suite::{Suite, SuiteError};

pub(crate) mod prover_artifact;
#[cfg(test)]
pub(crate) mod setup;

type NovaPublicParams<C> = PublicParams<PrimaryEngine, SecondaryEngine, C>;
type NovaRecursiveSnark<C> = RecursiveSNARK<PrimaryEngine, SecondaryEngine, C>;
type NovaCompressedSnark<C> =
    CompressedSNARK<PrimaryEngine, SecondaryEngine, C, PrimarySnark, SecondarySnark>;
type NovaProverKey<C> = ProverKey<PrimaryEngine, SecondaryEngine, C, PrimarySnark, SecondarySnark>;

/// A step circuit that declares which relation it belongs to and which
/// state it consumes, so a session can refuse foreign or discontinuous steps.
pub(crate) trait SessionStep<const ARITY: usize>: StepCircuit<Scalar> {
    fn relation_id(&self) -> RelationId;
    fn input_state(&self) -> &[Scalar; ARITY];
}

impl SessionStep<STATE_ARITY> for ConstructionParentStep {
    fn relation_id(&self) -> RelationId {
        self.declared_relation_id()
    }

    fn input_state(&self) -> &[Scalar; STATE_ARITY] {
        ConstructionParentStep::input_state(self)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum SessionError {
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
pub(crate) struct SuiteMetadata {
    pub(crate) relation_id: RelationId,
    pub(crate) public_parameter_digest: [u8; 32],
    pub(crate) primary_constraints: usize,
    pub(crate) secondary_constraints: usize,
    pub(crate) primary_variables: usize,
    pub(crate) secondary_variables: usize,
    pub(crate) proof_length: usize,
    pub(crate) codec_sequence_count: usize,
}

impl SuiteMetadata {
    /// Measures the parameter digest and augmented dimensions.
    ///
    /// `relation_id` is the step relation the parameters were generated or
    /// selected for; public parameters do not carry it.
    fn measure<const ARITY: usize, C: SessionStep<ARITY>>(
        relation_id: RelationId,
        public_params: &NovaPublicParams<C>,
        proof_shape: &ProofShape,
    ) -> Result<Self, SessionError> {
        let digest_repr = public_params.digest().to_repr();
        let public_parameter_digest = digest_repr
            .as_ref()
            .try_into()
            .map_err(|_| SessionError::Setup("public-parameter digest width"))?;
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
    ) -> Result<ProofShape, SessionError> {
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
pub(crate) struct Prover<const ARITY: usize, C: SessionStep<ARITY>> {
    public_params: NovaPublicParams<C>,
    prover_key: NovaProverKey<C>,
    proof_shape: ProofShape,
    pool: ThreadPool,
    operation: Mutex<()>,
}

/// A proving context promoted through one exact local profile.
pub(crate) struct SelectedProver<const ARITY: usize, C: SessionStep<ARITY>> {
    expected: &'static Suite,
    inner: Prover<ARITY, C>,
}

impl<const ARITY: usize, C: SessionStep<ARITY>> Prover<ARITY, C> {
    fn start(
        &self,
        initial_state: [Scalar; ARITY],
        expected_steps: usize,
        relation_id: RelationId,
    ) -> Result<ProverSession<'_, ARITY, C>, SessionError> {
        if expected_steps == 0 {
            return Err(SessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        Ok(ProverSession {
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
        operation: impl FnOnce() -> Result<T, SessionError> + Send,
    ) -> Result<T, SessionError> {
        let _guard = self
            .operation
            .lock()
            .expect("direct Nova prover operation mutex poisoned");
        self.pool.install(operation)
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SelectedProver<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static Suite {
        self.expected
    }

    pub(crate) fn start(
        &self,
        initial_state: [Scalar; ARITY],
        expected_steps: usize,
    ) -> Result<ProverSession<'_, ARITY, C>, SessionError> {
        self.inner.start(
            initial_state,
            expected_steps,
            RelationId::from_frozen_bytes(self.expected.parameters.relation_id),
        )
    }
}

pub(crate) struct ProverSession<'suite, const ARITY: usize, C: SessionStep<ARITY>> {
    prover: &'suite Prover<ARITY, C>,
    relation_id: RelationId,
    initial_state: [Scalar; ARITY],
    current_state: [Scalar; ARITY],
    expected_steps: usize,
    completed_steps: usize,
    recursive: Option<NovaRecursiveSnark<C>>,
}

fn validate_step_relation<const ARITY: usize, C: SessionStep<ARITY>>(
    expected: RelationId,
    step: &C,
) -> Result<(), SessionError> {
    if step.relation_id() != expected {
        return Err(SessionError::StepRelation);
    }
    Ok(())
}

impl<const ARITY: usize, C: SessionStep<ARITY>> ProverSession<'_, ARITY, C> {
    /// Consumes the session on both success and failure, so a partially
    /// mutated Nova proof can never be retried as if the fold were atomic.
    pub(crate) fn add_step(mut self, step: C) -> Result<Self, SessionError> {
        if self.completed_steps >= self.expected_steps {
            return Err(SessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps + 1,
            });
        }
        validate_step_relation(self.relation_id, &step)?;
        if step.input_state() != &self.current_state {
            return Err(SessionError::StateContinuity);
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
                    return Err(SessionError::StepCount {
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
            .ok_or(SessionError::FinalState)?
            .outputs()
            .try_into()
            .map_err(|_| SessionError::FinalState)?;
        self.completed_steps += 1;
        Ok(self)
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, SessionError> {
        if self.completed_steps != self.expected_steps {
            return Err(SessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps,
            });
        }
        let recursive = self.recursive.ok_or(SessionError::StepCount {
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
                return Err(SessionError::FinalState);
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
