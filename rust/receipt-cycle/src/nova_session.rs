//! Serialized one-thread Nova lifecycle for one exact direct relation.
//!
//! This module owns only the generic fixed-template mechanics. A production
//! receipt suite must still select a trusted canonical relation fixture and
//! freeze its relation ID, public-parameter digest, matrix dimensions, and
//! proof-codec shape before exposing an acceptance API.

use std::sync::Mutex;

use ff::PrimeField;
use nova_snark::{
    errors::NovaError,
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey},
    provider::ipa_pc,
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::RelaxedR1CSSNARKTrait,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use thiserror::Error;

use crate::{
    direct_nova::{
        DirectNovaPrimaryEngine, DirectNovaScalar, DirectNovaSecondaryEngine, DirectNovaStep,
        DirectNovaTemplate, DirectRelationId,
    },
    fixed_serde::{FixedSerdeError, NovaCompressedProofShape, NovaR1csDimensions},
    relation_builder::StatefulRelation,
    ReceiptCycleError,
};

type PrimaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaPrimaryEngine>;
type SecondaryEvaluationEngine = ipa_pc::EvaluationEngine<DirectNovaSecondaryEngine>;
type PrimarySnark = RelaxedR1CSSNARK<DirectNovaPrimaryEngine, PrimaryEvaluationEngine>;
type SecondarySnark = RelaxedR1CSSNARK<DirectNovaSecondaryEngine, SecondaryEvaluationEngine>;
type DirectPublicParams<const ARITY: usize> =
    PublicParams<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, DirectNovaStep<ARITY>>;
type DirectRecursiveSnark<const ARITY: usize> =
    RecursiveSNARK<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, DirectNovaStep<ARITY>>;
type DirectCompressedSnark<const ARITY: usize> = CompressedSNARK<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;
type DirectProverKey<const ARITY: usize> = ProverKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;
type DirectVerifierKey<const ARITY: usize> = VerifierKey<
    DirectNovaPrimaryEngine,
    DirectNovaSecondaryEngine,
    DirectNovaStep<ARITY>,
    PrimarySnark,
    SecondarySnark,
>;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum DirectNovaSessionError {
    #[error(transparent)]
    Relation(#[from] ReceiptCycleError),
    #[error(transparent)]
    Nova(#[from] NovaError),
    #[error(transparent)]
    Codec(#[from] FixedSerdeError),
    #[error("direct Nova suite setup failed: {0}")]
    Setup(&'static str),
    #[error("direct Nova state continuity mismatch")]
    StateContinuity,
    #[error("direct Nova verified final state mismatch")]
    FinalState,
    #[error("direct Nova step count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
    #[error("direct Nova proof length mismatch: expected {expected}, actual {actual}")]
    ProofLength { expected: usize, actual: usize },
}

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

pub(crate) struct DirectNovaSuite<const ARITY: usize> {
    template: DirectNovaTemplate<ARITY>,
    public_params: DirectPublicParams<ARITY>,
    prover_key: DirectProverKey<ARITY>,
    verifier_key: DirectVerifierKey<ARITY>,
    proof_shape: NovaCompressedProofShape,
    metadata: DirectNovaSuiteMetadata,
    pool: ThreadPool,
    operation: Mutex<()>,
}

impl<const ARITY: usize> DirectNovaSuite<ARITY> {
    /// Builds transparent parameters from one trusted canonical relation.
    ///
    /// Callers selecting a production suite must compare `metadata()` with
    /// locally frozen values before accepting any proof.
    pub(crate) fn setup(
        trusted_relation: StatefulRelation,
    ) -> Result<Self, DirectNovaSessionError> {
        let (template, trusted_step) = DirectNovaTemplate::from_relation(trusted_relation)?;
        let relation_id = trusted_step.relation_id();
        let pool = ThreadPoolBuilder::new()
            .num_threads(1)
            .thread_name(|_| "purify-direct-nova".to_owned())
            .build()
            .map_err(|_| DirectNovaSessionError::Setup("one-thread Rayon pool"))?;

        let (public_params, prover_key, verifier_key, proof_shape, metadata) =
            pool.install(|| -> Result<_, DirectNovaSessionError> {
                let public_params = DirectPublicParams::<ARITY>::setup(
                    &trusted_step,
                    &*PrimarySnark::ck_floor(),
                    &*SecondarySnark::ck_floor(),
                )?;
                let (primary_constraints, secondary_constraints) = public_params.num_constraints();
                let (primary_variables, secondary_variables) = public_params.num_variables();
                let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
                    NovaR1csDimensions::new(primary_constraints, primary_variables),
                    NovaR1csDimensions::new(secondary_constraints, secondary_variables),
                    ARITY,
                )?;
                let (prover_key, verifier_key) =
                    DirectCompressedSnark::<ARITY>::setup(&public_params)?;
                let digest_repr = public_params.digest().to_repr();
                let public_parameter_digest = digest_repr
                    .as_ref()
                    .try_into()
                    .map_err(|_| DirectNovaSessionError::Setup("public-parameter digest width"))?;
                let metadata = DirectNovaSuiteMetadata {
                    relation_id,
                    public_parameter_digest,
                    primary_constraints,
                    secondary_constraints,
                    primary_variables,
                    secondary_variables,
                    proof_length: proof_shape.encoded_len(),
                    codec_sequence_count: proof_shape.sequence_count(),
                };
                Ok((
                    public_params,
                    prover_key,
                    verifier_key,
                    proof_shape,
                    metadata,
                ))
            })?;

        Ok(Self {
            template,
            public_params,
            prover_key,
            verifier_key,
            proof_shape,
            metadata,
            pool,
            operation: Mutex::new(()),
        })
    }

    pub(crate) fn metadata(&self) -> DirectNovaSuiteMetadata {
        self.metadata
    }

    pub(crate) fn start(
        &self,
        initial_state: [DirectNovaScalar; ARITY],
        expected_steps: usize,
    ) -> Result<DirectNovaProverSession<'_, ARITY>, DirectNovaSessionError> {
        if expected_steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        Ok(DirectNovaProverSession {
            suite: self,
            initial_state,
            current_state: initial_state,
            expected_steps,
            completed_steps: 0,
            recursive: None,
        })
    }

    pub(crate) fn verify_exact(
        &self,
        initial_state: &[DirectNovaScalar; ARITY],
        steps: usize,
        expected_final_state: &[DirectNovaScalar; ARITY],
        proof: &[u8],
    ) -> Result<(), DirectNovaSessionError> {
        if steps == 0 {
            return Err(DirectNovaSessionError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        if proof.len() != self.proof_shape.encoded_len() {
            return Err(DirectNovaSessionError::ProofLength {
                expected: self.proof_shape.encoded_len(),
                actual: proof.len(),
            });
        }

        self.serialized(|| {
            let shape = self.proof_shape.as_fixed_serde_shape();
            let compressed = shape.decode_canonical::<DirectCompressedSnark<ARITY>>(proof)?;
            let final_state = compressed.verify(&self.verifier_key, steps, initial_state)?;
            if final_state.as_slice() != expected_final_state {
                return Err(DirectNovaSessionError::FinalState);
            }
            Ok(())
        })
    }

    fn serialized<T: Send>(
        &self,
        operation: impl FnOnce() -> Result<T, DirectNovaSessionError> + Send,
    ) -> Result<T, DirectNovaSessionError> {
        let _guard = self
            .operation
            .lock()
            .expect("direct Nova suite operation mutex poisoned");
        self.pool.install(operation)
    }
}

pub(crate) struct DirectNovaProverSession<'suite, const ARITY: usize> {
    suite: &'suite DirectNovaSuite<ARITY>,
    initial_state: [DirectNovaScalar; ARITY],
    current_state: [DirectNovaScalar; ARITY],
    expected_steps: usize,
    completed_steps: usize,
    recursive: Option<DirectRecursiveSnark<ARITY>>,
}

impl<const ARITY: usize> DirectNovaProverSession<'_, ARITY> {
    /// Consumes the session on both success and failure, so a partially
    /// mutated Nova proof can never be retried as if the fold were atomic.
    pub(crate) fn add_relation(
        mut self,
        relation: StatefulRelation,
    ) -> Result<Self, DirectNovaSessionError> {
        if self.completed_steps >= self.expected_steps {
            return Err(DirectNovaSessionError::StepCount {
                expected: self.expected_steps,
                actual: self.completed_steps + 1,
            });
        }
        let step = self.suite.template.bind_relation(relation)?;
        if step.input_state() != &self.current_state {
            return Err(DirectNovaSessionError::StateContinuity);
        }

        let recursive = &mut self.recursive;
        self.suite.serialized(|| {
            if let Some(recursive) = recursive.as_mut() {
                recursive.prove_step(&self.suite.public_params, &step)?;
            } else {
                let mut first = DirectRecursiveSnark::<ARITY>::new(
                    &self.suite.public_params,
                    &step,
                    &self.initial_state,
                )?;
                // `new` executes the first circuit with internal `i = 0`.
                // The first prove call advances the counter to one without
                // executing the circuit a second time.
                first.prove_step(&self.suite.public_params, &step)?;
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

        self.current_state = *step.output_state();
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

        self.suite.serialized(|| {
            let verified = recursive.verify(
                &self.suite.public_params,
                self.completed_steps,
                &self.initial_state,
            )?;
            if verified.as_slice() != self.current_state {
                return Err(DirectNovaSessionError::FinalState);
            }
            let compressed = DirectCompressedSnark::<ARITY>::prove(
                &self.suite.public_params,
                &self.suite.prover_key,
                &recursive,
            )?;
            Ok(self
                .suite
                .proof_shape
                .as_fixed_serde_shape()
                .encode(&compressed)?)
        })
    }
}

#[cfg(test)]
mod tests {
    use bulletproofs_cycle::Cycle;
    use ff::{Field, PrimeField};
    use golden_halo2curves::Secq256k1Cycle;

    use super::*;
    use crate::{
        relation_builder::{Builder, StateVariable},
        Scalar,
    };

    const TEST_ARITY: usize = 20;

    fn source_state(seed: u64) -> [Scalar; TEST_ARITY] {
        std::array::from_fn(|index| Scalar::from(seed + index as u64))
    }

    fn increment(state: [Scalar; TEST_ARITY]) -> [Scalar; TEST_ARITY] {
        state.map(|value| value + Scalar::ONE)
    }

    fn relation(state: [Scalar; TEST_ARITY]) -> StatefulRelation {
        let mut builder = Builder::default();
        let inputs: Vec<StateVariable> = state
            .iter()
            .map(|&value| builder.allocate_state(value))
            .collect();
        let mut outputs = Vec::with_capacity(TEST_ARITY);
        for input in &inputs {
            let next = input
                .expression()
                .clone()
                .add(&crate::relation_builder::Expression::constant(Scalar::ONE));
            outputs.push(builder.expose_state(&next));
        }
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("twenty-state Nova relation")
    }

    fn nova_state(state: [Scalar; TEST_ARITY]) -> [DirectNovaScalar; TEST_ARITY] {
        state.map(|value| {
            let bytes = Secq256k1Cycle::scalar_to_canonical(&value);
            let mut repr = <DirectNovaScalar as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&bytes);
            Option::<DirectNovaScalar>::from(DirectNovaScalar::from_repr(repr))
                .expect("canonical Nova state")
        })
    }

    #[test]
    #[ignore = "explicit slow real two-step Nova session"]
    fn tiny_twenty_state_session_round_trips_canonically() {
        const EXPECTED_RELATION_ID: [u8; 32] = [
            216, 68, 225, 212, 141, 3, 38, 194, 117, 15, 42, 255, 34, 4, 125, 137, 129, 43, 41, 78,
            189, 244, 129, 131, 165, 2, 204, 234, 60, 149, 220, 168,
        ];
        const EXPECTED_PUBLIC_PARAMETER_DIGEST: [u8; 32] = [
            247, 248, 171, 109, 59, 169, 222, 232, 34, 50, 169, 143, 71, 133, 71, 85, 255, 3, 30,
            104, 161, 57, 66, 253, 195, 30, 88, 65, 224, 42, 105, 3,
        ];
        let source_z0 = source_state(3);
        let source_z1 = increment(source_z0);
        let source_z2 = increment(source_z1);
        let z0 = nova_state(source_z0);
        let z1 = nova_state(source_z1);
        let z2 = nova_state(source_z2);

        let suite = DirectNovaSuite::<TEST_ARITY>::setup(relation(source_z0))
            .expect("tiny direct Nova suite");
        let metadata = suite.metadata();
        assert_eq!(*metadata.relation_id.bytes(), EXPECTED_RELATION_ID);
        assert_eq!(
            metadata.public_parameter_digest,
            EXPECTED_PUBLIC_PARAMETER_DIGEST
        );
        assert_eq!(
            (metadata.primary_constraints, metadata.secondary_constraints),
            (13_606, 10_787)
        );
        assert_eq!(
            (metadata.primary_variables, metadata.secondary_variables),
            (13_636, 10_769)
        );
        assert_eq!(metadata.proof_length, 10_436);
        assert_eq!(metadata.codec_sequence_count, 104);

        let session = suite
            .start(z0, 2)
            .expect("two-step session")
            .add_relation(relation(source_z0))
            .expect("first fold")
            .add_relation(relation(source_z1))
            .expect("second fold");
        let proof = session.finish().expect("compress two-step proof");
        assert_eq!(proof.len(), metadata.proof_length);
        suite
            .verify_exact(&z0, 2, &z2, &proof)
            .expect("verify canonical proof");

        let mut short = proof.clone();
        short.pop();
        assert!(matches!(
            suite.verify_exact(&z0, 2, &z2, &short),
            Err(DirectNovaSessionError::ProofLength { .. })
        ));

        let mut wrong_final = z2;
        wrong_final[0] += DirectNovaScalar::ONE;
        assert!(matches!(
            suite.verify_exact(&z0, 2, &wrong_final, &proof),
            Err(DirectNovaSessionError::FinalState)
        ));
        assert!(suite.verify_exact(&z0, 1, &z1, &proof).is_err());

        let incomplete = suite.start(z0, 2).expect("incomplete session");
        assert!(matches!(
            incomplete.finish(),
            Err(DirectNovaSessionError::StepCount {
                expected: 2,
                actual: 0
            })
        ));

        let discontinuous = suite
            .start(z0, 2)
            .expect("discontinuous session")
            .add_relation(relation(source_z1));
        assert!(matches!(
            discontinuous,
            Err(DirectNovaSessionError::StateContinuity)
        ));
    }
}
