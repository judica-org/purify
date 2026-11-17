//! Transparent setup and the in-memory verifier it yields.
//!
//! This module compiles only for tests. Production proving loads an
//! authenticated prover artifact and production verification loads an
//! authenticated verifier artifact; neither can reach this code.

use std::io::{Read, Seek, Write};
use std::sync::Mutex;

use nova_snark::{nova::VerifierKey, traits::snark::RelaxedR1CSSNARKTrait};
use rayon::ThreadPool;

use super::{
    NovaCompressedSnark, NovaPublicParams, Prover, ProverSession, SelectedProver, SessionError,
    SessionStep, SuiteMetadata,
};
use crate::artifact_writer::{write_artifact_payload, ArtifactWriteError};
use statement::{PrimaryEngine, Scalar, SecondaryEngine};
use verifier::artifact::ArtifactIdentity;
use verifier::codec::{ProofShape, R1csDimensions};
use verifier::nova::{
    one_thread_pool, PrimarySnark, SecondarySnark, VerifyError, VERIFIER_ARTIFACT_FORMAT,
};
use verifier::suite::{ConstructionVersions, R1csSize, Suite, SuiteError, SuiteParameters};

type NovaVerifierKey<C> =
    VerifierKey<PrimaryEngine, SecondaryEngine, C, PrimarySnark, SecondarySnark>;

/// A freshly generated, not yet selected prover and verifier pair.
pub(crate) struct SessionSuite<const ARITY: usize, C: SessionStep<ARITY>> {
    pub(crate) prover: Prover<ARITY, C>,
    pub(crate) verifier: SetupVerifier<ARITY, C>,
}

/// In-memory verifier over the real step circuit type.
///
/// The shipped verifier loads the same key bytes under an uninhabited circuit
/// marker. This generic form exists so setup tests can check a proof before
/// any artifact has been written, and for state arities other than the
/// production one.
pub(crate) struct SetupVerifier<const ARITY: usize, C: SessionStep<ARITY>> {
    pub(crate) verifier_key: NovaVerifierKey<C>,
    pub(crate) proof_shape: ProofShape,
    metadata: SuiteMetadata,
    pool: ThreadPool,
    operation: Mutex<()>,
}

/// A generic suite promoted through one exact local selection profile.
pub(crate) struct SelectedSessionSuite<const ARITY: usize, C: SessionStep<ARITY>> {
    pub(crate) prover: SelectedProver<ARITY, C>,
    pub(crate) verifier: SelectedSetupVerifier<ARITY, C>,
}

/// A setup verifier promoted through one exact local profile.
pub(crate) struct SelectedSetupVerifier<const ARITY: usize, C: SessionStep<ARITY>> {
    expected: &'static Suite,
    pub(crate) inner: SetupVerifier<ARITY, C>,
}

fn r1cs_size(constraints: usize, variables: usize) -> Result<R1csSize, SuiteError> {
    Ok(R1csSize {
        constraints: u64::try_from(constraints)
            .map_err(|_| SuiteError::Identity("constraint count"))?,
        variables: u64::try_from(variables).map_err(|_| SuiteError::Identity("variable count"))?,
    })
}

impl SuiteMetadata {
    /// Checks the declared relation and every measured value against one
    /// pinned profile.
    pub(crate) fn validate<const ARITY: usize>(
        &self,
        expected: &Suite,
    ) -> Result<ProofShape, SessionError> {
        if self.relation_id.bytes() != &expected.parameters.relation_id {
            return Err(SuiteError::Mismatch("relation ID").into());
        }
        self.validate_parameters::<ARITY>(expected)
    }

    /// Builds a self-consistent profile from these measured values.
    pub(crate) fn generated_suite<const ARITY: usize>(
        &self,
        versions: ConstructionVersions,
    ) -> Result<Suite, SuiteError> {
        let parameters = SuiteParameters {
            versions,
            state_arity: u32::try_from(ARITY).map_err(|_| SuiteError::Identity("state arity"))?,
            relation_id: *self.relation_id.bytes(),
            public_parameter_digest: self.public_parameter_digest,
            primary: r1cs_size(self.primary_constraints, self.primary_variables)?,
            secondary: r1cs_size(self.secondary_constraints, self.secondary_variables)?,
        };
        let proof_shape = parameters.proof_shape()?;
        Ok(Suite {
            parameters,
            proof_length: u64::try_from(proof_shape.encoded_len())
                .map_err(|_| SuiteError::Identity("proof length"))?,
            proof_sequences: u32::try_from(proof_shape.sequence_count())
                .map_err(|_| SuiteError::Identity("codec sequence count"))?,
            suite_id: parameters.suite_id(&proof_shape)?,
        })
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SessionSuite<ARITY, C> {
    /// Builds an unselected suite for internal experiments and test tools.
    pub(crate) fn setup(trusted_step: C) -> Result<Self, SessionError> {
        let relation_id = trusted_step.relation_id();
        let pool = one_thread_pool().map_err(SessionError::Setup)?;

        let (public_params, prover_key, verifier_key, proof_shape, metadata) =
            pool.install(move || -> Result<_, SessionError> {
                let public_params = NovaPublicParams::<C>::setup(
                    &trusted_step,
                    &*PrimarySnark::ck_floor(),
                    &*SecondarySnark::ck_floor(),
                )?;
                drop(trusted_step);
                let (primary_constraints, secondary_constraints) = public_params.num_constraints();
                let (primary_variables, secondary_variables) = public_params.num_variables();
                let proof_shape = ProofShape::from_suite_dimensions(
                    R1csDimensions::new(primary_constraints, primary_variables),
                    R1csDimensions::new(secondary_constraints, secondary_variables),
                    ARITY,
                )?;
                let (prover_key, verifier_key) = NovaCompressedSnark::<C>::setup(&public_params)?;
                let metadata =
                    SuiteMetadata::measure::<ARITY, C>(relation_id, &public_params, &proof_shape)?;
                Ok((
                    public_params,
                    prover_key,
                    verifier_key,
                    proof_shape,
                    metadata,
                ))
            })?;

        let verifier_pool = one_thread_pool().map_err(SessionError::Setup)?;
        Ok(Self {
            prover: Prover {
                public_params,
                prover_key,
                proof_shape: proof_shape.clone(),
                pool,
                operation: Mutex::new(()),
            },
            verifier: SetupVerifier {
                verifier_key,
                proof_shape,
                metadata,
                pool: verifier_pool,
                operation: Mutex::new(()),
            },
        })
    }

    /// Promotes one freshly generated qualification suite under its exact
    /// metadata and receipt-layer versions.
    ///
    /// The leaked profile is scoped to the resource-gated test process. It is
    /// deliberately not reachable by the production artifact loader, which
    /// remains pinned and fail-closed until these outputs are reviewed.
    pub(crate) fn select_generated_for_qualification(
        self,
        versions: ConstructionVersions,
    ) -> Result<SelectedSessionSuite<ARITY, C>, SessionError> {
        let expected = Box::leak(Box::new(
            self.verifier.metadata.generated_suite::<ARITY>(versions)?,
        ));
        self.select(expected)
    }

    /// Qualifies a suite only after its declared relation and complete
    /// measured metadata match one local profile. Production acceptance loads
    /// the resulting frozen verifier artifact; it never performs setup.
    pub(crate) fn setup_exact(
        trusted_step: C,
        expected: &'static Suite,
    ) -> Result<SelectedSessionSuite<ARITY, C>, SessionError> {
        if trusted_step.relation_id().bytes() != &expected.parameters.relation_id {
            return Err(SuiteError::Mismatch("relation ID").into());
        }
        Self::setup(trusted_step)?.select(expected)
    }

    pub(crate) fn metadata(&self) -> SuiteMetadata {
        self.verifier.metadata
    }

    pub(crate) fn select(
        self,
        expected: &'static Suite,
    ) -> Result<SelectedSessionSuite<ARITY, C>, SessionError> {
        self.verifier.metadata.validate::<ARITY>(expected)?;
        Ok(SelectedSessionSuite {
            prover: SelectedProver {
                expected,
                inner: self.prover,
            },
            verifier: SelectedSetupVerifier {
                expected,
                inner: self.verifier,
            },
        })
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SetupVerifier<ARITY, C> {
    pub(crate) fn metadata(&self) -> SuiteMetadata {
        self.metadata
    }

    /// Verifies the proof against the exact initial state and external step
    /// count, returning its authenticated recurrence output.
    pub(crate) fn verify_final(
        &self,
        initial_state: &[Scalar; ARITY],
        expected_steps: usize,
        proof: &[u8],
    ) -> Result<[Scalar; ARITY], VerifyError> {
        if expected_steps == 0 {
            return Err(VerifyError::StepCount {
                expected: 1,
                actual: 0,
            });
        }
        if proof.len() != self.proof_shape.encoded_len() {
            return Err(VerifyError::ProofLength {
                expected: self.proof_shape.encoded_len(),
                actual: proof.len(),
            });
        }

        let _guard = self
            .operation
            .lock()
            .expect("direct Nova suite operation mutex poisoned");
        self.pool.install(|| {
            let shape = self.proof_shape.as_fixed_serde_shape();
            let compressed = shape.decode_canonical::<NovaCompressedSnark<C>>(proof)?;
            let final_state =
                compressed.verify(&self.verifier_key, expected_steps, initial_state)?;
            final_state.try_into().map_err(|_| VerifyError::FinalState)
        })
    }

    pub(crate) fn verify_exact(
        &self,
        initial_state: &[Scalar; ARITY],
        expected_steps: usize,
        expected_final_state: &[Scalar; ARITY],
        proof: &[u8],
    ) -> Result<(), VerifyError> {
        if self.verify_final(initial_state, expected_steps, proof)? != *expected_final_state {
            return Err(VerifyError::FinalState);
        }
        Ok(())
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SelectedSessionSuite<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static Suite {
        self.prover.expected()
    }

    pub(crate) fn metadata(&self) -> SuiteMetadata {
        self.verifier.metadata()
    }

    pub(crate) fn start(
        &self,
        initial_state: [Scalar; ARITY],
        expected_steps: usize,
    ) -> Result<ProverSession<'_, ARITY, C>, SessionError> {
        self.prover.start(initial_state, expected_steps)
    }

    /// Discard the setup verifier and retain only qualification prover state.
    ///
    /// The setup-only qualification must persist and reload this state before
    /// it is used. Production code cannot perform transparent setup.
    pub(crate) fn into_prover(self) -> SelectedProver<ARITY, C> {
        self.prover
    }

    /// Permanently releases every proving component while retaining the
    /// exact selected verifier.
    pub(crate) fn into_verifier(self) -> SelectedSetupVerifier<ARITY, C> {
        self.verifier
    }
}

impl<const ARITY: usize, C: SessionStep<ARITY>> SelectedSetupVerifier<ARITY, C> {
    pub(crate) const fn expected(&self) -> &'static Suite {
        self.expected
    }

    pub(crate) fn metadata(&self) -> SuiteMetadata {
        self.inner.metadata()
    }

    /// Verifies only the caller's exact statement. The proof supplies neither
    /// suite metadata nor its own recursive step count.
    pub(crate) fn verify_exact(
        &self,
        initial_state: &[Scalar; ARITY],
        expected_steps: usize,
        expected_final_state: &[Scalar; ARITY],
        proof: &[u8],
    ) -> Result<(), VerifyError> {
        self.inner
            .verify_exact(initial_state, expected_steps, expected_final_state, proof)
    }

    /// Streams this selected verifier key into a new empty seekable
    /// destination in the shipped verifier-artifact format.
    ///
    /// The returned identity is qualification output. A production loader
    /// must compile in reviewed constants rather than derive them from the
    /// file it is about to accept.
    pub(crate) fn write_artifact<W>(
        &self,
        destination: &mut W,
    ) -> Result<ArtifactIdentity, ArtifactWriteError>
    where
        W: Read + Write + Seek,
    {
        write_artifact_payload(
            destination,
            &VERIFIER_ARTIFACT_FORMAT,
            self.expected.suite_id,
            ARITY,
            &self.inner.verifier_key,
        )
    }
}
