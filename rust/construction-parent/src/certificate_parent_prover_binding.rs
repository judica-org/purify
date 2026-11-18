//! Checked binding from one linear certificate witness to ordered Nova steps.
//!
//! Decoding establishes canonical encodings. This boundary additionally runs
//! every production constraint, checks the frozen relation dimensions, and
//! derives the complete state chain consumed by the prover.

use ff::Field;
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem},
    traits::circuit::StepCircuit,
};
use thiserror::Error;

use crate::certificate_joined_witness::{
    CertificateJoinedResponseWitness, CertificateLinearJoinedWitness,
};
use crate::certificate_parent_input::CertificateParentInputs;
use crate::certificate_profile::{
    CERTIFICATE_RECURRENCE_RELATION_AUXILIARY, CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS,
    CERTIFICATE_RECURRENCE_STATE_ARITY, CERTIFICATE_ROOT_BYTES, CERTIFICATE_ROOT_STATE_ARITY,
    NONCE_PREFIX_INDEX, NONCE_X_INDEX, RECORD_MANIFEST_INDEX,
};
use crate::certificate_recurrence::CertificateRecurrenceStateWitness;
use crate::certificate_recursive_manifest::{recursive_manifest_seed, recursive_manifest_step};
use crate::certificate_root::CertificateRoot;
use crate::construction_parent_prover_binding::CheckingWitnessCs;
use crate::nova_certificate_recurrence::{
    CertificateParentStep, QUALIFIED_CERTIFICATE_PARENT_RELATION_ID,
};
use crate::nova_session::NovaSessionStep;
use crate::secp_native::SecpEncodedPointWitness;
use crate::{scalar_to_canonical, RelationError, Scalar};

/// Failure while binding canonical CertJWit3 data to the certificate relation.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum CertificateParentWitnessBindingError {
    #[error("malformed certificate parent witness state: {0}")]
    State(&'static str),
    #[error("certificate parent witness count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
    #[error("malformed certificate parent witness step {step}: {detail}")]
    StepEncoding { step: usize, detail: &'static str },
    #[error("certificate parent witness state chain mismatch at step {step}")]
    StateChain { step: usize },
    #[error("certificate parent witness relation mismatch at step {step}")]
    Relation { step: usize },
    #[error("certificate parent witness synthesis failed at step {step}: {stage}")]
    Synthesis { step: usize, stage: &'static str },
    #[error("certificate parent witness constraint {constraint} is unsatisfied at step {step}")]
    Unsatisfied { step: usize, constraint: usize },
    #[error(
        "certificate parent witness auxiliary mismatch at step {step}: expected {expected}, actual {actual}"
    )]
    Auxiliary {
        step: usize,
        expected: usize,
        actual: usize,
    },
    #[error(
        "certificate parent witness constraint mismatch at step {step}: expected {expected}, actual {actual}"
    )]
    Constraints {
        step: usize,
        expected: usize,
        actual: usize,
    },
    #[error("certificate parent witness final manifest mismatch")]
    FinalManifest,
    #[error("certificate parent witness final frame mismatch")]
    FinalFrame,
}

impl From<RelationError> for CertificateParentWitnessBindingError {
    fn from(error: RelationError) -> Self {
        let RelationError::Malformed(detail) = error;
        Self::State(detail)
    }
}

/// Exact certificate prover input after all ordered witness equations pass.
pub(crate) struct BoundCertificateParentWitness {
    initial_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    steps: Vec<CertificateParentStep>,
    pending_root: [u8; CERTIFICATE_ROOT_BYTES],
    public_inputs: CertificateParentInputs,
}

impl BoundCertificateParentWitness {
    pub(crate) const fn initial_state(&self) -> &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        &self.initial_state
    }

    pub(crate) const fn final_state(&self) -> &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        &self.final_state
    }

    pub(crate) fn steps(&self) -> &[CertificateParentStep] {
        &self.steps
    }

    pub(crate) const fn pending_root(&self) -> &[u8; CERTIFICATE_ROOT_BYTES] {
        &self.pending_root
    }

    #[cfg(test)]
    pub(crate) fn trusted_setup_step(&self) -> Option<CertificateParentStep> {
        self.steps.first().cloned()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
        [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
        Vec<CertificateParentStep>,
        [u8; CERTIFICATE_ROOT_BYTES],
    ) {
        (
            self.initial_state,
            self.final_state,
            self.steps,
            self.pending_root,
        )
    }

    pub(crate) fn into_prover_parts(
        self,
    ) -> (
        [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
        [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
        Vec<CertificateParentStep>,
        [u8; CERTIFICATE_ROOT_BYTES],
        CertificateParentInputs,
    ) {
        (
            self.initial_state,
            self.final_state,
            self.steps,
            self.pending_root,
            self.public_inputs,
        )
    }
}

impl CertificateLinearJoinedWitness {
    /// Bind private CertJWit3 data to an independently resolved public frame.
    ///
    /// `inputs` must come from admitted public certificate records. In
    /// particular, its final manifest must not be copied from CertJWit3 parent
    /// constants or from a proof-authenticated final state.
    pub(crate) fn bind(
        self,
        inputs: CertificateParentInputs,
    ) -> Result<BoundCertificateParentWitness, CertificateParentWitnessBindingError> {
        let frame = self.frame();
        let response_count = usize::try_from(frame.total_responses())
            .map_err(|_| RelationError::Malformed("certificate response count"))?;
        if self.responses().len() != response_count {
            return Err(CertificateParentWitnessBindingError::StepCount {
                expected: response_count,
                actual: self.responses().len(),
            });
        }
        let total_steps = self.responses().iter().try_fold(
            0usize,
            |total, response| -> Result<usize, CertificateParentWitnessBindingError> {
                if response.response().members().len() != response.member_proofs().len() {
                    return Err(
                        RelationError::Malformed("certificate linear member proof count").into(),
                    );
                }
                total
                    .checked_add(response.member_proofs().len())
                    .ok_or_else(|| {
                        RelationError::Malformed("certificate linear total member count").into()
                    })
            },
        )?;

        let mut state = CertificateRecurrenceStateWitness::genesis(
            frame.certificate_context_digest(),
            frame.total_responses(),
        )?;
        let initial_state = state.state_fields()?;
        if inputs.initial_state() != &initial_state {
            return Err(CertificateParentWitnessBindingError::FinalFrame);
        }
        let mut expected_input = initial_state;
        let mut expected_manifest =
            recursive_manifest_seed(frame.certificate_context_digest(), frame.total_responses())?;
        if inputs.step_count() != total_steps {
            return Err(CertificateParentWitnessBindingError::StepCount {
                expected: inputs.step_count(),
                actual: total_steps,
            });
        }
        let mut steps = Vec::with_capacity(total_steps);

        for (response_index, linear_response) in self.responses().iter().enumerate() {
            let response_ordinal = u64::try_from(response_index)
                .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
            let response = linear_response.response();
            if response.boundary().ordinal() != response_ordinal {
                return Err(RelationError::Malformed("certificate response ordinal").into());
            }
            for member_index in 0..linear_response.member_proofs().len() {
                let member_ordinal = u32::try_from(member_index)
                    .map_err(|_| RelationError::Malformed("certificate member ordinal"))?;
                let step_number = steps.len() + 1;
                let step = CertificateParentStep::from_linear(
                    state,
                    &self,
                    response_ordinal,
                    member_ordinal,
                )
                .map_err(|error| {
                    let RelationError::Malformed(detail) = error;
                    CertificateParentWitnessBindingError::StepEncoding {
                        step: step_number,
                        detail,
                    }
                })?;
                if step.input_state() != &expected_input {
                    return Err(CertificateParentWitnessBindingError::StateChain {
                        step: step_number,
                    });
                }
                if NovaSessionStep::relation_id(&step) != QUALIFIED_CERTIFICATE_PARENT_RELATION_ID {
                    return Err(CertificateParentWitnessBindingError::Relation {
                        step: step_number,
                    });
                }

                expected_manifest = recursive_manifest_step(
                    expected_manifest,
                    response_ordinal,
                    member_ordinal,
                    step.expected_step_digest(),
                )?;
                let output = synthesize_output(step_number, &step)?;
                state = recurrence_state_from_output(
                    step_number,
                    output,
                    frame.certificate_context_digest(),
                    frame.total_responses(),
                    response,
                    member_ordinal,
                )?;
                if state.record_manifest != expected_manifest {
                    return Err(CertificateParentWitnessBindingError::FinalManifest);
                }
                expected_input = output;
                steps.push(step);
            }
        }

        let pending = inputs
            .validate_authenticated_final_state(expected_input)
            .map_err(|_| CertificateParentWitnessBindingError::FinalFrame)?;
        state
            .pending_root_for_decision(
                frame.certificate_context_digest(),
                frame.total_responses(),
                expected_manifest,
            )
            .map_err(|_| CertificateParentWitnessBindingError::FinalFrame)?;
        let pending_root = *pending.canonical_root_bytes();

        Ok(BoundCertificateParentWitness {
            initial_state,
            final_state: expected_input,
            steps,
            pending_root,
            public_inputs: inputs,
        })
    }
}

fn synthesize_output(
    step_number: usize,
    step: &CertificateParentStep,
) -> Result<[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY], CertificateParentWitnessBindingError> {
    let mut cs =
        CheckingWitnessCs::with_auxiliary_capacity(CERTIFICATE_RECURRENCE_RELATION_AUXILIARY);
    let mut inputs = Vec::with_capacity(CERTIFICATE_RECURRENCE_STATE_ARITY);
    for (index, value) in step.input_state().iter().enumerate() {
        let input =
            AllocatedNum::alloc_input(cs.namespace(|| format!("state {index}")), || Ok(*value))
                .map_err(|_| CertificateParentWitnessBindingError::Synthesis {
                    step: step_number,
                    stage: "state input",
                })?;
        inputs.push(input);
    }
    let outputs = step.synthesize(&mut cs, &inputs).map_err(|_| {
        CertificateParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "certificate recurrence",
        }
    })?;
    if let Some(constraint) = cs.first_unsatisfied() {
        return Err(CertificateParentWitnessBindingError::Unsatisfied {
            step: step_number,
            constraint,
        });
    }
    if cs.auxiliary_len() != CERTIFICATE_RECURRENCE_RELATION_AUXILIARY {
        return Err(CertificateParentWitnessBindingError::Auxiliary {
            step: step_number,
            expected: CERTIFICATE_RECURRENCE_RELATION_AUXILIARY,
            actual: cs.auxiliary_len(),
        });
    }
    if cs.constraint_count() != CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS {
        return Err(CertificateParentWitnessBindingError::Constraints {
            step: step_number,
            expected: CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS,
            actual: cs.constraint_count(),
        });
    }
    if outputs.len() != CERTIFICATE_RECURRENCE_STATE_ARITY {
        return Err(CertificateParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "output state arity",
        });
    }
    let values = outputs
        .into_iter()
        .map(|output| {
            output
                .get_value()
                .ok_or(CertificateParentWitnessBindingError::Synthesis {
                    step: step_number,
                    stage: "missing output assignment",
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    values
        .try_into()
        .map_err(|_| CertificateParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "output state arity",
        })
}

fn recurrence_state_from_output(
    step_number: usize,
    fields: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    context: [u8; 32],
    total_responses: u64,
    response: &CertificateJoinedResponseWitness,
    member_ordinal: u32,
) -> Result<CertificateRecurrenceStateWitness, CertificateParentWitnessBindingError> {
    let root_fields = fields[..CERTIFICATE_ROOT_STATE_ARITY]
        .try_into()
        .map_err(|_| RelationError::Malformed("certificate root state arity"))?;
    let root = CertificateRoot::from_state_fields(root_fields)?.claim();
    let mut record_manifest = scalar_to_canonical(&fields[RECORD_MANIFEST_INDEX]);
    record_manifest.reverse();

    let member_count = response.boundary().member_count();
    let next_member = member_ordinal
        .checked_add(1)
        .ok_or(CertificateParentWitnessBindingError::StateChain { step: step_number })?;
    let (partial_nonce, response_ordinal, member_ordinal, member_count, response_binding) =
        if next_member == member_count {
            (
                SecpEncodedPointWitness::identity(),
                response.boundary().ordinal() + 1,
                0,
                0,
                [0; 32],
            )
        } else {
            (
                point_from_state(fields[NONCE_PREFIX_INDEX], fields[NONCE_X_INDEX])?,
                response.boundary().ordinal(),
                next_member,
                member_count,
                masked_response_binding(response.response_binding()),
            )
        };
    let state = CertificateRecurrenceStateWitness {
        root,
        certificate_context_digest: context,
        total_responses,
        partial_nonce,
        record_manifest,
        response_ordinal,
        member_ordinal,
        member_count,
        response_binding,
    };
    if state.state_fields()? != fields {
        return Err(CertificateParentWitnessBindingError::StateChain { step: step_number });
    }
    Ok(state)
}

fn masked_response_binding(mut binding: [u8; 32]) -> [u8; 32] {
    binding[0] &= 0x7f;
    binding
}

fn point_from_state(
    prefix: Scalar,
    x: Scalar,
) -> Result<SecpEncodedPointWitness, CertificateParentWitnessBindingError> {
    let prefix = if prefix == Scalar::ZERO {
        0
    } else if prefix == Scalar::from(2) {
        2
    } else if prefix == Scalar::from(3) {
        3
    } else {
        return Err(RelationError::Malformed("certificate nonce point prefix").into());
    };
    if prefix == 0 {
        if x != Scalar::ZERO {
            return Err(RelationError::Malformed("certificate nonce identity point").into());
        }
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = prefix;
    let mut x_bytes = scalar_to_canonical(&x);
    x_bytes.reverse();
    encoded[1..].copy_from_slice(&x_bytes);
    Ok(SecpEncodedPointWitness::parse(encoded)?)
}

#[cfg(test)]
mod tests {
    use std::{panic, thread};

    use super::*;

    const WITNESS: &[u8] = include_bytes!("../tests/vectors/certificate_joined_witness_v3.bin");
    const CONTEXT: [u8; 32] = [
        0x7b, 0xcb, 0x06, 0xb8, 0x53, 0x8c, 0xcc, 0x9c, 0x79, 0xfd, 0x2f, 0x59, 0x5b, 0xbb, 0xee,
        0x9f, 0x08, 0xc0, 0xd8, 0x29, 0xa9, 0x7c, 0xcd, 0x92, 0xfc, 0x31, 0x75, 0xeb, 0x37, 0x90,
        0x39, 0xf5,
    ];
    const FINAL_MANIFEST: [u8; 32] = [
        0x45, 0xe8, 0x14, 0x7f, 0x29, 0x3a, 0x6e, 0xdc, 0xf5, 0x0c, 0x17, 0x8d, 0x94, 0xa4, 0x73,
        0x1b, 0x5e, 0x18, 0x78, 0x4c, 0x7b, 0x40, 0x4b, 0xa9, 0xc3, 0x57, 0xb9, 0xdb, 0x22, 0x4c,
        0x1f, 0x9c,
    ];

    fn witness() -> CertificateLinearJoinedWitness {
        CertificateLinearJoinedWitness::parse(WITNESS).expect("real CertJWit3 fixture")
    }

    fn inputs(manifest: [u8; 32], steps: u128) -> CertificateParentInputs {
        CertificateParentInputs::new(CONTEXT, 2, steps, manifest)
            .expect("certificate parent public inputs")
    }

    #[test]
    fn rejects_a_public_step_count_before_relation_synthesis() {
        assert_eq!(
            witness()
                .bind(inputs(FINAL_MANIFEST, 3))
                .err()
                .expect("wrong public step count rejects"),
            CertificateParentWitnessBindingError::StepCount {
                expected: 3,
                actual: 4,
            }
        );
    }

    #[test]
    #[ignore = "streams four full production certificate steps"]
    fn binds_real_linear_witness_to_external_public_frame() {
        let worker = thread::Builder::new()
            .name("certificate-parent-witness-binding".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(run_real_witness_binding)
            .expect("certificate binder worker");
        if let Err(payload) = worker.join() {
            panic::resume_unwind(payload);
        }
    }

    fn run_real_witness_binding() {
        let bound = witness()
            .bind(inputs(FINAL_MANIFEST, 4))
            .expect("bind real linear certificate witness");
        assert_eq!(bound.steps().len(), 4);
        assert_ne!(bound.pending_root(), &[0; CERTIFICATE_ROOT_BYTES]);

        let mut changed_manifest = FINAL_MANIFEST;
        changed_manifest[31] ^= 1;
        let changed_inputs = inputs(changed_manifest, 4);
        assert!(changed_inputs
            .validate_authenticated_final_state(*bound.final_state())
            .is_err());
    }
}
