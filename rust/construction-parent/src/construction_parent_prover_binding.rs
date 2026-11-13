//! Checked binding from one decoded Wit3 input to ordered Nova steps.
//!
//! Parsing establishes canonical encodings. This boundary additionally
//! executes every production constraint against the supplied witness, checks
//! the exact relation dimensions, and derives the state chain consumed by the
//! prover. No caller-supplied state is trusted.

use ff::Field;
use nova_snark::frontend::{
    gadgets::num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError,
    Variable,
};
use nova_snark::traits::circuit::StepCircuit;
use thiserror::Error;

use crate::candidate::CandidateRootClaim;
use crate::construction_manifest::ConstructionRoot;
use crate::construction_parent_prover_fixture::ConstructionParentProverFixture;
use crate::construction_profile::{
    CONSTRUCTION_PARENT_RELATION_AUXILIARY, CONSTRUCTION_PARENT_RELATION_CONSTRAINTS,
    CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS,
    CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::construction_recurrence::ConstructionRecurrenceStateWitness;
use crate::nova_construction_recurrence::{
    ConstructionParentStep, QUALIFIED_CONSTRUCTION_PARENT_RELATION_ID,
};
use crate::nova_session::NovaSessionStep;
use crate::{scalar_to_canonical, RelationError, Scalar};

/// Failure while binding canonical Wit3 data to the qualified relation.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ConstructionParentWitnessBindingError {
    /// A state or relation encoding was malformed.
    #[error("malformed construction parent witness state: {0}")]
    State(&'static str),
    /// One step contains malformed relation witness data.
    #[error("malformed construction parent witness step {step}: {detail}")]
    StepEncoding { step: usize, detail: &'static str },
    /// The decoded leaf count differs from the authenticated public count.
    #[error("construction parent witness count mismatch: expected {expected}, actual {actual}")]
    StepCount { expected: usize, actual: usize },
    /// One step does not consume the state produced by its predecessor.
    #[error("construction parent witness state chain mismatch at step {step}")]
    StateChain { step: usize },
    /// One step selects a relation other than the qualified relation.
    #[error("construction parent witness relation mismatch at step {step}")]
    Relation { step: usize },
    /// Constraint synthesis failed before producing a complete assignment.
    #[error("construction parent witness synthesis failed at step {step}: {stage}")]
    Synthesis { step: usize, stage: &'static str },
    /// A supplied witness violates a production constraint.
    #[error("construction parent witness constraint {constraint} is unsatisfied at step {step}")]
    Unsatisfied { step: usize, constraint: usize },
    /// The synthesized relation has an unexpected auxiliary-variable count.
    #[error(
        "construction parent witness auxiliary mismatch at step {step}: expected {expected}, actual {actual}"
    )]
    Auxiliary {
        step: usize,
        expected: usize,
        actual: usize,
    },
    /// The synthesized relation has an unexpected constraint count.
    #[error(
        "construction parent witness constraint mismatch at step {step}: expected {expected}, actual {actual}"
    )]
    Constraints {
        step: usize,
        expected: usize,
        actual: usize,
    },
    /// A recurrence output carries an unexpected step index.
    #[error("construction parent witness recurrence index mismatch: expected {expected}")]
    RecurrenceIndex { expected: u32 },
    /// The final state does not contain the independently derived manifest.
    #[error("construction parent witness final manifest mismatch")]
    FinalManifest,
    /// The final state does not encode the root appended to the Wit3 input.
    #[error("construction parent witness final root mismatch")]
    FinalRoot,
}

impl From<RelationError> for ConstructionParentWitnessBindingError {
    fn from(error: RelationError) -> Self {
        let RelationError::Malformed(detail) = error;
        Self::State(detail)
    }
}

/// Exact prover input after all ordered witness equations have been checked.
pub(crate) struct BoundConstructionParentWitness {
    initial_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    steps: Vec<ConstructionParentStep>,
}

impl BoundConstructionParentWitness {
    pub(crate) const fn initial_state(&self) -> &[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY] {
        &self.initial_state
    }

    pub(crate) const fn final_state(&self) -> &[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY] {
        &self.final_state
    }

    pub(crate) fn steps(&self) -> &[ConstructionParentStep] {
        &self.steps
    }

    #[cfg(test)]
    pub(crate) fn steps_mut(&mut self) -> &mut [ConstructionParentStep] {
        &mut self.steps
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
        [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
        Vec<ConstructionParentStep>,
    ) {
        (self.initial_state, self.final_state, self.steps)
    }
}

impl ConstructionParentProverFixture {
    /// Consume one canonical Wit3 input and bind its complete state chain.
    pub(crate) fn bind(
        self,
    ) -> Result<BoundConstructionParentWitness, ConstructionParentWitnessBindingError> {
        let expected_count = self.inputs.step_count();
        if self.leaves.len() != expected_count {
            return Err(ConstructionParentWitnessBindingError::StepCount {
                expected: expected_count,
                actual: self.leaves.len(),
            });
        }

        let initial_state = *self.inputs.initial_state();
        let mut state = recurrence_state_from_fields(initial_state, 0)?;
        let mut expected_input = initial_state;
        let mut steps = Vec::with_capacity(expected_count);

        for (index, leaf) in self.leaves.into_iter().enumerate() {
            let step_number = index + 1;
            let step = ConstructionParentStep::new(
                state,
                leaf.statement,
                leaf.transcript,
                leaf.reduction,
                leaf.step,
            )
            .map_err(|error| {
                let RelationError::Malformed(detail) = error;
                ConstructionParentWitnessBindingError::StepEncoding {
                    step: step_number,
                    detail,
                }
            })?;
            if step.input_state() != &expected_input {
                return Err(ConstructionParentWitnessBindingError::StateChain {
                    step: step_number,
                });
            }
            if NovaSessionStep::relation_id(&step) != QUALIFIED_CONSTRUCTION_PARENT_RELATION_ID {
                return Err(ConstructionParentWitnessBindingError::Relation { step: step_number });
            }

            let output = synthesize_output(step_number, &step)?;
            let expected_index = u32::try_from(step_number)
                .map_err(|_| RelationError::Malformed("construction witness step count"))?;
            state = recurrence_state_from_fields(output, expected_index)?;
            expected_input = output;
            steps.push(step);
        }

        if expected_input[CONSTRUCTION_ROOT_STATE_ARITY..] != self.inputs.expected_suffix() {
            return Err(ConstructionParentWitnessBindingError::FinalManifest);
        }
        let root = construction_root_from_claim(&state.root)?;
        if root.canonical_bytes() != self.expected_root.canonical_bytes() {
            return Err(ConstructionParentWitnessBindingError::FinalRoot);
        }

        Ok(BoundConstructionParentWitness {
            initial_state,
            final_state: expected_input,
            steps,
        })
    }
}

struct CheckingWitnessCs {
    inputs: Vec<Scalar>,
    auxiliary: Vec<Scalar>,
    constraints: usize,
    first_unsatisfied: Option<usize>,
}

impl CheckingWitnessCs {
    fn with_auxiliary_capacity(capacity: usize) -> Self {
        Self {
            inputs: vec![Scalar::ONE],
            auxiliary: Vec::with_capacity(capacity),
            constraints: 0,
            first_unsatisfied: None,
        }
    }

    fn value(&self, variable: Variable) -> Scalar {
        match variable.get_unchecked() {
            Index::Input(index) => self.inputs[index],
            Index::Aux(index) => self.auxiliary[index],
        }
    }

    fn evaluate(&self, linear: &LinearCombination<Scalar>) -> Scalar {
        linear
            .iter()
            .fold(Scalar::ZERO, |value, (variable, coefficient)| {
                value + self.value(variable) * coefficient
            })
    }
}

impl ConstraintSystem<Scalar> for CheckingWitnessCs {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.auxiliary.len();
        self.auxiliary.push(value()?);
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _annotation: A,
        value: F,
    ) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.inputs.len();
        self.inputs.push(value()?);
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let a = self.evaluate(&a(LinearCombination::zero()));
        let b = self.evaluate(&b(LinearCombination::zero()));
        let c = self.evaluate(&c(LinearCombination::zero()));
        if self.first_unsatisfied.is_none() && a * b != c {
            self.first_unsatisfied = Some(self.constraints);
        }
        self.constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

fn synthesize_output(
    step_number: usize,
    step: &ConstructionParentStep,
) -> Result<[Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY], ConstructionParentWitnessBindingError> {
    let mut cs = CheckingWitnessCs::with_auxiliary_capacity(CONSTRUCTION_PARENT_RELATION_AUXILIARY);
    let mut inputs = Vec::with_capacity(CONSTRUCTION_RECURRENCE_STATE_ARITY);
    for (index, value) in step.input_state().iter().enumerate() {
        let input =
            AllocatedNum::alloc_input(cs.namespace(|| format!("state {index}")), || Ok(*value))
                .map_err(|_| ConstructionParentWitnessBindingError::Synthesis {
                    step: step_number,
                    stage: "state input",
                })?;
        inputs.push(input);
    }
    let outputs = step.synthesize(&mut cs, &inputs).map_err(|_| {
        ConstructionParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "construction recurrence",
        }
    })?;
    if let Some(constraint) = cs.first_unsatisfied {
        return Err(ConstructionParentWitnessBindingError::Unsatisfied {
            step: step_number,
            constraint,
        });
    }
    if cs.auxiliary.len() != CONSTRUCTION_PARENT_RELATION_AUXILIARY {
        return Err(ConstructionParentWitnessBindingError::Auxiliary {
            step: step_number,
            expected: CONSTRUCTION_PARENT_RELATION_AUXILIARY,
            actual: cs.auxiliary.len(),
        });
    }
    if cs.constraints != CONSTRUCTION_PARENT_RELATION_CONSTRAINTS {
        return Err(ConstructionParentWitnessBindingError::Constraints {
            step: step_number,
            expected: CONSTRUCTION_PARENT_RELATION_CONSTRAINTS,
            actual: cs.constraints,
        });
    }
    if outputs.len() != CONSTRUCTION_RECURRENCE_STATE_ARITY {
        return Err(ConstructionParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "output state arity",
        });
    }
    let values = outputs
        .into_iter()
        .map(|output| {
            output
                .get_value()
                .ok_or(ConstructionParentWitnessBindingError::Synthesis {
                    step: step_number,
                    stage: "missing output assignment",
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    values
        .try_into()
        .map_err(|_| ConstructionParentWitnessBindingError::Synthesis {
            step: step_number,
            stage: "output state arity",
        })
}

fn recurrence_state_from_fields(
    fields: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    expected_index: u32,
) -> Result<ConstructionRecurrenceStateWitness, ConstructionParentWitnessBindingError> {
    let root_fields = fields[..CONSTRUCTION_ROOT_STATE_ARITY]
        .try_into()
        .map_err(|_| RelationError::Malformed("construction root state arity"))?;
    let root = ConstructionRoot::from_state_fields(root_fields)?;
    let manifest_field = fields[CONSTRUCTION_ROOT_STATE_ARITY];
    let mut manifest = scalar_to_canonical(&manifest_field);
    manifest.reverse();
    if fields[CONSTRUCTION_ROOT_STATE_ARITY + 1] != Scalar::from(u64::from(expected_index)) {
        return Err(ConstructionParentWitnessBindingError::RecurrenceIndex {
            expected: expected_index,
        });
    }
    Ok(ConstructionRecurrenceStateWitness {
        root: root.claim(),
        manifest,
        index: expected_index,
    })
}

fn construction_root_from_claim(
    root: &CandidateRootClaim,
) -> Result<ConstructionRoot, ConstructionParentWitnessBindingError> {
    if root.factors.len() != CONSTRUCTION_ROOT_ROUNDS {
        return Err(RelationError::Malformed("construction recurrence root factors").into());
    }
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&root.point.encoded);
    encoded[33..65].copy_from_slice(&root.scale.bytes);
    for (index, factor) in root.factors.iter().enumerate() {
        let offset = 65 + 32 * index;
        encoded[offset..offset + 32].copy_from_slice(&factor.bytes);
    }
    Ok(ConstructionRoot::parse(&encoded)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted_fixture() -> ConstructionParentProverFixture {
        ConstructionParentProverFixture::parse(include_bytes!(
            "../../../tests/vectors/construction_parent_sha256_accepted.wit3"
        ))
        .expect("parse accepted construction parent witness")
    }

    #[test]
    fn checking_witness_cs_reports_a_false_equation() {
        let mut cs = CheckingWitnessCs::with_auxiliary_capacity(1);
        let value = AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Scalar::from(2u64)))
            .expect("value");
        cs.enforce(
            || "false equation",
            |linear| linear + value.get_variable(),
            |linear| linear + CheckingWitnessCs::one(),
            |linear| linear + CheckingWitnessCs::one(),
        );
        assert_eq!(cs.first_unsatisfied, Some(0));
    }

    #[test]
    fn binding_rejects_a_missing_ordered_step_before_synthesis() {
        let mut fixture = accepted_fixture();
        let expected = fixture.inputs.step_count();
        fixture.leaves.pop().expect("accepted witness has leaves");
        assert_eq!(
            fixture.bind().err().expect("missing step rejects"),
            ConstructionParentWitnessBindingError::StepCount {
                expected,
                actual: expected - 1,
            }
        );
    }

    #[test]
    fn recurrence_state_rejects_a_mismatched_index() {
        let fixture = accepted_fixture();
        let mut fields = *fixture.inputs.initial_state();
        fields[CONSTRUCTION_ROOT_STATE_ARITY + 1] = Scalar::ONE;
        assert_eq!(
            recurrence_state_from_fields(fields, 0)
                .err()
                .expect("mismatched index rejects"),
            ConstructionParentWitnessBindingError::RecurrenceIndex { expected: 0 }
        );
    }
}
