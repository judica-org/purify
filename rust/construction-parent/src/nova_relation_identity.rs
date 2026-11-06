//! Allocation-bounded identity for direct Nova step relations.
//!
//! This hashes the exact frontend constraint stream and the ordered state
//! variables returned by a [`StepCircuit`]. It never retains the matrix or
//! evaluates witness closures.

use ff::Field;
use nova_snark::{
    frontend::{
        gadgets::num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError,
        Variable,
    },
    traits::circuit::StepCircuit,
};
use sha2::{Digest, Sha256};

use crate::{
    nova_types::{DirectRelationId, DIRECT_STEP_RELATION_ENCODING_VERSION},
    scalar_to_canonical, Scalar,
};

const DIRECT_STEP_RELATION_DOMAIN: &[u8] = b"Purify/Receipt/DirectNovaStepRelation/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectStepRelationShape {
    relation_id: DirectRelationId,
    inputs: usize,
    auxiliary: usize,
    constraints: usize,
}

impl DirectStepRelationShape {
    pub(crate) const fn relation_id(self) -> DirectRelationId {
        self.relation_id
    }

    pub(crate) const fn inputs(self) -> usize {
        self.inputs
    }

    pub(crate) const fn auxiliary(self) -> usize {
        self.auxiliary
    }

    pub(crate) const fn constraints(self) -> usize {
        self.constraints
    }
}

struct RelationIdentityCS {
    digest: Sha256,
    inputs: usize,
    auxiliary: usize,
    constraints: usize,
}

impl RelationIdentityCS {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(DIRECT_STEP_RELATION_DOMAIN);
        digest.update([DIRECT_STEP_RELATION_ENCODING_VERSION]);
        Self {
            digest,
            inputs: 1,
            auxiliary: 0,
            constraints: 0,
        }
    }

    fn hash_usize(&mut self, value: usize) {
        self.digest.update(
            u64::try_from(value)
                .expect("relation dimensions fit in u64")
                .to_le_bytes(),
        );
    }

    fn hash_variable(&mut self, variable: Variable) {
        let (kind, index) = match variable.get_unchecked() {
            Index::Input(index) => (0u8, index),
            Index::Aux(index) => (1u8, index),
        };
        self.digest.update([kind]);
        self.hash_usize(index);
    }

    fn hash_linear_combination(&mut self, tag: u8, linear: &LinearCombination<Scalar>) {
        self.digest.update([tag]);
        self.hash_usize(
            linear
                .iter()
                .filter(|(_, coefficient)| **coefficient != Scalar::ZERO)
                .count(),
        );
        for (variable, coefficient) in linear
            .iter()
            .filter(|(_, coefficient)| **coefficient != Scalar::ZERO)
        {
            self.hash_variable(variable);
            self.digest.update(scalar_to_canonical(coefficient));
        }
    }

    fn variable_is_allocated(&self, variable: Variable) -> bool {
        match variable.get_unchecked() {
            Index::Input(index) => index < self.inputs,
            Index::Aux(index) => index < self.auxiliary,
        }
    }

    fn finish<const ARITY: usize>(
        mut self,
        inputs: &[AllocatedNum<Scalar>],
        outputs: &[AllocatedNum<Scalar>],
    ) -> Result<DirectStepRelationShape, SynthesisError> {
        if inputs.len() != ARITY || self.inputs != ARITY + 1 || outputs.len() != ARITY {
            return Err(synthesis_error("direct step state shape"));
        }
        if inputs
            .iter()
            .chain(outputs)
            .any(|value| !self.variable_is_allocated(value.get_variable()))
        {
            return Err(synthesis_error("direct step state variable"));
        }

        self.digest.update([0xff]);
        self.hash_usize(self.inputs);
        self.hash_usize(self.auxiliary);
        self.hash_usize(self.constraints);
        self.hash_usize(ARITY);
        for input in inputs {
            self.hash_variable(input.get_variable());
        }
        self.hash_usize(outputs.len());
        for output in outputs {
            self.hash_variable(output.get_variable());
        }

        Ok(DirectStepRelationShape {
            relation_id: DirectRelationId::from_frozen_bytes(self.digest.finalize().into()),
            inputs: self.inputs,
            auxiliary: self.auxiliary,
            constraints: self.constraints,
        })
    }
}

impl ConstraintSystem<Scalar> for RelationIdentityCS {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, _value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.auxiliary;
        self.auxiliary = self
            .auxiliary
            .checked_add(1)
            .expect("relation auxiliary count");
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _annotation: A,
        _value: F,
    ) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.inputs;
        self.inputs = self.inputs.checked_add(1).expect("relation input count");
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
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());
        self.digest.update([0x01]);
        self.hash_usize(self.constraints);
        self.hash_linear_combination(0, &a);
        self.hash_linear_combination(1, &b);
        self.hash_linear_combination(2, &c);
        self.constraints = self
            .constraints
            .checked_add(1)
            .expect("relation constraint count");
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

pub(crate) fn direct_step_relation_shape<const ARITY: usize, C: StepCircuit<Scalar>>(
    circuit: &C,
) -> Result<DirectStepRelationShape, SynthesisError> {
    if circuit.arity() != ARITY {
        return Err(synthesis_error("direct step arity"));
    }
    let mut cs = RelationIdentityCS::new();
    let inputs = (0..ARITY)
        .map(|index| {
            AllocatedNum::alloc_input(cs.namespace(|| format!("state {index}")), || {
                Err(SynthesisError::AssignmentMissing)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = circuit.synthesize(&mut cs, &inputs)?;
    cs.finish::<ARITY>(&inputs, &outputs)
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

#[cfg(test)]
mod tests {
    use nova_snark::{
        frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
        traits::circuit::StepCircuit,
    };

    use super::*;

    #[derive(Clone, Copy)]
    struct OrderedOutputs {
        reverse: bool,
    }

    #[derive(Clone, Copy)]
    enum IgnoredWitness {
        Value(Scalar),
        Panic,
    }

    #[derive(Clone, Copy)]
    struct TinyRelationStep {
        constant: Scalar,
        ignored: IgnoredWitness,
    }

    impl StepCircuit<Scalar> for TinyRelationStep {
        fn arity(&self) -> usize {
            1
        }

        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            cs: &mut CS,
            z: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            if z.len() != 1 {
                return Err(synthesis_error("tiny relation state arity"));
            }
            let ignored = self.ignored;
            let _ = cs.alloc(
                || "ignored witness",
                move || match ignored {
                    IgnoredWitness::Value(value) => Ok(value),
                    IgnoredWitness::Panic => panic!("witness closure was evaluated"),
                },
            )?;
            let constant = self.constant;
            let output = AllocatedNum::alloc(cs.namespace(|| "output"), || {
                z[0].get_value()
                    .map(|value| value + constant)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            cs.enforce(
                || "affine output",
                |linear| linear + z[0].get_variable() + (constant, CS::one()),
                |linear| linear + CS::one(),
                |linear| linear + output.get_variable(),
            );
            Ok(vec![output])
        }
    }

    impl StepCircuit<Scalar> for OrderedOutputs {
        fn arity(&self) -> usize {
            2
        }

        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            _cs: &mut CS,
            z: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            if z.len() != 2 {
                return Err(synthesis_error("ordered output arity"));
            }
            Ok(if self.reverse {
                vec![z[1].clone(), z[0].clone()]
            } else {
                z.to_vec()
            })
        }
    }

    #[test]
    fn relation_identity_ignores_witnesses_and_pins_counts() {
        let first = direct_step_relation_shape::<1, _>(&TinyRelationStep {
            constant: Scalar::from(17),
            ignored: IgnoredWitness::Panic,
        })
        .expect("first tiny relation");
        let second = direct_step_relation_shape::<1, _>(&TinyRelationStep {
            constant: Scalar::from(17),
            ignored: IgnoredWitness::Value(Scalar::from(42)),
        })
        .expect("second tiny relation");
        assert_eq!(first, second);
        assert_eq!(first.inputs(), 2);
        assert_eq!(first.auxiliary(), 2);
        assert_eq!(first.constraints(), 1);
        assert!(std::mem::size_of::<RelationIdentityCS>() < 256);
    }

    #[test]
    fn relation_identity_binds_matrix_constants() {
        let first = direct_step_relation_shape::<1, _>(&TinyRelationStep {
            constant: Scalar::from(17),
            ignored: IgnoredWitness::Panic,
        })
        .expect("first tiny relation");
        let changed = direct_step_relation_shape::<1, _>(&TinyRelationStep {
            constant: Scalar::from(18),
            ignored: IgnoredWitness::Panic,
        })
        .expect("changed tiny relation");
        assert_ne!(first.relation_id(), changed.relation_id());
        assert_eq!(first.inputs(), changed.inputs());
        assert_eq!(first.auxiliary(), changed.auxiliary());
        assert_eq!(first.constraints(), changed.constraints());
    }

    #[test]
    fn relation_identity_binds_output_order() {
        let ordered = direct_step_relation_shape::<2, _>(&OrderedOutputs { reverse: false })
            .expect("ordered relation");
        let reversed = direct_step_relation_shape::<2, _>(&OrderedOutputs { reverse: true })
            .expect("reversed relation");
        assert_ne!(ordered.relation_id(), reversed.relation_id());
        assert_eq!(ordered.inputs(), reversed.inputs());
        assert_eq!(ordered.auxiliary(), reversed.auxiliary());
        assert_eq!(ordered.constraints(), reversed.constraints());
    }
}
