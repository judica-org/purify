//! Canonical circuit and assignment construction for parent relations.

use std::collections::BTreeMap;

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;

use crate::{Assignment, Circuit, ReceiptCycleError, Scalar, Term, WireKind};

#[derive(Clone, Debug)]
pub(crate) struct Expression {
    constant: Scalar,
    terms: BTreeMap<(WireKind, usize), Scalar>,
    value: Scalar,
}

impl Expression {
    pub(crate) fn constant(value: Scalar) -> Self {
        Self {
            constant: value,
            terms: BTreeMap::new(),
            value,
        }
    }

    pub(crate) fn variable(kind: WireKind, index: usize, value: Scalar) -> Self {
        let mut terms = BTreeMap::new();
        terms.insert((kind, index), Scalar::ONE);
        Self {
            constant: Scalar::ZERO,
            terms,
            value,
        }
    }

    pub(crate) fn add(mut self, rhs: &Self) -> Self {
        self.constant += rhs.constant;
        self.value += rhs.value;
        for (&key, &coefficient) in &rhs.terms {
            self.add_term(key, coefficient);
        }
        self
    }

    pub(crate) fn sub(mut self, rhs: &Self) -> Self {
        self.constant -= rhs.constant;
        self.value -= rhs.value;
        for (&key, &coefficient) in &rhs.terms {
            self.add_term(key, -coefficient);
        }
        self
    }

    pub(crate) fn scale(mut self, scalar: Scalar) -> Self {
        self.constant *= scalar;
        self.value *= scalar;
        self.terms.retain(|_, coefficient| {
            *coefficient *= scalar;
            *coefficient != Scalar::ZERO
        });
        self
    }

    pub(crate) fn value(&self) -> Scalar {
        self.value
    }

    fn add_term(&mut self, key: (WireKind, usize), coefficient: Scalar) {
        let value = self.terms.entry(key).or_insert(Scalar::ZERO);
        *value += coefficient;
        if *value == Scalar::ZERO {
            self.terms.remove(&key);
        }
    }
}

#[derive(Default)]
pub(crate) struct Builder {
    gates: Vec<(Scalar, Scalar)>,
    constraints: Vec<Expression>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StateWire {
    pub(crate) kind: WireKind,
    pub(crate) index: usize,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct StateVariable {
    expression: Expression,
    wire: StateWire,
}

#[allow(dead_code)]
impl StateVariable {
    pub(crate) fn expression(&self) -> &Expression {
        &self.expression
    }
}

// The recursive backend consumes this transport in the next integration
// patch; the candidate recurrence is intentionally not an acceptance API.
#[allow(dead_code)]
pub(crate) struct StatefulRelation {
    pub(crate) circuit: Vec<u8>,
    pub(crate) assignment: Vec<u8>,
    pub(crate) inputs: Vec<StateWire>,
    pub(crate) outputs: Vec<StateWire>,
}

impl Builder {
    #[cfg(test)]
    pub(crate) fn gate_count(&self) -> usize {
        self.gates.len()
    }

    pub(crate) fn allocate(&mut self, value: Scalar) -> Expression {
        let index = self.gates.len();
        self.gates.push((value, Scalar::ONE));
        self.constrain_zero(
            Expression::variable(WireKind::Right, index, Scalar::ONE)
                .sub(&Expression::constant(Scalar::ONE)),
        );
        Expression::variable(WireKind::Left, index, value)
    }

    #[allow(dead_code)]
    pub(crate) fn allocate_state(&mut self, value: Scalar) -> StateVariable {
        let index = self.gates.len();
        let expression = self.allocate(value);
        StateVariable {
            expression,
            wire: StateWire {
                kind: WireKind::Left,
                index,
            },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn expose_state(&mut self, value: &Expression) -> StateVariable {
        let state = self.allocate_state(value.value());
        self.constrain_equal(state.expression(), value);
        state
    }

    pub(crate) fn allocate_boolean(&mut self, value: bool) -> Expression {
        let value = if value { Scalar::ONE } else { Scalar::ZERO };
        let index = self.gates.len();
        self.gates.push((value, value));
        let left = Expression::variable(WireKind::Left, index, value);
        let right = Expression::variable(WireKind::Right, index, value);
        let output = Expression::variable(WireKind::Output, index, value);
        self.constrain_zero(left.clone().sub(&right));
        self.constrain_zero(output.sub(&left));
        Expression::variable(WireKind::Left, index, value)
    }

    pub(crate) fn multiply(&mut self, left: &Expression, right: &Expression) -> Expression {
        let index = self.gates.len();
        self.gates.push((left.value, right.value));
        let left_wire = Expression::variable(WireKind::Left, index, left.value);
        let right_wire = Expression::variable(WireKind::Right, index, right.value);
        self.constrain_zero(left_wire.sub(left));
        self.constrain_zero(right_wire.sub(right));
        Expression::variable(WireKind::Output, index, left.value * right.value)
    }

    pub(crate) fn constrain_zero(&mut self, expression: Expression) {
        if expression.constant != Scalar::ZERO || !expression.terms.is_empty() {
            self.constraints.push(expression);
        }
    }

    pub(crate) fn constrain_equal(&mut self, left: &Expression, right: &Expression) {
        self.constrain_zero(left.clone().sub(right));
    }

    pub(crate) fn finish(self) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let circuit = Circuit {
            gate_count: self.gates.len(),
            constraints: self
                .constraints
                .into_iter()
                .map(expression_terms)
                .collect::<Result<_, _>>()?,
        };
        let assignment = Assignment { gates: self.gates };
        Ok((encode_circuit(&circuit), encode_assignment(&assignment)))
    }

    #[allow(dead_code)]
    pub(crate) fn finish_stateful(
        self,
        inputs: &[StateVariable],
        outputs: &[StateVariable],
    ) -> Result<StatefulRelation, ReceiptCycleError> {
        if inputs.is_empty() || inputs.len() != outputs.len() {
            return Err(ReceiptCycleError::Malformed("state variable shape"));
        }
        let input_wires = inputs.iter().map(|state| state.wire).collect();
        let output_wires = outputs.iter().map(|state| state.wire).collect();
        let (circuit, assignment) = self.finish()?;
        Ok(StatefulRelation {
            circuit,
            assignment,
            inputs: input_wires,
            outputs: output_wires,
        })
    }
}

fn expression_terms(expression: Expression) -> Result<Vec<Term>, ReceiptCycleError> {
    let mut out = Vec::with_capacity(expression.terms.len() + 1);
    if expression.constant != Scalar::ZERO {
        out.push(Term {
            kind: WireKind::One,
            index: 0,
            coefficient: expression.constant,
        });
    }
    for ((kind, index), coefficient) in expression.terms {
        out.push(Term {
            kind,
            index,
            coefficient,
        });
    }
    if out.is_empty() {
        return Err(ReceiptCycleError::Malformed("empty built constraint"));
    }
    Ok(out)
}

fn append_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

fn append_scalar(out: &mut Vec<u8>, value: Scalar) {
    out.extend_from_slice(&Secq256k1Cycle::scalar_to_canonical(&value));
}

fn encode_circuit(circuit: &Circuit) -> Vec<u8> {
    let mut out = vec![1];
    append_u32(&mut out, circuit.gate_count);
    append_u32(&mut out, circuit.constraints.len());
    for constraint in &circuit.constraints {
        append_u32(&mut out, constraint.len());
        for term in constraint {
            out.push(term.kind as u8);
            append_u32(&mut out, term.index);
            append_scalar(&mut out, term.coefficient);
        }
    }
    out
}

fn encode_assignment(assignment: &Assignment) -> Vec<u8> {
    let mut out = vec![1];
    append_u32(&mut out, assignment.gates.len());
    for &(left, right) in &assignment.gates {
        append_scalar(&mut out, left);
        append_scalar(&mut out, right);
    }
    out
}
