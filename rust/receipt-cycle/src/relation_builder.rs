//! Canonical circuit and assignment construction for parent relations.

use std::{collections::BTreeMap, sync::Arc};

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{
    Assignment, Circuit, ReceiptCycleError, Scalar, Term, WireKind, ASSIGNMENT_VERSION,
    CIRCUIT_VERSION,
};

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
    operations: Vec<GateOperationShape>,
    constraints: Vec<Vec<Term>>,
    expected: Option<ExpectedRelation>,
}

struct ExpectedRelation {
    shape: Arc<RelationShape>,
    next_operation: usize,
    next_constraint: usize,
    drift: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GateOperationShape {
    AllocatedValue {
        unit_constraint: usize,
    },
    Boolean {
        input_constraint: usize,
        output_constraint: usize,
    },
    Product {
        left_binding: usize,
        right_binding: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StateWire {
    pub(crate) kind: WireKind,
    pub(crate) index: usize,
}

#[derive(Clone)]
pub(crate) struct StateVariable {
    expression: Expression,
    wire: StateWire,
}

impl StateVariable {
    pub(crate) fn expression(&self) -> &Expression {
        &self.expression
    }
}

// The recursive backend consumes this transport in the next integration
// patch; the candidate recurrence is intentionally not an acceptance API.
#[allow(dead_code)]
pub(crate) struct RelationShape {
    pub(crate) circuit: Circuit,
    pub(crate) operations: Vec<GateOperationShape>,
    pub(crate) inputs: Vec<StateWire>,
    pub(crate) outputs: Vec<StateWire>,
}

#[allow(dead_code)]
pub(crate) struct StatefulRelation {
    pub(crate) shape: Arc<RelationShape>,
    pub(crate) assignment: Assignment,
}

impl Builder {
    #[cfg(test)]
    fn matching(shape: Arc<RelationShape>) -> Self {
        Self {
            expected: Some(ExpectedRelation {
                shape,
                next_operation: 0,
                next_constraint: 0,
                drift: None,
            }),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn gate_count(&self) -> usize {
        self.gates.len()
    }

    pub(crate) fn allocate(&mut self, value: Scalar) -> Expression {
        let operation = GateOperationShape::AllocatedValue {
            unit_constraint: self.constraint_count(),
        };
        let index = self.push_gate(value, Scalar::ONE, operation);
        self.constrain_zero(
            Expression::variable(WireKind::Right, index, Scalar::ONE)
                .sub(&Expression::constant(Scalar::ONE)),
        );
        Expression::variable(WireKind::Left, index, value)
    }

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

    pub(crate) fn expose_state(&mut self, value: &Expression) -> StateVariable {
        let state = self.allocate_state(value.value());
        self.constrain_equal(state.expression(), value);
        state
    }

    pub(crate) fn allocate_boolean(&mut self, value: bool) -> Expression {
        let value = if value { Scalar::ONE } else { Scalar::ZERO };
        let input_constraint = self.constraint_count();
        let operation = GateOperationShape::Boolean {
            input_constraint,
            output_constraint: input_constraint + 1,
        };
        let index = self.push_gate(value, value, operation);
        let left = Expression::variable(WireKind::Left, index, value);
        let right = Expression::variable(WireKind::Right, index, value);
        let output = Expression::variable(WireKind::Output, index, value);
        self.constrain_zero(left.clone().sub(&right));
        self.constrain_zero(output.sub(&left));
        Expression::variable(WireKind::Left, index, value)
    }

    pub(crate) fn multiply(&mut self, left: &Expression, right: &Expression) -> Expression {
        let left_binding = self.constraint_count();
        let right_binding = left_binding + 1;
        let operation = GateOperationShape::Product {
            left_binding,
            right_binding,
        };
        let index = self.push_gate(left.value, right.value, operation);
        let left_wire = Expression::variable(WireKind::Left, index, left.value);
        let right_wire = Expression::variable(WireKind::Right, index, right.value);
        self.constrain_zero(left_wire.sub(left));
        self.constrain_zero(right_wire.sub(right));
        Expression::variable(WireKind::Output, index, left.value * right.value)
    }

    pub(crate) fn constrain_zero(&mut self, expression: Expression) {
        if expression.constant != Scalar::ZERO || !expression.terms.is_empty() {
            if let Some(expected) = &mut self.expected {
                let matches = expected
                    .shape
                    .circuit
                    .constraints
                    .get(expected.next_constraint)
                    .is_some_and(|row| expression_matches_row(&expression, row));
                if !matches && expected.drift.is_none() {
                    expected.drift = Some("matching builder constraint drift");
                }
                expected.next_constraint += 1;
            } else {
                // Expressions use BTreeMap for convenient affine composition.
                // Store the canonical row immediately so every retained
                // constraint owns only its compact ordered terms.
                self.constraints.push(expression_terms(expression));
            }
        }
    }

    pub(crate) fn constrain_equal(&mut self, left: &Expression, right: &Expression) {
        self.constrain_zero(left.clone().sub(right));
    }

    fn push_gate(&mut self, left: Scalar, right: Scalar, operation: GateOperationShape) -> usize {
        let index = self.gates.len();
        self.gates.push((left, right));
        if let Some(expected) = &mut self.expected {
            if expected.shape.operations.get(expected.next_operation) != Some(&operation)
                && expected.drift.is_none()
            {
                expected.drift = Some("matching builder operation drift");
            }
            expected.next_operation += 1;
        } else {
            self.operations.push(operation);
        }
        index
    }

    fn constraint_count(&self) -> usize {
        self.expected
            .as_ref()
            .map_or(self.constraints.len(), |expected| expected.next_constraint)
    }

    pub(crate) fn finish(self) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let (circuit, assignment, _) = self.finish_structured()?;
        Ok((encode_circuit(&circuit), encode_assignment(&assignment)))
    }

    fn finish_structured(
        self,
    ) -> Result<(Circuit, Assignment, Vec<GateOperationShape>), ReceiptCycleError> {
        if self.expected.is_some() {
            return Err(ReceiptCycleError::Malformed(
                "matching builder requires stateful finish",
            ));
        }
        let circuit = Circuit {
            gate_count: self.gates.len(),
            constraints: self.constraints,
        };
        validate_operations(&self.operations, &circuit)?;
        let assignment = Assignment { gates: self.gates };
        Ok((circuit, assignment, self.operations))
    }

    pub(crate) fn finish_stateful(
        mut self,
        inputs: &[StateVariable],
        outputs: &[StateVariable],
    ) -> Result<StatefulRelation, ReceiptCycleError> {
        if inputs.is_empty() || inputs.len() != outputs.len() {
            return Err(ReceiptCycleError::Malformed("state variable shape"));
        }
        let input_wires = inputs.iter().map(|state| state.wire).collect();
        let output_wires = outputs.iter().map(|state| state.wire).collect();
        if let Some(expected) = self.expected.take() {
            if let Some(drift) = expected.drift {
                return Err(ReceiptCycleError::Malformed(drift));
            }
            if self.gates.len() != expected.shape.circuit.gate_count
                || expected.next_operation != expected.shape.operations.len()
            {
                return Err(ReceiptCycleError::Malformed(
                    "matching builder operation drift",
                ));
            }
            if expected.next_constraint != expected.shape.circuit.constraints.len() {
                return Err(ReceiptCycleError::Malformed(
                    "matching builder constraint drift",
                ));
            }
            if input_wires != expected.shape.inputs || output_wires != expected.shape.outputs {
                return Err(ReceiptCycleError::Malformed("matching builder state drift"));
            }
            return Ok(StatefulRelation {
                shape: expected.shape,
                assignment: Assignment { gates: self.gates },
            });
        }
        let (circuit, assignment, operations) = self.finish_structured()?;
        Ok(StatefulRelation {
            shape: Arc::new(RelationShape {
                circuit,
                operations,
                inputs: input_wires,
                outputs: output_wires,
            }),
            assignment,
        })
    }
}

pub(crate) fn validate_operations(
    operations: &[GateOperationShape],
    circuit: &Circuit,
) -> Result<(), ReceiptCycleError> {
    if operations.len() != circuit.gate_count {
        return Err(ReceiptCycleError::Malformed("builder operation count"));
    }
    let mut previous_constraint = None;
    for (gate_index, operation) in operations.iter().enumerate() {
        match operation {
            GateOperationShape::AllocatedValue { unit_constraint } => {
                validate_operation_indices(
                    circuit,
                    &mut previous_constraint,
                    *unit_constraint,
                    None,
                )?;
                validate_exact_constraint(
                    circuit,
                    *unit_constraint,
                    &[
                        (WireKind::One, 0, -Scalar::ONE),
                        (WireKind::Right, gate_index, Scalar::ONE),
                    ],
                )?;
            }
            GateOperationShape::Boolean {
                input_constraint,
                output_constraint,
            } => {
                validate_operation_indices(
                    circuit,
                    &mut previous_constraint,
                    *input_constraint,
                    Some(*output_constraint),
                )?;
                validate_exact_constraint(
                    circuit,
                    *input_constraint,
                    &[
                        (WireKind::Left, gate_index, Scalar::ONE),
                        (WireKind::Right, gate_index, -Scalar::ONE),
                    ],
                )?;
                validate_exact_constraint(
                    circuit,
                    *output_constraint,
                    &[
                        (WireKind::Left, gate_index, -Scalar::ONE),
                        (WireKind::Output, gate_index, Scalar::ONE),
                    ],
                )?;
            }
            GateOperationShape::Product {
                left_binding,
                right_binding,
            } => {
                validate_operation_indices(
                    circuit,
                    &mut previous_constraint,
                    *left_binding,
                    Some(*right_binding),
                )?;
                validate_binding_constraint(circuit, *left_binding, gate_index, WireKind::Left)?;
                validate_binding_constraint(circuit, *right_binding, gate_index, WireKind::Right)?;
            }
        }
    }
    Ok(())
}

fn validate_operation_indices(
    circuit: &Circuit,
    previous_constraint: &mut Option<usize>,
    first: usize,
    second: Option<usize>,
) -> Result<(), ReceiptCycleError> {
    let last = second.unwrap_or(first);
    if second.is_some_and(|second| first.checked_add(1) != Some(second))
        || (*previous_constraint).is_some_and(|previous| previous >= first)
    {
        return Err(ReceiptCycleError::Malformed(
            "builder operation constraint order",
        ));
    }
    if last >= circuit.constraints.len() {
        return Err(ReceiptCycleError::Malformed(
            "builder operation constraint index",
        ));
    }
    *previous_constraint = Some(last);
    Ok(())
}

fn validate_exact_constraint(
    circuit: &Circuit,
    constraint_index: usize,
    expected: &[(WireKind, usize, Scalar)],
) -> Result<(), ReceiptCycleError> {
    let constraint =
        circuit
            .constraints
            .get(constraint_index)
            .ok_or(ReceiptCycleError::Malformed(
                "builder operation constraint index",
            ))?;
    if constraint.len() != expected.len()
        || constraint
            .iter()
            .zip(expected)
            .any(|(term, &(kind, index, coefficient))| {
                term.kind != kind || term.index != index || term.coefficient != coefficient
            })
    {
        return Err(ReceiptCycleError::Malformed("builder operation constraint"));
    }
    Ok(())
}

fn validate_binding_constraint(
    circuit: &Circuit,
    constraint_index: usize,
    gate_index: usize,
    bound_kind: WireKind,
) -> Result<(), ReceiptCycleError> {
    let constraint =
        circuit
            .constraints
            .get(constraint_index)
            .ok_or(ReceiptCycleError::Malformed(
                "builder operation binding index",
            ))?;
    let mut previous = None;
    let mut found_binding = false;
    for term in constraint {
        let key = (term.kind, term.index);
        if term.coefficient == Scalar::ZERO || previous.is_some_and(|prior| prior >= key) {
            return Err(ReceiptCycleError::Malformed("builder operation wire"));
        }
        if term.kind == WireKind::One {
            if term.index != 0 {
                return Err(ReceiptCycleError::Malformed("builder operation wire"));
            }
        } else if term.kind == bound_kind && term.index == gate_index {
            if term.coefficient != Scalar::ONE || found_binding {
                return Err(ReceiptCycleError::Malformed("builder operation binding"));
            }
            found_binding = true;
        } else if term.index >= gate_index {
            return Err(ReceiptCycleError::Malformed("builder operation wire"));
        }
        previous = Some(key);
    }
    if !found_binding {
        return Err(ReceiptCycleError::Malformed("builder operation binding"));
    }
    Ok(())
}

fn expression_terms(expression: Expression) -> Vec<Term> {
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
    assert!(!out.is_empty());
    out
}

fn expression_matches_row(expression: &Expression, row: &[Term]) -> bool {
    let mut expected = row.iter();
    if expression.constant != Scalar::ZERO
        && !expected.next().is_some_and(|term| {
            term.kind == WireKind::One && term.index == 0 && term.coefficient == expression.constant
        })
    {
        return false;
    }
    for (&(kind, index), &coefficient) in &expression.terms {
        if !expected.next().is_some_and(|term| {
            term.kind == kind && term.index == index && term.coefficient == coefficient
        }) {
            return false;
        }
    }
    expected.next().is_none()
}

fn append_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

fn append_scalar(out: &mut Vec<u8>, value: Scalar) {
    out.extend_from_slice(&Secq256k1Cycle::scalar_to_canonical(&value));
}

pub(crate) fn emit_circuit(circuit: &Circuit, mut emit: impl FnMut(&[u8])) {
    emit(&[CIRCUIT_VERSION]);
    emit(&(circuit.gate_count as u32).to_le_bytes());
    emit(&(circuit.constraints.len() as u32).to_le_bytes());
    for constraint in &circuit.constraints {
        emit(&(constraint.len() as u32).to_le_bytes());
        for term in constraint {
            emit(&[term.kind as u8]);
            emit(&(term.index as u32).to_le_bytes());
            emit(&Secq256k1Cycle::scalar_to_canonical(&term.coefficient));
        }
    }
}

fn encode_circuit(circuit: &Circuit) -> Vec<u8> {
    let mut out = Vec::new();
    emit_circuit(circuit, |bytes| out.extend_from_slice(bytes));
    out
}

#[cfg(test)]
pub(crate) fn circuit_digest(circuit: &Circuit) -> [u8; 32] {
    let mut digest = Sha256::new();
    emit_circuit(circuit, |bytes| digest.update(bytes));
    digest.finalize().into()
}

fn encode_assignment(assignment: &Assignment) -> Vec<u8> {
    let mut out = vec![ASSIGNMENT_VERSION];
    append_u32(&mut out, assignment.gates.len());
    for &(left, right) in &assignment.gates {
        append_scalar(&mut out, left);
        append_scalar(&mut out, right);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_term_mut(row: &mut [Term], kind: WireKind, index: usize) -> &mut Term {
        row.iter_mut()
            .find(|term| term.kind == kind && term.index == index)
            .expect("constraint term")
    }

    fn product_relation(
        input_value: u64,
        swap_operands: bool,
    ) -> (Builder, [StateVariable; 1], [StateVariable; 1]) {
        product_relation_with_builder(Builder::default(), input_value, swap_operands)
    }

    fn product_relation_with_builder(
        mut builder: Builder,
        input_value: u64,
        swap_operands: bool,
    ) -> (Builder, [StateVariable; 1], [StateVariable; 1]) {
        let input = builder.allocate_state(Scalar::from(input_value));
        let constant = Expression::constant(Scalar::from(4));
        let product = if swap_operands {
            builder.multiply(&constant, input.expression())
        } else {
            builder.multiply(input.expression(), &constant)
        };
        let output = builder.expose_state(&product);
        (builder, [input], [output])
    }

    fn finish_product(input_value: u64, swap_operands: bool) -> StatefulRelation {
        let (builder, inputs, outputs) = product_relation(input_value, swap_operands);
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("stateful relation")
    }

    fn boolean_relation(value: bool) -> (Builder, [StateVariable; 1], [StateVariable; 1]) {
        boolean_relation_with_builder(Builder::default(), value)
    }

    fn boolean_relation_with_builder(
        mut builder: Builder,
        value: bool,
    ) -> (Builder, [StateVariable; 1], [StateVariable; 1]) {
        let input = builder.allocate_state(Scalar::from(3));
        let _boolean = builder.allocate_boolean(value);
        let output = builder.expose_state(input.expression());
        (builder, [input], [output])
    }

    fn finish_boolean(value: bool) -> StatefulRelation {
        let (builder, inputs, outputs) = boolean_relation(value);
        builder
            .finish_stateful(&inputs, &outputs)
            .expect("stateful relation")
    }

    fn representative_relation(input_value: u64, condition: bool) -> StatefulRelation {
        let mut builder = Builder::default();
        let input = builder.allocate_state(Scalar::from(input_value));
        let condition = builder.allocate_boolean(condition);
        let affine = input
            .expression()
            .clone()
            .scale(Scalar::from(2))
            .add(&Expression::constant(Scalar::from(5)));
        let product = builder.multiply(&affine, &condition);
        let output = builder.expose_state(&product);
        builder
            .finish_stateful(&[input], &[output])
            .expect("representative relation")
    }

    fn term(kind: WireKind, index: usize, coefficient: Scalar) -> Term {
        Term {
            kind,
            index,
            coefficient,
        }
    }

    fn legacy_representative_rows() -> Vec<Vec<Term>> {
        vec![
            vec![
                term(WireKind::One, 0, -Scalar::ONE),
                term(WireKind::Right, 0, Scalar::ONE),
            ],
            vec![
                term(WireKind::Left, 1, Scalar::ONE),
                term(WireKind::Right, 1, -Scalar::ONE),
            ],
            vec![
                term(WireKind::Left, 1, -Scalar::ONE),
                term(WireKind::Output, 1, Scalar::ONE),
            ],
            vec![
                term(WireKind::One, 0, -Scalar::from(5)),
                term(WireKind::Left, 0, -Scalar::from(2)),
                term(WireKind::Left, 2, Scalar::ONE),
            ],
            vec![
                term(WireKind::Left, 1, -Scalar::ONE),
                term(WireKind::Right, 2, Scalar::ONE),
            ],
            vec![
                term(WireKind::One, 0, -Scalar::ONE),
                term(WireKind::Right, 3, Scalar::ONE),
            ],
            vec![
                term(WireKind::Left, 3, Scalar::ONE),
                term(WireKind::Output, 2, -Scalar::ONE),
            ],
        ]
    }

    #[test]
    fn stateful_finish_retains_the_canonical_relation() {
        let (builder, inputs, outputs) = product_relation(3, false);
        let input_wires = inputs.each_ref().map(|state| state.wire);
        let output_wires = outputs.each_ref().map(|state| state.wire);
        let relation = builder
            .finish_stateful(&inputs, &outputs)
            .expect("stateful relation");

        let (builder, _, _) = product_relation(3, false);
        let (circuit, assignment) = builder.finish().expect("canonical relation");
        assert_eq!(relation.shape.inputs, input_wires);
        assert_eq!(relation.shape.outputs, output_wires);
        assert_eq!(
            relation.shape.circuit,
            Circuit::parse(&circuit).expect("circuit")
        );
        assert_eq!(
            relation.assignment,
            Assignment::parse(&assignment).expect("assignment")
        );
        assert_eq!(encode_circuit(&relation.shape.circuit), circuit);
        assert_eq!(encode_assignment(&relation.assignment), assignment);
    }

    #[test]
    fn matching_builder_reuses_the_exact_shape_without_retaining_rows() {
        let original = finish_product(3, false);
        let expected = Arc::clone(&original.shape);
        let (builder, inputs, outputs) =
            product_relation_with_builder(Builder::matching(Arc::clone(&expected)), 9, false);
        assert!(builder.operations.is_empty());
        assert!(builder.constraints.is_empty());

        let matching = builder
            .finish_stateful(&inputs, &outputs)
            .expect("matching stateful relation");
        assert!(Arc::ptr_eq(&matching.shape, &expected));
        assert_eq!(matching.shape.circuit, original.shape.circuit);
        assert_eq!(matching.shape.operations, original.shape.operations);
        assert_ne!(matching.assignment, original.assignment);
    }

    #[test]
    fn matching_builder_rejects_exact_shape_drift() {
        let original = finish_product(3, false);

        let (changed_row, inputs, outputs) =
            product_relation_with_builder(Builder::matching(Arc::clone(&original.shape)), 9, true);
        assert!(matches!(
            changed_row.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed(
                "matching builder constraint drift"
            ))
        ));

        let (changed_operation, inputs, outputs) =
            boolean_relation_with_builder(Builder::matching(Arc::clone(&original.shape)), true);
        assert!(matches!(
            changed_operation.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed(
                "matching builder operation drift"
            ))
        ));

        let (changed_state, inputs, outputs) =
            product_relation_with_builder(Builder::matching(Arc::clone(&original.shape)), 9, false);
        assert!(matches!(
            changed_state.finish_stateful(&outputs, &inputs),
            Err(ReceiptCycleError::Malformed("matching builder state drift"))
        ));

        let (mut extra_operation, inputs, outputs) =
            product_relation_with_builder(Builder::matching(Arc::clone(&original.shape)), 9, false);
        let _extra = extra_operation.allocate(Scalar::ONE);
        assert!(matches!(
            extra_operation.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed(
                "matching builder operation drift"
            ))
        ));

        let (mut extra_row, inputs, outputs) =
            product_relation_with_builder(Builder::matching(Arc::clone(&original.shape)), 9, false);
        extra_row.constrain_zero(Expression::constant(Scalar::ONE));
        assert!(matches!(
            extra_row.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed(
                "matching builder constraint drift"
            ))
        ));

        let mut truncated = Builder::matching(Arc::clone(&original.shape));
        let input = truncated.allocate_state(Scalar::from(9));
        let output = input.clone();
        assert!(matches!(
            truncated.finish_stateful(&[input], &[output]),
            Err(ReceiptCycleError::Malformed(
                "matching builder operation drift"
            ))
        ));
    }

    #[test]
    fn eager_rows_preserve_legacy_canonical_encoding() {
        let relation = representative_relation(3, true);
        let legacy = Circuit {
            gate_count: 4,
            constraints: legacy_representative_rows(),
        };

        assert_eq!(relation.shape.circuit, legacy);
        assert_eq!(
            encode_circuit(&relation.shape.circuit),
            encode_circuit(&legacy)
        );
        assert_eq!(
            circuit_digest(&relation.shape.circuit),
            circuit_digest(&legacy)
        );

        let changed_witness = representative_relation(9, false);
        assert_eq!(changed_witness.shape.circuit, legacy);
        assert_eq!(
            circuit_digest(&changed_witness.shape.circuit),
            circuit_digest(&legacy)
        );
        assert_ne!(relation.assignment, changed_witness.assignment);
    }

    #[test]
    fn operation_shape_is_witness_independent() {
        let first = finish_product(3, false);
        let second = finish_product(9, false);

        assert_eq!(first.shape.operations, second.shape.operations);
        assert_eq!(first.shape.circuit, second.shape.circuit);
        assert_ne!(first.assignment, second.assignment);
        assert_eq!(
            encode_circuit(&first.shape.circuit),
            encode_circuit(&second.shape.circuit)
        );
        assert_ne!(
            encode_assignment(&first.assignment),
            encode_assignment(&second.assignment)
        );
        assert!(matches!(
            first.shape.operations.as_slice(),
            [
                GateOperationShape::AllocatedValue { unit_constraint: 0 },
                GateOperationShape::Product {
                    left_binding: 1,
                    right_binding: 2
                },
                GateOperationShape::AllocatedValue { unit_constraint: 3 }
            ]
        ));

        let true_relation = finish_boolean(true);
        let false_relation = finish_boolean(false);
        assert_eq!(
            true_relation.shape.operations,
            false_relation.shape.operations
        );
        assert_eq!(true_relation.shape.circuit, false_relation.shape.circuit);
        assert_ne!(true_relation.assignment, false_relation.assignment);
    }

    #[test]
    fn lowering_shape_binds_multiplication_structure() {
        let normal = finish_product(3, false);
        let swapped = finish_product(3, true);

        assert_eq!(
            normal.shape.operations.len(),
            swapped.shape.operations.len()
        );
        assert_eq!(normal.shape.operations, swapped.shape.operations);
        assert_ne!(normal.shape.circuit, swapped.shape.circuit);
    }

    #[test]
    fn stateful_finish_rejects_invalid_operation_metadata() {
        let (mut missing, inputs, outputs) = product_relation(3, false);
        missing.operations.pop();
        assert!(matches!(
            missing.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation count"))
        ));

        let (mut arbitrary, inputs, outputs) = product_relation(3, false);
        let GateOperationShape::Product {
            left_binding,
            right_binding,
        } = &mut arbitrary.operations[1]
        else {
            panic!("product operation");
        };
        *left_binding = 3;
        *right_binding = 4;
        assert!(matches!(
            arbitrary.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation wire"))
        ));

        let (mut wrong_coefficient, inputs, outputs) = product_relation(3, false);
        row_term_mut(&mut wrong_coefficient.constraints[1], WireKind::Left, 1).coefficient =
            Scalar::from(2);
        assert!(matches!(
            wrong_coefficient.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation binding"))
        ));

        let (mut non_prior, inputs, outputs) = product_relation(3, false);
        non_prior.constraints[1].push(Term {
            kind: WireKind::Right,
            index: 1,
            coefficient: Scalar::ONE,
        });
        non_prior.constraints[1].sort_by_key(|term| (term.kind, term.index));
        assert!(matches!(
            non_prior.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation wire"))
        ));
    }

    #[test]
    fn stateful_finish_rejects_changed_allocation_constraint() {
        let (mut builder, inputs, outputs) = product_relation(3, false);
        row_term_mut(&mut builder.constraints[0], WireKind::Right, 0).coefficient = Scalar::from(2);
        assert!(matches!(
            builder.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation constraint"))
        ));
    }

    #[test]
    fn stateful_finish_rejects_changed_boolean_constraint() {
        let (mut builder, inputs, outputs) = boolean_relation(true);
        row_term_mut(&mut builder.constraints[1], WireKind::Right, 1).coefficient = Scalar::ONE;
        assert!(matches!(
            builder.finish_stateful(&inputs, &outputs),
            Err(ReceiptCycleError::Malformed("builder operation constraint"))
        ));
    }
}
