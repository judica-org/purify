//! Allocation-light Nova lowering for canonical Builder relations.
//!
//! Builder multiplication gates contain three source wires, but their
//! operation metadata proves that only one logical value must remain after
//! eliminating the operation-owned alias rows. This module performs that
//! elimination directly and allocates one Nova variable per Builder gate.
//! It is an internal candidate component, not a receipt acceptance API.

use std::sync::Arc;

use bulletproofs_cycle::Cycle;
use ff::{Field, PrimeField};
use golden_halo2curves::Secq256k1Cycle;
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError},
    provider::{Secp256k1Sha256Engine, Secq256k1Sha256Engine},
    traits::{circuit::StepCircuit, Engine},
};
use sha2::{Digest, Sha256};

use crate::{
    anchor_recurrence::ANCHOR_RECURRENCE_STATE_ARITY,
    relation_builder::{
        emit_circuit, validate_operations, Builder, GateOperationShape, RelationShape, StateWire,
        StatefulRelation,
    },
    Assignment, Circuit, ReceiptCycleError, Scalar, Term, WireKind,
};

const RELATION_ID_DOMAIN: &[u8] = b"Purify/Receipt/DirectNovaRelation/v1";
pub(crate) const DIRECT_RELATION_ENCODING_VERSION: u8 = 1;
pub(crate) const DIRECT_LOWERING_VERSION: u8 = 1;

// These limits apply only to internally constructed structured relations.
// They do not widen the generic proof/C-ABI parser's untrusted input bounds.
const DIRECT_NOVA_MAX_SOURCE_GATES: usize = 1 << 24;
const DIRECT_NOVA_MAX_SOURCE_CONSTRAINTS: usize = 1 << 25;
const DIRECT_NOVA_MAX_SOURCE_TERMS: usize = 1 << 26;

pub(crate) type DirectNovaPrimaryEngine = Secq256k1Sha256Engine;
pub(crate) type DirectNovaSecondaryEngine = Secp256k1Sha256Engine;
pub(crate) type DirectNovaScalar = <DirectNovaPrimaryEngine as Engine>::Scalar;
pub(crate) type AnchorDirectNovaTemplate = DirectNovaTemplate<ANCHOR_RECURRENCE_STATE_ARITY>;
pub(crate) type AnchorDirectNovaStep = DirectNovaStep<ANCHOR_RECURRENCE_STATE_ARITY>;
type NovaScalar = DirectNovaScalar;

/// Converts one complete source state into the primary Nova scalar field.
pub(crate) fn source_state_to_nova<const ARITY: usize>(
    source: [Scalar; ARITY],
) -> Result<[DirectNovaScalar; ARITY], ReceiptCycleError> {
    let mut state = [DirectNovaScalar::ZERO; ARITY];
    for (target, value) in state.iter_mut().zip(source) {
        *target = source_to_nova(value)?;
    }
    Ok(state)
}

/// Converts one complete primary Nova state back into the source field.
pub(crate) fn nova_state_to_source<const ARITY: usize>(
    state: [DirectNovaScalar; ARITY],
) -> Result<[Scalar; ARITY], ReceiptCycleError> {
    let mut source = [Scalar::ZERO; ARITY];
    for (target, value) in source.iter_mut().zip(state) {
        *target = nova_to_source(value)?;
    }
    Ok(source)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectRelationId([u8; 32]);

impl DirectRelationId {
    /// This identifies only the source relation and direct lowering. A future
    /// suite ID must additionally bind Nova, both engines, public parameters,
    /// compression, and the canonical proof codec.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstructs an ID only from a locally frozen suite profile.
    pub(crate) const fn from_frozen_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectNovaRawMetrics {
    pub(crate) relation_id: DirectRelationId,
    pub(crate) source_gates: usize,
    pub(crate) source_constraints: usize,
    pub(crate) source_terms: usize,
    pub(crate) allocated_operations: usize,
    pub(crate) boolean_operations: usize,
    pub(crate) product_operations: usize,
    pub(crate) semantic_constraints: usize,
    /// Auxiliary variables contributed by the direct step circuit. This does
    /// not include Nova's augmented-circuit variables.
    pub(crate) direct_variables: usize,
    /// Constraints contributed by the direct step circuit. This does not
    /// include Nova's augmented-circuit constraints.
    pub(crate) direct_constraints: usize,
    /// An upper bound before coefficient coalescing in Nova's matrices.
    pub(crate) direct_nnz_upper_bound: usize,
    /// The raw step bucket, before Nova's augmented-circuit overhead.
    pub(crate) direct_power_of_two_bucket: usize,
    /// Capacity left in the raw bucket before augmented-circuit overhead.
    pub(crate) direct_bucket_headroom: usize,
    pub(crate) direct_rounds: u32,
}

struct DirectNovaShape<const ARITY: usize> {
    gate_kinds: Box<[DirectGateKind]>,
    product_bindings: CompiledRows,
    semantic_rows: CompiledRows,
    inputs: [u32; ARITY],
    outputs: [u32; ARITY],
    relation_id: DirectRelationId,
}

pub(crate) struct DirectNovaTemplate<const ARITY: usize> {
    source: Arc<RelationShape>,
    shape: Arc<DirectNovaShape<ARITY>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum DirectGateKind {
    AllocatedValue,
    Boolean,
    Product,
}

/// Compact structure-of-arrays storage for already lowered linear rows.
///
/// Offsets and variable indices are bounded by the canonical relation limits,
/// so fixed-width indices avoid retaining millions of host-sized values. The
/// distinguished maximum index addresses the constraint system's constant
/// wire; every ordinary value is one direct gate index.
struct CompiledRows {
    offsets: Box<[u32]>,
    variables: Box<[u32]>,
    coefficients: Box<[NovaScalar]>,
}

const DIRECT_CONSTANT_INDEX: u32 = u32::MAX;

#[derive(Clone)]
pub(crate) struct DirectNovaStep<const ARITY: usize> {
    shape: Arc<DirectNovaShape<ARITY>>,
    gate_values: Arc<[NovaScalar]>,
    input_state: [NovaScalar; ARITY],
    output_state: [NovaScalar; ARITY],
}

impl<const ARITY: usize> DirectNovaStep<ARITY> {
    #[cfg(test)]
    pub(crate) fn from_relation(relation: StatefulRelation) -> Result<Self, ReceiptCycleError> {
        let (_, step) = DirectNovaTemplate::from_relation(relation)?;
        Ok(step)
    }

    pub(crate) fn relation_id(&self) -> DirectRelationId {
        self.shape.relation_id
    }

    pub(crate) fn input_state(&self) -> &[NovaScalar; ARITY] {
        &self.input_state
    }

    pub(crate) fn output_state(&self) -> &[NovaScalar; ARITY] {
        &self.output_state
    }
}

impl<const ARITY: usize> DirectNovaTemplate<ARITY> {
    pub(crate) fn from_relation(
        relation: StatefulRelation,
    ) -> Result<(Self, DirectNovaStep<ARITY>), ReceiptCycleError> {
        let source = relation.shape;
        let shape = Arc::new(DirectNovaShape::compile(&source)?);
        let template = Self { source, shape };
        let step = template.bind_assignment(relation.assignment)?;
        Ok((template, step))
    }

    pub(crate) fn bind_relation(
        &self,
        relation: StatefulRelation,
    ) -> Result<DirectNovaStep<ARITY>, ReceiptCycleError> {
        let StatefulRelation { shape, assignment } = relation;
        // Pointer equality refers to the immutable source Arc already
        // validated by this template. It skips only the duplicate structural
        // comparison; bind_assignment still checks every witness constraint.
        if !Arc::ptr_eq(&shape, &self.source) {
            self.validate_source(&shape)?;
        }
        drop(shape);
        self.bind_assignment(assignment)
    }

    pub(crate) fn matching_builder(&self) -> Builder {
        Builder::matching(Arc::clone(&self.source))
    }

    fn validate_source(&self, candidate: &RelationShape) -> Result<(), ReceiptCycleError> {
        let trusted = &self.source;
        if candidate.circuit != trusted.circuit {
            return Err(ReceiptCycleError::Malformed("direct Nova circuit drift"));
        }
        if candidate.operations != trusted.operations {
            return Err(ReceiptCycleError::Malformed("direct Nova operation drift"));
        }
        if candidate.inputs != trusted.inputs || candidate.outputs != trusted.outputs {
            return Err(ReceiptCycleError::Malformed("direct Nova state drift"));
        }
        Ok(())
    }

    fn bind_assignment(
        &self,
        assignment: Assignment,
    ) -> Result<DirectNovaStep<ARITY>, ReceiptCycleError> {
        validate_assignment(&self.source.circuit, &assignment)?;
        let mut gate_values = Vec::with_capacity(self.source.circuit.gate_count);
        for (index, operation) in self.source.operations.iter().enumerate() {
            let &(left, right) = assignment
                .gates
                .get(index)
                .ok_or(ReceiptCycleError::AssignmentShape)?;
            let logical = match operation {
                GateOperationShape::Product { .. } => left * right,
                GateOperationShape::AllocatedValue { .. } | GateOperationShape::Boolean { .. } => {
                    left
                }
            };
            gate_values.push(source_to_nova(logical)?);
        }
        let input_state = state_values(&gate_values, &self.shape.inputs)?;
        let output_state = state_values(&gate_values, &self.shape.outputs)?;
        Ok(DirectNovaStep {
            shape: Arc::clone(&self.shape),
            gate_values: gate_values.into(),
            input_state,
            output_state,
        })
    }
}

impl<const ARITY: usize> DirectNovaShape<ARITY> {
    #[cfg(test)]
    fn from_parts(
        circuit: Circuit,
        operations: Vec<GateOperationShape>,
        inputs: Vec<StateWire>,
        outputs: Vec<StateWire>,
    ) -> Result<Self, ReceiptCycleError> {
        let source = RelationShape {
            circuit,
            operations,
            inputs,
            outputs,
        };
        Self::compile(&source)
    }

    fn compile(source: &RelationShape) -> Result<Self, ReceiptCycleError> {
        validate_direct_shape::<ARITY>(
            &source.circuit,
            &source.operations,
            &source.inputs,
            &source.outputs,
        )?;
        let relation_id = relation_id::<ARITY>(
            &source.circuit,
            &source.operations,
            &source.inputs,
            &source.outputs,
            DIRECT_LOWERING_VERSION,
        )?;
        let gate_kinds = source
            .operations
            .iter()
            .map(|operation| match operation {
                GateOperationShape::AllocatedValue { .. } => DirectGateKind::AllocatedValue,
                GateOperationShape::Boolean { .. } => DirectGateKind::Boolean,
                GateOperationShape::Product { .. } => DirectGateKind::Product,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let (product_rows, product_terms, semantic_rows, semantic_terms) =
            compact_row_counts(source)?;
        let mut product_bindings = CompiledRowsBuilder::new(product_rows, product_terms)?;
        for (gate_index, operation) in source.operations.iter().enumerate() {
            if let GateOperationShape::Product {
                left_binding,
                right_binding,
            } = operation
            {
                product_bindings.push_binding(source, *left_binding, gate_index, WireKind::Left)?;
                product_bindings.push_binding(
                    source,
                    *right_binding,
                    gate_index,
                    WireKind::Right,
                )?;
            }
        }
        let product_bindings = product_bindings.finish()?;

        let mut semantic = CompiledRowsBuilder::new(semantic_rows, semantic_terms)?;
        let mut operation_rows = OperationRows::new(&source.operations);
        let mut next_operation_row = operation_rows.next();
        for (row_index, row) in source.circuit.constraints.iter().enumerate() {
            if next_operation_row == Some(row_index) {
                next_operation_row = operation_rows.next();
                continue;
            }
            if next_operation_row.is_some_and(|owned| owned < row_index) {
                return Err(ReceiptCycleError::Malformed(
                    "direct Nova operation row order",
                ));
            }
            semantic.push_row(source, row, false)?;
        }
        if next_operation_row.is_some() {
            return Err(ReceiptCycleError::Malformed("direct Nova operation rows"));
        }
        let semantic_rows = semantic.finish()?;

        let inputs = compact_state_indices::<ARITY>(&source.inputs, "direct Nova input state")?;
        let outputs = compact_state_indices::<ARITY>(&source.outputs, "direct Nova output state")?;
        Ok(Self {
            gate_kinds,
            product_bindings,
            semantic_rows,
            inputs,
            outputs,
            relation_id,
        })
    }
}

impl<const ARITY: usize> StepCircuit<NovaScalar> for DirectNovaStep<ARITY> {
    fn arity(&self) -> usize {
        ARITY
    }

    fn synthesize<CS: ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<NovaScalar>],
    ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        if z.len() != ARITY || self.gate_values.len() != self.shape.gate_kinds.len() {
            return Err(synthesis_error("direct Nova state shape"));
        }

        // Nova uses a WitnessCS for every fold. It ignores constraints, so
        // retain only the small output set instead of one AllocatedNum per
        // gate while populating its assignment in the fixed gate order.
        if cs.is_witness_generator() {
            return self.synthesize_witness(cs);
        }

        let mut gates = Vec::with_capacity(self.gate_values.len());
        for &value in self.gate_values.iter() {
            let variable = cs.alloc(|| "direct gate", || Ok(value))?;
            gates.push(AllocatedNum::from_parts(variable, Some(value)));
        }

        let mut product_index = 0usize;
        for (gate_index, operation) in self.shape.gate_kinds.iter().enumerate() {
            let output = gates
                .get(gate_index)
                .ok_or_else(|| synthesis_error("direct Nova gate index"))?;
            match operation {
                DirectGateKind::AllocatedValue => {}
                DirectGateKind::Boolean => {
                    let variable = output.get_variable();
                    cs.enforce(
                        || "direct boolean",
                        |linear| linear + variable,
                        |linear| linear + variable,
                        |linear| linear + variable,
                    );
                }
                DirectGateKind::Product => {
                    let left_row = product_index
                        .checked_mul(2)
                        .ok_or_else(|| synthesis_error("direct Nova product row"))?;
                    let right_row = left_row
                        .checked_add(1)
                        .ok_or_else(|| synthesis_error("direct Nova product row"))?;
                    let left = self.shape.product_bindings.lower::<CS>(&gates, left_row)?;
                    let right = self.shape.product_bindings.lower::<CS>(&gates, right_row)?;
                    let variable = output.get_variable();
                    cs.enforce(
                        || "direct product",
                        |_| left,
                        |_| right,
                        |linear| linear + variable,
                    );
                    product_index = product_index
                        .checked_add(1)
                        .ok_or_else(|| synthesis_error("direct Nova product count"))?;
                }
            }
        }
        if product_index
            .checked_mul(2)
            .ok_or_else(|| synthesis_error("direct Nova product row"))?
            != self.shape.product_bindings.row_count()
        {
            return Err(synthesis_error("direct Nova product row count"));
        }

        for row_index in 0..self.shape.semantic_rows.row_count() {
            let semantic = self.shape.semantic_rows.lower::<CS>(&gates, row_index)?;
            cs.enforce(
                || "direct semantic",
                |_| semantic,
                |linear| linear + CS::one(),
                |linear| linear,
            );
        }

        for (&wire, state) in self.shape.inputs.iter().zip(z) {
            let wire =
                usize::try_from(wire).map_err(|_| synthesis_error("direct Nova input gate"))?;
            let gate = gates
                .get(wire)
                .ok_or_else(|| synthesis_error("direct Nova input gate"))?;
            let gate_variable = gate.get_variable();
            let state_variable = state.get_variable();
            cs.enforce(
                || "direct state input",
                |linear| linear + gate_variable,
                |linear| linear + CS::one(),
                |linear| linear + state_variable,
            );
        }

        self.shape
            .outputs
            .iter()
            .map(|&wire| {
                let wire = usize::try_from(wire)
                    .map_err(|_| synthesis_error("direct Nova output gate"))?;
                gates
                    .get(wire)
                    .cloned()
                    .ok_or_else(|| synthesis_error("direct Nova output gate"))
            })
            .collect()
    }
}

impl<const ARITY: usize> DirectNovaStep<ARITY> {
    fn synthesize_witness<CS: ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        let mut output_positions = self
            .shape
            .outputs
            .iter()
            .enumerate()
            .map(|(position, &wire)| {
                usize::try_from(wire)
                    .map(|wire| (wire, position))
                    .map_err(|_| synthesis_error("direct Nova witness output gate"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        output_positions.sort_unstable_by_key(|&(gate_index, _)| gate_index);
        let mut output_positions = output_positions.into_iter().peekable();
        let mut outputs = vec![None; ARITY];

        for (gate_index, &value) in self.gate_values.iter().enumerate() {
            let variable = cs.alloc(|| "direct gate", || Ok(value))?;
            if output_positions
                .peek()
                .is_some_and(|&(output_gate, _)| output_gate == gate_index)
            {
                let (_, position) = output_positions
                    .next()
                    .ok_or_else(|| synthesis_error("direct Nova witness output position"))?;
                outputs[position] = Some(AllocatedNum::from_parts(variable, Some(value)));
            }
        }
        if output_positions.next().is_some() {
            return Err(synthesis_error("direct Nova witness output gate"));
        }

        outputs
            .into_iter()
            .map(|output| {
                output.ok_or_else(|| synthesis_error("direct Nova witness output assignment"))
            })
            .collect()
    }
}

struct CompiledRowsBuilder {
    expected_rows: usize,
    expected_terms: usize,
    offsets: Vec<u32>,
    variables: Vec<u32>,
    coefficients: Vec<NovaScalar>,
}

impl CompiledRowsBuilder {
    fn new(expected_rows: usize, expected_terms: usize) -> Result<Self, ReceiptCycleError> {
        let offset_count = expected_rows
            .checked_add(1)
            .ok_or(ReceiptCycleError::Malformed(
                "direct Nova compact row count",
            ))?;
        u32::try_from(expected_rows)
            .map_err(|_| ReceiptCycleError::Malformed("direct Nova compact row count"))?;
        u32::try_from(expected_terms)
            .map_err(|_| ReceiptCycleError::Malformed("direct Nova compact term count"))?;
        let mut offsets = Vec::with_capacity(offset_count);
        offsets.push(0);
        Ok(Self {
            expected_rows,
            expected_terms,
            offsets,
            variables: Vec::with_capacity(expected_terms),
            coefficients: Vec::with_capacity(expected_terms),
        })
    }

    fn push_binding(
        &mut self,
        source: &RelationShape,
        row_index: usize,
        gate_index: usize,
        binding_kind: WireKind,
    ) -> Result<(), ReceiptCycleError> {
        let row = source
            .circuit
            .constraints
            .get(row_index)
            .ok_or(ReceiptCycleError::Malformed("direct Nova binding row"))?;
        let mut binding_seen = false;
        for term in row {
            if term.kind == binding_kind && term.index == gate_index {
                if term.coefficient != Scalar::ONE || binding_seen {
                    return Err(ReceiptCycleError::Malformed("direct Nova binding term"));
                }
                binding_seen = true;
                continue;
            }
            self.push_term(source, term, true)?;
        }
        if !binding_seen {
            return Err(ReceiptCycleError::Malformed("direct Nova missing binding"));
        }
        self.finish_row()
    }

    fn push_row(
        &mut self,
        source: &RelationShape,
        row: &[Term],
        negate: bool,
    ) -> Result<(), ReceiptCycleError> {
        for term in row {
            self.push_term(source, term, negate)?;
        }
        self.finish_row()
    }

    fn push_term(
        &mut self,
        source: &RelationShape,
        term: &Term,
        negate: bool,
    ) -> Result<(), ReceiptCycleError> {
        let variable = compact_variable_index(source, term)?;
        let mut coefficient = source_to_nova(term.coefficient)?;
        if negate {
            coefficient = -coefficient;
        }
        self.variables.push(variable);
        self.coefficients.push(coefficient);
        Ok(())
    }

    fn finish_row(&mut self) -> Result<(), ReceiptCycleError> {
        let offset = u32::try_from(self.variables.len())
            .map_err(|_| ReceiptCycleError::Malformed("direct Nova compact term count"))?;
        self.offsets.push(offset);
        Ok(())
    }

    fn finish(self) -> Result<CompiledRows, ReceiptCycleError> {
        if self.offsets.len() != self.expected_rows + 1
            || self.variables.len() != self.expected_terms
            || self.coefficients.len() != self.expected_terms
        {
            return Err(ReceiptCycleError::Malformed(
                "direct Nova compact row shape",
            ));
        }
        Ok(CompiledRows {
            offsets: self.offsets.into_boxed_slice(),
            variables: self.variables.into_boxed_slice(),
            coefficients: self.coefficients.into_boxed_slice(),
        })
    }
}

impl CompiledRows {
    fn row_count(&self) -> usize {
        self.offsets.len() - 1
    }

    fn lower<CS: ConstraintSystem<NovaScalar>>(
        &self,
        gates: &[AllocatedNum<NovaScalar>],
        row_index: usize,
    ) -> Result<LinearCombination<NovaScalar>, SynthesisError> {
        let offset_end = row_index
            .checked_add(2)
            .ok_or_else(|| synthesis_error("direct Nova compact row"))?;
        let offsets = self
            .offsets
            .get(row_index..offset_end)
            .ok_or_else(|| synthesis_error("direct Nova compact row"))?;
        let start = usize::try_from(offsets[0])
            .map_err(|_| synthesis_error("direct Nova compact offset"))?;
        let end = usize::try_from(offsets[1])
            .map_err(|_| synthesis_error("direct Nova compact offset"))?;
        let variables = self
            .variables
            .get(start..end)
            .ok_or_else(|| synthesis_error("direct Nova compact variables"))?;
        let coefficients = self
            .coefficients
            .get(start..end)
            .ok_or_else(|| synthesis_error("direct Nova compact coefficients"))?;
        let mut linear = LinearCombination::zero();
        for (&variable, &coefficient) in variables.iter().zip(coefficients) {
            linear = if variable == DIRECT_CONSTANT_INDEX {
                linear + (coefficient, CS::one())
            } else {
                let variable = usize::try_from(variable)
                    .map_err(|_| synthesis_error("direct Nova compact gate"))?;
                let gate = gates
                    .get(variable)
                    .ok_or_else(|| synthesis_error("direct Nova compact gate"))?;
                linear + (coefficient, gate.get_variable())
            };
        }
        Ok(linear)
    }
}

fn compact_variable_index(source: &RelationShape, term: &Term) -> Result<u32, ReceiptCycleError> {
    if term.kind == WireKind::One {
        return Ok(DIRECT_CONSTANT_INDEX);
    }
    let operation = source
        .operations
        .get(term.index)
        .ok_or(ReceiptCycleError::Malformed("direct Nova operation index"))?;
    let is_constant = match operation {
        GateOperationShape::AllocatedValue { .. } => match term.kind {
            WireKind::Left | WireKind::Output => false,
            WireKind::Right => true,
            WireKind::One => unreachable!("constant terms return above"),
        },
        GateOperationShape::Boolean { .. } => match term.kind {
            WireKind::Left | WireKind::Right | WireKind::Output => false,
            WireKind::One => unreachable!("constant terms return above"),
        },
        GateOperationShape::Product { .. } => match term.kind {
            WireKind::Output => false,
            WireKind::Left | WireKind::Right | WireKind::One => {
                return Err(ReceiptCycleError::Malformed("direct Nova product alias"));
            }
        },
    };
    if is_constant {
        Ok(DIRECT_CONSTANT_INDEX)
    } else {
        u32::try_from(term.index)
            .map_err(|_| ReceiptCycleError::Malformed("direct Nova compact gate index"))
    }
}

fn compact_state_indices<const ARITY: usize>(
    wires: &[StateWire],
    label: &'static str,
) -> Result<[u32; ARITY], ReceiptCycleError> {
    if wires.len() != ARITY {
        return Err(ReceiptCycleError::Malformed(label));
    }
    let mut compact = [0u32; ARITY];
    for (target, wire) in compact.iter_mut().zip(wires) {
        *target = u32::try_from(wire.index).map_err(|_| ReceiptCycleError::Malformed(label))?;
    }
    Ok(compact)
}

fn compact_row_counts(
    source: &RelationShape,
) -> Result<(usize, usize, usize, usize), ReceiptCycleError> {
    let mut product_rows = 0usize;
    let mut product_terms = 0usize;
    for operation in &source.operations {
        if let GateOperationShape::Product {
            left_binding,
            right_binding,
        } = operation
        {
            product_rows = product_rows
                .checked_add(2)
                .ok_or(ReceiptCycleError::Malformed(
                    "direct Nova compact row count",
                ))?;
            for &row_index in [left_binding, right_binding] {
                let row = source
                    .circuit
                    .constraints
                    .get(row_index)
                    .ok_or(ReceiptCycleError::Malformed("direct Nova binding row"))?;
                product_terms = product_terms
                    .checked_add(
                        row.len()
                            .checked_sub(1)
                            .ok_or(ReceiptCycleError::Malformed("direct Nova binding row"))?,
                    )
                    .ok_or(ReceiptCycleError::Malformed(
                        "direct Nova compact term count",
                    ))?;
            }
        }
    }

    let mut operation_rows = OperationRows::new(&source.operations);
    let mut next_operation_row = operation_rows.next();
    let mut semantic_rows = 0usize;
    let mut semantic_terms = 0usize;
    for (row_index, row) in source.circuit.constraints.iter().enumerate() {
        if next_operation_row == Some(row_index) {
            next_operation_row = operation_rows.next();
            continue;
        }
        if next_operation_row.is_some_and(|owned| owned < row_index) {
            return Err(ReceiptCycleError::Malformed(
                "direct Nova operation row order",
            ));
        }
        semantic_rows = semantic_rows
            .checked_add(1)
            .ok_or(ReceiptCycleError::Malformed(
                "direct Nova compact row count",
            ))?;
        semantic_terms =
            semantic_terms
                .checked_add(row.len())
                .ok_or(ReceiptCycleError::Malformed(
                    "direct Nova compact term count",
                ))?;
    }
    if next_operation_row.is_some() {
        return Err(ReceiptCycleError::Malformed("direct Nova operation rows"));
    }
    Ok((product_rows, product_terms, semantic_rows, semantic_terms))
}

struct OperationRows<'a> {
    operations: &'a [GateOperationShape],
    operation_index: usize,
    pending_second: Option<usize>,
}

impl<'a> OperationRows<'a> {
    fn new(operations: &'a [GateOperationShape]) -> Self {
        Self {
            operations,
            operation_index: 0,
            pending_second: None,
        }
    }
}

impl Iterator for OperationRows<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(second) = self.pending_second.take() {
            self.operation_index += 1;
            return Some(second);
        }
        let operation = self.operations.get(self.operation_index)?;
        match operation {
            GateOperationShape::AllocatedValue { unit_constraint } => {
                self.operation_index += 1;
                Some(*unit_constraint)
            }
            GateOperationShape::Boolean {
                input_constraint,
                output_constraint,
            } => {
                self.pending_second = Some(*output_constraint);
                Some(*input_constraint)
            }
            GateOperationShape::Product {
                left_binding,
                right_binding,
            } => {
                self.pending_second = Some(*right_binding);
                Some(*left_binding)
            }
        }
    }
}

fn validate_direct_shape<const ARITY: usize>(
    circuit: &Circuit,
    operations: &[GateOperationShape],
    inputs: &[StateWire],
    outputs: &[StateWire],
) -> Result<(), ReceiptCycleError> {
    validate_structured_circuit(circuit)?;
    validate_operations(operations, circuit)?;
    validate_direct_wire_provenance(circuit, operations)?;
    validate_state_wires::<ARITY>(circuit, operations, inputs, outputs)
}

#[cfg(test)]
pub(crate) fn direct_nova_raw_metrics<const ARITY: usize>(
    shape: &RelationShape,
) -> Result<DirectNovaRawMetrics, ReceiptCycleError> {
    validate_direct_shape::<ARITY>(
        &shape.circuit,
        &shape.operations,
        &shape.inputs,
        &shape.outputs,
    )?;

    let source_terms = shape
        .circuit
        .constraints
        .iter()
        .try_fold(0usize, |total, row| {
            total
                .checked_add(row.len())
                .ok_or(ReceiptCycleError::Malformed(
                    "direct Nova metric term overflow",
                ))
        })?;

    let mut allocated_operations = 0usize;
    let mut boolean_operations = 0usize;
    let mut product_operations = 0usize;
    let mut operation_nnz_upper_bound = 0usize;
    for operation in &shape.operations {
        let operation_nnz = match operation {
            GateOperationShape::AllocatedValue { .. } => {
                allocated_operations += 1;
                0
            }
            GateOperationShape::Boolean { .. } => {
                boolean_operations += 1;
                3
            }
            GateOperationShape::Product {
                left_binding,
                right_binding,
            } => {
                product_operations += 1;
                let left_terms = shape.circuit.constraints[*left_binding]
                    .len()
                    .checked_sub(1)
                    .ok_or(ReceiptCycleError::Malformed("direct Nova product binding"))?;
                let right_terms = shape.circuit.constraints[*right_binding]
                    .len()
                    .checked_sub(1)
                    .ok_or(ReceiptCycleError::Malformed("direct Nova product binding"))?;
                left_terms
                    .checked_add(right_terms)
                    .and_then(|terms| terms.checked_add(1))
                    .ok_or(ReceiptCycleError::Malformed(
                        "direct Nova metric nonzero overflow",
                    ))?
            }
        };
        operation_nnz_upper_bound = operation_nnz_upper_bound.checked_add(operation_nnz).ok_or(
            ReceiptCycleError::Malformed("direct Nova metric nonzero overflow"),
        )?;
    }

    let mut operation_rows = OperationRows::new(&shape.operations);
    let mut next_operation_row = operation_rows.next();
    let mut semantic_constraints = 0usize;
    let mut semantic_nnz_upper_bound = 0usize;
    for (row_index, row) in shape.circuit.constraints.iter().enumerate() {
        if next_operation_row == Some(row_index) {
            next_operation_row = operation_rows.next();
            continue;
        }
        if next_operation_row.is_some_and(|owned| owned < row_index) {
            return Err(ReceiptCycleError::Malformed(
                "direct Nova metric operation row order",
            ));
        }
        semantic_constraints += 1;
        semantic_nnz_upper_bound = semantic_nnz_upper_bound
            .checked_add(row.len())
            .and_then(|terms| terms.checked_add(1))
            .ok_or(ReceiptCycleError::Malformed(
                "direct Nova metric nonzero overflow",
            ))?;
    }
    if next_operation_row.is_some() {
        return Err(ReceiptCycleError::Malformed(
            "direct Nova metric operation rows",
        ));
    }

    let direct_constraints = boolean_operations
        .checked_add(product_operations)
        .and_then(|constraints| constraints.checked_add(semantic_constraints))
        .and_then(|constraints| constraints.checked_add(ARITY))
        .ok_or(ReceiptCycleError::Malformed(
            "direct Nova metric constraint overflow",
        ))?;
    let expected_direct_constraints = shape
        .circuit
        .constraints
        .len()
        .checked_sub(shape.circuit.gate_count)
        .and_then(|constraints| constraints.checked_add(ARITY))
        .ok_or(ReceiptCycleError::Malformed(
            "direct Nova metric constraint shape",
        ))?;
    if direct_constraints != expected_direct_constraints {
        return Err(ReceiptCycleError::Malformed(
            "direct Nova metric constraint shape",
        ));
    }
    let direct_nnz_upper_bound = operation_nnz_upper_bound
        .checked_add(semantic_nnz_upper_bound)
        .and_then(|terms| terms.checked_add(ARITY.checked_mul(3)?))
        .ok_or(ReceiptCycleError::Malformed(
            "direct Nova metric nonzero overflow",
        ))?;
    let direct_variables = shape.circuit.gate_count;
    let direct_power_of_two_bucket = direct_variables
        .max(direct_constraints)
        .checked_next_power_of_two()
        .ok_or(ReceiptCycleError::Malformed(
            "direct Nova metric bucket overflow",
        ))?;

    Ok(DirectNovaRawMetrics {
        relation_id: relation_id::<ARITY>(
            &shape.circuit,
            &shape.operations,
            &shape.inputs,
            &shape.outputs,
            DIRECT_LOWERING_VERSION,
        )?,
        source_gates: shape.circuit.gate_count,
        source_constraints: shape.circuit.constraints.len(),
        source_terms,
        allocated_operations,
        boolean_operations,
        product_operations,
        semantic_constraints,
        direct_variables,
        direct_constraints,
        direct_nnz_upper_bound,
        direct_power_of_two_bucket,
        direct_bucket_headroom: direct_power_of_two_bucket
            - direct_variables.max(direct_constraints),
        direct_rounds: direct_power_of_two_bucket.ilog2(),
    })
}

fn validate_structured_circuit(circuit: &Circuit) -> Result<(), ReceiptCycleError> {
    if circuit.gate_count == 0 || circuit.gate_count > DIRECT_NOVA_MAX_SOURCE_GATES {
        return Err(ReceiptCycleError::Malformed("direct Nova gate count"));
    }
    if circuit.constraints.len() > DIRECT_NOVA_MAX_SOURCE_CONSTRAINTS
        || u32::try_from(circuit.gate_count).is_err()
        || u32::try_from(circuit.constraints.len()).is_err()
    {
        return Err(ReceiptCycleError::Malformed("direct Nova constraint shape"));
    }

    let mut total_terms = 0usize;
    for row in &circuit.constraints {
        if row.is_empty() || u32::try_from(row.len()).is_err() {
            return Err(ReceiptCycleError::Malformed("direct Nova empty row"));
        }
        total_terms = total_terms
            .checked_add(row.len())
            .ok_or(ReceiptCycleError::Malformed("direct Nova term overflow"))?;
        if total_terms > DIRECT_NOVA_MAX_SOURCE_TERMS {
            return Err(ReceiptCycleError::Malformed("direct Nova term count"));
        }
        let mut previous = None;
        for term in row {
            let key = (term.kind, term.index);
            if term.coefficient == Scalar::ZERO
                || previous.is_some_and(|prior| prior >= key)
                || u32::try_from(term.index).is_err()
                || (term.kind == WireKind::One && term.index != 0)
                || (term.kind != WireKind::One && term.index >= circuit.gate_count)
            {
                return Err(ReceiptCycleError::Malformed("direct Nova term"));
            }
            previous = Some(key);
        }
    }
    Ok(())
}

fn validate_direct_wire_provenance(
    circuit: &Circuit,
    operations: &[GateOperationShape],
) -> Result<(), ReceiptCycleError> {
    for (row_index, row) in circuit.constraints.iter().enumerate() {
        for term in row {
            if term.kind == WireKind::One {
                continue;
            }
            let operation = operations
                .get(term.index)
                .ok_or(ReceiptCycleError::Malformed("direct Nova wire index"))?;
            let allowed = match operation {
                GateOperationShape::AllocatedValue { unit_constraint } => {
                    term.kind == WireKind::Left
                        || (term.kind == WireKind::Right && row_index == *unit_constraint)
                }
                GateOperationShape::Boolean {
                    input_constraint,
                    output_constraint,
                } => {
                    term.kind == WireKind::Left
                        || (term.kind == WireKind::Right && row_index == *input_constraint)
                        || (term.kind == WireKind::Output && row_index == *output_constraint)
                }
                GateOperationShape::Product {
                    left_binding,
                    right_binding,
                } => {
                    term.kind == WireKind::Output
                        || (term.kind == WireKind::Left
                            && row_index == *left_binding
                            && term.coefficient == Scalar::ONE)
                        || (term.kind == WireKind::Right
                            && row_index == *right_binding
                            && term.coefficient == Scalar::ONE)
                }
            };
            if !allowed {
                return Err(ReceiptCycleError::Malformed("direct Nova wire provenance"));
            }
        }
    }
    Ok(())
}

fn validate_state_wires<const ARITY: usize>(
    circuit: &Circuit,
    operations: &[GateOperationShape],
    inputs: &[StateWire],
    outputs: &[StateWire],
) -> Result<(), ReceiptCycleError> {
    if ARITY == 0
        || ARITY > ANCHOR_RECURRENCE_STATE_ARITY
        || inputs.len() != ARITY
        || outputs.len() != ARITY
    {
        return Err(ReceiptCycleError::Malformed("direct Nova state arity"));
    }
    for (wire_index, wire) in inputs.iter().chain(outputs).enumerate() {
        if wire.kind != WireKind::Left
            || wire.index >= circuit.gate_count
            || !matches!(
                operations.get(wire.index),
                Some(GateOperationShape::AllocatedValue { .. })
            )
        {
            return Err(ReceiptCycleError::Malformed("direct Nova state wire"));
        }
        if inputs
            .iter()
            .chain(outputs)
            .take(wire_index)
            .any(|prior| prior.index == wire.index)
        {
            return Err(ReceiptCycleError::Malformed("direct Nova state alias"));
        }
    }
    Ok(())
}

fn validate_assignment(
    circuit: &Circuit,
    assignment: &Assignment,
) -> Result<(), ReceiptCycleError> {
    if assignment.gates.len() != circuit.gate_count {
        return Err(ReceiptCycleError::AssignmentShape);
    }
    for row in &circuit.constraints {
        let mut value = Scalar::ZERO;
        for term in row {
            let wire = match term.kind {
                WireKind::One => Scalar::ONE,
                WireKind::Left => {
                    assignment
                        .gates
                        .get(term.index)
                        .ok_or(ReceiptCycleError::AssignmentShape)?
                        .0
                }
                WireKind::Right => {
                    assignment
                        .gates
                        .get(term.index)
                        .ok_or(ReceiptCycleError::AssignmentShape)?
                        .1
                }
                WireKind::Output => {
                    let &(left, right) = assignment
                        .gates
                        .get(term.index)
                        .ok_or(ReceiptCycleError::AssignmentShape)?;
                    left * right
                }
            };
            value += term.coefficient * wire;
        }
        if value != Scalar::ZERO {
            return Err(ReceiptCycleError::Malformed(
                "direct Nova unsatisfied assignment",
            ));
        }
    }
    Ok(())
}

fn state_values<const ARITY: usize>(
    gates: &[NovaScalar],
    wires: &[u32; ARITY],
) -> Result<[NovaScalar; ARITY], ReceiptCycleError> {
    let mut values = [NovaScalar::ZERO; ARITY];
    for (value, &wire) in values.iter_mut().zip(wires) {
        let wire = usize::try_from(wire)
            .map_err(|_| ReceiptCycleError::Malformed("direct Nova state index"))?;
        *value = gates
            .get(wire)
            .copied()
            .ok_or(ReceiptCycleError::Malformed("direct Nova state index"))?;
    }
    Ok(values)
}

fn source_to_nova(value: Scalar) -> Result<NovaScalar, ReceiptCycleError> {
    let bytes = Secq256k1Cycle::scalar_to_canonical(&value);
    let mut repr = <NovaScalar as PrimeField>::Repr::default();
    if repr.as_ref().len() != bytes.len() {
        return Err(ReceiptCycleError::Malformed("direct Nova scalar width"));
    }
    repr.as_mut().copy_from_slice(&bytes);
    Option::<NovaScalar>::from(NovaScalar::from_repr(repr))
        .ok_or(ReceiptCycleError::Malformed("direct Nova scalar"))
}

fn nova_to_source(value: NovaScalar) -> Result<Scalar, ReceiptCycleError> {
    let repr = value.to_repr();
    let bytes: [u8; 32] = repr
        .as_ref()
        .try_into()
        .map_err(|_| ReceiptCycleError::Malformed("direct Nova scalar width"))?;
    Secq256k1Cycle::scalar_from_canonical(&bytes)
        .ok_or(ReceiptCycleError::Malformed("direct Nova scalar"))
}

fn relation_id<const ARITY: usize>(
    circuit: &Circuit,
    operations: &[GateOperationShape],
    inputs: &[StateWire],
    outputs: &[StateWire],
    lowering_version: u8,
) -> Result<DirectRelationId, ReceiptCycleError> {
    let mut digest = Sha256::new();
    digest.update(RELATION_ID_DOMAIN);
    digest.update([DIRECT_RELATION_ENCODING_VERSION, lowering_version]);
    emit_circuit(circuit, |bytes| digest.update(bytes));
    hash_u32(&mut digest, operations.len())?;
    for operation in operations {
        match operation {
            GateOperationShape::AllocatedValue { unit_constraint } => {
                digest.update([0]);
                hash_u32(&mut digest, *unit_constraint)?;
            }
            GateOperationShape::Boolean {
                input_constraint,
                output_constraint,
            } => {
                digest.update([1]);
                hash_u32(&mut digest, *input_constraint)?;
                hash_u32(&mut digest, *output_constraint)?;
            }
            GateOperationShape::Product {
                left_binding,
                right_binding,
            } => {
                digest.update([2]);
                hash_u32(&mut digest, *left_binding)?;
                hash_u32(&mut digest, *right_binding)?;
            }
        }
    }
    hash_u32(&mut digest, ARITY)?;
    for wire in inputs.iter().chain(outputs) {
        digest.update([wire.kind as u8]);
        hash_u32(&mut digest, wire.index)?;
    }
    Ok(DirectRelationId(digest.finalize().into()))
}

fn hash_u32(digest: &mut Sha256, value: usize) -> Result<(), ReceiptCycleError> {
    let value = u32::try_from(value)
        .map_err(|_| ReceiptCycleError::Malformed("direct Nova relation index"))?;
    digest.update(value.to_le_bytes());
    Ok(())
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use nova_snark::frontend::{shape_cs::ShapeCS, util_cs::witness_cs::WitnessCS};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::relation_builder::{Builder, Expression};

    type RelationParts = (
        Circuit,
        Assignment,
        Vec<GateOperationShape>,
        Vec<StateWire>,
        Vec<StateWire>,
    );

    #[test]
    fn reviewed_sha_source_shape_uses_direct_only_limits() {
        const PRODUCTION_GATES: usize = 10_428_979;
        const PRODUCTION_CONSTRAINTS: usize = 21_056_835;
        const PRODUCTION_TERMS: usize = 66_078_014;

        assert_eq!(
            PRODUCTION_GATES.next_power_of_two(),
            DIRECT_NOVA_MAX_SOURCE_GATES
        );
        assert_eq!(
            PRODUCTION_CONSTRAINTS.next_power_of_two(),
            DIRECT_NOVA_MAX_SOURCE_CONSTRAINTS
        );
        assert_eq!(
            PRODUCTION_TERMS.next_power_of_two(),
            DIRECT_NOVA_MAX_SOURCE_TERMS
        );
        const { assert!(PRODUCTION_CONSTRAINTS > crate::MAX_CONSTRAINTS) };
    }

    fn fixture(input_value: u64, interleaved_semantic: bool) -> StatefulRelation {
        fixture_with_builder(Builder::default(), input_value, interleaved_semantic)
    }

    fn fixture_with_builder(
        mut builder: Builder,
        input_value: u64,
        interleaved_semantic: bool,
    ) -> StatefulRelation {
        let input = builder.allocate_state(Scalar::from(input_value));
        let condition = builder.allocate_boolean(true);
        if interleaved_semantic {
            builder.constrain_equal(&condition, &Expression::constant(Scalar::ONE));
        }
        let product = builder.multiply(input.expression(), &condition);
        let output = builder.expose_state(&product);
        builder
            .finish_stateful(&[input], &[output])
            .expect("direct Nova fixture")
    }

    fn two_state_fixture() -> StatefulRelation {
        let mut builder = Builder::default();
        let first = builder.allocate_state(Scalar::from(3));
        let second = builder.allocate_state(Scalar::from(5));
        let first_output = builder.expose_state(first.expression());
        let second_output = builder.expose_state(second.expression());
        builder
            .finish_stateful(&[first, second], &[first_output, second_output])
            .expect("two-state direct Nova fixture")
    }

    fn two_product_fixture() -> StatefulRelation {
        let mut builder = Builder::default();
        let input = builder.allocate_state(Scalar::from(3));
        let condition = builder.allocate_boolean(true);
        let first = builder.multiply(input.expression(), &condition);
        let second = builder.multiply(&first, &condition);
        let output = builder.expose_state(&second);
        builder
            .finish_stateful(&[input], &[output])
            .expect("two-product direct Nova fixture")
    }

    fn affine_product_fixture() -> StatefulRelation {
        let mut builder = Builder::default();
        let input = builder.allocate_state(Scalar::from(3));
        let affine = input
            .expression()
            .clone()
            .scale(Scalar::from(2))
            .add(&Expression::constant(Scalar::from(5)));
        let factor = builder.allocate_boolean(true);
        let product = builder.multiply(&affine, &factor);
        let output = builder.expose_state(&product);
        builder
            .finish_stateful(&[input], &[output])
            .expect("affine-product direct Nova fixture")
    }

    fn split(relation: StatefulRelation) -> RelationParts {
        let shape = match Arc::try_unwrap(relation.shape) {
            Ok(shape) => shape,
            Err(_) => panic!("fixture owns its relation shape"),
        };
        (
            shape.circuit,
            relation.assignment,
            shape.operations,
            shape.inputs,
            shape.outputs,
        )
    }

    fn relation_shape_mut(relation: &mut StatefulRelation) -> &mut RelationShape {
        Arc::get_mut(&mut relation.shape).expect("fixture owns its relation shape")
    }

    fn prepared(input_value: u64) -> (DirectNovaTemplate<1>, Assignment) {
        let relation = fixture(input_value, false);
        let assignment = relation.assignment.clone();
        let (template, _) =
            DirectNovaTemplate::from_relation(relation).expect("direct Nova template");
        (template, assignment)
    }

    fn synthesized_shape(step: &DirectNovaStep<1>) -> ShapeCS<DirectNovaPrimaryEngine> {
        let mut shape = ShapeCS::<DirectNovaPrimaryEngine>::new();
        let state = AllocatedNum::alloc_input(&mut shape, || Ok(NovaScalar::ZERO))
            .expect("shape state input");
        step.synthesize(&mut shape, &[state])
            .expect("shape synthesis");
        shape
    }

    fn synthesize_with_input(step: &DirectNovaStep<1>, input: NovaScalar) -> bool {
        let mut shape = ShapeCS::<DirectNovaPrimaryEngine>::new();
        let shape_state =
            AllocatedNum::alloc_input(&mut shape, || Ok(input)).expect("shape state input");
        step.synthesize(&mut shape, &[shape_state])
            .expect("shape synthesis");

        let mut witness = WitnessCS::with_capacity(step.gate_values.len(), 1);
        let witness_state =
            AllocatedNum::alloc_input(&mut witness, || Ok(input)).expect("witness state input");
        let outputs = step
            .synthesize(&mut witness, &[witness_state])
            .expect("witness synthesis");

        if witness.aux_assignment() != step.gate_values.as_ref()
            || outputs.len() != 1
            || outputs[0].get_value() != Some(step.output_state()[0])
        {
            return false;
        }

        shape.constraints.iter().all(|(left, right, output)| {
            left.eval(witness.input_assignment(), witness.aux_assignment())
                * right.eval(witness.input_assignment(), witness.aux_assignment())
                == output.eval(witness.input_assignment(), witness.aux_assignment())
        })
    }

    #[test]
    fn direct_lowering_has_exact_raw_shape() {
        let relation = fixture(3, false);
        let gate_count = relation.shape.circuit.gate_count;
        let source_constraints = relation.shape.circuit.constraints.len();
        let step = DirectNovaStep::<1>::from_relation(relation).expect("direct step");
        let mut cs = ShapeCS::<DirectNovaPrimaryEngine>::new();
        let state =
            AllocatedNum::alloc_input(&mut cs, || Ok(NovaScalar::ZERO)).expect("shape state");
        let outputs = step.synthesize(&mut cs, &[state]).expect("shape");

        assert_eq!(outputs.len(), 1);
        assert_eq!(cs.num_aux(), gate_count);
        assert_eq!(cs.num_constraints(), source_constraints - gate_count + 1);
        assert_eq!(
            step.input_state(),
            &[source_to_nova(Scalar::from(3)).expect("scalar")]
        );
        assert_eq!(step.output_state(), step.input_state());
        assert!(synthesize_with_input(&step, step.input_state()[0]));
    }

    #[test]
    fn semantic_rows_interleaved_with_operations_are_retained() {
        let relation = fixture(7, true);
        let gate_count = relation.shape.circuit.gate_count;
        let source_constraints = relation.shape.circuit.constraints.len();
        let step = DirectNovaStep::<1>::from_relation(relation).expect("direct step");
        let mut cs = ShapeCS::<DirectNovaPrimaryEngine>::new();
        let state =
            AllocatedNum::alloc_input(&mut cs, || Ok(NovaScalar::ZERO)).expect("shape state");
        step.synthesize(&mut cs, &[state]).expect("shape");

        assert_eq!(cs.num_aux(), gate_count);
        assert_eq!(cs.num_constraints(), source_constraints - gate_count + 1);
        assert!(synthesize_with_input(&step, step.input_state()[0]));
    }

    #[test]
    fn affine_product_bindings_preserve_signs_and_constants() {
        let step = DirectNovaStep::<1>::from_relation(affine_product_fixture())
            .expect("affine-product direct step");

        assert_eq!(
            step.output_state(),
            &[source_to_nova(Scalar::from(11)).expect("scalar")]
        );
        assert!(synthesize_with_input(&step, step.input_state()[0]));
    }

    #[test]
    fn assignment_and_state_mutations_are_rejected() {
        let mutations = [
            (0usize, Scalar::from(3), Scalar::from(2)),
            (1, Scalar::ONE, Scalar::ZERO),
            (1, Scalar::from(2), Scalar::from(2)),
            (2, Scalar::from(4), Scalar::ONE),
            (3, Scalar::from(4), Scalar::ONE),
        ];
        for (gate, left, right) in mutations {
            let (template, mut assignment) = prepared(3);
            assignment.gates[gate] = (left, right);
            assert!(matches!(
                template.bind_assignment(assignment),
                Err(ReceiptCycleError::Malformed(
                    "direct Nova unsatisfied assignment"
                ))
            ));
        }

        let (template, assignment) = prepared(3);
        let step = template.bind_assignment(assignment).expect("direct step");
        let wrong_input = step.input_state()[0] + NovaScalar::ONE;
        assert!(!synthesize_with_input(&step, wrong_input));
    }

    #[test]
    fn product_internal_wires_cannot_escape_owned_rows() {
        let (mut circuit, _, operations, inputs, outputs) = split(fixture(3, false));
        let semantic = circuit.constraints.last_mut().expect("semantic row");
        semantic.push(Term {
            kind: WireKind::Right,
            index: 2,
            coefficient: Scalar::ONE,
        });
        semantic.sort_by_key(|term| (term.kind, term.index));
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova wire provenance"))
        ));

        let (mut circuit, _, operations, inputs, outputs) = split(two_product_fixture());
        let later_left_binding = match operations[3] {
            GateOperationShape::Product { left_binding, .. } => left_binding,
            _ => panic!("later product operation"),
        };
        circuit.constraints[later_left_binding].push(Term {
            kind: WireKind::Left,
            index: 2,
            coefficient: Scalar::ONE,
        });
        circuit.constraints[later_left_binding].sort_by_key(|term| (term.kind, term.index));
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova wire provenance"))
        ));

        let (mut circuit, _, operations, inputs, outputs) = split(fixture(3, false));
        let output_binding = match operations[2] {
            GateOperationShape::Product { right_binding, .. } => right_binding,
            _ => panic!("product operation"),
        };
        circuit.constraints[output_binding].push(Term {
            kind: WireKind::Left,
            index: 2,
            coefficient: Scalar::ONE,
        });
        circuit.constraints[output_binding].sort_by_key(|term| (term.kind, term.index));
        assert!(DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs).is_err());
    }

    #[test]
    fn structured_shape_is_revalidated_without_reencoding() {
        let (mut circuit, _, operations, inputs, outputs) = split(fixture(3, false));
        circuit.constraints.last_mut().expect("semantic row")[0].coefficient = Scalar::ZERO;
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova term"))
        ));

        let (mut circuit, _, operations, inputs, outputs) = split(fixture(3, false));
        let duplicate = circuit.constraints.last().expect("semantic row")[0].clone();
        let semantic = circuit.constraints.last_mut().expect("semantic row");
        semantic.push(duplicate);
        semantic.sort_by_key(|term| (term.kind, term.index));
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova term"))
        ));
    }

    #[test]
    fn state_wires_are_fresh_allocated_values() {
        let (circuit, _, operations, mut inputs, outputs) = split(fixture(3, false));
        inputs[0].kind = WireKind::Right;
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova state wire"))
        ));

        let relation = fixture(3, false);
        let (circuit, _, operations, mut inputs, outputs) = split(relation);
        inputs[0].index = 2;
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova state wire"))
        ));

        let relation = fixture(3, false);
        let (circuit, _, operations, inputs, mut outputs) = split(relation);
        outputs[0] = inputs[0];
        assert!(matches!(
            DirectNovaShape::<1>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova state alias"))
        ));

        let (circuit, _, operations, mut inputs, outputs) = split(two_state_fixture());
        inputs[1] = inputs[0];
        assert!(matches!(
            DirectNovaShape::<2>::from_parts(circuit, operations, inputs, outputs),
            Err(ReceiptCycleError::Malformed("direct Nova state alias"))
        ));
    }

    #[test]
    fn relation_id_excludes_witness_and_binds_lowering_metadata() {
        let first = DirectNovaStep::<1>::from_relation(fixture(3, false)).expect("first");
        let second = DirectNovaStep::<1>::from_relation(fixture(9, false)).expect("second");
        assert_eq!(first.relation_id(), second.relation_id());

        let (mut circuit, _, operations, inputs, outputs) = split(fixture(3, false));
        let semantic = circuit.constraints.last_mut().expect("semantic row");
        semantic[0].coefficient *= Scalar::from(2);
        let changed = DirectNovaShape::<1>::from_parts(
            circuit,
            operations.clone(),
            inputs.clone(),
            outputs.clone(),
        )
        .expect("changed shape");
        assert_ne!(first.relation_id(), changed.relation_id);

        let (circuit, _, mut changed_operations, inputs, outputs) = split(fixture(3, false));
        if let GateOperationShape::AllocatedValue { unit_constraint } = &mut changed_operations[0] {
            *unit_constraint += 1;
        }
        let changed_operation_id = relation_id::<1>(
            &circuit,
            &changed_operations,
            &inputs,
            &outputs,
            DIRECT_LOWERING_VERSION,
        )
        .expect("operation id");
        assert_ne!(first.relation_id(), changed_operation_id);

        let changed_version = relation_id::<1>(
            &circuit,
            &operations,
            &inputs,
            &outputs,
            DIRECT_LOWERING_VERSION + 1,
        )
        .expect("version id");
        assert_ne!(first.relation_id(), changed_version);
        assert_ne!(first.relation_id().bytes(), &[0; 32]);

        let (circuit, _, operations, mut inputs, outputs) = split(two_state_fixture());
        let ordered = DirectNovaShape::<2>::from_parts(
            circuit.clone(),
            operations.clone(),
            inputs.clone(),
            outputs.clone(),
        )
        .expect("ordered state shape");
        inputs.swap(0, 1);
        let reordered = DirectNovaShape::<2>::from_parts(circuit, operations, inputs, outputs)
            .expect("reordered state shape");
        assert_ne!(ordered.relation_id, reordered.relation_id);
    }

    #[test]
    fn scalar_conversion_is_canonical_in_both_directions() {
        let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
        let values = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from(2),
            -Scalar::ONE,
            Scalar::random(&mut rng),
        ];
        let nova_values = source_state_to_nova(values).expect("source state to Nova");
        assert_eq!(
            nova_state_to_source(nova_values).expect("Nova state to source"),
            values
        );
        for (value, nova) in values.into_iter().zip(nova_values) {
            let round_trip = nova_to_source(nova).expect("Nova to source");
            assert_eq!(round_trip, value);
            let source_bytes = Secq256k1Cycle::scalar_to_canonical(&value);
            assert_eq!(nova.to_repr().as_ref(), source_bytes.as_slice());
        }
    }

    #[test]
    fn template_reuses_the_validated_shape_across_witnesses() {
        let first_relation = fixture(3, false);
        let original_source = Arc::clone(&first_relation.shape);
        let (template, first) =
            DirectNovaTemplate::<1>::from_relation(first_relation).expect("direct Nova template");
        assert!(Arc::ptr_eq(&template.source, &original_source));
        assert!(Arc::ptr_eq(&template.shape, &first.shape));

        let later_relation = fixture(9, false);
        let discarded_source = Arc::downgrade(&later_relation.shape);
        let second = template
            .bind_relation(later_relation)
            .expect("matching direct Nova relation");

        assert!(discarded_source.upgrade().is_none());
        assert!(Arc::ptr_eq(&template.shape, &second.shape));
        assert!(Arc::ptr_eq(&first.shape, &second.shape));
        assert_eq!(first.relation_id(), second.relation_id());
        assert_ne!(first.input_state(), second.input_state());
        assert_ne!(first.output_state(), second.output_state());
    }

    #[test]
    fn bound_steps_release_source_and_keep_identical_synthesis() {
        let relation = fixture(3, false);
        let source = Arc::downgrade(&relation.shape);
        let (template, first) =
            DirectNovaTemplate::<1>::from_relation(relation).expect("direct Nova template");
        let second_relation = fixture_with_builder(template.matching_builder(), 9, false);
        let second = template
            .bind_relation(second_relation)
            .expect("matching direct Nova relation");
        let before_release = synthesized_shape(&first);

        assert!(source.upgrade().is_some());
        drop(template);
        assert!(source.upgrade().is_none());

        let after_release = synthesized_shape(&second);
        assert_eq!(before_release.num_aux(), after_release.num_aux());
        assert_eq!(before_release.num_inputs(), after_release.num_inputs());
        assert_eq!(before_release.constraints, after_release.constraints);
        assert!(synthesize_with_input(&first, first.input_state()[0]));
        assert!(synthesize_with_input(&second, second.input_state()[0]));
    }

    #[test]
    fn template_streams_matching_witnesses_into_the_trusted_shape() {
        let (template, first) = DirectNovaTemplate::<1>::from_relation(fixture(3, false))
            .expect("direct Nova template");
        let later_relation = fixture_with_builder(template.matching_builder(), 9, false);
        assert!(Arc::ptr_eq(&later_relation.shape, &template.source));

        let second = template
            .bind_relation(later_relation)
            .expect("matching direct Nova relation");
        assert!(Arc::ptr_eq(&first.shape, &second.shape));
        assert_eq!(first.relation_id(), second.relation_id());
        assert_ne!(first.input_state(), second.input_state());
        assert_ne!(first.output_state(), second.output_state());
    }

    #[test]
    fn template_rejects_exact_shape_drift_before_binding() {
        let (template, _) = DirectNovaTemplate::<1>::from_relation(fixture(3, false))
            .expect("direct Nova template");

        let mut changed_circuit = fixture(9, false);
        relation_shape_mut(&mut changed_circuit)
            .circuit
            .constraints
            .last_mut()
            .expect("semantic row")[0]
            .coefficient *= Scalar::from(2);
        assert!(matches!(
            template.bind_relation(changed_circuit),
            Err(ReceiptCycleError::Malformed("direct Nova circuit drift"))
        ));

        let mut changed_operation = fixture(9, false);
        let GateOperationShape::AllocatedValue { unit_constraint } =
            &mut relation_shape_mut(&mut changed_operation).operations[0]
        else {
            panic!("allocated operation");
        };
        *unit_constraint += 1;
        assert!(matches!(
            template.bind_relation(changed_operation),
            Err(ReceiptCycleError::Malformed("direct Nova operation drift"))
        ));

        let (two_state_template, _) = DirectNovaTemplate::<2>::from_relation(two_state_fixture())
            .expect("two-state direct Nova template");
        let mut reordered_state = two_state_fixture();
        relation_shape_mut(&mut reordered_state).inputs.swap(0, 1);
        assert!(matches!(
            two_state_template.bind_relation(reordered_state),
            Err(ReceiptCycleError::Malformed("direct Nova state drift"))
        ));
    }
}
