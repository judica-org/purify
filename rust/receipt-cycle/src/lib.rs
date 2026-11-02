//! Transparent Secq256k1 Bulletproof backend for compact Purify receipts.
//!
//! The outer proof commits in Secq256k1, whose scalar field is the
//! secp256k1 coordinate field. This is the curve-cycle direction needed to
//! check secp256k1 group arithmetic without a non-native coordinate gadget.
//! This crate deliberately exposes an authenticated R1CS transport, not a
//! receipt acceptance API. The C++ receipt verifier remains responsible for
//! reconstructing the exact purpose-specific circuit from public inputs.

use bulletproofs_cycle::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
use bulletproofs_cycle::{BulletproofGens, Cycle, PedersenGens, R1CSError};
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;
use merlin::Transcript;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod ffi;

pub(crate) type Scalar = <Secq256k1Cycle as Cycle>::Scalar;

const CIRCUIT_VERSION: u8 = 1;
const ASSIGNMENT_VERSION: u8 = 1;
const TRANSCRIPT_DOMAIN: &[u8] = b"Purify/Receipt/SecqParent/v1";
const VERIFIER_RNG_DOMAIN: &[u8] = b"Purify/Receipt/SecqVerifierRng/v1";
const MAX_GATES: usize = 1 << 24;
const MAX_CONSTRAINTS: usize = 1 << 24;
const MAX_TERMS: usize = 1 << 27;

/// Canonical parser or proof-backend failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ReceiptCycleError {
    /// A canonical circuit, assignment, or proof encoding was malformed.
    #[error("malformed receipt-cycle encoding: {0}")]
    Malformed(&'static str),
    /// The assignment shape did not match the authenticated circuit.
    #[error("receipt-cycle assignment shape mismatch")]
    AssignmentShape,
    /// The transparent Bulletproof backend rejected the operation.
    #[error("receipt-cycle proof backend rejected the operation: {0}")]
    Backend(#[from] R1CSError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum WireKind {
    One = 0,
    Left = 1,
    Right = 2,
    Output = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Term {
    kind: WireKind,
    index: usize,
    coefficient: Scalar,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Circuit {
    gate_count: usize,
    constraints: Vec<Vec<Term>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Assignment {
    gates: Vec<(Scalar, Scalar)>,
}

#[derive(Clone, Copy)]
struct GateVariables {
    left: Variable<Scalar>,
    right: Variable<Scalar>,
    output: Variable<Scalar>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ReceiptCycleError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ReceiptCycleError::Malformed("length overflow"))?;
        if end > self.bytes.len() {
            return Err(ReceiptCycleError::Malformed("truncated input"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, ReceiptCycleError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ReceiptCycleError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ReceiptCycleError::Malformed("u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn scalar(&mut self) -> Result<Scalar, ReceiptCycleError> {
        let bytes: [u8; 32] = self
            .take(32)?
            .try_into()
            .map_err(|_| ReceiptCycleError::Malformed("scalar width"))?;
        Secq256k1Cycle::scalar_from_canonical(&bytes)
            .ok_or(ReceiptCycleError::Malformed("noncanonical scalar"))
    }

    fn finish(self) -> Result<(), ReceiptCycleError> {
        if self.offset != self.bytes.len() {
            return Err(ReceiptCycleError::Malformed("trailing bytes"));
        }
        Ok(())
    }
}

impl Circuit {
    fn parse(bytes: &[u8]) -> Result<Self, ReceiptCycleError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.byte()? != CIRCUIT_VERSION {
            return Err(ReceiptCycleError::Malformed("circuit version"));
        }
        let gate_count = cursor.u32()? as usize;
        let constraint_count = cursor.u32()? as usize;
        if gate_count == 0 || gate_count > MAX_GATES {
            return Err(ReceiptCycleError::Malformed("gate count"));
        }
        if constraint_count > MAX_CONSTRAINTS {
            return Err(ReceiptCycleError::Malformed("constraint count"));
        }
        // Every constraint needs a term count and at least one 37-byte term.
        // Reject impossible advertised capacities before reserving memory.
        if constraint_count > cursor.bytes.len().saturating_sub(cursor.offset) / 41 {
            return Err(ReceiptCycleError::Malformed("constraint count"));
        }

        let mut total_terms = 0usize;
        let mut constraints = Vec::with_capacity(constraint_count);
        for _ in 0..constraint_count {
            let term_count = cursor.u32()? as usize;
            if term_count == 0 {
                return Err(ReceiptCycleError::Malformed("empty constraint"));
            }
            total_terms = total_terms
                .checked_add(term_count)
                .ok_or(ReceiptCycleError::Malformed("term count overflow"))?;
            if total_terms > MAX_TERMS {
                return Err(ReceiptCycleError::Malformed("term count"));
            }
            if term_count > cursor.bytes.len().saturating_sub(cursor.offset) / 37 {
                return Err(ReceiptCycleError::Malformed("term count"));
            }

            let mut terms = Vec::with_capacity(term_count);
            let mut previous = None;
            for _ in 0..term_count {
                let kind = match cursor.byte()? {
                    0 => WireKind::One,
                    1 => WireKind::Left,
                    2 => WireKind::Right,
                    3 => WireKind::Output,
                    _ => return Err(ReceiptCycleError::Malformed("wire kind")),
                };
                let index = cursor.u32()? as usize;
                if (kind == WireKind::One && index != 0)
                    || (kind != WireKind::One && index >= gate_count)
                {
                    return Err(ReceiptCycleError::Malformed("wire index"));
                }
                let key = (kind, index);
                if previous.is_some_and(|prior| prior >= key) {
                    return Err(ReceiptCycleError::Malformed("term order"));
                }
                previous = Some(key);
                let coefficient = cursor.scalar()?;
                if coefficient == Scalar::ZERO {
                    return Err(ReceiptCycleError::Malformed("zero coefficient"));
                }
                terms.push(Term {
                    kind,
                    index,
                    coefficient,
                });
            }
            constraints.push(terms);
        }
        cursor.finish()?;
        Ok(Self {
            gate_count,
            constraints,
        })
    }
}

impl Assignment {
    fn parse(bytes: &[u8]) -> Result<Self, ReceiptCycleError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.byte()? != ASSIGNMENT_VERSION {
            return Err(ReceiptCycleError::Malformed("assignment version"));
        }
        let gate_count = cursor.u32()? as usize;
        if gate_count == 0 || gate_count > MAX_GATES {
            return Err(ReceiptCycleError::Malformed("assignment gate count"));
        }
        let expected = 5usize
            .checked_add(
                gate_count
                    .checked_mul(64)
                    .ok_or(ReceiptCycleError::Malformed("assignment length"))?,
            )
            .ok_or(ReceiptCycleError::Malformed("assignment length"))?;
        if bytes.len() != expected {
            return Err(ReceiptCycleError::Malformed("assignment length"));
        }
        let mut gates = Vec::with_capacity(gate_count);
        for _ in 0..gate_count {
            gates.push((cursor.scalar()?, cursor.scalar()?));
        }
        cursor.finish()?;
        Ok(Self { gates })
    }
}

fn proof_transcript(circuit: &[u8], statement: &[u8]) -> Transcript {
    let circuit_digest = Sha256::digest(circuit);
    let mut transcript = Transcript::new(TRANSCRIPT_DOMAIN);
    transcript.append_message(b"circuit", &circuit_digest);
    transcript.append_message(b"statement", statement);
    transcript
}

/// Deterministic entropy for combining one proof's verification equations.
///
/// The Bulletproof verifier uses this RNG after its Merlin transcript has
/// fixed the proof in order to combine independent group equations with a
/// random scalar. Consensus verification cannot depend on operating-system
/// entropy, so the external seed is a domain-separated hash of the complete
/// verification instance. This is Fiat-Shamir equation randomization, not
/// prover randomness. A future batch verifier must instead bind the complete
/// ordered batch before deriving any equation coefficient.
fn deterministic_verifier_rng(circuit: &[u8], statement: &[u8], proof: &[u8]) -> ChaCha20Rng {
    let mut hash = Sha256::new();
    hash.update(VERIFIER_RNG_DOMAIN);
    hash.update((circuit.len() as u64).to_le_bytes());
    hash.update(circuit);
    hash.update((statement.len() as u64).to_le_bytes());
    hash.update(statement);
    hash.update((proof.len() as u64).to_le_bytes());
    hash.update(proof);
    let seed: [u8; 32] = hash.finalize().into();
    ChaCha20Rng::from_seed(seed)
}

fn term_variable(term: &Term, gates: &[GateVariables]) -> Option<Variable<Scalar>> {
    match term.kind {
        WireKind::One => None,
        WireKind::Left => Some(gates[term.index].left),
        WireKind::Right => Some(gates[term.index].right),
        WireKind::Output => Some(gates[term.index].output),
    }
}

fn install_constraints<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    circuit: &Circuit,
    gates: &[GateVariables],
) {
    for constraint in &circuit.constraints {
        let mut linear = LinearCombination::default();
        for term in constraint {
            linear = match term_variable(term, gates) {
                Some(variable) => linear + variable * term.coefficient,
                None => linear + term.coefficient,
            };
        }
        cs.constrain(linear);
    }
}

fn padded_gate_count(gate_count: usize) -> usize {
    gate_count.next_power_of_two()
}

/// Returns the exact single-phase proof length for a canonical circuit.
pub fn proof_wire_len(circuit: &[u8]) -> Result<usize, ReceiptCycleError> {
    let circuit = Circuit::parse(circuit)?;
    let lg_n = padded_gate_count(circuit.gate_count).ilog2() as usize;
    Ok(R1CSProof::<Secq256k1Cycle>::single_phase_wire_len(lg_n))
}

/// Proves one authenticated R1CS assignment with transparent generators.
pub fn prove(
    circuit_bytes: &[u8],
    assignment_bytes: &[u8],
    statement: &[u8],
    prover_seed: [u8; 32],
) -> Result<Vec<u8>, ReceiptCycleError> {
    let circuit = Circuit::parse(circuit_bytes)?;
    let assignment = Assignment::parse(assignment_bytes)?;
    if assignment.gates.len() != circuit.gate_count {
        return Err(ReceiptCycleError::AssignmentShape);
    }

    let pc_gens = PedersenGens::<Secq256k1Cycle>::default();
    let bp_gens = BulletproofGens::<Secq256k1Cycle>::new(padded_gate_count(circuit.gate_count), 1);
    let mut prover =
        Prover::<Secq256k1Cycle, _>::new(&pc_gens, proof_transcript(circuit_bytes, statement));
    let mut gates = Vec::with_capacity(circuit.gate_count);
    for &(left, right) in &assignment.gates {
        let (left, right, output) = prover.allocate_multiplier(Some((left, right)))?;
        gates.push(GateVariables {
            left,
            right,
            output,
        });
    }
    install_constraints(&mut prover, &circuit, &gates);
    let mut rng = ChaCha20Rng::from_seed(prover_seed);
    Ok(prover.prove(&bp_gens, &mut rng)?.to_bytes())
}

/// Verifies one proof against the exact canonical circuit and public statement.
pub fn verify(
    circuit_bytes: &[u8],
    statement: &[u8],
    proof_bytes: &[u8],
) -> Result<(), ReceiptCycleError> {
    let circuit = Circuit::parse(circuit_bytes)?;
    let lg_n = padded_gate_count(circuit.gate_count).ilog2() as usize;
    if proof_bytes.len() != R1CSProof::<Secq256k1Cycle>::single_phase_wire_len(lg_n) {
        return Err(ReceiptCycleError::Malformed("proof length"));
    }
    let proof = R1CSProof::<Secq256k1Cycle>::from_bytes(proof_bytes)?;
    let pc_gens = PedersenGens::<Secq256k1Cycle>::default();
    let bp_gens = BulletproofGens::<Secq256k1Cycle>::new(padded_gate_count(circuit.gate_count), 1);
    let mut verifier =
        Verifier::<Secq256k1Cycle, _>::new(proof_transcript(circuit_bytes, statement));
    let mut gates = Vec::with_capacity(circuit.gate_count);
    for _ in 0..circuit.gate_count {
        let (left, right, output) = verifier.allocate_multiplier(None)?;
        gates.push(GateVariables {
            left,
            right,
            output,
        });
    }
    install_constraints(&mut verifier, &circuit, &gates);
    let mut rng = deterministic_verifier_rng(circuit_bytes, statement, proof_bytes);
    verifier.verify(&proof, &pc_gens, &bp_gens, &mut rng)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn append_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn append_scalar(out: &mut Vec<u8>, value: Scalar) {
        out.extend_from_slice(&Secq256k1Cycle::scalar_to_canonical(&value));
    }

    pub(crate) fn multiplication_circuit(expected: u64) -> Vec<u8> {
        let mut out = vec![CIRCUIT_VERSION];
        append_u32(&mut out, 1);
        append_u32(&mut out, 1);
        append_u32(&mut out, 2);
        out.push(WireKind::One as u8);
        append_u32(&mut out, 0);
        append_scalar(&mut out, -scalar(expected));
        out.push(WireKind::Output as u8);
        append_u32(&mut out, 0);
        append_scalar(&mut out, Scalar::ONE);
        out
    }

    pub(crate) fn multiplication_assignment(left: u64, right: u64) -> Vec<u8> {
        let mut out = vec![ASSIGNMENT_VERSION];
        append_u32(&mut out, 1);
        append_scalar(&mut out, scalar(left));
        append_scalar(&mut out, scalar(right));
        out
    }

    #[test]
    fn proof_round_trip_binds_statement_and_circuit() {
        let circuit = multiplication_circuit(12);
        let assignment = multiplication_assignment(3, 4);
        let statement = b"coalition construction receipt";
        let proof = prove(&circuit, &assignment, statement, [0x42; 32]).expect("prove");
        assert_eq!(proof.len(), proof_wire_len(&circuit).expect("wire length"));
        verify(&circuit, statement, &proof).expect("verify");

        assert!(verify(&circuit, b"other receipt", &proof).is_err());
        assert!(verify(&multiplication_circuit(13), statement, &proof).is_err());
        let mut changed_proof = proof;
        changed_proof[0] ^= 1;
        assert!(verify(&circuit, statement, &changed_proof).is_err());
    }

    #[test]
    fn unsatisfied_assignment_cannot_produce_an_accepted_proof() {
        let circuit = multiplication_circuit(12);
        let proof = prove(
            &circuit,
            &multiplication_assignment(3, 5),
            b"statement",
            [0x19; 32],
        )
        .expect("the prover can form an algebraic transcript");
        assert!(verify(&circuit, b"statement", &proof).is_err());
    }

    #[test]
    fn canonical_codecs_reject_malleable_inputs() {
        let circuit = multiplication_circuit(12);
        let assignment = multiplication_assignment(3, 4);

        let mut trailing = circuit.clone();
        trailing.push(0);
        assert_eq!(
            proof_wire_len(&trailing),
            Err(ReceiptCycleError::Malformed("trailing bytes"))
        );

        let mut duplicate = circuit.clone();
        duplicate[9..13].copy_from_slice(&3u32.to_le_bytes());
        let first_term = duplicate[13..50].to_vec();
        duplicate.splice(50..50, first_term);
        assert_eq!(
            proof_wire_len(&duplicate),
            Err(ReceiptCycleError::Malformed("term order"))
        );

        let mut bad_assignment = assignment;
        bad_assignment.push(0);
        assert!(matches!(
            prove(&circuit, &bad_assignment, b"statement", [7; 32]),
            Err(ReceiptCycleError::Malformed("assignment length"))
        ));
    }

    #[test]
    fn verifier_equation_randomization_is_deterministic_and_bound() {
        let circuit = multiplication_circuit(12);
        let statement = b"consensus receipt";
        let proof = vec![0x5a; 425];
        let mut first = deterministic_verifier_rng(&circuit, statement, &proof);
        let mut second = deterministic_verifier_rng(&circuit, statement, &proof);
        assert_eq!(first.next_u64(), second.next_u64());

        let mut changed_proof = proof.clone();
        changed_proof[0] ^= 1;
        let mut changed = deterministic_verifier_rng(&circuit, statement, &changed_proof);
        let mut original = deterministic_verifier_rng(&circuit, statement, &proof);
        assert_ne!(original.next_u64(), changed.next_u64());

        let mut changed_statement = deterministic_verifier_rng(&circuit, b"other receipt", &proof);
        let mut original = deterministic_verifier_rng(&circuit, statement, &proof);
        assert_ne!(original.next_u64(), changed_statement.next_u64());
    }
}
