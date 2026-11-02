//! Narrow C ABI for the authenticated cycle-R1CS transport.

use core::ptr;
use std::slice;

use bulletproofs_cycle::R1CSError;

use crate::{proof_wire_len, prove, verify, ReceiptCycleError};

/// Stable status values mirrored by `purify/recursive/receipt_cycle.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurifyReceiptCycleStatus {
    Ok = 0,
    Malformed = 1,
    AssignmentShape = 2,
    ProofRejected = 3,
    BufferTooSmall = 4,
    InternalError = 5,
}

fn status(error: ReceiptCycleError) -> PurifyReceiptCycleStatus {
    match error {
        ReceiptCycleError::Malformed(_) => PurifyReceiptCycleStatus::Malformed,
        ReceiptCycleError::AssignmentShape => PurifyReceiptCycleStatus::AssignmentShape,
        ReceiptCycleError::Backend(R1CSError::FormatError) => PurifyReceiptCycleStatus::Malformed,
        ReceiptCycleError::Backend(R1CSError::VerificationError) => {
            PurifyReceiptCycleStatus::ProofRejected
        }
        ReceiptCycleError::Backend(
            R1CSError::InvalidGeneratorsLength | R1CSError::MissingAssignment,
        ) => PurifyReceiptCycleStatus::InternalError,
    }
}

unsafe fn copy_input(data: *const u8, len: usize) -> Result<Vec<u8>, PurifyReceiptCycleStatus> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if data.is_null() {
        return Err(PurifyReceiptCycleStatus::Malformed);
    }
    // SAFETY: the C ABI requires every non-empty input pair to identify a
    // readable allocation of exactly `len` bytes for the duration of this
    // call. Copying immediately prevents output aliasing from invalidating a
    // borrowed input slice later in the call.
    let bytes = unsafe { slice::from_raw_parts(data, len) };
    Ok(bytes.to_vec())
}

unsafe fn set_size(output: *mut usize, value: usize) -> Result<(), PurifyReceiptCycleStatus> {
    if output.is_null() {
        return Err(PurifyReceiptCycleStatus::Malformed);
    }
    // SAFETY: the C ABI requires `output` to reference one writable `size_t`.
    unsafe { output.write(value) };
    Ok(())
}

/// Returns the exact proof length selected by the canonical circuit shape.
#[no_mangle]
pub unsafe extern "C" fn purify_receipt_cycle_proof_wire_len(
    circuit: *const u8,
    circuit_len: usize,
    proof_len_out: *mut usize,
) -> PurifyReceiptCycleStatus {
    let circuit = match unsafe { copy_input(circuit, circuit_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let proof_len = match proof_wire_len(&circuit) {
        Ok(value) => value,
        Err(error) => return status(error),
    };
    match unsafe { set_size(proof_len_out, proof_len) } {
        Ok(()) => PurifyReceiptCycleStatus::Ok,
        Err(error) => error,
    }
}

/// Proves one assignment for the exact circuit and statement.
#[no_mangle]
pub unsafe extern "C" fn purify_receipt_cycle_prove(
    circuit: *const u8,
    circuit_len: usize,
    assignment: *const u8,
    assignment_len: usize,
    statement: *const u8,
    statement_len: usize,
    prover_seed32: *const u8,
    proof_out: *mut u8,
    proof_capacity: usize,
    proof_len_out: *mut usize,
) -> PurifyReceiptCycleStatus {
    let circuit = match unsafe { copy_input(circuit, circuit_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let assignment = match unsafe { copy_input(assignment, assignment_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let statement = match unsafe { copy_input(statement, statement_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let seed = match unsafe { copy_input(prover_seed32, 32) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let seed: [u8; 32] = match seed.try_into() {
        Ok(value) => value,
        Err(_) => return PurifyReceiptCycleStatus::InternalError,
    };

    let required = match proof_wire_len(&circuit) {
        Ok(value) => value,
        Err(error) => return status(error),
    };
    if let Err(error) = unsafe { set_size(proof_len_out, required) } {
        return error;
    }
    if proof_capacity < required {
        return PurifyReceiptCycleStatus::BufferTooSmall;
    }
    if required != 0 && proof_out.is_null() {
        return PurifyReceiptCycleStatus::Malformed;
    }

    let proof = match prove(&circuit, &assignment, &statement, seed) {
        Ok(value) => value,
        Err(error) => return status(error),
    };
    if proof.len() != required {
        return PurifyReceiptCycleStatus::InternalError;
    }
    // SAFETY: capacity was checked above and the proof is held in an
    // independent Rust allocation, so source and destination cannot overlap.
    unsafe { ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len()) };
    PurifyReceiptCycleStatus::Ok
}

/// Verifies one proof against the exact circuit and statement.
#[no_mangle]
pub unsafe extern "C" fn purify_receipt_cycle_verify(
    circuit: *const u8,
    circuit_len: usize,
    statement: *const u8,
    statement_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> PurifyReceiptCycleStatus {
    let circuit = match unsafe { copy_input(circuit, circuit_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let statement = match unsafe { copy_input(statement, statement_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let proof = match unsafe { copy_input(proof, proof_len) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    match verify(&circuit, &statement, &proof) {
        Ok(()) => PurifyReceiptCycleStatus::Ok,
        Err(error) => status(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{multiplication_assignment, multiplication_circuit};

    #[test]
    fn c_abi_round_trip_and_capacity_contract() {
        let circuit = multiplication_circuit(12);
        let assignment = multiplication_assignment(3, 4);
        let statement = b"ffi receipt";
        let seed = [0x63; 32];
        let mut required = 0usize;
        // SAFETY: all pointers and lengths reference live Rust allocations.
        let len_status = unsafe {
            purify_receipt_cycle_proof_wire_len(circuit.as_ptr(), circuit.len(), &mut required)
        };
        assert_eq!(len_status, PurifyReceiptCycleStatus::Ok);
        assert!(required > 0);

        let mut proof = vec![0u8; required];
        let mut written = 0usize;
        // SAFETY: all pointers and lengths reference live Rust allocations.
        let too_small = unsafe {
            purify_receipt_cycle_prove(
                circuit.as_ptr(),
                circuit.len(),
                assignment.as_ptr(),
                assignment.len(),
                statement.as_ptr(),
                statement.len(),
                seed.as_ptr(),
                proof.as_mut_ptr(),
                required - 1,
                &mut written,
            )
        };
        assert_eq!(too_small, PurifyReceiptCycleStatus::BufferTooSmall);
        assert_eq!(written, required);

        // SAFETY: all pointers and lengths reference live Rust allocations.
        let prove_status = unsafe {
            purify_receipt_cycle_prove(
                circuit.as_ptr(),
                circuit.len(),
                assignment.as_ptr(),
                assignment.len(),
                statement.as_ptr(),
                statement.len(),
                seed.as_ptr(),
                proof.as_mut_ptr(),
                proof.len(),
                &mut written,
            )
        };
        assert_eq!(prove_status, PurifyReceiptCycleStatus::Ok);
        assert_eq!(written, proof.len());

        // SAFETY: all pointers and lengths reference live Rust allocations.
        let verify_status = unsafe {
            purify_receipt_cycle_verify(
                circuit.as_ptr(),
                circuit.len(),
                statement.as_ptr(),
                statement.len(),
                proof.as_ptr(),
                proof.len(),
            )
        };
        assert_eq!(verify_status, PurifyReceiptCycleStatus::Ok);
    }

    #[test]
    fn c_abi_rejects_null_nonempty_inputs() {
        let mut output = 0usize;
        // SAFETY: this deliberately exercises the ABI's null-pointer check.
        let result = unsafe { purify_receipt_cycle_proof_wire_len(ptr::null(), 1, &mut output) };
        assert_eq!(result, PurifyReceiptCycleStatus::Malformed);
    }
}
