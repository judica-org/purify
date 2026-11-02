// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file recursive/receipt_cycle.h
 * @brief C transport for the transparent Secq256k1 parent-proof backend.
 *
 * This API proves an authenticated R1CS transport. A successful call does
 * not by itself mean that a coalition receipt is valid. Receipt callers must
 * reconstruct the purpose-specific circuit from its public statement and
 * then invoke this backend with that exact canonical circuit.
 */

#ifndef PURIFY_RECURSIVE_RECEIPT_CYCLE_H
#define PURIFY_RECURSIVE_RECEIPT_CYCLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum purify_receipt_cycle_status {
    PURIFY_RECEIPT_CYCLE_OK = 0,
    PURIFY_RECEIPT_CYCLE_MALFORMED = 1,
    PURIFY_RECEIPT_CYCLE_ASSIGNMENT_SHAPE = 2,
    PURIFY_RECEIPT_CYCLE_PROOF_REJECTED = 3,
    PURIFY_RECEIPT_CYCLE_BUFFER_TOO_SMALL = 4,
    PURIFY_RECEIPT_CYCLE_INTERNAL_ERROR = 5,
} purify_receipt_cycle_status;

/** Returns the exact single-phase proof size for `circuit`. */
purify_receipt_cycle_status purify_receipt_cycle_proof_wire_len(
    const uint8_t* circuit, size_t circuit_len, size_t* proof_len_out);

/**
 * Proves one canonical assignment for the exact circuit and statement.
 *
 * `prover_seed32` must contain fresh secret randomness. `proof_len_out` is
 * populated with the required size before a buffer-size error is returned.
 */
purify_receipt_cycle_status purify_receipt_cycle_prove(
    const uint8_t* circuit, size_t circuit_len,
    const uint8_t* assignment, size_t assignment_len,
    const uint8_t* statement, size_t statement_len,
    const uint8_t prover_seed32[32], uint8_t* proof_out,
    size_t proof_capacity, size_t* proof_len_out);

/** Verifies one proof against the exact canonical circuit and statement. */
purify_receipt_cycle_status purify_receipt_cycle_verify(
    const uint8_t* circuit, size_t circuit_len,
    const uint8_t* statement, size_t statement_len,
    const uint8_t* proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif // PURIFY_RECURSIVE_RECEIPT_CYCLE_H
