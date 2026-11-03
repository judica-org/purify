// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * Private C transport for a caller-supplied transparent Secq256k1 R1CS.
 *
 * This experimental boundary does not select a purpose-specific relation or
 * recursively fold receipts. It is retained for cross-language backend tests
 * and is deliberately not installed as production API.
 */

#ifndef PURIFY_SRC_BRIDGE_RECEIPT_CYCLE_BRIDGE_H
#define PURIFY_SRC_BRIDGE_RECEIPT_CYCLE_BRIDGE_H

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

purify_receipt_cycle_status purify_receipt_cycle_proof_wire_len(
    const uint8_t* circuit, size_t circuit_len, size_t* proof_len_out);

purify_receipt_cycle_status purify_receipt_cycle_prove(
    const uint8_t* circuit, size_t circuit_len,
    const uint8_t* assignment, size_t assignment_len,
    const uint8_t* statement, size_t statement_len,
    const uint8_t prover_seed32[32], uint8_t* proof_out,
    size_t proof_capacity, size_t* proof_len_out);

purify_receipt_cycle_status purify_receipt_cycle_verify(
    const uint8_t* circuit, size_t circuit_len,
    const uint8_t* statement, size_t statement_len,
    const uint8_t* proof, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif // PURIFY_SRC_BRIDGE_RECEIPT_CYCLE_BRIDGE_H
