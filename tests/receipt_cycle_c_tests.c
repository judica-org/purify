// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "purify/recursive/receipt_cycle.h"

static int expect(int condition, const char* message) {
    if (condition) {
        return 1;
    }
    fprintf(stderr, "FAIL: %s\n", message);
    return 0;
}

static void put_u32(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

int main(void) {
    /* One gate with left=3, right=0 and the constraint output=0. */
    uint8_t circuit[50] = {0};
    uint8_t assignment[69] = {0};
    uint8_t seed[32];
    uint8_t proof[2048];
    static const uint8_t statement[] = "cycle C ABI receipt";
    size_t proof_len = 0;
    size_t written = 0;
    int ok = 1;

    circuit[0] = 1;
    put_u32(circuit + 1, 1);
    put_u32(circuit + 5, 1);
    put_u32(circuit + 9, 1);
    circuit[13] = 3;
    put_u32(circuit + 14, 0);
    circuit[18] = 1;

    assignment[0] = 1;
    put_u32(assignment + 1, 1);
    assignment[5] = 3;
    memset(seed, 0x5a, sizeof(seed));

    ok &= expect(
        purify_receipt_cycle_proof_wire_len(
            circuit, sizeof(circuit), &proof_len) ==
            PURIFY_RECEIPT_CYCLE_OK,
        "proof length query accepts the canonical circuit");
    ok &= expect(proof_len > 0 && proof_len <= sizeof(proof),
                 "proof length fits the transport buffer");
    if (!ok) {
        return 1;
    }

    ok &= expect(
        purify_receipt_cycle_prove(
            circuit, sizeof(circuit), assignment, sizeof(assignment),
            statement, sizeof(statement) - 1, seed, proof,
            proof_len - 1, &written) ==
            PURIFY_RECEIPT_CYCLE_BUFFER_TOO_SMALL,
        "prover rejects a short output buffer");
    ok &= expect(written == proof_len,
                 "short-buffer result reports the required proof length");

    ok &= expect(
        purify_receipt_cycle_prove(
            circuit, sizeof(circuit), assignment, sizeof(assignment),
            statement, sizeof(statement) - 1, seed, proof,
            sizeof(proof), &written) == PURIFY_RECEIPT_CYCLE_OK,
        "C transport proves the canonical assignment");
    ok &= expect(written == proof_len,
                 "C transport writes the exact advertised proof length");
    ok &= expect(
        purify_receipt_cycle_verify(
            circuit, sizeof(circuit), statement, sizeof(statement) - 1,
            proof, written) == PURIFY_RECEIPT_CYCLE_OK,
        "C transport verifies the proof");
    ok &= expect(
        purify_receipt_cycle_verify(
            circuit, sizeof(circuit), (const uint8_t*)"other", 5,
            proof, written) == PURIFY_RECEIPT_CYCLE_PROOF_REJECTED,
        "C transport binds the public statement");

    proof[written - 1] ^= 1;
    ok &= expect(
        purify_receipt_cycle_verify(
            circuit, sizeof(circuit), statement, sizeof(statement) - 1,
            proof, written) != PURIFY_RECEIPT_CYCLE_OK,
        "C transport rejects a mutated proof");
    return ok ? 0 : 1;
}
