// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <span>
#include <vector>

#include "purify/bulletproof.hpp"

namespace purify {

/**
 * @brief One ordered coalition/topic relation with its own summed nonce output.
 *
 * evaluation_input is the exact existing Purify input, not a batch-dependent
 * derivation. Hosts must be distinct within a group; a host may occur in other
 * groups. Application coalition identities and signing-slot labels must be
 * authenticated by the caller alongside these public inputs.
 */
struct NonceBatchGroup {
    Bytes evaluation_input;
    std::vector<UInt512> hosts;
};

/**
 * @brief Builds a public verifier circuit with one output commitment per group.
 *
 * Group and host order are retained. Each group uses the existing summed-host
 * relation, including its padding; the combined circuit is padded once more
 * to a power of two. No witnesses or completed proofs are needed here.
 * This builds a relation, not a public compression of completed group proofs.
 */
Result<NativeBulletproofCircuit> nonce_batch_circuit(
    std::span<const NonceBatchGroup> groups);

/**
 * @brief Validates and combines member assignments for nonce_batch_circuit.
 *
 * assignments[g][i] belongs to groups[g].hosts[i] for that group's exact
 * evaluation input. The caller receives all private witnesses and summed
 * output scalars; this is a centralized prover helper, not an MPC interface
 * or an operation for a public certificate assembler.
 */
Result<BulletproofAssignmentData> nonce_batch_assignments(
    std::span<const NonceBatchGroup> groups,
    std::span<const std::vector<BulletproofAssignmentData>> assignments);

} // namespace purify
