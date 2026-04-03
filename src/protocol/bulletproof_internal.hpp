// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/bulletproof.hpp"

namespace purify {

Bytes experimental_circuit_binding_digest(
    const NativeBulletproofCircuit& circuit,
    std::span<const unsigned char> statement_binding = {});

Bytes experimental_circuit_binding_digest(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    std::span<const unsigned char> statement_binding = {});

Result<ExperimentalBulletproofProof> prove_experimental_circuit_assume_valid(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    purify_secp_context* secp_context,
    std::span<const unsigned char> statement_binding = {},
    std::optional<BulletproofScalarBytes> blind = std::nullopt,
    ExperimentalBulletproofBackendCache* backend_cache = nullptr);

}  // namespace purify
