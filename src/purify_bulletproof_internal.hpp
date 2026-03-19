// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/bulletproof.hpp"

namespace purify {

Result<ExperimentalBulletproofProof> prove_experimental_circuit_assume_valid(
    const NativeBulletproofCircuit::PackedWithSlack& circuit,
    const BulletproofAssignmentData& assignment,
    const BulletproofScalarBytes& nonce,
    const BulletproofGeneratorBytes& value_generator,
    std::span<const unsigned char> statement_binding = {},
    std::optional<BulletproofScalarBytes> blind = std::nullopt);

}  // namespace purify
