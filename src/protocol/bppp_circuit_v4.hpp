// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_circuit_v4.hpp
 * @brief V4 statement binding shared by the V4 prover and verifier.
 */

#pragma once

#include <span>

#include "algebraic_circuit_proof.hpp"
#include "bppp_circuit_reduction.hpp"
#include "purify/bppp.hpp"

namespace purify::bppp {

namespace detail {

Result<candidate::CircuitTranscriptShapeV4> circuit_shape_v4(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments);

Result<candidate::TranscriptDigest> circuit_binding_digest_v4(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding);

Status validate_circuit_proof_v4_inputs(
    const NativeBulletproofCircuit &circuit,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments);

} // namespace detail

} // namespace purify::bppp
