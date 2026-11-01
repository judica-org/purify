// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "algebraic_circuit_proof.hpp"
#include "purify/accumulation.hpp"

namespace purify::bppp::accumulation {

/**
 * Convert an outer-authenticated V4 proof into its algebraic norm obligation.
 *
 * This consumes a value returned by a V4 prepare function and authenticates
 * its exact raw-generator bridge. The purpose-owned caller selects the Basis
 * semantic digest. This does not accept the child proof: the caller must
 * verify the coefficient reduction and call decide() on the pending claim.
 */
[[nodiscard]] Result<AlgebraicPreparedNorm>
prepare_v4_circuit_norm_for_algebraic_reduction(
    const Basis &basis, candidate::PreparedCircuitZkNormArgV4 prepared,
    purify_secp_context *secp_context);

} // namespace purify::bppp::accumulation
