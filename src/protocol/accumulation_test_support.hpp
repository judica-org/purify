// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/accumulation.hpp"

namespace purify::bppp::accumulation::test_support {

/**
 * Returns the short-verifier residual without accepting the step.
 *
 * This symbol exists only when Purify is built with its test suite.
 */
[[nodiscard]] Result<PointBytes> algebraic_step_equation_residual(
    const Basis& basis, std::span<const PendingClaim> claims,
    const AlgebraicStepProof& proof, purify_secp_context* context);

} // namespace purify::bppp::accumulation::test_support
