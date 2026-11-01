// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/accumulation.hpp"

namespace purify::bppp::accumulation::internal {

/** Test-only escape hatch for algebraic transcript fixtures. */
struct UnsafeAlgebraicPreparedNormTestAccess {
    static AlgebraicPreparedNorm bind(
        const PreparedNorm& prepared, FieldElement prepared_binding) {
        return AlgebraicPreparedNorm(
            prepared.basis_digest(), prepared_binding,
            prepared.c_vec(), prepared.coefficient_commitment(),
            prepared.residual(), prepared.polynomial());
    }
};

} // namespace purify::bppp::accumulation::internal

namespace purify::bppp::accumulation {

inline AlgebraicPreparedNorm
unsafe_bind_algebraic_prepared_norm_for_test(
    const PreparedNorm& prepared, FieldElement prepared_binding) {
    return internal::UnsafeAlgebraicPreparedNormTestAccess::bind(
        prepared, prepared_binding);
}

} // namespace purify::bppp::accumulation
