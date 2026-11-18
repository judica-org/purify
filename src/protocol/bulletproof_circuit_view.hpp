// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <span>

#include "purify/bulletproof.hpp"

namespace purify::detail {

/** Borrows a shape-checked circuit for algorithms that only read its rows. */
template <typename Left, typename Right, typename Output, typename Commitment>
struct CircuitView {
    std::size_t gate_count;
    std::size_t commitment_count;
    std::size_t bit_count;
    std::span<const FieldElement> constants;
    Left left_entries;
    Right right_entries;
    Output output_entries;
    Commitment commitment_entries;
};

inline auto circuit_view(const NativeBulletproofCircuit& circuit) noexcept {
    const auto entries = [](std::span<const NativeBulletproofCircuitRow> rows) {
        return [rows](std::size_t i) -> std::span<const NativeBulletproofCircuitTerm> {
            return rows[i].entries;
        };
    };
    return CircuitView{circuit.n_gates, circuit.n_commitments, circuit.n_bits, circuit.c,
                       entries(circuit.wl), entries(circuit.wr), entries(circuit.wo), entries(circuit.wv)};
}

inline auto circuit_view(const NativeBulletproofCircuit::PackedWithSlack& circuit) noexcept {
    return CircuitView{
        circuit.n_gates(), circuit.n_commitments(), circuit.n_bits(), circuit.constants(),
        [&circuit](std::size_t i) { return circuit.left_row(i).entries_view(); },
        [&circuit](std::size_t i) { return circuit.right_row(i).entries_view(); },
        [&circuit](std::size_t i) { return circuit.output_row(i).entries_view(); },
        [&circuit](std::size_t i) { return circuit.commitment_row(i).entries_view(); },
    };
}

}  // namespace purify::detail
