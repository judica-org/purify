// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <utility>

#include "purify/accumulation.hpp"
#include "purify/puresign/anchor_escrow.hpp"

namespace purify::accountable {

/**
 * Fixed-basis adapter for accumulating production anchor-escrow proofs.
 *
 * The private constructor prevents callers from substituting another circuit
 * family or semantic basis. prepare() reconstructs the exact escrow circuit
 * and transcript binding from the typed public statement. Its result remains
 * a pending norm obligation: the reduction, every accumulation transition,
 * and the final decide() call are all mandatory for proof acceptance.
 */
class AnchorEscrowAccumulator {
public:
    static constexpr std::size_t kNormVectorLength = 16384;

    AnchorEscrowAccumulator(const AnchorEscrowAccumulator&) = delete;
    AnchorEscrowAccumulator& operator=(const AnchorEscrowAccumulator&) =
        delete;
    AnchorEscrowAccumulator(AnchorEscrowAccumulator&&) noexcept = default;
    AnchorEscrowAccumulator& operator=(AnchorEscrowAccumulator&&) noexcept =
        default;

    [[nodiscard]] static Result<AnchorEscrowAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const bppp::accumulation::Basis& basis() const noexcept {
        return basis_;
    }

    [[nodiscard]] Result<bppp::accumulation::PreparedNorm> prepare(
        const RecoveryBoundSigningRoster& roster,
        const UInt512& advertised_anchor_root,
        const AnchorEscrowContextDigest& context_digest,
        const AnchorEscrowRecord& record,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

private:
    explicit AnchorEscrowAccumulator(bppp::accumulation::Basis basis)
        : basis_(std::move(basis)) {}

    bppp::accumulation::Basis basis_;
};

} // namespace purify::accountable
