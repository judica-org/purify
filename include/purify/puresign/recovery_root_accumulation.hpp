// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <utility>

#include "purify/accumulation.hpp"
#include "purify/puresign/recovery_root.hpp"

namespace purify::accountable {

/**
 * Fixed-basis adapter for a production recovery-root setup proof.
 *
 * prepare() reconstructs the exact setup circuit, public signing-key output,
 * and transcript binding. The result remains a pending norm obligation until
 * its reduction and every later transition are verified and decided.
 */
class RecoveryRootSetupAccumulator {
public:
    static constexpr std::size_t kNormVectorLength = 4096;

    RecoveryRootSetupAccumulator(const RecoveryRootSetupAccumulator&) =
        delete;
    RecoveryRootSetupAccumulator& operator=(
        const RecoveryRootSetupAccumulator&) = delete;
    RecoveryRootSetupAccumulator(
        RecoveryRootSetupAccumulator&&) noexcept = default;
    RecoveryRootSetupAccumulator& operator=(
        RecoveryRootSetupAccumulator&&) noexcept = default;

    [[nodiscard]] static Result<RecoveryRootSetupAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const bppp::accumulation::Basis& basis() const noexcept {
        return basis_;
    }

    [[nodiscard]] Result<bppp::accumulation::PreparedNorm> prepare(
        const NonceHostBoundSigningRoster& roster,
        const UInt512& recovery_root,
        const RecoveryRootSetupProof& proof,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

private:
    explicit RecoveryRootSetupAccumulator(
        bppp::accumulation::Basis basis)
        : basis_(std::move(basis)) {}

    bppp::accumulation::Basis basis_;
};

} // namespace purify::accountable
