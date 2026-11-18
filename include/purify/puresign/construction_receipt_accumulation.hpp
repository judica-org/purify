// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <span>
#include <utility>

#include "purify/puresign/construction_leaf_accumulation.hpp"
#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/recovery_root.hpp"

namespace purify::accountable {

/**
 * Registry-resolved public context for one distributed construction receipt.
 *
 * This weak capability does not authenticate any contribution proof and does
 * not authorize anchor escrow. It supplies only the exact public context from
 * which a parent verifier derives setup and anchor leaf descriptors.
 */
class ResolvedConstructionSetup {
public:
    ResolvedConstructionSetup(const ResolvedConstructionSetup&) = delete;
    ResolvedConstructionSetup& operator=(
        const ResolvedConstructionSetup&) = delete;
    ResolvedConstructionSetup(ResolvedConstructionSetup&&) noexcept =
        default;
    ResolvedConstructionSetup& operator=(
        ResolvedConstructionSetup&&) noexcept = default;

    [[nodiscard]] static Result<ResolvedConstructionSetup> create(
        NonceHostBoundSigningRoster roster,
        CoalitionFormation formation,
        UInt512 recovery_root,
        ResolvedConstructionSetupDigest resolved_digest);

    [[nodiscard]] const NonceHostBoundSigningRoster& roster()
        const noexcept {
        return roster_;
    }

    [[nodiscard]] const CoalitionFormation& formation() const noexcept {
        return formation_;
    }

    [[nodiscard]] const UInt512& recovery_root() const noexcept {
        return recovery_root_;
    }

    [[nodiscard]] const ResolvedConstructionSetupDigest& resolved_digest()
        const noexcept {
        return resolved_digest_;
    }

private:
    ResolvedConstructionSetup(
        NonceHostBoundSigningRoster roster,
        CoalitionFormation formation,
        UInt512 recovery_root,
        ResolvedConstructionSetupDigest resolved_digest)
        : roster_(std::move(roster)),
          formation_(std::move(formation)),
          recovery_root_(recovery_root),
          resolved_digest_(std::move(resolved_digest)) {}

    NonceHostBoundSigningRoster roster_;
    CoalitionFormation formation_;
    UInt512 recovery_root_{};
    ResolvedConstructionSetupDigest resolved_digest_;
};

/**
 * The one homogeneous accumulation basis for construction receipt leaves.
 */
class ConstructionReceiptAccumulator {
public:
    static constexpr std::size_t kRootClaimRounds = std::bit_width(
        2 * ConstructionLeafAccumulator::kNormVectorLength) - 1;
    static constexpr std::size_t kRootClaimSerializedSize =
        33 + 32 + kRootClaimRounds * 32;
    static_assert(kRootClaimSerializedSize == 545);

    ConstructionReceiptAccumulator(const ConstructionReceiptAccumulator&) =
        delete;
    ConstructionReceiptAccumulator& operator=(
        const ConstructionReceiptAccumulator&) = delete;
    ConstructionReceiptAccumulator(
        ConstructionReceiptAccumulator&&) noexcept = default;
    ConstructionReceiptAccumulator& operator=(
        ConstructionReceiptAccumulator&&) noexcept = default;

    [[nodiscard]] static Result<ConstructionReceiptAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const ConstructionLeafAccumulator& leaves()
        const noexcept {
        return leaves_;
    }

private:
    explicit ConstructionReceiptAccumulator(
        ConstructionLeafAccumulator leaves)
        : leaves_(std::move(leaves)) {}

    ConstructionLeafAccumulator leaves_;
};

} // namespace purify::accountable
