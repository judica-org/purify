// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <span>
#include <utility>

#include "purify/puresign/anchor_escrow_accumulation.hpp"
#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/recovery_root_accumulation.hpp"

namespace purify::accountable {

/**
 * A fully verified setup record resolved to its decided construction seed.
 *
 * This capability can only be created by replaying the public setup proof,
 * its deterministic reduction, the setup-to-anchor basis promotion, the
 * deterministic one-claim step, and the final native decision. Seed bytes
 * alone are not authenticated ancestry and cannot construct this type.
 */
class ResolvedConstructionSetup {
public:
    static constexpr std::size_t kSeedRootSize = 545;

    ResolvedConstructionSetup(const ResolvedConstructionSetup&) = delete;
    ResolvedConstructionSetup& operator=(
        const ResolvedConstructionSetup&) = delete;
    ResolvedConstructionSetup(ResolvedConstructionSetup&&) noexcept =
        default;
    ResolvedConstructionSetup& operator=(
        ResolvedConstructionSetup&&) noexcept = default;

    [[nodiscard]] const RecoveryBoundSigningRoster& roster()
        const noexcept {
        return roster_;
    }

    [[nodiscard]] const ResolvedConstructionSetupDigest& resolved_digest()
        const noexcept {
        return resolved_digest_;
    }

    [[nodiscard]] std::span<const unsigned char> seed_root()
        const noexcept {
        return seed_root_;
    }

private:
    ResolvedConstructionSetup(
        RecoveryBoundSigningRoster roster,
        ResolvedConstructionSetupDigest resolved_digest,
        std::array<unsigned char, kSeedRootSize> seed_root);

    RecoveryBoundSigningRoster roster_;
    ResolvedConstructionSetupDigest resolved_digest_;
    std::array<unsigned char, kSeedRootSize> seed_root_{};

    friend class ConstructionReceiptAccumulator;
};

/**
 * The fixed accumulation bases for one coalition construction receipt.
 *
 * Setup proofs use a smaller selected circuit than anchor escrow proofs. A
 * resolved setup replays its reduction, embeds the pending obligation into the
 * prefix of the anchor basis, and decides the deterministic seed before it is
 * exposed to a construction parent.
 */
class ConstructionReceiptAccumulator {
public:
    static constexpr std::size_t kRootClaimRounds = std::bit_width(
        2 * AnchorEscrowAccumulator::kNormVectorLength) - 1;
    static constexpr std::size_t kRootClaimSerializedSize =
        33 + 32 + kRootClaimRounds * 32;
    static_assert(kRootClaimSerializedSize == 545);
    static_assert(kRootClaimSerializedSize ==
                  ResolvedConstructionSetup::kSeedRootSize);

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

    [[nodiscard]] const AnchorEscrowAccumulator& anchors() const noexcept {
        return anchors_;
    }

    /**
     * Verifies one public setup record through a decided construction seed.
     *
     * The deterministic reduction and one-claim step are local replay data;
     * only the decided seed state is retained. The caller-supplied digest is
     * the authenticated registry identity and is owned by the result.
     */
    [[nodiscard]] Result<ResolvedConstructionSetup>
    resolve_setup_record(
        NonceHostBoundSigningRoster roster,
        const UInt512& recovery_root,
        const RecoveryRootSetupProof& setup_proof,
        ResolvedConstructionSetupDigest resolved_digest,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

private:
    ConstructionReceiptAccumulator(
        RecoveryRootSetupAccumulator setup,
        AnchorEscrowAccumulator anchors)
        : setup_(std::move(setup)), anchors_(std::move(anchors)) {}

    [[nodiscard]] Result<bppp::accumulation::PendingClaim>
    promote_setup_claim(
        const bppp::accumulation::PendingClaim& setup_claim) const;

    RecoveryRootSetupAccumulator setup_;
    AnchorEscrowAccumulator anchors_;
};

} // namespace purify::accountable
