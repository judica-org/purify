// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <bit>
#include <cstddef>
#include <utility>

#include "purify/puresign/anchor_escrow_accumulation.hpp"
#include "purify/puresign/recovery_root_accumulation.hpp"

namespace purify::accountable {

/**
 * The fixed accumulation bases for one coalition construction receipt.
 *
 * Setup proofs use a smaller production circuit than anchor escrow proofs.
 * verify_setup_reduction() authenticates the exact setup statement and embeds
 * its pending obligation into the prefix of the anchor basis. This is only a
 * basis transition: the setup reduction and every later transition remain
 * mandatory parts of the authenticated receipt ancestry, and the final claim
 * must still pass decide().
 */
class ConstructionReceiptAccumulator {
public:
    static constexpr std::size_t kRootClaimRounds = std::bit_width(
        2 * AnchorEscrowAccumulator::kNormVectorLength) - 1;
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

    [[nodiscard]] const RecoveryRootSetupAccumulator& setup() const noexcept {
        return setup_;
    }

    [[nodiscard]] const AnchorEscrowAccumulator& anchors() const noexcept {
        return anchors_;
    }

    [[nodiscard]] Result<bppp::accumulation::PendingClaim>
    verify_setup_reduction(
        const NonceHostBoundSigningRoster& roster,
        const UInt512& recovery_root,
        const RecoveryRootSetupProof& setup_proof,
        const bppp::accumulation::NormReductionProof& reduction,
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
