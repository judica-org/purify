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

/** Pending setup obligation bound to one exact coalition roster and root. */
class PendingConstructionSetup {
public:
    PendingConstructionSetup(const PendingConstructionSetup&) = delete;
    PendingConstructionSetup& operator=(const PendingConstructionSetup&) =
        delete;
    PendingConstructionSetup(PendingConstructionSetup&&) noexcept = default;
    PendingConstructionSetup& operator=(
        PendingConstructionSetup&&) noexcept = default;

    [[nodiscard]] const bppp::accumulation::PendingClaim& claim()
        const noexcept {
        return claim_;
    }

    [[nodiscard]] const UInt512& recovery_root() const noexcept {
        return recovery_root_;
    }

private:
    PendingConstructionSetup(NonceHostBoundSigningRoster roster,
                             UInt512 recovery_root,
                             bppp::accumulation::PendingClaim claim)
        : roster_(std::move(roster)),
          recovery_root_(recovery_root),
          claim_(std::move(claim)) {}

    NonceHostBoundSigningRoster roster_;
    UInt512 recovery_root_;
    bppp::accumulation::PendingClaim claim_;

    friend class ConstructionReceiptAccumulator;
};

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

    [[nodiscard]] Result<PendingConstructionSetup>
    verify_setup_reduction(
        const NonceHostBoundSigningRoster& roster,
        const UInt512& recovery_root,
        const RecoveryRootSetupProof& setup_proof,
        const bppp::accumulation::NormReductionProof& reduction,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

    [[nodiscard]] Result<bppp::accumulation::PendingClaim>
    verify_anchor_reduction(
        const PendingConstructionSetup& setup,
        const RecoveryBoundSigningRoster& roster,
        const UInt512& advertised_anchor_root,
        const AnchorEscrowContextDigest& context_digest,
        const AnchorEscrowRecord& record,
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
