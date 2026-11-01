// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <utility>

#include "purify/puresign/anchor_escrow_accumulation.hpp"
#include "purify/puresign/recovery_root_accumulation.hpp"

namespace purify::accountable {

/**
 * The fixed accumulation bases for one coalition construction receipt.
 *
 * Setup proofs use a smaller production circuit than anchor escrow proofs.
 * promote_setup_claim() embeds their pending obligations into the prefix of
 * the anchor basis. This is only a basis transition: the setup reduction and
 * every later transition remain mandatory parts of the authenticated receipt
 * ancestry, and the final claim must still pass decide().
 */
class ConstructionReceiptAccumulator {
public:
    static constexpr std::size_t kRootClaimSerializedSize =
        33 + 32 + 15 * 32;

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

    /**
     * Rebind a pending setup claim to the larger construction basis.
     *
     * The deterministic target generators must have the complete setup basis
     * as an exact prefix. No proof obligation is discharged by this method.
     */
    [[nodiscard]] Result<bppp::accumulation::PendingClaim>
    promote_setup_claim(
        const bppp::accumulation::PendingClaim& setup_claim) const;

private:
    ConstructionReceiptAccumulator(
        RecoveryRootSetupAccumulator setup,
        AnchorEscrowAccumulator anchors)
        : setup_(std::move(setup)), anchors_(std::move(anchors)) {}

    RecoveryRootSetupAccumulator setup_;
    AnchorEscrowAccumulator anchors_;
};

} // namespace purify::accountable
