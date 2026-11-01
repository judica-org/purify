// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"

namespace purify::accountable {

/**
 * Typed native assembly of one exact construction manifest.
 *
 * This object prevents setup, payload, manifest, and anchor leaves from being
 * spliced accidentally. It still produces pending accumulator obligations,
 * never proof acceptance. A purpose-specific parent must authenticate the
 * exact ordered ancestry and the final root must pass decide().
 */
class ConstructionReceiptAssembly {
public:
    ConstructionReceiptAssembly(const ConstructionReceiptAssembly&) = delete;
    ConstructionReceiptAssembly& operator=(
        const ConstructionReceiptAssembly&) = delete;
    ConstructionReceiptAssembly(ConstructionReceiptAssembly&&) noexcept =
        default;
    ConstructionReceiptAssembly& operator=(
        ConstructionReceiptAssembly&&) noexcept = default;

    [[nodiscard]] static Result<ConstructionReceiptAssembly> create(
        PendingConstructionSetup setup,
        ConstructionReceiptPayload payload,
        ResolvedConstructionSetupDigest resolved_setup,
        std::vector<ResolvedConstructionReceiptEntry> resolved_entries);

    [[nodiscard]] Result<bppp::accumulation::PendingClaim>
    verify_anchor_reduction(
        std::size_t index,
        const ConstructionReceiptAccumulator& accumulator,
        const RecoveryBoundSigningRoster& roster,
        const AnchorEscrowRecord& record,
        const bppp::accumulation::NormReductionProof& reduction,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr);

    /** Setup first, followed by every anchor in exact payload order. */
    [[nodiscard]] Result<std::vector<bppp::accumulation::PendingClaim>>
    ordered_leaves() const;

    [[nodiscard]] const PendingConstructionSetup& setup() const noexcept {
        return setup_;
    }

    [[nodiscard]] const ConstructionReceiptPayload& payload() const noexcept {
        return payload_;
    }

    [[nodiscard]] const ResolvedConstructionSetupDigest& resolved_setup()
        const noexcept {
        return resolved_setup_;
    }

    [[nodiscard]] const ConstructionReceiptStatementDigest&
    statement_digest() const noexcept {
        return statement_digest_;
    }

    [[nodiscard]] std::span<const ResolvedConstructionReceiptEntry>
    resolved_entries() const noexcept {
        return resolved_entries_;
    }

private:
    ConstructionReceiptAssembly(
        PendingConstructionSetup setup,
        ConstructionReceiptPayload payload,
        ResolvedConstructionSetupDigest resolved_setup,
        std::vector<ResolvedConstructionReceiptEntry> resolved_entries,
        ConstructionReceiptStatementDigest statement_digest)
        : setup_(std::move(setup)),
          payload_(std::move(payload)),
          resolved_setup_(std::move(resolved_setup)),
          resolved_entries_(std::move(resolved_entries)),
          statement_digest_(statement_digest),
          anchor_claims_(resolved_entries_.size()) {}

    PendingConstructionSetup setup_;
    ConstructionReceiptPayload payload_;
    ResolvedConstructionSetupDigest resolved_setup_;
    std::vector<ResolvedConstructionReceiptEntry> resolved_entries_;
    ConstructionReceiptStatementDigest statement_digest_{};
    std::vector<std::optional<bppp::accumulation::PendingClaim>>
        anchor_claims_;
};

} // namespace purify::accountable
