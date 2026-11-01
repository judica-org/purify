// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_receipt_assembly.hpp"

#include <algorithm>
#include <utility>

namespace purify::accountable {
namespace {

bool same_ciphertext(const AnchorEscrowCiphertext& left,
                     const AnchorEscrowCiphertext& right) {
    return left.ephemeral_keys == right.ephemeral_keys &&
           left.masked_scalars == right.masked_scalars;
}

} // namespace

Result<ConstructionReceiptAssembly> ConstructionReceiptAssembly::create(
    PendingConstructionSetup setup,
    ConstructionReceiptPayload payload,
    std::vector<ResolvedConstructionReceiptEntry> resolved_entries) {
    if (payload.recovery_root() != setup.recovery_root()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "construction_assembly:setup_recovery_root");
    }
    if (payload.entries().size() != resolved_entries.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "construction_assembly:manifest_size");
    }
    for (std::size_t i = 0; i < resolved_entries.size(); ++i) {
        for (std::size_t prior = 0; prior < i; ++prior) {
            if (resolved_entries[prior].anchor_reference ==
                resolved_entries[i].anchor_reference) {
                return unexpected_error(
                    ErrorCode::BindingMismatch,
                    "construction_assembly:duplicate_anchor_reference");
            }
            if (resolved_entries[prior].anchor_root ==
                resolved_entries[i].anchor_root) {
                return unexpected_error(
                    ErrorCode::BindingMismatch,
                    "construction_assembly:duplicate_anchor_root");
            }
        }
    }
    return ConstructionReceiptAssembly(
        std::move(setup), std::move(payload),
        std::move(resolved_entries));
}

Result<bppp::accumulation::PendingClaim>
ConstructionReceiptAssembly::verify_anchor_reduction(
    std::size_t index,
    const ConstructionReceiptAccumulator& accumulator,
    const RecoveryBoundSigningRoster& roster,
    const AnchorEscrowRecord& record,
    const bppp::accumulation::NormReductionProof& reduction,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    if (index >= anchor_claims_.size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "construction_assembly:anchor_index");
    }
    if (anchor_claims_[index].has_value()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_assembly:duplicate_anchor");
    }
    if (!same_ciphertext(payload_.entries()[index].ciphertext,
                         record.ciphertext())) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "construction_assembly:anchor_ciphertext");
    }
    const auto& resolved = resolved_entries_[index];
    PURIFY_ASSIGN_OR_RETURN(
        auto pending,
        accumulator.verify_anchor_reduction(
            setup_, roster, resolved.anchor_root,
            resolved.context_digest, record, reduction,
            secp_context, cache),
        "construction_assembly:anchor_reduction");
    anchor_claims_[index] = pending;
    return pending;
}

Result<std::vector<bppp::accumulation::PendingClaim>>
ConstructionReceiptAssembly::ordered_leaves() const {
    if (std::any_of(
            anchor_claims_.begin(), anchor_claims_.end(),
            [](const auto& claim) { return !claim.has_value(); })) {
        return unexpected_error(ErrorCode::MissingValue,
                                "construction_assembly:missing_anchor");
    }
    std::vector<bppp::accumulation::PendingClaim> leaves;
    leaves.reserve(anchor_claims_.size() + 1);
    leaves.push_back(setup_.claim());
    for (const auto& claim : anchor_claims_) {
        leaves.push_back(*claim);
    }
    return leaves;
}

} // namespace purify::accountable
