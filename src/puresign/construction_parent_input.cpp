// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "construction_parent_input_internal.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace purify::accountable::detail {
namespace {

template <std::size_t N>
void append(std::vector<unsigned char>& output,
            const std::array<unsigned char, N>& bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

Status append_constants(
    std::vector<unsigned char>& descriptors,
    const ConstructionLeafParentConstants& constants,
    const bppp::ScalarBytes& circuit_precommitment,
    std::array<unsigned char, 32>& raw_generator_digest,
    bool& have_raw_generator_digest) {
    if (have_raw_generator_digest &&
        raw_generator_digest != constants.raw_generator_digest) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "construction_parent:raw_generator_digest");
    }
    raw_generator_digest = constants.raw_generator_digest;
    have_raw_generator_digest = true;
    append(descriptors, constants.circuit_binding_digest);
    append(descriptors, circuit_precommitment);
    append(descriptors, constants.coefficient_commitment);
    append(descriptors, constants.anchored_offset);
    return {};
}

} // namespace

Result<ResolvedConstructionParentPublicInputs>
resolve_construction_parent_public_inputs(
    const ResolvedConstructionSetup& setup,
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
    const ConstructionLeafAccumulator& leaves,
    purify_secp_context* secp_context) {
    if (payload.recovery_root() != setup.recovery_root()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_parent:recovery_root");
    }
    const auto setup_entries = payload.setup_entries();
    const auto anchor_entries = payload.anchor_entries();
    if (setup_entries.size() != setup.roster().members().size()) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "construction_parent:setup_count");
    }
    if (!size_fits_u32(setup_entries.size()) ||
        !size_fits_u32(anchor_entries.size())) {
        return unexpected_error(ErrorCode::UnexpectedSize,
                                "construction_parent:leaf_count");
    }

    std::vector<RecoveryRootShare> setup_shares;
    setup_shares.reserve(setup_entries.size());
    for (const auto& entry : setup_entries) {
        setup_shares.push_back(entry.share);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto aggregate,
        aggregate_recovery_root_shares(setup_shares),
        "construction_parent:setup_aggregate");
    if (aggregate.recovery_root() != setup.recovery_root()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_parent:setup_root");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto statement_digest,
        construction_receipt_statement_digest(
            payload, setup.resolved_digest(), resolved_entries),
        "construction_parent:statement");

    std::size_t leaf_count = 0;
    if (!checked_add_size(setup_entries.size(), anchor_entries.size(),
                          leaf_count) ||
        leaf_count >
            std::numeric_limits<std::size_t>::max() /
                kConstructionParentDescriptorSize) {
        return unexpected_error(ErrorCode::Overflow,
                                "construction_parent:descriptors");
    }
    std::vector<unsigned char> descriptors;
    descriptors.reserve(leaf_count * kConstructionParentDescriptorSize);
    std::array<unsigned char, 32> raw_generator_digest{};
    bool have_raw_generator_digest = false;

    for (std::size_t index = 0; index < setup_entries.size(); ++index) {
        const auto& entry = setup_entries[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto constants,
            leaves.derive_parent_constants(
                setup.roster(), setup.formation(), index, entry.share,
                entry.circuit_precommitment, secp_context),
            "construction_parent:setup_constants");
        PURIFY_RETURN_IF_ERROR(
            append_constants(descriptors, constants,
                             entry.circuit_precommitment,
                             raw_generator_digest,
                             have_raw_generator_digest),
            "construction_parent:setup_descriptor");
    }
    for (std::size_t index = 0; index < anchor_entries.size(); ++index) {
        const auto& resolved = resolved_entries[index];
        const auto& entry = anchor_entries[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto constants,
            leaves.derive_pending_anchor_parent_constants(
                setup.roster(), setup.recovery_root(),
                resolved.anchor_root, resolved.punishment_key,
                resolved.context_digest, entry.ciphertext,
                entry.circuit_precommitment, secp_context),
            "construction_parent:anchor_constants");
        PURIFY_RETURN_IF_ERROR(
            append_constants(descriptors, constants,
                             entry.circuit_precommitment,
                             raw_generator_digest,
                             have_raw_generator_digest),
            "construction_parent:anchor_descriptor");
    }

    return ResolvedConstructionParentPublicInputs{
        statement_digest,
        std::move(aggregate),
        std::move(descriptors),
        raw_generator_digest,
        static_cast<std::uint32_t>(setup_entries.size()),
        static_cast<std::uint32_t>(anchor_entries.size())};
}

} // namespace purify::accountable::detail
