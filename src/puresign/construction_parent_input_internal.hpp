// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "purify/puresign/construction_receipt_accumulation.hpp"

namespace purify::accountable::detail {

inline constexpr std::size_t kConstructionParentDescriptorSize =
    32 + 32 + 33 + 33;

/** Public inputs shared verbatim by the formatter and recursive verifier. */
struct ResolvedConstructionParentPublicInputs {
    ConstructionReceiptStatementDigest statement_digest{};
    RecoveryRootShareAggregate aggregate;
    std::vector<unsigned char> descriptors;
    std::array<unsigned char, 32> raw_generator_digest{};
    std::uint32_t setup_count{};
    std::uint32_t anchor_count{};
};

[[nodiscard]] Result<ResolvedConstructionParentPublicInputs>
resolve_construction_parent_public_inputs(
    const ResolvedConstructionSetup& setup,
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
    const ConstructionLeafAccumulator& leaves,
    purify_secp_context* secp_context);

} // namespace purify::accountable::detail
