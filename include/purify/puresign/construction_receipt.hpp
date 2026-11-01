// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file construction_receipt.hpp
 * @brief Canonical public statement for a coalition construction receipt.
 */

#pragma once

#include "purify/puresign/anchor_escrow.hpp"

namespace purify::accountable {

using AnchorReference = std::array<unsigned char, 32>;
using ConstructionReceiptStatementDigest = std::array<unsigned char, 32>;

/** @brief One ordered anchor ciphertext in a construction receipt. */
struct ConstructionReceiptEntry {
    AnchorEscrowCiphertext ciphertext{};
};

/**
 * @brief Canonical public payload for a coalition construction receipt.
 *
 * This type commits to public inputs only. It is not a proof and does not
 * represent proof acceptance. The recovery root identifies the coalition
 * setup in the authenticated registry. Anchor identities are supplied by the
 * deterministic surrounding construction context and are bound by
 * construction_receipt_statement_digest(). They are deliberately not
 * duplicated in the on-chain payload.
 */
class ConstructionReceiptPayload {
public:
    static constexpr unsigned char kSerializationVersion = 1;
    static constexpr std::size_t kFixedHeaderSize = 1 + 64 + 4;
    static constexpr std::size_t kEntrySize = 192;

    [[nodiscard]] static Result<ConstructionReceiptPayload> create(
        UInt512 recovery_root,
        std::vector<ConstructionReceiptEntry> entries);

    [[nodiscard]] Bytes serialize() const;

    [[nodiscard]] static Result<ConstructionReceiptPayload> deserialize(
        std::span<const unsigned char> encoded);

    [[nodiscard]] const UInt512& recovery_root() const noexcept {
        return recovery_root_;
    }

    [[nodiscard]] std::span<const ConstructionReceiptEntry>
    entries() const noexcept {
        return entries_;
    }

    [[nodiscard]] std::size_t serialized_size() const noexcept {
        return kFixedHeaderSize + entries_.size() * kEntrySize;
    }

private:
    ConstructionReceiptPayload(
        UInt512 recovery_root,
        std::vector<ConstructionReceiptEntry> entries)
        : recovery_root_(recovery_root),
          entries_(std::move(entries)) {}

    UInt512 recovery_root_{};
    std::vector<ConstructionReceiptEntry> entries_;
};

/**
 * @brief Registry-resolved public inputs for one ordered anchor entry.
 */
struct ResolvedConstructionReceiptEntry {
    AnchorReference anchor_reference{};
    UInt512 anchor_root{};
    AnchorEscrowContextDigest context_digest{};
};

/**
 * @brief Bind a canonical payload to its ordered, resolved anchor inputs.
 *
 * The digest binds the exact serialized payload followed by each unique
 * anchor reference, exact anchor root, and context digest in deterministic
 * payload order. This operation does not verify an escrow proof or
 * authenticate the referenced setup and anchors.
 */
[[nodiscard]] Result<ConstructionReceiptStatementDigest>
construction_receipt_statement_digest(
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries);

}  // namespace purify::accountable
