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
using ResolvedConstructionSetupDigestBytes =
    std::array<unsigned char, 32>;

/**
 * @brief Immutable registry-record digest selected by a recovery root.
 *
 * The registry preimage must include the recovery root, exact ordered roster,
 * coalition core, nonce-host commitment, setup context, and registry schema
 * version. Zero is reserved for an unresolved setup and cannot be bound into a
 * construction statement.
 */
class ResolvedConstructionSetupDigest {
public:
    static constexpr std::size_t kSerializedSize = 32;

    [[nodiscard]] static Result<ResolvedConstructionSetupDigest> create(
        const ResolvedConstructionSetupDigestBytes& digest);

    [[nodiscard]] const ResolvedConstructionSetupDigestBytes& bytes()
        const noexcept {
        return digest_;
    }

private:
    explicit ResolvedConstructionSetupDigest(
        ResolvedConstructionSetupDigestBytes digest)
        : digest_(digest) {}

    ResolvedConstructionSetupDigestBytes digest_{};
};

/** @brief One ordered anchor ciphertext and its exact V4 precommitment. */
struct ConstructionReceiptEntry {
    AnchorEscrowCiphertext ciphertext{};
    bppp::ScalarBytes circuit_precommitment{};
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
    static constexpr unsigned char kSerializationVersion = 2;
    static constexpr std::size_t kFixedHeaderSize = 1 + 64 + 4;
    static constexpr std::size_t kEntrySize =
        AnchorEscrowCiphertext::kSerializedSize +
        bppp::ScalarBytes{}.size();
    static_assert(kEntrySize == 224);

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
 *
 * Construction requires a validated punishment-key type so an unresolved or
 * malformed x-only key cannot enter the authenticated receipt statement.
 */
struct ResolvedConstructionReceiptEntry {
    ResolvedConstructionReceiptEntry(
        AnchorReference reference, UInt512 root,
        AnchorPunishmentPublicKey punishment,
        AnchorEscrowContextDigest context)
        : anchor_reference(reference), anchor_root(root),
          punishment_key(std::move(punishment)),
          context_digest(context) {}

    AnchorReference anchor_reference;
    UInt512 anchor_root;
    AnchorPunishmentPublicKey punishment_key;
    AnchorEscrowContextDigest context_digest;
};

/**
 * @brief Bind a canonical payload to its ordered, resolved anchor inputs.
 *
 * The digest binds the exact serialized payload, its registry-resolved setup
 * record digest, then each unique anchor reference, exact anchor root,
 * punishment key, and context digest in deterministic payload order. The
 * registry must resolve a
 * recovery root immutably and one-to-one to the exact setup record whose
 * digest is supplied here. This operation does not verify an escrow proof or
 * authenticate the registry lookup and referenced anchors.
 */
[[nodiscard]] Result<ConstructionReceiptStatementDigest>
construction_receipt_statement_digest(
    const ConstructionReceiptPayload& payload,
    const ResolvedConstructionSetupDigest& resolved_setup,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries);

}  // namespace purify::accountable
