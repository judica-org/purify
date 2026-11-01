// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <span>
#include <utility>

#include "purify/puresign/construction_receipt.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"

namespace purify::accountable {

/**
 * Canonical transport for one candidate construction receipt.
 *
 * Encoding is payload || root_claim || parent_proof with no additional
 * framing. The payload entry count fixes its size, the receipt version fixes
 * the root size, and the remaining bytes are the parent proof. Parsing only
 * establishes canonical transport. Acceptance still requires the exact
 * purpose parent verifier and a successful final accumulation decision.
 */
class ConstructionReceiptEnvelope {
public:
    static constexpr std::size_t kMaximumParentProofSize = 4096;

    [[nodiscard]] static Result<ConstructionReceiptEnvelope> create(
        ConstructionReceiptPayload payload,
        Bytes root_claim,
        Bytes parent_proof,
        const ConstructionReceiptAccumulator& accumulator,
        purify_secp_context* secp_context);

    [[nodiscard]] static Result<ConstructionReceiptEnvelope> deserialize(
        std::span<const unsigned char> encoded,
        const ConstructionReceiptAccumulator& accumulator,
        purify_secp_context* secp_context);

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] std::size_t serialized_size() const noexcept;

    [[nodiscard]] const ConstructionReceiptPayload& payload() const noexcept {
        return payload_;
    }

    [[nodiscard]] const Bytes& root_claim() const noexcept {
        return root_claim_;
    }

    [[nodiscard]] const Bytes& parent_proof() const noexcept {
        return parent_proof_;
    }

private:
    ConstructionReceiptEnvelope(ConstructionReceiptPayload payload,
                                Bytes root_claim,
                                Bytes parent_proof)
        : payload_(std::move(payload)),
          root_claim_(std::move(root_claim)),
          parent_proof_(std::move(parent_proof)) {}

    ConstructionReceiptPayload payload_;
    Bytes root_claim_;
    Bytes parent_proof_;
};

} // namespace purify::accountable
