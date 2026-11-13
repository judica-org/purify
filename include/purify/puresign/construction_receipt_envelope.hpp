// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file construction_receipt_envelope.hpp
 * @brief Canonical transport for a construction receipt parent proof.
 */

#pragma once

#include <cstddef>
#include <span>
#include <utility>

#include "purify/puresign/construction_receipt.hpp"

namespace purify::accountable {

/**
 * Canonical transport for one candidate construction receipt.
 *
 * Encoding is payload || parent_proof with no additional framing. The payload
 * entry count fixes its size and the selected SHA-256 Nova suite fixes the
 * proof size. Parsing only establishes canonical transport. Acceptance still
 * requires exact recursive proof verification and native final decision.
 */
class ConstructionReceiptEnvelope {
public:
    /** Exact proof size fixed by the mixed SHA-256 qualification. */
    static constexpr std::size_t kParentProofSize = 15'076;

    [[nodiscard]] static Result<ConstructionReceiptEnvelope> create(
        ConstructionReceiptPayload payload,
        Bytes parent_proof);

    [[nodiscard]] static Result<ConstructionReceiptEnvelope> deserialize(
        std::span<const unsigned char> encoded);

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] std::size_t serialized_size() const noexcept;

    [[nodiscard]] const ConstructionReceiptPayload& payload() const noexcept {
        return payload_;
    }

    [[nodiscard]] const Bytes& parent_proof() const noexcept {
        return parent_proof_;
    }

private:
    ConstructionReceiptEnvelope(ConstructionReceiptPayload payload,
                                Bytes parent_proof)
        : payload_(std::move(payload)),
          parent_proof_(std::move(parent_proof)) {}

    ConstructionReceiptPayload payload_;
    Bytes parent_proof_;
};

}  // namespace purify::accountable
