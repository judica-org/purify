// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

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
 * entry count fixes its size and the selected native-profile Nova suite fixes
 * the proof size. Parsing only establishes canonical transport. Acceptance
 * still requires exact Rust proof verification and use of its authenticated
 * returned root, followed by native parsing and the final accumulation
 * decision.
 */
class ConstructionReceiptEnvelope {
public:
    /** Exact canonical proof size of the selected native-profile Nova suite. */
    static constexpr std::size_t kParentProofSize = 12'466;

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

} // namespace purify::accountable
