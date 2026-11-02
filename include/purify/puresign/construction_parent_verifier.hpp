// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file construction_parent_verifier.hpp
 * @brief Accepted construction receipts under the selected recursive suite.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "purify/puresign/construction_receipt_accumulation.hpp"
#include "purify/puresign/construction_receipt_envelope.hpp"

#if defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)

namespace purify::accountable {

/**
 * A construction receipt whose recursive ancestry and final native equation
 * have both been verified.
 *
 * This capability intentionally exposes no pending accumulation root.
 */
class VerifiedConstructionReceipt {
public:
    [[nodiscard]] const ConstructionReceiptStatementDigest&
    statement_digest() const noexcept {
        return statement_digest_;
    }

    [[nodiscard]] std::uint32_t anchor_count() const noexcept {
        return anchor_count_;
    }

private:
    VerifiedConstructionReceipt(
        ConstructionReceiptStatementDigest statement_digest,
        std::uint32_t anchor_count)
        : statement_digest_(statement_digest),
          anchor_count_(anchor_count) {}

    ConstructionReceiptStatementDigest statement_digest_{};
    std::uint32_t anchor_count_{};

    friend class ConstructionParentVerifier;
};

/** The one locally qualified recursive construction-parent verifier. */
class ConstructionParentVerifier {
public:
    ConstructionParentVerifier(const ConstructionParentVerifier&) = delete;
    ConstructionParentVerifier& operator=(
        const ConstructionParentVerifier&) = delete;
    ConstructionParentVerifier(ConstructionParentVerifier&&) noexcept;
    ConstructionParentVerifier& operator=(
        ConstructionParentVerifier&&) noexcept;
    ~ConstructionParentVerifier();

    /**
     * Loads the qualified verifier from an explicit UTF-8 storage path.
     *
     * The path cannot select artifact identity. A digest or shape mismatch is
     * an internal deployment error, not a peer-retry condition.
     */
    [[nodiscard]] static Result<ConstructionParentVerifier> load(
        std::string_view artifact_path);

    /**
     * Verifies exact payload ancestry and completes the final native decision
     * before returning an acceptance capability.
     */
    [[nodiscard]] Result<VerifiedConstructionReceipt> verify(
        const ResolvedConstructionSetup& setup,
        const ConstructionReceiptEnvelope& envelope,
        std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
        const ConstructionReceiptAccumulator& accumulator,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

private:
    struct Impl;
    explicit ConstructionParentVerifier(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

} // namespace purify::accountable

#endif // PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER
