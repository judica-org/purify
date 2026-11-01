// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file construction_receipt_batch.hpp
 * @brief Canonical fixed-fan-in construction receipt batch statements.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "purify/puresign/construction_receipt.hpp"

namespace purify::accountable {

using ConstructionReceiptBatchStatementDigest =
    std::array<unsigned char, 32>;

/**
 * @brief One canonical parent-proof batch in a construction receipt.
 *
 * Version one fixes a fan-in of 16 ordered anchor entries. The descriptor
 * repeats its derived partition fields so a parent statement binds the exact
 * range it proves. Construction rejects any non-canonical count, range, or
 * setup placement instead of treating those fields as caller policy.
 */
class ConstructionReceiptBatchDescriptor {
public:
    static constexpr unsigned char kStatementVersion = 1;
    static constexpr std::uint32_t kMaximumEntries = 16;
    static constexpr std::size_t kSerializedSize =
        1 + 32 + 4 + 4 + 4 + 4 + 4 + 1;

    /**
     * @brief Derive one descriptor from the full construction statement.
     *
     * `total_entries` must be nonzero and `batch_index` must identify one of
     * `ceil(total_entries / 16)` batches.
     */
    [[nodiscard]] static Result<ConstructionReceiptBatchDescriptor> create(
        const ConstructionReceiptStatementDigest& construction_statement,
        std::uint32_t total_entries,
        std::uint32_t batch_index);

    /** @brief Parse an exact canonical version-one descriptor. */
    [[nodiscard]] static Result<ConstructionReceiptBatchDescriptor>
    deserialize(std::span<const unsigned char> encoded);

    /**
     * @brief Return canonical parent-statement bytes.
     *
     * The bytes bind the statement suite/version and every descriptor field.
     */
    [[nodiscard]] Bytes serialize() const;

    /** @brief Hash the canonical bytes in the batch-statement domain. */
    [[nodiscard]] ConstructionReceiptBatchStatementDigest
    statement_digest() const;

    [[nodiscard]] const ConstructionReceiptStatementDigest&
    construction_statement() const noexcept {
        return construction_statement_;
    }

    [[nodiscard]] std::uint32_t total_entries() const noexcept {
        return total_entries_;
    }

    [[nodiscard]] std::uint32_t batch_index() const noexcept {
        return batch_index_;
    }

    [[nodiscard]] std::uint32_t batch_count() const noexcept {
        return batch_count_;
    }

    [[nodiscard]] std::uint32_t entry_start() const noexcept {
        return entry_start_;
    }

    [[nodiscard]] std::uint32_t entry_end() const noexcept {
        return entry_end_;
    }

    [[nodiscard]] bool includes_setup() const noexcept {
        return includes_setup_;
    }

    bool operator==(const ConstructionReceiptBatchDescriptor&) const =
        default;

private:
    ConstructionReceiptBatchDescriptor(
        ConstructionReceiptStatementDigest construction_statement,
        std::uint32_t total_entries,
        std::uint32_t batch_index,
        std::uint32_t batch_count,
        std::uint32_t entry_start,
        std::uint32_t entry_end,
        bool includes_setup)
        : construction_statement_(construction_statement),
          total_entries_(total_entries),
          batch_index_(batch_index),
          batch_count_(batch_count),
          entry_start_(entry_start),
          entry_end_(entry_end),
          includes_setup_(includes_setup) {}

    ConstructionReceiptStatementDigest construction_statement_{};
    std::uint32_t total_entries_{};
    std::uint32_t batch_index_{};
    std::uint32_t batch_count_{};
    std::uint32_t entry_start_{};
    std::uint32_t entry_end_{};
    bool includes_setup_{};
};

/**
 * @brief Derive the complete ordered fixed-fan-in partition.
 *
 * The result contains exactly `ceil(total_entries / 16)` descriptors. Only
 * its first descriptor includes the shared setup proof.
 */
[[nodiscard]] Result<std::vector<ConstructionReceiptBatchDescriptor>>
construction_receipt_batch_partition(
    const ConstructionReceiptStatementDigest& construction_statement,
    std::uint32_t total_entries);

/**
 * @brief Validate an externally assembled descriptor partition exactly.
 *
 * The supplied descriptors must equal the deterministic partition for the
 * expected construction statement and count, in order and without omissions
 * or duplicates.
 */
[[nodiscard]] Status validate_construction_receipt_batch_partition(
    const ConstructionReceiptStatementDigest& construction_statement,
    std::uint32_t total_entries,
    std::span<const ConstructionReceiptBatchDescriptor> batches);

}  // namespace purify::accountable
