// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_receipt_batch.hpp"

#include <algorithm>
#include <cstdint>

#include "purify/curve.hpp"

namespace purify::accountable {
namespace {

const TaggedHash kConstructionReceiptBatchStatementHash(
    "Purify/Accountable/ConstructionReceiptBatchStatement/v1");

void append_u32_be(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffU));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffU));
    out.push_back(static_cast<unsigned char>(value & 0xffU));
}

std::uint32_t read_u32_be(std::span<const unsigned char, 4> encoded) {
    return (static_cast<std::uint32_t>(encoded[0]) << 24) |
           (static_cast<std::uint32_t>(encoded[1]) << 16) |
           (static_cast<std::uint32_t>(encoded[2]) << 8) |
           static_cast<std::uint32_t>(encoded[3]);
}

std::uint32_t read_u32_be_at(std::span<const unsigned char> encoded,
                             std::size_t offset) {
    return read_u32_be(
        std::span<const unsigned char, 4>(encoded.data() + offset, 4));
}

Result<std::uint32_t> batch_count_for(std::uint32_t total_entries) {
    if (total_entries == 0) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "construction_batch:total_entries");
    }
    return total_entries /
               ConstructionReceiptBatchDescriptor::kMaximumEntries +
           static_cast<std::uint32_t>(
               total_entries %
                   ConstructionReceiptBatchDescriptor::kMaximumEntries !=
               0);
}

}  // namespace

Result<ConstructionReceiptBatchDescriptor>
ConstructionReceiptBatchDescriptor::create(
    const ConstructionReceiptStatementDigest& construction_statement,
    std::uint32_t total_entries,
    std::uint32_t batch_index) {
    PURIFY_ASSIGN_OR_RETURN(const std::uint32_t batch_count,
                            batch_count_for(total_entries),
                            "construction_batch:batch_count");
    if (batch_index >= batch_count) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "construction_batch:batch_index");
    }

    const std::uint64_t entry_start_wide =
        static_cast<std::uint64_t>(batch_index) * kMaximumEntries;
    const auto entry_start =
        static_cast<std::uint32_t>(entry_start_wide);
    const std::uint32_t remaining = total_entries - entry_start;
    const std::uint32_t entry_count =
        remaining < kMaximumEntries ? remaining : kMaximumEntries;
    const std::uint32_t entry_end = entry_start + entry_count;

    return ConstructionReceiptBatchDescriptor(
        construction_statement, total_entries, batch_index, batch_count,
        entry_start, entry_end, batch_index == 0);
}

Result<ConstructionReceiptBatchDescriptor>
ConstructionReceiptBatchDescriptor::deserialize(
    std::span<const unsigned char> encoded) {
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "construction_batch:encoded_size");
    }
    if (encoded[0] != kStatementVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "construction_batch:version");
    }

    std::size_t offset = 1;
    ConstructionReceiptStatementDigest construction_statement{};
    std::copy_n(encoded.data() + offset,
                construction_statement.size(),
                construction_statement.begin());
    offset += construction_statement.size();

    const std::uint32_t total_entries = read_u32_be_at(encoded, offset);
    offset += 4;
    const std::uint32_t batch_index = read_u32_be_at(encoded, offset);
    offset += 4;
    const std::uint32_t encoded_batch_count =
        read_u32_be_at(encoded, offset);
    offset += 4;
    const std::uint32_t encoded_entry_start =
        read_u32_be_at(encoded, offset);
    offset += 4;
    const std::uint32_t encoded_entry_end =
        read_u32_be_at(encoded, offset);
    offset += 4;
    const unsigned char encoded_includes_setup = encoded[offset];
    if (encoded_includes_setup > 1) {
        return unexpected_error(ErrorCode::NonBooleanValue,
                                "construction_batch:includes_setup");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto expected,
        create(construction_statement, total_entries, batch_index),
        "construction_batch:canonical_descriptor");
    if (encoded_batch_count != expected.batch_count() ||
        encoded_entry_start != expected.entry_start() ||
        encoded_entry_end != expected.entry_end() ||
        (encoded_includes_setup != 0) != expected.includes_setup()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_batch:derived_fields");
    }
    return expected;
}

Bytes ConstructionReceiptBatchDescriptor::serialize() const {
    Bytes encoded;
    encoded.reserve(kSerializedSize);
    encoded.push_back(kStatementVersion);
    encoded.insert(encoded.end(), construction_statement_.begin(),
                   construction_statement_.end());
    append_u32_be(encoded, total_entries_);
    append_u32_be(encoded, batch_index_);
    append_u32_be(encoded, batch_count_);
    append_u32_be(encoded, entry_start_);
    append_u32_be(encoded, entry_end_);
    encoded.push_back(static_cast<unsigned char>(includes_setup_));
    return encoded;
}

ConstructionReceiptBatchStatementDigest
ConstructionReceiptBatchDescriptor::statement_digest() const {
    return kConstructionReceiptBatchStatementHash.digest(serialize());
}

Result<std::vector<ConstructionReceiptBatchDescriptor>>
construction_receipt_batch_partition(
    const ConstructionReceiptStatementDigest& construction_statement,
    std::uint32_t total_entries) {
    PURIFY_ASSIGN_OR_RETURN(const std::uint32_t batch_count,
                            batch_count_for(total_entries),
                            "construction_batch:batch_count");
    std::vector<ConstructionReceiptBatchDescriptor> batches;
    batches.reserve(batch_count);
    for (std::uint32_t batch_index = 0;
         batch_index < batch_count;
         ++batch_index) {
        PURIFY_ASSIGN_OR_RETURN(
            auto descriptor,
            ConstructionReceiptBatchDescriptor::create(
                construction_statement, total_entries, batch_index),
            "construction_batch:descriptor");
        batches.push_back(std::move(descriptor));
    }
    return batches;
}

Status validate_construction_receipt_batch_partition(
    const ConstructionReceiptStatementDigest& construction_statement,
    std::uint32_t total_entries,
    std::span<const ConstructionReceiptBatchDescriptor> batches) {
    PURIFY_ASSIGN_OR_RETURN(const std::uint32_t batch_count,
                            batch_count_for(total_entries),
                            "construction_batch:batch_count");
    if (batches.size() != batch_count) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "construction_batch:partition_size");
    }
    for (std::uint32_t batch_index = 0;
         batch_index < batch_count;
         ++batch_index) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto expected,
            ConstructionReceiptBatchDescriptor::create(
                construction_statement, total_entries, batch_index),
            "construction_batch:expected_descriptor");
        if (batches[batch_index] != expected) {
            return unexpected_error(ErrorCode::BindingMismatch,
                                    "construction_batch:partition_order");
        }
    }
    return {};
}

}  // namespace purify::accountable
