// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

#include "test_harness.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::Bytes;
using purify::ErrorCode;
using purify::UInt256;
using purify::accountable::ConstructionReceiptBatchDescriptor;
using purify::accountable::ConstructionReceiptStatementDigest;
using purify::accountable::construction_receipt_batch_partition;
using purify::accountable::validate_construction_receipt_batch_partition;

ConstructionReceiptStatementDigest sequential_statement() {
    ConstructionReceiptStatementDigest statement{};
    for (std::size_t i = 0; i < statement.size(); ++i) {
        statement[i] = static_cast<unsigned char>(i);
    }
    return statement;
}

unsigned char hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned char>(value - '0');
    }
    return static_cast<unsigned char>(value - 'a' + 10);
}

Bytes hex_bytes(std::string_view encoded) {
    Bytes out;
    out.reserve(encoded.size() / 2);
    for (std::size_t i = 0; i < encoded.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(
            (hex_nibble(encoded[i]) << 4) |
            hex_nibble(encoded[i + 1])));
    }
    return out;
}

void test_partition_boundaries(TestContext& ctx) {
    const auto statement = sequential_statement();
    struct Boundary {
        std::uint32_t total;
        std::uint32_t batches;
    };
    constexpr std::array<Boundary, 6> boundaries{{
        {1, 1}, {16, 1}, {17, 2}, {32, 2}, {33, 3}, {100, 7},
    }};

    expect_error(ctx,
                 construction_receipt_batch_partition(statement, 0),
                 ErrorCode::EmptyInput,
                 "zero entries do not define a batch partition");
    expect_error(ctx,
                 ConstructionReceiptBatchDescriptor::create(
                     statement, 0, 0),
                 ErrorCode::EmptyInput,
                 "zero entries do not define a descriptor");

    for (const Boundary& boundary : boundaries) {
        auto partition = construction_receipt_batch_partition(
            statement, boundary.total);
        expect_ok(ctx, partition, "boundary partition constructs");
        if (!partition) continue;
        ctx.expect(partition->size() == boundary.batches,
                   "partition count is ceil(N / 16)");
        expect_ok(ctx,
                  validate_construction_receipt_batch_partition(
                      statement, boundary.total, *partition),
                  "generated partition validates exactly");

        std::uint32_t prior_end = 0;
        std::uint32_t setup_count = 0;
        for (std::uint32_t i = 0; i < partition->size(); ++i) {
            const auto& batch = (*partition)[i];
            const std::uint32_t expected_end =
                std::min<std::uint32_t>(
                    boundary.total, prior_end +
                                        ConstructionReceiptBatchDescriptor::
                                            kMaximumEntries);
            ctx.expect(batch.construction_statement() == statement,
                       "batch binds the full construction statement");
            ctx.expect(batch.total_entries() == boundary.total,
                       "batch binds the total entry count");
            ctx.expect(batch.batch_index() == i,
                       "batch indices are contiguous and ordered");
            ctx.expect(batch.batch_count() == boundary.batches,
                       "batch binds the complete partition count");
            ctx.expect(batch.entry_start() == prior_end &&
                           batch.entry_end() == expected_end,
                       "batch ranges are exact and contiguous");
            ctx.expect(batch.entry_end() > batch.entry_start() &&
                           batch.entry_end() - batch.entry_start() <=
                               ConstructionReceiptBatchDescriptor::
                                   kMaximumEntries,
                       "every batch carries one through sixteen entries");
            ctx.expect(batch.includes_setup() == (i == 0),
                       "only the first batch includes setup");
            setup_count += static_cast<std::uint32_t>(
                batch.includes_setup());
            prior_end = expected_end;
        }
        ctx.expect(prior_end == boundary.total,
                   "partition covers the final entry exactly");
        ctx.expect(setup_count == 1,
                   "setup occurs exactly once in every partition");

        expect_error(ctx,
                     ConstructionReceiptBatchDescriptor::create(
                         statement, boundary.total, boundary.batches),
                     ErrorCode::IndexOutOfRange,
                     "the first absent batch index is rejected");
    }

    constexpr std::uint32_t maximum =
        std::numeric_limits<std::uint32_t>::max();
    constexpr std::uint32_t maximum_batch_count =
        maximum / ConstructionReceiptBatchDescriptor::kMaximumEntries + 1;
    auto last = ConstructionReceiptBatchDescriptor::create(
        statement, maximum, maximum_batch_count - 1);
    expect_ok(ctx, last, "maximum count final descriptor constructs");
    if (!last) return;
    ctx.expect(last->batch_count() == maximum_batch_count &&
                   last->entry_start() == 0xfffffff0U &&
                   last->entry_end() == maximum,
               "maximum count partition arithmetic does not wrap");
}

void test_canonical_codec_and_digest_vector(TestContext& ctx) {
    const auto statement = sequential_statement();
    auto descriptor = ConstructionReceiptBatchDescriptor::create(
        statement, 17, 1);
    expect_ok(ctx, descriptor, "vector descriptor constructs");
    if (!descriptor) return;

    static_assert(ConstructionReceiptBatchDescriptor::kSerializedSize == 54);
    const Bytes expected = hex_bytes(
        "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
        "1e1f000000110000000100000002000000100000001100");
    const Bytes encoded = descriptor->serialize();
    ctx.expect(encoded == expected,
               "descriptor encoding matches the canonical byte vector");

    auto decoded = ConstructionReceiptBatchDescriptor::deserialize(encoded);
    expect_ok(ctx, decoded, "canonical descriptor decodes");
    if (!decoded) return;
    ctx.expect(*decoded == *descriptor && decoded->serialize() == encoded,
               "descriptor codec round trip is exact");

    const auto expected_digest = UInt256::from_hex(
        "0cfd76dcc7e4a17ba95c5c9085cfc0699eb29826192d9f4f"
        "aa9e47415501b74c")
                                     .to_bytes_be();
    ctx.expect(descriptor->statement_digest() == expected_digest,
               "tagged batch statement digest matches the fixed vector");

    auto first = ConstructionReceiptBatchDescriptor::create(
        statement, 17, 0);
    expect_ok(ctx, first, "first vector descriptor constructs");
    if (!first) return;
    ctx.expect(first->statement_digest() != descriptor->statement_digest(),
               "batch position changes the statement digest");

    auto changed_statement = statement;
    changed_statement[0] ^= 1U;
    auto changed = ConstructionReceiptBatchDescriptor::create(
        changed_statement, 17, 1);
    expect_ok(ctx, changed, "changed construction descriptor constructs");
    if (!changed) return;
    ctx.expect(changed->statement_digest() !=
                   descriptor->statement_digest(),
               "full construction statement changes the batch digest");
}

void test_noncanonical_codec_rejection(TestContext& ctx) {
    const auto statement = sequential_statement();
    auto descriptor = ConstructionReceiptBatchDescriptor::create(
        statement, 17, 1);
    expect_ok(ctx, descriptor, "negative codec descriptor constructs");
    if (!descriptor) return;
    const Bytes encoded = descriptor->serialize();

    auto truncated = encoded;
    truncated.pop_back();
    expect_error(ctx,
                 ConstructionReceiptBatchDescriptor::deserialize(truncated),
                 ErrorCode::InvalidFixedSize,
                 "truncated descriptors are rejected");
    auto trailing = encoded;
    trailing.push_back(0);
    expect_error(ctx,
                 ConstructionReceiptBatchDescriptor::deserialize(trailing),
                 ErrorCode::InvalidFixedSize,
                 "trailing descriptor bytes are rejected");

    auto wrong_version = encoded;
    wrong_version[0] = 2;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(wrong_version),
        ErrorCode::UnsupportedSymbol,
        "unknown batch statement versions are rejected");

    constexpr std::size_t kTotalOffset = 33;
    constexpr std::size_t kIndexOffset = 37;
    constexpr std::size_t kCountOffset = 41;
    constexpr std::size_t kStartOffset = 45;
    constexpr std::size_t kEndOffset = 49;
    constexpr std::size_t kSetupOffset = 53;

    auto zero_total = encoded;
    std::fill_n(zero_total.begin() + kTotalOffset, 4, 0);
    expect_error(ctx,
                 ConstructionReceiptBatchDescriptor::deserialize(zero_total),
                 ErrorCode::EmptyInput,
                 "encoded zero totals are rejected");

    auto absent_index = encoded;
    absent_index[kIndexOffset + 3] = 2;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(absent_index),
        ErrorCode::IndexOutOfRange,
        "encoded out-of-range batch indices are rejected");

    auto wrong_count = encoded;
    wrong_count[kCountOffset + 3] = 3;
    expect_error(ctx,
                 ConstructionReceiptBatchDescriptor::deserialize(wrong_count),
                 ErrorCode::BindingMismatch,
                 "non-canonical batch counts are rejected");

    auto overlapping_start = encoded;
    overlapping_start[kStartOffset + 3] = 15;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(overlapping_start),
        ErrorCode::BindingMismatch,
        "non-canonical overlapping ranges are rejected");

    auto out_of_range_end = encoded;
    out_of_range_end[kEndOffset + 3] = 18;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(out_of_range_end),
        ErrorCode::BindingMismatch,
        "non-canonical range ends are rejected");

    auto misplaced_setup = encoded;
    misplaced_setup[kSetupOffset] = 1;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(misplaced_setup),
        ErrorCode::BindingMismatch,
        "setup cannot be included after the first batch");

    auto non_boolean_setup = encoded;
    non_boolean_setup[kSetupOffset] = 2;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(non_boolean_setup),
        ErrorCode::NonBooleanValue,
        "setup inclusion must use a canonical boolean");

    auto first = ConstructionReceiptBatchDescriptor::create(
        statement, 17, 0);
    expect_ok(ctx, first, "first negative descriptor constructs");
    if (!first) return;
    auto omitted_setup = first->serialize();
    omitted_setup[kSetupOffset] = 0;
    expect_error(
        ctx,
        ConstructionReceiptBatchDescriptor::deserialize(omitted_setup),
        ErrorCode::BindingMismatch,
        "the first batch cannot omit setup");
}

void test_partition_rejection(TestContext& ctx) {
    const auto statement = sequential_statement();
    auto partition = construction_receipt_batch_partition(statement, 33);
    expect_ok(ctx, partition, "negative partition fixture constructs");
    if (!partition) return;

    auto missing = *partition;
    missing.erase(missing.begin() + 1);
    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 33, missing),
                 ErrorCode::SizeMismatch,
                 "partitions with a gap are rejected");

    auto reordered = *partition;
    std::swap(reordered[0], reordered[1]);
    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 33, reordered),
                 ErrorCode::BindingMismatch,
                 "reordered partitions are rejected");

    auto duplicate = *partition;
    duplicate[1] = duplicate[0];
    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 33, duplicate),
                 ErrorCode::BindingMismatch,
                 "overlapping duplicate batches are rejected");

    auto other_statement = statement;
    other_statement.back() ^= 1U;
    auto foreign = ConstructionReceiptBatchDescriptor::create(
        other_statement, 33, 1);
    expect_ok(ctx, foreign, "foreign descriptor constructs");
    if (!foreign) return;
    auto mixed = *partition;
    mixed[1] = *foreign;
    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 33, mixed),
                 ErrorCode::BindingMismatch,
                 "partitions cannot mix construction statements");

    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 33, {}),
                 ErrorCode::SizeMismatch,
                 "an empty list cannot cover a nonempty statement");
    expect_error(ctx,
                 validate_construction_receipt_batch_partition(
                     statement, 0, {}),
                 ErrorCode::EmptyInput,
                 "zero-entry expected partitions are rejected");
}

}  // namespace

void run_construction_receipt_batch_tests(TestContext& ctx) {
    test_partition_boundaries(ctx);
    test_canonical_codec_and_digest_vector(ctx);
    test_noncanonical_codec_rejection(ctx);
    test_partition_rejection(ctx);
}
