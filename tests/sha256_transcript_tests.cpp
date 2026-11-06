// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cassert>
#include <cstddef>
#include <exception>
#include <string>
#include <string_view>

#include "../src/protocol/sha256_transcript.hpp"
#include "test_harness.hpp"

namespace {

namespace candidate = purify::bppp::candidate;
using candidate::Sha256Transcript;
using candidate::TranscriptBytes32;
using candidate::TranscriptDigest;
using purify::FieldElement;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

template <std::size_t Size>
std::array<unsigned char, Size> bytes(std::string_view hex) {
    assert(hex.size() == 2 * Size);
    std::array<unsigned char, Size> out{};
    for (std::size_t index = 0; index < Size; ++index) {
        out[index] = static_cast<unsigned char>(
            std::stoul(std::string(hex.substr(2 * index, 2)), nullptr, 16));
    }
    return out;
}

TranscriptBytes32 bytes32_from_u64(std::uint64_t value) {
    TranscriptBytes32 out{};
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        out[out.size() - 1 - index] =
            static_cast<unsigned char>(value >> (8 * index));
    }
    return out;
}

Sha256Transcript vector_transcript(std::uint64_t seed) {
    Sha256Transcript transcript;
    transcript.append_field(bytes32_from_u64(seed + 1));
    transcript.append_scalar(FieldElement::from_u64(seed + 2));
    const auto point = transcript.append_point(
        static_cast<unsigned char>(2 + (seed & 1U)),
        bytes32_from_u64(seed + 3));
    if (!point.has_value()) std::terminate();
    const auto pair = transcript.append_point_pair(
        static_cast<unsigned char>(seed & 3U), bytes32_from_u64(seed + 4),
        bytes32_from_u64(seed + 5));
    if (!pair.has_value()) std::terminate();
    std::array<unsigned char, 33> raw{};
    for (std::size_t index = 0; index < raw.size(); ++index) {
        raw[index] = static_cast<unsigned char>(seed + index);
    }
    const auto appended = transcript.append_bytes(raw);
    if (!appended.has_value()) std::terminate();
    transcript.append_u64(seed + 6);
    return transcript;
}

void check_vectors(TestContext& ctx) {
    struct Vector {
        std::uint64_t seed;
        unsigned char basis_byte;
        std::string_view challenge_digest;
        std::string_view challenge_scalar;
        std::string_view opening_digest;
        std::string_view opening_scalar;
    };
    constexpr std::array<Vector, 3> vectors{{
        {1,
         0x5b,
         "0a997123945598aaeaf28a886806665fda9b0ec16218d28289f3236088ce9729",
         "0a997123945598aaeaf28a886806665fda9b0ec16218d28289f3236088ce9729",
         "ce986dca0f6571807080ea08aec3c9597836370e625e781c42f2403126221cf0",
         "4e986dca0f6571807080ea08aec3c9597836370e625e781c42f2403126221cf0"},
        {17,
         0x4b,
         "4a264e452e7a4067a168d0a7cb69add7ef2477193fece404b3f85cca9d5b8b64",
         "4a264e452e7a4067a168d0a7cb69add7ef2477193fece404b3f85cca9d5b8b64",
         "316081dc185a89ca3f52ae3eeb550b21de815377fa91385541294bf5133f602a",
         "316081dc185a89ca3f52ae3eeb550b21de815377fa91385541294bf5133f602a"},
        {255,
         0xa5,
         "effe489a18724424f077c2911e951fe285ef2de9b7ff9342053556d2b06fd716",
         "6ffe489a18724424f077c2911e951fe285ef2de9b7ff9342053556d2b06fd716",
         "695e113dfd1efdb0e210a97a1cf35b6b36e5ae9bad0c038d7c93551b9413f1ef",
         "695e113dfd1efdb0e210a97a1cf35b6b36e5ae9bad0c038d7c93551b9413f1ef"},
    }};

    for (const auto& vector : vectors) {
        auto ordinary_transcript = vector_transcript(vector.seed);
        auto ordinary = ordinary_transcript.challenge(vector.seed + 7);
        expect_ok(ctx, ordinary, "SHA transcript challenge derives");
        if (ordinary) {
            ctx.expect(ordinary->digest == bytes<32>(vector.challenge_digest),
                       "SHA transcript digest matches the Python vector");
            ctx.expect(ordinary->scalar.to_bytes_be() ==
                           bytes<32>(vector.challenge_scalar),
                       "SHA transcript scalar matches the Python vector");
        }

        auto opening_transcript = vector_transcript(vector.seed);
        TranscriptDigest basis{};
        basis.fill(vector.basis_byte);
        auto opening = opening_transcript.opening_base_scalar(
            basis, 1 + (vector.seed & 1U));
        expect_ok(ctx, opening, "SHA opening-base challenge derives");
        if (opening) {
            ctx.expect(opening->digest == bytes<32>(vector.opening_digest),
                       "SHA opening digest matches the Python vector");
            ctx.expect(opening->scalar.to_bytes_be() ==
                           bytes<32>(vector.opening_scalar),
                       "SHA opening scalar matches the Python vector");
        }
    }
}

void check_chaining_and_forks(TestContext& ctx) {
    auto transcript = vector_transcript(9);
    auto same_prefix = transcript;
    auto first = transcript.challenge(16);
    auto repeated = same_prefix.challenge(16);
    expect_ok(ctx, first, "first chained challenge derives");
    expect_ok(ctx, repeated, "copied chained challenge derives");
    if (!first || !repeated) return;
    ctx.expect(*first == *repeated,
               "equal transcript states produce equal challenges");

    auto second = transcript.challenge(17);
    expect_ok(ctx, second, "second chained challenge derives");
    if (second) {
        ctx.expect(second->digest != first->digest,
                   "a chained challenge binds the prior digest state");
    }

    TranscriptDigest basis{};
    basis.fill(0x42);
    auto fork_source = vector_transcript(23);
    auto fork_copy = fork_source;
    auto opening = fork_source.opening_base_scalar(basis, 2);
    auto opening_again = fork_source.opening_base_scalar(basis, 2);
    expect_ok(ctx, opening, "opening fork derives");
    expect_ok(ctx, opening_again, "repeated opening fork derives");
    if (opening && opening_again) {
        ctx.expect(*opening == *opening_again,
                   "opening derivation does not mutate the transcript");
    }
    auto after_opening = fork_source.challenge(30);
    auto without_opening = fork_copy.challenge(30);
    expect_ok(ctx, after_opening, "post-opening challenge derives");
    expect_ok(ctx, without_opening, "fork comparison challenge derives");
    if (after_opening && without_opening) {
        ctx.expect(*after_opening == *without_opening,
                   "opening fork leaves the challenge chain unchanged");
    }
}

void check_typed_framing(TestContext& ctx) {
    Sha256Transcript short_bytes;
    expect_ok(ctx, short_bytes.append_bytes(std::array<unsigned char, 1>{1}),
              "short SHA byte item appends");
    Sha256Transcript leading_zero;
    expect_ok(ctx,
              leading_zero.append_bytes(std::array<unsigned char, 2>{0, 1}),
              "leading-zero SHA byte item appends");
    auto short_challenge = short_bytes.challenge(9);
    auto zero_challenge = leading_zero.challenge(9);
    expect_ok(ctx, short_challenge, "short SHA byte challenge derives");
    expect_ok(ctx, zero_challenge, "leading-zero SHA byte challenge derives");
    if (short_challenge && zero_challenge) {
        ctx.expect(*short_challenge != *zero_challenge,
                   "byte length disambiguates leading zeros");
    }

    Sha256Transcript joined;
    expect_ok(ctx, joined.append_bytes(purify::bytes_from_ascii("ab")),
              "joined SHA bytes append");
    Sha256Transcript split;
    expect_ok(ctx, split.append_bytes(purify::bytes_from_ascii("a")),
              "first split SHA bytes append");
    expect_ok(ctx, split.append_bytes(purify::bytes_from_ascii("b")),
              "second split SHA bytes append");
    auto joined_challenge = joined.challenge(9);
    auto split_challenge = split.challenge(9);
    expect_ok(ctx, joined_challenge, "joined SHA challenge derives");
    expect_ok(ctx, split_challenge, "split SHA challenge derives");
    if (joined_challenge && split_challenge) {
        ctx.expect(*joined_challenge != *split_challenge,
                   "typed SHA item boundaries are unambiguous");
    }

    Sha256Transcript scalar_item;
    scalar_item.append_scalar(FieldElement::from_u64(7));
    Sha256Transcript field_item;
    TranscriptBytes32 field{};
    field.back() = 7;
    field_item.append_field(field);
    auto scalar_challenge = scalar_item.challenge(0);
    auto field_challenge = field_item.challenge(0);
    expect_ok(ctx, scalar_challenge, "typed scalar challenge derives");
    expect_ok(ctx, field_challenge, "typed field challenge derives");
    if (scalar_challenge && field_challenge) {
        ctx.expect(*scalar_challenge != *field_challenge,
                   "equal bytes in different item types remain distinct");
    }
}

void check_canonical_points(TestContext& ctx) {
    Sha256Transcript transcript;
    TranscriptBytes32 one{};
    one.back() = 1;
    TranscriptBytes32 zero{};
    expect_error(ctx,
                 transcript.append_point(4, one),
                 purify::ErrorCode::UnsupportedSymbol,
                 "invalid SEC1 prefix rejects");
    expect_error(ctx,
                 transcript.append_point(0, one),
                 purify::ErrorCode::BindingMismatch,
                 "hybrid identity encoding rejects");
    expect_error(ctx,
                 transcript.append_point_pair(4, zero, zero),
                 purify::ErrorCode::RangeViolation,
                 "invalid point-pair parity rejects");
}

} // namespace

void run_sha256_transcript_tests(TestContext& ctx) {
    check_vectors(ctx);
    check_chaining_and_forks(ctx);
    check_typed_framing(ctx);
    check_canonical_points(ctx);
}
