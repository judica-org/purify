// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <string_view>

#include "../src/protocol/algebraic_transcript.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::UInt256;
using purify::bppp::candidate::AlgebraicTranscript;
using purify::bppp::candidate::CoordinateFieldElement;
using purify::bppp::candidate::select_nonzero_scalar;
using purify::bppp::candidate::TranscriptDigest;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

CoordinateFieldElement field(std::string_view hex) {
    const UInt256 value = UInt256::from_hex(hex);
    auto parsed = CoordinateFieldElement::from_bytes_be(value.to_bytes_be());
    assert(parsed.has_value());
    return *parsed;
}

AlgebraicTranscript filled_transcript() {
    AlgebraicTranscript transcript;
    transcript.append_field(CoordinateFieldElement::from_u64(2));
    transcript.append_scalar(FieldElement::from_u64(3));
    const auto point =
        transcript.append_point(2, CoordinateFieldElement::from_u64(5));
    if (!point.has_value()) std::terminate();
    const auto pair = transcript.append_point_pair(
        1, CoordinateFieldElement::from_u64(7),
        CoordinateFieldElement::from_u64(11));
    if (!pair.has_value()) std::terminate();
    const std::array<unsigned char, 33> bytes{1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                              12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                              23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33};
    const auto appended = transcript.append_bytes(bytes);
    if (!appended.has_value()) std::terminate();
    transcript.append_u64(13);
    return transcript;
}

AlgebraicTranscript vector_transcript(std::uint64_t seed) {
    AlgebraicTranscript transcript;
    transcript.append_field(CoordinateFieldElement::from_u64(seed + 1));
    transcript.append_scalar(FieldElement::from_u64(seed + 2));
    const auto point = transcript.append_point(
        static_cast<unsigned char>(2 + (seed & 1U)),
        CoordinateFieldElement::from_u64(seed + 3));
    if (!point.has_value()) std::terminate();
    const auto pair = transcript.append_point_pair(
        static_cast<unsigned char>(seed & 3U),
        CoordinateFieldElement::from_u64(seed + 4),
        CoordinateFieldElement::from_u64(seed + 5));
    if (!pair.has_value()) std::terminate();
    std::array<unsigned char, 33> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<unsigned char>(seed + index);
    }
    const auto appended = transcript.append_bytes(bytes);
    if (!appended.has_value()) std::terminate();
    transcript.append_u64(seed + 6);
    return transcript;
}

void check_transcript_vectors(TestContext& ctx) {
    struct Vector {
        std::uint64_t seed;
        unsigned char basis_byte;
        std::array<std::string_view, 2> ordinary;
        std::array<std::string_view, 2> opening;
    };
    constexpr std::array<Vector, 3> vectors{{
        {1,
         0x5b,
         {"ab0e8f26c1bf0ab7c15831c59eda00600aa3efccd39686b7ebcf51b9bb96181e",
          "d3963675f895c1569be1a3150a810858897dadd6c2bc3ccd90c68feb3ac44b8c"},
         {"0ca7279cf396dea0616b5ee9f0c8515b0abfe29a34b51e0fa1d22bd6dc99a379",
          "7e3ae7ecd3ef26599be938bc417b84630aff3594bc23c4577cbf5174a5537a47"}},
        {17,
         0x4b,
         {"e5c9f694bb6998fc038d6ead172e81c965260131e6247b489d374ebef9fcb3a8",
          "428acf8641802ee866573a881b1902ffe6dfbf4247e43a5e5700c27537979543"},
         {"96828a205736d1112f12e87d840d63af6dc7cc860e262f253970507d735fb170",
          "3ed5b76e1f56358ae63a45681aaaa9890063d8de671ac79557552e8acbf08dab"}},
        {255,
         0xa5,
         {"535b864af766d7a927fe88366d00c5e182339249710ba996df9f34b5bfd2e8c7",
          "8b7c0aaf5686fe2cd33b85bb7166845ae832b1cc93244c68cc9ccc49573603a8"},
         {"a64017dc6f982c270ef3722bc415666e9bc525b9d63a26718334c4b991a0c611",
          "46ae3a993b1f778f3133a6d499786643677713c7fd28df7303e51444f37729d1"}},
    }};

    for (const auto& vector : vectors) {
        const auto transcript = vector_transcript(vector.seed);
        const auto ordinary = transcript.challenge(vector.seed + 7);
        TranscriptDigest basis{};
        basis.fill(vector.basis_byte);
        const auto opening = transcript.opening_base_scalar(basis, 1 + (vector.seed & 1U));
        for (std::size_t lane = 0; lane < 2; ++lane) {
            ctx.expect(ordinary[lane] == field(vector.ordinary[lane]),
                       "ordinary squeeze matches the Python vector");
            ctx.expect(opening[lane] == field(vector.opening[lane]),
                       "opening squeeze matches the Python vector");
        }
    }
}

void check_transcript_domains(TestContext& ctx) {
    const auto transcript = filled_transcript();
    ctx.expect(transcript.challenge(17) == transcript.challenge(17),
               "ordinary challenge is deterministic");
    ctx.expect(transcript.challenge(17) != transcript.challenge(18),
               "ordinary challenge binds its index");

    TranscriptDigest first_basis{};
    first_basis.fill(0x31);
    TranscriptDigest second_basis = first_basis;
    second_basis[0] ^= 1;
    const auto opening = transcript.opening_base_scalar(first_basis, 1);
    ctx.expect(opening != transcript.challenge(1),
               "opening squeeze is separate from an ordinary challenge");
    ctx.expect(opening != transcript.opening_base_scalar(first_basis, 2),
               "opening squeeze binds its role");
    ctx.expect(opening != transcript.opening_base_scalar(second_basis, 1),
               "opening squeeze binds its basis");

    AlgebraicTranscript short_bytes;
    expect_ok(ctx, short_bytes.append_bytes(std::array<unsigned char, 1>{1}),
              "short byte item appends");
    AlgebraicTranscript leading_zero;
    expect_ok(ctx, leading_zero.append_bytes(std::array<unsigned char, 2>{0, 1}),
              "leading-zero byte item appends");
    ctx.expect(short_bytes.challenge(9) != leading_zero.challenge(9),
               "byte length disambiguates leading zeros");

    AlgebraicTranscript joined;
    expect_ok(ctx, joined.append_bytes(purify::bytes_from_ascii("ab")), "joined bytes append");
    AlgebraicTranscript split;
    expect_ok(ctx, split.append_bytes(purify::bytes_from_ascii("a")), "first split bytes append");
    expect_ok(ctx, split.append_bytes(purify::bytes_from_ascii("b")), "second split bytes append");
    ctx.expect(joined.challenge(9) != split.challenge(9), "byte item boundaries are unambiguous");
}

void check_canonical_inputs(TestContext& ctx) {
    AlgebraicTranscript transcript;
    expect_error(ctx, transcript.append_point(4, CoordinateFieldElement::from_u64(1)),
                 purify::ErrorCode::UnsupportedSymbol, "invalid SEC1 prefix rejects");
    expect_error(ctx, transcript.append_point(0, CoordinateFieldElement::from_u64(1)),
                 purify::ErrorCode::BindingMismatch, "hybrid identity encoding rejects");
    expect_error(ctx,
                 transcript.append_point_pair(4, CoordinateFieldElement::zero(),
                                              CoordinateFieldElement::zero()),
                 purify::ErrorCode::RangeViolation, "invalid point-pair parity rejects");

    const auto order = field("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const std::array<CoordinateFieldElement, 2> fallback{order, CoordinateFieldElement::one()};
    auto selected = select_nonzero_scalar(fallback);
    expect_ok(ctx, selected, "second scalar lane is a valid fallback");
    if (selected) {
        ctx.expect(*selected == FieldElement::one(), "fallback selects the second scalar lane");
    }
    const std::array<CoordinateFieldElement, 2> exhausted{CoordinateFieldElement::zero(), order};
    expect_error(ctx, select_nonzero_scalar(exhausted), purify::ErrorCode::RangeViolation,
                 "two invalid scalar lanes reject");
}

} // namespace

void run_algebraic_transcript_tests(TestContext& ctx) {
    check_transcript_vectors(ctx);
    check_transcript_domains(ctx);
    check_canonical_inputs(ctx);
}
