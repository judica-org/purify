// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cassert>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "../src/protocol/poseidon.hpp"
#include "test_harness.hpp"

namespace {

using purify::Bytes;
using purify::UInt256;
using purify::bppp::candidate::CoordinateFieldElement;
using purify::bppp::candidate::poseidon_parameters;
using purify::bppp::candidate::poseidon_permute;
using purify::bppp::candidate::PoseidonState;
using purify_test::TestContext;

CoordinateFieldElement field(std::string_view hex) {
    const UInt256 value = UInt256::from_hex(hex);
    auto parsed = CoordinateFieldElement::from_bytes_be(value.to_bytes_be());
    assert(parsed.has_value());
    return *parsed;
}

std::string digest_fields(std::span<const CoordinateFieldElement> values) {
    Bytes encoded;
    encoded.reserve(values.size() * CoordinateFieldElement::kSerializedSize);
    for (const auto& value : values) {
        encoded.insert(encoded.end(), value.bytes().begin(), value.bytes().end());
    }
    std::array<unsigned char, 32> digest{};
    purify_sha256(digest.data(), encoded.data(), encoded.size());
    return UInt256::from_bytes_be(digest.data(), digest.size()).to_hex();
}

void check_parameters(TestContext& ctx) {
    const auto& parameters = poseidon_parameters();
    ctx.expect(digest_fields(parameters.round_constants) ==
                   "de0209e6db9909a2bebd435499a3dd1e199626ac0d1415b55f832c8dd5bdca6d",
               "native round constants match the pinned generator");
    std::array<CoordinateFieldElement, 9> mds{};
    std::size_t offset = 0;
    for (const auto& row : parameters.mds) {
        for (const auto& value : row) mds[offset++] = value;
    }
    ctx.expect(digest_fields(mds) ==
                   "b214b9440fa5cb193ab6bc98fad114eaad5da447dc61629c03ab1805328945d5",
               "native MDS matrix matches the pinned generator");
}

void check_permutation_vectors(TestContext& ctx) {
    struct Vector {
        std::array<std::string_view, 3> input;
        std::array<std::string_view, 3> output;
    };
    constexpr std::array<Vector, 3> vectors{{
        {{{"0", "0", "0"}},
         {{"4a24c66e3902e5546c7e6e67a28f1d8891628c8dc784674e4843159f9559fecf",
           "47d870755becb9a61d9ea5c071027c11683bedfcfcff52b1517050bfcded7ea8",
           "23e77599805d6bfc503551211fa4d59a536f1eb34a8671f2e52ca6f9c70edd9e"}}},
        {{{"0", "1", "2"}},
         {{"e424f198c2e4f551e9590f2f39f55861e4e7279f2ed1f80e651b1f855b4885c3",
           "6f6b895369120efdd4ffb930da00b5cfe0029e2a6239ae4c7deb41317962c09c",
           "2c8bfdbb6d972c1bd54690fc90a9c222954b4404c059e0231b99d099aa6c632b"}}},
        {{{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
           "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
           "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c"}},
         {{"8c6c4a63a5e145999bc9004180ad9b2ad4ba371965afb110185282c1a34b6658",
           "51758d9b486bc7697a49f2be2ec0a86a118625d265a6be0e5b79afde7a8f3ce0",
           "f064dcd1c689f7cefd9b1289fcc2f413f231b38cdaa6b340261da73804c84c0d"}}},
    }};

    for (const auto& vector : vectors) {
        PoseidonState input{field(vector.input[0]), field(vector.input[1]), field(vector.input[2])};
        const PoseidonState output = poseidon_permute(input);
        for (std::size_t lane = 0; lane < output.size(); ++lane) {
            ctx.expect(output[lane] == field(vector.output[lane]),
                       "native permutation matches the Rust vector");
        }
    }
}

} // namespace

void run_poseidon_tests(TestContext& ctx) {
    check_parameters(ctx);
    check_permutation_vectors(ctx);
}
