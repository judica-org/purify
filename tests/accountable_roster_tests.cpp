// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable_roster.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify::accountable::SigningRoster;

auto bytes32(std::string_view hex) {
    return purify::UInt256::from_hex(hex).to_bytes_be();
}

auto key33(unsigned char prefix, std::string_view hex) {
    std::array<unsigned char, 33> out{};
    out[0] = prefix;
    const auto x = bytes32(hex);
    std::copy(x.begin(), x.end(), out.begin() + 1);
    return out;
}

struct RosterVector {
    std::string_view list_hash;
    std::array<std::string_view, 3> coefficients;
    bool negated;
    std::string_view signing_key;
};

} // namespace

void run_accountable_roster_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "roster secp context creates");
    if (!secp) return;

    // Independent Python fixtures use scalars 3, 6, and 8. Individual key two
    // has odd Y, while the three-member aggregate needs an additional sign.
    const std::array keys{
        key33(0x02, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        key33(0x03, "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"),
        key33(0x02, "2f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"),
    };
    const std::array<RosterVector, 3> vectors{{
        {"de3f347d358e18c7e7d1d1c17d098f55ae77d3eed4880a296186e7135297ee31",
         {"d5ab8b5493a08cb4dd788cce6df35b06eea5e53fe0a26e4783f06201d1723fb1", "", ""},
         false, "74108ca6d5ed40b37c4a441e96438d144bd7e95cd515b996ca4f70f78342f0ad"},
        {"30345f702a599f2a31f00299683232eca13ea2232797c1c3122d5c84ce531a98",
         {"47839be1625a46b5b04c52bf0fadc0215abea9e02a000d2c8d654b3d6087a12d",
          "0000000000000000000000000000000000000000000000000000000000000001", ""},
         false, "cf60b1e6b4756088b1253c1227d265a1794976a9a02af86f8e9ba884452e4f4b"},
        {"ba461b263966a4cd084a3b6caefb24bc5e5aa1982d6fe88c15816e2d8598f75e",
         {"0acb5d59d8f48a1a617913279edf9f994aec5bd360b7a230d855b70dc732093e",
          "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
          "a46012a21915d24d16a8bc3281ff57b35b6ffac04f828b86895cd649c048ad56"},
         true, "c05e42bbe294c6b6795907ffbc44bc79dedafa83dd384cc9ea4982370c1c0527"},
    }};
    for (std::size_t count = 1; count <= keys.size(); ++count) {
        const auto& expected = vectors[count - 1];
        auto roster = SigningRoster::aggregate(std::span(keys).first(count), secp.get());
        expect_ok(ctx, roster, "N=1,2,3 roster aggregates");
        if (!roster) continue;
        ctx.expect(roster->key_list_hash() == bytes32(expected.list_hash),
                   "ordered key hash matches independent vector");
        ctx.expect(roster->signing_key() == bytes32(expected.signing_key),
                   "normalized aggregate key matches independent vector");
        ctx.expect(roster->aggregate_was_negated() == expected.negated,
                   "aggregate parity matches independent vector");
        ctx.expect(roster->members().size() == count, "roster retains every member");
        for (std::size_t i = 0; i < count; ++i) {
            ctx.expect(roster->members()[i].public_key == keys[i], "member key and order are preserved");
            ctx.expect(roster->members()[i].coefficient.to_bytes_be() == bytes32(expected.coefficients[i]),
                       "member coefficient includes exactly the aggregate parity sign");
        }
    }

    // Official BIP327 key_agg_vectors.json, distinct-key cases 0 and 1.
    const std::array official{
        keys[0],
        key33(0x03, "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"),
        key33(0x02, "3590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66"),
    };
    auto ordered = SigningRoster::aggregate(official, secp.get());
    const std::array reverse{official[2], official[1], official[0]};
    auto reversed = SigningRoster::aggregate(reverse, secp.get());
    expect_ok(ctx, ordered, "official ordered roster aggregates");
    expect_ok(ctx, reversed, "official reversed roster aggregates");
    if (ordered && reversed) {
        ctx.expect(ordered->signing_key() == bytes32("90539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c"),
                   "official ordered aggregate matches");
        ctx.expect(reversed->signing_key() == bytes32("6204de8b083426dc6eaf9502d27024d53fc826bf7d2012148a0575435df54b2b"),
                   "official reversed aggregate matches");
        ctx.expect(ordered->key_list_hash() != reversed->key_list_hash(), "roster order binds key hash");
    }

    const std::array duplicate{keys[0], keys[1], keys[0]};
    expect_error(ctx, SigningRoster::aggregate(duplicate, secp.get()), purify::ErrorCode::BindingMismatch,
                 "nonadjacent duplicate keys reject instead of being counted twice");
    expect_error(ctx, SigningRoster::aggregate({}, secp.get()), purify::ErrorCode::EmptyInput,
                 "empty signing roster rejects");
    expect_error(ctx, SigningRoster::aggregate(keys, nullptr), purify::ErrorCode::MissingValue,
                 "roster without a secp context rejects");

    auto invalid = keys;
    invalid[0][0] = 0x04;
    expect_error(ctx, SigningRoster::aggregate(invalid, secp.get()), purify::ErrorCode::RangeViolation,
                 "noncompressed prefix rejects");
    invalid[0] = key33(0x02, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");
    expect_error(ctx, SigningRoster::aggregate(invalid, secp.get()), purify::ErrorCode::RangeViolation,
                 "out-of-field public x coordinate rejects");
    invalid[0] = key33(0x02, "0000000000000000000000000000000000000000000000000000000000000005");
    expect_error(ctx, SigningRoster::aggregate(invalid, secp.get()), purify::ErrorCode::RangeViolation,
                 "non-lifting public x coordinate rejects");

    auto opposite = keys[0];
    opposite[0] ^= 1;
    const std::array signed_keys{keys[0], opposite};
    auto signed_roster = SigningRoster::aggregate(signed_keys, secp.get());
    expect_ok(ctx, signed_roster, "opposite full points remain distinct member keys");
    if (signed_roster) {
        ctx.expect(signed_roster->members()[0].public_key != signed_roster->members()[1].public_key,
                   "individual parity is preserved rather than normalized away");
    }
}
