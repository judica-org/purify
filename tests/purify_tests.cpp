// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/secp_bridge.h"
#include "test_harness.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::sample_message;
using purify_test::sample_secret;
using purify::BulletproofAssignmentData;
using purify::BulletproofTranscript;
using purify::Bytes;
using purify::ErrorCode;
using purify::Expr;
using purify::FieldElement;
using purify::GeneratedKey;
using purify::NativeBulletproofCircuit;
using purify::Result;
using purify::Status;
using purify::Transcript;
using purify::UInt256;
using purify::UInt512;

std::string hex32(const std::array<unsigned char, 32>& bytes) {
    return purify::UInt256::from_bytes_be(bytes.data(), bytes.size()).to_hex();
}

FieldElement inverse_small(std::int64_t value) {
    return FieldElement::from_int(value).inverse();
}

FieldElement weighted_bppp_norm(std::span<const FieldElement> values, const FieldElement& rho) {
    FieldElement mu = rho * rho;
    FieldElement weight = mu;
    FieldElement total = FieldElement::zero();
    for (const FieldElement& value : values) {
        total = total + (weight * value * value);
        weight = weight * mu;
    }
    return total;
}

struct ToyBpppReduction {
    purify::bppp::NormArgInputs inputs;
    std::vector<FieldElement> n_vec;
    std::vector<FieldElement> l_vec;
    std::vector<FieldElement> c_vec;
    FieldElement rho = FieldElement::zero();
    FieldElement folded_value = FieldElement::zero();
};

ToyBpppReduction reduce_single_mul_gate_to_bppp(const FieldElement& left,
                                                const FieldElement& right,
                                                const FieldElement& output,
                                                const FieldElement& rho,
                                                const FieldElement& sqrt_minus_one) {
    const FieldElement one = FieldElement::one();
    const FieldElement inv2 = inverse_small(2);
    const FieldElement inv4 = inverse_small(4);
    const FieldElement rho_inv = rho.inverse();

    const FieldElement u = left + right;
    const FieldElement v = left - right;
    const FieldElement d_plus = inv4;
    const FieldElement d_minus = inv4.negate();

    auto two_square_terms = [&](const FieldElement& coefficient) {
        const FieldElement first = (coefficient + one) * inv2;
        const FieldElement second = sqrt_minus_one * (coefficient - one) * inv2;
        return std::array<FieldElement, 2>{first, second};
    };

    const std::array<FieldElement, 2> plus_terms = two_square_terms(d_plus);
    const std::array<FieldElement, 2> minus_terms = two_square_terms(d_minus);

    ToyBpppReduction out;
    out.rho = rho;
    out.folded_value = (left * right) - output;
    out.n_vec.reserve(4);
    out.l_vec = {output};
    out.c_vec = {FieldElement::from_int(-1)};

    FieldElement rho_weight_inv = rho_inv;
    for (const FieldElement& term : plus_terms) {
        out.n_vec.push_back(term * u * rho_weight_inv);
        rho_weight_inv = rho_weight_inv * rho_inv;
    }
    for (const FieldElement& term : minus_terms) {
        out.n_vec.push_back(term * v * rho_weight_inv);
        rho_weight_inv = rho_weight_inv * rho_inv;
    }

    out.inputs.rho = purify::bppp::scalar_bytes(rho);
    out.inputs.n_vec = purify::bppp::scalar_bytes(out.n_vec);
    out.inputs.l_vec = purify::bppp::scalar_bytes(out.l_vec);
    out.inputs.c_vec = purify::bppp::scalar_bytes(out.c_vec);
    return out;
}

FieldElement evaluate_toy_bppp_relation(const ToyBpppReduction& reduction) {
    FieldElement total = weighted_bppp_norm(reduction.n_vec, reduction.rho);
    for (std::size_t i = 0; i < reduction.l_vec.size(); ++i) {
        total = total + (reduction.l_vec[i] * reduction.c_vec[i]);
    }
    return total;
}

void test_sha256_many_bridge(TestContext& ctx) {
    const std::array<unsigned char, 2> part1{{'a', 'b'}};
    const std::array<unsigned char, 0> part2{};
    const std::array<unsigned char, 2> part3{{'c', 'd'}};
    const unsigned char* items[] = {part1.data(), part2.data(), part3.data()};
    const size_t item_lens[] = {part1.size(), part2.size(), part3.size()};

    std::array<unsigned char, 32> direct{};
    std::array<unsigned char, 32> many{};
    const Bytes concatenated{'a', 'b', 'c', 'd'};

    purify_sha256(direct.data(), concatenated.data(), concatenated.size());
    int ok = purify_sha256_many(many.data(), items, item_lens, std::size(items));
    ctx.expect(ok != 0, "purify_sha256_many accepts valid segmented input");
    if (ok != 0) {
        ctx.expect(many == direct, "purify_sha256_many matches purify_sha256 on concatenated data");
    }

    std::array<unsigned char, 32> empty_direct{};
    std::array<unsigned char, 32> empty_many{};
    purify_sha256(empty_direct.data(), nullptr, 0);
    ok = purify_sha256_many(empty_many.data(), nullptr, nullptr, 0);
    ctx.expect(ok != 0, "purify_sha256_many accepts an empty segment set");
    if (ok != 0) {
        ctx.expect(empty_many == empty_direct, "purify_sha256_many empty input matches purify_sha256 empty input");
    }

    const unsigned char* invalid_items[] = {nullptr};
    const size_t invalid_item_lens[] = {1};
    std::array<unsigned char, 32> invalid{};
    ok = purify_sha256_many(invalid.data(), invalid_items, invalid_item_lens, std::size(invalid_items));
    ctx.expect(ok == 0, "purify_sha256_many rejects null non-empty segments");
}

void test_tagged_hash(TestContext& ctx) {
    static const purify::TaggedHash kTaggedHash("tag");
    const Bytes message{'m', 's', 'g'};
    const std::array<unsigned char, 32> digest =
        kTaggedHash.digest(std::span<const unsigned char>(message.data(), message.size()));
    ctx.expect(hex32(digest) == "47a5e17b58647c13cc6ebc0aa583b62fb1643326877406ce276559a3bde55b3",
               "TaggedHash matches the secp256k1 tagged-sha256 test vector");
}

void test_biguint_arithmetic(TestContext& ctx) {
    const UInt256 value = UInt256::from_hex("ffffffffffffffffffffffffffffffff");
    ctx.expect(value.to_decimal() == "340282366920938463463374607431768211455",
               "BigUInt decimal formatting handles 128-bit values without native __int128");
    ctx.expect(purify::prime_p().to_decimal()
                   == "115792089237316195423570985008687907852837564279074904382605163141518161494337",
               "BigUInt decimal formatting handles full-width 256-bit values without native __int128");

    UInt256 borrow_edge = UInt256::from_hex("100000000000000000000000000000000");
    borrow_edge.sub_assign(UInt256::one());
    ctx.expect(borrow_edge.to_hex() == "ffffffffffffffffffffffffffffffff",
               "BigUInt subtraction borrows cleanly across limb boundaries");

    UInt256 saturated = UInt256::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    ctx.expect(!saturated.try_add_small(1), "BigUInt detects overflow when adding to the maximum value");

    const UInt512 squared = purify::multiply(value, value);
    ctx.expect(squared.to_hex() == "fffffffffffffffffffffffffffffffe00000000000000000000000000000001",
               "BigUInt wide multiplication preserves the full product");

    const auto [quotient, remainder] = purify::divmod_same(squared, purify::widen<8>(value));
    ctx.expect(quotient == purify::widen<8>(value) && remainder.is_zero(),
               "BigUInt long division round-trips a wide square product");
}

void test_known_sample(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Result<FieldElement> value = purify::eval(*secret, message);
    expect_ok(ctx, value, "sample eval succeeds");
    if (value.has_value()) {
#if PURIFY_USE_LEGACY_FIELD_HASHES
        ctx.expect(value->to_hex() == "afae82108c66397451ce376bc95751c398e40eaf8c768d1b18cc9dd4161cee35",
                   "sample eval matches the reference output");
#else
        ctx.expect(value->to_hex() == "4478a2677ecba287abe0d09e15b521e9193d136904297beae498054b512c3a3c",
                   "sample eval matches the reference output");
#endif
    }

    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, *secret);
    expect_ok(ctx, witness, "sample witness generation succeeds");
    if (!witness.has_value()) {
        return;
    }

    Result<bool> verifier_ok = purify::evaluate_verifier_circuit(message, *witness);
    expect_ok(ctx, verifier_ok, "sample verifier circuit evaluation succeeds");
    if (verifier_ok.has_value()) {
        ctx.expect(*verifier_ok, "sample verifier circuit accepts the generated witness");
    }

    Result<std::string> verifier_program = purify::verifier(message, witness->public_key);
    expect_ok(ctx, verifier_program, "sample verifier serialization succeeds");
    if (verifier_program.has_value()) {
        ctx.expect(!verifier_program->empty(), "sample verifier serialization is non-empty");
    }

    Result<Bytes> assignment = purify::prove_assignment(message, *secret);
    expect_ok(ctx, assignment, "sample assignment serialization succeeds");
    if (assignment.has_value()) {
        ctx.expect(!assignment->empty(), "sample assignment serialization is non-empty");
    }
}

void test_secret_hardening_path(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for secret hardening checks");
    if (!secret.has_value()) {
        return;
    }

    Result<std::pair<purify::UInt256, purify::UInt256>> unpacked = purify::unpack_secret(secret->packed());
    expect_ok(ctx, unpacked, "sample secret unpacks for hardened multiplication checks");
    if (!unpacked.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Bytes m1_input = purify::bytes_from_ascii("Eval/1/");
    m1_input.insert(m1_input.end(), message.begin(), message.end());
    Result<purify::JacobianPoint> m1 = purify::hash_to_curve(m1_input, purify::curve1());
    expect_ok(ctx, m1, "hash_to_curve for curve1 succeeds in hardened multiplication checks");
    Bytes m2_input = purify::bytes_from_ascii("Eval/2/");
    m2_input.insert(m2_input.end(), message.begin(), message.end());
    Result<purify::JacobianPoint> m2 = purify::hash_to_curve(m2_input, purify::curve2());
    expect_ok(ctx, m2, "hash_to_curve for curve2 succeeds in hardened multiplication checks");
    if (!m1.has_value() || !m2.has_value()) {
        return;
    }

    purify::AffinePoint p1_public = purify::curve1().affine(purify::curve1().mul(purify::generator1(), unpacked->first));
    purify::AffinePoint p2_public = purify::curve2().affine(purify::curve2().mul(purify::generator2(), unpacked->second));
    purify::AffinePoint q1_public = purify::curve1().affine(purify::curve1().mul(*m1, unpacked->first));
    purify::AffinePoint q2_public = purify::curve2().affine(purify::curve2().mul(*m2, unpacked->second));

    Result<purify::AffinePoint> p1_secret = purify::curve1().mul_secret_affine(purify::generator1(), unpacked->first);
    expect_ok(ctx, p1_secret, "hardened generator multiplication succeeds on curve1");
    Result<purify::AffinePoint> p2_secret = purify::curve2().mul_secret_affine(purify::generator2(), unpacked->second);
    expect_ok(ctx, p2_secret, "hardened generator multiplication succeeds on curve2");
    Result<purify::AffinePoint> q1_secret = purify::curve1().mul_secret_affine(*m1, unpacked->first);
    expect_ok(ctx, q1_secret, "hardened message multiplication succeeds on curve1");
    Result<purify::AffinePoint> q2_secret = purify::curve2().mul_secret_affine(*m2, unpacked->second);
    expect_ok(ctx, q2_secret, "hardened message multiplication succeeds on curve2");
    if (!p1_secret.has_value() || !p2_secret.has_value() || !q1_secret.has_value() || !q2_secret.has_value()) {
        return;
    }

    ctx.expect(p1_secret->x == p1_public.x && p1_secret->y == p1_public.y,
               "hardened curve1 generator multiplication matches the existing arithmetic");
    ctx.expect(p2_secret->x == p2_public.x && p2_secret->y == p2_public.y,
               "hardened curve2 generator multiplication matches the existing arithmetic");
    ctx.expect(q1_secret->x == q1_public.x && q1_secret->y == q1_public.y,
               "hardened curve1 message multiplication matches the existing arithmetic");
    ctx.expect(q2_secret->x == q2_public.x && q2_secret->y == q2_public.y,
               "hardened curve2 message multiplication matches the existing arithmetic");
}

void test_curve_mul_small_scalar_consistency(TestContext& ctx) {
    const UInt256 two = UInt256::from_u64(2);
    const UInt256 three = UInt256::from_u64(3);

    purify::AffinePoint curve1_double = purify::curve1().affine(purify::curve1().double_point(purify::generator1()));
    purify::AffinePoint curve1_mul2 = purify::curve1().affine(purify::curve1().mul(purify::generator1(), two));
    ctx.expect(curve1_double.x == curve1_mul2.x && curve1_double.y == curve1_mul2.y,
               "curve1 double_point matches mul(generator, 2)");

    purify::AffinePoint curve2_double = purify::curve2().affine(purify::curve2().double_point(purify::generator2()));
    purify::AffinePoint curve2_mul2 = purify::curve2().affine(purify::curve2().mul(purify::generator2(), two));
    ctx.expect(curve2_double.x == curve2_mul2.x && curve2_double.y == curve2_mul2.y,
               "curve2 double_point matches mul(generator, 2)");

    purify::AffinePoint curve1_add3 = purify::curve1().affine(
        purify::curve1().add(purify::curve1().double_point(purify::generator1()), purify::generator1()));
    purify::AffinePoint curve1_mul3 = purify::curve1().affine(purify::curve1().mul(purify::generator1(), three));
    ctx.expect(curve1_add3.x == curve1_mul3.x && curve1_add3.y == curve1_mul3.y,
               "curve1 add(double(generator), generator) matches mul(generator, 3)");
}

void test_key_space_derivation(TestContext& ctx) {
    UInt512 twice_half_n1 = purify::widen<8>(purify::half_n1());
    twice_half_n1.add_assign(purify::widen<8>(purify::half_n1()));
    twice_half_n1.add_small(1);
    ctx.expect(twice_half_n1 == purify::widen<8>(purify::order_n1()),
               "half_n1 is floor(order_n1 / 2)");

    UInt512 twice_half_n2 = purify::widen<8>(purify::half_n2());
    twice_half_n2.add_assign(purify::widen<8>(purify::half_n2()));
    twice_half_n2.add_small(1);
    ctx.expect(twice_half_n2 == purify::widen<8>(purify::order_n2()),
               "half_n2 is floor(order_n2 / 2)");

    const UInt512 derived_secret_space = purify::multiply(purify::half_n1(), purify::half_n2());
    ctx.expect(derived_secret_space == purify::packed_secret_key_space_size(),
               "packed secret key space size is half_n1 * half_n2");

    UInt512 last_secret = purify::packed_secret_key_space_size();
    last_secret.sub_assign(UInt512::one());
    Result<std::pair<UInt256, UInt256>> unpacked_secret = purify::unpack_secret(last_secret);
    expect_ok(ctx, unpacked_secret, "the largest valid packed secret unpacks");
    if (unpacked_secret.has_value()) {
        ctx.expect(unpacked_secret->first == purify::half_n1() && unpacked_secret->second == purify::half_n2(),
                   "the largest valid packed secret decodes to (half_n1, half_n2)");
    }

    const UInt512 derived_public_space = purify::multiply(purify::prime_p(), purify::prime_p());
    ctx.expect(derived_public_space == purify::packed_public_key_space_size(),
               "packed public key space size is p^2");

    UInt256 max_x = purify::prime_p();
    max_x.sub_assign(UInt256::one());
    const UInt512 max_public = purify::pack_public(max_x, max_x);
    UInt512 last_public = purify::packed_public_key_space_size();
    last_public.sub_assign(UInt512::one());
    ctx.expect(max_public == last_public,
               "packing (p - 1, p - 1) reaches the largest valid packed public key");

    Result<std::pair<UInt256, UInt256>> unpacked_public = purify::unpack_public(last_public);
    expect_ok(ctx, unpacked_public, "the largest valid packed public key unpacks");
    if (unpacked_public.has_value()) {
        ctx.expect(unpacked_public->first == max_x && unpacked_public->second == max_x,
                   "the largest valid packed public key decodes to (p - 1, p - 1)");
    }
}

void test_field_sqrt_zero(TestContext& ctx) {
    std::optional<FieldElement> zero_sqrt = FieldElement::zero().sqrt();
    ctx.expect(zero_sqrt.has_value(), "FieldElement::sqrt accepts zero");
    if (zero_sqrt.has_value()) {
        ctx.expect(zero_sqrt->is_zero(), "FieldElement::sqrt(0) returns 0");
    }
}

void test_library_key_generation(TestContext& ctx) {
    std::array<unsigned char, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>(i);
    }

    Result<purify::GeneratedKey> seeded_a = purify::generate_key(std::span<const unsigned char>(seed));
    expect_ok(ctx, seeded_a, "seeded generate_key succeeds");
    Result<purify::GeneratedKey> seeded_b = purify::generate_key(std::span<const unsigned char>(seed));
    expect_ok(ctx, seeded_b, "seeded generate_key is repeatable");
    if (seeded_a.has_value() && seeded_b.has_value()) {
        ctx.expect(seeded_a->secret == seeded_b->secret, "seeded generate_key is deterministic");
        ctx.expect(seeded_a->public_key == seeded_b->public_key, "seeded generate_key derives a stable public key");
        ctx.expect(seeded_a->secret.packed().to_hex()
                       == "244033992dfe583985332da27b7cdfddaf05df5c5c3bc8db763af6dd75f07ee28737e8d9a8d5592a3f10944c89f6ae82e53f76ae9dc17c77c22cf7a352cdb59c",
                   "seeded generate_key preserves the legacy packed-secret test vector");
#if PURIFY_USE_LEGACY_FIELD_HASHES
        ctx.expect(seeded_a->public_key.to_hex()
                       == "c000e3169636f34eb81b1d25280219abd1bb2f1185c6b55780e53f2a3b95d97b2b1576df976499bcc7687673d7efeb5621d2e5c6c2939aa4a57276185b6bf09e",
                   "seeded generate_key preserves the legacy packed-public-key test vector");
#else
        ctx.expect(seeded_a->public_key.to_hex()
                       == "79b928249e7889d70fe96c9b748d9d3863f5ac48e66340c5c8962aba2f12bd0985bb7f26a806cf0bfc8f149984117903917723d62bd4059475f6287c05622397",
                   "seeded generate_key preserves the legacy packed-public-key test vector");
#endif
    }

    Bytes short_seed(15, 0x42);
    expect_error(ctx, purify::generate_key(std::span<const unsigned char>(short_seed)), ErrorCode::RangeViolation,
                 "generate_key rejects seed material shorter than 16 bytes");

    std::array<unsigned char, 16> min_seed{};
    for (std::size_t i = 0; i < min_seed.size(); ++i) {
        min_seed[i] = static_cast<unsigned char>(0xa0 + i);
    }
    Result<purify::GeneratedKey> min_seed_a = purify::generate_key(std::span<const unsigned char>(min_seed));
    expect_ok(ctx, min_seed_a, "minimum-length seeded generate_key succeeds");
    Result<purify::GeneratedKey> min_seed_b = purify::generate_key(std::span<const unsigned char>(min_seed));
    expect_ok(ctx, min_seed_b, "minimum-length seeded generate_key is repeatable");
    if (min_seed_a.has_value() && min_seed_b.has_value()) {
        ctx.expect(min_seed_a->secret == min_seed_b->secret, "minimum-length seeded generate_key is deterministic");
        ctx.expect(min_seed_a->public_key == min_seed_b->public_key,
                   "minimum-length seeded generate_key derives a stable public key");
    }

    auto fill_one = [](std::span<unsigned char> bytes) noexcept {
        std::fill(bytes.begin(), bytes.end(), static_cast<unsigned char>(0));
        if (!bytes.empty()) {
            bytes.back() = 1;
        }
    };
    Result<purify::GeneratedKey> callable_key = purify::generate_key(fill_one);
    expect_ok(ctx, callable_key, "generate_key accepts a no-fail byte-fill callable");
    Result<purify::SecretKey> secret_one = purify::SecretKey::from_packed(purify::UInt512::one());
    expect_ok(ctx, secret_one, "SecretKey::from_packed accepts the packed secret one");
    if (secret_one.has_value()) {
        Result<purify::GeneratedKey> expected_one = purify::derive_key(*secret_one);
        expect_ok(ctx, expected_one, "derive_key succeeds for the packed secret one");
        if (callable_key.has_value() && expected_one.has_value()) {
            ctx.expect(callable_key->secret == expected_one->secret,
                       "callable-based generate_key uses the supplied bytes");
            ctx.expect(callable_key->public_key == expected_one->public_key,
                       "callable-based generate_key derives the expected public key");
        }
    }

    auto fill_two = [](std::span<unsigned char> bytes) noexcept -> Status {
        std::fill(bytes.begin(), bytes.end(), static_cast<unsigned char>(0));
        if (!bytes.empty()) {
            bytes.back() = 2;
        }
        return {};
    };
    Result<purify::GeneratedKey> checked_callable_key = purify::generate_key(fill_two);
    expect_ok(ctx, checked_callable_key, "generate_key accepts a checked byte-fill callable");

    Result<purify::GeneratedKey> os_key = purify::generate_key();
    expect_ok(ctx, os_key, "default generate_key succeeds");
    if (os_key.has_value()) {
        ctx.expect(purify::is_valid_secret_key(os_key->secret.packed()),
                   "default generate_key returns a canonical packed secret");
        Result<purify::GeneratedKey> roundtrip = purify::derive_key(os_key->secret);
        expect_ok(ctx, roundtrip, "default generate_key output round-trips through derive_key");
        if (roundtrip.has_value()) {
            ctx.expect(roundtrip->public_key == os_key->public_key,
                       "default generate_key public key matches a round-trip derivation");
        }
    }
}

void test_bip340_key_derivation(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for BIP340 derivation");
    if (!secret.has_value()) {
        return;
    }

    Result<purify::Bip340Key> key_a = purify::derive_bip340_key(*secret);
    expect_ok(ctx, key_a, "derive_bip340_key succeeds");
    Result<purify::Bip340Key> key_b = purify::derive_bip340_key(*secret);
    expect_ok(ctx, key_b, "derive_bip340_key is deterministic");
    if (!key_a.has_value() || !key_b.has_value()) {
        return;
    }

    ctx.expect(key_a->seckey == key_b->seckey, "derive_bip340_key returns a stable secret key");
    ctx.expect(key_a->xonly_pubkey == key_b->xonly_pubkey, "derive_bip340_key returns a stable x-only pubkey");
#if PURIFY_USE_LEGACY_FIELD_HASHES
    ctx.expect(hex32(key_a->seckey) == "d63b91a76a1231be98f516d544312b7337ece46564e002ed50df0cd77a1b610e",
               "derive_bip340_key matches the expected sample canonical seckey");
    ctx.expect(hex32(key_a->xonly_pubkey) == "82b3533efb11978a9447ba70d452f022d10bd9b8347985fdc9b36aa984190856",
               "derive_bip340_key matches the expected sample x-only pubkey");
#else
    ctx.expect(hex32(key_a->seckey) == "3c0d31c7ed35bb439bfc7b878afc32a5e75465fee7680c937f410064a65834ef",
               "derive_bip340_key matches the expected sample canonical seckey");
    ctx.expect(hex32(key_a->xonly_pubkey) == "bfe94a7fb4e1bc20ab083bd21505d35002005e2c392b26a5cfbe10cf89b8dbc8",
               "derive_bip340_key matches the expected sample x-only pubkey");
#endif

    std::array<unsigned char, 32> canonical = key_a->seckey;
    std::array<unsigned char, 32> xonly = {};
    ctx.expect(purify_bip340_key_from_seckey(canonical.data(), xonly.data()) == 1,
               "bridge accepts the derived canonical BIP340 secret key");
    ctx.expect(canonical == key_a->seckey,
               "derive_bip340_key returns an idempotently canonicalized even-Y secret key");
    ctx.expect(xonly == key_a->xonly_pubkey,
               "derived x-only pubkey matches the canonical secret key");
}

void test_secret_key_validation(TestContext& ctx) {
    Bytes message = sample_message();

    UInt512 invalid = purify::key_space_size();
    expect_error(ctx, purify::SecretKey::from_packed(invalid), ErrorCode::RangeViolation,
                 "SecretKey::from_packed rejects the packed-secret upper bound");

    UInt512 last_valid = purify::key_space_size();
    last_valid.sub_assign(purify::widen<8>(purify::half_n1()));
    Result<purify::SecretKey> canonical_secret = purify::SecretKey::from_packed(last_valid);
    expect_ok(ctx, canonical_secret, "SecretKey::from_packed accepts the last canonical packed secret");
    if (canonical_secret.has_value()) {
        expect_ok(ctx, purify::derive_key(*canonical_secret), "derive_key accepts the last canonical packed secret");
        expect_ok(ctx, purify::eval(*canonical_secret, message), "eval accepts the last canonical packed secret");
        expect_ok(ctx, purify::prove_assignment_data(message, *canonical_secret),
                  "prove_assignment_data accepts the last canonical packed secret");
        expect_ok(ctx, purify::derive_bip340_key(*canonical_secret),
                  "derive_bip340_key accepts the last canonical packed secret");
    }
}

void test_public_key_validation(TestContext& ctx) {
    Bytes message = sample_message();

    UInt512 invalid = purify::packed_public_key_space_size();
    expect_error(ctx, purify::verifier(message, invalid), ErrorCode::RangeViolation,
                 "verifier rejects the packed-public-key upper bound");
    expect_error(ctx, purify::verifier_circuit(message, invalid), ErrorCode::RangeViolation,
                 "verifier_circuit rejects the packed-public-key upper bound");
}

void test_equal_lowering(TestContext& ctx) {
    Transcript transcript;
    Expr witness = transcript.secret(std::nullopt);
    transcript.equal(witness, Expr(0));

    BulletproofTranscript bp;
    Status lower_status = bp.from_transcript(transcript, 0);
    expect_ok(ctx, lower_status, "from_transcript lowers equality constraints with raw witnesses");
    if (!lower_status.has_value()) {
        return;
    }

    NativeBulletproofCircuit circuit = bp.native_circuit();
    auto vars = transcript.varmap();
    vars[0] = FieldElement::one();
    Result<BulletproofAssignmentData> bad_assignment = bp.assignment_data(vars, FieldElement::zero());
    expect_ok(ctx, bad_assignment, "assignment_data materializes a raw-witness equality assignment");
    if (bad_assignment.has_value()) {
        ctx.expect(!circuit.evaluate(*bad_assignment), "lowered equality constraint rejects a non-zero witness");
    }

    vars[0] = FieldElement::zero();
    Result<BulletproofAssignmentData> good_assignment = bp.assignment_data(vars, FieldElement::zero());
    expect_ok(ctx, good_assignment, "assignment_data materializes a satisfying raw-witness equality assignment");
    if (good_assignment.has_value()) {
        ctx.expect(circuit.evaluate(*good_assignment), "lowered equality constraint accepts the satisfying witness");
    }
}

void test_expr_builder(TestContext& ctx) {
    Transcript transcript;
    Expr x = transcript.secret(FieldElement::from_int(3));
    Expr y = transcript.secret(FieldElement::from_int(5));

    Expr built = purify::ExprBuilder::reserved(x.linear().size() + y.linear().size())
        .add(7)
        .add_scaled(x, 2)
        .add_scaled(y, -3)
        .build();
    Expr expected = Expr(7) + 2 * x - 3 * y;

    ctx.expect(built == expected, "ExprBuilder flattens affine combinations equivalently");
    ctx.expect(transcript.evaluate(built) == transcript.evaluate(expected),
               "ExprBuilder preserves affine evaluation semantics");
}

void test_expr_cache_ordering(TestContext& ctx) {
    Transcript transcript;
    Expr x = transcript.secret(std::nullopt);
    Expr y = transcript.secret(std::nullopt);

    Expr first = purify::ExprBuilder::reserved(2).add_scaled(y, 2).add(x).build();
    Expr second = purify::ExprBuilder::reserved(2).add(x).add_scaled(y, 2).build();

    ctx.expect(first == second, "ExprBuilder canonicalizes equivalent affine expressions");
    ctx.expect(!(first < second) && !(second < first),
               "Expr ordering treats equivalent affine expressions as the same key");

    Expr out1 = transcript.mul(first, y);
    Expr out2 = transcript.mul(second, y);
    ctx.expect(out1 == out2, "Transcript mul cache reuses equivalent affine expression inputs");
    ctx.expect(transcript.muls().size() == 1,
               "Transcript mul cache stores one entry for equivalent affine expression keys");

    transcript.boolean(first);
    transcript.boolean(second);
    ctx.expect(transcript.muls().size() == 2,
               "Transcript boolean cache deduplicates equivalent affine expression keys");
}

void test_bppp_move_overload(TestContext& ctx) {
    purify::bppp::NormArgInputs inputs;
    Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(std::move(inputs));
    expect_error(ctx, proof, ErrorCode::EmptyInput, "rvalue prove_norm_arg overload preserves empty-input validation");
}

void test_toy_bppp_circuit_reduction(TestContext& ctx) {
    std::optional<FieldElement> sqrt_minus_one = FieldElement::from_int(-1).sqrt();
    ctx.expect(sqrt_minus_one.has_value(), "the secp256k1 scalar field admits sqrt(-1) for the toy BPPP reduction");
    if (!sqrt_minus_one.has_value()) {
        return;
    }

    const FieldElement rho = FieldElement::from_int(7);
    const ToyBpppReduction valid =
        reduce_single_mul_gate_to_bppp(FieldElement::from_int(3), FieldElement::from_int(4),
                                       FieldElement::from_int(12), rho, *sqrt_minus_one);
    const FieldElement valid_relation = evaluate_toy_bppp_relation(valid);
    ctx.expect(valid_relation == valid.folded_value,
               "toy BPPP reduction preserves the one-gate folded relation for a satisfying witness");
    ctx.expect(valid.folded_value.is_zero(),
               "the satisfying one-gate witness reduces to a zero folded scalar");

    Result<purify::bppp::NormArgProof> valid_proof = purify::bppp::prove_norm_arg(valid.inputs);
    expect_ok(ctx, valid_proof, "toy BPPP reduction proves a satisfying one-gate relation");
    if (!valid_proof.has_value()) {
        return;
    }
    ctx.expect(purify::bppp::verify_norm_arg(*valid_proof),
               "toy BPPP reduction verifies for a satisfying one-gate witness");

    const ToyBpppReduction invalid =
        reduce_single_mul_gate_to_bppp(FieldElement::from_int(3), FieldElement::from_int(4),
                                       FieldElement::from_int(11), rho, *sqrt_minus_one);
    const FieldElement invalid_relation = evaluate_toy_bppp_relation(invalid);
    ctx.expect(invalid_relation == invalid.folded_value,
               "toy BPPP reduction preserves the one-gate folded relation for a non-satisfying witness");
    ctx.expect(!invalid.folded_value.is_zero(),
               "the non-satisfying one-gate witness reduces to a non-zero folded scalar");

    Result<purify::bppp::NormArgProof> invalid_proof = purify::bppp::prove_norm_arg(invalid.inputs);
    expect_ok(ctx, invalid_proof, "toy BPPP reduction also proves a non-satisfying witness under its own commitment");
    if (!invalid_proof.has_value()) {
        return;
    }
    ctx.expect(purify::bppp::verify_norm_arg(*invalid_proof),
               "standalone BPPP accepts the non-satisfying toy witness because it proves the committed relation value");

    purify::bppp::NormArgProof rebound = *invalid_proof;
    rebound.commitment = valid_proof->commitment;
    ctx.expect(!purify::bppp::verify_norm_arg(rebound),
               "swapping in the satisfying commitment rejects the non-satisfying toy witness proof");

    Result<purify::bppp::PointBytes> anchored_commitment = purify::bppp::commit_norm_arg(valid.inputs);
    expect_ok(ctx, anchored_commitment, "toy BPPP reduction computes an external satisfying commitment");
    if (!anchored_commitment.has_value()) {
        return;
    }

    Result<purify::bppp::NormArgProof> anchored_valid =
        purify::bppp::prove_norm_arg_to_commitment(valid.inputs, *anchored_commitment);
    expect_ok(ctx, anchored_valid, "toy BPPP reduction proves against an external satisfying commitment");
    if (!anchored_valid.has_value()) {
        return;
    }
    ctx.expect(purify::bppp::verify_norm_arg(*anchored_valid),
               "anchored toy BPPP proof verifies against the external satisfying commitment");

    Result<purify::bppp::NormArgProof> anchored_invalid =
        purify::bppp::prove_norm_arg_to_commitment(invalid.inputs, *anchored_commitment);
    expect_error(ctx, anchored_invalid, ErrorCode::BackendRejectedInput,
                 "toy BPPP reduction rejects a non-satisfying witness against the satisfying commitment");
}

void test_experimental_circuit_norm_arg_one_gate(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};

    Bytes binding = purify::bytes_from_ascii("one-gate-norm-arg-binding");

    Result<purify::bppp::PointBytes> witness_commitment =
        purify::bppp::commit_experimental_circuit_witness(circuit, assignment, binding);
    expect_ok(ctx, witness_commitment, "commit_experimental_circuit_witness commits the reduced one-gate witness");
    if (!witness_commitment.has_value()) {
        return;
    }

    Result<purify::bppp::ExperimentalCircuitNormArgProof> proof =
        purify::bppp::prove_experimental_circuit_norm_arg_to_commitment(circuit, assignment, *witness_commitment, binding);
    expect_ok(ctx, proof, "prove_experimental_circuit_norm_arg_to_commitment proves a satisfying one-gate circuit");
    if (!proof.has_value()) {
        return;
    }
    ctx.expect(proof->witness_commitment == *witness_commitment,
               "experimental circuit norm argument preserves the caller-supplied reduced witness commitment");

    Result<bool> verified = purify::bppp::verify_experimental_circuit_norm_arg(circuit, *proof, binding);
    expect_ok(ctx, verified, "verify_experimental_circuit_norm_arg succeeds on the one-gate proof");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit norm argument verifies on the one-gate circuit");
    }

    Result<bool> wrong_binding =
        purify::bppp::verify_experimental_circuit_norm_arg(circuit, *proof,
                                                           purify::bytes_from_ascii("one-gate-norm-arg-binding-wrong"));
    expect_ok(ctx, wrong_binding, "verify_experimental_circuit_norm_arg runs with a wrong one-gate binding");
    if (wrong_binding.has_value()) {
        ctx.expect(!*wrong_binding, "experimental circuit norm argument is bound to the supplied one-gate statement bytes");
    }

    BulletproofAssignmentData invalid = assignment;
    invalid.output[0] = FieldElement::from_int(11);
    Result<purify::bppp::ExperimentalCircuitNormArgProof> invalid_proof =
        purify::bppp::prove_experimental_circuit_norm_arg(circuit, invalid, binding);
    expect_error(ctx, invalid_proof, ErrorCode::EquationMismatch,
                 "prove_experimental_circuit_norm_arg rejects a non-satisfying one-gate witness");
}

void test_experimental_circuit_norm_arg_sample_verifier(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for the experimental circuit norm argument");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, *secret);
    expect_ok(ctx, witness, "prove_assignment_data succeeds for the experimental circuit norm argument");
    if (!witness.has_value()) {
        return;
    }

    Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(message, witness->public_key);
    expect_ok(ctx, circuit, "verifier_circuit succeeds for the experimental circuit norm argument");
    if (!circuit.has_value()) {
        return;
    }

    Bytes binding = purify::bytes_from_ascii("sample-verifier-norm-arg-binding");
    Result<purify::bppp::ExperimentalCircuitNormArgProof> proof =
        purify::bppp::prove_experimental_circuit_norm_arg(*circuit, witness->assignment, binding);
    expect_ok(ctx, proof, "prove_experimental_circuit_norm_arg proves the sample verifier circuit");
    if (!proof.has_value()) {
        return;
    }

    Result<bool> verified = purify::bppp::verify_experimental_circuit_norm_arg(*circuit, *proof, binding);
    expect_ok(ctx, verified, "verify_experimental_circuit_norm_arg succeeds on the sample verifier circuit");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit norm argument verifies on the sample verifier circuit");
    }

    purify::bppp::ExperimentalCircuitNormArgProof tampered = *proof;
    tampered.proof.back() ^= 0x01;
    Result<bool> tampered_ok = purify::bppp::verify_experimental_circuit_norm_arg(*circuit, tampered, binding);
    expect_ok(ctx, tampered_ok, "verify_experimental_circuit_norm_arg runs on a tampered sample proof");
    if (tampered_ok.has_value()) {
        ctx.expect(!*tampered_ok, "tampering the sample norm-argument proof is detected");
    }
}

void test_experimental_circuit_zk_norm_arg_one_gate(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};

    purify::bppp::ScalarBytes nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(0x21 + i);
    }
    Bytes binding = purify::bytes_from_ascii("one-gate-zk-norm-arg-binding");

    Result<purify::bppp::ExperimentalCircuitZkNormArgProof> proof =
        purify::bppp::prove_experimental_circuit_zk_norm_arg(circuit, assignment, nonce, binding);
    expect_ok(ctx, proof, "prove_experimental_circuit_zk_norm_arg proves a satisfying one-gate circuit");
    if (!proof.has_value()) {
        return;
    }

    ctx.expect(proof->a_commitment != purify::bppp::PointBytes{},
               "experimental circuit ZK proof carries a non-empty A commitment");
    ctx.expect(proof->s_commitment != purify::bppp::PointBytes{},
               "experimental circuit ZK proof carries a non-empty S commitment");

    Result<bool> verified = purify::bppp::verify_experimental_circuit_zk_norm_arg(circuit, *proof, binding);
    expect_ok(ctx, verified, "verify_experimental_circuit_zk_norm_arg succeeds on the one-gate proof");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit ZK norm argument verifies on the one-gate circuit");
    }

    Result<bool> wrong_binding =
        purify::bppp::verify_experimental_circuit_zk_norm_arg(circuit, *proof,
                                                              purify::bytes_from_ascii("one-gate-zk-norm-arg-binding-wrong"));
    expect_ok(ctx, wrong_binding, "verify_experimental_circuit_zk_norm_arg runs with a wrong one-gate binding");
    if (wrong_binding.has_value()) {
        ctx.expect(!*wrong_binding, "experimental circuit ZK norm argument is bound to the supplied one-gate statement bytes");
    }
}

void test_experimental_circuit_zk_norm_arg_sample_verifier(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for the experimental circuit ZK norm argument");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, *secret);
    expect_ok(ctx, witness, "prove_assignment_data succeeds for the experimental circuit ZK norm argument");
    if (!witness.has_value()) {
        return;
    }

    Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(message, witness->public_key);
    expect_ok(ctx, circuit, "verifier_circuit succeeds for the experimental circuit ZK norm argument");
    if (!circuit.has_value()) {
        return;
    }

    purify::bppp::ScalarBytes nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(0x80 + i);
    }
    Bytes binding = purify::bytes_from_ascii("sample-verifier-zk-norm-arg-binding");

    Result<purify::bppp::ExperimentalCircuitZkNormArgProof> proof =
        purify::bppp::prove_experimental_circuit_zk_norm_arg(*circuit, witness->assignment, nonce, binding);
    expect_ok(ctx, proof, "prove_experimental_circuit_zk_norm_arg proves the sample verifier circuit");
    if (!proof.has_value()) {
        return;
    }

    Result<bool> verified = purify::bppp::verify_experimental_circuit_zk_norm_arg(*circuit, *proof, binding);
    expect_ok(ctx, verified, "verify_experimental_circuit_zk_norm_arg succeeds on the sample verifier circuit");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit ZK norm argument verifies on the sample verifier circuit");
    }

    purify::bppp::ExperimentalCircuitZkNormArgProof tampered = *proof;
    tampered.proof.back() ^= 0x01;
    Result<bool> tampered_ok = purify::bppp::verify_experimental_circuit_zk_norm_arg(*circuit, tampered, binding);
    expect_ok(ctx, tampered_ok, "verify_experimental_circuit_zk_norm_arg runs on a tampered sample proof");
    if (tampered_ok.has_value()) {
        ctx.expect(!*tampered_ok, "tampering the sample ZK norm-argument proof is detected");
    }
}

void test_packed_circuit_with_slack(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t base_constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, base_constraint, FieldElement::one());
    circuit.add_commitment_term(0, base_constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};

    NativeBulletproofCircuit::PackedSlackPlan slack;
    slack.constraint_slack = 1;
    slack.wo = {1};
    slack.wv = {1};

    Result<NativeBulletproofCircuit::PackedWithSlack> packed = circuit.pack_with_slack(slack);
    expect_ok(ctx, packed, "pack_with_slack succeeds on a one-gate circuit");
    if (!packed.has_value()) {
        return;
    }

    ctx.expect(packed->constraint_count() == 1, "packed circuit starts at the base constraint count");
    std::size_t extra_constraint = packed->add_constraint(FieldElement::zero());
    packed->add_output_term(0, extra_constraint, FieldElement::one());
    packed->add_commitment_term(0, extra_constraint, FieldElement::from_int(-1));
    ctx.expect(packed->constraint_count() == 2, "packed circuit can append one extra constraint inside slack");
    ctx.expect(packed->evaluate(assignment), "packed circuit evaluates successfully after in-place mutation");

    packed->reset();
    ctx.expect(packed->constraint_count() == 1, "packed circuit reset restores the base constraint count");

    Result<NativeBulletproofCircuit> unpacked = packed->unpack();
    expect_ok(ctx, unpacked, "packed circuit unpacks after reset");
    if (!unpacked.has_value()) {
        return;
    }
    ctx.expect(unpacked->c.size() == circuit.c.size(), "unpacked reset circuit restores the original constraint count");
    ctx.expect(unpacked->evaluate(assignment), "unpacked reset circuit still accepts the original witness");
}

void test_packed_circuit_move_leaves_empty_source(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(2)};
    assignment.right = {FieldElement::from_int(5)};
    assignment.output = {FieldElement::from_int(10)};
    assignment.commitments = {FieldElement::from_int(10)};

    Result<NativeBulletproofCircuit::PackedWithSlack> packed = circuit.pack_with_slack();
    expect_ok(ctx, packed, "pack_with_slack succeeds before move regression coverage");
    if (!packed.has_value()) {
        return;
    }

    NativeBulletproofCircuit::PackedWithSlack moved = std::move(*packed);
    ctx.expect(moved.has_valid_shape(), "moved-to packed circuit remains valid");
    ctx.expect(moved.evaluate(assignment), "moved-to packed circuit still evaluates the original witness");

    ctx.expect(packed->has_valid_shape(), "moved-from packed circuit remains internally consistent");
    ctx.expect(packed->n_gates() == 0, "moved-from packed circuit clears its gate count");
    ctx.expect(packed->n_commitments() == 0, "moved-from packed circuit clears its commitment count");
    ctx.expect(packed->constraint_count() == 0, "moved-from packed circuit clears its constraint count");
    ctx.expect(packed->constraint_capacity() == 0, "moved-from packed circuit clears its constraint capacity");
    ctx.expect(packed->constants().empty(), "moved-from packed circuit exposes no constants");
}

void test_circuit_template_partial_final_eval(TestContext& ctx) {
    Result<purify::SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for template partial/final evaluation");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Result<purify::puresign::MessageProofCache> cache = purify::puresign::MessageProofCache::build(message);
    expect_ok(ctx, cache, "MessageProofCache::build succeeds for template partial/final evaluation");
    if (!cache.has_value()) {
        return;
    }

    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(cache->eval_input, *secret);
    expect_ok(ctx, witness, "prove_assignment_data succeeds for template partial/final evaluation");
    if (!witness.has_value()) {
        return;
    }

    Result<bool> partial_ok = cache->circuit_template.partial_evaluate(witness->assignment);
    expect_ok(ctx, partial_ok, "circuit template partial_evaluate succeeds");
    if (partial_ok.has_value()) {
        ctx.expect(*partial_ok, "circuit template partial_evaluate accepts the generated witness");
    }

    Result<bool> final_ok = cache->circuit_template.final_evaluate(witness->assignment, witness->public_key);
    expect_ok(ctx, final_ok, "circuit template final_evaluate succeeds");
    if (final_ok.has_value()) {
        ctx.expect(*final_ok, "circuit template final_evaluate accepts the bound public key");
    }
}

}  // namespace

void run_purify_tests(TestContext& ctx) {
    test_sha256_many_bridge(ctx);
    test_tagged_hash(ctx);
    test_biguint_arithmetic(ctx);
    test_known_sample(ctx);
    test_secret_hardening_path(ctx);
    test_curve_mul_small_scalar_consistency(ctx);
    test_key_space_derivation(ctx);
    test_field_sqrt_zero(ctx);
    test_library_key_generation(ctx);
    test_bip340_key_derivation(ctx);
    test_secret_key_validation(ctx);
    test_public_key_validation(ctx);
    test_equal_lowering(ctx);
    test_expr_builder(ctx);
    test_expr_cache_ordering(ctx);
    test_bppp_move_overload(ctx);
    test_toy_bppp_circuit_reduction(ctx);
    test_experimental_circuit_norm_arg_one_gate(ctx);
    test_experimental_circuit_norm_arg_sample_verifier(ctx);
    test_experimental_circuit_zk_norm_arg_one_gate(ctx);
    test_experimental_circuit_zk_norm_arg_sample_verifier(ctx);
    test_packed_circuit_with_slack(ctx);
    test_packed_circuit_move_leaves_empty_source(ctx);
    test_circuit_template_partial_final_eval(ctx);
}
