// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <span>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/secp_bridge.h"
#include "test_harness.hpp"

namespace {

using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify_test::TestContext;
using purify_test::expect_ok;
using Digest = std::array<unsigned char, 32>;

// This test-local gadget is a first verifier component, not a proof of a
// child verifier. Its inputs remain symbolic even when the fixture knows them.
struct Word {
    std::array<Expr, 32> bits;
    std::optional<std::uint32_t> value;
};

Word constant(std::uint32_t value) {
    Word out{{}, value};
    for (std::size_t i = 0; i < 32; ++i) out.bits[i] = Expr((value >> i) & 1U);
    return out;
}

Expr packed(const Word& word) {
    auto out = purify::ExprBuilder::reserved(32);
    for (std::size_t i = 0; i < 32; ++i) out.add_scaled(word.bits[i], std::int64_t{1} << i);
    return out.build();
}

Expr product(purify::Transcript& transcript, const Expr& a, const Expr& b) {
    if (a.linear().empty()) return a.constant() * b;
    if (b.linear().empty()) return b.constant() * a;
    return transcript.mul(a, b);
}

Word xor_words(purify::Transcript& transcript, const Word& a, const Word& b) {
    Word out;
    for (std::size_t i = 0; i < 32; ++i) {
        out.bits[i] = a.bits[i] + b.bits[i] - 2 * product(transcript, a.bits[i], b.bits[i]);
    }
    if (a.value && b.value) out.value = *a.value ^ *b.value;
    return out;
}

Word rotate(const Word& word, unsigned count) {
    Word out;
    for (std::size_t i = 0; i < 32; ++i) out.bits[i] = word.bits[(i + count) % 32];
    if (word.value) out.value = std::rotr(*word.value, static_cast<int>(count));
    return out;
}

Word shift(const Word& word, unsigned count) {
    Word out;
    for (std::size_t i = 0; i < 32; ++i) out.bits[i] = i + count < 32 ? word.bits[i + count] : Expr(0);
    if (word.value) out.value = *word.value >> count;
    return out;
}

Word sigma(purify::Transcript& transcript, const Word& word, unsigned a, unsigned b,
           unsigned c, bool shift_last = false) {
    return xor_words(transcript, xor_words(transcript, rotate(word, a), rotate(word, b)),
                     shift_last ? shift(word, c) : rotate(word, c));
}

Word choose(purify::Transcript& transcript, const Word& x, const Word& y, const Word& z) {
    Word out;
    for (std::size_t i = 0; i < 32; ++i) {
        out.bits[i] = z.bits[i] + product(transcript, x.bits[i], y.bits[i] - z.bits[i]);
    }
    if (x.value && y.value && z.value) out.value = (*x.value & *y.value) ^ (~*x.value & *z.value);
    return out;
}

Word majority(purify::Transcript& transcript, const Word& x, const Word& y, const Word& z) {
    Word out;
    for (std::size_t i = 0; i < 32; ++i) {
        const auto xy = product(transcript, x.bits[i], y.bits[i]);
        out.bits[i] = xy + product(transcript, z.bits[i], x.bits[i] + y.bits[i] - 2 * xy);
    }
    if (x.value && y.value && z.value) {
        out.value = (*x.value & *y.value) ^ (*x.value & *z.value) ^ (*y.value & *z.value);
    }
    return out;
}

Word add_words(purify::Transcript& transcript, std::initializer_list<Word> words) {
    assert(words.size() >= 2 && words.size() <= 5);
    Expr sum(0);
    std::optional<std::uint64_t> value{0};
    for (const auto& word : words) {
        sum = sum + packed(word);
        if (value && word.value) *value += *word.value;
        else value.reset();
    }
    // At most five 32-bit summands. Bounding the entire sum to 35 bits makes
    // this an integer equality in F_n; the high bits are the modular carry.
    const std::size_t width = 32 + std::bit_width(words.size() - 1);
    auto reconstructed = purify::ExprBuilder::reserved(width);
    Word out;
    for (std::size_t i = 0; i < width; ++i) {
        const auto known = value ? std::optional<FieldElement>(FieldElement::from_u64((*value >> i) & 1U)) : std::nullopt;
        const auto bit = transcript.boolean(transcript.secret(known));
        reconstructed.add_scaled(bit, std::int64_t{1} << i);
        if (i < 32) out.bits[i] = bit;
    }
    transcript.equal(sum, reconstructed.build());
    if (value) out.value = static_cast<std::uint32_t>(*value);
    return out;
}

constexpr std::array<std::uint32_t, 64> ROUND_CONSTANTS{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

constexpr std::array<std::uint32_t, 8> INITIAL_STATE{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

std::uint32_t read_word(const unsigned char* bytes) {
    std::uint32_t out = 0;
    for (std::size_t i = 0; i < 4; ++i) out = (out << 8) | bytes[i];
    return out;
}

Result<purify::BulletproofTranscript> sha256_relation(purify::Transcript& transcript, std::size_t length,
                                                    const Digest& digest, const purify::Bytes* message) {
    if (length > 64 || (message && message->size() != length)) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "receipt_sha256:fixture_length");
    }
    const std::size_t total = ((length + 9 + 63) / 64) * 64;
    std::vector<std::array<Expr, 8>> bytes(total);
    purify::Bytes padded(total, 0);
    padded[length] = 0x80;
    const auto bit_length = static_cast<std::uint64_t>(length) * 8;
    for (std::size_t i = 0; i < 8; ++i) padded[total - 1 - i] = static_cast<unsigned char>(bit_length >> (8 * i));
    if (message) std::copy(message->begin(), message->end(), padded.begin());
    for (std::size_t j = 0; j < total; ++j) {
        for (std::size_t i = 0; i < 8; ++i) {
            if (j < length) {
                const auto known = message ? std::optional<FieldElement>(FieldElement::from_u64((padded[j] >> i) & 1U)) : std::nullopt;
                bytes[j][i] = transcript.boolean(transcript.secret(known));
            } else {
                bytes[j][i] = Expr((padded[j] >> i) & 1U);
            }
        }
    }
    std::array<Word, 8> state;
    for (std::size_t i = 0; i < state.size(); ++i) state[i] = constant(INITIAL_STATE[i]);
    for (std::size_t block = 0; block < total; block += 64) {
        std::array<Word, 64> schedule;
        for (std::size_t j = 0; j < 16; ++j) {
            for (std::size_t i = 0; i < 32; ++i) schedule[j].bits[i] = bytes[block + 4 * j + 3 - i / 8][i % 8];
            if (message || block + 4 * j >= length) schedule[j].value = read_word(padded.data() + block + 4 * j);
        }
        for (std::size_t i = 16; i < schedule.size(); ++i) {
            schedule[i] = add_words(transcript, {sigma(transcript, schedule[i - 2], 17, 19, 10, true),
                schedule[i - 7], sigma(transcript, schedule[i - 15], 7, 18, 3, true), schedule[i - 16]});
        }
        auto work = state;
        for (std::size_t i = 0; i < 64; ++i) {
            const auto t1 = add_words(transcript, {work[7], sigma(transcript, work[4], 6, 11, 25),
                choose(transcript, work[4], work[5], work[6]), constant(ROUND_CONSTANTS[i]), schedule[i]});
            const auto t2 = add_words(transcript, {sigma(transcript, work[0], 2, 13, 22),
                majority(transcript, work[0], work[1], work[2])});
            work = {add_words(transcript, {t1, t2}), work[0], work[1], work[2],
                add_words(transcript, {work[3], t1}), work[4], work[5], work[6]};
        }
        for (std::size_t i = 0; i < state.size(); ++i) state[i] = add_words(transcript, {state[i], work[i]});
    }
    for (std::size_t i = 0; i < state.size(); ++i) {
        transcript.equal(packed(state[i]), Expr(FieldElement::from_u64(read_word(digest.data() + 4 * i))));
    }
    purify::BulletproofTranscript lowered;
    // Boolean constraints occur throughout the circuit, so retain them as
    // ordinary multiplication gates rather than claiming a leading bit prefix.
    PURIFY_RETURN_IF_ERROR(lowered.from_transcript(transcript, 0), "receipt_sha256:lower");
    PURIFY_RETURN_IF_ERROR(lowered.add_pubkey_and_out(purify::UInt512{}, Expr(0), Expr(0), Expr(1)), "receipt_sha256:fixed_output");
    return lowered;
}

Digest reference_digest(const purify::Bytes& message) {
    Digest out{};
    purify_sha256(out.data(), message.data(), message.size());
    return out;
}

purify::Bytes binding(std::size_t length, const Digest& digest) {
    const auto size = purify::UInt256::from_u64(length).to_bytes_be();
    const auto hash = purify::TaggedHash("Purify/Receipt/SHA256/HonestV1").digest_many<2>({size, digest});
    return purify::Bytes(hash.begin(), hash.end());
}

void test_sha256_circuit(TestContext& ctx) {
    const purify::Bytes abc{'a', 'b', 'c'};
    ctx.expect(reference_digest({}) == purify::UInt256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_bytes_be(), "empty SHA256 known answer");
    ctx.expect(reference_digest(abc) == purify::UInt256::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").to_bytes_be(), "abc SHA256 known answer");
    for (std::size_t length : {0U, 3U, 55U, 56U, 64U}) {
        purify::Bytes message(length);
        for (std::size_t i = 0; i < length; ++i) message[i] = static_cast<unsigned char>(i * 17 + 3);
        if (length == 3) message = abc;
        const auto digest = reference_digest(message);
        purify::Transcript known;
        auto lowered = sha256_relation(known, length, digest, &message);
        expect_ok(ctx, lowered, "honest SHA256 relation lowers at padding boundaries");
        if (!lowered) return;
        auto witness = lowered->assignment_data(known.varmap(), FieldElement::one());
        expect_ok(ctx, witness, "SHA256 witness lowers");
        if (!witness) return;
        purify::Transcript unknown;
        auto public_relation = sha256_relation(unknown, length, digest, nullptr);
        expect_ok(ctx, public_relation, "SHA256 public circuit builds without message bytes");
        if (!public_relation) return;
        const auto circuit = public_relation->native_circuit();
        ctx.expect(circuit.evaluate(*witness), "symbolic SHA256 matches independent C hash at padding boundaries");
        std::cout << "receipt_sha256 message_bytes=" << length << " sha_blocks=" << ((length + 72) / 64)
                  << " gates=" << circuit.n_gates << " constraints=" << circuit.c.size() << std::endl;
        if (length != 3) continue;
        auto secp = purify::make_secp_context();
        ctx.expect(secp != nullptr, "SHA256 proof context creates");
        if (!secp) return;
        const auto generator = purify::bppp::base_generator(secp.get());
        const purify::bppp::ScalarBytes zero{};
        auto point = purify::bppp::pedersen_commit_char(zero, FieldElement::one().to_bytes_be(),
                                                       secp.get(), generator, generator);
        expect_ok(ctx, point, "SHA256 fixed output uses the public-point encoding of G");
        if (!point) return;
        const std::array<purify::bppp::PointBytes, 1> outputs{*point};
        purify::bppp::ScalarBytes nonce{};
        nonce.fill(0x6d);
        const auto start = std::chrono::steady_clock::now();
        auto proof = purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, *witness, nonce, outputs, secp.get(), binding(length, digest));
        const auto proved = std::chrono::steady_clock::now();
        expect_ok(ctx, proof, "experimental BP++ proves the symbolic SHA256 relation");
        if (!proof) return;
        auto verified = purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, *proof, outputs, secp.get(), binding(length, digest));
        const auto checked = std::chrono::steady_clock::now();
        expect_ok(ctx, verified, "SHA256 BP++ verification runs");
        if (verified) ctx.expect(*verified, "SHA256 BP++ proof verifies");
        auto other_digest = digest;
        other_digest[0] ^= 1;
        purify::Transcript other;
        auto other_relation = sha256_relation(other, length, other_digest, nullptr);
        expect_ok(ctx, other_relation, "changed public digest relation builds without a witness");
        if (!other_relation) return;
        auto rejected = purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
            other_relation->native_circuit(), *proof, outputs, secp.get(), binding(length, other_digest));
        ctx.expect(!rejected || !*rejected, "unchanged SHA256 proof rejects a changed public digest");
        const auto size = proof->proof.size() + proof->a_commitment.size() + proof->s_commitment.size() + proof->t2.size();
        std::cout << "receipt_sha256_proof message_bytes=3 complete_proof_bytes=" << size
                  << " prove_ms=" << std::chrono::duration<double, std::milli>(proved - start).count()
                  << " verify_ms=" << std::chrono::duration<double, std::milli>(checked - proved).count() << std::endl;
    }
}

} // namespace

void run_receipt_sha256_tests(TestContext& ctx) {
    test_sha256_circuit(ctx);
}
