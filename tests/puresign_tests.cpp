// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "purify.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::sample_message;
using purify_test::sample_secret;
using purify::Bytes;
using purify::ErrorCode;
using purify::Result;
using purify::SecretKey;

purify::SecpContextPtr make_test_secp_context(TestContext& ctx) {
    purify::SecpContextPtr context = purify::make_secp_context();
    ctx.expect(context != nullptr, "secp context creation succeeds");
    return context;
}

void overwrite_u32_le(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<unsigned char>((value >> (8 * i)) & 0xffU);
    }
}

std::string hex_of(std::span<const unsigned char> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0fU]);
    }
    return out;
}

std::string sha256_hex_of(std::span<const unsigned char> bytes) {
    std::array<unsigned char, 32> digest{};
    purify_sha256(digest.data(), bytes.data(), bytes.size());
    return hex_of(digest);
}

void expect_pinned(TestContext& ctx, std::string_view actual, std::string_view expected, std::string_view message) {
    if (actual != expected) {
        std::cerr << "      actual: " << actual << "\n";
    }
    ctx.expect(actual == expected, message);
}

/** The byte-level outputs of one backend for the sample secret, message and topic. */
struct PinnedSigningVectors {
    std::string_view message_nonce;
    std::string_view message_signature;
    std::string_view message_nonce_proof_sha256;
    std::string_view message_proven_signature_sha256;
    std::string_view topic_nonce;
    std::string_view topic_signature;
    std::string_view topic_nonce_proof_sha256;
    std::string_view topic_proven_signature_sha256;
};

/**
 * Pins every derived value of one proof(R) backend: nonces, signatures, and the complete
 * serialized proof artifacts, with and without a reusable proof cache.
 */
template <typename KeyPair, typename MessageProofCache, typename TopicProofCache, typename CallerCache>
void expect_pinned_signing_vectors(TestContext& ctx, std::string_view backend,
                                   const PinnedSigningVectors& expected) {
    const std::string label(backend);
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, label + " pinned vectors parse the sample secret");
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (!secret.has_value() || context == nullptr) {
        return;
    }
    const Bytes message = sample_message();
    const Bytes topic = purify::bytes_from_ascii("session-1");

    auto key_pair = KeyPair::from_secret(*secret, context.get());
    auto message_cache = MessageProofCache::build(message);
    auto topic_cache = TopicProofCache::build(topic);
    expect_ok(ctx, key_pair, label + " pinned vectors derive the key pair");
    expect_ok(ctx, message_cache, label + " pinned vectors build the message cache");
    expect_ok(ctx, topic_cache, label + " pinned vectors build the topic cache");
    if (!key_pair.has_value() || !message_cache.has_value() || !topic_cache.has_value()) {
        return;
    }

    auto message_proven = key_pair->sign_message_with_proof(message, context.get());
    auto message_proven_cached = key_pair->sign_message_with_proof(*message_cache, context.get());
    auto topic_proven = key_pair->sign_with_topic_proof(message, topic, context.get());
    auto topic_proven_cached = key_pair->sign_with_topic_proof(message, *topic_cache, context.get());
    expect_ok(ctx, message_proven, label + " pinned vectors sign the message with proof");
    expect_ok(ctx, message_proven_cached, label + " pinned vectors sign the cached message with proof");
    expect_ok(ctx, topic_proven, label + " pinned vectors sign under the topic with proof");
    expect_ok(ctx, topic_proven_cached, label + " pinned vectors sign under the cached topic with proof");
    if (!message_proven.has_value() || !message_proven_cached.has_value() || !topic_proven.has_value() ||
        !topic_proven_cached.has_value()) {
        return;
    }

    const auto expect_bundle = [&](const auto& proven, std::string_view nonce, std::string_view signature,
                                   std::string_view nonce_proof_sha256, std::string_view proven_sha256,
                                   const std::string& what) {
        auto nonce_proof_bytes = proven.nonce_proof.serialize(context.get());
        auto proven_bytes = proven.serialize(context.get());
        expect_ok(ctx, nonce_proof_bytes, label + " " + what + " nonce proof serializes");
        expect_ok(ctx, proven_bytes, label + " " + what + " proven signature serializes");
        if (!nonce_proof_bytes.has_value() || !proven_bytes.has_value()) {
            return;
        }
        expect_pinned(ctx, hex_of(proven.nonce_proof.nonce.xonly), nonce, label + " " + what + " nonce is pinned");
        expect_pinned(ctx, hex_of(proven.signature.bytes), signature, label + " " + what + " signature is pinned");
        expect_pinned(ctx, sha256_hex_of(*nonce_proof_bytes), nonce_proof_sha256,
                      label + " " + what + " nonce proof bytes are pinned");
        expect_pinned(ctx, sha256_hex_of(*proven_bytes), proven_sha256,
                      label + " " + what + " proven signature bytes are pinned");
    };
    expect_bundle(*message_proven, expected.message_nonce, expected.message_signature,
                  expected.message_nonce_proof_sha256, expected.message_proven_signature_sha256, "message");
    expect_bundle(*message_proven_cached, expected.message_nonce, expected.message_signature,
                  expected.message_nonce_proof_sha256, expected.message_proven_signature_sha256,
                  "cached message");
    expect_bundle(*topic_proven, expected.topic_nonce, expected.topic_signature,
                  expected.topic_nonce_proof_sha256, expected.topic_proven_signature_sha256, "topic");
    expect_bundle(*topic_proven_cached, expected.topic_nonce, expected.topic_signature,
                  expected.topic_nonce_proof_sha256, expected.topic_proven_signature_sha256, "cached topic");

    // A caller-supplied backend cache may speed proving up but must not change a single byte.
    CallerCache caller_cache;
    auto message_proven_caller = key_pair->sign_message_with_proof(message, context.get(), &caller_cache);
    auto topic_proven_caller = key_pair->sign_with_topic_proof(message, topic, context.get(), &caller_cache);
    auto topic_proven_caller_cached =
        key_pair->sign_with_topic_proof(message, *topic_cache, context.get(), &caller_cache);
    expect_ok(ctx, message_proven_caller, label + " pinned vectors sign the message with a caller cache");
    expect_ok(ctx, topic_proven_caller, label + " pinned vectors sign under the topic with a caller cache");
    expect_ok(ctx, topic_proven_caller_cached,
              label + " pinned vectors sign under the cached topic with a caller cache");
    if (!message_proven_caller.has_value() || !topic_proven_caller.has_value() ||
        !topic_proven_caller_cached.has_value()) {
        return;
    }
    expect_bundle(*message_proven_caller, expected.message_nonce, expected.message_signature,
                  expected.message_nonce_proof_sha256, expected.message_proven_signature_sha256,
                  "caller-cache message");
    expect_bundle(*topic_proven_caller, expected.topic_nonce, expected.topic_signature,
                  expected.topic_nonce_proof_sha256, expected.topic_proven_signature_sha256,
                  "caller-cache topic");
    expect_bundle(*topic_proven_caller_cached, expected.topic_nonce, expected.topic_signature,
                  expected.topic_nonce_proof_sha256, expected.topic_proven_signature_sha256,
                  "caller-cache cached topic");

    // The proof-free paths must derive the same nonces and signatures.
    auto message_nonce = key_pair->prepare_message_nonce(message, context.get());
    auto topic_nonce = key_pair->prepare_topic_nonce(topic, context.get());
    auto message_signature = key_pair->sign_message(message, context.get());
    auto topic_signature = key_pair->sign_with_topic(message, topic, context.get());
    expect_ok(ctx, message_nonce, label + " pinned vectors prepare the message nonce");
    expect_ok(ctx, topic_nonce, label + " pinned vectors prepare the topic nonce");
    expect_ok(ctx, message_signature, label + " pinned vectors sign the message");
    expect_ok(ctx, topic_signature, label + " pinned vectors sign under the topic");
    if (!message_nonce.has_value() || !topic_nonce.has_value() || !message_signature.has_value() ||
        !topic_signature.has_value()) {
        return;
    }
    expect_pinned(ctx, hex_of(message_nonce->public_nonce().xonly), expected.message_nonce,
                  label + " prepared message nonce is pinned");
    expect_pinned(ctx, hex_of(topic_nonce->public_nonce().xonly), expected.topic_nonce,
                  label + " prepared topic nonce is pinned");
    expect_pinned(ctx, hex_of(message_signature->bytes), expected.message_signature,
                  label + " plain message signature is pinned");
    expect_pinned(ctx, hex_of(topic_signature->bytes), expected.topic_signature,
                  label + " plain topic signature is pinned");
}

// Key derivation, and so every value below, depends on the configured field hashes.
#if PURIFY_USE_LEGACY_FIELD_HASHES
constexpr PinnedSigningVectors kBulletproofVectors{
    .message_nonce = "af107e7489139e49674ccb97a2ff0fd63aa4f758d058ec6778d99bc1fc7c13a3",
    .message_signature = "af107e7489139e49674ccb97a2ff0fd63aa4f758d058ec6778d99bc1fc7c13a3"
                         "d099373b87ed7b4a616925e54eb0262f5c1e15dfc2c551323d966c73b1f90b1d",
    .message_nonce_proof_sha256 = "63c060b86985df5e6d443de4baa30d7e8dac8b272c92e1366397e05e4aea9cf3",
    .message_proven_signature_sha256 = "251eeba7de234814338cc1efc8b14a4c7c507581f5f2e058321b347f1199a3d7",
    .topic_nonce = "0da0cb5c9169b21dfbe0d46da89133a82ce4d7c66c52966e24b9114c80cb4bc5",
    .topic_signature = "0da0cb5c9169b21dfbe0d46da89133a82ce4d7c66c52966e24b9114c80cb4bc5"
                         "c624f97a32661399cb823e8c9430aafceab58791aa883f3e4892121406a9aebe",
    .topic_nonce_proof_sha256 = "7cee668e645725b0e682c15eec2cd6abe67e16c815c21df306059dc1f8a1a285",
    .topic_proven_signature_sha256 = "3a102f5bbf3820c0059321f4caba907e7c5c97488e428c7e53bc7d9740047988",
};

constexpr PinnedSigningVectors kBpppVectors{
    .message_nonce = "af107e7489139e49674ccb97a2ff0fd63aa4f758d058ec6778d99bc1fc7c13a3",
    .message_signature = "af107e7489139e49674ccb97a2ff0fd63aa4f758d058ec6778d99bc1fc7c13a3"
                         "d099373b87ed7b4a616925e54eb0262f5c1e15dfc2c551323d966c73b1f90b1d",
    .message_nonce_proof_sha256 = "30bd4fef790f775b880166e40a33f62e5fc9923dab10bac20821ef8056f42a23",
    .message_proven_signature_sha256 = "94fbe277468cbd3c91906198a66baffbcd8c4a134a4f7ee242a96799529f05dc",
    .topic_nonce = "0da0cb5c9169b21dfbe0d46da89133a82ce4d7c66c52966e24b9114c80cb4bc5",
    .topic_signature = "0da0cb5c9169b21dfbe0d46da89133a82ce4d7c66c52966e24b9114c80cb4bc5"
                         "c624f97a32661399cb823e8c9430aafceab58791aa883f3e4892121406a9aebe",
    .topic_nonce_proof_sha256 = "6b42a730796b18c2f784397f1d10c6b1180f052bc5094cbcfe44fc409aa388d9",
    .topic_proven_signature_sha256 = "d9598c91e56fd6267822e207aaeecfdbd6a636f79eb5b29fbd5e0c3cd37da92d",
};
#else
constexpr PinnedSigningVectors kBulletproofVectors{
    .message_nonce = "489376c6dab8a30fde84c19c7448b29dc401826a8e0c14510d5804a7a051bd4f",
    .message_signature = "489376c6dab8a30fde84c19c7448b29dc401826a8e0c14510d5804a7a051bd4f"
                         "fc98d4f408047c0354a8b0634b43a6bceb63d90c0fe6e1333c69761b5314c553",
    .message_nonce_proof_sha256 = "6f5637891d10399004a430fbb7574731fcffc3d129e5be63d1e314186e74ea30",
    .message_proven_signature_sha256 = "73b6dcd3239acc94be3a0fbdef62ceaaed2177b2dfefd4dc3d274887d3b725bd",
    .topic_nonce = "4492ce5bc4ddddb3e89c9630248047411c2807645a3ad9d36b723d09e9811334",
    .topic_signature = "4492ce5bc4ddddb3e89c9630248047411c2807645a3ad9d36b723d09e9811334"
                         "8907b863f889792099fae4f7c266ca0138df01fb2a07384627a4a51487c5307d",
    .topic_nonce_proof_sha256 = "4a975d130ee4a4485de065efe8f5c3be4dfb2d149f11bd4c1b8fe8371d18792a",
    .topic_proven_signature_sha256 = "786f7c1d884afa8506de8183ee910bfda54db7621772cebde9ff11ae1d395ba0",
};

constexpr PinnedSigningVectors kBpppVectors{
    .message_nonce = "489376c6dab8a30fde84c19c7448b29dc401826a8e0c14510d5804a7a051bd4f",
    .message_signature = "489376c6dab8a30fde84c19c7448b29dc401826a8e0c14510d5804a7a051bd4f"
                         "fc98d4f408047c0354a8b0634b43a6bceb63d90c0fe6e1333c69761b5314c553",
    .message_nonce_proof_sha256 = "36329a879d79fd8ebafc5b14c2dfabcd0c4016d78ef0eb1dca4a3897a2d048c4",
    .message_proven_signature_sha256 = "1e27a745bd54e517bc14877b8fbc3163ac6dbce1ee7fc8ad923cb9457711b647",
    .topic_nonce = "4492ce5bc4ddddb3e89c9630248047411c2807645a3ad9d36b723d09e9811334",
    .topic_signature = "4492ce5bc4ddddb3e89c9630248047411c2807645a3ad9d36b723d09e9811334"
                         "8907b863f889792099fae4f7c266ca0138df01fb2a07384627a4a51487c5307d",
    .topic_nonce_proof_sha256 = "f392f6ca73e9a4edfc79cfeefc448970e1c15cb376ba3ef6e7df7bec6dc9600c",
    .topic_proven_signature_sha256 = "27c6a2172605982a5c0871ab26b14183dbcbbc35a5b29afc6a9389d4fb00011f",
};
#endif

void test_puresign_pinned_signing_vectors(TestContext& ctx) {
    expect_pinned_signing_vectors<purify::puresign::KeyPair, purify::puresign::MessageProofCache,
                                  purify::puresign::TopicProofCache,
                                  purify::ExperimentalBulletproofBackendCache>(ctx, "PureSign",
                                                                               kBulletproofVectors);
    expect_pinned_signing_vectors<purify::puresign_plusplus::KeyPair,
                                  purify::puresign_plusplus::MessageProofCache,
                                  purify::puresign_plusplus::TopicProofCache,
                                  purify::bppp::ExperimentalCircuitCache>(ctx, "PureSign++", kBpppVectors);
}

void test_puresign_message_signing(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign message signing");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes message = sample_message();

    Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "KeyPair::from_secret succeeds");
    if (!key_pair.has_value()) {
        return;
    }
    Result<purify::puresign::MessageProofCache> proof_cache =
        purify::puresign::MessageProofCache::build(message);
    expect_ok(ctx, proof_cache, "MessageProofCache::build succeeds");
    Result<purify::puresign::PreparedNonceWithProof> prepared_with_proof =
        key_pair->prepare_message_nonce_with_proof(message, context.get());
    expect_ok(ctx, prepared_with_proof, "KeyPair::prepare_message_nonce_with_proof succeeds");
    Result<purify::puresign::PreparedNonce> prepared_a = key_pair->prepare_message_nonce(message, context.get());
    expect_ok(ctx, prepared_a, "KeyPair::prepare_message_nonce succeeds");
    Result<purify::puresign::PreparedNonce> prepared_b = key_pair->prepare_message_nonce(message, context.get());
    expect_ok(ctx, prepared_b, "KeyPair::prepare_message_nonce is deterministic");
    if (!proof_cache.has_value() || !prepared_with_proof.has_value() || !prepared_a.has_value() || !prepared_b.has_value()) {
        return;
    }
    const purify::puresign::PublicKey& public_key = key_pair->public_key();

    Result<bool> nonce_proof_ok =
        public_key.verify_message_nonce_proof(message, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, nonce_proof_ok, "PublicKey::verify_message_nonce_proof succeeds on the generated proof");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "generated message-bound nonce proof verifies");
    }
    Result<bool> wrong_nonce_proof =
        public_key.verify_message_nonce_proof(Bytes{0x89}, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, wrong_nonce_proof, "PublicKey::verify_message_nonce_proof runs on a wrong message");
    if (wrong_nonce_proof.has_value()) {
        ctx.expect(!*wrong_nonce_proof, "message-bound nonce proof rejects a different message");
    }

    Result<purify::puresign::PreparedNonceWithProof> cached_prepared_with_proof =
        key_pair->prepare_message_nonce_with_proof(*proof_cache, context.get());
    expect_ok(ctx, cached_prepared_with_proof, "KeyPair::prepare_message_nonce_with_proof succeeds with a cached template");
    if (cached_prepared_with_proof.has_value()) {
        ctx.expect(cached_prepared_with_proof->public_nonce().xonly == prepared_with_proof->public_nonce().xonly,
                   "cached message proof preparation preserves the deterministic public nonce");
        Result<bool> cached_nonce_proof_ok =
            public_key.verify_message_nonce_proof(*proof_cache, cached_prepared_with_proof->proof(), context.get());
        expect_ok(ctx, cached_nonce_proof_ok, "PublicKey::verify_message_nonce_proof succeeds with a cached template");
        if (cached_nonce_proof_ok.has_value()) {
            ctx.expect(*cached_nonce_proof_ok, "cached message-bound nonce proof verifies");
        }
    }

    ctx.expect(prepared_a->public_nonce().xonly == prepared_b->public_nonce().xonly,
               "message-bound public nonces are deterministic");
    auto prepared_a_scalar = prepared_a->scalar();
    auto prepared_b_scalar = prepared_b->scalar();
    expect_ok(ctx, prepared_a_scalar,
              "first message-bound secret nonce scalar exports");
    expect_ok(ctx, prepared_b_scalar,
              "second message-bound secret nonce scalar exports");
    if (prepared_a_scalar && prepared_b_scalar) {
        ctx.expect(*prepared_a_scalar == *prepared_b_scalar,
                   "message-bound secret nonce scalars are deterministic");
    }

    Result<purify::puresign::Signature> direct = key_pair->sign_message(message, context.get());
    expect_ok(ctx, direct, "KeyPair::sign_message succeeds");
    Result<purify::puresign::Signature> cached =
        key_pair->sign_message_with_prepared(message, std::move(*prepared_a), context.get());
    expect_ok(ctx, cached, "KeyPair::sign_message_with_prepared succeeds");
    if (!direct.has_value() || !cached.has_value()) {
        return;
    }

    Result<purify::puresign::ProvenSignature> proven =
        key_pair->sign_message_with_prepared_proof(message, std::move(*prepared_with_proof), context.get());
    expect_ok(ctx, proven, "KeyPair::sign_message_with_prepared_proof succeeds");
    Result<purify::puresign::ProvenSignature> cached_proven =
        key_pair->sign_message_with_proof(*proof_cache, context.get());
    expect_ok(ctx, cached_proven, "KeyPair::sign_message_with_proof succeeds with a cached template");
    if (proven.has_value()) {
        Result<bool> proven_ok = public_key.verify_message_signature_with_proof(message, *proven, context.get());
        expect_ok(ctx, proven_ok, "PublicKey::verify_message_signature_with_proof succeeds");
        if (proven_ok.has_value()) {
            ctx.expect(*proven_ok, "message signature with proof verifies");
        }

        Result<Bytes> nonce_proof_bytes = proven->nonce_proof.serialize(context.get());
        expect_ok(ctx, nonce_proof_bytes, "NonceProof serializes");
        if (nonce_proof_bytes.has_value()) {
            ctx.expect(!nonce_proof_bytes->empty() && (*nonce_proof_bytes)[0] == 2,
                       "NonceProof uses the unique-derivation wire format version");
            Result<purify::puresign::NonceProof> parsed_nonce_proof =
                purify::puresign::NonceProof::deserialize(*nonce_proof_bytes, context.get());
            expect_ok(ctx, parsed_nonce_proof, "NonceProof round-trips");

            Bytes length_tampered_nonce_proof = *nonce_proof_bytes;
            overwrite_u32_le(length_tampered_nonce_proof, 1, 0xffffffffU);
            expect_error(ctx,
                         purify::puresign::NonceProof::deserialize(length_tampered_nonce_proof, context.get()),
                         ErrorCode::InvalidFixedSize,
                         "NonceProof rejects a huge declared proof length");

            Bytes legacy_nonce_proof = *nonce_proof_bytes;
            legacy_nonce_proof[0] = 1;
            expect_error(ctx, purify::puresign::NonceProof::deserialize(legacy_nonce_proof, context.get()),
                         ErrorCode::BackendRejectedInput,
                         "NonceProof rejects the old counter-bearing wire format");
        }

        Result<Bytes> proven_bytes = proven->serialize(context.get());
        expect_ok(ctx, proven_bytes, "ProvenSignature serializes");
        if (proven_bytes.has_value()) {
            Result<purify::puresign::ProvenSignature> parsed_proven =
                purify::puresign::ProvenSignature::deserialize(*proven_bytes, context.get());
            expect_ok(ctx, parsed_proven, "ProvenSignature round-trips");
            if (parsed_proven.has_value()) {
                Result<bool> parsed_ok =
                    public_key.verify_message_signature_with_proof(message, *parsed_proven, context.get());
                expect_ok(ctx, parsed_ok, "parsed message signature with proof verifies");
                if (parsed_ok.has_value()) {
                    ctx.expect(*parsed_ok, "parsed message signature with proof is accepted");
                }
            }

            Bytes length_tampered_proven = *proven_bytes;
            overwrite_u32_le(length_tampered_proven, 1, 0xffffffffU);
            expect_error(ctx,
                         purify::puresign::ProvenSignature::deserialize(length_tampered_proven, context.get()),
                         ErrorCode::InvalidFixedSize,
                         "ProvenSignature rejects a huge declared nonce-proof length");
        }
    }
    if (cached_proven.has_value()) {
        Result<bool> cached_proven_ok =
            public_key.verify_message_signature_with_proof(*proof_cache, *cached_proven, context.get());
        expect_ok(ctx, cached_proven_ok, "PublicKey::verify_message_signature_with_proof succeeds with a cached template");
        if (cached_proven_ok.has_value()) {
            ctx.expect(*cached_proven_ok, "cached message signature with proof verifies");
        }

        Result<purify::puresign::MessageProofCache> wrong_cache =
            purify::puresign::MessageProofCache::build(Bytes{0x99, 0x88, 0x77});
        expect_ok(ctx, wrong_cache, "MessageProofCache::build succeeds for tamper coverage");
        if (wrong_cache.has_value()) {
            purify::puresign::MessageProofCache tampered_cache{};
            tampered_cache.message = proof_cache->message;
            tampered_cache.eval_input = proof_cache->eval_input;
            tampered_cache.circuit_template = wrong_cache->circuit_template;
            tampered_cache.template_digest = proof_cache->template_digest;
            expect_error(ctx,
                         public_key.verify_message_signature_with_proof(tampered_cache, *cached_proven, context.get()),
                         ErrorCode::BindingMismatch,
                         "cached message signature verification rejects a cache with the wrong circuit template");
        }
    }

    ctx.expect(direct->bytes == cached->bytes, "cached message-bound signing matches direct signing");
    ctx.expect(direct->nonce().xonly == prepared_b->public_nonce().xonly,
               "signature nonce matches the prepared public nonce");

    Result<bool> verified = public_key.verify_signature(message, *direct, context.get());
    expect_ok(ctx, verified, "PublicKey::verify_signature succeeds on a PureSign message signature");
    if (verified.has_value()) {
        ctx.expect(*verified, "PureSign message signature verifies");
    }

    Bytes public_key_bytes = public_key.serialize();
    ctx.expect(public_key_bytes.size() == purify::puresign::PublicKey::kSerializedSize,
               "PureSign public key serialization has the expected size");
    Result<purify::puresign::PublicKey> parsed_public_key =
        purify::puresign::PublicKey::deserialize(public_key_bytes, context.get());
    expect_ok(ctx, parsed_public_key, "PureSign public key round-trips");

    Bytes nonce_bytes = prepared_b->public_nonce().serialize();
    ctx.expect(nonce_bytes.size() == purify::puresign::Nonce::kSerializedSize,
               "PureSign nonce serialization has the expected size");
    Result<purify::puresign::Nonce> parsed_nonce = purify::puresign::Nonce::deserialize(nonce_bytes, context.get());
    expect_ok(ctx, parsed_nonce, "PureSign nonce round-trips");
    if (parsed_nonce.has_value()) {
        ctx.expect(parsed_nonce->xonly == prepared_b->public_nonce().xonly, "PureSign nonce deserialization preserves x-only bytes");
    }

    Bytes signature_bytes = direct->serialize();
    ctx.expect(signature_bytes.size() == purify::puresign::Signature::kSerializedSize,
               "PureSign signature serialization has the expected size");
    Result<purify::puresign::Signature> parsed_signature =
        purify::puresign::Signature::deserialize(signature_bytes, context.get());
    expect_ok(ctx, parsed_signature, "PureSign signature round-trips");
    if (parsed_public_key.has_value() && parsed_signature.has_value()) {
        Result<bool> reparsed_verified = parsed_public_key->verify_signature(message, *parsed_signature, context.get());
        expect_ok(ctx, reparsed_verified, "verify_signature accepts parsed PureSign artifacts");
        if (reparsed_verified.has_value()) {
            ctx.expect(*reparsed_verified, "parsed PureSign artifacts verify");
        }
    }
}

void test_puresign_topic_signing(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign topic signing");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes message = sample_message();
    Bytes topic = purify::bytes_from_ascii("session-1");

    Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "KeyPair::from_secret succeeds for topic signing");
    if (!key_pair.has_value()) {
        return;
    }
    Result<purify::puresign::TopicProofCache> proof_cache =
        purify::puresign::TopicProofCache::build(topic);
    expect_ok(ctx, proof_cache, "TopicProofCache::build succeeds");
    Result<purify::puresign::PreparedNonceWithProof> prepared_with_proof =
        key_pair->prepare_topic_nonce_with_proof(topic, context.get());
    expect_ok(ctx, prepared_with_proof, "KeyPair::prepare_topic_nonce_with_proof succeeds");
    Result<purify::puresign::PreparedNonce> prepared_a = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, prepared_a, "KeyPair::prepare_topic_nonce succeeds");
    Result<purify::puresign::PreparedNonce> prepared_b = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, prepared_b, "KeyPair::prepare_topic_nonce is deterministic");
    if (!proof_cache.has_value() || !prepared_with_proof.has_value() || !prepared_a.has_value() || !prepared_b.has_value()) {
        return;
    }
    const purify::puresign::PublicKey& public_key = key_pair->public_key();

    Result<bool> nonce_proof_ok =
        public_key.verify_topic_nonce_proof(topic, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, nonce_proof_ok, "PublicKey::verify_topic_nonce_proof succeeds on the generated proof");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "generated topic-bound nonce proof verifies");
    }

    Result<purify::puresign::PreparedNonceWithProof> cached_prepared_with_proof =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get());
    expect_ok(ctx, cached_prepared_with_proof, "KeyPair::prepare_topic_nonce_with_proof succeeds with a cached template");
    if (cached_prepared_with_proof.has_value()) {
        ctx.expect(cached_prepared_with_proof->public_nonce().xonly == prepared_with_proof->public_nonce().xonly,
                   "cached topic proof preparation preserves the deterministic public nonce");
        Result<bool> cached_nonce_proof_ok =
            public_key.verify_topic_nonce_proof(*proof_cache, cached_prepared_with_proof->proof(), context.get());
        expect_ok(ctx, cached_nonce_proof_ok, "PublicKey::verify_topic_nonce_proof succeeds with a cached template");
        if (cached_nonce_proof_ok.has_value()) {
            ctx.expect(*cached_nonce_proof_ok, "cached topic-bound nonce proof verifies");
        }
    }

    ctx.expect(prepared_a->public_nonce().xonly == prepared_b->public_nonce().xonly,
               "topic-bound public nonces are deterministic");
    auto prepared_a_scalar = prepared_a->scalar();
    auto prepared_b_scalar = prepared_b->scalar();
    expect_ok(ctx, prepared_a_scalar,
              "first topic-bound secret nonce scalar exports");
    expect_ok(ctx, prepared_b_scalar,
              "second topic-bound secret nonce scalar exports");
    if (prepared_a_scalar && prepared_b_scalar) {
        ctx.expect(*prepared_a_scalar == *prepared_b_scalar,
                   "topic-bound secret nonce scalars are deterministic");
    }

    Result<purify::puresign::Signature> direct = key_pair->sign_with_topic(message, topic, context.get());
    expect_ok(ctx, direct, "KeyPair::sign_with_topic succeeds");
    Result<purify::puresign::Signature> cached =
        key_pair->sign_with_prepared_topic(message, std::move(*prepared_a), context.get());
    expect_ok(ctx, cached, "KeyPair::sign_with_prepared_topic succeeds");
    if (!direct.has_value() || !cached.has_value()) {
        return;
    }

    Result<purify::puresign::ProvenSignature> proven =
        key_pair->sign_with_prepared_topic_proof(message, std::move(*prepared_with_proof), context.get());
    expect_ok(ctx, proven, "KeyPair::sign_with_prepared_topic_proof succeeds");
    ctx.expect(!prepared_with_proof->available(),
               "successful proof signing consumes the wrapped nonce");
    expect_error(ctx, prepared_with_proof->scalar(),
                 ErrorCode::UninitializedState,
                 "a consumed proof bundle cannot export its scalar");
    expect_error(ctx,
                 key_pair->sign_with_prepared_topic_proof(
                     message, std::move(*prepared_with_proof), context.get()),
                 ErrorCode::UninitializedState,
                 "a consumed proof bundle cannot sign a second time");
    Result<purify::puresign::ProvenSignature> cached_proven =
        key_pair->sign_with_topic_proof(message, *proof_cache, context.get());
    expect_ok(ctx, cached_proven, "KeyPair::sign_with_topic_proof succeeds with a cached template");
    if (proven.has_value()) {
        Result<bool> proven_ok =
            public_key.verify_topic_signature_with_proof(message, topic, *proven, context.get());
        expect_ok(ctx, proven_ok, "PublicKey::verify_topic_signature_with_proof succeeds");
        if (proven_ok.has_value()) {
            ctx.expect(*proven_ok, "topic-bound signature with proof verifies");
        }
    }
    if (cached_proven.has_value()) {
        Result<bool> cached_proven_ok =
            public_key.verify_topic_signature_with_proof(*proof_cache, message, *cached_proven, context.get());
        expect_ok(ctx, cached_proven_ok, "PublicKey::verify_topic_signature_with_proof succeeds with a cached template");
        if (cached_proven_ok.has_value()) {
            ctx.expect(*cached_proven_ok, "cached topic-bound signature with proof verifies");
        }
    }

    ctx.expect(direct->bytes == cached->bytes, "cached topic-bound signing matches direct signing");
    ctx.expect(direct->nonce().xonly == prepared_b->public_nonce().xonly,
               "topic-bound signature nonce matches the prepared public nonce");

    expect_error(ctx, key_pair->prepare_topic_nonce(Bytes{}, context.get()), ErrorCode::EmptyInput,
                 "prepare_topic_nonce rejects an empty topic");
}

void test_puresign_topic_proof_cache_clone_for_thread(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign cache cloning");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes topic = purify::bytes_from_ascii("session-legacy-clone");
    Result<purify::puresign::KeyPair> key_pair =
        purify::puresign::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "PureSign KeyPair::from_secret succeeds for cache cloning");
    Result<purify::puresign::TopicProofCache> proof_cache =
        purify::puresign::TopicProofCache::build(topic);
    expect_ok(ctx, proof_cache, "PureSign TopicProofCache::build succeeds for cache cloning");
    if (!key_pair.has_value() || !proof_cache.has_value()) {
        return;
    }

    Result<purify::puresign::PreparedNonceWithProof> warmed =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get());
    expect_ok(ctx, warmed, "PureSign warms the embedded backend cache before cloning");
    ctx.expect(proof_cache->backend_cache.size() > 0, "PureSign embedded backend cache contains warmed resources");
    Result<purify::NativeBulletproofCircuit::PackedWithSlack> circuit =
        proof_cache->circuit_template.instantiate_packed(key_pair->public_key().purify_pubkey);
    expect_ok(ctx, circuit, "PureSign instantiates the cached circuit for line cloning");
    if (!warmed.has_value() || !circuit.has_value()) {
        return;
    }

    Result<purify::ExperimentalBulletproofBackendCache> cloned_cache =
        proof_cache->backend_cache.clone_for_thread(circuit->n_gates());
    expect_ok(ctx, cloned_cache, "PureSign backend cache clones for thread-local reuse");
    if (!cloned_cache.has_value()) {
        return;
    }
    ctx.expect(cloned_cache->size() == proof_cache->backend_cache.size(),
               "PureSign cloned backend cache preserves warmed entry count");

    Result<bool> cloned_ok =
        key_pair->public_key().verify_topic_nonce_proof(*proof_cache, warmed->proof(), context.get(), &*cloned_cache);
    expect_ok(ctx, cloned_ok, "PureSign verifies a topic proof with the cloned backend cache");
    if (cloned_ok.has_value()) {
        ctx.expect(*cloned_ok, "PureSign cloned backend cache accepts the topic proof");
    }
}

void test_puresign_binding_checks(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign binding checks");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes message = sample_message();
    Bytes wrong_message = Bytes{0x89, 0xab};
    Bytes topic = purify::bytes_from_ascii("session-2");

    Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "KeyPair::from_secret succeeds for binding checks");
    if (!key_pair.has_value()) {
        return;
    }

    Result<purify::puresign::PreparedNonce> message_nonce = key_pair->prepare_message_nonce(message, context.get());
    expect_ok(ctx, message_nonce, "KeyPair::prepare_message_nonce succeeds for binding checks");
    if (message_nonce.has_value()) {
        expect_error(ctx, key_pair->sign_message_with_prepared(wrong_message, std::move(*message_nonce), context.get()),
                     ErrorCode::BindingMismatch,
                     "message-bound prepared nonces reject signing a different message");
        ctx.expect(!message_nonce->available(),
                   "a binding failure consumes the prepared nonce");
        expect_error(ctx,
                     key_pair->sign_message_with_prepared(
                         message, std::move(*message_nonce), context.get()),
                     ErrorCode::UninitializedState,
                     "a binding-failed nonce cannot later sign");
    }

    Result<purify::puresign::PreparedNonce> topic_nonce = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, topic_nonce, "KeyPair::prepare_topic_nonce succeeds for binding checks");
    if (topic_nonce.has_value()) {
        expect_error(ctx, key_pair->sign_message_with_prepared(message, std::move(*topic_nonce), context.get()),
                     ErrorCode::BindingMismatch,
                     "topic-bound prepared nonces reject the message-bound signing API");
        ctx.expect(!topic_nonce->available(),
                   "a scope failure consumes the prepared nonce");
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         message, std::move(*topic_nonce), context.get()),
                     ErrorCode::UninitializedState,
                     "a scope-failed nonce cannot later sign");
    }

    auto missing_context_nonce =
        key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, missing_context_nonce,
              "topic nonce prepares for context-failure consumption");
    if (missing_context_nonce) {
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         message, std::move(*missing_context_nonce), nullptr),
                     ErrorCode::MissingValue,
                     "a missing signing context rejects before signing");
        ctx.expect(!missing_context_nonce->available(),
                   "a context failure still consumes the prepared nonce");
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         message, std::move(*missing_context_nonce),
                         context.get()),
                     ErrorCode::UninitializedState,
                     "a context-failed nonce cannot later sign");
    }
}

void test_puresign_plusplus_prepared_nonce_consumption(TestContext& ctx) {
    auto secret = sample_secret();
    expect_ok(ctx, secret,
              "sample secret parses for PureSign++ nonce consumption");
    if (!secret) return;
    auto context = make_test_secp_context(ctx);
    if (!context) return;

    const auto message = sample_message();
    const auto wrong_message = purify::bytes_from_ascii("wrong-message");
    const auto topic = purify::bytes_from_ascii("one-shot-topic");
    auto key_pair = purify::puresign_plusplus::KeyPair::from_secret(
        *secret, context.get());
    expect_ok(ctx, key_pair,
              "PureSign++ key pair derives for nonce consumption");
    if (!key_pair) return;

    auto successful = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, successful, "PureSign++ topic nonce prepares");
    if (successful) {
        auto signature = key_pair->sign_with_prepared_topic(
            message, std::move(*successful), context.get());
        expect_ok(ctx, signature,
                  "PureSign++ prepared topic nonce signs once");
        ctx.expect(!successful->available(),
                   "successful PureSign++ signing consumes its nonce");
        expect_error(ctx, successful->scalar(), ErrorCode::UninitializedState,
                     "consumed PureSign++ nonce cannot export its scalar");
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         wrong_message, std::move(*successful), context.get()),
                     ErrorCode::UninitializedState,
                     "PureSign++ nonce reuse rejects a second message");
    }

    auto binding_failure =
        key_pair->prepare_message_nonce(message, context.get());
    expect_ok(ctx, binding_failure,
              "PureSign++ message nonce prepares for binding failure");
    if (binding_failure) {
        expect_error(ctx,
                     key_pair->sign_message_with_prepared(
                         wrong_message, std::move(*binding_failure),
                         context.get()),
                     ErrorCode::BindingMismatch,
                     "PureSign++ rejects the wrong message binding");
        ctx.expect(!binding_failure->available(),
                   "PureSign++ binding failure consumes its nonce");
        expect_error(ctx,
                     key_pair->sign_message_with_prepared(
                         message, std::move(*binding_failure), context.get()),
                     ErrorCode::UninitializedState,
                     "PureSign++ binding-failed nonce cannot later sign");
    }

    auto context_failure = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, context_failure,
              "PureSign++ topic nonce prepares for context failure");
    if (context_failure) {
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         message, std::move(*context_failure), nullptr),
                     ErrorCode::MissingValue,
                     "PureSign++ rejects a missing signing context");
        ctx.expect(!context_failure->available(),
                   "PureSign++ context failure consumes its nonce");
        expect_error(ctx,
                     key_pair->sign_with_prepared_topic(
                         message, std::move(*context_failure), context.get()),
                     ErrorCode::UninitializedState,
                     "PureSign++ context-failed nonce cannot later sign");
    }
}

void test_puresign_plusplus_message_signing(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign++ message signing");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes message = sample_message();

    Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "PureSign++ KeyPair::from_secret succeeds");
    if (!key_pair.has_value()) {
        return;
    }
    Result<purify::puresign_plusplus::MessageProofCache> proof_cache =
        purify::puresign_plusplus::MessageProofCache::build(message);
    expect_ok(ctx, proof_cache, "PureSign++ MessageProofCache::build succeeds");
    Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared_with_proof =
        key_pair->prepare_message_nonce_with_proof(message, context.get());
    expect_ok(ctx, prepared_with_proof, "PureSign++ KeyPair::prepare_message_nonce_with_proof succeeds");
    if (!proof_cache.has_value() || !prepared_with_proof.has_value()) {
        return;
    }
    const purify::puresign_plusplus::PublicKey& public_key = key_pair->public_key();

    Result<bool> nonce_proof_ok =
        public_key.verify_message_nonce_proof(message, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, nonce_proof_ok, "PureSign++ PublicKey::verify_message_nonce_proof succeeds");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "PureSign++ generated nonce proof verifies");
    }
    Result<bool> wrong_nonce_proof =
        public_key.verify_message_nonce_proof(Bytes{0x89}, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, wrong_nonce_proof, "PureSign++ PublicKey::verify_message_nonce_proof runs on a wrong message");
    if (wrong_nonce_proof.has_value()) {
        ctx.expect(!*wrong_nonce_proof, "PureSign++ nonce proof rejects a different message");
    }

    Result<purify::puresign_plusplus::PreparedNonceWithProof> cached_prepared_with_proof =
        key_pair->prepare_message_nonce_with_proof(*proof_cache, context.get());
    expect_ok(ctx, cached_prepared_with_proof,
              "PureSign++ KeyPair::prepare_message_nonce_with_proof succeeds with a cached template");

    Result<purify::puresign_plusplus::Signature> direct = key_pair->sign_message(message, context.get());
    expect_ok(ctx, direct, "PureSign++ KeyPair::sign_message succeeds");
    Result<purify::puresign_plusplus::ProvenSignature> proven =
        key_pair->sign_message_with_prepared_proof(message, std::move(*prepared_with_proof), context.get());
    expect_ok(ctx, proven, "PureSign++ KeyPair::sign_message_with_prepared_proof succeeds");
    Result<purify::puresign_plusplus::ProvenSignature> cached_proven =
        key_pair->sign_message_with_proof(*proof_cache, context.get());
    expect_ok(ctx, cached_proven, "PureSign++ KeyPair::sign_message_with_proof succeeds with a cached template");
    if (!direct.has_value() || !proven.has_value() || !cached_proven.has_value()) {
        return;
    }

    Result<bool> proven_ok = public_key.verify_message_signature_with_proof(message, *proven, context.get());
    expect_ok(ctx, proven_ok, "PureSign++ PublicKey::verify_message_signature_with_proof succeeds");
    if (proven_ok.has_value()) {
        ctx.expect(*proven_ok, "PureSign++ message signature with proof verifies");
    }
    Result<bool> cached_proven_ok =
        public_key.verify_message_signature_with_proof(*proof_cache, *cached_proven, context.get());
    expect_ok(ctx, cached_proven_ok,
              "PureSign++ PublicKey::verify_message_signature_with_proof succeeds with a cached template");
    if (cached_proven_ok.has_value()) {
        ctx.expect(*cached_proven_ok, "PureSign++ cached message signature with proof verifies");
    }

    Result<purify::puresign_plusplus::MessageProofCache> wrong_cache =
        purify::puresign_plusplus::MessageProofCache::build(Bytes{0xaa, 0xbb, 0xcc});
    expect_ok(ctx, wrong_cache, "PureSign++ MessageProofCache::build succeeds for tamper coverage");
    if (wrong_cache.has_value()) {
        purify::puresign_plusplus::MessageProofCache tampered_cache{};
        tampered_cache.message = proof_cache->message;
        tampered_cache.eval_input = proof_cache->eval_input;
        tampered_cache.circuit_template = wrong_cache->circuit_template;
        tampered_cache.template_digest = proof_cache->template_digest;
        expect_error(ctx,
                     public_key.verify_message_signature_with_proof(tampered_cache, *cached_proven, context.get()),
                     ErrorCode::BindingMismatch,
                     "PureSign++ cached message signature verification rejects a cache with the wrong circuit template");
    }

    ctx.expect(direct->bytes == proven->signature.bytes,
               "PureSign++ proof signing preserves the deterministic BIP340 signature bytes");

    auto dlog_tampered_proof = proven->nonce_proof;
    dlog_tampered_proof.proof.public_commitment_dlog_response.back() ^= 1;
    Result<bool> dlog_tampered_ok = public_key.verify_message_nonce_proof(
        message, dlog_tampered_proof, context.get());
    expect_ok(ctx, dlog_tampered_ok,
              "PureSign++ verifies a tampered DLog response without parser ambiguity");
    if (dlog_tampered_ok.has_value()) {
        ctx.expect(!*dlog_tampered_ok,
                   "PureSign++ rejects a tampered public-commitment DLog response");
    }

    Result<Bytes> nonce_proof_bytes = proven->nonce_proof.serialize(context.get());
    expect_ok(ctx, nonce_proof_bytes, "PureSign++ NonceProof serializes");
    if (nonce_proof_bytes.has_value()) {
        ctx.expect((*nonce_proof_bytes)[0] == 3,
                   "PureSign++ NonceProof identifies the raw-precommit transcript");
        ctx.expect(nonce_proof_bytes->size() == 1072 &&
                       nonce_proof_bytes->size() ==
                           purify::puresign_plusplus::NonceProof::kSerializedSize,
                   "PureSign++ V3 nonce proof stays within its measured wire budget");
        auto old_transcript_frame = *nonce_proof_bytes;
        old_transcript_frame[0] = 1;
        expect_error(ctx, purify::puresign_plusplus::NonceProof::deserialize(old_transcript_frame, context.get()),
                     purify::ErrorCode::BackendRejectedInput,
                     "PureSign++ NonceProof rejects the previous transcript version");
        Result<purify::puresign_plusplus::NonceProof> parsed_nonce_proof =
            purify::puresign_plusplus::NonceProof::deserialize(*nonce_proof_bytes, context.get());
        expect_ok(ctx, parsed_nonce_proof, "PureSign++ NonceProof round-trips");

        Bytes truncated_nonce_proof = *nonce_proof_bytes;
        truncated_nonce_proof.pop_back();
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         truncated_nonce_proof, context.get()),
                     ErrorCode::InvalidFixedSize,
                     "PureSign++ NonceProof rejects a truncated inner proof");

        Bytes oversized_nonce_proof = *nonce_proof_bytes;
        oversized_nonce_proof.push_back(0);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         oversized_nonce_proof, context.get()),
                     ErrorCode::InvalidFixedSize,
                     "PureSign++ NonceProof rejects an oversized inner proof");

        Bytes invalid_a = *nonce_proof_bytes;
        std::fill_n(invalid_a.begin() + 66, 33, 0);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         invalid_a, context.get()),
                     ErrorCode::BackendRejectedInput,
                     "PureSign++ NonceProof rejects an invalid A commitment");

        Bytes invalid_s = *nonce_proof_bytes;
        std::fill_n(invalid_s.begin() + 99, 33, 0);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         invalid_s, context.get()),
                     ErrorCode::BackendRejectedInput,
                     "PureSign++ NonceProof rejects an invalid S commitment");

        Bytes noncanonical_t2 = *nonce_proof_bytes;
        std::fill_n(noncanonical_t2.begin() + 132, 32, 0xff);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         noncanonical_t2, context.get()),
                     ErrorCode::RangeViolation,
                     "PureSign++ NonceProof rejects a non-canonical t2 scalar");

        Bytes zero_dlog_response = *nonce_proof_bytes;
        std::fill_n(zero_dlog_response.begin() + 196, 32, 0);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         zero_dlog_response, context.get()),
                     ErrorCode::BackendRejectedInput,
                     "PureSign++ NonceProof rejects a zero DLog response");

        Bytes noncanonical_dlog_response = *nonce_proof_bytes;
        std::fill_n(noncanonical_dlog_response.begin() + 196, 32, 0xff);
        expect_error(ctx,
                     purify::puresign_plusplus::NonceProof::deserialize(
                         noncanonical_dlog_response, context.get()),
                     ErrorCode::RangeViolation,
                     "PureSign++ NonceProof rejects a non-canonical DLog response");

    }

    Result<Bytes> proven_bytes = proven->serialize(context.get());
    expect_ok(ctx, proven_bytes, "PureSign++ ProvenSignature serializes");
    if (proven_bytes.has_value()) {
        ctx.expect((*proven_bytes)[0] == 2,
                   "PureSign++ ProvenSignature identifies its fixed framing");
        ctx.expect(
            proven_bytes->size() == 1137 &&
                proven_bytes->size() ==
                    purify::puresign_plusplus::ProvenSignature::kSerializedSize,
                   "PureSign++ V3 proven signature stays within its measured wire budget");
        Result<purify::puresign_plusplus::ProvenSignature> parsed_proven =
            purify::puresign_plusplus::ProvenSignature::deserialize(*proven_bytes, context.get());
        expect_ok(ctx, parsed_proven, "PureSign++ ProvenSignature round-trips");
        if (parsed_proven.has_value()) {
            Result<bool> parsed_ok =
                public_key.verify_message_signature_with_proof(message, *parsed_proven, context.get());
            expect_ok(ctx, parsed_ok, "PureSign++ parsed message signature with proof verifies");
            if (parsed_ok.has_value()) {
                ctx.expect(*parsed_ok, "PureSign++ parsed message signature with proof is accepted");
            }
        }

        Bytes old_framing_proven = *proven_bytes;
        old_framing_proven[0] = 1;
        expect_error(ctx,
                     purify::puresign_plusplus::ProvenSignature::deserialize(
                         old_framing_proven, context.get()),
                     ErrorCode::BackendRejectedInput,
                     "PureSign++ ProvenSignature rejects the length-framed version");

        Bytes truncated_proven = *proven_bytes;
        truncated_proven.pop_back();
        expect_error(ctx,
                     purify::puresign_plusplus::ProvenSignature::deserialize(
                         truncated_proven, context.get()),
                     ErrorCode::InvalidFixedSize,
                     "PureSign++ ProvenSignature rejects truncation");
        Bytes oversized_proven = *proven_bytes;
        oversized_proven.push_back(0);
        expect_error(ctx,
                     purify::puresign_plusplus::ProvenSignature::deserialize(
                         oversized_proven, context.get()),
                     ErrorCode::InvalidFixedSize,
                     "PureSign++ ProvenSignature rejects extension");
    }
}

void test_puresign_plusplus_topic_signing(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign++ topic signing");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes message = sample_message();
    Bytes topic = purify::bytes_from_ascii("session-pp");

    Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "PureSign++ KeyPair::from_secret succeeds for topic signing");
    if (!key_pair.has_value()) {
        return;
    }
    Result<purify::puresign_plusplus::TopicProofCache> proof_cache =
        purify::puresign_plusplus::TopicProofCache::build(topic);
    expect_ok(ctx, proof_cache, "PureSign++ TopicProofCache::build succeeds");
    Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared_with_proof =
        key_pair->prepare_topic_nonce_with_proof(topic, context.get());
    expect_ok(ctx, prepared_with_proof, "PureSign++ KeyPair::prepare_topic_nonce_with_proof succeeds");
    if (!proof_cache.has_value() || !prepared_with_proof.has_value()) {
        return;
    }
    const purify::puresign_plusplus::PublicKey& public_key = key_pair->public_key();

    Result<bool> nonce_proof_ok =
        public_key.verify_topic_nonce_proof(topic, prepared_with_proof->proof(), context.get());
    expect_ok(ctx, nonce_proof_ok, "PureSign++ PublicKey::verify_topic_nonce_proof succeeds");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "PureSign++ generated topic nonce proof verifies");
    }

    Result<purify::puresign_plusplus::ProvenSignature> proven =
        key_pair->sign_with_prepared_topic_proof(message, std::move(*prepared_with_proof), context.get());
    expect_ok(ctx, proven, "PureSign++ KeyPair::sign_with_prepared_topic_proof succeeds");
    ctx.expect(!prepared_with_proof->available(),
               "PureSign++ proof signing consumes the wrapped nonce");
    expect_error(ctx, prepared_with_proof->scalar(),
                 ErrorCode::UninitializedState,
                 "consumed PureSign++ proof cannot export its scalar");
    expect_error(ctx,
                 key_pair->sign_with_prepared_topic_proof(
                     message, std::move(*prepared_with_proof), context.get()),
                 ErrorCode::UninitializedState,
                 "PureSign++ consumed proof bundle cannot sign twice");
    Result<purify::puresign_plusplus::ProvenSignature> cached_proven =
        key_pair->sign_with_topic_proof(message, *proof_cache, context.get());
    expect_ok(ctx, cached_proven, "PureSign++ KeyPair::sign_with_topic_proof succeeds with a cached template");
    if (!proven.has_value() || !cached_proven.has_value()) {
        return;
    }

    Result<bool> proven_ok = public_key.verify_topic_signature_with_proof(message, topic, *proven, context.get());
    expect_ok(ctx, proven_ok, "PureSign++ PublicKey::verify_topic_signature_with_proof succeeds");
    if (proven_ok.has_value()) {
        ctx.expect(*proven_ok, "PureSign++ topic signature with proof verifies");
    }
    Result<bool> cached_proven_ok =
        public_key.verify_topic_signature_with_proof(*proof_cache, message, *cached_proven, context.get());
    expect_ok(ctx, cached_proven_ok,
              "PureSign++ PublicKey::verify_topic_signature_with_proof succeeds with a cached template");
    if (cached_proven_ok.has_value()) {
        ctx.expect(*cached_proven_ok, "PureSign++ cached topic signature with proof verifies");
    }
}

void test_puresign_plusplus_topic_proof_cache_reuse(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign++ repeated topic proof generation");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes topic = purify::bytes_from_ascii("session-pp-reuse");
    Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "PureSign++ KeyPair::from_secret succeeds for repeated topic proof generation");
    Result<purify::puresign_plusplus::TopicProofCache> proof_cache =
        purify::puresign_plusplus::TopicProofCache::build(topic);
    expect_ok(ctx, proof_cache, "PureSign++ TopicProofCache::build succeeds for repeated topic proof generation");
    if (!key_pair.has_value() || !proof_cache.has_value()) {
        return;
    }

    purify::bppp::ExperimentalCircuitCache shared_cache;
    const purify::puresign_plusplus::PublicKey& public_key = key_pair->public_key();

    Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared_a =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get(), &shared_cache);
    expect_ok(ctx, prepared_a, "PureSign++ cached topic proof generation succeeds on the first call");
    const std::size_t cache_size_after_a = shared_cache.size();
    ctx.expect(cache_size_after_a > 0, "PureSign++ repeated topic proof generation populates the shared cache");

    Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared_b =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get(), &shared_cache);
    expect_ok(ctx, prepared_b, "PureSign++ cached topic proof generation succeeds on the second call");
    ctx.expect(shared_cache.size() == cache_size_after_a,
               "PureSign++ repeated topic proof generation reuses the shared cache entries");

    Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared_c =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get(), &shared_cache);
    expect_ok(ctx, prepared_c, "PureSign++ cached topic proof generation succeeds on the third call");
    ctx.expect(shared_cache.size() == cache_size_after_a,
               "PureSign++ repeated topic proof generation keeps the shared cache stable");

    if (!prepared_a.has_value() || !prepared_b.has_value() || !prepared_c.has_value()) {
        return;
    }

    Result<bool> prepared_a_ok =
        public_key.verify_topic_nonce_proof(*proof_cache, prepared_a->proof(), context.get(), &shared_cache);
    expect_ok(ctx, prepared_a_ok, "PureSign++ first cached topic proof verifies with the shared cache");
    if (prepared_a_ok.has_value()) {
        ctx.expect(*prepared_a_ok, "PureSign++ first cached topic proof is accepted");
    }

    Result<bool> prepared_b_ok =
        public_key.verify_topic_nonce_proof(*proof_cache, prepared_b->proof(), context.get(), &shared_cache);
    expect_ok(ctx, prepared_b_ok, "PureSign++ second cached topic proof verifies with the shared cache");
    if (prepared_b_ok.has_value()) {
        ctx.expect(*prepared_b_ok, "PureSign++ second cached topic proof is accepted");
    }

    Result<bool> prepared_c_ok =
        public_key.verify_topic_nonce_proof(*proof_cache, prepared_c->proof(), context.get(), &shared_cache);
    expect_ok(ctx, prepared_c_ok, "PureSign++ third cached topic proof verifies with the shared cache");
    if (prepared_c_ok.has_value()) {
        ctx.expect(*prepared_c_ok, "PureSign++ third cached topic proof is accepted");
    }
}

void test_puresign_plusplus_topic_proof_cache_clone_for_thread(TestContext& ctx) {
    Result<SecretKey> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign++ cache cloning");
    if (!secret.has_value()) {
        return;
    }
    purify::SecpContextPtr context = make_test_secp_context(ctx);
    if (context == nullptr) {
        return;
    }

    Bytes topic = purify::bytes_from_ascii("session-pp-clone");
    Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(*secret, context.get());
    expect_ok(ctx, key_pair, "PureSign++ KeyPair::from_secret succeeds for cache cloning");
    Result<purify::puresign_plusplus::TopicProofCache> proof_cache =
        purify::puresign_plusplus::TopicProofCache::build(topic);
    expect_ok(ctx, proof_cache, "PureSign++ TopicProofCache::build succeeds for cache cloning");
    if (!key_pair.has_value() || !proof_cache.has_value()) {
        return;
    }

    purify::bppp::ExperimentalCircuitCache shared_cache;
    Result<purify::puresign_plusplus::PreparedNonceWithProof> warmed =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get(), &shared_cache);
    expect_ok(ctx, warmed, "PureSign++ warms the shared backend cache before cloning");
    ctx.expect(shared_cache.size() > 0, "PureSign++ shared cache contains warmed entries");
    Result<purify::NativeBulletproofCircuit> circuit =
        proof_cache->circuit_template.instantiate(key_pair->public_key().purify_pubkey);
    expect_ok(ctx, circuit, "PureSign++ instantiates the cached circuit for line cloning");
    if (!warmed.has_value() || !circuit.has_value()) {
        return;
    }

    const std::size_t generator_count = 4 * circuit->n_gates;
    Result<std::vector<purify::bppp::PointBytes>> generators =
        purify::bppp::create_generators(generator_count, context.get());
    expect_ok(ctx, generators, "PureSign++ reconstructs the cached generator line for cloning");
    if (!generators.has_value()) {
        return;
    }

    Result<purify::bppp::ExperimentalCircuitCacheLine> cloned_line =
        shared_cache.clone_line_for_thread(*generators);
    expect_ok(ctx, cloned_line, "PureSign++ cache clones for thread-local reuse");
    if (!cloned_line.has_value()) {
        return;
    }
    ctx.expect(!cloned_line->empty(),
               "PureSign++ cloned cache line contains one warmed backend line");

    Result<purify::puresign_plusplus::PreparedNonceWithProof> cloned_prepared =
        key_pair->prepare_topic_nonce_with_proof(*proof_cache, context.get(), &*cloned_line);
    expect_ok(ctx, cloned_prepared, "PureSign++ prepares a topic proof with the cloned cache");
    if (!cloned_prepared.has_value()) {
        return;
    }

    Result<bool> cloned_ok =
        key_pair->public_key().verify_topic_nonce_proof(*proof_cache, cloned_prepared->proof(), context.get(), &*cloned_line);
    expect_ok(ctx, cloned_ok, "PureSign++ verifies a topic proof with the cloned cache");
    if (cloned_ok.has_value()) {
        ctx.expect(*cloned_ok, "PureSign++ cloned cache accepts the topic proof");
    }
}

}  // namespace

void run_puresign_tests(purify_test::TestContext& ctx) {
    test_puresign_pinned_signing_vectors(ctx);
    test_puresign_message_signing(ctx);
    test_puresign_topic_signing(ctx);
    test_puresign_topic_proof_cache_clone_for_thread(ctx);
    test_puresign_binding_checks(ctx);
    test_puresign_plusplus_prepared_nonce_consumption(ctx);
    test_puresign_plusplus_message_signing(ctx);
    test_puresign_plusplus_topic_signing(ctx);
    test_puresign_plusplus_topic_proof_cache_reuse(ctx);
    test_puresign_plusplus_topic_proof_cache_clone_for_thread(ctx);
}
