// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
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
    ctx.expect(prepared_a->scalar() == prepared_b->scalar(),
               "message-bound secret nonce scalars are deterministic");

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
    ctx.expect(prepared_a->scalar() == prepared_b->scalar(),
               "topic-bound secret nonce scalars are deterministic");

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
    }

    Result<purify::puresign::PreparedNonce> topic_nonce = key_pair->prepare_topic_nonce(topic, context.get());
    expect_ok(ctx, topic_nonce, "KeyPair::prepare_topic_nonce succeeds for binding checks");
    if (topic_nonce.has_value()) {
        expect_error(ctx, key_pair->sign_message_with_prepared(message, std::move(*topic_nonce), context.get()),
                     ErrorCode::BindingMismatch,
                     "topic-bound prepared nonces reject the message-bound signing API");
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

    Result<Bytes> nonce_proof_bytes = proven->nonce_proof.serialize(context.get());
    expect_ok(ctx, nonce_proof_bytes, "PureSign++ NonceProof serializes");
    if (nonce_proof_bytes.has_value()) {
        Result<purify::puresign_plusplus::NonceProof> parsed_nonce_proof =
            purify::puresign_plusplus::NonceProof::deserialize(*nonce_proof_bytes, context.get());
        expect_ok(ctx, parsed_nonce_proof, "PureSign++ NonceProof round-trips");
    }

    Result<Bytes> proven_bytes = proven->serialize(context.get());
    expect_ok(ctx, proven_bytes, "PureSign++ ProvenSignature serializes");
    if (proven_bytes.has_value()) {
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

}  // namespace

void run_puresign_tests(purify_test::TestContext& ctx) {
    test_puresign_message_signing(ctx);
    test_puresign_topic_signing(ctx);
    test_puresign_binding_checks(ctx);
    test_puresign_plusplus_message_signing(ctx);
    test_puresign_plusplus_topic_signing(ctx);
}
