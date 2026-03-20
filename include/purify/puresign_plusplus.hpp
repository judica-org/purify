// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign_plusplus.hpp
 * @brief Experimental BPPP-backed PureSign proof(R) helpers.
 */

#pragma once

#include <span>
#include <utility>

#include "purify/puresign.hpp"
#include "purify_bppp.hpp"

namespace purify::puresign_plusplus {

using Scalar32 = purify::puresign::Scalar32;
using XOnly32 = purify::puresign::XOnly32;
using Signature64 = purify::puresign::Signature64;
using PublicKey = purify::puresign::PublicKey;
using Nonce = purify::puresign::Nonce;
using Signature = purify::puresign::Signature;
using MessageProofCache = purify::puresign::MessageProofCache;
using TopicProofCache = purify::puresign::TopicProofCache;
using PreparedNonce = purify::puresign::PreparedNonce;

struct NonceProof {
    static constexpr unsigned char kSerializationVersion = 1;

    Nonce nonce;
    bppp::PointBytes commitment_point{};
    bppp::ExperimentalCircuitZkNormArgProof proof;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<NonceProof> deserialize(std::span<const unsigned char> serialized);
};

struct ProvenSignature {
    static constexpr unsigned char kSerializationVersion = 1;

    Signature signature;
    NonceProof nonce_proof;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<ProvenSignature> deserialize(std::span<const unsigned char> serialized);
};

class PreparedNonceWithProof {
public:
    PreparedNonceWithProof(const PreparedNonceWithProof&) = delete;
    PreparedNonceWithProof& operator=(const PreparedNonceWithProof&) = delete;

    PreparedNonceWithProof(PreparedNonceWithProof&& other) noexcept = default;
    PreparedNonceWithProof& operator=(PreparedNonceWithProof&& other) noexcept = default;
    ~PreparedNonceWithProof() = default;

    [[nodiscard]] const Nonce& public_nonce() const noexcept {
        return prepared_.public_nonce();
    }

    [[nodiscard]] const NonceProof& proof() const noexcept {
        return proof_;
    }

    [[nodiscard]] Scalar32 scalar() const {
        return prepared_.scalar();
    }

private:
    PreparedNonceWithProof(PreparedNonce prepared, NonceProof proof)
        : prepared_(std::move(prepared)), proof_(std::move(proof)) {}

    PreparedNonce prepared_;
    NonceProof proof_;

    friend Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                           std::span<const unsigned char> message,
                                                                           bppp::ExperimentalCircuitCache* circuit_cache);
    friend Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                           const MessageProofCache& cache,
                                                                           bppp::ExperimentalCircuitCache* circuit_cache);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         std::span<const unsigned char> topic,
                                                                         bppp::ExperimentalCircuitCache* circuit_cache);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         const TopicProofCache& cache,
                                                                         bppp::ExperimentalCircuitCache* circuit_cache);
    friend Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret,
                                                                    std::span<const unsigned char> message,
                                                                    PreparedNonceWithProof&& prepared);
    friend Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret,
                                                                  std::span<const unsigned char> message,
                                                                  PreparedNonceWithProof&& prepared);
};

Result<PublicKey> derive_public_key(const UInt512& secret);

Result<MessageProofCache> build_message_proof_cache(std::span<const unsigned char> message);
Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic);

Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message);
Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                std::span<const unsigned char> message,
                                                                bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                const MessageProofCache& cache,
                                                                bppp::ExperimentalCircuitCache* circuit_cache = nullptr);

Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic);
Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              std::span<const unsigned char> topic,
                                                              bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              const TopicProofCache& cache,
                                                              bppp::ExperimentalCircuitCache* circuit_cache = nullptr);

Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message);
Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared);
Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret,
                                                         std::span<const unsigned char> message,
                                                         PreparedNonceWithProof&& prepared);

Result<Signature> sign_with_topic(const UInt512& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic);
Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared);
Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret,
                                                       std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared);

Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, std::span<const unsigned char> message,
                                                bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, const MessageProofCache& cache,
                                                bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic,
                                              bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache,
                                              bppp::ExperimentalCircuitCache* circuit_cache = nullptr);

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature);
Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof,
                                        bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof,
                                        bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof,
                                      bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof,
                                      bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_message_signature_with_proof(const PublicKey& public_key,
                                                 std::span<const unsigned char> message,
                                                 const ProvenSignature& signature,
                                                 bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_message_signature_with_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                                 const ProvenSignature& signature,
                                                 bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature,
                                               bppp::ExperimentalCircuitCache* circuit_cache = nullptr);
Result<bool> verify_topic_signature_with_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               const ProvenSignature& signature,
                                               bppp::ExperimentalCircuitCache* circuit_cache = nullptr);

}  // namespace purify::puresign_plusplus
