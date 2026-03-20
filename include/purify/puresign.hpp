// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign.hpp
 * @brief Legacy Bulletproof-backed Purify-derived BIP340 signing helpers with prepared nonces.
 *
 * This layer exposes deterministic nonces, signatures, and experimental `proof(R)` artifacts
 * derived from a packed Purify secret and intended to be ready for transport or direct
 * secp256k1 use. This is the legacy Bulletproof-backed `proof(R)` surface.
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>

#include "purify/api.hpp"

namespace purify::puresign {

using Scalar32 = std::array<unsigned char, 32>;
using XOnly32 = std::array<unsigned char, 32>;
using Signature64 = std::array<unsigned char, 64>;

/**
 * @brief Public key bundle pairing a Purify packed public key with its derived BIP340 x-only key.
 *
 * This bundle is convenient for applications that need both identities. Third parties can verify
 * signatures against `bip340_pubkey`, but this convenience type does not by itself prove that the
 * bundled Purify and BIP340 keys came from the same secret.
 */
struct PublicKey {
    static constexpr std::size_t kSerializedSize = 96;

    UInt512 purify_pubkey;
    XOnly32 bip340_pubkey{};

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<PublicKey> deserialize(std::span<const unsigned char> serialized);
};

/** @brief Public BIP340 nonce point in x-only form. */
struct Nonce {
    static constexpr std::size_t kSerializedSize = 32;

    XOnly32 xonly{};

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Nonce> deserialize(std::span<const unsigned char> serialized);
};

/** @brief Standard 64-byte BIP340 signature. */
struct Signature {
    static constexpr std::size_t kSerializedSize = 64;

    Signature64 bytes{};

    [[nodiscard]] Nonce nonce() const;
    [[nodiscard]] Scalar32 s() const;
    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<Signature> deserialize(std::span<const unsigned char> serialized);
};

/**
 * @brief Public nonce together with its experimental Purify statement proof.
 *
 * The proved statement binds `nonce` to the unique Purify evaluation for the supplied
 * `(secret, scope, input)`. There is intentionally no public retry selector in this format:
 * if the derived scalar is zero, preparation fails instead of allowing multiple valid public
 * nonces for the same input. That failure occurs with negligible probability, about `2^-256`.
 */
struct NonceProof {
    Nonce nonce;
    ExperimentalBulletproofProof proof;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<NonceProof> deserialize(std::span<const unsigned char> serialized);
};

/** @brief Standard signature bundled with the public nonce proof it relied on. */
struct ProvenSignature {
    Signature signature;
    NonceProof nonce_proof;

    [[nodiscard]] Result<Bytes> serialize() const;
    [[nodiscard]] static Result<ProvenSignature> deserialize(std::span<const unsigned char> serialized);
};

/**
 * @brief Cacheable message-bound nonce-proof template.
 *
 * This bundles the exact message together with the public-key-agnostic circuit template needed for
 * message-bound `proof(R)` creation and verification. Reuse the same instance across multiple
 * users for the same message.
 */
struct MessageProofCache {
    Bytes message;
    Bytes eval_input;
    NativeBulletproofCircuitTemplate circuit_template;
    mutable ExperimentalBulletproofBackendCache backend_cache;
};

/**
 * @brief Cacheable topic-bound nonce-proof template.
 *
 * This bundles the exact topic together with the public-key-agnostic circuit template needed for
 * topic-bound `proof(R)` creation and verification. Reuse the same instance across multiple users
 * for the same topic.
 */
struct TopicProofCache {
    Bytes topic;
    Bytes eval_input;
    NativeBulletproofCircuitTemplate circuit_template;
    mutable ExperimentalBulletproofBackendCache backend_cache;
};

class PreparedNonceWithProof;

/**
 * @brief Move-only prepared nonce bound to either a message or a topic.
 *
 * The public nonce is safe to send over the wire. The secret scalar is intentionally not
 * serializable and is wiped on destruction and after moves.
 */
class PreparedNonce {
public:
    enum class Scope : std::uint8_t {
        Message,
        Topic,
    };

    PreparedNonce(const PreparedNonce&) = delete;
    PreparedNonce& operator=(const PreparedNonce&) = delete;

    PreparedNonce(PreparedNonce&& other) noexcept;
    PreparedNonce& operator=(PreparedNonce&& other) noexcept;
    ~PreparedNonce();

    [[nodiscard]] const Nonce& public_nonce() const noexcept {
        return nonce_;
    }

    /**
     * @brief Explicitly exports the secret nonce scalar.
     *
     * This is intentionally a copy-returning accessor so callers have to opt in to handling the
     * secret value.
     */
    [[nodiscard]] Scalar32 scalar() const {
        return scalar_;
    }

private:
    PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                  const XOnly32& signer_pubkey, const XOnly32& binding_digest);

    void clear() noexcept;

    Scope scope_{Scope::Message};
    Scalar32 scalar_{};
    Nonce nonce_{};
    XOnly32 signer_pubkey_{};
    XOnly32 binding_digest_{};

    friend class PreparedNonceWithProof;
    friend Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message);
    friend Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic);
    friend Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                           std::span<const unsigned char> message);
    friend Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                           const MessageProofCache& cache);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         std::span<const unsigned char> topic);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         const TopicProofCache& cache);
    friend Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                                        PreparedNonce&& prepared);
    friend Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                                      PreparedNonce&& prepared);
};

/**
 * @brief Move-only prepared nonce bundled with its public statement proof.
 *
 * The proof is always present and the secret nonce scalar remains non-serializable. This avoids
 * forcing callers to branch on a maybe-present proof after the type has already crossed an API
 * boundary.
 */
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
                                                                           std::span<const unsigned char> message);
    friend Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                           const MessageProofCache& cache);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         std::span<const unsigned char> topic);
    friend Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                                         const TopicProofCache& cache);
    friend Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret,
                                                                    std::span<const unsigned char> message,
                                                                    PreparedNonceWithProof&& prepared);
    friend Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret,
                                                                  std::span<const unsigned char> message,
                                                                  PreparedNonceWithProof&& prepared);
};

/** @brief Derives the public PureSign key bundle from a packed Purify secret. */
Result<PublicKey> derive_public_key(const UInt512& secret);

/** @brief Builds and caches the message-bound proof template for repeated cross-user use. */
Result<MessageProofCache> build_message_proof_cache(std::span<const unsigned char> message);
/** @brief Builds and caches the topic-bound proof template for repeated cross-user use. */
Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic);

/** @brief Derives a deterministic nonce bound to an exact message. */
Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message);
/** @brief Derives a deterministic message-bound nonce and proves its public point `R`. */
Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret, std::span<const unsigned char> message);
/** @brief Derives a deterministic message-bound nonce and proves it using a prebuilt message proof cache. */
Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret, const MessageProofCache& cache);
/**
 * @brief Derives a deterministic nonce bound to a caller-chosen topic.
 *
 * The topic must be non-empty and single-use. Reusing the same topic-bound prepared nonce for more
 * than one message will reuse the signing nonce and leak the signing key.
 */
Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic);
/** @brief Derives a deterministic topic-bound nonce and proves its public point `R`. */
Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret, std::span<const unsigned char> topic);
/** @brief Derives a deterministic topic-bound nonce and proves it using a prebuilt topic proof cache. */
Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret, const TopicProofCache& cache);

/** @brief Signs a message using a Purify-derived nonce bound to that same message. */
Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message);
/** @brief Signs a message using a previously prepared message-bound nonce. */
Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared);
/** @brief Signs a message and returns the signature bundled with the prepared public nonce proof. */
Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret, std::span<const unsigned char> message,
                                                         PreparedNonceWithProof&& prepared);
/**
 * @brief Signs a message using a Purify-derived nonce bound only to the supplied topic.
 *
 * The topic must be single-use for this signature. Reusing a topic across two different messages
 * reuses the nonce and leaks the signing key.
 */
Result<Signature> sign_with_topic(const UInt512& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic);
/**
 * @brief Signs a message using a previously prepared topic-bound nonce.
 *
 * The prepared nonce is consumed and must never be reused for a second message.
 */
Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared);
/** @brief Signs with a prepared topic-bound nonce and returns the bundled public nonce proof. */
Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared);

/** @brief Prepares, signs, and returns the bundled message-bound nonce proof and signature. */
Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, std::span<const unsigned char> message);
/** @brief Prepares, signs, and returns the bundled message-bound nonce proof using a prebuilt message proof cache. */
Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, const MessageProofCache& cache);
/** @brief Prepares, signs, and returns the bundled topic-bound nonce proof and signature. */
Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic);
/** @brief Prepares, signs, and returns the bundled topic-bound nonce proof using a prebuilt topic proof cache. */
Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache);

/** @brief Verifies a standard BIP340 signature against the derived x-only public key. */
Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature);
/** @brief Verifies a message-bound public nonce proof against the Purify public key. */
Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof);
/** @brief Verifies a message-bound public nonce proof using a prebuilt message proof cache. */
Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof);
/** @brief Verifies a topic-bound public nonce proof against the Purify public key. */
Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof);
/** @brief Verifies a topic-bound public nonce proof using a prebuilt topic proof cache. */
Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof);
/** @brief Verifies a message signature together with the claimed public nonce proof. */
Result<bool> verify_message_signature_with_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                                 const ProvenSignature& signature);
/** @brief Verifies a message signature together with the claimed public nonce proof using a prebuilt message proof cache. */
Result<bool> verify_message_signature_with_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                                 const ProvenSignature& signature);
/** @brief Verifies a topic-bound signature together with the claimed public nonce proof. */
Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature);
/** @brief Verifies a topic-bound signature together with the claimed public nonce proof using a prebuilt topic proof cache. */
Result<bool> verify_topic_signature_with_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               const ProvenSignature& signature);

}  // namespace purify::puresign
