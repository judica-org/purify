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
using Nonce = purify::puresign::Nonce;
using Signature = purify::puresign::Signature;
using MessageProofCache = purify::puresign::MessageProofCache;
using TopicProofCache = purify::puresign::TopicProofCache;
using PreparedNonce = purify::puresign::PreparedNonce;

struct NonceProof;
struct ProvenSignature;

struct PublicKey {
    static constexpr std::size_t kSerializedSize = purify::puresign::PublicKey::kSerializedSize;

    UInt512 purify_pubkey;
    XOnly32 bip340_pubkey{};

    /**
     * @brief Serializes this PureSign++ public-key bundle into its fixed-size wire format.
     * @return The 96-byte serialization of `(purify_pubkey, bip340_pubkey)`.
     */
    [[nodiscard]] Bytes serialize() const;

    /**
     * @brief Parses a serialized PureSign++ public-key bundle.
     * @param serialized The byte sequence previously produced by `serialize()`.
     * @return The parsed public-key bundle on success, or an error if the payload is malformed.
     */
    [[nodiscard]] static Result<PublicKey> deserialize(std::span<const unsigned char> serialized);

    /**
     * @brief Derives both public identities from one packed Purify secret.
     * @param secret The packed secret used to derive the Purify and BIP340 public keys.
     * @return The derived public-key bundle.
     */
    [[nodiscard]] static Result<PublicKey> from_secret(const UInt512& secret);

    /**
     * @brief Verifies a plain BIP340 signature against this bundle's x-only public key.
     * @param message The message that was signed.
     * @param signature The signature to verify.
     * @return `true` when the signature is valid for `(message, bip340_pubkey)`.
     */
    [[nodiscard]] Result<bool> verify_signature(std::span<const unsigned char> message,
                                                const Signature& signature) const;

    /**
     * @brief Verifies a message-bound BPPP nonce proof against this public key.
     * @param message The message that defines the nonce binding.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and message.
     */
    [[nodiscard]] Result<bool> verify_message_nonce_proof(
        std::span<const unsigned char> message,
        const NonceProof& nonce_proof,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message-bound BPPP nonce proof using a reusable message cache.
     * @param cache The prebuilt cache for the exact message bound into the proof.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and cached message template.
     */
    [[nodiscard]] Result<bool> verify_message_nonce_proof(
        const MessageProofCache& cache,
        const NonceProof& nonce_proof,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound BPPP nonce proof against this public key.
     * @param topic The topic that defines the nonce binding.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and topic.
     */
    [[nodiscard]] Result<bool> verify_topic_nonce_proof(
        std::span<const unsigned char> topic,
        const NonceProof& nonce_proof,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound BPPP nonce proof using a reusable topic cache.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and cached topic template.
     */
    [[nodiscard]] Result<bool> verify_topic_nonce_proof(
        const TopicProofCache& cache,
        const NonceProof& nonce_proof,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message signature bundled with its BPPP nonce proof.
     * @param message The signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and the nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_message_signature_with_proof(
        std::span<const unsigned char> message,
        const ProvenSignature& signature,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message signature bundle using a reusable message proof cache.
     * @param cache The prebuilt cache for the exact signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and cached nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_message_signature_with_proof(
        const MessageProofCache& cache,
        const ProvenSignature& signature,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound signature bundled with its BPPP nonce proof.
     * @param message The signed message.
     * @param topic The topic that defines the nonce binding.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and topic-bound nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_topic_signature_with_proof(
        std::span<const unsigned char> message,
        std::span<const unsigned char> topic,
        const ProvenSignature& signature,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound signature bundle using a reusable topic proof cache.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @param message The signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional BPPP verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and cached topic-bound nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_topic_signature_with_proof(
        const TopicProofCache& cache,
        std::span<const unsigned char> message,
        const ProvenSignature& signature,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;
};

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

    /**
     * @brief Returns the public nonce proved by this bundle.
     * @return The x-only public nonce that the bundled proof refers to.
     */
    [[nodiscard]] const Nonce& public_nonce() const noexcept {
        return prepared_.public_nonce();
    }

    /**
     * @brief Returns the public nonce proof carried by this bundle.
     * @return The BPPP-backed nonce proof paired with the prepared nonce.
     */
    [[nodiscard]] const NonceProof& proof() const noexcept {
        return proof_;
    }

    /**
     * @brief Explicitly exports the secret nonce scalar from the wrapped prepared nonce.
     * @return A copy of the secret nonce scalar.
     */
    [[nodiscard]] Scalar32 scalar() const {
        return prepared_.scalar();
    }

    /**
     * @brief Bundles a prepared nonce with its matching BPPP-backed public nonce proof.
     * @param prepared The prepared nonce carrying the secret scalar.
     * @param proof The public nonce proof matching `prepared`.
     * @return The constructed move-only prepared nonce-plus-proof bundle.
     */
    [[nodiscard]] static PreparedNonceWithProof from_parts(PreparedNonce prepared, NonceProof proof);

    /**
     * @brief Consumes this message-bound prepared proof bundle and signs the message.
     * @param secret The packed secret corresponding to the prepared nonce.
     * @param message The message that must match the nonce binding.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message(const UInt512& secret,
                                                       std::span<const unsigned char> message) &&;

    /**
     * @brief Consumes this topic-bound prepared proof bundle and signs the message.
     * @param secret The packed secret corresponding to the prepared nonce.
     * @param message The message to sign.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_topic_message(const UInt512& secret,
                                                             std::span<const unsigned char> message) &&;

private:
    PreparedNonceWithProof(PreparedNonce prepared, NonceProof proof)
        : prepared_(std::move(prepared)), proof_(std::move(proof)) {}

    PreparedNonce prepared_;
    NonceProof proof_;
};

class KeyPair {
public:
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair(KeyPair&& other) noexcept = default;
    KeyPair& operator=(KeyPair&& other) noexcept = default;
    ~KeyPair() = default;

    /**
     * @brief Derives a PureSign++ signing key pair from one packed Purify secret.
     * @param secret The packed secret to own inside the returned key pair.
     * @return A move-only signer object bundling the secret, BIP340 signer, and public key.
     */
    [[nodiscard]] static Result<KeyPair> from_secret(const UInt512& secret);

    /**
     * @brief Returns the public key bundle associated with this signer.
     * @return The derived public-key bundle.
     */
    [[nodiscard]] const PublicKey& public_key() const noexcept {
        return public_key_;
    }

    /**
     * @brief Deterministically prepares a message-bound nonce.
     * @param message The message to bind into the nonce derivation.
     * @return The move-only prepared nonce.
     */
    [[nodiscard]] Result<PreparedNonce> prepare_message_nonce(std::span<const unsigned char> message) const;

    /**
     * @brief Deterministically prepares a message-bound nonce together with its BPPP proof.
     * @param message The message to bind into the nonce derivation and proof statement.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(
        std::span<const unsigned char> message,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Prepares a message-bound nonce proof using a reusable message cache.
     * @param cache The prebuilt cache for the exact message to bind.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(
        const MessageProofCache& cache,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Deterministically prepares a topic-bound nonce.
     * @param topic The topic to bind into the nonce derivation.
     * @return The move-only prepared nonce.
     */
    [[nodiscard]] Result<PreparedNonce> prepare_topic_nonce(std::span<const unsigned char> topic) const;

    /**
     * @brief Deterministically prepares a topic-bound nonce together with its BPPP proof.
     * @param topic The topic to bind into the nonce derivation and proof statement.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(
        std::span<const unsigned char> topic,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Prepares a topic-bound nonce proof using a reusable topic cache.
     * @param cache The prebuilt cache for the exact topic to bind.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(
        const TopicProofCache& cache,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Signs a message with a deterministically derived message-bound nonce.
     * @param message The message to sign.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_message(std::span<const unsigned char> message) const;

    /**
     * @brief Signs a message using an already prepared message-bound nonce.
     * @param message The message that must match the prepared nonce binding.
     * @param prepared The prepared message-bound nonce to consume.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_message_with_prepared(std::span<const unsigned char> message,
                                                               PreparedNonce&& prepared) const;

    /**
     * @brief Signs a message using an already prepared message-bound nonce proof bundle.
     * @param message The message that must match the prepared nonce binding.
     * @param prepared The prepared nonce-plus-proof bundle to consume.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message_with_prepared_proof(
        std::span<const unsigned char> message,
        PreparedNonceWithProof&& prepared) const;

    /**
     * @brief Signs a message using a topic-bound deterministic nonce.
     * @param message The message to sign.
     * @param topic The topic that the nonce must be bound to.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_with_topic(std::span<const unsigned char> message,
                                                    std::span<const unsigned char> topic) const;

    /**
     * @brief Signs a message using an already prepared topic-bound nonce.
     * @param message The message to sign.
     * @param prepared The topic-bound nonce to consume.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_with_prepared_topic(std::span<const unsigned char> message,
                                                             PreparedNonce&& prepared) const;

    /**
     * @brief Signs a message using an already prepared topic-bound nonce proof bundle.
     * @param message The message to sign.
     * @param prepared The topic-bound nonce-plus-proof bundle to consume.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_with_prepared_topic_proof(
        std::span<const unsigned char> message,
        PreparedNonceWithProof&& prepared) const;

    /**
     * @brief Signs a message and returns the signature bundled with its BPPP nonce proof.
     * @param message The message to sign.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message_with_proof(
        std::span<const unsigned char> message,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Signs a message with proof using a reusable message cache.
     * @param cache The prebuilt cache for the exact signed message.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message_with_proof(
        const MessageProofCache& cache,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Signs a message with a topic-bound nonce proof.
     * @param message The message to sign.
     * @param topic The topic that the nonce proof must bind to.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_with_topic_proof(
        std::span<const unsigned char> message,
        std::span<const unsigned char> topic,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

    /**
     * @brief Signs a message with a topic-bound nonce proof using a reusable topic cache.
     * @param message The message to sign.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @param circuit_cache Optional BPPP prover cache to reuse across calls.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_with_topic_proof(
        std::span<const unsigned char> message,
        const TopicProofCache& cache,
        bppp::ExperimentalCircuitCache* circuit_cache = nullptr) const;

private:
    KeyPair(const UInt512& secret, Bip340Key signer, PublicKey public_key)
        : secret_(secret), signer_(std::move(signer)), public_key_(std::move(public_key)) {}

    UInt512 secret_{};
    Bip340Key signer_{};
    PublicKey public_key_{};
};

}  // namespace purify::puresign_plusplus
