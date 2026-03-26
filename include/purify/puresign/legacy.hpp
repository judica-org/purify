// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/legacy.hpp
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

struct MessageProofCache;
struct TopicProofCache;
struct Signature;
struct NonceProof;
struct ProvenSignature;

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

    /**
     * @brief Serializes this public-key bundle into its fixed-size wire format.
     * @return The 96-byte serialization of `(purify_pubkey, bip340_pubkey)`.
     */
    [[nodiscard]] Bytes serialize() const;

    /**
     * @brief Parses a serialized public-key bundle.
     * @param serialized The byte sequence previously produced by `serialize()`.
     * @return The parsed public-key bundle on success, or an error if the payload is malformed.
     */
    [[nodiscard]] static Result<PublicKey> deserialize(std::span<const unsigned char> serialized);

    /**
     * @brief Derives both public identities from one packed Purify secret.
     * @param secret The owned secret used to derive the Purify and BIP340 public keys.
     * @return The derived public-key bundle.
     */
    [[nodiscard]] static Result<PublicKey> from_secret(const SecretKey& secret);

    /**
     * @brief Verifies a plain BIP340 signature against this bundle's x-only public key.
     * @param message The message that was signed.
     * @param signature The signature to verify.
     * @return `true` when the signature is valid for `(message, bip340_pubkey)`.
     */
    [[nodiscard]] Result<bool> verify_signature(std::span<const unsigned char> message,
                                                const Signature& signature) const;

    /**
     * @brief Verifies a message-bound nonce proof against this public key.
     * @param message The message that defines the nonce binding.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and message.
     */
    [[nodiscard]] Result<bool> verify_message_nonce_proof(
        std::span<const unsigned char> message,
        const NonceProof& nonce_proof,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message-bound nonce proof using a reusable message proof cache.
     * @param cache The prebuilt cache for the exact message bound into the proof.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and cached message template.
     */
    [[nodiscard]] Result<bool> verify_message_nonce_proof(
        const MessageProofCache& cache,
        const NonceProof& nonce_proof,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound nonce proof against this public key.
     * @param topic The topic that defines the nonce binding.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and topic.
     */
    [[nodiscard]] Result<bool> verify_topic_nonce_proof(
        std::span<const unsigned char> topic,
        const NonceProof& nonce_proof,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound nonce proof using a reusable topic proof cache.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @param nonce_proof The public nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when the proof is valid for this public key and cached topic template.
     */
    [[nodiscard]] Result<bool> verify_topic_nonce_proof(
        const TopicProofCache& cache,
        const NonceProof& nonce_proof,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message signature bundled with its nonce proof.
     * @param message The signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and the nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_message_signature_with_proof(
        std::span<const unsigned char> message,
        const ProvenSignature& signature,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a message signature bundle using a reusable message proof cache.
     * @param cache The prebuilt cache for the exact signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and cached nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_message_signature_with_proof(
        const MessageProofCache& cache,
        const ProvenSignature& signature,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound signature bundled with its nonce proof.
     * @param message The signed message.
     * @param topic The topic that defines the nonce binding.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and topic-bound nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_topic_signature_with_proof(
        std::span<const unsigned char> message,
        std::span<const unsigned char> topic,
        const ProvenSignature& signature,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;

    /**
     * @brief Verifies a topic-bound signature bundle using a reusable topic proof cache.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @param message The signed message.
     * @param signature The bundled signature and nonce proof to verify.
     * @param circuit_cache Optional backend verifier cache to reuse across calls.
     * @return `true` when both the BIP340 signature and cached topic-bound nonce proof verify.
     */
    [[nodiscard]] Result<bool> verify_topic_signature_with_proof(
        const TopicProofCache& cache,
        std::span<const unsigned char> message,
        const ProvenSignature& signature,
        ExperimentalBulletproofBackendCache* circuit_cache = nullptr) const;
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
    Bytes template_digest;
    mutable ExperimentalBulletproofBackendCache backend_cache;

    /**
     * @brief Builds a reusable verifier template for one exact message.
     * @param message The message that all later prepared nonces or proofs must bind to.
     * @return The reusable cache for that message.
     */
    [[nodiscard]] static Result<MessageProofCache> build(std::span<const unsigned char> message);
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
    Bytes template_digest;
    mutable ExperimentalBulletproofBackendCache backend_cache;

    /**
     * @brief Builds a reusable verifier template for one exact topic.
     * @param topic The topic that all later prepared nonces or proofs must bind to.
     * @return The reusable cache for that topic.
     */
    [[nodiscard]] static Result<TopicProofCache> build(std::span<const unsigned char> topic);
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

    /**
     * @brief Returns the public nonce corresponding to this prepared secret nonce scalar.
     * @return The x-only public nonce that is safe to share with a verifier.
     */
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

    /**
     * @brief Builds a prepared nonce from already-derived nonce components.
     * @param scope Whether the nonce is message-bound or topic-bound.
     * @param scalar The secret nonce scalar to store.
     * @param nonce The public x-only nonce corresponding to `scalar`.
     * @param signer_pubkey The signer's BIP340 x-only public key.
     * @param binding_digest The binding digest that this nonce must later match.
     * @return The constructed move-only prepared nonce.
     */
    [[nodiscard]] static PreparedNonce from_parts(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                                                  const XOnly32& signer_pubkey, const XOnly32& binding_digest);

    /**
     * @brief Consumes this message-bound nonce and signs the matching message.
     * @param signer The BIP340 signer derived from the same secret as this prepared nonce.
     * @param message The message that must match the nonce binding.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_message(const Bip340Key& signer,
                                                 std::span<const unsigned char> message) &&;

    /**
     * @brief Consumes this topic-bound nonce and signs a message under that topic binding.
     * @param signer The BIP340 signer derived from the same secret as this prepared nonce.
     * @param message The message to sign.
     * @return The resulting BIP340 signature.
     */
    [[nodiscard]] Result<Signature> sign_topic_message(const Bip340Key& signer,
                                                       std::span<const unsigned char> message) &&;

private:
    PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                  const XOnly32& signer_pubkey, const XOnly32& binding_digest);

    void clear() noexcept;

    Scope scope_{Scope::Message};
    Scalar32 scalar_{};
    Nonce nonce_{};
    XOnly32 signer_pubkey_{};
    XOnly32 binding_digest_{};
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

    /**
     * @brief Returns the public nonce proved by this bundle.
     * @return The x-only public nonce that the bundled proof refers to.
     */
    [[nodiscard]] const Nonce& public_nonce() const noexcept {
        return prepared_.public_nonce();
    }

    /**
     * @brief Returns the public nonce proof carried by this bundle.
     * @return The nonce proof paired with the prepared nonce.
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
     * @brief Bundles a prepared nonce with its matching public nonce proof.
     * @param prepared The prepared nonce carrying the secret scalar.
     * @param proof The public nonce proof matching `prepared`.
     * @return The constructed move-only prepared nonce-plus-proof bundle.
     */
    [[nodiscard]] static PreparedNonceWithProof from_parts(PreparedNonce prepared, NonceProof proof);

    /**
     * @brief Consumes this message-bound prepared proof bundle and signs the message.
     * @param secret The owned secret corresponding to the prepared nonce.
     * @param message The message that must match the nonce binding.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message(const SecretKey& secret,
                                                       std::span<const unsigned char> message) &&;

    /**
     * @brief Consumes this topic-bound prepared proof bundle and signs the message.
     * @param secret The owned secret corresponding to the prepared nonce.
     * @param message The message to sign.
     * @return The resulting signature bundled with its nonce proof.
     */
    [[nodiscard]] Result<ProvenSignature> sign_topic_message(const SecretKey& secret,
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
     * @brief Derives a signing key pair from one packed Purify secret.
     * @param secret The secret to clone into the returned key pair.
     * @return A move-only signer object bundling the secret and public key.
     */
    [[nodiscard]] static Result<KeyPair> from_secret(const SecretKey& secret);

    /**
     * @brief Derives a signing key pair from one owned Purify secret.
     * @param secret The secret to move into the returned key pair.
     * @return A move-only signer object bundling the secret and public key.
     */
    [[nodiscard]] static Result<KeyPair> from_secret(SecretKey&& secret);

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
     * @brief Deterministically prepares a message-bound nonce together with its proof.
     * @param message The message to bind into the nonce derivation and proof statement.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(
        std::span<const unsigned char> message) const;

    /**
     * @brief Prepares a message-bound nonce proof using a reusable message cache.
     * @param cache The prebuilt cache for the exact message to bind.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(
        const MessageProofCache& cache) const;

    /**
     * @brief Deterministically prepares a topic-bound nonce.
     * @param topic The topic to bind into the nonce derivation.
     * @return The move-only prepared nonce.
     */
    [[nodiscard]] Result<PreparedNonce> prepare_topic_nonce(std::span<const unsigned char> topic) const;

    /**
     * @brief Deterministically prepares a topic-bound nonce together with its proof.
     * @param topic The topic to bind into the nonce derivation and proof statement.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(
        std::span<const unsigned char> topic) const;

    /**
     * @brief Prepares a topic-bound nonce proof using a reusable topic cache.
     * @param cache The prebuilt cache for the exact topic to bind.
     * @return The prepared nonce plus its public proof.
     */
    [[nodiscard]] Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(
        const TopicProofCache& cache) const;

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
     * @brief Signs a message and returns the signature bundled with its nonce proof.
     * @param message The message to sign.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message_with_proof(
        std::span<const unsigned char> message) const;

    /**
     * @brief Signs a message with proof using a reusable message cache.
     * @param cache The prebuilt cache for the exact signed message.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_message_with_proof(
        const MessageProofCache& cache) const;

    /**
     * @brief Signs a message with a topic-bound nonce proof.
     * @param message The message to sign.
     * @param topic The topic that the nonce proof must bind to.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_with_topic_proof(
        std::span<const unsigned char> message,
        std::span<const unsigned char> topic) const;

    /**
     * @brief Signs a message with a topic-bound nonce proof using a reusable topic cache.
     * @param message The message to sign.
     * @param cache The prebuilt cache for the exact topic bound into the proof.
     * @return The resulting signature-plus-proof bundle.
     */
    [[nodiscard]] Result<ProvenSignature> sign_with_topic_proof(
        std::span<const unsigned char> message,
        const TopicProofCache& cache) const;

private:
    KeyPair(SecretKey secret, PublicKey public_key)
        : secret_(std::move(secret)), public_key_(std::move(public_key)) {}

    SecretKey secret_;
    PublicKey public_key_{};
};

}  // namespace purify::puresign
