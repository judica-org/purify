// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign.hpp
 * @brief Purify-derived BIP340 signing helpers with prepared nonces and wire-format artifacts.
 *
 * This layer exposes deterministic nonces and signatures derived from a packed Purify secret and
 * intended to be ready for transport or direct secp256k1 use. It does not yet emit a third-party-
 * verifiable Purify statement proof because the current backend only exposes witness generation
 * and a standalone norm argument, not a full statement-proof API.
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "purify/api.hpp"

namespace purify::puresign {

using Scalar32 = std::array<unsigned char, 32>;
using XOnly32 = std::array<unsigned char, 32>;
using Signature64 = std::array<unsigned char, 64>;

/**
 * @brief Public key bundle pairing a Purify packed public key with its derived BIP340 x-only key.
 *
 * This bundle is convenient for applications that need both identities. Until a full statement
 * proof is exposed, third parties can verify signatures against `bip340_pubkey` but cannot
 * independently prove that the bundled Purify and BIP340 keys came from the same secret.
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
 * @brief Move-only prepared nonce bound to either a message or a topic.
 *
 * The public nonce is safe to send over the wire. The secret scalar is intentionally not
 * serializable and is wiped on destruction and after moves.
 */
class PreparedNonce {
public:
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
    enum class Scope : std::uint8_t {
        Message,
        Topic,
    };

    PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                  const XOnly32& signer_pubkey, const XOnly32& binding_digest);

    void clear() noexcept;

    Scope scope_{Scope::Message};
    Scalar32 scalar_{};
    Nonce nonce_{};
    XOnly32 signer_pubkey_{};
    XOnly32 binding_digest_{};

    friend Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message);
    friend Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic);
    friend Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                                        PreparedNonce&& prepared);
    friend Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                                      PreparedNonce&& prepared);
};

/** @brief Derives the public PureSign key bundle from a packed Purify secret. */
Result<PublicKey> derive_public_key(const UInt512& secret);

/** @brief Derives a deterministic nonce bound to an exact message. */
Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message);
/**
 * @brief Derives a deterministic nonce bound to a caller-chosen topic.
 *
 * The topic must be non-empty and single-use. Reusing the same topic-bound prepared nonce for more
 * than one message will reuse the signing nonce and leak the signing key.
 */
Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic);

/** @brief Signs a message using a Purify-derived nonce bound to that same message. */
Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message);
/** @brief Signs a message using a previously prepared message-bound nonce. */
Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared);
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

/** @brief Verifies a standard BIP340 signature against the derived x-only public key. */
Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature);

}  // namespace purify::puresign
