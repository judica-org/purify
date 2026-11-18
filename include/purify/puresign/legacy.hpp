// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/legacy.hpp
 * @brief Legacy Bulletproof-backed Purify-derived BIP340 signing helpers with prepared nonces.
 *
 * This layer exposes deterministic nonces, signatures, and experimental `proof(R)` artifacts
 * derived from a packed Purify secret and intended to be ready for transport or direct
 * secp256k1 use. This is the legacy Bulletproof-backed `proof(R)` surface; the signing flows it
 * shares with the BPPP-backed surface are documented in `purify/puresign/core.hpp`.
 */

#pragma once

#include <span>

#include "purify/puresign/core.hpp"

namespace purify::puresign {

using puresign_core::Nonce;
using puresign_core::PreparedNonce;
using puresign_core::Scalar32;
using puresign_core::Signature;
using puresign_core::Signature64;
using puresign_core::XOnly32;

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

    [[nodiscard]] Result<Bytes> serialize(purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<NonceProof> deserialize(std::span<const unsigned char> serialized,
                                                        purify_secp_context* secp_context);
};

/** @brief Standard signature bundled with the public nonce proof it relied on. */
struct ProvenSignature {
    Signature signature;
    NonceProof nonce_proof;

    [[nodiscard]] Result<Bytes> serialize(purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<ProvenSignature> deserialize(std::span<const unsigned char> serialized,
                                                             purify_secp_context* secp_context);
};

/** @brief Selects the legacy Bulletproof proof system for the shared PureSign layer. */
struct Backend {
    using NonceProof = puresign::NonceProof;
    using ProvenSignature = puresign::ProvenSignature;
    using ProofCache = ExperimentalBulletproofBackendCache;
    using CircuitCache = ExperimentalBulletproofBackendCache;

    /** The proof commits to the nonce's x coordinate only. */
    static constexpr bool kProofBindsRawPoint = false;

    struct Ops;
};

/** @brief Purify and BIP340 public keys, with Bulletproof `proof(R)` verification. */
using PublicKey = puresign_core::PublicKey<Backend>;
/** @brief Cacheable message-bound nonce-proof template for the Bulletproof backend. */
using MessageProofCache = puresign_core::MessageProofCache<Backend>;
/** @brief Cacheable topic-bound nonce-proof template for the Bulletproof backend. */
using TopicProofCache = puresign_core::TopicProofCache<Backend>;
/** @brief Move-only prepared nonce bundled with its Bulletproof `proof(R)`. */
using PreparedNonceWithProof = puresign_core::PreparedNonceWithProof<Backend>;
/** @brief Move-only signer producing Bulletproof-backed `proof(R)` artifacts. */
using KeyPair = puresign_core::KeyPair<Backend>;

}  // namespace purify::puresign
