// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/bppp.hpp
 * @brief Experimental BPPP-backed PureSign proof(R) helpers.
 *
 * The signing flows this surface shares with the legacy Bulletproof-backed one are documented in
 * `purify/puresign/core.hpp`.
 */

#pragma once

#include <cstddef>
#include <span>

#include "purify/bppp.hpp"
#include "purify/puresign/core.hpp"

namespace purify::puresign_plusplus {

using puresign_core::Nonce;
using puresign_core::PreparedNonce;
using puresign_core::Scalar32;
using puresign_core::Signature;
using puresign_core::Signature64;
using puresign_core::XOnly32;

/** @brief Public nonce together with its experimental BPPP statement proof and raw nonce point. */
struct NonceProof {
    // Version 3 commits raw circuit coordinates before deriving fold weights.
    static constexpr unsigned char kSerializationVersion = 3;
    static constexpr std::size_t kInnerProofSize = 844;
    static constexpr std::size_t kSerializedSize = 228 + kInnerProofSize;

    Nonce nonce;
    bppp::PointBytes commitment_point{};
    bppp::ExperimentalCircuitZkNormArgProof proof;

    [[nodiscard]] Result<Bytes> serialize(purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<NonceProof> deserialize(std::span<const unsigned char> serialized,
                                                        purify_secp_context* secp_context);
};

/** @brief Standard signature bundled with the public BPPP nonce proof it relied on. */
struct ProvenSignature {
    static constexpr unsigned char kSerializationVersion = 2;
    static constexpr std::size_t kSerializedSize =
        1 + NonceProof::kSerializedSize + Signature::kSerializedSize;

    Signature signature;
    NonceProof nonce_proof;

    [[nodiscard]] Result<Bytes> serialize(purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<ProvenSignature> deserialize(std::span<const unsigned char> serialized,
                                                             purify_secp_context* secp_context);
};

/** @brief Selects the experimental BPPP proof system for the shared PureSign layer. */
struct Backend {
    using NonceProof = puresign_plusplus::NonceProof;
    using ProvenSignature = puresign_plusplus::ProvenSignature;
    using ProofCache = bppp::ExperimentalCircuitCache;
    using CircuitCache = bppp::ExperimentalCircuitBackend;

    /** The proof commits to the full nonce point in `NonceProof::commitment_point`. */
    static constexpr bool kProofBindsRawPoint = true;

    struct Ops;
};

/** @brief Purify and BIP340 public keys, with BPPP `proof(R)` verification. */
using PublicKey = puresign_core::PublicKey<Backend>;
/** @brief Cacheable message-bound nonce-proof template for the BPPP backend. */
using MessageProofCache = puresign_core::MessageProofCache<Backend>;
/** @brief Cacheable topic-bound nonce-proof template for the BPPP backend. */
using TopicProofCache = puresign_core::TopicProofCache<Backend>;
/** @brief Move-only prepared nonce bundled with its BPPP `proof(R)`. */
using PreparedNonceWithProof = puresign_core::PreparedNonceWithProof<Backend>;
/** @brief Move-only signer producing BPPP-backed `proof(R)` artifacts. */
using KeyPair = puresign_core::KeyPair<Backend>;

}  // namespace purify::puresign_plusplus
