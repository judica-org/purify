// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/accountable.hpp
 * @brief Experimental public transcripts for scalar-only accountable signatures.
 */

#pragma once

#include <array>
#include <span>

#include "purify/numeric.hpp"

namespace purify::accountable {

/**
 * @brief Public context shared by conflicting statements in one slashable slot.
 *
 * The caller authenticates the key and ordered Purify host/roster commitment
 * against its registry. The signing key is the even-Y x-only representation.
 * The slot is a canonical, nonempty application encoding and must outlive uses
 * of this view. Proof artifacts and local session identifiers are excluded.
 */
struct ConflictContext {
    std::array<unsigned char, 32> signing_key{};
    std::array<unsigned char, 32> host_commitment{};
    std::span<const unsigned char> slot;
};

/** @brief Canonical 32-byte scalar response; carries no nonce or proof. */
class ScalarSignature {
public:
    /** @brief Parse exactly 32 big-endian bytes below the group order, including zero. */
    [[nodiscard]] static Result<ScalarSignature> deserialize(std::span<const unsigned char> bytes);

    /** @brief Return the complete scalar-only wire representation. */
    [[nodiscard]] std::array<unsigned char, 32> serialize() const { return scalar_.to_bytes_be(); }

private:
    explicit ScalarSignature(FieldElement scalar) : scalar_(scalar) {}
    FieldElement scalar_;
};

/**
 * @brief Derive the candidate deterministic Purify input from the registered slot.
 *
 * This input binds the signing key, host/roster commitment, and slot. It contains
 * neither the decision body nor a nonce, proof, batch, or signing-attempt ID.
 */
[[nodiscard]] Result<std::array<unsigned char, 32>> nonce_evaluation_input(
    const ConflictContext& context, purify_secp_context* secp_context);

/**
 * @brief Compute the versioned Q/U/T/body challenge, without a nonce point.
 *
 * The SHA-256 digest is reduced modulo the secp256k1 group order. A zero result
 * rejects this statement; callers must not retry by changing its slot.
 */
[[nodiscard]] Result<FieldElement> signature_challenge(
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    purify_secp_context* secp_context);

/**
 * @brief Reconstruct the full nonce point as sigma*G - e*Q, rejecting infinity.
 *
 * This is NOT signature verification. A reviewed nonce proof must accept this
 * exact compressed point and authenticated context before an endorsement counts.
 * The nonce proof transcript must bind the point even though the challenge omits it.
 */
[[nodiscard]] Result<std::array<unsigned char, 33>> reconstruct_nonce(
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    const ScalarSignature& signature, purify_secp_context* secp_context);

} // namespace purify::accountable
