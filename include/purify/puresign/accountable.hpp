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

/**
 * @brief Recover the exact signing scalar exposed by two same-slot responses.
 *
 * Both responses are interpreted under the one supplied Q/U/T context. Rejects
 * equal challenges, a recovered scalar whose full public point differs from
 * the even-Y signing key, and a common nonce at infinity. The result is derived
 * entirely from public input, so it is returned as ordinary scalar bytes.
 *
 * This is NOT certificate or conflict verification. Before using the result
 * for enforcement, the caller must validate both nonce proofs, authenticate
 * each endorsement's context, and establish the application conflict/liability
 * rules. Successful recovery alone does not authorize a penalty.
 */
[[nodiscard]] Result<std::array<unsigned char, 32>> recover_same_slot_key(
    const ConflictContext& context,
    std::span<const unsigned char> first_body, const ScalarSignature& first_signature,
    std::span<const unsigned char> second_body, const ScalarSignature& second_signature,
    purify_secp_context* secp_context);

} // namespace purify::accountable
