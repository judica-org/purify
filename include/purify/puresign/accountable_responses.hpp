// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/accountable.hpp"
#include "purify/puresign/accountable_roster.hpp"

namespace purify::accountable {

/** @brief Public session contribution; the raw full nonce is not normalized. */
struct PartialResponse {
    std::array<unsigned char, 33> nonce;
    ScalarSignature response;
};

/**
 * @brief Check sigma_i*G = R_i + e*b_i*P_i for one ordered roster member.
 *
 * This checks public algebra only. It does not establish the Purify relation,
 * member consent, authenticated hosts, or certificate validity. The effective
 * coefficient b_i already includes aggregate-key parity; raw R_i retains its
 * original sign. Context.Q must equal the roster's even-Y aggregate key.
 */
[[nodiscard]] Status verify_partial_response(
    const SigningRoster& roster, std::size_t member_index,
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    const PartialResponse& partial, purify_secp_context* secp_context);

/**
 * @brief Check all ordered partial equations and sum their scalar responses.
 *
 * Exactly one contribution per roster member is required. Computes the common
 * challenge once and rejects a final nonce at infinity. The returned scalar
 * is not a verified signature: the caller still needs the reviewed nonce proof
 * and application authorization/conflict checks before accepting a certificate.
 */
[[nodiscard]] Result<ScalarSignature> aggregate_responses(
    const SigningRoster& roster, const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    std::span<const PartialResponse> partials, purify_secp_context* secp_context);

} // namespace purify::accountable
