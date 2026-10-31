// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable_responses.hpp"

#include <algorithm>

#include "bppp_bridge.h"

namespace purify::accountable {
namespace {

Result<FieldElement> roster_challenge(
    const SigningRoster& roster, const ConflictContext& context,
    std::span<const unsigned char> canonical_body, purify_secp_context* secp_context) {
    if (context.signing_key != roster.signing_key()) {
        return unexpected_error(ErrorCode::BindingMismatch, "accountable:response_roster_key");
    }
    return signature_challenge(context, canonical_body, secp_context);
}

Result<std::array<unsigned char, 33>> response_nonce(
    const std::array<unsigned char, 33>& key, const FieldElement& weighted_challenge,
    const ScalarSignature& response, purify_secp_context* secp_context) {
    const auto negative_weight = weighted_challenge.negate().to_bytes_be();
    std::array<unsigned char, 33> key_term{};
    if (purify_point_scale(secp_context, key.data(), negative_weight.data(), key_term.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "accountable:response_key_term");
    }
    const auto scalar = response.serialize();
    std::array<unsigned char, 33> nonce{};
    if (purify_bppp_offset_commitment(secp_context, key_term.data(), scalar.data(), nonce.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:response_nonce_at_infinity");
    }
    return nonce;
}

Status check_partial(
    const SigningRosterMember& member, const FieldElement& challenge,
    const PartialResponse& partial, purify_secp_context* secp_context) {
    if ((partial.nonce[0] != 0x02 && partial.nonce[0] != 0x03) ||
        purify_bip340_validate_xonly_pubkey(secp_context, partial.nonce.data() + 1) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:partial_nonce_encoding");
    }
    PURIFY_ASSIGN_OR_RETURN(auto nonce, response_nonce(member.public_key, challenge * member.coefficient,
                                                       partial.response, secp_context),
                            "accountable:partial_nonce");
    if (nonce != partial.nonce) {
        return unexpected_error(ErrorCode::EquationMismatch, "accountable:partial_response_equation");
    }
    return {};
}

} // namespace

Status verify_partial_response(
    const SigningRoster& roster, std::size_t member_index,
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    const PartialResponse& partial, purify_secp_context* secp_context) {
    if (member_index >= roster.members().size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange, "accountable:response_member_index");
    }
    PURIFY_ASSIGN_OR_RETURN(auto challenge, roster_challenge(roster, context, canonical_body, secp_context),
                            "accountable:partial_challenge");
    return check_partial(roster.members()[member_index], challenge, partial, secp_context);
}

Result<ScalarSignature> aggregate_responses(
    const SigningRoster& roster, const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    std::span<const PartialResponse> partials, purify_secp_context* secp_context) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accountable:empty_response_roster");
    }
    if (partials.size() != roster.members().size()) {
        return unexpected_error(ErrorCode::SizeMismatch, "accountable:response_member_count");
    }
    PURIFY_ASSIGN_OR_RETURN(auto challenge, roster_challenge(roster, context, canonical_body, secp_context),
                            "accountable:aggregate_challenge");
    auto sum = FieldElement::from_u64(0);
    for (std::size_t i = 0; i < partials.size(); ++i) {
        PURIFY_RETURN_IF_ERROR(check_partial(roster.members()[i], challenge, partials[i], secp_context),
                               "accountable:aggregate_partial");
        sum = sum + FieldElement::from_bytes32(partials[i].response.serialize());
    }
    PURIFY_ASSIGN_OR_RETURN(auto response, ScalarSignature::deserialize(sum.to_bytes_be()),
                            "accountable:aggregate_response");
    std::array<unsigned char, 33> key{};
    key[0] = 0x02;
    std::copy(roster.signing_key().begin(), roster.signing_key().end(), key.begin() + 1);
    // The checked partial equations imply this is the sum of their raw nonces.
    // Reject its identity without a second challenge hash or nonce-point sum.
    PURIFY_ASSIGN_OR_RETURN(auto nonce, response_nonce(key, challenge, response, secp_context),
                            "accountable:aggregate_nonce");
    (void)nonce;
    return response;
}

} // namespace purify::accountable
