// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable.hpp"

#include <algorithm>

#include "purify/curve.hpp"
#include "bppp_bridge.h"

namespace purify::accountable {
namespace {

std::array<unsigned char, 8> encode_length(std::size_t size) {
    std::array<unsigned char, 8> out{};
    const auto value = static_cast<std::uint64_t>(size);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[out.size() - 1 - i] = static_cast<unsigned char>(value >> (8 * i));
    }
    return out;
}

Status validate_context(const ConflictContext& context, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "accountable:context"),
                           "accountable:validate_context");
    if (context.slot.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accountable:empty_slot");
    }
    if (!size_fits_u64(context.slot.size())) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:slot_length");
    }
    if (purify_bip340_validate_xonly_pubkey(secp_context, context.signing_key.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:signing_key");
    }
    return {};
}

} // namespace

Result<ScalarSignature> ScalarSignature::deserialize(std::span<const unsigned char> bytes) {
    if (bytes.size() != 32) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "accountable:scalar_size");
    }
    std::array<unsigned char, 32> encoded{};
    std::copy(bytes.begin(), bytes.end(), encoded.begin());
    PURIFY_ASSIGN_OR_RETURN(auto scalar, FieldElement::try_from_bytes32(encoded),
                            "accountable:scalar_encoding");
    return ScalarSignature(scalar);
}

Result<std::array<unsigned char, 32>> nonce_evaluation_input(
    const ConflictContext& context, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_context(context, secp_context), "accountable:nonce_input");
    static const TaggedHash hash("Purify/Accountable/Nonce/v1");
    const auto slot_length = encode_length(context.slot.size());
    return hash.digest_many<4>({context.signing_key, context.host_commitment,
                               slot_length, context.slot});
}

Result<FieldElement> signature_challenge(
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_context(context, secp_context), "accountable:challenge");
    if (!size_fits_u64(canonical_body.size())) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:body_length");
    }
    static const TaggedHash hash("Purify/Accountable/Challenge/v1");
    const auto slot_length = encode_length(context.slot.size());
    const auto body_length = encode_length(canonical_body.size());
    const auto digest = hash.digest_many<6>({context.signing_key, context.host_commitment,
                                           slot_length, context.slot, body_length, canonical_body});
    purify_scalar reduced;
    purify_scalar_set_b32(&reduced, digest.data(), nullptr);
    const auto challenge = purify::detail::FieldElementAccess::from_raw(reduced);
    if (challenge.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:zero_challenge");
    }
    return challenge;
}

Result<std::array<unsigned char, 33>> reconstruct_nonce(
    const ConflictContext& context, std::span<const unsigned char> canonical_body,
    const ScalarSignature& signature, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto challenge, signature_challenge(context, canonical_body, secp_context),
                            "accountable:reconstruct_nonce");
    std::array<unsigned char, 33> key{};
    key[0] = 0x02;
    std::copy(context.signing_key.begin(), context.signing_key.end(), key.begin() + 1);
    const auto negative_challenge = challenge.negate().to_bytes_be();
    std::array<unsigned char, 33> negative_key_term{};
    if (purify_point_scale(secp_context, key.data(), negative_challenge.data(),
                           negative_key_term.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "accountable:public_key_term");
    }
    const auto scalar = signature.serialize();
    std::array<unsigned char, 33> nonce{};
    if (purify_bppp_offset_commitment(secp_context, negative_key_term.data(), scalar.data(),
                                     nonce.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:nonce_at_infinity");
    }
    return nonce;
}

} // namespace purify::accountable
