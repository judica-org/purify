// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable_roster.hpp"

#include <algorithm>
#include <optional>

#include "purify/curve.hpp"
#include "bppp_bridge.h"

namespace purify::accountable {

Result<SigningRoster> SigningRoster::aggregate(
    std::span<const std::array<unsigned char, 33>> ordered_public_keys,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "accountable:roster"),
                           "accountable:aggregate_roster");
    if (ordered_public_keys.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "accountable:empty_roster");
    }
    std::size_t encoded_size = 0;
    if (!size_fits_u32(ordered_public_keys.size()) ||
        !checked_mul_size(ordered_public_keys.size(), 33, encoded_size)) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:roster_size");
    }
    for (const auto& key : ordered_public_keys) {
        if ((key[0] != 0x02 && key[0] != 0x03) ||
            purify_bip340_validate_xonly_pubkey(secp_context, key.data() + 1) == 0) {
            return unexpected_error(ErrorCode::RangeViolation, "accountable:member_key");
        }
    }
    // Sorting a copy detects duplicates without changing the authenticated order.
    auto sorted = std::vector(ordered_public_keys.begin(), ordered_public_keys.end());
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
        return unexpected_error(ErrorCode::BindingMismatch, "accountable:duplicate_member_key");
    }

    Bytes encoded;
    encoded.reserve(encoded_size);
    for (const auto& key : ordered_public_keys) {
        encoded.insert(encoded.end(), key.begin(), key.end());
    }
    static const TaggedHash list_hash("KeyAgg list");
    static const TaggedHash coefficient_hash("KeyAgg coefficient");
    SigningRoster out;
    out.key_list_hash_ = list_hash.digest(encoded);
    out.members_.reserve(ordered_public_keys.size());
    std::optional<std::array<unsigned char, 33>> sum;
    for (std::size_t i = 0; i < ordered_public_keys.size(); ++i) {
        const auto& key = ordered_public_keys[i];
        // Duplicates are excluded, so index one is the second distinct key.
        auto coefficient = FieldElement::from_u64(1);
        if (i != 1) {
            const auto digest = coefficient_hash.digest_many<2>({out.key_list_hash_, key});
            purify_scalar raw;
            purify_scalar_set_b32(&raw, digest.data(), nullptr);
            coefficient = purify::detail::FieldElementAccess::from_raw(raw);
        }
        if (coefficient.is_zero()) {
            return unexpected_error(ErrorCode::RangeViolation, "accountable:zero_key_coefficient");
        }
        const auto scalar = coefficient.to_bytes_be();
        std::array<unsigned char, 33> term{};
        if (purify_point_scale(secp_context, key.data(), scalar.data(), term.data()) == 0) {
            return unexpected_error(ErrorCode::InternalMismatch, "accountable:weighted_member_key");
        }
        out.members_.push_back({key, coefficient});
        if (!sum) {
            sum = term;
        } else if ((*sum)[0] != term[0] && std::equal(sum->begin() + 1, sum->end(), term.begin() + 1)) {
            // Intermediate cancellation is valid; only the final sum must be nonzero.
            sum.reset();
        } else {
            std::array<unsigned char, 33> next{};
            if (purify_point_add(secp_context, sum->data(), term.data(), next.data()) == 0) {
                return unexpected_error(ErrorCode::InternalMismatch, "accountable:aggregate_key_sum");
            }
            sum = next;
        }
    }
    if (!sum) {
        return unexpected_error(ErrorCode::RangeViolation, "accountable:aggregate_key_at_infinity");
    }
    out.aggregate_was_negated_ = (*sum)[0] == 0x03;
    std::copy(sum->begin() + 1, sum->end(), out.signing_key_.begin());
    if (out.aggregate_was_negated_) {
        for (auto& member : out.members_) member.coefficient = member.coefficient.negate();
    }
    return out;
}

} // namespace purify::accountable
