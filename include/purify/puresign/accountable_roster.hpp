// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <span>
#include <vector>

#include "purify/numeric.hpp"

namespace purify::accountable {

/** @brief An ordered individual signing key and its normalized public weight. */
struct SigningRosterMember {
    std::array<unsigned char, 33> public_key;
    /** @brief BIP327 key coefficient multiplied by the aggregate parity sign. */
    FieldElement coefficient;
};

/**
 * @brief Experimental public key aggregation for one ordered coalition roster.
 *
 * This uses BIP327's untweaked KeyAgg calculation, with exact duplicate keys
 * and zero coefficients rejected as coalition enrollment policy. Individual
 * keys are compressed SEC1 points; the aggregate is normalized to even Y.
 * No nonce protocol, member consent, host association, or signature security
 * follows from constructing this object.
 */
class SigningRoster {
public:
    [[nodiscard]] static Result<SigningRoster> aggregate(
        std::span<const std::array<unsigned char, 33>> ordered_public_keys,
        purify_secp_context* secp_context);

    /** @brief Members in their original order; effective weights include parity. */
    [[nodiscard]] std::span<const SigningRosterMember> members() const { return members_; }

    /** @brief Canonical even-Y aggregate signing key for ConflictContext. */
    [[nodiscard]] const std::array<unsigned char, 32>& signing_key() const { return signing_key_; }

    /** @brief BIP327 key-list hash; this is NOT the authenticated Purify host commitment U. */
    [[nodiscard]] const std::array<unsigned char, 32>& key_list_hash() const { return key_list_hash_; }

    /** @brief Whether the unnormalized weighted sum had odd Y. */
    [[nodiscard]] bool aggregate_was_negated() const { return aggregate_was_negated_; }

private:
    SigningRoster() = default;

    std::vector<SigningRosterMember> members_;
    std::array<unsigned char, 32> signing_key_{};
    std::array<unsigned char, 32> key_list_hash_{};
    bool aggregate_was_negated_ = false;
};

} // namespace purify::accountable
