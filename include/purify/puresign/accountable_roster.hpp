// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <span>
#include <utility>
#include <vector>

#include "purify/numeric.hpp"

namespace purify::puresign_plusplus {
struct PublicKey;
}

namespace purify::accountable {

/**
 * Digest of the immutable coalition core and pre-proof setup context.
 *
 * Applications must define a canonical, domain-separated preimage containing
 * every setup field not bound separately by this library. The preimage must
 * exclude this proof and any receipt containing it, which would be circular.
 */
using CoalitionCoreDigest = std::array<unsigned char, 32>;
/** Digest of the immutable ordered Purify nonce-host registration. */
using NonceHostCommitment = std::array<unsigned char, 32>;

class SigningRoster;
class NonceHostBoundSigningRoster;

/** Validate and bind one ordered nonce-host list to a coalition core. */
[[nodiscard]] Result<NonceHostBoundSigningRoster> bind_nonce_hosts(
    SigningRoster roster, const CoalitionCoreDigest& coalition_core_digest,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context);

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

/**
 * @brief An ordered signing roster bound to one core and nonce-host list.
 *
 * The capability records the exact host commitment and coalition core.
 * `bind_nonce_hosts` validates the presented host bundles while response
 * verification recomputes their commitment. This type does not establish
 * member consent or application authorization.
 */
class NonceHostBoundSigningRoster {
public:
    [[nodiscard]] std::span<const SigningRosterMember> members() const {
        return roster_.members();
    }
    [[nodiscard]] const std::array<unsigned char, 32>& signing_key() const {
        return roster_.signing_key();
    }
    [[nodiscard]] const std::array<unsigned char, 32>& key_list_hash() const {
        return roster_.key_list_hash();
    }
    [[nodiscard]] bool aggregate_was_negated() const {
        return roster_.aggregate_was_negated();
    }
    [[nodiscard]] const CoalitionCoreDigest& coalition_core_digest() const {
        return coalition_core_digest_;
    }
    [[nodiscard]] const NonceHostCommitment& nonce_host_commitment() const {
        return nonce_host_commitment_;
    }

private:
    NonceHostBoundSigningRoster(
        SigningRoster roster,
        CoalitionCoreDigest coalition_core_digest,
        NonceHostCommitment nonce_host_commitment)
        : roster_(std::move(roster)),
          coalition_core_digest_(coalition_core_digest),
          nonce_host_commitment_(nonce_host_commitment) {}

    SigningRoster roster_;
    CoalitionCoreDigest coalition_core_digest_{};
    NonceHostCommitment nonce_host_commitment_{};

    friend Result<NonceHostBoundSigningRoster> bind_nonce_hosts(
        SigningRoster, const CoalitionCoreDigest&,
        std::span<const puresign_plusplus::PublicKey>,
        purify_secp_context*);
};

} // namespace purify::accountable
