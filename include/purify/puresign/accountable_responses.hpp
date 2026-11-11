// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <span>
#include <utility>
#include <vector>

#include "purify/puresign/accountable.hpp"
#include "purify/puresign/accountable_roster.hpp"
#include "purify/puresign/bppp.hpp"

namespace purify::accountable {

/** Scalar-only public response for one ordered coalition member. */
struct PartialResponse {
    ScalarSignature response;
};

class VerifiedCoalitionNonceSet;
class VerifiedScalarResponse;
class ExposedCoalitionKey;

/** Hash the exact ordered signing roster and registered PureSign++ hosts. */
[[nodiscard]] Result<NonceHostCommitment> nonce_host_commitment(
    const SigningRoster& roster,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context);

[[nodiscard]] Result<NonceHostCommitment> nonce_host_commitment(
    const NonceHostBoundSigningRoster& roster,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context);

/** Proof-attested deterministic full nonces for every ordered member. */
class VerifiedCoalitionNonceSet {
public:
    using Point = std::array<unsigned char, 33>;

    [[nodiscard]] std::span<const Point> member_nonces() const {
        return member_nonces_;
    }
    [[nodiscard]] const Point& aggregate_nonce() const {
        return aggregate_nonce_;
    }
    [[nodiscard]] const std::array<unsigned char, 32>& signing_key() const {
        return signing_key_;
    }
    [[nodiscard]] const NonceHostCommitment& host_commitment() const {
        return host_commitment_;
    }
    [[nodiscard]] const CoalitionCoreDigest& coalition_core_digest() const {
        return coalition_core_digest_;
    }
    [[nodiscard]] const std::array<unsigned char, 32>& nonce_input() const {
        return nonce_input_;
    }

private:
    VerifiedCoalitionNonceSet(
        std::vector<Point> member_nonces, Point aggregate_nonce,
        std::array<unsigned char, 32> signing_key,
        NonceHostCommitment host_commitment,
        CoalitionCoreDigest coalition_core_digest,
        std::array<unsigned char, 32> nonce_input)
        : member_nonces_(std::move(member_nonces)),
          aggregate_nonce_(aggregate_nonce), signing_key_(signing_key),
          host_commitment_(host_commitment),
          coalition_core_digest_(coalition_core_digest),
          nonce_input_(nonce_input) {}

    std::vector<Point> member_nonces_;
    Point aggregate_nonce_{};
    std::array<unsigned char, 32> signing_key_{};
    NonceHostCommitment host_commitment_{};
    CoalitionCoreDigest coalition_core_digest_{};
    std::array<unsigned char, 32> nonce_input_{};

    friend Result<VerifiedCoalitionNonceSet> verify_coalition_nonce_set(
        const NonceHostBoundSigningRoster&, const ConflictContext&,
        std::span<const puresign_plusplus::PublicKey>,
        std::span<const puresign_plusplus::NonceProof>,
        purify_secp_context*, bppp::ExperimentalCircuitBackend*);
    friend Status verify_partial_response(
        const NonceHostBoundSigningRoster&,
        const VerifiedCoalitionNonceSet&,
        std::size_t, const ConflictContext&,
        std::span<const unsigned char>, const PartialResponse&,
        purify_secp_context*);
    friend Result<VerifiedScalarResponse> aggregate_responses(
        const NonceHostBoundSigningRoster&,
        const VerifiedCoalitionNonceSet&,
        const ConflictContext&, std::span<const unsigned char>,
        std::span<const PartialResponse>, purify_secp_context*);
    friend Result<VerifiedScalarResponse> verify_scalar_response(
        const NonceHostBoundSigningRoster&,
        const VerifiedCoalitionNonceSet&,
        const ConflictContext&, std::span<const unsigned char>,
        const ScalarSignature&, purify_secp_context*);
};

/** Accepted scalar response bound to one exact proof-attested raw nonce. */
class VerifiedScalarResponse {
public:
    [[nodiscard]] const ScalarSignature& response() const {
        return response_;
    }

private:
    VerifiedScalarResponse(
        ScalarSignature response, std::array<unsigned char, 33> nonce,
        std::array<unsigned char, 32> signing_key,
        NonceHostCommitment host_commitment,
        CoalitionCoreDigest coalition_core_digest, Bytes slot, Bytes body)
        : response_(response), nonce_(nonce), signing_key_(signing_key),
          host_commitment_(host_commitment),
          coalition_core_digest_(coalition_core_digest),
          slot_(std::move(slot)), body_(std::move(body)) {}

    ScalarSignature response_;
    std::array<unsigned char, 33> nonce_{};
    std::array<unsigned char, 32> signing_key_{};
    NonceHostCommitment host_commitment_{};
    CoalitionCoreDigest coalition_core_digest_{};
    Bytes slot_;
    Bytes body_;

    friend Result<VerifiedScalarResponse> aggregate_responses(
        const NonceHostBoundSigningRoster&,
        const VerifiedCoalitionNonceSet&,
        const ConflictContext&, std::span<const unsigned char>,
        std::span<const PartialResponse>, purify_secp_context*);
    friend Result<VerifiedScalarResponse> verify_scalar_response(
        const NonceHostBoundSigningRoster&,
        const VerifiedCoalitionNonceSet&,
        const ConflictContext&, std::span<const unsigned char>,
        const ScalarSignature&, purify_secp_context*);
    friend Result<ExposedCoalitionKey> recover_verified_same_slot_key(
        const VerifiedScalarResponse&, const VerifiedScalarResponse&,
        purify_secp_context*);
};

/** Exact aggregate signing key exposed by two accepted conflicts. */
class ExposedCoalitionKey {
public:
    [[nodiscard]] const FieldElement& scalar() const { return scalar_; }
    [[nodiscard]] const std::array<unsigned char, 32>& signing_key() const {
        return signing_key_;
    }
    [[nodiscard]] const NonceHostCommitment& host_commitment() const {
        return host_commitment_;
    }
    [[nodiscard]] const CoalitionCoreDigest& coalition_core_digest() const {
        return coalition_core_digest_;
    }

private:
    ExposedCoalitionKey(
        FieldElement scalar, std::array<unsigned char, 32> signing_key,
        NonceHostCommitment host_commitment,
        CoalitionCoreDigest coalition_core_digest)
        : scalar_(scalar), signing_key_(signing_key),
          host_commitment_(host_commitment),
          coalition_core_digest_(coalition_core_digest) {}

    FieldElement scalar_;
    std::array<unsigned char, 32> signing_key_{};
    NonceHostCommitment host_commitment_{};
    CoalitionCoreDigest coalition_core_digest_{};

    friend Result<ExposedCoalitionKey> recover_verified_same_slot_key(
        const VerifiedScalarResponse&, const VerifiedScalarResponse&,
        purify_secp_context*);
};

[[nodiscard]] Result<VerifiedCoalitionNonceSet> verify_coalition_nonce_set(
    const NonceHostBoundSigningRoster& roster,
    const ConflictContext& context,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    std::span<const puresign_plusplus::NonceProof> ordered_proofs,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

[[nodiscard]] Status verify_partial_response(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set, std::size_t member_index,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const PartialResponse& partial, purify_secp_context* secp_context);

[[nodiscard]] Result<VerifiedScalarResponse> aggregate_responses(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    std::span<const PartialResponse> partials,
    purify_secp_context* secp_context);

[[nodiscard]] Result<VerifiedScalarResponse> verify_scalar_response(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const ScalarSignature& response, purify_secp_context* secp_context);

[[nodiscard]] Result<ExposedCoalitionKey> recover_verified_same_slot_key(
    const VerifiedScalarResponse& first,
    const VerifiedScalarResponse& second,
    purify_secp_context* secp_context);

} // namespace purify::accountable
