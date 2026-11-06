// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/accountable_responses.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "bppp_bridge.h"
#include "purify/secp_bridge.h"

namespace purify::accountable {
namespace {

std::array<unsigned char, 8> encode_u64(std::size_t value) {
    std::array<unsigned char, 8> out{};
    const auto encoded = static_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[out.size() - 1 - i] =
            static_cast<unsigned char>(encoded >> (8 * i));
    }
    return out;
}

template <typename Roster>
Result<NonceHostCommitment> compute_nonce_host_commitment(
    const Roster& roster,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "accountable:nonce_hosts_context"),
        "accountable:nonce_hosts_context");
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "accountable:nonce_hosts_empty");
    }
    if (ordered_hosts.size() != roster.members().size()) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "accountable:nonce_hosts_count");
    }
    if (!size_fits_u64(ordered_hosts.size())) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "accountable:nonce_hosts_count");
    }

    const auto count = encode_u64(ordered_hosts.size());
    std::size_t encoded_size = 0;
    if (!checked_mul_size(ordered_hosts.size(), 33 + 96, encoded_size) ||
        !checked_add_size(32 + 32 + count.size(), encoded_size,
                          encoded_size)) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "accountable:nonce_hosts_size");
    }
    Bytes preimage;
    preimage.reserve(encoded_size);
    preimage.insert(preimage.end(), roster.signing_key().begin(),
                    roster.signing_key().end());
    preimage.insert(preimage.end(), roster.key_list_hash().begin(),
                    roster.key_list_hash().end());
    preimage.insert(preimage.end(), count.begin(), count.end());

    for (std::size_t i = 0; i < ordered_hosts.size(); ++i) {
        const auto& member = roster.members()[i];
        const auto& host = ordered_hosts[i];
        if (member.public_key[0] != 0x02 ||
            !std::equal(host.bip340_pubkey.begin(),
                        host.bip340_pubkey.end(),
                        member.public_key.begin() + 1)) {
            return unexpected_error(ErrorCode::BindingMismatch,
                                    "accountable:nonce_host_member_key");
        }
        PURIFY_RETURN_IF_ERROR(validate_public_key(host.purify_pubkey),
                               "accountable:nonce_host_purify_key");
        if (purify_bip340_validate_xonly_pubkey(
                secp_context, host.bip340_pubkey.data()) == 0) {
            return unexpected_error(ErrorCode::RangeViolation,
                                    "accountable:nonce_host_signing_key");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (ordered_hosts[j].purify_pubkey == host.purify_pubkey) {
                return unexpected_error(ErrorCode::BindingMismatch,
                                        "accountable:duplicate_nonce_host");
            }
        }
        const auto encoded_host = host.serialize();
        preimage.insert(preimage.end(), member.public_key.begin(),
                        member.public_key.end());
        preimage.insert(preimage.end(), encoded_host.begin(),
                        encoded_host.end());
    }
    static const TaggedHash hash(
        "Purify/Accountable/NonceHostRoster/v1");
    return hash.digest(preimage);
}

Result<FieldElement> roster_challenge(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    purify_secp_context* secp_context) {
    if (context.signing_key != roster.signing_key() ||
        context.host_commitment != roster.nonce_host_commitment() ||
        context.coalition_core_digest != roster.coalition_core_digest() ||
        nonce_set.signing_key() != roster.signing_key() ||
        nonce_set.host_commitment() != roster.nonce_host_commitment() ||
        nonce_set.coalition_core_digest() !=
            roster.coalition_core_digest()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accountable:response_roster_binding");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& nonce_input,
        nonce_evaluation_input(context, secp_context),
        "accountable:response_nonce_input");
    if (nonce_input != nonce_set.nonce_input()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accountable:response_nonce_context");
    }
    return signature_challenge(context, canonical_body, secp_context);
}

Result<std::array<unsigned char, 33>> response_nonce(
    const std::array<unsigned char, 33>& key,
    const FieldElement& weighted_challenge,
    const ScalarSignature& response,
    purify_secp_context* secp_context) {
    const auto negative_weight = weighted_challenge.negate().to_bytes_be();
    std::array<unsigned char, 33> key_term{};
    if (purify_point_scale(secp_context, key.data(),
                           negative_weight.data(), key_term.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "accountable:response_key_term");
    }
    const auto scalar = response.serialize();
    std::array<unsigned char, 33> nonce{};
    if (purify_bppp_offset_commitment(
            secp_context, key_term.data(), scalar.data(),
            nonce.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "accountable:response_nonce_at_infinity");
    }
    return nonce;
}

Status check_partial(
    const SigningRosterMember& member,
    const std::array<unsigned char, 33>& verified_nonce,
    const FieldElement& challenge, const PartialResponse& partial,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& nonce,
        response_nonce(member.public_key,
                       challenge * member.coefficient,
                       partial.response, secp_context),
        "accountable:partial_nonce");
    if (nonce != verified_nonce) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "accountable:partial_response_equation");
    }
    return {};
}

} // namespace

Result<NonceHostCommitment> nonce_host_commitment(
    const SigningRoster& roster,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context) {
    return compute_nonce_host_commitment(roster, ordered_hosts,
                                         secp_context);
}

Result<NonceHostCommitment> nonce_host_commitment(
    const NonceHostBoundSigningRoster& roster,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context) {
    return compute_nonce_host_commitment(roster, ordered_hosts,
                                         secp_context);
}

Result<NonceHostBoundSigningRoster> bind_nonce_hosts(
    SigningRoster roster,
    const CoalitionCoreDigest& coalition_core_digest,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& commitment,
        nonce_host_commitment(roster, ordered_hosts, secp_context),
        "accountable:bind_nonce_hosts");
    return NonceHostBoundSigningRoster(
        std::move(roster), coalition_core_digest, commitment);
}

Result<VerifiedCoalitionNonceSet> verify_coalition_nonce_set(
    const NonceHostBoundSigningRoster& roster,
    const ConflictContext& context,
    std::span<const puresign_plusplus::PublicKey> ordered_hosts,
    std::span<const puresign_plusplus::NonceProof> ordered_proofs,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    if (ordered_proofs.size() != ordered_hosts.size() ||
        ordered_hosts.size() != roster.members().size()) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "accountable:nonce_proof_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& registered_hosts,
        nonce_host_commitment(roster, ordered_hosts, secp_context),
        "accountable:nonce_host_commitment");
    if (registered_hosts != roster.nonce_host_commitment() ||
        context.host_commitment != registered_hosts ||
        context.signing_key != roster.signing_key() ||
        context.coalition_core_digest != roster.coalition_core_digest()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accountable:nonce_roster_binding");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& nonce_input,
        nonce_evaluation_input(context, secp_context),
        "accountable:nonce_input");
    PURIFY_ASSIGN_OR_RETURN(
        auto proof_cache,
        puresign_plusplus::TopicProofCache::build(nonce_input),
        "accountable:nonce_proof_cache");

    std::vector<VerifiedCoalitionNonceSet::Point> member_nonces;
    member_nonces.reserve(ordered_proofs.size());
    std::optional<VerifiedCoalitionNonceSet::Point> aggregate;
    for (std::size_t i = 0; i < ordered_proofs.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto& accepted,
            ordered_hosts[i].verify_topic_nonce_proof(
                proof_cache, ordered_proofs[i], secp_context, cache),
            "accountable:nonce_proof");
        if (!accepted) {
            return unexpected_error(ErrorCode::EquationMismatch,
                                    "accountable:nonce_proof");
        }
        const auto point = ordered_proofs[i].commitment_point;
        member_nonces.push_back(point);
        if (!aggregate) {
            aggregate = point;
        } else if ((*aggregate)[0] != point[0] &&
                   std::equal(aggregate->begin() + 1, aggregate->end(),
                              point.begin() + 1)) {
            // Exact opposite points cancel. A later member may make the final
            // aggregate finite again.
            aggregate.reset();
        } else {
            VerifiedCoalitionNonceSet::Point next{};
            if (purify_point_add(secp_context, aggregate->data(),
                                 point.data(), next.data()) == 0) {
                return unexpected_error(ErrorCode::InternalMismatch,
                                        "accountable:aggregate_nonce_sum");
            }
            aggregate = next;
        }
    }
    if (!aggregate) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "accountable:aggregate_nonce_infinity");
    }
    return VerifiedCoalitionNonceSet(
        std::move(member_nonces), *aggregate, roster.signing_key(),
        registered_hosts, roster.coalition_core_digest(), nonce_input);
}

Status verify_partial_response(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    std::size_t member_index, const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const PartialResponse& partial,
    purify_secp_context* secp_context) {
    if (member_index >= roster.members().size() ||
        member_index >= nonce_set.member_nonces_.size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "accountable:response_member_index");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& challenge,
        roster_challenge(roster, nonce_set, context, canonical_body,
                         secp_context),
        "accountable:partial_challenge");
    return check_partial(roster.members()[member_index],
                         nonce_set.member_nonces_[member_index], challenge,
                         partial, secp_context);
}

Result<VerifiedScalarResponse> verify_scalar_response(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const ScalarSignature& response,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        roster_challenge(roster, nonce_set, context, canonical_body,
                         secp_context),
        "accountable:scalar_response_context");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& reconstructed,
        reconstruct_nonce(context, canonical_body, response, secp_context),
        "accountable:scalar_response_nonce");
    if (reconstructed != nonce_set.aggregate_nonce_) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "accountable:scalar_response_nonce");
    }
    return VerifiedScalarResponse(
        response, reconstructed, roster.signing_key(),
        roster.nonce_host_commitment(), roster.coalition_core_digest(),
        Bytes(context.slot.begin(), context.slot.end()),
        Bytes(canonical_body.begin(), canonical_body.end()));
}

Result<VerifiedScalarResponse> aggregate_responses(
    const NonceHostBoundSigningRoster& roster,
    const VerifiedCoalitionNonceSet& nonce_set,
    const ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    std::span<const PartialResponse> partials,
    purify_secp_context* secp_context) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "accountable:empty_response_roster");
    }
    if (partials.size() != roster.members().size() ||
        partials.size() != nonce_set.member_nonces_.size()) {
        return unexpected_error(ErrorCode::SizeMismatch,
                                "accountable:response_member_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& challenge,
        roster_challenge(roster, nonce_set, context, canonical_body,
                         secp_context),
        "accountable:aggregate_challenge");
    auto sum = FieldElement::zero();
    for (std::size_t i = 0; i < partials.size(); ++i) {
        PURIFY_RETURN_IF_ERROR(
            check_partial(roster.members()[i], nonce_set.member_nonces_[i],
                          challenge, partials[i], secp_context),
            "accountable:aggregate_partial");
        sum = sum + FieldElement::from_bytes32(
                        partials[i].response.serialize());
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& response,
        ScalarSignature::deserialize(sum.to_bytes_be()),
        "accountable:aggregate_response");
    return verify_scalar_response(roster, nonce_set, context,
                                  canonical_body, response, secp_context);
}

Result<ExposedCoalitionKey> recover_verified_same_slot_key(
    const VerifiedScalarResponse& first,
    const VerifiedScalarResponse& second,
    purify_secp_context* secp_context) {
    if (first.signing_key_ != second.signing_key_ ||
        first.host_commitment_ != second.host_commitment_ ||
        first.coalition_core_digest_ != second.coalition_core_digest_ ||
        first.slot_ != second.slot_ || first.nonce_ != second.nonce_) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accountable:verified_conflict_binding");
    }
    if (first.body_ == second.body_) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "accountable:verified_conflict_body");
    }
    const ConflictContext context{
        first.signing_key_, first.host_commitment_,
        first.coalition_core_digest_, first.slot_};
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recovered,
        recover_same_slot_key(context, first.body_, first.response_,
                              second.body_, second.response_, secp_context),
        "accountable:verified_conflict_recover");
    return ExposedCoalitionKey(
        FieldElement::from_bytes32(recovered), first.signing_key_,
        first.host_commitment_, first.coalition_core_digest_);
}

} // namespace purify::accountable
