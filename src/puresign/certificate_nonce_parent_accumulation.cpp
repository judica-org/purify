// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/certificate_nonce_parent_accumulation.hpp"

#include "bppp_bridge.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace purify::puresign_plusplus {
namespace {

constexpr unsigned char kPublicInputVersion = 1;
constexpr unsigned char kTreeNodeVersion = 1;
constexpr std::size_t kRecursiveMemberMessageSize =
    8 + 4 + 32 + 96 + 32 + 32 + 33 + 33 + 32;
constexpr std::size_t kRecursiveStepMessageSize =
    32 + 32 + 4 + 32 + 32 + 32;
constexpr std::size_t kRecursiveManifestSeedMessageSize = 32 + 8;
constexpr std::size_t kRecursiveManifestStepMessageSize =
    32 + 8 + 4 + 32;
constexpr std::array<unsigned char, 16> kNativeReceiptMagic{
    'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
    'e', 'r', 't', 'W', 'i', 't', '/', '1'};
static_assert(CertificateNonceLeafAccumulator::kNormVectorLength ==
              4'096);
static_assert(
    CertificateNonceNativeReceipt::kReductionSerializedSize ==
    66 * 12 + 98);
static_assert(
    CertificateNonceNativeReceipt::kStepSerializedSize ==
    66 * 13 + 66);
static_assert(PublicKey::kSerializedSize == 96);
static_assert(bppp::PointBytes{}.size() == 33);
static_assert(bppp::accumulation::Digest{}.size() == 32);
static_assert(
    CertificateNonceLinearReceipt::kReductionSerializedSize ==
    66 * 12 + 98);
static_assert(
    CertificateNonceLinearReceipt::kStepSerializedSize ==
    66 * 13 + 66);
const TaggedHash kResponseStatementHash(
    "Purify/Accountable/CertificateNonceResponse/v1");
const TaggedHash kResponseAuthorizationHash(
    "Purify/Accountable/CertificateResponseAuthorization/v1");
const TaggedHash kResponseAuthorizationCommonHash(
    "Purify/Accountable/CertificateResponseCommon/v1");
const TaggedHash kResponseAuthorizationBindingHash(
    "Purify/Accountable/CertificateResponseBinding/v1");
const TaggedHash kMemberAuthorizationHash(
    "Purify/Accountable/CertificateMemberAuthorization/v1");
const TaggedHash kRecursiveMemberHash(
    "Purify/Accountable/CertificateRecursiveMember/v1");
const TaggedHash kRecursiveStepHash(
    "Purify/Accountable/CertificateRecursiveStep/v1");
const TaggedHash kRecursiveManifestSeedHash(
    "Purify/Accountable/CertificateRecursiveManifest/v1/init");
const TaggedHash kRecursiveManifestStepHash(
    "Purify/Accountable/CertificateRecursiveManifest/v1/member");
const TaggedHash kAuthorizationManifestSeedHash(
    "Purify/Accountable/CertificateAuthorizationManifest/v1/init");
const TaggedHash kAuthorizationManifestStepHash(
    "Purify/Accountable/CertificateAuthorizationManifest/v1/member");
const TaggedHash kTreeNodeHash(
    "Purify/Accountable/CertificateNonceTreeNode/v1");

template <std::size_t N>
void append(Bytes& out, const std::array<unsigned char, N>& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append(Bytes& out, std::span<const unsigned char> value) {
    out.insert(out.end(), value.begin(), value.end());
}

void append_u32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>(value >> 24));
    out.push_back(static_cast<unsigned char>(value >> 16));
    out.push_back(static_cast<unsigned char>(value >> 8));
    out.push_back(static_cast<unsigned char>(value));
}

void append_u64(Bytes& out, std::uint64_t value) {
    for (unsigned int shift = 56; shift != 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>(value >> shift));
    }
    out.push_back(static_cast<unsigned char>(value));
}

std::uint64_t read_u64(std::span<const unsigned char> encoded)
{
    assert(encoded.size() == sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const auto byte : encoded) {
        value = (value << 8) | byte;
    }
    return value;
}

bool is_zero(const bppp::accumulation::Digest& digest) {
    return std::ranges::all_of(
        digest, [](unsigned char byte) { return byte == 0; });
}

Status validate_recursive_member_frame(
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal)
{
    const auto& frame = authorization.frame();
    const auto member_digests = authorization.member_digests();
    if (frame.total_responses == 0 ||
        frame.total_responses >
            CertificateNonceParentAccumulator::kMaxResponses ||
        frame.response_ordinal >= frame.total_responses ||
        member_digests.empty() ||
        member_digests.size() >
            CertificateNonceParentPublicInputs::kMemberBatchCapacity ||
        member_ordinal >= member_digests.size()) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_recursive:member_frame");
    }
    return {};
}

Status validate_recursive_public_response(
    const CertificateNonceRecursiveResponseView& response)
{
    const auto hosts = response.ordered_hosts();
    const auto leaves = response.ordered_leaves();
    const auto member_digests =
        response.authorization().member_digests();
    if (hosts.empty() ||
        hosts.size() >
            CertificateNonceParentPublicInputs::kMemberBatchCapacity ||
        hosts.size() != leaves.size() ||
        hosts.size() != member_digests.size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_recursive:public_response_members");
    }

    std::set<bppp::accumulation::Digest> unique_leaf_bindings;
    for (const auto& leaf : leaves) {
        if (!unique_leaf_bindings.insert(leaf.leaf_binding).second) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_recursive:public_response_leaf");
        }
    }
    return validate_recursive_member_frame(
        response.authorization(), 0);
}

Result<bppp::accumulation::Digest>
recursive_member_digest_from_derived_constants(
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    std::span<const unsigned char> topic,
    const CertificateNonceLeafParentConstants& constants,
    const bppp::accumulation::Digest& leaf_binding)
{
    const auto& frame = authorization.frame();
    const auto member_digests = authorization.member_digests();
    const auto host_bytes = host.serialize();
    if (host_bytes.size() != PublicKey::kSerializedSize) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_recursive:member_host");
    }

    Bytes encoded;
    encoded.reserve(kRecursiveMemberMessageSize);
    append_u64(encoded, frame.response_ordinal);
    append_u32(encoded, member_ordinal);
    append(encoded, member_digests[member_ordinal]);
    append(encoded, host_bytes);
    append(encoded, topic);
    append(encoded, constants.circuit_binding_digest);
    append(encoded, constants.coefficient_commitment);
    append(encoded, constants.anchored_offset);
    append(encoded, leaf_binding);
    assert(encoded.size() == kRecursiveMemberMessageSize);
    return kRecursiveMemberHash.digest(encoded);
}

Result<bppp::accumulation::Digest>
recursive_member_digest_from_public_descriptor(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    const CertificateNoncePublicLeafDescriptor& descriptor,
    std::span<const unsigned char> topic,
    const TopicProofCache& cache,
    purify_secp_context* secp_context)
{
    PURIFY_ASSIGN_OR_RETURN(
        const auto constants,
        leaf_accumulator.derive_parent_constants_from_public_data(
            host, cache, descriptor.circuit_precommitment,
            descriptor.nonce_point, secp_context),
        "certificate_nonce_recursive:public_member_constants");
    return recursive_member_digest_from_derived_constants(
        authorization, member_ordinal, host, topic, constants,
        descriptor.leaf_binding);
}

Result<std::vector<bppp::accumulation::Digest>>
recursive_response_step_digests_from_validated(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceRecursiveResponseView& response,
    purify_secp_context* secp_context)
{
    const auto hosts = response.ordered_hosts();
    const auto leaves = response.ordered_leaves();
    PURIFY_ASSIGN_OR_RETURN(
        const auto topic,
        accountable::nonce_evaluation_input(
            response.context(), secp_context),
        "certificate_nonce_recursive:public_response_topic");
    PURIFY_ASSIGN_OR_RETURN(
        const auto cache, TopicProofCache::build(topic),
        "certificate_nonce_recursive:public_response_cache");

    std::vector<bppp::accumulation::Digest> step_digests;
    step_digests.reserve(hosts.size());
    for (std::size_t member_index = 0;
         member_index < hosts.size(); ++member_index) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto member_digest,
            recursive_member_digest_from_public_descriptor(
                leaf_accumulator, response.authorization(),
                static_cast<std::uint32_t>(member_index),
                hosts[member_index], leaves[member_index], topic,
                cache, secp_context),
            "certificate_nonce_recursive:public_response_member");
        PURIFY_ASSIGN_OR_RETURN(
            auto step_digest,
            certificate_nonce_recursive_step_digest(
                response.authorization(), response.context(),
                response.canonical_body(), response.response(),
                member_digest, secp_context),
            "certificate_nonce_recursive:public_response_step");
        step_digests.push_back(std::move(step_digest));
    }
    return step_digests;
}

Status validate_authorization_inputs(
    const CertificateNonceResponseFrame& frame,
    const accountable::NonceHostBoundSigningRoster& roster,
    const accountable::ConflictContext& context,
    std::span<const PublicKey> ordered_hosts,
    std::span<const unsigned char> canonical_body,
    purify_secp_context* secp_context)
{
    if (is_zero(frame.certificate_context_digest) ||
        frame.total_responses == 0 ||
        frame.total_responses >
            CertificateNonceParentAccumulator::kMaxResponses ||
        frame.response_ordinal >= frame.total_responses ||
        frame.electorate_weight == 0) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_authorization:frame");
    }
    if (frame.scope !=
        CertificateNonceParentScope::AccountableTopic) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_authorization:scope");
    }
    if (ordered_hosts.empty() ||
        ordered_hosts.size() >
            CertificateNonceParentPublicInputs::
                kMemberBatchCapacity ||
        roster.members().size() != ordered_hosts.size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_authorization:member_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto registered_hosts,
        accountable::nonce_host_commitment(
            roster, ordered_hosts, secp_context),
        "certificate_nonce_authorization:host_commitment");
    if (registered_hosts != roster.nonce_host_commitment() ||
        context.host_commitment != registered_hosts ||
        context.signing_key != roster.signing_key() ||
        context.coalition_core_digest !=
            roster.coalition_core_digest()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_authorization:roster");
    }
    if (!size_fits_u64(context.slot.size()) ||
        !size_fits_u64(canonical_body.size())) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_authorization:length");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto nonce_input,
        accountable::nonce_evaluation_input(context, secp_context),
        "certificate_nonce_authorization:nonce_input");
    PURIFY_ASSIGN_OR_RETURN(
        const auto challenge,
        accountable::signature_challenge(
            context, canonical_body, secp_context),
        "certificate_nonce_authorization:challenge");
    (void)nonce_input;
    (void)challenge;
    return {};
}

void append_authorization_prefix(
    Bytes& encoded, const CertificateNonceResponseFrame& frame,
    const accountable::NonceHostBoundSigningRoster& roster,
    const accountable::ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const accountable::ScalarSignature& response,
    std::size_t member_count)
{
    encoded.push_back(kPublicInputVersion);
    encoded.push_back(static_cast<unsigned char>(frame.scope));
    append_u32(
        encoded, static_cast<std::uint32_t>(
                     CertificateNonceParentPublicInputs::
                         kMemberBatchCapacity));
    append(encoded, frame.certificate_context_digest);
    append_u64(encoded, frame.total_responses);
    append_u64(encoded, frame.response_ordinal);
    append_u32(encoded, frame.electorate_index);
    append_u64(encoded, frame.electorate_weight);
    append(encoded, context.signing_key);
    append(encoded, context.host_commitment);
    append(encoded, context.coalition_core_digest);
    append_u64(encoded, static_cast<std::uint64_t>(context.slot.size()));
    append(encoded, context.slot);
    append_u64(
        encoded, static_cast<std::uint64_t>(canonical_body.size()));
    append(encoded, canonical_body);
    append(encoded, response.serialize());
    append(encoded, roster.key_list_hash());
    encoded.push_back(
        static_cast<unsigned char>(roster.aggregate_was_negated()));
    append_u32(encoded, static_cast<std::uint32_t>(member_count));
}

void append_authorization_member(
    Bytes& encoded, std::size_t index,
    const accountable::SigningRosterMember& member,
    const PublicKey& host)
{
    append_u32(encoded, static_cast<std::uint32_t>(index));
    append(encoded, member.public_key);
    append(encoded, member.coefficient.to_bytes_be());
    append(encoded, host.serialize());
}

Result<bppp::PointBytes> sum_nonces(
    std::span<const PreparedCertificateNonceLeaf> leaves,
    purify_secp_context* secp_context) {
    std::optional<bppp::PointBytes> aggregate;
    for (const auto& leaf : leaves) {
        const auto& point = leaf.nonce_point();
        if (!aggregate) {
            aggregate = point;
        } else if ((*aggregate)[0] != point[0] &&
                   std::equal(aggregate->begin() + 1, aggregate->end(),
                              point.begin() + 1)) {
            aggregate.reset();
        } else {
            bppp::PointBytes next{};
            if (purify_point_add(secp_context, aggregate->data(),
                                 point.data(), next.data()) == 0) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_parent:nonce_sum");
            }
            aggregate = next;
        }
    }
    if (!aggregate) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_parent:nonce_infinity");
    }
    return *aggregate;
}

Status match_inputs_and_leaves(
    const CertificateNonceParentPublicInputs& inputs,
    std::span<const PreparedCertificateNonceLeaf> leaves) {
    if (inputs.leaf_bindings().size() != leaves.size() ||
        inputs.member_nonces().size() != leaves.size() ||
        inputs.recursive_step_digests().size() != leaves.size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_parent:leaf_count");
    }
    for (std::size_t index = 0; index < leaves.size(); ++index) {
        if (inputs.leaf_bindings()[index] !=
                leaves[index].binding_digest() ||
            inputs.member_nonces()[index] !=
                leaves[index].nonce_point()) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_parent:leaf_order");
        }
    }
    return {};
}

struct ParentMetadata {
    bppp::accumulation::Digest certificate_context_digest{};
    bppp::accumulation::Digest node_digest{};
    std::uint64_t total_responses = 0;
    std::uint32_t level = 0;
    std::uint64_t first_response = 0;
    std::uint64_t response_count = 0;
};

Result<std::uint64_t> level_span(std::uint32_t level) {
    std::uint64_t span = 1;
    for (std::uint32_t index = 0; index < level; ++index) {
        if (span > std::numeric_limits<std::uint64_t>::max() /
                       CertificateNonceParentAccumulator::kTreeFanout) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_tree:level_span");
        }
        span *= CertificateNonceParentAccumulator::kTreeFanout;
    }
    return span;
}

Result<std::size_t> native_tree_proof_count(
    std::size_t response_count)
{
    if (response_count == 0 ||
        response_count >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_native:response_count");
    }
    std::size_t proof_count = 0;
    auto level_count = response_count;
    while (level_count > 1) {
        const auto parent_count =
            1 + (level_count - 1) /
                    CertificateNonceParentAccumulator::kTreeFanout;
        if (!checked_add_size(
                proof_count, parent_count, proof_count)) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_native:tree_count");
        }
        level_count = parent_count;
    }
    return proof_count;
}

Status validate_native_receipt_shape(
    const bppp::accumulation::Digest& context_digest,
    std::span<const CertificateNonceNativeResponse> responses,
    std::span<const CertificateNonceTreeProof> tree_proofs)
{
    if (is_zero(context_digest)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_native:context_digest");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto expected_tree_proofs,
        native_tree_proof_count(responses.size()),
        "certificate_nonce_native:tree_shape");
    if (tree_proofs.size() != expected_tree_proofs) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_native:tree_proofs");
    }
    for (const auto& response : responses) {
        if (is_zero(response.statement_digest()) ||
            response.proof().reductions.empty() ||
            response.proof().reductions.size() >
                CertificateNonceParentPublicInputs::
                    kMemberBatchCapacity) {
            return unexpected_error(
                ErrorCode::RangeViolation,
                "certificate_nonce_native:member_count");
        }
    }
    return {};
}

Status validate_linear_receipt_shape(
    const bppp::accumulation::Digest& context_digest,
    std::span<const CertificateNonceLinearResponseProof> responses)
{
    if (is_zero(context_digest) || responses.empty() ||
        responses.size() >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_linear:response_count");
    }
    for (const auto& response : responses) {
        if (response.members.empty() ||
            response.members.size() >
                CertificateNonceParentPublicInputs::
                    kMemberBatchCapacity) {
            return unexpected_error(
                ErrorCode::RangeViolation,
                "certificate_nonce_linear:member_count");
        }
    }
    return {};
}

Result<bppp::accumulation::Digest> validate_linear_public_inputs(
    std::span<const CertificateNonceResponseVerificationView>
        ordered_responses)
{
    if (ordered_responses.empty() ||
        ordered_responses.size() >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_linear:public_responses");
    }
    const auto context_digest = ordered_responses.front()
                                    .inputs()
                                    .frame()
                                    .certificate_context_digest;
    if (is_zero(context_digest)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_linear:context_digest");
    }
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        const auto& view = ordered_responses[index];
        const auto& frame = view.inputs().frame();
        if (frame.certificate_context_digest != context_digest ||
            frame.total_responses !=
                static_cast<std::uint64_t>(ordered_responses.size()) ||
            frame.response_ordinal !=
                static_cast<std::uint64_t>(index)) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_linear:response_frame");
        }
        PURIFY_RETURN_IF_ERROR(
            match_inputs_and_leaves(
                view.inputs(), view.ordered_leaves()),
            "certificate_nonce_linear:response_inputs");
    }
    return context_digest;
}

Result<ParentMetadata> parent_metadata(
    std::span<const PendingCertificateNonceParent> children) {
    if (children.empty() ||
        children.size() >
            CertificateNonceParentAccumulator::kTreeFanout) {
        return unexpected_error(
            ErrorCode::InvalidDimensions,
            "certificate_nonce_tree:child_count");
    }
    const auto& first = children.front();
    if (first.level() == std::numeric_limits<std::uint32_t>::max()) {
        return unexpected_error(
            ErrorCode::Overflow, "certificate_nonce_tree:level");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto child_span, level_span(first.level()),
        "certificate_nonce_tree:child_span");
    if (child_span > std::numeric_limits<std::uint64_t>::max() /
                         CertificateNonceParentAccumulator::kTreeFanout) {
        return unexpected_error(
            ErrorCode::Overflow, "certificate_nonce_tree:parent_span");
    }
    const auto parent_span =
        child_span * CertificateNonceParentAccumulator::kTreeFanout;
    if (first.first_response() % parent_span != 0 ||
        first.first_response() >= first.total_responses()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_tree:parent_alignment");
    }
    const auto available =
        first.total_responses() - first.first_response();
    const auto parent_count = std::min(parent_span, available);
    const auto expected_children =
        (parent_count + child_span - 1) / child_span;
    if (children.size() != expected_children) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_tree:framing");
    }
    if (children.size() == 1 && first.first_response() == 0 &&
        first.response_count() == first.total_responses()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_tree:redundant_root");
    }

    Bytes encoded;
    encoded.push_back(kTreeNodeVersion);
    append_u32(
        encoded,
        static_cast<std::uint32_t>(
            CertificateNonceParentAccumulator::kTreeFanout));
    append(encoded, first.certificate_context_digest());
    append_u64(encoded, first.total_responses());
    append_u32(encoded, first.level() + 1);
    append_u64(encoded, first.first_response());
    append_u64(encoded, parent_count);
    append_u32(encoded, static_cast<std::uint32_t>(children.size()));
    for (std::size_t index = 0; index < children.size(); ++index) {
        const auto& child = children[index];
        const auto expected_first =
            first.first_response() + index * child_span;
        const auto expected_count = std::min(
            child_span, first.total_responses() - expected_first);
        if (child.certificate_context_digest() !=
                first.certificate_context_digest() ||
            child.total_responses() != first.total_responses() ||
            child.level() != first.level() ||
            child.first_response() != expected_first ||
            child.response_count() != expected_count) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_tree:child_order");
        }
        append(encoded, child.node_digest());
    }
    return ParentMetadata{
        first.certificate_context_digest(),
        kTreeNodeHash.digest(encoded), first.total_responses(),
        first.level() + 1, first.first_response(), parent_count,
    };
}

} // namespace

Result<CertificateNonceResponseAuthorization>
CertificateNonceResponseAuthorization::create(
    CertificateNonceResponseFrame frame,
    const accountable::NonceHostBoundSigningRoster& roster,
    const accountable::ConflictContext& context,
    std::span<const PublicKey> ordered_hosts,
    std::span<const unsigned char> canonical_body,
    const accountable::ScalarSignature& response,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        validate_authorization_inputs(
            frame, roster, context, ordered_hosts, canonical_body,
            secp_context),
        "certificate_nonce_authorization:inputs");
    Bytes prefix;
    append_authorization_prefix(
        prefix, frame, roster, context, canonical_body, response,
        ordered_hosts.size());
    const auto common_digest =
        kResponseAuthorizationCommonHash.digest(prefix);

    Bytes encoded = prefix;
    for (std::size_t index = 0; index < ordered_hosts.size(); ++index) {
        append_authorization_member(
            encoded, index, roster.members()[index],
            ordered_hosts[index]);
    }
    const auto response_digest =
        kResponseAuthorizationHash.digest(encoded);

    Bytes binding_bytes;
    binding_bytes.reserve(common_digest.size() + response_digest.size());
    append(binding_bytes, common_digest);
    append(binding_bytes, response_digest);
    const auto response_binding =
        kResponseAuthorizationBindingHash.digest(binding_bytes);

    std::vector<bppp::accumulation::Digest> member_digests;
    member_digests.reserve(ordered_hosts.size());
    for (std::size_t index = 0; index < ordered_hosts.size(); ++index) {
        Bytes member_bytes;
        append(member_bytes, response_binding);
        append_u64(member_bytes, frame.response_ordinal);
        append_authorization_member(
            member_bytes, index, roster.members()[index],
            ordered_hosts[index]);
        member_digests.push_back(
            kMemberAuthorizationHash.digest(member_bytes));
    }
    return CertificateNonceResponseAuthorization(
        std::move(frame), common_digest, response_digest,
        response_binding, std::move(member_digests));
}

Result<bppp::accumulation::Digest>
certificate_nonce_recursive_member_digest(
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    const PreparedCertificateNonceLeaf& leaf,
    const accountable::ConflictContext& context,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        validate_recursive_member_frame(
            authorization, member_ordinal),
        "certificate_nonce_recursive:member_frame");
    const auto purify_host = host.purify_pubkey.to_bytes_be();
    PURIFY_ASSIGN_OR_RETURN(
        const auto topic,
        accountable::nonce_evaluation_input(context, secp_context),
        "certificate_nonce_recursive:member_topic");
    if (leaf.nonce_host() != purify_host ||
        leaf.topic().size() != topic.size() ||
        !std::equal(
            leaf.topic().begin(), leaf.topic().end(), topic.begin())) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_recursive:member_binding");
    }
    return recursive_member_digest_from_derived_constants(
        authorization, member_ordinal, host, topic,
        leaf.parent_constants(), leaf.binding_digest());
}

Result<bppp::accumulation::Digest>
certificate_nonce_recursive_member_digest(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    const CertificateNoncePublicLeafDescriptor& descriptor,
    const accountable::ConflictContext& context,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        validate_recursive_member_frame(
            authorization, member_ordinal),
        "certificate_nonce_recursive:public_member_frame");
    PURIFY_ASSIGN_OR_RETURN(
        const auto topic,
        accountable::nonce_evaluation_input(context, secp_context),
        "certificate_nonce_recursive:public_member_topic");
    PURIFY_ASSIGN_OR_RETURN(
        const auto cache, TopicProofCache::build(topic),
        "certificate_nonce_recursive:public_member_cache");
    return recursive_member_digest_from_public_descriptor(
        leaf_accumulator, authorization, member_ordinal, host,
        descriptor, topic, cache, secp_context);
}

Result<bppp::accumulation::Digest>
certificate_nonce_recursive_step_digest(
    const CertificateNonceResponseAuthorization& authorization,
    const accountable::ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const accountable::ScalarSignature& response,
    const bppp::accumulation::Digest& member_digest,
    purify_secp_context* secp_context)
{
    const auto& frame = authorization.frame();
    const auto member_digests = authorization.member_digests();
    if (frame.total_responses == 0 ||
        frame.total_responses >
            CertificateNonceParentAccumulator::kMaxResponses ||
        frame.response_ordinal >= frame.total_responses ||
        member_digests.empty() ||
        member_digests.size() >
            CertificateNonceParentPublicInputs::kMemberBatchCapacity) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_recursive:step_frame");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto challenge,
        accountable::signature_challenge(
            context, canonical_body, secp_context),
        "certificate_nonce_recursive:step_challenge");
    const auto response_scalar = response.serialize();
    const auto challenge_scalar = challenge.to_bytes_be();

    Bytes encoded;
    encoded.reserve(kRecursiveStepMessageSize);
    append(encoded, member_digest);
    append(encoded, authorization.response_binding());
    append_u32(encoded, static_cast<std::uint32_t>(member_digests.size()));
    append(encoded, context.signing_key);
    append(encoded, response_scalar);
    append(encoded, challenge_scalar);
    assert(encoded.size() == kRecursiveStepMessageSize);
    return kRecursiveStepHash.digest(encoded);
}

Result<std::vector<bppp::accumulation::Digest>>
certificate_nonce_recursive_response_step_digests(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceRecursiveResponseView& response,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        validate_recursive_public_response(response),
        "certificate_nonce_recursive:public_response");
    return recursive_response_step_digests_from_validated(
        leaf_accumulator, response, secp_context);
}

Result<CertificateNonceRecursiveManifest>
certificate_nonce_recursive_manifest_seed(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses)
{
    if (is_zero(certificate_context_digest) || total_responses == 0 ||
        total_responses >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_recursive:manifest_seed");
    }
    Bytes encoded;
    encoded.reserve(kRecursiveManifestSeedMessageSize);
    append(encoded, certificate_context_digest);
    append_u64(encoded, total_responses);
    assert(encoded.size() == kRecursiveManifestSeedMessageSize);
    auto manifest = kRecursiveManifestSeedHash.digest(encoded);
    manifest[0] &= 0x7f;
    return CertificateNonceRecursiveManifest(manifest);
}

Result<CertificateNonceRecursiveManifest>
certificate_nonce_recursive_manifest_step(
    const CertificateNonceRecursiveManifest& prior,
    std::uint64_t response_ordinal, std::uint32_t member_ordinal,
    const bppp::accumulation::Digest& step_digest)
{
    if ((prior.bytes()[0] & 0x80) != 0 ||
        member_ordinal >=
            CertificateNonceParentPublicInputs::kMemberBatchCapacity) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_recursive:manifest_step");
    }
    Bytes encoded;
    encoded.reserve(kRecursiveManifestStepMessageSize);
    append(encoded, prior.bytes());
    append_u64(encoded, response_ordinal);
    append_u32(encoded, member_ordinal);
    append(encoded, step_digest);
    assert(encoded.size() == kRecursiveManifestStepMessageSize);
    auto manifest = kRecursiveManifestStepHash.digest(encoded);
    manifest[0] &= 0x7f;
    return CertificateNonceRecursiveManifest(manifest);
}

Result<CertificateNonceRecursiveManifestResolution>
certificate_nonce_recursive_manifest(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const bppp::accumulation::Digest& certificate_context_digest,
    std::span<const CertificateNonceRecursiveResponseView>
        ordered_responses,
    purify_secp_context* secp_context)
{
    if (!size_fits_u64(ordered_responses.size()) ||
        ordered_responses.empty() ||
        ordered_responses.size() >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_recursive:public_manifest_responses");
    }
    const auto total_responses =
        static_cast<std::uint64_t>(ordered_responses.size());
    std::size_t total_steps = 0;
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size(); ++response_index) {
        const auto& response = ordered_responses[response_index];
        const auto& frame = response.authorization().frame();
        if (frame.certificate_context_digest !=
                certificate_context_digest ||
            frame.total_responses != total_responses ||
            frame.response_ordinal !=
                static_cast<std::uint64_t>(response_index)) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_recursive:public_manifest_frame");
        }
        PURIFY_RETURN_IF_ERROR(
            validate_recursive_public_response(response),
            "certificate_nonce_recursive:public_manifest_response");
        const auto member_count = response.ordered_hosts().size();
        if (!checked_add_size(
                total_steps, member_count, total_steps)) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_recursive:public_manifest_steps");
        }
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto manifest,
        certificate_nonce_recursive_manifest_seed(
            certificate_context_digest, total_responses),
        "certificate_nonce_recursive:public_manifest_seed");

    std::vector<bppp::accumulation::Digest> step_digests;
    step_digests.reserve(total_steps);
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size(); ++response_index) {
        const auto& response = ordered_responses[response_index];
        const auto& frame = response.authorization().frame();
        PURIFY_ASSIGN_OR_RETURN(
            auto response_steps,
            recursive_response_step_digests_from_validated(
                leaf_accumulator, response, secp_context),
            "certificate_nonce_recursive:public_manifest_response");
        for (std::size_t member_index = 0;
             member_index < response_steps.size(); ++member_index) {
            PURIFY_ASSIGN_OR_RETURN(
                manifest,
                certificate_nonce_recursive_manifest_step(
                    manifest, frame.response_ordinal,
                    static_cast<std::uint32_t>(member_index),
                    response_steps[member_index]),
                "certificate_nonce_recursive:public_manifest_member");
            step_digests.push_back(
                std::move(response_steps[member_index]));
        }
    }
    return CertificateNonceRecursiveManifestResolution(
        certificate_context_digest, total_responses,
        std::move(step_digests), std::move(manifest));
}

Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest_seed(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses)
{
    if (is_zero(certificate_context_digest) || total_responses == 0 ||
        total_responses >
            CertificateNonceParentAccumulator::kMaxResponses) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_authorization:manifest_seed");
    }
    Bytes encoded;
    append(encoded, certificate_context_digest);
    append_u64(encoded, total_responses);
    auto manifest = kAuthorizationManifestSeedHash.digest(encoded);
    manifest[0] &= 0x7f;
    return manifest;
}

Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest_step(
    const CertificateNonceAuthorizationManifest& prior,
    std::uint64_t response_ordinal, std::uint32_t member_ordinal,
    const bppp::accumulation::Digest& member_digest)
{
    if ((prior[0] & 0x80) != 0 ||
        member_ordinal >=
            CertificateNonceParentPublicInputs::kMemberBatchCapacity) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_authorization:manifest_step");
    }
    Bytes encoded;
    append(encoded, prior);
    append_u64(encoded, response_ordinal);
    append_u32(encoded, member_ordinal);
    append(encoded, member_digest);
    auto manifest = kAuthorizationManifestStepHash.digest(encoded);
    manifest[0] &= 0x7f;
    return manifest;
}

Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses,
    std::span<const CertificateNonceResponseAuthorization> responses)
{
    if (!size_fits_u64(responses.size()) ||
        responses.size() != total_responses) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_authorization:manifest_responses");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto manifest,
        certificate_nonce_authorization_manifest_seed(
            certificate_context_digest, total_responses),
        "certificate_nonce_authorization:manifest_seed");
    for (std::size_t response_index = 0;
         response_index < responses.size(); ++response_index) {
        const auto& authorization = responses[response_index];
        const auto& frame = authorization.frame();
        if (frame.certificate_context_digest !=
                certificate_context_digest ||
            frame.total_responses != total_responses ||
            frame.response_ordinal != response_index) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_authorization:manifest_frame");
        }
        const auto member_digests = authorization.member_digests();
        for (std::size_t member_index = 0;
             member_index < member_digests.size(); ++member_index) {
            PURIFY_ASSIGN_OR_RETURN(
                manifest,
                certificate_nonce_authorization_manifest_step(
                    manifest, frame.response_ordinal,
                    static_cast<std::uint32_t>(member_index),
                    member_digests[member_index]),
                "certificate_nonce_authorization:manifest_member");
        }
    }
    return manifest;
}

Result<CertificateNonceNativeResponse>
CertificateNonceNativeResponse::create(
    bppp::accumulation::Digest statement_digest,
    CertificateNonceResponseProof proof)
{
    if (is_zero(statement_digest) || proof.reductions.empty() ||
        proof.reductions.size() >
            CertificateNonceParentPublicInputs::
                kMemberBatchCapacity) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_native:response_shape");
    }
    return CertificateNonceNativeResponse(
        statement_digest, std::move(proof));
}

Result<CertificateNonceNativeReceipt>
CertificateNonceNativeReceipt::create(
    bppp::accumulation::Digest certificate_context_digest,
    std::vector<CertificateNonceNativeResponse> responses,
    std::vector<CertificateNonceTreeProof> tree_proofs)
{
    PURIFY_RETURN_IF_ERROR(
        validate_native_receipt_shape(
            certificate_context_digest, responses, tree_proofs),
        "certificate_nonce_native:shape");
    return CertificateNonceNativeReceipt(
        certificate_context_digest, std::move(responses),
        std::move(tree_proofs));
}

Result<CertificateNonceLinearReceipt>
CertificateNonceLinearReceipt::create(
    bppp::accumulation::Digest certificate_context_digest,
    std::vector<CertificateNonceLinearResponseProof> responses)
{
    PURIFY_RETURN_IF_ERROR(
        validate_linear_receipt_shape(
            certificate_context_digest, responses),
        "certificate_nonce_linear:shape");
    return CertificateNonceLinearReceipt(
        certificate_context_digest, std::move(responses));
}

Result<std::size_t> certificate_nonce_native_receipt_size(
    std::span<const std::size_t> member_counts)
{
    PURIFY_ASSIGN_OR_RETURN(
        const auto tree_proofs,
        native_tree_proof_count(member_counts.size()),
        "certificate_nonce_native:size_tree");

    std::size_t encoded_size =
        CertificateNonceNativeReceipt::kHeaderSerializedSize;
    for (const auto member_count : member_counts) {
        if (member_count == 0 ||
            member_count >
                CertificateNonceParentPublicInputs::
                    kMemberBatchCapacity) {
            return unexpected_error(
                ErrorCode::RangeViolation,
                "certificate_nonce_native:size_members");
        }
        std::size_t reduction_size = 0;
        std::size_t response_size = 0;
        if (!checked_mul_size(
                member_count,
                CertificateNonceNativeReceipt::
                    kReductionSerializedSize,
                reduction_size) ||
            !checked_add_size(
                CertificateNonceNativeReceipt::
                    kResponseHeaderSerializedSize,
                reduction_size, response_size) ||
            !checked_add_size(
                response_size,
                CertificateNonceNativeReceipt::kStepSerializedSize,
                response_size) ||
            !checked_add_size(
                encoded_size, response_size, encoded_size)) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_native:size_responses");
        }
    }
    std::size_t tree_size = 0;
    if (!checked_mul_size(
            tree_proofs,
            CertificateNonceNativeReceipt::kStepSerializedSize,
            tree_size) ||
        !checked_add_size(encoded_size, tree_size, encoded_size)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_nonce_native:size_tree_proofs");
    }
    return encoded_size;
}

Result<Bytes> serialize_certificate_nonce_native_receipt(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceNativeReceipt& receipt,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context, "certificate_nonce_native:context"),
        "certificate_nonce_native:context");
    PURIFY_RETURN_IF_ERROR(
        validate_native_receipt_shape(
            receipt.certificate_context_digest(), receipt.responses(),
            receipt.tree_proofs()),
        "certificate_nonce_native:shape");

    std::vector<std::size_t> member_counts;
    member_counts.reserve(receipt.responses().size());
    for (const auto& response : receipt.responses()) {
        member_counts.push_back(response.proof().reductions.size());
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto expected_size,
        certificate_nonce_native_receipt_size(member_counts),
        "certificate_nonce_native:size");

    Bytes encoded;
    encoded.reserve(expected_size);
    append(encoded, kNativeReceiptMagic);
    append(encoded, accumulator.leaves().basis().digest());
    append(encoded, receipt.certificate_context_digest());
    append_u64(
        encoded,
        static_cast<std::uint64_t>(receipt.responses().size()));

    const auto& basis = accumulator.leaves().basis();
    for (const auto& response : receipt.responses()) {
        append(encoded, response.statement_digest());
        encoded.push_back(static_cast<unsigned char>(
            response.proof().reductions.size()));
        for (const auto& reduction : response.proof().reductions) {
            PURIFY_ASSIGN_OR_RETURN(
                auto proof,
                bppp::accumulation::
                    serialize_algebraic_norm_reduction(
                        basis, reduction, secp_context),
                "certificate_nonce_native:serialize_reduction");
            if (proof.size() !=
                CertificateNonceNativeReceipt::
                    kReductionSerializedSize) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_native:reduction_size");
            }
            append(encoded, proof);
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            bppp::accumulation::serialize_algebraic_step(
                basis, response.proof().accumulation,
                secp_context),
            "certificate_nonce_native:serialize_response_step");
        if (step.size() !=
            CertificateNonceNativeReceipt::kStepSerializedSize) {
            return unexpected_error(
                ErrorCode::InternalMismatch,
                "certificate_nonce_native:response_step_size");
        }
        append(encoded, step);
    }
    for (const auto& tree_proof : receipt.tree_proofs()) {
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            bppp::accumulation::serialize_algebraic_step(
                basis, tree_proof.accumulation, secp_context),
            "certificate_nonce_native:serialize_tree_step");
        if (step.size() !=
            CertificateNonceNativeReceipt::kStepSerializedSize) {
            return unexpected_error(
                ErrorCode::InternalMismatch,
                "certificate_nonce_native:tree_step_size");
        }
        append(encoded, step);
    }
    if (encoded.size() != expected_size) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_nonce_native:final_size");
    }
    return encoded;
}

Result<CertificateNonceNativeReceipt>
parse_certificate_nonce_native_receipt(
    const CertificateNonceParentAccumulator& accumulator,
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context)
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context, "certificate_nonce_native:context"),
        "certificate_nonce_native:context");
    if (encoded.size() <
        CertificateNonceNativeReceipt::kHeaderSerializedSize) {
        return unexpected_error(
            ErrorCode::InvalidFixedSize,
            "certificate_nonce_native:header");
    }
    if (!std::equal(
            kNativeReceiptMagic.begin(), kNativeReceiptMagic.end(),
            encoded.begin())) {
        return unexpected_error(
            ErrorCode::UnsupportedSymbol,
            "certificate_nonce_native:magic");
    }

    std::size_t offset = kNativeReceiptMagic.size();
    bppp::accumulation::Digest basis_digest{};
    std::copy_n(
        encoded.begin() + offset, basis_digest.size(),
        basis_digest.begin());
    offset += basis_digest.size();
    if (basis_digest != accumulator.leaves().basis().digest()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_native:basis_digest");
    }
    bppp::accumulation::Digest context_digest{};
    std::copy_n(
        encoded.begin() + offset, context_digest.size(),
        context_digest.begin());
    offset += context_digest.size();
    if (is_zero(context_digest)) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_native:context_digest");
    }
    const auto response_count_u64 = read_u64(
        encoded.subspan(offset, sizeof(std::uint64_t)));
    offset += sizeof(std::uint64_t);
    if (response_count_u64 == 0 ||
        response_count_u64 >
            CertificateNonceParentAccumulator::kMaxResponses ||
        response_count_u64 >
            std::numeric_limits<std::size_t>::max()) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_nonce_native:response_count");
    }
    const auto response_count =
        static_cast<std::size_t>(response_count_u64);
    constexpr std::size_t kMinimumResponseSize =
        CertificateNonceNativeReceipt::
            kResponseHeaderSerializedSize +
        CertificateNonceNativeReceipt::kReductionSerializedSize +
        CertificateNonceNativeReceipt::kStepSerializedSize;
    if (response_count >
        (encoded.size() - offset) / kMinimumResponseSize) {
        return unexpected_error(
            ErrorCode::InvalidFixedSize,
            "certificate_nonce_native:response_bytes");
    }

    const auto& basis = accumulator.leaves().basis();
    std::vector<CertificateNonceNativeResponse> responses;
    responses.reserve(response_count);
    std::vector<std::size_t> member_counts;
    member_counts.reserve(response_count);
    for (std::size_t response_index = 0;
         response_index < response_count; ++response_index) {
        if (encoded.size() - offset <
            CertificateNonceNativeReceipt::
                kResponseHeaderSerializedSize) {
            return unexpected_error(
                ErrorCode::InvalidFixedSize,
                "certificate_nonce_native:response_header");
        }
        bppp::accumulation::Digest statement_digest{};
        std::copy_n(
            encoded.begin() + offset, statement_digest.size(),
            statement_digest.begin());
        offset += statement_digest.size();
        const auto member_count = encoded[offset++];
        if (member_count == 0 ||
            member_count >
                CertificateNonceParentPublicInputs::
                    kMemberBatchCapacity) {
            return unexpected_error(
                ErrorCode::RangeViolation,
                "certificate_nonce_native:member_count");
        }
        CertificateNonceResponseProof response;
        response.reductions.reserve(member_count);
        for (std::size_t member_index = 0;
             member_index < member_count; ++member_index) {
            constexpr auto kSize = CertificateNonceNativeReceipt::
                kReductionSerializedSize;
            if (encoded.size() - offset < kSize) {
                return unexpected_error(
                    ErrorCode::InvalidFixedSize,
                    "certificate_nonce_native:reduction_bytes");
            }
            PURIFY_ASSIGN_OR_RETURN(
                auto reduction,
                bppp::accumulation::
                    parse_algebraic_norm_reduction(
                        basis, encoded.subspan(offset, kSize),
                        secp_context),
                "certificate_nonce_native:parse_reduction");
            offset += kSize;
            response.reductions.push_back(std::move(reduction));
        }
        constexpr auto kStepSize =
            CertificateNonceNativeReceipt::kStepSerializedSize;
        if (encoded.size() - offset < kStepSize) {
            return unexpected_error(
                ErrorCode::InvalidFixedSize,
                "certificate_nonce_native:response_step_bytes");
        }
        PURIFY_ASSIGN_OR_RETURN(
            response.accumulation,
            bppp::accumulation::parse_algebraic_step(
                basis, encoded.subspan(offset, kStepSize),
                secp_context),
            "certificate_nonce_native:parse_response_step");
        offset += kStepSize;
        member_counts.push_back(member_count);
        PURIFY_ASSIGN_OR_RETURN(
            auto native_response,
            CertificateNonceNativeResponse::create(
                statement_digest, std::move(response)),
            "certificate_nonce_native:response");
        responses.push_back(std::move(native_response));
    }

    PURIFY_ASSIGN_OR_RETURN(
        const auto tree_proof_count,
        native_tree_proof_count(response_count),
        "certificate_nonce_native:tree_count");
    std::size_t tree_bytes = 0;
    if (!checked_mul_size(
            tree_proof_count,
            CertificateNonceNativeReceipt::kStepSerializedSize,
            tree_bytes) ||
        encoded.size() - offset != tree_bytes) {
        return unexpected_error(
            ErrorCode::InvalidFixedSize,
            "certificate_nonce_native:tree_bytes");
    }
    std::vector<CertificateNonceTreeProof> tree_proofs;
    tree_proofs.reserve(tree_proof_count);
    for (std::size_t index = 0; index < tree_proof_count; ++index) {
        constexpr auto kStepSize =
            CertificateNonceNativeReceipt::kStepSerializedSize;
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            bppp::accumulation::parse_algebraic_step(
                basis, encoded.subspan(offset, kStepSize),
                secp_context),
            "certificate_nonce_native:parse_tree_step");
        offset += kStepSize;
        tree_proofs.push_back(
            CertificateNonceTreeProof{std::move(step)});
    }
    assert(offset == encoded.size());
    PURIFY_ASSIGN_OR_RETURN(
        const auto expected_size,
        certificate_nonce_native_receipt_size(member_counts),
        "certificate_nonce_native:parsed_size");
    if (expected_size != encoded.size()) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_nonce_native:parsed_size");
    }
    return CertificateNonceNativeReceipt::create(
        context_digest, std::move(responses),
        std::move(tree_proofs));
}

Result<CertificateNonceParentPublicInputs>
CertificateNonceParentPublicInputs::create(
    CertificateNonceResponseFrame frame,
    const accountable::NonceHostBoundSigningRoster& roster,
    const accountable::ConflictContext& context,
    std::span<const PublicKey> ordered_hosts,
    std::span<const unsigned char> canonical_body,
    const accountable::ScalarSignature& response,
    std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto authorization,
        CertificateNonceResponseAuthorization::create(
            frame, roster, context, ordered_hosts, canonical_body,
            response, secp_context),
        "certificate_nonce_parent:authorization");
    if (ordered_hosts.size() != ordered_leaves.size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_parent:member_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto nonce_input,
        accountable::nonce_evaluation_input(context, secp_context),
        "certificate_nonce_parent:topic");

    std::set<bppp::accumulation::Digest> unique_leaves;
    std::vector<bppp::accumulation::Digest> leaf_bindings;
    std::vector<bppp::PointBytes> member_nonces;
    leaf_bindings.reserve(ordered_leaves.size());
    member_nonces.reserve(ordered_leaves.size());
    for (std::size_t index = 0; index < ordered_leaves.size(); ++index) {
        const auto& leaf = ordered_leaves[index];
        const auto host = ordered_hosts[index].purify_pubkey.to_bytes_be();
        if (leaf.nonce_host() != host ||
            leaf.topic().size() != nonce_input.size() ||
            !std::equal(leaf.topic().begin(), leaf.topic().end(),
                        nonce_input.begin()) ||
            !unique_leaves.insert(leaf.binding_digest()).second) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_parent:leaf_binding");
        }
        leaf_bindings.push_back(leaf.binding_digest());
        member_nonces.push_back(leaf.nonce_point());
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto aggregate_nonce,
        sum_nonces(ordered_leaves, secp_context),
        "certificate_nonce_parent:aggregate_nonce");
    PURIFY_ASSIGN_OR_RETURN(
        const auto reconstructed,
        accountable::reconstruct_nonce(
            context, canonical_body, response, secp_context),
        "certificate_nonce_parent:response");
    if (aggregate_nonce != reconstructed) {
        return unexpected_error(
            ErrorCode::EquationMismatch,
            "certificate_nonce_parent:response_nonce");
    }

    std::vector<bppp::accumulation::Digest> recursive_step_digests;
    recursive_step_digests.reserve(ordered_leaves.size());
    for (std::size_t index = 0; index < ordered_leaves.size(); ++index) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto member_digest,
            certificate_nonce_recursive_member_digest(
                authorization, static_cast<std::uint32_t>(index),
                ordered_hosts[index], ordered_leaves[index], context,
                secp_context),
            "certificate_nonce_parent:recursive_member");
        PURIFY_ASSIGN_OR_RETURN(
            auto step_digest,
            certificate_nonce_recursive_step_digest(
                authorization, context, canonical_body, response,
                member_digest, secp_context),
            "certificate_nonce_parent:recursive_step");
        recursive_step_digests.push_back(std::move(step_digest));
    }

    Bytes encoded;
    append_authorization_prefix(
        encoded, frame, roster, context, canonical_body, response,
        ordered_leaves.size());
    for (std::size_t index = 0; index < ordered_leaves.size(); ++index) {
        const auto& member = roster.members()[index];
        append_authorization_member(
            encoded, index, member, ordered_hosts[index]);
        append(encoded, ordered_leaves[index].binding_digest());
        append(encoded, ordered_leaves[index].proof_digest());
        append(encoded,
               ordered_leaves[index].circuit_precommitment());
        append(encoded, ordered_leaves[index].nonce_point());
    }
    append(encoded, aggregate_nonce);
    const auto statement_digest = kResponseStatementHash.digest(encoded);
    return CertificateNonceParentPublicInputs(
        std::move(frame), std::move(encoded), statement_digest,
        std::move(authorization),
        aggregate_nonce, std::move(leaf_bindings),
        std::move(member_nonces),
        std::move(recursive_step_digests));
}

Result<CertificateNonceParentAccumulator>
CertificateNonceParentAccumulator::create(
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto leaves, CertificateNonceLeafAccumulator::create(secp_context),
        "certificate_nonce_parent:leaf_accumulator");
    return CertificateNonceParentAccumulator(std::move(leaves));
}

Result<CertificateNonceResponseProof>
CertificateNonceParentAccumulator::prove_response(
    const CertificateNonceParentPublicInputs& inputs,
    std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        match_inputs_and_leaves(inputs, ordered_leaves),
        "certificate_nonce_parent:inputs");
    CertificateNonceResponseProof proof;
    proof.reductions.reserve(ordered_leaves.size());
    std::vector<bppp::accumulation::PendingClaim> claims;
    claims.reserve(ordered_leaves.size());
    for (const auto& leaf : ordered_leaves) {
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction,
            bppp::accumulation::prove_algebraic_norm_reduction(
                leaves_.basis(), leaf.norm(), secp_context),
            "certificate_nonce_parent:prove_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto claim,
            bppp::accumulation::verify_algebraic_norm_reduction(
                leaves_.basis(), leaf.norm(), reduction, secp_context),
            "certificate_nonce_parent:verify_reduction");
        proof.reductions.push_back(std::move(reduction));
        claims.push_back(std::move(claim));
    }
    PURIFY_ASSIGN_OR_RETURN(
        proof.accumulation,
        bppp::accumulation::prove_bound_algebraic_step(
            leaves_.basis(), claims, inputs.statement_digest(),
            secp_context),
        "certificate_nonce_parent:prove_step");
    return proof;
}

Result<PendingCertificateNonceParent>
CertificateNonceParentAccumulator::verify_response(
    const CertificateNonceParentPublicInputs& inputs,
    std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
    const CertificateNonceResponseProof& proof,
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        match_inputs_and_leaves(inputs, ordered_leaves),
        "certificate_nonce_parent:inputs");
    if (proof.reductions.size() != ordered_leaves.size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_parent:reduction_count");
    }
    std::vector<bppp::accumulation::PendingClaim> claims;
    claims.reserve(ordered_leaves.size());
    for (std::size_t index = 0; index < ordered_leaves.size(); ++index) {
        PURIFY_ASSIGN_OR_RETURN(
            auto claim,
            bppp::accumulation::verify_algebraic_norm_reduction(
                leaves_.basis(), ordered_leaves[index].norm(),
                proof.reductions[index], secp_context),
            "certificate_nonce_parent:verify_reduction");
        claims.push_back(std::move(claim));
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto pending,
        bppp::accumulation::verify_bound_algebraic_step(
            leaves_.basis(), claims, inputs.statement_digest(),
            proof.accumulation, secp_context),
        "certificate_nonce_parent:verify_step");
    const auto& frame = inputs.frame();
    return PendingCertificateNonceParent(
        frame.certificate_context_digest, inputs.statement_digest(),
        frame.total_responses, 0, frame.response_ordinal, 1,
        inputs.aggregate_nonce(), std::move(pending));
}

Result<CertificateNonceTreeProof>
CertificateNonceParentAccumulator::prove_parent(
    std::span<const PendingCertificateNonceParent> ordered_children,
    purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(
        const auto metadata, parent_metadata(ordered_children),
        "certificate_nonce_tree:metadata");
    std::vector<bppp::accumulation::PendingClaim> claims;
    claims.reserve(ordered_children.size());
    for (const auto& child : ordered_children) {
        claims.push_back(child.claim_);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto accumulation,
        bppp::accumulation::prove_bound_algebraic_step(
            leaves_.basis(), claims, metadata.node_digest,
            secp_context),
        "certificate_nonce_tree:prove_step");
    return CertificateNonceTreeProof{std::move(accumulation)};
}

Result<PendingCertificateNonceParent>
CertificateNonceParentAccumulator::verify_parent(
    std::span<const PendingCertificateNonceParent> ordered_children,
    const CertificateNonceTreeProof& proof,
    purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(
        const auto metadata, parent_metadata(ordered_children),
        "certificate_nonce_tree:metadata");
    std::vector<bppp::accumulation::PendingClaim> claims;
    claims.reserve(ordered_children.size());
    for (const auto& child : ordered_children) {
        claims.push_back(child.claim_);
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto pending,
        bppp::accumulation::verify_bound_algebraic_step(
            leaves_.basis(), claims, metadata.node_digest,
            proof.accumulation, secp_context),
        "certificate_nonce_tree:verify_step");
    return PendingCertificateNonceParent(
        metadata.certificate_context_digest, metadata.node_digest,
        metadata.total_responses, metadata.level,
        metadata.first_response, metadata.response_count,
        std::nullopt, std::move(pending));
}

Status CertificateNonceParentAccumulator::decide_root(
    const PendingCertificateNonceParent& root,
    purify_secp_context* secp_context) const {
    if (root.first_response() != 0 || root.total_responses() == 0 ||
        root.response_count() != root.total_responses()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_tree:incomplete_root");
    }
    return bppp::accumulation::decide(
        leaves_.basis(), root.claim_, secp_context);
}

Status CertificateNonceParentAccumulator::verify_native_receipt(
    const CertificateNonceNativeReceipt& receipt,
    std::span<const CertificateNonceResponseVerificationView>
        ordered_responses,
    purify_secp_context* secp_context) const
{
    PURIFY_RETURN_IF_ERROR(
        validate_native_receipt_shape(
            receipt.certificate_context_digest(), receipt.responses(),
            receipt.tree_proofs()),
        "certificate_nonce_native:shape");
    if (ordered_responses.size() != receipt.responses().size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_native:public_responses");
    }

    std::vector<PendingCertificateNonceParent> current;
    current.reserve(ordered_responses.size());
    for (std::size_t index = 0; index < ordered_responses.size();
         ++index) {
        const auto& view = ordered_responses[index];
        const auto& inputs = view.inputs();
        const auto& frame = inputs.frame();
        if (inputs.statement_digest() !=
                receipt.responses()[index].statement_digest() ||
            frame.certificate_context_digest !=
                receipt.certificate_context_digest() ||
            frame.total_responses != ordered_responses.size() ||
            frame.response_ordinal != index) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_native:response_frame");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto pending,
            verify_response(
                inputs, view.ordered_leaves(),
                receipt.responses()[index].proof(), secp_context),
            "certificate_nonce_native:verify_response");
        current.push_back(std::move(pending));
    }

    std::size_t tree_proof_index = 0;
    while (current.size() > 1) {
        std::vector<PendingCertificateNonceParent> parents;
        parents.reserve(
            1 + (current.size() - 1) / kTreeFanout);
        for (std::size_t offset = 0; offset < current.size();
             offset += kTreeFanout) {
            if (tree_proof_index >= receipt.tree_proofs().size()) {
                return unexpected_error(
                    ErrorCode::SizeMismatch,
                    "certificate_nonce_native:missing_tree_proof");
            }
            const auto child_count =
                std::min(kTreeFanout, current.size() - offset);
            PURIFY_ASSIGN_OR_RETURN(
                auto parent,
                verify_parent(
                    std::span<const PendingCertificateNonceParent>{
                        current}
                        .subspan(offset, child_count),
                    receipt.tree_proofs()[tree_proof_index],
                    secp_context),
                "certificate_nonce_native:verify_tree_proof");
            ++tree_proof_index;
            parents.push_back(std::move(parent));
        }
        current = std::move(parents);
    }
    if (current.size() != 1 ||
        tree_proof_index != receipt.tree_proofs().size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_native:tree_shape");
    }
    return decide_root(current.front(), secp_context);
}

Result<CertificateNonceLinearReceipt>
CertificateNonceParentAccumulator::prove_linear_receipt(
    std::span<const CertificateNonceResponseVerificationView>
        ordered_responses,
    purify_secp_context* secp_context) const
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context, "certificate_nonce_linear:context"),
        "certificate_nonce_linear:context");
    PURIFY_ASSIGN_OR_RETURN(
        const auto context_digest,
        validate_linear_public_inputs(ordered_responses),
        "certificate_nonce_linear:public_inputs");
    PURIFY_ASSIGN_OR_RETURN(
        auto root,
        bppp::accumulation::canonical_zero_claim(leaves_.basis()),
        "certificate_nonce_linear:zero_claim");

    std::vector<CertificateNonceLinearResponseProof> responses;
    responses.reserve(ordered_responses.size());
    for (const auto& view : ordered_responses) {
        CertificateNonceLinearResponseProof response;
        response.members.reserve(view.ordered_leaves().size());
        for (std::size_t member_index = 0;
             member_index < view.ordered_leaves().size();
             ++member_index) {
            const auto& leaf = view.ordered_leaves()[member_index];
            PURIFY_ASSIGN_OR_RETURN(
                auto reduction,
                bppp::accumulation::prove_algebraic_norm_reduction(
                    leaves_.basis(), leaf.norm(), secp_context),
                "certificate_nonce_linear:prove_reduction");
            PURIFY_ASSIGN_OR_RETURN(
                auto leaf_claim,
                bppp::accumulation::verify_algebraic_norm_reduction(
                    leaves_.basis(), leaf.norm(), reduction,
                    secp_context),
                "certificate_nonce_linear:verify_reduction");
            const std::array claims{root, std::move(leaf_claim)};
            const auto& step_digest =
                view.inputs().recursive_step_digests()[member_index];
            PURIFY_ASSIGN_OR_RETURN(
                auto accumulation,
                bppp::accumulation::prove_bound_algebraic_step(
                    leaves_.basis(), claims, step_digest,
                    secp_context),
                "certificate_nonce_linear:prove_step");
            PURIFY_ASSIGN_OR_RETURN(
                auto next_root,
                bppp::accumulation::verify_bound_algebraic_step(
                    leaves_.basis(), claims, step_digest,
                    accumulation, secp_context),
                "certificate_nonce_linear:verify_step");
            root = std::move(next_root);
            response.members.push_back({std::move(reduction), std::move(accumulation)});
        }
        responses.push_back(std::move(response));
    }
    PURIFY_RETURN_IF_ERROR(
        bppp::accumulation::decide(
            leaves_.basis(), root, secp_context),
        "certificate_nonce_linear:decide");
    return CertificateNonceLinearReceipt::create(
        context_digest, std::move(responses));
}

Status CertificateNonceParentAccumulator::verify_linear_receipt(
    const CertificateNonceLinearReceipt& receipt,
    std::span<const CertificateNonceResponseVerificationView>
        ordered_responses,
    purify_secp_context* secp_context) const
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context, "certificate_nonce_linear:context"),
        "certificate_nonce_linear:context");
    PURIFY_RETURN_IF_ERROR(
        validate_linear_receipt_shape(
            receipt.certificate_context_digest(),
            receipt.responses()),
        "certificate_nonce_linear:shape");
    PURIFY_ASSIGN_OR_RETURN(
        const auto context_digest,
        validate_linear_public_inputs(ordered_responses),
        "certificate_nonce_linear:public_inputs");
    if (context_digest != receipt.certificate_context_digest() ||
        receipt.responses().size() != ordered_responses.size()) {
        return unexpected_error(
            ErrorCode::BindingMismatch,
            "certificate_nonce_linear:receipt_frame");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto root,
        bppp::accumulation::canonical_zero_claim(leaves_.basis()),
        "certificate_nonce_linear:zero_claim");
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size();
         ++response_index) {
        const auto& view = ordered_responses[response_index];
        const auto& proof = receipt.responses()[response_index];
        if (proof.members.size() != view.ordered_leaves().size()) {
            return unexpected_error(
                ErrorCode::SizeMismatch,
                "certificate_nonce_linear:member_count");
        }
        for (std::size_t member_index = 0;
             member_index < view.ordered_leaves().size();
             ++member_index) {
            const auto& leaf = view.ordered_leaves()[member_index];
            const auto& member_proof = proof.members[member_index];
            PURIFY_ASSIGN_OR_RETURN(
                auto leaf_claim,
                bppp::accumulation::verify_algebraic_norm_reduction(
                    leaves_.basis(), leaf.norm(),
                    member_proof.reduction, secp_context),
                "certificate_nonce_linear:verify_reduction");
            const std::array claims{root, std::move(leaf_claim)};
            PURIFY_ASSIGN_OR_RETURN(
                auto next_root,
                bppp::accumulation::verify_bound_algebraic_step(
                    leaves_.basis(), claims,
                    view.inputs().recursive_step_digests()[member_index],
                    member_proof.accumulation, secp_context),
                "certificate_nonce_linear:verify_step");
            root = std::move(next_root);
        }
    }
    return bppp::accumulation::decide(
        leaves_.basis(), root, secp_context);
}

} // namespace purify::puresign_plusplus
