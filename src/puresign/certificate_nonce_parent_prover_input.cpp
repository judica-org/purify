// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/certificate_nonce_parent_prover_input.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace purify::puresign_plusplus {
namespace {

constexpr std::array<unsigned char, 16> kJoinedWitnessMagic{
    'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
    'e', 'r', 't', 'J', 'W', 'i', 't', '2'};
constexpr std::array<unsigned char, 16> kLinearJoinedWitnessMagic{
    'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
    'e', 'r', 't', 'J', 'W', 'i', 't', '3'};
constexpr std::array<unsigned char, 16>
    kCertificateParentPublicFrameMagic{
        'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
        'e', 'r', 't', 'P', 'u', 'b', '1', 0};
constexpr std::size_t kDigestSize = 32;
constexpr std::size_t kPointSize = 33;
constexpr std::size_t kParentConstantsSize =
    kDigestSize + 2 * kPointSize;
constexpr std::size_t kHeaderSize =
    kJoinedWitnessMagic.size() + kDigestSize + 8;
constexpr std::size_t kResponseHeaderSize = 8 + 4;
constexpr std::size_t kReceiptHeaderSize = 8;
constexpr std::size_t kLinearHeaderSize =
    kLinearJoinedWitnessMagic.size() + 3 * kDigestSize + 8;
constexpr std::size_t kLinearMemberSize =
    kParentConstantsSize + NonceProof::kSerializedSize +
    CertificateNonceLinearReceipt::kReductionSerializedSize +
    CertificateNonceLinearReceipt::kStepSerializedSize;
static_assert(
    kCertificateParentPublicFrameMagic.size() + 2 * kDigestSize +
        2 * sizeof(std::uint64_t) ==
    kCertificateParentPublicFrameSize);
static_assert(kLinearHeaderSize == 120);
static_assert(kLinearMemberSize == 2'984);

template <std::size_t N>
void append(Bytes& output, const std::array<unsigned char, N>& bytes)
{
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append(Bytes& output, std::span<const unsigned char> bytes)
{
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_u32(Bytes& output, std::uint32_t value)
{
    output.push_back(static_cast<unsigned char>(value >> 24));
    output.push_back(static_cast<unsigned char>(value >> 16));
    output.push_back(static_cast<unsigned char>(value >> 8));
    output.push_back(static_cast<unsigned char>(value));
}

void append_u64(Bytes& output, std::uint64_t value)
{
    for (unsigned int shift = 56; shift != 0; shift -= 8) {
        output.push_back(static_cast<unsigned char>(value >> shift));
    }
    output.push_back(static_cast<unsigned char>(value));
}

struct AcceptedResponse {
    std::vector<PreparedCertificateNonceLeaf> leaves;
    std::vector<Bytes> proofs;
};

Status add_size(std::size_t& total, std::size_t value)
{
    if (!checked_add_size(total, value, total)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_nonce_parent_witness:encoded_size");
    }
    return {};
}

} // namespace

Result<CertificateParentPublicFrame>
serialize_certificate_parent_public_frame(
    const CertificateNonceRecursiveManifestResolution& resolution)
{
    const auto step_count = resolution.step_digests().size();
    if (!size_fits_u64(step_count)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_parent_public_frame:step_count");
    }

    CertificateParentPublicFrame frame{};
    std::size_t offset = 0;
    const auto append = [&](std::span<const unsigned char> bytes) {
        assert(bytes.size() <= frame.size() - offset);
        std::copy(bytes.begin(), bytes.end(), frame.begin() + offset);
        offset += bytes.size();
    };
    const auto append_u64 = [&](std::uint64_t value) {
        assert(sizeof(value) <= frame.size() - offset);
        for (unsigned int shift = 56; shift != 0; shift -= 8) {
            frame[offset++] = static_cast<unsigned char>(value >> shift);
        }
        frame[offset++] = static_cast<unsigned char>(value);
    };

    append(kCertificateParentPublicFrameMagic);
    append(resolution.certificate_context_digest());
    append_u64(resolution.total_responses());
    append_u64(static_cast<std::uint64_t>(step_count));
    append(resolution.manifest().bytes());
    assert(offset == frame.size());
    return frame;
}

Result<Bytes> serialize_accepted_certificate_nonce_parent_witness(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceNativeReceipt& receipt,
    std::span<const CertificateNonceResponseProverView>
        ordered_responses,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache)
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context, "certificate_nonce_parent_witness:context"),
        "certificate_nonce_parent_witness:context");
    if (ordered_responses.size() != receipt.responses().size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_parent_witness:response_count");
    }

    std::vector<AcceptedResponse> accepted;
    accepted.reserve(ordered_responses.size());
    std::optional<std::array<unsigned char, 32>> raw_generator_digest;
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size(); ++response_index) {
        const auto& view = ordered_responses[response_index];
        const auto& inputs = view.inputs();
        const auto& frame = inputs.frame();
        if (frame.certificate_context_digest !=
                receipt.certificate_context_digest() ||
            frame.total_responses != ordered_responses.size() ||
            frame.response_ordinal != response_index ||
            inputs.statement_digest() !=
                receipt.responses()[response_index].statement_digest()) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_parent_witness:response_frame");
        }
        if (view.ordered_hosts().size() !=
                view.ordered_proofs().size() ||
            view.ordered_proofs().size() !=
                inputs.leaf_bindings().size()) {
            return unexpected_error(
                ErrorCode::SizeMismatch,
                "certificate_nonce_parent_witness:member_count");
        }

        PURIFY_ASSIGN_OR_RETURN(
            const auto nonce_input,
            accountable::nonce_evaluation_input(
                view.context(), secp_context),
            "certificate_nonce_parent_witness:nonce_input");
        PURIFY_ASSIGN_OR_RETURN(
            const auto topic_cache, TopicProofCache::build(nonce_input),
            "certificate_nonce_parent_witness:topic_cache");

        AcceptedResponse response;
        response.leaves.reserve(view.ordered_proofs().size());
        response.proofs.reserve(view.ordered_proofs().size());
        for (std::size_t member_index = 0;
             member_index < view.ordered_proofs().size();
             ++member_index) {
            PURIFY_ASSIGN_OR_RETURN(
                auto leaf,
                accumulator.leaves().prepare(
                    view.ordered_hosts()[member_index], topic_cache,
                    view.ordered_proofs()[member_index], secp_context,
                    cache),
                "certificate_nonce_parent_witness:prepare_leaf");
            PURIFY_ASSIGN_OR_RETURN(
                auto proof,
                view.ordered_proofs()[member_index].serialize(
                    secp_context),
                "certificate_nonce_parent_witness:serialize_proof");
            if (proof.size() != NonceProof::kSerializedSize) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_parent_witness:proof_size");
            }
            const auto& constants = leaf.parent_constants();
            if (raw_generator_digest.has_value() &&
                *raw_generator_digest != constants.raw_generator_digest) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_parent_witness:raw_generator_digest");
            }
            raw_generator_digest = constants.raw_generator_digest;
            response.leaves.push_back(std::move(leaf));
            response.proofs.push_back(std::move(proof));
        }
        accepted.push_back(std::move(response));
    }
    if (!raw_generator_digest.has_value()) {
        return unexpected_error(
            ErrorCode::EmptyInput,
            "certificate_nonce_parent_witness:empty_leaves");
    }

    std::vector<CertificateNonceResponseVerificationView>
        verification_views;
    verification_views.reserve(ordered_responses.size());
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        verification_views.emplace_back(
            ordered_responses[index].inputs(), accepted[index].leaves);
    }
    PURIFY_RETURN_IF_ERROR(
        accumulator.verify_native_receipt(
            receipt, verification_views, secp_context),
        "certificate_nonce_parent_witness:verify_receipt");

    PURIFY_ASSIGN_OR_RETURN(
        const auto receipt_bytes,
        serialize_certificate_nonce_native_receipt(
            accumulator, receipt, secp_context),
        "certificate_nonce_parent_witness:serialize_receipt");

    std::size_t expected_size = kHeaderSize;
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        PURIFY_RETURN_IF_ERROR(
            add_size(expected_size, kResponseHeaderSize),
            "certificate_nonce_parent_witness:response_header");
        PURIFY_RETURN_IF_ERROR(
            add_size(expected_size,
                     ordered_responses[index].inputs().canonical_bytes().size()),
            "certificate_nonce_parent_witness:response_inputs");
        std::size_t proof_bytes = 0;
        if (!checked_mul_size(
                accepted[index].proofs.size(),
                kParentConstantsSize + NonceProof::kSerializedSize,
                proof_bytes)) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_parent_witness:proof_bytes");
        }
        PURIFY_RETURN_IF_ERROR(
            add_size(expected_size, proof_bytes),
            "certificate_nonce_parent_witness:proof_bytes");
    }
    PURIFY_RETURN_IF_ERROR(
        add_size(expected_size, kReceiptHeaderSize),
        "certificate_nonce_parent_witness:receipt_header");
    PURIFY_RETURN_IF_ERROR(
        add_size(expected_size, receipt_bytes.size()),
        "certificate_nonce_parent_witness:receipt");

    if (!size_fits_u64(ordered_responses.size()) ||
        !size_fits_u64(receipt_bytes.size())) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_nonce_parent_witness:framing");
    }

    Bytes encoded;
    encoded.reserve(expected_size);
    append(encoded, kJoinedWitnessMagic);
    append(encoded, *raw_generator_digest);
    append_u64(
        encoded, static_cast<std::uint64_t>(ordered_responses.size()));
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        const auto canonical =
            ordered_responses[index].inputs().canonical_bytes();
        if (!size_fits_u64(canonical.size()) ||
            accepted[index].proofs.size() >
                std::numeric_limits<std::uint32_t>::max()) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_parent_witness:response_framing");
        }
        append_u64(
            encoded, static_cast<std::uint64_t>(canonical.size()));
        append(encoded, canonical);
        append_u32(
            encoded,
            static_cast<std::uint32_t>(accepted[index].proofs.size()));
        for (std::size_t member_index = 0;
             member_index < accepted[index].proofs.size();
             ++member_index) {
            const auto& constants =
                accepted[index].leaves[member_index].parent_constants();
            append(encoded, constants.circuit_binding_digest);
            append(encoded, constants.coefficient_commitment);
            append(encoded, constants.anchored_offset);
            append(encoded, accepted[index].proofs[member_index]);
        }
    }
    append_u64(
        encoded, static_cast<std::uint64_t>(receipt_bytes.size()));
    append(encoded, receipt_bytes);
    if (encoded.size() != expected_size) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_nonce_parent_witness:final_size");
    }
    return encoded;
}

Result<Bytes>
serialize_accepted_linear_certificate_nonce_parent_witness(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceLinearReceipt& receipt,
    std::span<const CertificateNonceResponseProverView>
        ordered_responses,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache)
{
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(
            secp_context,
            "certificate_nonce_linear_witness:context"),
        "certificate_nonce_linear_witness:context");
    if (ordered_responses.size() != receipt.responses().size()) {
        return unexpected_error(
            ErrorCode::SizeMismatch,
            "certificate_nonce_linear_witness:response_count");
    }

    std::vector<AcceptedResponse> accepted;
    accepted.reserve(ordered_responses.size());
    std::optional<std::array<unsigned char, 32>> raw_generator_digest;
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size(); ++response_index) {
        const auto& view = ordered_responses[response_index];
        const auto& inputs = view.inputs();
        const auto& frame = inputs.frame();
        if (frame.certificate_context_digest !=
                receipt.certificate_context_digest() ||
            frame.total_responses != ordered_responses.size() ||
            frame.response_ordinal != response_index) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "certificate_nonce_linear_witness:response_frame");
        }
        if (view.ordered_hosts().size() !=
                view.ordered_proofs().size() ||
            view.ordered_proofs().size() !=
                inputs.leaf_bindings().size() ||
            view.ordered_proofs().size() !=
                receipt.responses()[response_index].members.size()) {
            return unexpected_error(
                ErrorCode::SizeMismatch,
                "certificate_nonce_linear_witness:member_count");
        }

        PURIFY_ASSIGN_OR_RETURN(
            const auto nonce_input,
            accountable::nonce_evaluation_input(
                view.context(), secp_context),
            "certificate_nonce_linear_witness:nonce_input");
        PURIFY_ASSIGN_OR_RETURN(
            const auto topic_cache, TopicProofCache::build(nonce_input),
            "certificate_nonce_linear_witness:topic_cache");

        AcceptedResponse response;
        response.leaves.reserve(view.ordered_proofs().size());
        response.proofs.reserve(view.ordered_proofs().size());
        for (std::size_t member_index = 0;
             member_index < view.ordered_proofs().size();
             ++member_index) {
            PURIFY_ASSIGN_OR_RETURN(
                auto leaf,
                accumulator.leaves().prepare(
                    view.ordered_hosts()[member_index], topic_cache,
                    view.ordered_proofs()[member_index], secp_context,
                    cache),
                "certificate_nonce_linear_witness:prepare_leaf");
            PURIFY_ASSIGN_OR_RETURN(
                auto proof,
                view.ordered_proofs()[member_index].serialize(
                    secp_context),
                "certificate_nonce_linear_witness:serialize_proof");
            if (proof.size() != NonceProof::kSerializedSize) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_linear_witness:proof_size");
            }
            const auto& constants = leaf.parent_constants();
            if (raw_generator_digest.has_value() &&
                *raw_generator_digest != constants.raw_generator_digest) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_linear_witness:generator_digest");
            }
            raw_generator_digest = constants.raw_generator_digest;
            response.leaves.push_back(std::move(leaf));
            response.proofs.push_back(std::move(proof));
        }
        accepted.push_back(std::move(response));
    }
    if (!raw_generator_digest.has_value()) {
        return unexpected_error(
            ErrorCode::EmptyInput,
            "certificate_nonce_linear_witness:empty_leaves");
    }

    std::vector<CertificateNonceResponseVerificationView>
        verification_views;
    verification_views.reserve(ordered_responses.size());
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        verification_views.emplace_back(
            ordered_responses[index].inputs(), accepted[index].leaves);
    }
    PURIFY_RETURN_IF_ERROR(
        accumulator.verify_linear_receipt(
            receipt, verification_views, secp_context),
        "certificate_nonce_linear_witness:verify_receipt");

    std::size_t expected_size = kLinearHeaderSize;
    for (std::size_t index = 0; index < ordered_responses.size(); ++index) {
        PURIFY_RETURN_IF_ERROR(
            add_size(expected_size, kResponseHeaderSize),
            "certificate_nonce_linear_witness:response_header");
        PURIFY_RETURN_IF_ERROR(
            add_size(
                expected_size,
                ordered_responses[index]
                    .inputs()
                    .canonical_bytes()
                    .size()),
            "certificate_nonce_linear_witness:response_inputs");
        std::size_t member_bytes = 0;
        if (!checked_mul_size(
                accepted[index].proofs.size(), kLinearMemberSize,
                member_bytes)) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_linear_witness:member_bytes");
        }
        PURIFY_RETURN_IF_ERROR(
            add_size(expected_size, member_bytes),
            "certificate_nonce_linear_witness:member_bytes");
    }
    if (!size_fits_u64(ordered_responses.size())) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_nonce_linear_witness:response_count");
    }

    Bytes encoded;
    encoded.reserve(expected_size);
    append(encoded, kLinearJoinedWitnessMagic);
    append(encoded, *raw_generator_digest);
    append(encoded, accumulator.leaves().basis().digest());
    append(encoded, receipt.certificate_context_digest());
    append_u64(
        encoded, static_cast<std::uint64_t>(ordered_responses.size()));
    const auto& basis = accumulator.leaves().basis();
    for (std::size_t response_index = 0;
         response_index < ordered_responses.size(); ++response_index) {
        const auto canonical =
            ordered_responses[response_index].inputs().canonical_bytes();
        const auto& response = accepted[response_index];
        if (!size_fits_u64(canonical.size()) ||
            response.proofs.size() >
                std::numeric_limits<std::uint32_t>::max()) {
            return unexpected_error(
                ErrorCode::Overflow,
                "certificate_nonce_linear_witness:response_framing");
        }
        append_u64(
            encoded, static_cast<std::uint64_t>(canonical.size()));
        append(encoded, canonical);
        append_u32(
            encoded,
            static_cast<std::uint32_t>(response.proofs.size()));
        for (std::size_t member_index = 0;
             member_index < response.proofs.size(); ++member_index) {
            const auto& constants =
                response.leaves[member_index].parent_constants();
            append(encoded, constants.circuit_binding_digest);
            append(encoded, constants.coefficient_commitment);
            append(encoded, constants.anchored_offset);
            append(encoded, response.proofs[member_index]);

            const auto& member = receipt.responses()[response_index]
                                     .members[member_index];
            PURIFY_ASSIGN_OR_RETURN(
                auto reduction,
                bppp::accumulation::
                    serialize_algebraic_norm_reduction(
                        basis, member.reduction, secp_context),
                "certificate_nonce_linear_witness:reduction");
            if (reduction.size() !=
                CertificateNonceLinearReceipt::
                    kReductionSerializedSize) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_linear_witness:reduction_size");
            }
            append(encoded, reduction);
            PURIFY_ASSIGN_OR_RETURN(
                auto step,
                bppp::accumulation::serialize_algebraic_step(
                    basis, member.accumulation, secp_context),
                "certificate_nonce_linear_witness:step");
            if (step.size() !=
                CertificateNonceLinearReceipt::kStepSerializedSize) {
                return unexpected_error(
                    ErrorCode::InternalMismatch,
                    "certificate_nonce_linear_witness:step_size");
            }
            append(encoded, step);
        }
    }
    if (encoded.size() != expected_size) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_nonce_linear_witness:final_size");
    }
    return encoded;
}

} // namespace purify::puresign_plusplus
