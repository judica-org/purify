// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::Result;
using purify::accountable::ConflictContext;
using purify::accountable::NonceHostBoundSigningRoster;
using purify::accountable::ScalarSignature;
using purify::accountable::SigningRoster;
using purify::puresign_plusplus::CertificateNonceNativeReceipt;
using purify::puresign_plusplus::CertificateNonceNativeResponse;
using purify::puresign_plusplus::CertificateNonceParentAccumulator;
using purify::puresign_plusplus::CertificateNonceParentPublicInputs;
using purify::puresign_plusplus::CertificateNonceParentScope;
using purify::puresign_plusplus::CertificateNoncePublicLeafDescriptor;
using purify::puresign_plusplus::CertificateNonceRecursiveManifestResolution;
using purify::puresign_plusplus::CertificateNonceRecursiveResponseView;
using purify::puresign_plusplus::CertificateNonceResponseAuthorization;
using purify::puresign_plusplus::CertificateNonceResponseFrame;
using purify::puresign_plusplus::CertificateNonceResponseVerificationView;
using purify::puresign_plusplus::NonceProof;
using purify::puresign_plusplus::PublicKey;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

using Point = std::array<unsigned char, 33>;
using OnePreparedLeaf =
    std::array<
        purify::puresign_plusplus::PreparedCertificateNonceLeaf, 1>;
using OneHost = std::array<PublicKey, 1>;
using OneProof = std::array<NonceProof, 1>;

static_assert(std::is_constructible_v<
              CertificateNonceResponseVerificationView,
              const CertificateNonceParentPublicInputs&,
              const OnePreparedLeaf&>);
static_assert(!std::is_constructible_v<
              CertificateNonceResponseVerificationView,
              CertificateNonceParentPublicInputs&&,
              const OnePreparedLeaf&>);
static_assert(!std::is_constructible_v<
              CertificateNonceResponseVerificationView,
              const CertificateNonceParentPublicInputs&,
              OnePreparedLeaf>);
static_assert(!std::is_constructible_v<
              CertificateNonceResponseVerificationView,
              const CertificateNonceParentPublicInputs&,
              std::vector<
                  purify::puresign_plusplus::
                      PreparedCertificateNonceLeaf>>);
static_assert(std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              const ConflictContext&, const OneHost&, const OneProof&>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              CertificateNonceParentPublicInputs&&,
              const ConflictContext&, const OneHost&, const OneProof&>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              ConflictContext&&, const OneHost&, const OneProof&>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              const ConflictContext&, OneHost, const OneProof&>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              const ConflictContext&, const OneHost&, OneProof>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              const ConflictContext&, std::vector<PublicKey>,
              const OneProof&>);
static_assert(!std::is_constructible_v<
              purify::puresign_plusplus::CertificateNonceResponseProverView,
              const CertificateNonceParentPublicInputs&,
              const ConflictContext&, const OneHost&,
              std::vector<NonceProof>>);

constexpr std::size_t kQualifiedWitnessSize = 14'608;
constexpr std::size_t kQualifiedResponseCount = 2;
constexpr std::size_t kQualifiedMemberCount = 2;
constexpr std::size_t kQualifiedParentConstantsSize = 98;
constexpr std::size_t kQualifiedMemberProofSize =
    kQualifiedParentConstantsSize + NonceProof::kSerializedSize +
    purify::puresign_plusplus::CertificateNonceLinearReceipt::
        kReductionSerializedSize +
    purify::puresign_plusplus::CertificateNonceLinearReceipt::
        kStepSerializedSize;

class FixtureCursor {
public:
    explicit FixtureCursor(std::span<const unsigned char> bytes) : bytes_(bytes)
    {}

    Result<std::span<const unsigned char>> take(std::size_t size)
    {
        if (size > bytes_.size() - offset_) {
            return purify::unexpected_error(
                purify::ErrorCode::InvalidFixedSize,
                "certificate_parent_test:fixture_truncated");
        }
        const auto result = bytes_.subspan(offset_, size);
        offset_ += size;
        return result;
    }

    template <std::size_t Size> Result<std::array<unsigned char, Size>> array()
    {
        PURIFY_ASSIGN_OR_RETURN(const auto bytes, take(Size),
                                "certificate_parent_test:fixture_array");
        std::array<unsigned char, Size> result{};
        std::copy(bytes.begin(), bytes.end(), result.begin());
        return result;
    }

    Result<unsigned char> u8()
    {
        PURIFY_ASSIGN_OR_RETURN(const auto bytes, array<1>(),
                                "certificate_parent_test:fixture_u8");
        return bytes[0];
    }

    Result<std::uint32_t> u32()
    {
        PURIFY_ASSIGN_OR_RETURN(const auto bytes, array<4>(),
                                "certificate_parent_test:fixture_u32");
        std::uint32_t result = 0;
        for (const auto byte : bytes) {
            result = (result << 8) | byte;
        }
        return result;
    }

    Result<std::uint64_t> u64()
    {
        PURIFY_ASSIGN_OR_RETURN(const auto bytes, array<8>(),
                                "certificate_parent_test:fixture_u64");
        std::uint64_t result = 0;
        for (const auto byte : bytes) {
            result = (result << 8) | byte;
        }
        return result;
    }

    std::size_t remaining() const noexcept { return bytes_.size() - offset_; }

private:
    std::span<const unsigned char> bytes_;
    std::size_t offset_ = 0;
};

struct DecodedQualifiedResponse {
    CertificateNonceResponseFrame frame;
    std::array<unsigned char, 32> signing_key{};
    std::array<unsigned char, 32> host_commitment{};
    purify::accountable::CoalitionCoreDigest coalition_core{};
    purify::Bytes slot;
    purify::Bytes body;
    std::array<unsigned char, 32> response{};
    std::array<unsigned char, 32> key_list_hash{};
    bool aggregate_was_negated = false;
    std::vector<Point> roster_keys;
    std::vector<std::array<unsigned char, 32>> coefficients;
    std::vector<PublicKey> hosts;
    std::vector<CertificateNoncePublicLeafDescriptor> leaves;
};

class QualifiedPublicResponse {
public:
    static Result<std::unique_ptr<QualifiedPublicResponse>>
    create(DecodedQualifiedResponse decoded, purify_secp_context* secp_context)
    {
        auto result = std::unique_ptr<QualifiedPublicResponse>(
            new QualifiedPublicResponse(std::move(decoded)));
        PURIFY_ASSIGN_OR_RETURN(auto roster,
                                SigningRoster::aggregate(
                                    result->decoded_.roster_keys, secp_context),
                                "certificate_parent_test:qualified_roster");
        if (roster.signing_key() != result->decoded_.signing_key ||
            roster.key_list_hash() != result->decoded_.key_list_hash ||
            roster.aggregate_was_negated() !=
                result->decoded_.aggregate_was_negated ||
            roster.members().size() != result->decoded_.coefficients.size()) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "certificate_parent_test:qualified_roster_binding");
        }
        for (std::size_t index = 0; index < roster.members().size(); ++index) {
            if (roster.members()[index].public_key !=
                    result->decoded_.roster_keys[index] ||
                roster.members()[index].coefficient.to_bytes_be() !=
                    result->decoded_.coefficients[index]) {
                return purify::unexpected_error(
                    purify::ErrorCode::BindingMismatch,
                    "certificate_parent_test:qualified_member_binding");
            }
        }
        PURIFY_ASSIGN_OR_RETURN(auto bound_roster,
                                purify::accountable::bind_nonce_hosts(
                                    std::move(roster),
                                    result->decoded_.coalition_core,
                                    result->decoded_.hosts, secp_context),
                                "certificate_parent_test:qualified_hosts");
        if (bound_roster.nonce_host_commitment() !=
            result->decoded_.host_commitment) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "certificate_parent_test:qualified_host_binding");
        }
        result->roster_.emplace(std::move(bound_roster));
        result->context_.emplace(ConflictContext{
            result->decoded_.signing_key, result->decoded_.host_commitment,
            result->decoded_.coalition_core, result->decoded_.slot});
        PURIFY_ASSIGN_OR_RETURN(
            auto response,
            ScalarSignature::deserialize(result->decoded_.response),
            "certificate_parent_test:qualified_response");
        result->response_.emplace(std::move(response));
        PURIFY_ASSIGN_OR_RETURN(
            auto authorization,
            CertificateNonceResponseAuthorization::create(
                result->decoded_.frame, *result->roster_, *result->context_,
                result->decoded_.hosts, result->decoded_.body,
                *result->response_, secp_context),
            "certificate_parent_test:qualified_authorization");
        result->authorization_.emplace(std::move(authorization));
        return result;
    }

    CertificateNonceRecursiveResponseView view() const
    {
        return CertificateNonceRecursiveResponseView(
            *authorization_, *context_, decoded_.hosts, decoded_.body,
            *response_, decoded_.leaves);
    }

    CertificateNoncePublicLeafDescriptor& first_leaf()
    {
        return decoded_.leaves.front();
    }

private:
    explicit QualifiedPublicResponse(DecodedQualifiedResponse decoded)
        : decoded_(std::move(decoded))
    {}

    DecodedQualifiedResponse decoded_;
    std::optional<NonceHostBoundSigningRoster> roster_;
    std::optional<ConflictContext> context_;
    std::optional<ScalarSignature> response_;
    std::optional<CertificateNonceResponseAuthorization> authorization_;
};

struct QualifiedManifestFixture {
    CertificateNonceRecursiveManifestResolution manifest;
    CertificateNonceRecursiveManifestResolution changed_manifest;
};

Result<purify::Bytes> read_qualified_witness()
{
    std::ifstream input(PURIFY_TEST_CERTIFICATE_PARENT_WITNESS_V3_PATH,
                        std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        return purify::unexpected_error(
            purify::ErrorCode::IoOpenFailed,
            "certificate_parent_test:qualified_witness_open");
    }
    const auto end = input.tellg();
    if (end != static_cast<std::streamoff>(kQualifiedWitnessSize)) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_witness_size");
    }
    purify::Bytes bytes(kQualifiedWitnessSize);
    input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size()) ||
        input.peek() != std::ifstream::traits_type::eof()) {
        return purify::unexpected_error(
            purify::ErrorCode::UnexpectedSize,
            "certificate_parent_test:qualified_witness_read");
    }
    std::array<unsigned char, 32> digest{};
    purify_sha256(digest.data(), bytes.data(), bytes.size());
    if (digest != purify::UInt256::from_hex("36a4806d937edd496f28464248256512"
                                            "d45e51e25e36b5b6c184e991b88c9d46")
                      .to_bytes_be()) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "certificate_parent_test:qualified_witness_digest");
    }
    return bytes;
}

Result<DecodedQualifiedResponse> decode_qualified_response(
    std::span<const unsigned char> encoded,
    const purify::bppp::accumulation::Digest& context_digest,
    std::uint64_t response_ordinal, purify_secp_context* secp_context)
{
    FixtureCursor cursor(encoded);
    PURIFY_ASSIGN_OR_RETURN(const auto version, cursor.u8(),
                            "certificate_parent_test:qualified_version");
    PURIFY_ASSIGN_OR_RETURN(const auto scope, cursor.u8(),
                            "certificate_parent_test:qualified_scope");
    PURIFY_ASSIGN_OR_RETURN(const auto member_capacity, cursor.u32(),
                            "certificate_parent_test:qualified_capacity");
    if (version != 1 ||
        scope != static_cast<unsigned char>(
                     CertificateNonceParentScope::AccountableTopic) ||
        member_capacity !=
            CertificateNonceParentPublicInputs::kMemberBatchCapacity) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "certificate_parent_test:qualified_public_frame");
    }

    DecodedQualifiedResponse result;
    PURIFY_ASSIGN_OR_RETURN(const auto encoded_context, cursor.array<32>(),
                            "certificate_parent_test:qualified_context");
    PURIFY_ASSIGN_OR_RETURN(result.frame.total_responses, cursor.u64(),
                            "certificate_parent_test:qualified_response_count");
    PURIFY_ASSIGN_OR_RETURN(
        result.frame.response_ordinal, cursor.u64(),
        "certificate_parent_test:qualified_response_ordinal");
    PURIFY_ASSIGN_OR_RETURN(
        result.frame.electorate_index, cursor.u32(),
        "certificate_parent_test:qualified_electorate_index");
    PURIFY_ASSIGN_OR_RETURN(
        result.frame.electorate_weight, cursor.u64(),
        "certificate_parent_test:qualified_electorate_weight");
    result.frame.certificate_context_digest = encoded_context;
    result.frame.scope = CertificateNonceParentScope::AccountableTopic;
    if (encoded_context != context_digest ||
        result.frame.total_responses != kQualifiedResponseCount ||
        result.frame.response_ordinal != response_ordinal ||
        result.frame.electorate_weight == 0) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "certificate_parent_test:qualified_response_frame");
    }

    PURIFY_ASSIGN_OR_RETURN(result.signing_key, cursor.array<32>(),
                            "certificate_parent_test:qualified_signing_key");
    PURIFY_ASSIGN_OR_RETURN(
        result.host_commitment, cursor.array<32>(),
        "certificate_parent_test:qualified_host_commitment");
    PURIFY_ASSIGN_OR_RETURN(result.coalition_core, cursor.array<32>(),
                            "certificate_parent_test:qualified_coalition_core");
    PURIFY_ASSIGN_OR_RETURN(const auto slot_size, cursor.u64(),
                            "certificate_parent_test:qualified_slot_size");
    if (slot_size == 0 || slot_size > cursor.remaining()) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_slot");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto slot,
                            cursor.take(static_cast<std::size_t>(slot_size)),
                            "certificate_parent_test:qualified_slot");
    result.slot.assign(slot.begin(), slot.end());
    PURIFY_ASSIGN_OR_RETURN(const auto body_size, cursor.u64(),
                            "certificate_parent_test:qualified_body_size");
    if (body_size > cursor.remaining()) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_body");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto body,
                            cursor.take(static_cast<std::size_t>(body_size)),
                            "certificate_parent_test:qualified_body");
    result.body.assign(body.begin(), body.end());
    PURIFY_ASSIGN_OR_RETURN(
        result.response, cursor.array<32>(),
        "certificate_parent_test:qualified_scalar_response");
    PURIFY_ASSIGN_OR_RETURN(result.key_list_hash, cursor.array<32>(),
                            "certificate_parent_test:qualified_key_list_hash");
    PURIFY_ASSIGN_OR_RETURN(
        const auto aggregate_was_negated, cursor.u8(),
        "certificate_parent_test:qualified_aggregate_parity");
    if (aggregate_was_negated > 1) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "certificate_parent_test:qualified_aggregate_parity");
    }
    result.aggregate_was_negated = aggregate_was_negated != 0;
    PURIFY_ASSIGN_OR_RETURN(const auto member_count, cursor.u32(),
                            "certificate_parent_test:qualified_member_count");
    if (member_count != kQualifiedMemberCount) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_member_count");
    }

    result.roster_keys.reserve(member_count);
    result.coefficients.reserve(member_count);
    result.hosts.reserve(member_count);
    result.leaves.reserve(member_count);
    for (std::uint32_t member = 0; member < member_count; ++member) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto member_ordinal, cursor.u32(),
            "certificate_parent_test:qualified_member_ordinal");
        if (member_ordinal != member) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "certificate_parent_test:qualified_member_order");
        }
        PURIFY_ASSIGN_OR_RETURN(const auto roster_key, cursor.array<33>(),
                                "certificate_parent_test:qualified_roster_key");
        result.roster_keys.push_back(roster_key);
        PURIFY_ASSIGN_OR_RETURN(
            const auto coefficient, cursor.array<32>(),
            "certificate_parent_test:qualified_coefficient");
        result.coefficients.push_back(coefficient);
        PURIFY_ASSIGN_OR_RETURN(const auto serialized_host, cursor.array<96>(),
                                "certificate_parent_test:qualified_host");
        PURIFY_ASSIGN_OR_RETURN(
            auto host, PublicKey::deserialize(serialized_host, secp_context),
            "certificate_parent_test:qualified_host");
        result.hosts.push_back(std::move(host));

        CertificateNoncePublicLeafDescriptor descriptor;
        PURIFY_ASSIGN_OR_RETURN(
            descriptor.leaf_binding, cursor.array<32>(),
            "certificate_parent_test:qualified_leaf_binding");
        PURIFY_ASSIGN_OR_RETURN(
            const auto proof_digest, cursor.array<32>(),
            "certificate_parent_test:qualified_proof_digest");
        (void)proof_digest;
        PURIFY_ASSIGN_OR_RETURN(
            descriptor.circuit_precommitment, cursor.array<32>(),
            "certificate_parent_test:qualified_precommitment");
        PURIFY_ASSIGN_OR_RETURN(descriptor.nonce_point, cursor.array<33>(),
                                "certificate_parent_test:qualified_nonce");
        result.leaves.push_back(descriptor);
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto aggregate_nonce, cursor.array<33>(),
        "certificate_parent_test:qualified_aggregate_nonce");
    (void)aggregate_nonce;
    if (cursor.remaining() != 0) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_statement_trailing");
    }
    return result;
}

Result<QualifiedManifestFixture>
qualified_manifest_fixture(const CertificateNonceParentAccumulator& accumulator,
                           purify_secp_context* secp_context)
{
    PURIFY_ASSIGN_OR_RETURN(const auto witness, read_qualified_witness(),
                            "certificate_parent_test:qualified_witness");
    FixtureCursor cursor(witness);
    constexpr std::array<unsigned char, 16> magic{'P', 'u', 'r', 'i', 'f', 'y',
                                                  '/', 'C', 'e', 'r', 't', 'J',
                                                  'W', 'i', 't', '3'};
    PURIFY_ASSIGN_OR_RETURN(const auto encoded_magic, cursor.array<16>(),
                            "certificate_parent_test:qualified_magic");
    PURIFY_ASSIGN_OR_RETURN(const auto raw_generator_digest, cursor.array<32>(),
                            "certificate_parent_test:qualified_raw_generators");
    PURIFY_ASSIGN_OR_RETURN(const auto basis_digest, cursor.array<32>(),
                            "certificate_parent_test:qualified_basis");
    PURIFY_ASSIGN_OR_RETURN(const auto context_digest, cursor.array<32>(),
                            "certificate_parent_test:qualified_context");
    PURIFY_ASSIGN_OR_RETURN(const auto response_count, cursor.u64(),
                            "certificate_parent_test:qualified_response_count");
    if (encoded_magic != magic ||
        raw_generator_digest !=
            purify::UInt256::from_hex("44ab48d4ab2fdbb95eeed572e9e0a6c4"
                                      "69dbc1a32116ebd918b487ca5ea60582")
                .to_bytes_be() ||
        basis_digest != accumulator.leaves().basis().digest() ||
        context_digest !=
            purify::UInt256::from_hex("7bcb06b8538ccc9c79fd2f595bbbee9f"
                                      "08c0d829a97ccd92fc3175eb379039f5")
                .to_bytes_be() ||
        response_count != kQualifiedResponseCount) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "certificate_parent_test:qualified_header");
    }

    std::vector<std::unique_ptr<QualifiedPublicResponse>> responses;
    responses.reserve(response_count);
    for (std::uint64_t ordinal = 0; ordinal < response_count; ++ordinal) {
        PURIFY_ASSIGN_OR_RETURN(
            const auto statement_size, cursor.u64(),
            "certificate_parent_test:qualified_statement_size");
        if (statement_size > cursor.remaining()) {
            return purify::unexpected_error(
                purify::ErrorCode::InvalidFixedSize,
                "certificate_parent_test:qualified_statement_size");
        }
        PURIFY_ASSIGN_OR_RETURN(
            const auto statement,
            cursor.take(static_cast<std::size_t>(statement_size)),
            "certificate_parent_test:qualified_statement");
        PURIFY_ASSIGN_OR_RETURN(
            auto decoded,
            decode_qualified_response(statement, context_digest, ordinal,
                                      secp_context),
            "certificate_parent_test:qualified_statement");
        PURIFY_ASSIGN_OR_RETURN(
            const auto proof_count, cursor.u32(),
            "certificate_parent_test:qualified_proof_count");
        if (proof_count != decoded.leaves.size()) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "certificate_parent_test:qualified_proof_count");
        }
        const auto proof_bytes =
            static_cast<std::size_t>(proof_count) * kQualifiedMemberProofSize;
        PURIFY_ASSIGN_OR_RETURN(
            const auto ignored_proofs, cursor.take(proof_bytes),
            "certificate_parent_test:qualified_member_proofs");
        (void)ignored_proofs;
        PURIFY_ASSIGN_OR_RETURN(
            auto response,
            QualifiedPublicResponse::create(std::move(decoded), secp_context),
            "certificate_parent_test:qualified_public_response");
        responses.push_back(std::move(response));
    }
    if (cursor.remaining() != 0) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_witness_trailing");
    }

    std::vector<CertificateNonceRecursiveResponseView> views;
    views.reserve(responses.size());
    for (const auto& response : responses) {
        views.push_back(response->view());
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto manifest,
        purify::puresign_plusplus::certificate_nonce_recursive_manifest(
            accumulator.leaves(), context_digest, views, secp_context),
        "certificate_parent_test:qualified_manifest");

    responses.front()->first_leaf().leaf_binding.back() ^= 1;
    views.clear();
    for (const auto& response : responses) {
        views.push_back(response->view());
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto changed_manifest,
        purify::puresign_plusplus::certificate_nonce_recursive_manifest(
            accumulator.leaves(), context_digest, views, secp_context),
        "certificate_parent_test:changed_qualified_manifest");
    return QualifiedManifestFixture{std::move(manifest),
                                    std::move(changed_manifest)};
}

#if defined(PURIFY_HAS_CERTIFICATE_PARENT_VERIFIER)
Result<std::array<unsigned char, purify::puresign_plusplus::
                                     CertificateParentVerifier::kProofSize>>
read_qualified_proof(const char* path)
{
    using Proof = std::array<
        unsigned char,
        purify::puresign_plusplus::CertificateParentVerifier::kProofSize>;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        return purify::unexpected_error(
            purify::ErrorCode::IoOpenFailed,
            "certificate_parent_test:qualified_proof_open");
    }
    if (input.tellg() != static_cast<std::streamoff>(Proof{}.size())) {
        return purify::unexpected_error(
            purify::ErrorCode::InvalidFixedSize,
            "certificate_parent_test:qualified_proof_size");
    }
    Proof proof{};
    input.seekg(0);
    input.read(reinterpret_cast<char*>(proof.data()),
               static_cast<std::streamsize>(proof.size()));
    if (input.gcount() != static_cast<std::streamsize>(proof.size()) ||
        input.peek() != std::ifstream::traits_type::eof()) {
        return purify::unexpected_error(
            purify::ErrorCode::UnexpectedSize,
            "certificate_parent_test:qualified_proof_read");
    }
    std::array<unsigned char, 32> digest{};
    purify_sha256(digest.data(), proof.data(), proof.size());
    if (digest != purify::UInt256::from_hex("887eb27a8893078734a57fb497ed9f9aa"
                                            "dff03803454e419d497f0650727babb")
                      .to_bytes_be()) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "certificate_parent_test:qualified_proof_digest");
    }
    return proof;
}
#endif

Result<std::pair<FieldElement, Point>> even_secret_and_point(
    FieldElement scalar, purify_secp_context* secp_context)
{
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> xonly{};
    if (purify_bip340_key_from_seckey(
            secp_context, normalized.data(), xonly.data()) == 0) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "certificate_nonce_parent_test:signing_key");
    }
    Point point{};
    point[0] = normalized == original ? 0x02 : 0x03;
    std::copy(xonly.begin(), xonly.end(), point.begin() + 1);
    if (point[0] == 0x03) {
        scalar = scalar.negate();
        point[0] = 0x02;
    }
    return std::pair{scalar, point};
}

CertificateNonceResponseFrame response_frame(
    const purify::bppp::accumulation::Digest& context_digest,
    std::uint64_t response_ordinal)
{
    CertificateNonceResponseFrame frame{};
    frame.certificate_context_digest = context_digest;
    frame.total_responses = 2;
    frame.response_ordinal = response_ordinal;
    frame.electorate_index =
        static_cast<std::uint32_t>(7 + response_ordinal);
    frame.electorate_weight = 50 + response_ordinal;
    frame.scope = CertificateNonceParentScope::AccountableTopic;
    return frame;
}

void test_recursive_manifest_vectors(TestContext& ctx)
{
    purify::bppp::accumulation::Digest context_digest{};
    context_digest.fill(0x11);
    purify::bppp::accumulation::Digest first_step{};
    first_step.fill(0x22);
    purify::bppp::accumulation::Digest second_step{};
    second_step.fill(0x33);

    auto seed = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_seed(context_digest, 2);
    expect_ok(ctx, seed, "certificate manifest seed derives");
    if (!seed) return;
    ctx.expect(
        seed->bytes() ==
            purify::UInt256::from_hex(
                "2d0bb6c8254e72de3989292fd006aa7f"
                "091fd6b2f3c2a80ce721c6e647cb47e3")
                .to_bytes_be(),
        "certificate manifest seed matches the Rust vector");

    auto first = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *seed, 0, 0, first_step);
    expect_ok(ctx, first, "first certificate manifest step derives");
    if (!first) return;
    ctx.expect(
        first->bytes() ==
            purify::UInt256::from_hex(
                "3a84a6d47d7f6ffb2e103602bf93bf65"
                "a18db0733436302a635cecd1a2c9432c")
                .to_bytes_be(),
        "first certificate manifest step matches the Rust vector");

    auto second = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *first, 0, 1, second_step);
    expect_ok(ctx, second, "second certificate manifest step derives");
    if (!second) return;
    ctx.expect(
        second->bytes() ==
            purify::UInt256::from_hex(
                "4d0d41244c51fab3a31baac488adee3a"
                "fc287436de90a6c1df0f9a45b6568271")
                .to_bytes_be(),
        "second certificate manifest step matches the Rust vector");

    auto reordered = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *first, 1, 0, second_step);
    expect_ok(ctx, reordered,
              "reordered certificate manifest step derives");
    if (!reordered) return;
    ctx.expect(*reordered != *second,
               "certificate manifest binds response and member order");
}

void test_native_receipt_size(TestContext& ctx)
{
    std::array<std::size_t, 1> member_counts{};
    ctx.expect(
        !purify::puresign_plusplus::
             certificate_nonce_native_receipt_size(member_counts),
        "zero-member certificate response size rejects");
    member_counts[0] =
        CertificateNonceParentPublicInputs::kMemberBatchCapacity + 1;
    ctx.expect(
        !purify::puresign_plusplus::
             certificate_nonce_native_receipt_size(member_counts),
        "oversized certificate response size rejects");

    const std::array<std::size_t, 2> two_singletons{1, 1};
    auto size = purify::puresign_plusplus::
        certificate_nonce_native_receipt_size(two_singletons);
    expect_ok(ctx, size, "two-response certificate size derives");
    if (!size) return;
    constexpr std::size_t expected =
        CertificateNonceNativeReceipt::kHeaderSerializedSize +
        2 * (CertificateNonceNativeReceipt::kResponseHeaderSerializedSize +
             CertificateNonceNativeReceipt::kReductionSerializedSize +
             CertificateNonceNativeReceipt::kStepSerializedSize) +
        CertificateNonceNativeReceipt::kStepSerializedSize;
    ctx.expect(*size == expected,
               "native certificate size accounts for every proof exactly");
}

void test_native_certificate_parent(TestContext& ctx)
{
#if PURIFY_USE_LEGACY_FIELD_HASHES
    ctx.expect(true,
               "certificate nonce parents require the modern hash suite");
    return;
#else
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "certificate nonce parent secp context creates");
    if (!secp) return;

    auto signing = even_secret_and_point(
        FieldElement::from_u64(3), secp.get());
    expect_ok(ctx, signing, "certificate signing key derives");
    if (!signing) return;
    const std::array<Point, 1> signing_keys{signing->second};
    auto raw_roster = SigningRoster::aggregate(signing_keys, secp.get());
    expect_ok(ctx, raw_roster, "certificate signing roster aggregates");
    if (!raw_roster) return;

    std::array<unsigned char, 32> nonce_seed{};
    nonce_seed.fill(0xd1);
    auto generated = purify::generate_key(nonce_seed);
    expect_ok(ctx, generated, "certificate nonce host secret derives");
    if (!generated) return;
    auto nonce_signer = purify::puresign_plusplus::KeyPair::from_secret(
        generated->secret, secp.get());
    expect_ok(ctx, nonce_signer, "certificate nonce host derives");
    if (!nonce_signer) return;
    auto host = nonce_signer->public_key();
    std::copy(signing->second.begin() + 1, signing->second.end(),
              host.bip340_pubkey.begin());
    const std::array hosts{host};

    purify::accountable::CoalitionCoreDigest coalition_core{};
    coalition_core.fill(0x44);
    auto roster = purify::accountable::bind_nonce_hosts(
        std::move(*raw_roster), coalition_core, hosts, secp.get());
    expect_ok(ctx, roster, "certificate nonce host binds to roster");
    if (!roster) return;

    const auto slot = purify::bytes_from_ascii(
        "certificate/domain=4/epoch=8/slot=3");
    const auto body = purify::bytes_from_ascii("decision:root-a");
    const ConflictContext signing_context{
        roster->signing_key(), roster->nonce_host_commitment(),
        roster->coalition_core_digest(), slot};
    auto topic = purify::accountable::nonce_evaluation_input(
        signing_context, secp.get());
    expect_ok(ctx, topic, "certificate nonce topic derives");
    if (!topic) return;
    auto cache =
        purify::puresign_plusplus::TopicProofCache::build(*topic);
    expect_ok(ctx, cache, "certificate nonce proof cache builds");
    if (!cache) return;

    purify::bppp::ExperimentalCircuitCache circuit_cache;
    auto prepared_nonce = nonce_signer->prepare_topic_nonce_with_proof(
        *cache, secp.get(), &circuit_cache);
    expect_ok(ctx, prepared_nonce,
              "certificate member produces a V4 nonce proof");
    if (!prepared_nonce) return;
    auto proof_bytes = prepared_nonce->proof().serialize(secp.get());
    expect_ok(ctx, proof_bytes, "V4 certificate nonce proof serializes");
    if (!proof_bytes) return;
    ctx.expect(
        proof_bytes->size() == NonceProof::kSerializedSize &&
            proof_bytes->front() == NonceProof::kSerializationVersion,
        "certificate nonce proof uses the exact V4 wire frame");
    auto proof = NonceProof::deserialize(*proof_bytes, secp.get());
    expect_ok(ctx, proof, "V4 certificate nonce proof reparses");
    if (!proof) return;
    auto legacy_version = *proof_bytes;
    legacy_version.front() = 3;
    expect_error(
        ctx, NonceProof::deserialize(legacy_version, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "certificate nonce proof rejects the old wire version");

    auto raw_nonce = prepared_nonce->raw_scalar();
    expect_ok(ctx, raw_nonce, "certificate raw nonce scalar exports");
    if (!raw_nonce) return;
    auto challenge = purify::accountable::signature_challenge(
        signing_context, body, secp.get());
    expect_ok(ctx, challenge, "certificate response challenge derives");
    if (!challenge) return;
    const auto response_scalar =
        FieldElement::from_bytes32(*raw_nonce) +
        *challenge * roster->members().front().coefficient *
            signing->first;
    auto response = ScalarSignature::deserialize(
        response_scalar.to_bytes_be());
    expect_ok(ctx, response, "certificate scalar response constructs");
    if (!response) return;

    auto accumulator = CertificateNonceParentAccumulator::create(
        secp.get());
    expect_ok(ctx, accumulator,
              "certificate parent accumulator creates");
    if (!accumulator) return;
    auto leaf = accumulator->leaves().prepare(
        hosts.front(), *cache, *proof, secp.get(), &circuit_cache);
    expect_ok(ctx, leaf,
              "certificate parent authenticates the V4 nonce leaf");
    if (!leaf) return;
    std::vector<purify::puresign_plusplus::
                    PreparedCertificateNonceLeaf>
        leaves;
    leaves.push_back(std::move(*leaf));

    auto tampered_proof_bytes = *proof_bytes;
    tampered_proof_bytes.back() ^= 1;
    auto tampered_proof = NonceProof::deserialize(
        tampered_proof_bytes, secp.get());
    bool tamper_rejected = !tampered_proof;
    if (tampered_proof) {
        auto tampered_ok = host.verify_topic_nonce_proof(
            *cache, *tampered_proof, secp.get(), &circuit_cache);
        tamper_rejected = !tampered_ok || !*tampered_ok;
    }
    ctx.expect(tamper_rejected,
               "changed V4 nonce proof rejects under full verification");

    auto changed_slot = slot;
    changed_slot.back() ^= 1;
    const ConflictContext changed_context{
        roster->signing_key(), roster->nonce_host_commitment(),
        roster->coalition_core_digest(), changed_slot};
    auto changed_topic = purify::accountable::nonce_evaluation_input(
        changed_context, secp.get());
    expect_ok(ctx, changed_topic, "changed certificate topic derives");
    if (!changed_topic) return;
    auto changed_cache =
        purify::puresign_plusplus::TopicProofCache::build(*changed_topic);
    expect_ok(ctx, changed_cache,
              "changed certificate nonce cache builds");
    if (!changed_cache) return;
    ctx.expect(
        !accumulator->leaves().prepare(
            hosts.front(), *changed_cache, *proof, secp.get(),
            &circuit_cache),
        "V4 certificate nonce proof cannot cross topics");

    purify::bppp::accumulation::Digest certificate_context{};
    certificate_context.fill(0x77);
    auto first_inputs = CertificateNonceParentPublicInputs::create(
        response_frame(certificate_context, 0), *roster,
        signing_context, hosts, body, *response, leaves, secp.get());
    expect_ok(ctx, first_inputs,
              "first certificate response inputs validate");
    if (!first_inputs) return;
    auto second_inputs = CertificateNonceParentPublicInputs::create(
        response_frame(certificate_context, 1), *roster,
        signing_context, hosts, body, *response, leaves, secp.get());
    expect_ok(ctx, second_inputs,
              "second certificate response inputs validate");
    if (!second_inputs) return;

    auto first_proof = accumulator->prove_response(
        *first_inputs, leaves, secp.get());
    expect_ok(ctx, first_proof,
              "first certificate response accumulation proves");
    if (!first_proof) return;
    auto second_proof = accumulator->prove_response(
        *second_inputs, leaves, secp.get());
    expect_ok(ctx, second_proof,
              "second certificate response accumulation proves");
    if (!second_proof) return;
    auto first_pending = accumulator->verify_response(
        *first_inputs, leaves, *first_proof, secp.get());
    expect_ok(ctx, first_pending,
              "first certificate response accumulation verifies");
    if (!first_pending) return;
    auto second_pending = accumulator->verify_response(
        *second_inputs, leaves, *second_proof, secp.get());
    expect_ok(ctx, second_pending,
              "second certificate response accumulation verifies");
    if (!second_pending) return;

    std::vector<purify::puresign_plusplus::
                    PendingCertificateNonceParent>
        children;
    children.push_back(std::move(*first_pending));
    children.push_back(std::move(*second_pending));
    auto tree_proof = accumulator->prove_parent(children, secp.get());
    expect_ok(ctx, tree_proof,
              "certificate response parents accumulate");
    if (!tree_proof) return;
    auto root = accumulator->verify_parent(
        children, *tree_proof, secp.get());
    expect_ok(ctx, root, "certificate response parent verifies");
    if (!root) return;
    expect_ok(ctx, accumulator->decide_root(*root, secp.get()),
              "certificate native root completes final decision");

    auto first_native = CertificateNonceNativeResponse::create(
        first_inputs->statement_digest(), *first_proof);
    auto second_native = CertificateNonceNativeResponse::create(
        second_inputs->statement_digest(), *second_proof);
    expect_ok(ctx, first_native,
              "first native certificate response creates");
    expect_ok(ctx, second_native,
              "second native certificate response creates");
    if (!first_native || !second_native) return;
    std::vector<CertificateNonceNativeResponse> native_responses;
    native_responses.push_back(std::move(*first_native));
    native_responses.push_back(std::move(*second_native));
    std::vector<purify::puresign_plusplus::CertificateNonceTreeProof>
        native_tree_proofs{*tree_proof};
    auto native_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(native_responses),
        std::move(native_tree_proofs));
    expect_ok(ctx, native_receipt,
              "native certificate receipt creates");
    if (!native_receipt) return;
    auto encoded = purify::puresign_plusplus::
        serialize_certificate_nonce_native_receipt(
            *accumulator, *native_receipt, secp.get());
    expect_ok(ctx, encoded, "native certificate receipt serializes");
    if (!encoded) return;
    const std::array<std::size_t, 2> member_counts{1, 1};
    auto expected_size = purify::puresign_plusplus::
        certificate_nonce_native_receipt_size(member_counts);
    expect_ok(ctx, expected_size,
              "native certificate receipt size derives");
    if (!expected_size) return;
    ctx.expect(encoded->size() == *expected_size,
               "native certificate receipt has its exact derived size");

    auto parsed = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, *encoded, secp.get());
    expect_ok(ctx, parsed, "native certificate receipt reparses");
    if (!parsed) return;
    auto reencoded = purify::puresign_plusplus::
        serialize_certificate_nonce_native_receipt(
            *accumulator, *parsed, secp.get());
    expect_ok(ctx, reencoded,
              "parsed native certificate receipt reserializes");
    if (!reencoded) return;
    ctx.expect(*reencoded == *encoded,
               "native certificate receipt round-trips exactly");

    const std::array verification_views{
        CertificateNonceResponseVerificationView{
            *first_inputs, leaves},
        CertificateNonceResponseVerificationView{
            *second_inputs, leaves},
    };
    expect_ok(ctx,
              accumulator->verify_native_receipt(
                  *parsed, verification_views, secp.get()),
              "native certificate receipt verifies end to end");

    auto linear_receipt =
        accumulator->prove_linear_receipt(verification_views, secp.get());
    expect_ok(ctx, linear_receipt,
              "linear certificate receipt proves end to end");
    if (!linear_receipt) return;
    expect_ok(ctx,
              accumulator->verify_linear_receipt(
                  *linear_receipt, verification_views, secp.get()),
              "linear certificate receipt verifies end to end");

    const OneProof raw_proofs{*proof};
    const std::array prover_views{
        purify::puresign_plusplus::CertificateNonceResponseProverView{
            *first_inputs, signing_context, hosts, raw_proofs},
        purify::puresign_plusplus::CertificateNonceResponseProverView{
            *second_inputs, signing_context, hosts, raw_proofs},
    };
    auto linear_witness = purify::puresign_plusplus::
        serialize_accepted_linear_certificate_nonce_parent_witness(
            *accumulator, *linear_receipt, prover_views, secp.get(),
            &circuit_cache);
    expect_ok(ctx, linear_witness,
              "accepted linear certificate witness serializes");
    if (!linear_witness) return;
    constexpr std::array<unsigned char, 16> linear_witness_magic{
        'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
        'e', 'r', 't', 'J', 'W', 'i', 't', '3'};
    constexpr std::size_t linear_witness_header_size = 120;
    constexpr std::size_t linear_response_header_size = 12;
    const std::size_t expected_linear_witness_size =
        linear_witness_header_size + 2 * linear_response_header_size +
        first_inputs->canonical_bytes().size() +
        second_inputs->canonical_bytes().size() +
        2 * kQualifiedMemberProofSize;
    ctx.expect(linear_witness->size() == expected_linear_witness_size &&
                   std::equal(linear_witness_magic.begin(),
                              linear_witness_magic.end(),
                              linear_witness->begin()),
               "linear certificate witness has the exact CertJWit3 frame");

    auto repeated_witness = purify::puresign_plusplus::
        serialize_accepted_linear_certificate_nonce_parent_witness(
            *accumulator, *linear_receipt, prover_views, secp.get(),
            &circuit_cache);
    expect_ok(ctx, repeated_witness,
              "linear certificate witness reserializes");
    if (!repeated_witness) return;
    ctx.expect(*repeated_witness == *linear_witness,
               "linear certificate witness serialization is deterministic");

    std::vector<CertificateNonceNativeResponse> reordered_responses{
        parsed->responses()[1], parsed->responses()[0]};
    auto reordered_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(reordered_responses),
        {parsed->tree_proofs().front()});
    expect_ok(ctx, reordered_receipt,
              "reordered native receipt remains structurally valid");
    if (!reordered_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *reordered_receipt, verification_views, secp.get()),
        "native certificate verification binds response order");

    std::vector<CertificateNonceNativeResponse> changed_tree_responses{
        parsed->responses().begin(), parsed->responses().end()};
    auto changed_tree_proof = parsed->tree_proofs().front();
    changed_tree_proof.accumulation.terminal_scalar.front() ^= 1;
    auto changed_tree_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(changed_tree_responses),
        {std::move(changed_tree_proof)});
    expect_ok(ctx, changed_tree_receipt,
              "changed tree proof remains structurally valid");
    if (!changed_tree_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_tree_receipt, verification_views, secp.get()),
        "native certificate verification rejects a changed tree proof");

    auto bad_encoding = *encoded;
    bad_encoding.front() ^= 1;
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects changed magic");
    bad_encoding = *encoded;
    bad_encoding.pop_back();
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects truncation");
    bad_encoding = *encoded;
    bad_encoding.push_back(0);
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects trailing bytes");

    auto changed_context_encoding = *encoded;
    changed_context_encoding[48] ^= 1;
    auto changed_context_receipt = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, changed_context_encoding, secp.get());
    expect_ok(ctx, changed_context_receipt,
              "changed public context remains canonically encoded");
    if (!changed_context_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_context_receipt, verification_views, secp.get()),
        "native certificate verification binds the public context");

    auto changed_statement_encoding = *encoded;
    changed_statement_encoding[
        CertificateNonceNativeReceipt::kHeaderSerializedSize] ^= 1;
    auto changed_statement_receipt = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, changed_statement_encoding, secp.get());
    expect_ok(ctx, changed_statement_receipt,
              "changed statement digest remains canonically encoded");
    if (!changed_statement_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_statement_receipt, verification_views, secp.get()),
        "native certificate verification binds each statement digest");

    const std::array descriptors{leaves.front().public_descriptor()};
    const std::array recursive_responses{
        CertificateNonceRecursiveResponseView(
            first_inputs->authorization(), signing_context, hosts,
            body, *response, descriptors),
        CertificateNonceRecursiveResponseView(
            second_inputs->authorization(), signing_context, hosts,
            body, *response, descriptors),
    };
    auto public_manifest = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest(
            accumulator->leaves(), certificate_context,
            recursive_responses, secp.get());
    expect_ok(ctx, public_manifest,
              "public certificate manifest resolves without proofs");
    if (!public_manifest) return;
    auto public_frame = purify::puresign_plusplus::
        serialize_certificate_parent_public_frame(*public_manifest);
    expect_ok(ctx, public_frame,
              "public certificate prover frame serializes");
    if (!public_frame) return;
    constexpr std::array<unsigned char, 16> public_frame_magic{
        'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
        'e', 'r', 't', 'P', 'u', 'b', '1', 0};
    ctx.expect(
        public_frame->size() ==
                purify::puresign_plusplus::
                    kCertificateParentPublicFrameSize &&
            std::equal(
                public_frame_magic.begin(), public_frame_magic.end(),
                public_frame->begin()),
        "certificate prover frame has the fixed public boundary");

    auto changed_descriptors = descriptors;
    changed_descriptors.front().leaf_binding.back() ^= 1;
    const std::array changed_recursive_responses{
        CertificateNonceRecursiveResponseView(
            first_inputs->authorization(), signing_context, hosts,
            body, *response, changed_descriptors),
        recursive_responses[1],
    };
    auto changed_manifest = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest(
            accumulator->leaves(), certificate_context,
            changed_recursive_responses, secp.get());
    expect_ok(ctx, changed_manifest,
              "changed public leaf resolves a distinct manifest");
    if (!changed_manifest) return;
    ctx.expect(
        changed_manifest->manifest() != public_manifest->manifest(),
        "public certificate manifest binds each leaf descriptor");

    auto qualified = qualified_manifest_fixture(
        *accumulator, secp.get());
    expect_ok(ctx, qualified,
              "qualified public certificate fixture reconstructs");
    if (!qualified) return;
    auto qualified_frame = purify::puresign_plusplus::
        serialize_certificate_parent_public_frame(qualified->manifest);
    expect_ok(ctx, qualified_frame,
              "qualified public certificate frame serializes");
    if (!qualified_frame) return;
    std::array<unsigned char, 32> qualified_frame_digest{};
    purify_sha256(
        qualified_frame_digest.data(), qualified_frame->data(),
        qualified_frame->size());
    ctx.expect(
        qualified_frame_digest ==
            purify::UInt256::from_hex(
                "9057d923d70e4b600eb9e7f085a32f4a"
                "1eb245e6188dde6a0b8147a0ad816196")
                .to_bytes_be(),
        "qualified public certificate frame matches qualification");
    ctx.expect(
        qualified->changed_manifest.manifest() !=
            qualified->manifest.manifest(),
        "qualified public certificate manifest binds every leaf");

#if defined(PURIFY_HAS_CERTIFICATE_PARENT_VERIFIER)
    ctx.expect(
        !purify::puresign_plusplus::CertificateParentVerifier::load(""),
        "certificate verifier rejects an empty artifact path");
    const char* verifier_artifact = std::getenv(
        "PURIFY_TEST_CERTIFICATE_PARENT_VERIFIER_ARTIFACT");
    const char* proof_path = std::getenv(
        "PURIFY_TEST_CERTIFICATE_PARENT_PROOF");
    const bool has_artifact =
        verifier_artifact != nullptr && *verifier_artifact != '\0';
    const bool has_proof =
        proof_path != nullptr && *proof_path != '\0';
    ctx.expect(
        has_artifact == has_proof,
        "qualified verifier resources are configured together");
    if (has_artifact && has_proof) {
        auto proof = read_qualified_proof(proof_path);
        expect_ok(ctx, proof,
                  "qualified certificate proof loads and authenticates");
        if (!proof) return;
        auto verifier = purify::puresign_plusplus::
            CertificateParentVerifier::load(verifier_artifact);
        expect_ok(ctx, verifier,
                  "qualified certificate verifier artifact loads");
        if (!verifier) return;
        expect_ok(ctx,
                  verifier->verify(
                      qualified->manifest, *proof, *accumulator,
                      secp.get()),
                  "qualified recursive certificate proof verifies");
        ctx.expect(
            !verifier->verify(
                qualified->changed_manifest, *proof, *accumulator,
                secp.get()),
            "recursive verifier rejects a changed public manifest");
        auto changed_proof = *proof;
        changed_proof.back() ^= 1;
        ctx.expect(
            !verifier->verify(
                qualified->manifest, changed_proof, *accumulator,
                secp.get()),
            "recursive verifier rejects a changed proof");
    }
#endif
#endif
}

} // namespace

void run_certificate_nonce_parent_tests(TestContext& ctx)
{
    test_recursive_manifest_vectors(ctx);
    test_native_receipt_size(ctx);
    test_native_certificate_parent(ctx);
}
