// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/certificate_parent_verifier.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "../bridge/certificate_parent_bridge.h"

namespace purify::puresign_plusplus {
namespace {

static_assert(
    CertificateNonceParentAccumulator::kRootClaimSerializedSize ==
    PURIFY_CERTIFICATE_PARENT_ROOT_SIZE);
static_assert(
    CertificateParentVerifier::kProofSize ==
    PURIFY_CERTIFICATE_PARENT_PROOF_SIZE);

Unexpected<Error> load_error(
    purify_certificate_parent_status status)
{
    switch (status) {
    case PURIFY_CERTIFICATE_PARENT_MALFORMED:
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_parent:artifact_path");
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_OPEN_FAILED:
        return unexpected_error(
            ErrorCode::IoOpenFailed,
            "certificate_parent:artifact_open");
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_REJECTED:
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_parent:artifact_identity");
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_SNAPSHOT_FAILED:
        return unexpected_error(
            ErrorCode::IoWriteFailed,
            "certificate_parent:artifact_snapshot");
    case PURIFY_CERTIFICATE_PARENT_PROOF_REJECTED:
    case PURIFY_CERTIFICATE_PARENT_BUFFER_TOO_SMALL:
    case PURIFY_CERTIFICATE_PARENT_INTERNAL_ERROR:
    case PURIFY_CERTIFICATE_PARENT_OK:
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_parent:artifact_backend");
    }
    return unexpected_error(
        ErrorCode::InternalMismatch,
        "certificate_parent:artifact_status");
}

Unexpected<Error> verify_error(
    purify_certificate_parent_status status)
{
    switch (status) {
    case PURIFY_CERTIFICATE_PARENT_MALFORMED:
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "certificate_parent:malformed");
    case PURIFY_CERTIFICATE_PARENT_PROOF_REJECTED:
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "certificate_parent:proof");
    case PURIFY_CERTIFICATE_PARENT_BUFFER_TOO_SMALL:
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_OPEN_FAILED:
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_REJECTED:
    case PURIFY_CERTIFICATE_PARENT_ARTIFACT_SNAPSHOT_FAILED:
    case PURIFY_CERTIFICATE_PARENT_INTERNAL_ERROR:
    case PURIFY_CERTIFICATE_PARENT_OK:
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_parent:backend");
    }
    return unexpected_error(
        ErrorCode::InternalMismatch,
        "certificate_parent:status");
}

} // namespace

struct CertificateParentVerifier::Impl {
    explicit Impl(purify_certificate_parent_verifier* verifier_in)
        : verifier(verifier_in) {}

    ~Impl()
    {
        purify_certificate_parent_verifier_destroy(verifier);
    }

    purify_certificate_parent_verifier* verifier;
};

CertificateParentVerifier::CertificateParentVerifier(
    std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

CertificateParentVerifier::CertificateParentVerifier(
    CertificateParentVerifier&&) noexcept = default;

CertificateParentVerifier& CertificateParentVerifier::operator=(
    CertificateParentVerifier&&) noexcept = default;

CertificateParentVerifier::~CertificateParentVerifier() = default;

Result<CertificateParentVerifier> CertificateParentVerifier::load(
    std::string_view artifact_path)
{
    if (artifact_path.empty() ||
        artifact_path.find('\0') != std::string_view::npos) {
        return unexpected_error(
            ErrorCode::RangeViolation,
            "certificate_parent:artifact_path");
    }
    purify_certificate_parent_verifier* verifier = nullptr;
    const auto status = purify_certificate_parent_verifier_load(
        reinterpret_cast<const std::uint8_t*>(artifact_path.data()),
        artifact_path.size(), &verifier);
    if (status != PURIFY_CERTIFICATE_PARENT_OK) {
        return load_error(status);
    }
    if (verifier == nullptr) {
        return unexpected_error(
            ErrorCode::InternalMismatch,
            "certificate_parent:artifact_owner");
    }
    return CertificateParentVerifier(std::make_unique<Impl>(verifier));
}

Status CertificateParentVerifier::verify(
    const CertificateNonceRecursiveManifestResolution& resolution,
    std::span<const unsigned char> proof,
    const CertificateNonceParentAccumulator& accumulator,
    purify_secp_context* secp_context) const
{
    if (!impl_ || impl_->verifier == nullptr) {
        return unexpected_error(
            ErrorCode::UninitializedState,
            "certificate_parent:verifier");
    }
    if (proof.size() != kProofSize) {
        return unexpected_error(
            ErrorCode::BackendRejectedInput,
            "certificate_parent:proof_size");
    }
    const auto step_count = resolution.step_digests().size();
    if (!std::in_range<std::uint64_t>(step_count)) {
        return unexpected_error(
            ErrorCode::Overflow,
            "certificate_parent:step_count");
    }

    std::array<
        unsigned char,
        CertificateNonceParentAccumulator::kRootClaimSerializedSize>
        pending_root{};
    const auto& context_digest =
        resolution.certificate_context_digest();
    const auto& manifest = resolution.manifest().bytes();
    const auto status = purify_certificate_parent_verify(
        impl_->verifier, context_digest.data(),
        resolution.total_responses(),
        static_cast<std::uint64_t>(step_count), manifest.data(),
        proof.data(), proof.size(), pending_root.data(),
        pending_root.size());
    if (status != PURIFY_CERTIFICATE_PARENT_OK) {
        return verify_error(status);
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto final_claim,
        bppp::accumulation::parse_root_claim(
            accumulator.leaves().basis(), pending_root, secp_context),
        "certificate_parent:parse_root");
    return bppp::accumulation::decide(
        accumulator.leaves().basis(), final_claim, secp_context);
}

} // namespace purify::puresign_plusplus
