// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file certificate_parent_verifier.hpp
 * @brief Selected recursive verification for certificate nonce parents.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

#include "purify/puresign/certificate_nonce_parent_accumulation.hpp"

namespace purify::puresign_plusplus {

/** Exact wire size selected by certificate-parent qualification. */
inline constexpr std::size_t QUALIFIED_CERTIFICATE_PARENT_PROOF_SIZE{
    15'268};

#if defined(PURIFY_HAS_CERTIFICATE_PARENT_VERIFIER)

/** The locally configured recursive certificate-parent verifier. */
class CertificateParentVerifier
{
public:
    static constexpr std::size_t kProofSize{
        QUALIFIED_CERTIFICATE_PARENT_PROOF_SIZE};

    CertificateParentVerifier(const CertificateParentVerifier&) = delete;
    CertificateParentVerifier& operator=(
        const CertificateParentVerifier&) = delete;
    CertificateParentVerifier(CertificateParentVerifier&&) noexcept;
    CertificateParentVerifier& operator=(
        CertificateParentVerifier&&) noexcept;
    ~CertificateParentVerifier();

    /**
     * Loads the configured verifier from an explicit UTF-8 storage path.
     *
     * The path cannot select artifact identity. A digest or shape mismatch is
     * an internal deployment error, not a peer-retry condition. Deploy the
     * artifact through an immutable, read-only snapshot; concurrent mutation
     * is also a deployment fault.
     */
    [[nodiscard]] static Result<CertificateParentVerifier> load(
        std::string_view artifact_path);

    /**
     * Authenticates one exact public manifest and completes native decide.
     *
     * The manifest capability can be created only by resolving the complete
     * ordered public response sequence. Success discharges its nonce-proof
     * obligations but does not establish quorum or certificate admission.
     */
    [[nodiscard]] Status verify(
        const CertificateNonceRecursiveManifestResolution& resolution,
        std::span<const unsigned char> proof,
        const CertificateNonceParentAccumulator& accumulator,
        purify_secp_context* secp_context) const;

private:
    struct Impl;
    explicit CertificateParentVerifier(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

#endif // PURIFY_HAS_CERTIFICATE_PARENT_VERIFIER

} // namespace purify::puresign_plusplus
