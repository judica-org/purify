// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file certificate_nonce_parent_prover_input.hpp
 * @brief Accepted joined witness for a certificate-parent prover.
 */

#pragma once

#include <array>
#include <span>

#include "purify/puresign/certificate_nonce_parent_accumulation.hpp"

namespace purify::puresign_plusplus {

/** Fixed external public frame consumed by the certificate prover. */
inline constexpr std::size_t kCertificateParentPublicFrameSize = 96;
using CertificateParentPublicFrame =
    std::array<unsigned char, kCertificateParentPublicFrameSize>;

/**
 * Serialize independently resolved public certificate facts for proving.
 *
 * Every field comes from the private-constructor manifest resolution. The
 * frame contains no proof- or peer-supplied context, count, or manifest.
 */
[[nodiscard]] Result<CertificateParentPublicFrame>
serialize_certificate_parent_public_frame(
    const CertificateNonceRecursiveManifestResolution& resolution);

/** Exact public response and raw nonce proofs joined for proving. */
class CertificateNonceResponseProverView
{
public:
    CertificateNonceResponseProverView(
        const CertificateNonceParentPublicInputs& inputs,
        const accountable::ConflictContext& context,
        std::span<const PublicKey> ordered_hosts,
        std::span<const NonceProof> ordered_proofs)
        : inputs_(&inputs), context_(&context),
          ordered_hosts_(ordered_hosts), ordered_proofs_(ordered_proofs)
    {
    }
    CertificateNonceResponseProverView(
        const CertificateNonceParentPublicInputs&,
        accountable::ConflictContext&&,
        std::span<const PublicKey>,
        std::span<const NonceProof>) = delete;

    [[nodiscard]] const CertificateNonceParentPublicInputs& inputs()
        const noexcept
    {
        return *inputs_;
    }
    [[nodiscard]] const accountable::ConflictContext& context()
        const noexcept
    {
        return *context_;
    }
    [[nodiscard]] std::span<const PublicKey> ordered_hosts()
        const noexcept
    {
        return ordered_hosts_;
    }
    [[nodiscard]] std::span<const NonceProof> ordered_proofs()
        const noexcept
    {
        return ordered_proofs_;
    }

private:
    const CertificateNonceParentPublicInputs* inputs_;
    const accountable::ConflictContext* context_;
    std::span<const PublicKey> ordered_hosts_;
    std::span<const NonceProof> ordered_proofs_;
};

/**
 * Serialize an accepted native receipt together with its exact raw leaves.
 *
 * Each V4 nonce proof is reauthenticated for its ordered host and accountable
 * topic. The resulting leaves are then used to replay every receipt reduction
 * and accumulation step through the final native decision. Bytes are returned
 * only after that decision succeeds.
 *
 * The joined witness carries each response's canonical statement bytes,
 * verifier-derived V4 parent constants, and raw nonce proofs, followed by the
 * exact canonical native receipt. It is prover input, not a compact proof or
 * certificate admission result.
 */
[[nodiscard]] Result<Bytes>
serialize_accepted_certificate_nonce_parent_witness(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceNativeReceipt& receipt,
    std::span<const CertificateNonceResponseProverView>
        ordered_responses,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/**
 * Serialize the homogeneous linear receipt and its exact raw leaves.
 *
 * The CertJWit3 stream carries one reduction and one bound transition beside
 * every raw leaf. It has no detached native receipt or tree suffix. Bytes are
 * returned only after replay reaches the final native decision.
 */
[[nodiscard]] Result<Bytes>
serialize_accepted_linear_certificate_nonce_parent_witness(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceLinearReceipt& receipt,
    std::span<const CertificateNonceResponseProverView>
        ordered_responses,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify::puresign_plusplus
