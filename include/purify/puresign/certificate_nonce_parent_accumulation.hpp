// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "purify/accumulation.hpp"
#include "purify/puresign/accountable_responses.hpp"
#include "purify/puresign/certificate_nonce_leaf_accumulation.hpp"

namespace purify::puresign_plusplus {

/** Proof scope named by a certificate nonce-response parent. */
enum class CertificateNonceParentScope : std::uint8_t {
    AccountableTopic = 1,
};

/** Fixed public frame for one electorate response in a certificate tree. */
struct CertificateNonceResponseFrame {
    /** Digest of the complete typed certificate trace context. */
    bppp::accumulation::Digest certificate_context_digest{};
    std::uint64_t total_responses = 0;
    std::uint64_t response_ordinal = 0;
    std::uint32_t electorate_index = 0;
    std::uint64_t electorate_weight = 0;
    CertificateNonceParentScope scope =
        CertificateNonceParentScope::AccountableTopic;
};

/** Public authorization facts for one compact-certificate response. */
class CertificateNonceResponseAuthorization {
public:
    /**
     * Bind the response facts an application resolves without nonce proofs.
     *
     * The full response digest binds the trace frame, scalar response,
     * accountable context, roster, and ordered nonce hosts. The common digest
     * omits individual roster entries. Per-member digests bind one exact
     * roster entry and host to the full response so a recursive step need not
     * absorb every member. None of these digests verifies a nonce proof or the
     * scalar-response equation.
     */
    [[nodiscard]] static Result<CertificateNonceResponseAuthorization>
    create(
        CertificateNonceResponseFrame frame,
        const accountable::NonceHostBoundSigningRoster& roster,
        const accountable::ConflictContext& context,
        std::span<const PublicKey> ordered_hosts,
        std::span<const unsigned char> canonical_body,
        const accountable::ScalarSignature& response,
        purify_secp_context* secp_context);

    [[nodiscard]] const CertificateNonceResponseFrame& frame()
        const noexcept
    {
        return frame_;
    }
    [[nodiscard]] const bppp::accumulation::Digest& common_digest()
        const noexcept
    {
        return common_digest_;
    }
    [[nodiscard]] const bppp::accumulation::Digest& response_digest()
        const noexcept
    {
        return response_digest_;
    }
    [[nodiscard]] const bppp::accumulation::Digest& response_binding()
        const noexcept
    {
        return response_binding_;
    }
    [[nodiscard]] std::span<const bppp::accumulation::Digest>
    member_digests() const noexcept
    {
        return member_digests_;
    }

private:
    CertificateNonceResponseAuthorization(
        CertificateNonceResponseFrame frame,
        bppp::accumulation::Digest common_digest,
        bppp::accumulation::Digest response_digest,
        bppp::accumulation::Digest response_binding,
        std::vector<bppp::accumulation::Digest> member_digests)
        : frame_(std::move(frame)),
          common_digest_(common_digest),
          response_digest_(response_digest),
          response_binding_(response_binding),
          member_digests_(std::move(member_digests))
    {
    }

    CertificateNonceResponseFrame frame_;
    bppp::accumulation::Digest common_digest_{};
    bppp::accumulation::Digest response_digest_{};
    bppp::accumulation::Digest response_binding_{};
    std::vector<bppp::accumulation::Digest> member_digests_;
};

/** One canonical 255-bit field encoding for an ordered member manifest. */
using CertificateNonceAuthorizationManifest = bppp::ScalarBytes;

/** Seed the ordered authorization manifest for one certificate trace. */
[[nodiscard]] Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest_seed(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses);

/** Append one response member at its exact canonical position. */
[[nodiscard]] Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest_step(
    const CertificateNonceAuthorizationManifest& prior,
    std::uint64_t response_ordinal, std::uint32_t member_ordinal,
    const bppp::accumulation::Digest& member_digest);

/** Derive the final manifest from a complete ordered response sequence. */
[[nodiscard]] Result<CertificateNonceAuthorizationManifest>
certificate_nonce_authorization_manifest(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses,
    std::span<const CertificateNonceResponseAuthorization> responses);

/**
 * Canonical public statement for one proof-backed scalar response.
 *
 * Creation checks the registered roster, exact ordered nonce hosts, topic,
 * unique prepared leaves, aggregate nonce, and scalar-response equation. The
 * certificate-context digest must be derived by the caller from the complete
 * canonical trace, including its kind and every response. This type does not
 * perform registry or consensus admission.
 */
class CertificateNonceParentPublicInputs {
public:
    static constexpr std::size_t kMemberBatchCapacity = 128;

    [[nodiscard]] static Result<CertificateNonceParentPublicInputs> create(
        CertificateNonceResponseFrame frame,
        const accountable::NonceHostBoundSigningRoster& roster,
        const accountable::ConflictContext& context,
        std::span<const PublicKey> ordered_hosts,
        std::span<const unsigned char> canonical_body,
        const accountable::ScalarSignature& response,
        std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
        purify_secp_context* secp_context);

    [[nodiscard]] const CertificateNonceResponseFrame& frame()
        const noexcept {
        return frame_;
    }
    [[nodiscard]] std::span<const unsigned char> canonical_bytes()
        const noexcept {
        return canonical_bytes_;
    }
    [[nodiscard]] const bppp::accumulation::Digest& statement_digest()
        const noexcept {
        return statement_digest_;
    }
    [[nodiscard]] const CertificateNonceResponseAuthorization&
    authorization() const noexcept
    {
        return authorization_;
    }
    [[nodiscard]] const bppp::PointBytes& aggregate_nonce()
        const noexcept {
        return aggregate_nonce_;
    }
    [[nodiscard]] std::span<const bppp::accumulation::Digest>
    leaf_bindings() const noexcept {
        return leaf_bindings_;
    }
    [[nodiscard]] std::span<const bppp::PointBytes> member_nonces()
        const noexcept {
        return member_nonces_;
    }

private:
    CertificateNonceParentPublicInputs(
        CertificateNonceResponseFrame frame, Bytes canonical_bytes,
        bppp::accumulation::Digest statement_digest,
        CertificateNonceResponseAuthorization authorization,
        bppp::PointBytes aggregate_nonce,
        std::vector<bppp::accumulation::Digest> leaf_bindings,
        std::vector<bppp::PointBytes> member_nonces)
        : frame_(std::move(frame)),
          canonical_bytes_(std::move(canonical_bytes)),
          statement_digest_(statement_digest),
          authorization_(std::move(authorization)),
          aggregate_nonce_(aggregate_nonce),
          leaf_bindings_(std::move(leaf_bindings)),
          member_nonces_(std::move(member_nonces)) {}

    CertificateNonceResponseFrame frame_;
    Bytes canonical_bytes_;
    bppp::accumulation::Digest statement_digest_{};
    CertificateNonceResponseAuthorization authorization_;
    bppp::PointBytes aggregate_nonce_{};
    std::vector<bppp::accumulation::Digest> leaf_bindings_;
    std::vector<bppp::PointBytes> member_nonces_;
};

/** Linear public witness for one response-level accumulation step. */
struct CertificateNonceResponseProof {
    std::vector<bppp::accumulation::AlgebraicNormReductionProof>
        reductions;
    bppp::accumulation::AlgebraicStepProof accumulation;
};

/** One fixed-fanout transition above already verified response parents. */
struct CertificateNonceTreeProof {
    bppp::accumulation::AlgebraicStepProof accumulation;
};

class CertificateNonceParentAccumulator;

/** One statement-bound response record in the native witness stream. */
class CertificateNonceNativeResponse
{
public:
    [[nodiscard]] static Result<CertificateNonceNativeResponse> create(
        bppp::accumulation::Digest statement_digest,
        CertificateNonceResponseProof proof);

    [[nodiscard]] const bppp::accumulation::Digest& statement_digest()
        const noexcept
    {
        return statement_digest_;
    }
    [[nodiscard]] const CertificateNonceResponseProof& proof()
        const noexcept
    {
        return proof_;
    }

private:
    CertificateNonceNativeResponse(
        bppp::accumulation::Digest statement_digest,
        CertificateNonceResponseProof proof)
        : statement_digest_(statement_digest),
          proof_(std::move(proof)) {}

    bppp::accumulation::Digest statement_digest_{};
    CertificateNonceResponseProof proof_;
};

/**
 * Canonical native proof transport for one complete certificate tree.
 *
 * This is not a compact recursive proof and parsing it proves nothing. The
 * complete ordered public inputs and prepared leaves are still required by
 * verify_native_receipt(), which replays every transition and calls the final
 * native decision. Its header pins the native basis and every response record
 * carries the exact statement digest. Those fields form the handoff to a
 * future, separately qualified certificate-Nova relation; they do not make
 * the current transport recursively verified.
 */
class CertificateNonceNativeReceipt
{
public:
    static constexpr std::size_t kHeaderSerializedSize = 88;
    static constexpr std::size_t kResponseHeaderSerializedSize = 33;
    static constexpr std::size_t kReductionSerializedSize = 890;
    static constexpr std::size_t kStepSerializedSize = 924;

    [[nodiscard]] static Result<CertificateNonceNativeReceipt> create(
        bppp::accumulation::Digest certificate_context_digest,
        std::vector<CertificateNonceNativeResponse> responses,
        std::vector<CertificateNonceTreeProof> tree_proofs);

    [[nodiscard]] const bppp::accumulation::Digest&
    certificate_context_digest() const noexcept
    {
        return certificate_context_digest_;
    }
    [[nodiscard]] std::span<const CertificateNonceNativeResponse>
    responses() const noexcept
    {
        return responses_;
    }
    [[nodiscard]] std::span<const CertificateNonceTreeProof>
    tree_proofs() const noexcept
    {
        return tree_proofs_;
    }

private:
    CertificateNonceNativeReceipt(
        bppp::accumulation::Digest certificate_context_digest,
        std::vector<CertificateNonceNativeResponse> responses,
        std::vector<CertificateNonceTreeProof> tree_proofs)
        : certificate_context_digest_(certificate_context_digest),
          responses_(std::move(responses)),
          tree_proofs_(std::move(tree_proofs)) {}

    bppp::accumulation::Digest certificate_context_digest_{};
    std::vector<CertificateNonceNativeResponse> responses_;
    std::vector<CertificateNonceTreeProof> tree_proofs_;
};

/** Exact encoded size for the supplied ordered response member counts. */
[[nodiscard]] Result<std::size_t>
certificate_nonce_native_receipt_size(
    std::span<const std::size_t> member_counts);

/** Canonical native witness encoding; serialization is not verification. */
[[nodiscard]] Result<Bytes> serialize_certificate_nonce_native_receipt(
    const CertificateNonceParentAccumulator& accumulator,
    const CertificateNonceNativeReceipt& receipt,
    purify_secp_context* secp_context);

/** Strict canonical parser; parsing is not proof acceptance. */
[[nodiscard]] Result<CertificateNonceNativeReceipt>
parse_certificate_nonce_native_receipt(
    const CertificateNonceParentAccumulator& accumulator,
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context);

/** Borrowed exact public material for one ordered response proof. */
class CertificateNonceResponseVerificationView
{
public:
    CertificateNonceResponseVerificationView(
        const CertificateNonceParentPublicInputs& inputs,
        std::span<const PreparedCertificateNonceLeaf> ordered_leaves)
        : inputs_(&inputs), ordered_leaves_(ordered_leaves) {}

    [[nodiscard]] const CertificateNonceParentPublicInputs& inputs()
        const noexcept
    {
        return *inputs_;
    }
    [[nodiscard]] std::span<const PreparedCertificateNonceLeaf>
    ordered_leaves() const noexcept
    {
        return ordered_leaves_;
    }

private:
    const CertificateNonceParentPublicInputs* inputs_;
    std::span<const PreparedCertificateNonceLeaf> ordered_leaves_;
};

/**
 * A typed but still pending certificate nonce parent.
 *
 * The hidden claim can feed a later fixed-fanout tree level. It is not a
 * receipt, and no caller may accept it without verifying all descendants and
 * completing decide_root().
 */
class PendingCertificateNonceParent {
public:
    PendingCertificateNonceParent(
        const PendingCertificateNonceParent&) = delete;
    PendingCertificateNonceParent& operator=(
        const PendingCertificateNonceParent&) = delete;
    PendingCertificateNonceParent(
        PendingCertificateNonceParent&&) noexcept = default;
    PendingCertificateNonceParent& operator=(
        PendingCertificateNonceParent&&) noexcept = default;

    [[nodiscard]] const bppp::accumulation::Digest&
    certificate_context_digest() const noexcept {
        return certificate_context_digest_;
    }
    [[nodiscard]] const bppp::accumulation::Digest& node_digest()
        const noexcept {
        return node_digest_;
    }
    [[nodiscard]] std::uint64_t total_responses() const noexcept {
        return total_responses_;
    }
    [[nodiscard]] std::uint32_t level() const noexcept { return level_; }
    [[nodiscard]] std::uint64_t first_response() const noexcept {
        return first_response_;
    }
    [[nodiscard]] std::uint64_t response_count() const noexcept {
        return response_count_;
    }
    [[nodiscard]] const std::optional<bppp::PointBytes>& aggregate_nonce()
        const noexcept {
        return aggregate_nonce_;
    }

private:
    PendingCertificateNonceParent(
        bppp::accumulation::Digest certificate_context_digest,
        bppp::accumulation::Digest node_digest,
        std::uint64_t total_responses, std::uint32_t level,
        std::uint64_t first_response, std::uint64_t response_count,
        std::optional<bppp::PointBytes> aggregate_nonce,
        bppp::accumulation::PendingClaim claim)
        : certificate_context_digest_(certificate_context_digest),
          node_digest_(node_digest), total_responses_(total_responses),
          level_(level), first_response_(first_response),
          response_count_(response_count),
          aggregate_nonce_(std::move(aggregate_nonce)),
          claim_(std::move(claim)) {}

    bppp::accumulation::Digest certificate_context_digest_{};
    bppp::accumulation::Digest node_digest_{};
    std::uint64_t total_responses_ = 0;
    std::uint32_t level_ = 0;
    std::uint64_t first_response_ = 0;
    std::uint64_t response_count_ = 0;
    std::optional<bppp::PointBytes> aggregate_nonce_;
    bppp::accumulation::PendingClaim claim_;

    friend class CertificateNonceParentAccumulator;
};

/**
 * Purpose-owned native accumulator for certificate nonce responses.
 *
 * This authenticates the prepared nonce-proof algebra and public response
 * frames. Registry resolution, quorum arithmetic, and certificate admission
 * remain application checks and are not compressed by this API.
 */
class CertificateNonceParentAccumulator {
public:
    static constexpr std::size_t kTreeFanout = 16;
    /** Largest range whose canonical fanout tree fits uint64_t framing. */
    static constexpr std::uint64_t kMaxTreeResponses{
        std::uint64_t{1} << 60};

    CertificateNonceParentAccumulator(
        const CertificateNonceParentAccumulator&) = delete;
    CertificateNonceParentAccumulator& operator=(
        const CertificateNonceParentAccumulator&) = delete;
    CertificateNonceParentAccumulator(
        CertificateNonceParentAccumulator&&) noexcept = default;
    CertificateNonceParentAccumulator& operator=(
        CertificateNonceParentAccumulator&&) noexcept = default;

    [[nodiscard]] static Result<CertificateNonceParentAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const CertificateNonceLeafAccumulator& leaves()
        const noexcept {
        return leaves_;
    }

    [[nodiscard]] Result<CertificateNonceResponseProof> prove_response(
        const CertificateNonceParentPublicInputs& inputs,
        std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
        purify_secp_context* secp_context) const;

    [[nodiscard]] Result<PendingCertificateNonceParent> verify_response(
        const CertificateNonceParentPublicInputs& inputs,
        std::span<const PreparedCertificateNonceLeaf> ordered_leaves,
        const CertificateNonceResponseProof& proof,
        purify_secp_context* secp_context) const;

    [[nodiscard]] Result<CertificateNonceTreeProof> prove_parent(
        std::span<const PendingCertificateNonceParent> ordered_children,
        purify_secp_context* secp_context) const;

    [[nodiscard]] Result<PendingCertificateNonceParent> verify_parent(
        std::span<const PendingCertificateNonceParent> ordered_children,
        const CertificateNonceTreeProof& proof,
        purify_secp_context* secp_context) const;

    /**
     * Discharge nonce obligations only for a complete fixed-fanout tree.
     *
     * Success is not certificate or quorum acceptance.
     */
    [[nodiscard]] Status decide_root(
        const PendingCertificateNonceParent& root,
        purify_secp_context* secp_context) const;

    /** Replay and discharge every proof in one canonical native receipt. */
    [[nodiscard]] Status verify_native_receipt(
        const CertificateNonceNativeReceipt& receipt,
        std::span<const CertificateNonceResponseVerificationView>
            ordered_responses,
        purify_secp_context* secp_context) const;

private:
    explicit CertificateNonceParentAccumulator(
        CertificateNonceLeafAccumulator leaves)
        : leaves_(std::move(leaves)) {}

    CertificateNonceLeafAccumulator leaves_;
};

} // namespace purify::puresign_plusplus
