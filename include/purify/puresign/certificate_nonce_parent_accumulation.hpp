// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <type_traits>
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

/**
 * Derive the recursive record digest for one authenticated nonce leaf.
 *
 * The Purify half of the supplied host must equal the leaf nonce host, and
 * the leaf topic must equal the nonce input recomputed from the context.
 */
[[nodiscard]] Result<bppp::accumulation::Digest>
certificate_nonce_recursive_member_digest(
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    const PreparedCertificateNonceLeaf& leaf,
    const accountable::ConflictContext& context,
    purify_secp_context* secp_context);

/**
 * Derive the same member digest from proof-free public leaf material.
 *
 * Parent constants are recomputed from the host, accountable topic, and
 * descriptor. Callers cannot supply constants recovered from a raw proof.
 */
[[nodiscard]] Result<bppp::accumulation::Digest>
certificate_nonce_recursive_member_digest(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceResponseAuthorization& authorization,
    std::uint32_t member_ordinal, const PublicKey& host,
    const CertificateNoncePublicLeafDescriptor& descriptor,
    const accountable::ConflictContext& context,
    purify_secp_context* secp_context);

/**
 * Derive the response relation digest consumed by one recursive step.
 *
 * This is framing, not authorization verification. The response binding is
 * hashed in full beside the supplied signing key, scalar response, and the
 * challenge recomputed from the supplied context and body. A mismatched set
 * therefore derives a different value from the verifier-recomputed manifest;
 * callers must compare that manifest before accepting the recursive result.
 */
[[nodiscard]] Result<bppp::accumulation::Digest>
certificate_nonce_recursive_step_digest(
    const CertificateNonceResponseAuthorization& authorization,
    const accountable::ConflictContext& context,
    std::span<const unsigned char> canonical_body,
    const accountable::ScalarSignature& response,
    const bppp::accumulation::Digest& member_digest,
    purify_secp_context* secp_context);

/**
 * Borrowed proof-free inputs for one ordered certificate response.
 *
 * Owning input ranges must be lvalues. Rvalue ranges are admitted only when
 * the standard marks them as borrowed, as it does for std::span.
 */
class CertificateNonceRecursiveResponseView
{
public:
    template <
        std::ranges::contiguous_range Hosts,
        std::ranges::contiguous_range Body,
        std::ranges::contiguous_range Leaves>
        requires std::ranges::sized_range<Hosts> &&
                 std::ranges::sized_range<Body> &&
                 std::ranges::sized_range<Leaves> &&
                 std::same_as<
                     std::ranges::range_value_t<Hosts>, PublicKey> &&
                 std::same_as<
                     std::ranges::range_value_t<Body>, unsigned char> &&
                 std::same_as<
                     std::ranges::range_value_t<Leaves>,
                     CertificateNoncePublicLeafDescriptor> &&
                 (std::is_lvalue_reference_v<Hosts> ||
                  std::ranges::borrowed_range<Hosts>) &&
                 (std::is_lvalue_reference_v<Body> ||
                  std::ranges::borrowed_range<Body>) &&
                 (std::is_lvalue_reference_v<Leaves> ||
                  std::ranges::borrowed_range<Leaves>)
    CertificateNonceRecursiveResponseView(
        const CertificateNonceResponseAuthorization& authorization,
        const accountable::ConflictContext& context,
        Hosts&& ordered_hosts, Body&& canonical_body,
        const accountable::ScalarSignature& response,
        Leaves&& ordered_leaves)
        : authorization_(&authorization), context_(&context),
          ordered_hosts_(ordered_hosts), canonical_body_(canonical_body),
          response_(&response), ordered_leaves_(ordered_leaves)
    {
    }
    template <typename Hosts, typename Body, typename Leaves>
    CertificateNonceRecursiveResponseView(
        const CertificateNonceResponseAuthorization&&,
        const accountable::ConflictContext&,
        Hosts&&, Body&&,
        const accountable::ScalarSignature&,
        Leaves&&) = delete;
    template <typename Hosts, typename Body, typename Leaves>
    CertificateNonceRecursiveResponseView(
        const CertificateNonceResponseAuthorization&,
        const accountable::ConflictContext&&,
        Hosts&&, Body&&,
        const accountable::ScalarSignature&,
        Leaves&&) = delete;
    template <typename Hosts, typename Body, typename Leaves>
    CertificateNonceRecursiveResponseView(
        const CertificateNonceResponseAuthorization&,
        const accountable::ConflictContext&,
        Hosts&&, Body&&,
        const accountable::ScalarSignature&&,
        Leaves&&) = delete;

    [[nodiscard]] const CertificateNonceResponseAuthorization&
    authorization() const noexcept
    {
        return *authorization_;
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
    [[nodiscard]] std::span<const unsigned char> canonical_body()
        const noexcept
    {
        return canonical_body_;
    }
    [[nodiscard]] const accountable::ScalarSignature& response()
        const noexcept
    {
        return *response_;
    }
    [[nodiscard]] std::span<const CertificateNoncePublicLeafDescriptor>
    ordered_leaves() const noexcept
    {
        return ordered_leaves_;
    }

private:
    const CertificateNonceResponseAuthorization* authorization_;
    const accountable::ConflictContext* context_;
    std::span<const PublicKey> ordered_hosts_;
    std::span<const unsigned char> canonical_body_;
    const accountable::ScalarSignature* response_;
    std::span<const CertificateNoncePublicLeafDescriptor> ordered_leaves_;
};

/** Canonical low-255-bit manifest value for recursive member records. */
class CertificateNonceRecursiveManifest
{
public:
    [[nodiscard]] const bppp::ScalarBytes& bytes() const noexcept
    {
        return bytes_;
    }

    friend bool operator==(
        const CertificateNonceRecursiveManifest&,
        const CertificateNonceRecursiveManifest&) = default;

private:
    explicit CertificateNonceRecursiveManifest(bppp::ScalarBytes bytes)
        : bytes_(bytes)
    {
    }

    bppp::ScalarBytes bytes_{};

    friend Result<CertificateNonceRecursiveManifest>
    certificate_nonce_recursive_manifest_seed(
        const bppp::accumulation::Digest&, std::uint64_t);
    friend Result<CertificateNonceRecursiveManifest>
    certificate_nonce_recursive_manifest_step(
        const CertificateNonceRecursiveManifest&, std::uint64_t,
        std::uint32_t, const bppp::accumulation::Digest&);
};

/** Public recursive step digests and their final ordered manifest. */
class CertificateNonceRecursiveManifestResolution
{
public:
    [[nodiscard]] const bppp::accumulation::Digest&
    certificate_context_digest() const noexcept
    {
        return certificate_context_digest_;
    }
    [[nodiscard]] std::uint64_t total_responses() const noexcept
    {
        return total_responses_;
    }
    [[nodiscard]] std::span<const bppp::accumulation::Digest>
    step_digests() const noexcept
    {
        return step_digests_;
    }
    [[nodiscard]] const CertificateNonceRecursiveManifest& manifest()
        const noexcept
    {
        return manifest_;
    }

private:
    CertificateNonceRecursiveManifestResolution(
        bppp::accumulation::Digest certificate_context_digest,
        std::uint64_t total_responses,
        std::vector<bppp::accumulation::Digest> step_digests,
        CertificateNonceRecursiveManifest manifest)
        : certificate_context_digest_(certificate_context_digest),
          total_responses_(total_responses),
          step_digests_(std::move(step_digests)),
          manifest_(std::move(manifest))
    {
    }

    bppp::accumulation::Digest certificate_context_digest_{};
    std::uint64_t total_responses_ = 0;
    std::vector<bppp::accumulation::Digest> step_digests_;
    CertificateNonceRecursiveManifest manifest_;

    friend Result<CertificateNonceRecursiveManifestResolution>
    certificate_nonce_recursive_manifest(
        const CertificateNonceLeafAccumulator&,
        const bppp::accumulation::Digest&,
        std::span<const CertificateNonceRecursiveResponseView>,
        purify_secp_context*);
};

/** Seed the recursive record manifest for one certificate trace. */
[[nodiscard]] Result<CertificateNonceRecursiveManifest>
certificate_nonce_recursive_manifest_seed(
    const bppp::accumulation::Digest& certificate_context_digest,
    std::uint64_t total_responses);

/** Append one recursive step digest at its exact canonical position. */
[[nodiscard]] Result<CertificateNonceRecursiveManifest>
certificate_nonce_recursive_manifest_step(
    const CertificateNonceRecursiveManifest& prior,
    std::uint64_t response_ordinal, std::uint32_t member_ordinal,
    const bppp::accumulation::Digest& step_digest);

/** Derive every recursive step digest for one public response. */
[[nodiscard]] Result<std::vector<bppp::accumulation::Digest>>
certificate_nonce_recursive_response_step_digests(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const CertificateNonceRecursiveResponseView& response,
    purify_secp_context* secp_context);

/** Resolve a complete ordered public response sequence and manifest. */
[[nodiscard]] Result<CertificateNonceRecursiveManifestResolution>
certificate_nonce_recursive_manifest(
    const CertificateNonceLeafAccumulator& leaf_accumulator,
    const bppp::accumulation::Digest& certificate_context_digest,
    std::span<const CertificateNonceRecursiveResponseView>
        ordered_responses,
    purify_secp_context* secp_context);

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
    [[nodiscard]] std::span<const bppp::accumulation::Digest>
    recursive_step_digests() const noexcept {
        return recursive_step_digests_;
    }

private:
    CertificateNonceParentPublicInputs(
        CertificateNonceResponseFrame frame, Bytes canonical_bytes,
        bppp::accumulation::Digest statement_digest,
        CertificateNonceResponseAuthorization authorization,
        bppp::PointBytes aggregate_nonce,
        std::vector<bppp::accumulation::Digest> leaf_bindings,
        std::vector<bppp::PointBytes> member_nonces,
        std::vector<bppp::accumulation::Digest> recursive_step_digests)
        : frame_(std::move(frame)),
          canonical_bytes_(std::move(canonical_bytes)),
          statement_digest_(statement_digest),
          authorization_(std::move(authorization)),
          aggregate_nonce_(aggregate_nonce),
          leaf_bindings_(std::move(leaf_bindings)),
          member_nonces_(std::move(member_nonces)),
          recursive_step_digests_(std::move(recursive_step_digests)) {}

    CertificateNonceResponseFrame frame_;
    Bytes canonical_bytes_;
    bppp::accumulation::Digest statement_digest_{};
    CertificateNonceResponseAuthorization authorization_;
    bppp::PointBytes aggregate_nonce_{};
    std::vector<bppp::accumulation::Digest> leaf_bindings_;
    std::vector<bppp::PointBytes> member_nonces_;
    std::vector<bppp::accumulation::Digest> recursive_step_digests_;
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
 * carries the exact statement digest. Those fields can feed the separately
 * qualified certificate-parent relation, but do not make this native
 * transport a recursively verified proof.
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

/** One reduction and bound two-claim transition in the linear receipt. */
struct CertificateNonceLinearMemberProof {
    bppp::accumulation::AlgebraicNormReductionProof reduction;
    bppp::accumulation::AlgebraicStepProof accumulation;
};

/** Ordered member transitions for one canonical certificate response. */
struct CertificateNonceLinearResponseProof {
    std::vector<CertificateNonceLinearMemberProof> members;
};

/**
 * Native proof chain matching the homogeneous certificate recurrence.
 *
 * The first transition consumes the canonical zero claim. Every later
 * transition consumes the preceding root and one authenticated nonce leaf.
 * This remains unaccepted until verify_linear_receipt() replays the complete
 * chain and calls the native decision exactly once.
 */
class CertificateNonceLinearReceipt {
public:
    static constexpr std::size_t kReductionSerializedSize = 890;
    static constexpr std::size_t kStepSerializedSize = 924;

    [[nodiscard]] static Result<CertificateNonceLinearReceipt> create(
        bppp::accumulation::Digest certificate_context_digest,
        std::vector<CertificateNonceLinearResponseProof> responses);

    [[nodiscard]] const bppp::accumulation::Digest&
    certificate_context_digest() const noexcept {
        return certificate_context_digest_;
    }
    [[nodiscard]] std::span<const CertificateNonceLinearResponseProof>
    responses() const noexcept
    {
        return responses_;
    }

private:
    CertificateNonceLinearReceipt(
        bppp::accumulation::Digest certificate_context_digest,
        std::vector<CertificateNonceLinearResponseProof> responses)
        : certificate_context_digest_(certificate_context_digest),
          responses_(std::move(responses))
    {
    }

    bppp::accumulation::Digest certificate_context_digest_{};
    std::vector<CertificateNonceLinearResponseProof> responses_;
};

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
    static constexpr std::size_t kRootClaimRounds = std::bit_width(
        2 * CertificateNonceLeafAccumulator::kNormVectorLength) - 1;
    static constexpr std::size_t kRootClaimSerializedSize =
        33 + 32 + kRootClaimRounds * 32;
    static_assert(kRootClaimSerializedSize == 481);
    /** Largest response sequence admitted by certificate framing. */
    static constexpr std::uint64_t kMaxResponses{
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

    /** Build the exact one-member-at-a-time native recurrence witness. */
    [[nodiscard]] Result<CertificateNonceLinearReceipt>
    prove_linear_receipt(
        std::span<const CertificateNonceResponseVerificationView>
            ordered_responses,
        purify_secp_context* secp_context) const;

    /** Replay the complete linear chain and decide its final pending root. */
    [[nodiscard]] Status verify_linear_receipt(
        const CertificateNonceLinearReceipt& receipt,
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
