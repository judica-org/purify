// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <utility>

#include "purify/accumulation.hpp"
#include "purify/puresign/bppp.hpp"

namespace purify::puresign_plusplus {

/** Verifier-derived public constants for one certificate nonce leaf. */
struct CertificateNonceLeafParentConstants {
    std::array<unsigned char, 32> circuit_binding_digest{};
    std::array<unsigned char, 32> raw_generator_digest{};
    bppp::PointBytes coefficient_commitment{};
    bppp::PointBytes anchored_offset{};

    friend bool operator==(
        const CertificateNonceLeafParentConstants&,
        const CertificateNonceLeafParentConstants&) = default;
};

/** Public material that identifies one certificate nonce leaf. */
struct CertificateNoncePublicLeafDescriptor {
    bppp::ScalarBytes circuit_precommitment{};
    bppp::PointBytes nonce_point{};
    bppp::accumulation::Digest leaf_binding{};

    friend bool operator==(
        const CertificateNoncePublicLeafDescriptor&,
        const CertificateNoncePublicLeafDescriptor&) = default;
};

/** One outer-authenticated certificate nonce proof pending reduction. */
class PreparedCertificateNonceLeaf {
public:
    PreparedCertificateNonceLeaf(const PreparedCertificateNonceLeaf&) =
        delete;
    PreparedCertificateNonceLeaf& operator=(
        const PreparedCertificateNonceLeaf&) = delete;
    PreparedCertificateNonceLeaf(
        PreparedCertificateNonceLeaf&&) noexcept = default;
    PreparedCertificateNonceLeaf& operator=(
        PreparedCertificateNonceLeaf&&) noexcept = default;

    [[nodiscard]] const bppp::ScalarBytes& circuit_precommitment()
        const noexcept {
        return circuit_precommitment_;
    }

    /** The exact full nonce point later summed by the parent relation. */
    [[nodiscard]] const bppp::PointBytes& nonce_point() const noexcept {
        return nonce_point_;
    }

    /** Exact public Purify nonce host used by the outer verifier. */
    [[nodiscard]] const std::array<unsigned char, 64>& nonce_host()
        const noexcept {
        return nonce_host_;
    }

    /** Exact topic bytes used by the outer verifier. */
    [[nodiscard]] std::span<const unsigned char> topic() const noexcept {
        return topic_;
    }

    /** Digest of the canonical V4 child proof bytes. */
    [[nodiscard]] const bppp::accumulation::Digest& proof_digest()
        const noexcept {
        return proof_digest_;
    }

    /** Typed binding of the host, topic, proof, and prepared norm. */
    [[nodiscard]] const bppp::accumulation::Digest& binding_digest()
        const noexcept {
        return binding_digest_;
    }

    /** Proof-free public descriptor for recursive manifest resolution. */
    [[nodiscard]] CertificateNoncePublicLeafDescriptor
    public_descriptor() const noexcept
    {
        return {
            circuit_precommitment_, nonce_point_, binding_digest_};
    }

    [[nodiscard]] const bppp::accumulation::AlgebraicPreparedNorm& norm()
        const noexcept {
        return norm_;
    }

    /** Exact verifier-derived constants consumed by the parent relation. */
    [[nodiscard]] const CertificateNonceLeafParentConstants&
    parent_constants() const noexcept {
        return parent_constants_;
    }

private:
    PreparedCertificateNonceLeaf(
        bppp::ScalarBytes circuit_precommitment,
        bppp::PointBytes nonce_point,
        std::array<unsigned char, 64> nonce_host,
        Bytes topic,
        bppp::accumulation::Digest proof_digest,
        bppp::accumulation::Digest binding_digest,
        CertificateNonceLeafParentConstants parent_constants,
        bppp::accumulation::AlgebraicPreparedNorm norm)
        : circuit_precommitment_(circuit_precommitment),
          nonce_point_(nonce_point), nonce_host_(nonce_host),
          topic_(std::move(topic)), proof_digest_(proof_digest),
          binding_digest_(binding_digest),
          parent_constants_(std::move(parent_constants)),
          norm_(std::move(norm)) {}

    bppp::ScalarBytes circuit_precommitment_{};
    bppp::PointBytes nonce_point_{};
    std::array<unsigned char, 64> nonce_host_{};
    Bytes topic_;
    bppp::accumulation::Digest proof_digest_{};
    bppp::accumulation::Digest binding_digest_{};
    CertificateNonceLeafParentConstants parent_constants_;
    bppp::accumulation::AlgebraicPreparedNorm norm_;

    friend class CertificateNonceLeafAccumulator;
};

/**
 * Purpose-owned adapter for topic-bound PureSign V4 certificate leaves.
 *
 * prepare() authenticates the exact outer proof and public nonce point, then
 * returns a pending norm obligation. A caller must verify its reduction,
 * every later accumulation transition, and the final native decision.
 */
class CertificateNonceLeafAccumulator {
public:
    static constexpr std::size_t kNormVectorLength = 4096;

    CertificateNonceLeafAccumulator(
        const CertificateNonceLeafAccumulator&) = delete;
    CertificateNonceLeafAccumulator& operator=(
        const CertificateNonceLeafAccumulator&) = delete;
    CertificateNonceLeafAccumulator(
        CertificateNonceLeafAccumulator&&) noexcept = default;
    CertificateNonceLeafAccumulator& operator=(
        CertificateNonceLeafAccumulator&&) noexcept = default;

    [[nodiscard]] static Result<CertificateNonceLeafAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const bppp::accumulation::Basis& basis() const noexcept {
        return basis_;
    }

    /**
     * Derive constants consumed by a certificate parent recurrence.
     *
     * This does not authenticate the proof or accept its norm obligation.
     * The parent must constrain the precommitment to the exact proof bytes.
     */
    [[nodiscard]] Result<CertificateNonceLeafParentConstants>
    derive_parent_constants(
        const PublicKey& public_key,
        const TopicProofCache& cache,
        const NonceProof& proof,
        const bppp::ScalarBytes& circuit_precommitment,
        purify_secp_context* secp_context) const;

    /**
     * Derive the same constants using only admitted public leaf data.
     *
     * The precommitment must be a canonical nonzero scalar and the nonce
     * point must be a finite canonical compressed point. This path does not
     * authenticate either value; the parent relation and public certificate
     * manifest must bind both to the accepted leaf.
     */
    [[nodiscard]] Result<CertificateNonceLeafParentConstants>
    derive_parent_constants_from_public_data(
        const PublicKey& public_key,
        const TopicProofCache& cache,
        const bppp::ScalarBytes& circuit_precommitment,
        const bppp::PointBytes& nonce_point,
        purify_secp_context* secp_context) const;

    [[nodiscard]] Result<PreparedCertificateNonceLeaf> prepare(
        const PublicKey& public_key,
        const TopicProofCache& cache,
        const NonceProof& proof,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* circuit_cache = nullptr) const;

private:
    explicit CertificateNonceLeafAccumulator(
        bppp::accumulation::Basis basis)
        : basis_(std::move(basis)) {}

    bppp::accumulation::Basis basis_;
};

} // namespace purify::puresign_plusplus
