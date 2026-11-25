// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <utility>

#include "purify/accumulation.hpp"
#include "purify/puresign/anchor_escrow.hpp"

namespace purify::accountable {

class RecoveryRootContribution;
class RecoveryRootShare;

/**
 * Verifier-derived public constants consumed by one recursive parent leaf.
 *
 * `circuit_precommitment` is recomputed from the leaf's registered public
 * point and the raw commitment carried by the payload. The parent relation
 * proves that the same value is the hash of its own witness for those two
 * points, so its discrete-log check applies to the registered point itself.
 */
struct ConstructionLeafParentConstants {
    std::array<unsigned char, 32> circuit_binding_digest{};
    std::array<unsigned char, 32> raw_generator_digest{};
    bppp::ScalarBytes circuit_precommitment{};
    bppp::PointBytes coefficient_commitment{};
    bppp::PointBytes anchored_offset{};
};

/** Selected V4 construction leaf prepared with its exact public digest. */
class PreparedConstructionLeaf {
public:
    PreparedConstructionLeaf(const PreparedConstructionLeaf&) = delete;
    PreparedConstructionLeaf& operator=(
        const PreparedConstructionLeaf&) = delete;
    PreparedConstructionLeaf(PreparedConstructionLeaf&&) noexcept = default;
    PreparedConstructionLeaf& operator=(
        PreparedConstructionLeaf&&) noexcept = default;

    /** The proof's raw witness commitment, retained by the final payload. */
    [[nodiscard]] const bppp::PointBytes& raw_commitment() const noexcept {
        return raw_commitment_;
    }

    /** The precommitment this proof's transcript starts from. */
    [[nodiscard]] const bppp::ScalarBytes& circuit_precommitment()
        const noexcept {
        return circuit_precommitment_;
    }

    [[nodiscard]] const bppp::accumulation::AlgebraicPreparedNorm& norm()
        const noexcept {
        return norm_;
    }

private:
    PreparedConstructionLeaf(
        bppp::PointBytes raw_commitment,
        bppp::ScalarBytes circuit_precommitment,
        bppp::accumulation::AlgebraicPreparedNorm norm)
        : raw_commitment_(raw_commitment),
          circuit_precommitment_(circuit_precommitment),
          norm_(std::move(norm)) {}

    bppp::PointBytes raw_commitment_{};
    bppp::ScalarBytes circuit_precommitment_{};
    bppp::accumulation::AlgebraicPreparedNorm norm_;

    friend class ConstructionLeafAccumulator;
};

/**
 * Fixed-basis adapter for accumulating selected V4 construction proofs.
 *
 * The private constructor prevents callers from substituting another circuit
 * family or semantic basis. Each prepare() overload reconstructs one exact
 * circuit and transcript binding from its typed public statement. Its result
 * remains a pending norm obligation: the reduction, every accumulation
 * transition, and the final decide() call are all mandatory for acceptance.
 */
class ConstructionLeafAccumulator {
public:
    static constexpr std::size_t kNormVectorLength = 16384;

    ConstructionLeafAccumulator(const ConstructionLeafAccumulator&) =
        delete;
    ConstructionLeafAccumulator& operator=(
        const ConstructionLeafAccumulator&) = delete;
    ConstructionLeafAccumulator(ConstructionLeafAccumulator&&) noexcept =
        default;
    ConstructionLeafAccumulator& operator=(
        ConstructionLeafAccumulator&&) noexcept = default;

    [[nodiscard]] static Result<ConstructionLeafAccumulator> create(
        purify_secp_context* secp_context);

    [[nodiscard]] const bppp::accumulation::Basis& basis() const noexcept {
        return basis_;
    }

    /**
     * Derives the exact public constants bound by one parent recurrence leaf.
     *
     * `raw_commitment` is the child proof's raw witness commitment as carried
     * by the payload. The leaf precommitment is recomputed from it and the
     * registered punishment key; it is never accepted from the payload.
     *
     * This authenticates no proof and does not discharge an accumulation
     * obligation. Receipt acceptance must verify the recursive parent and
     * complete the final native decision.
     */
    [[nodiscard]] Result<ConstructionLeafParentConstants>
    derive_parent_constants(
        const RecoveryBoundSigningRoster& roster,
        const UInt512& advertised_anchor_root,
        const AnchorPunishmentPublicKey& punishment_key,
        const AnchorEscrowContextDigest& context_digest,
        const AnchorEscrowCiphertext& ciphertext,
        const bppp::PointBytes& raw_commitment,
        purify_secp_context* secp_context) const;

    /**
     * Derive a pending anchor descriptor from weak resolved context.
     *
     * This authenticates no escrow or recovery setup. It exists only for a
     * parent verifier that separately proves every setup leaf and completes
     * the final native decision.
     */
    [[nodiscard]] Result<ConstructionLeafParentConstants>
    derive_pending_anchor_parent_constants(
        const NonceHostBoundSigningRoster& roster,
        const UInt512& recovery_root,
        const UInt512& advertised_anchor_root,
        const AnchorPunishmentPublicKey& punishment_key,
        const AnchorEscrowContextDigest& context_digest,
        const AnchorEscrowCiphertext& ciphertext,
        const bppp::PointBytes& raw_commitment,
        purify_secp_context* secp_context) const;

    /** Derive one formation-bound recovery-contribution leaf descriptor. */
    [[nodiscard]] Result<ConstructionLeafParentConstants>
    derive_parent_constants(
        const NonceHostBoundSigningRoster& roster,
        const CoalitionFormation& formation,
        std::size_t member_index,
        const RecoveryRootShare& share,
        const bppp::PointBytes& raw_commitment,
        purify_secp_context* secp_context) const;

    [[nodiscard]] Result<PreparedConstructionLeaf> prepare(
        const RecoveryBoundSigningRoster& roster,
        const UInt512& advertised_anchor_root,
        const AnchorPunishmentPublicKey& punishment_key,
        const AnchorEscrowContextDigest& context_digest,
        const AnchorEscrowRecord& record,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

    [[nodiscard]] Result<PreparedConstructionLeaf> prepare(
        const NonceHostBoundSigningRoster& roster,
        const CoalitionFormation& formation,
        std::size_t member_index,
        const RecoveryRootContribution& contribution,
        purify_secp_context* secp_context,
        bppp::ExperimentalCircuitBackend* cache = nullptr) const;

private:
    explicit ConstructionLeafAccumulator(bppp::accumulation::Basis basis)
        : basis_(std::move(basis)) {}

    bppp::accumulation::Basis basis_;
};

} // namespace purify::accountable
