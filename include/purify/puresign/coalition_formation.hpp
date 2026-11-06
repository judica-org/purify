// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file coalition_formation.hpp
 * @brief One-shot Bitcoin bindings for accountable coalition formation.
 */

#pragma once

#include <array>
#include <cstdint>

#include "purify/error.hpp"

namespace purify::accountable {

/** Raw Bitcoin `uint256` bytes in consensus serialization order. */
using BitcoinGenesisHash = std::array<unsigned char, 32>;
using BitcoinTransactionId = std::array<unsigned char, 32>;

/** Application-defined identifier for one Char protocol deployment. */
using CoalitionDeploymentId = std::array<unsigned char, 32>;

/**
 * Digest of the acyclic, immutable coalition manifest.
 *
 * The manifest must exclude the formation transaction ID and every proof,
 * ciphertext, content hash, or receipt derived using the resulting coalition
 * core. It normally commits member identities, management keys, lifecycle
 * policy, and protocol versions not bound separately by Purify.
 */
using CoalitionManifestDigest = std::array<unsigned char, 32>;

/** Immutable coalition core bound by every accountable proof and response. */
using CoalitionCoreDigest = std::array<unsigned char, 32>;

/** Stable registry key for one deployment's claim on one Bitcoin output. */
using CoalitionPermitId = std::array<unsigned char, 32>;

/** Exact predecessor output consumed by a coalition formation transaction. */
struct BitcoinOutpoint {
    BitcoinTransactionId transaction_id{};
    std::uint32_t output_index{};

    friend bool operator==(const BitcoinOutpoint&,
                           const BitcoinOutpoint&) = default;
};

/** Named public inputs to one formation derivation. */
struct CoalitionFormationInput {
    BitcoinGenesisHash genesis_hash{};
    CoalitionDeploymentId deployment_id{};
    BitcoinOutpoint permit{};
    CoalitionManifestDigest manifest_digest{};
};

/**
 * A coalition manifest bound to a one-shot Bitcoin formation permit.
 *
 * Creation rejects Bitcoin's null outpoint. It does not establish that the
 * outpoint exists or is spent: the surrounding protocol must accept a
 * formation only from a transaction that consumes this exact predecessor.
 */
class CoalitionFormation {
public:
    [[nodiscard]] static Result<CoalitionFormation> create(
        CoalitionFormationInput input);

    [[nodiscard]] const BitcoinGenesisHash& genesis_hash() const noexcept {
        return input_.genesis_hash;
    }

    [[nodiscard]] const CoalitionDeploymentId& deployment_id()
        const noexcept {
        return input_.deployment_id;
    }

    [[nodiscard]] const BitcoinOutpoint& permit() const noexcept {
        return input_.permit;
    }

    [[nodiscard]] const CoalitionManifestDigest& manifest_digest()
        const noexcept {
        return input_.manifest_digest;
    }

    [[nodiscard]] const CoalitionPermitId& permit_id() const noexcept {
        return permit_id_;
    }

    [[nodiscard]] const CoalitionCoreDigest& core_digest() const noexcept {
        return core_digest_;
    }

private:
    CoalitionFormation(CoalitionFormationInput input,
                       CoalitionPermitId permit_id,
                       CoalitionCoreDigest core_digest)
        : input_(input),
          permit_id_(permit_id),
          core_digest_(core_digest) {}

    CoalitionFormationInput input_{};
    CoalitionPermitId permit_id_{};
    CoalitionCoreDigest core_digest_{};
};

} // namespace purify::accountable
