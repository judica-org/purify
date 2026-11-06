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

/** Stable identity of one manifest's claim on one formation permit. */
using CoalitionFormationId = std::array<unsigned char, 32>;

/** Exact predecessor output consumed by a coalition formation transaction. */
struct BitcoinOutpoint {
    BitcoinTransactionId transaction_id{};
    std::uint32_t output_index{};

    friend bool operator==(const BitcoinOutpoint&,
                           const BitcoinOutpoint&) = default;
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
        BitcoinGenesisHash genesis_hash,
        CoalitionDeploymentId deployment_id,
        BitcoinOutpoint permit,
        CoalitionManifestDigest manifest_digest);

    [[nodiscard]] const BitcoinGenesisHash& genesis_hash() const noexcept {
        return genesis_hash_;
    }

    [[nodiscard]] const CoalitionDeploymentId& deployment_id()
        const noexcept {
        return deployment_id_;
    }

    [[nodiscard]] const BitcoinOutpoint& permit() const noexcept {
        return permit_;
    }

    [[nodiscard]] const CoalitionManifestDigest& manifest_digest()
        const noexcept {
        return manifest_digest_;
    }

    [[nodiscard]] const CoalitionFormationId& id() const noexcept {
        return id_;
    }

private:
    CoalitionFormation(
        BitcoinGenesisHash genesis_hash,
        CoalitionDeploymentId deployment_id,
        BitcoinOutpoint permit,
        CoalitionManifestDigest manifest_digest,
        CoalitionFormationId id)
        : genesis_hash_(genesis_hash),
          deployment_id_(deployment_id),
          permit_(permit),
          manifest_digest_(manifest_digest),
          id_(id) {}

    BitcoinGenesisHash genesis_hash_{};
    CoalitionDeploymentId deployment_id_{};
    BitcoinOutpoint permit_{};
    CoalitionManifestDigest manifest_digest_{};
    CoalitionFormationId id_{};
};

} // namespace purify::accountable
