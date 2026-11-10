// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify.hpp"

#if !defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
#error "installed Purify target did not export construction parent support"
#endif

int main() {
    purify::accountable::BitcoinGenesisHash genesis_hash{};
    purify::accountable::CoalitionDeploymentId deployment_id{};
    purify::accountable::BitcoinTransactionId transaction_id{};
    purify::accountable::CoalitionManifestDigest manifest_digest{};
    genesis_hash.front() = 1;
    deployment_id.front() = 2;
    transaction_id.front() = 3;
    manifest_digest.front() = 4;
    const auto formation =
        purify::accountable::CoalitionFormation::create({
            .genesis_hash = genesis_hash,
            .deployment_id = deployment_id,
            .permit = {transaction_id, 0},
            .manifest_digest = manifest_digest,
        });
    if (!formation.has_value()) {
        return 1;
    }

    const auto verifier =
        purify::accountable::ConstructionParentVerifier::load({});
    if (verifier.has_value()) {
        return 1;
    }
    return verifier.error().code == purify::ErrorCode::RangeViolation
        ? 0
        : 1;
}
