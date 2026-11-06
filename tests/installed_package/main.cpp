// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify.hpp"

#if !defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
#error "installed Purify target did not export construction parent support"
#endif

int main() {
    purify::accountable::BitcoinTransactionId transaction_id{};
    transaction_id.front() = 1;
    const auto formation =
        purify::accountable::CoalitionFormation::create({
            .permit = {transaction_id, 0},
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
