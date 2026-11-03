// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cstddef>

#include "purify.hpp"
#include "purify/recursive/receipt_cycle.h"

#if !defined(PURIFY_HAS_RECEIPT_CYCLE) || !PURIFY_HAS_RECEIPT_CYCLE
#error "installed Purify target did not export receipt-cycle support"
#endif

#if !defined(PURIFY_HAS_CONSTRUCTION_PARENT_VERIFIER)
#error "installed Purify target did not export construction parent support"
#endif

int main() {
    std::size_t proof_size = 0;
    if (purify_receipt_cycle_proof_wire_len(
            nullptr, 0, &proof_size) != PURIFY_RECEIPT_CYCLE_MALFORMED) {
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
