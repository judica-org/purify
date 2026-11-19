// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/recovery_root.hpp"

namespace purify::accountable::testing {

[[nodiscard]] Status recovery_root_share_count_valid_for_testing(
    std::size_t member_count);

struct RecoveryRootContributionCircuitShape {
    std::size_t relation_multiplications = 0;
    std::size_t padded_gates = 0;
};

/** Return the fixed centered-share circuit shape for qualification tests. */
[[nodiscard]] Result<RecoveryRootContributionCircuitShape>
recovery_root_contribution_circuit_shape_for_testing(
    const RecoveryRootShare& share);

[[nodiscard]] Result<bool>
recovery_root_contribution_assignment_satisfies_for_testing(
    const RecoveryRootShare& circuit_share,
    const RecoveryRootShare& assignment_share,
    const FieldElement& effective_scalar);

} // namespace purify::accountable::testing
