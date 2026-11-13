// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/recovery_root.hpp"

namespace purify::accountable::testing {

[[nodiscard]] Result<bool>
recovery_root_contribution_assignment_satisfies_for_testing(
    const RecoveryRootShare& share,
    const FieldElement& effective_scalar);

} // namespace purify::accountable::testing
