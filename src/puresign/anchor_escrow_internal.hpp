// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/anchor_escrow.hpp"

namespace purify::accountable {

/** Internal deterministic hedged constructor used by security-vector tests. */
[[nodiscard]] Result<AnchorEscrowRecord>
create_anchor_escrow_with_aux_randomness(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify::accountable
