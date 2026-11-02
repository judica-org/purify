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
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

struct AnchorEscrowCircuitShape {
    std::size_t unpadded_gates;
    std::size_t padded_gates;
};

/** Internal circuit-shape seam guarding the fixed 8,192-gate suite. */
[[nodiscard]] Result<AnchorEscrowCircuitShape>
anchor_escrow_circuit_shape_for_testing(
    const UInt512& recipient, const UInt512& anchor_root,
    const AnchorEscrowCiphertext& ciphertext);

} // namespace purify::accountable
