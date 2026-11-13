// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify/puresign/anchor_escrow.hpp"

namespace purify::accountable {

/**
 * Recover one ciphertext whose complete escrow relation was authenticated by
 * a stronger proof capability.
 *
 * This deliberately remains private to the library. Public callers must use
 * either recover_escrowed_anchor(), which verifies the child proof, or a
 * VerifiedConstructionReceipt, which authenticates the same relation through
 * its construction parent.
 */
[[nodiscard]] Result<AnchorPunishmentKey>
recover_authenticated_anchor_ciphertext(
    const GeneratedKey& recovered_recipient,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowCiphertext& ciphertext,
    purify_secp_context* secp_context);

/** Internal deterministic hedged constructor used by security-vector tests. */
[[nodiscard]] Result<AnchorEscrowRecord>
create_anchor_escrow_with_aux_randomness(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

struct AnchorEscrowCircuitShape {
    std::size_t relation_multiplications;
    std::size_t padded_gates;
};

/** Internal circuit-shape seam guarding the fixed 8,192-gate suite. */
[[nodiscard]] Result<AnchorEscrowCircuitShape>
anchor_escrow_circuit_shape_for_testing(
    const UInt512& recipient,
    const AnchorEscrowCiphertext& ciphertext);

} // namespace purify::accountable
