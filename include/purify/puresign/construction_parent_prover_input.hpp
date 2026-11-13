// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file construction_parent_prover_input.hpp
 * @brief Accepted public witness for one construction-parent proof.
 */

#pragma once

#include <span>

#include "purify/accumulation.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"
#include "purify/puresign/construction_receipt.hpp"

namespace purify::accountable {

/** Public proof material for one ordered distributed-recovery leaf. */
struct ConstructionParentSetupWitness {
    RecoveryRootContribution contribution;
    bppp::accumulation::AlgebraicNormReductionProof reduction;
    bppp::accumulation::AlgebraicStepProof step;
};

/** Public proof material for one ordered anchor-escrow leaf. */
struct ConstructionParentAnchorWitness {
    AnchorEscrowRecord record;
    bppp::accumulation::AlgebraicNormReductionProof reduction;
    bppp::accumulation::AlgebraicStepProof step;
};

/**
 * Serialize the exact accepted public witness consumed by the parent prover.
 *
 * Every leaf proof is reconstructed from the typed registry context, reduced,
 * accumulated in payload order, and discharged by native `decide()` before
 * bytes are returned. The caller cannot supply descriptors, precommitments,
 * public witness points, or a final root independently.
 *
 * The returned Wit3 frame contains no coalition, member, nonce-host, anchor,
 * or punishment secret. It is nevertheless bound to the verified distributed
 * setup capability required to prepare the anchor leaves.
 */
[[nodiscard]] Result<Bytes> serialize_accepted_construction_parent_wit3(
    const ResolvedConstructionSetup& resolved_setup,
    const VerifiedDistributedRecoverySetup& verified_setup,
    const ConstructionReceiptPayload& payload,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
    std::span<const ConstructionParentSetupWitness> setup_witnesses,
    std::span<const ConstructionParentAnchorWitness> anchor_witnesses,
    const ConstructionReceiptAccumulator& accumulator,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify::accountable
