// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <vector>

#include "purify/puresign/accountable_responses.hpp"
#include "purify/puresign/anchor_escrow_accumulation.hpp"
#include "purify/puresign/construction_receipt_accumulation.hpp"
#include "purify/puresign/recovery_root.hpp"

namespace purify_test::slashability {

struct CoalitionFixture {
    purify::accountable::NonceHostBoundSigningRoster registry_roster;
    purify::accountable::RecoveryBoundSigningRoster recovery_roster;
    purify::accountable::RecoveryRootSetupProof setup_proof;
    purify::FieldElement signing_scalar;
    std::vector<purify::FieldElement> member_secrets;
    std::vector<purify::puresign_plusplus::KeyPair> nonce_signers;
    std::vector<purify::puresign_plusplus::PublicKey> nonce_hosts;
};

struct EscrowedAnchorFixture {
    purify::GeneratedKey recovery_key;
    purify::accountable::AnchorPunishmentKey punishment_key;
    purify::accountable::AnchorEscrowContextDigest context;
    purify::accountable::AnchorEscrowRecord record;
    purify::accountable::AnchorReference reference;
    purify::bppp::ScalarBytes circuit_precommitment;
    purify::accountable::AnchorEscrowParentConstants parent_constants;
};

/**
 * A complete native replay of the witness consumed by the Nova parent.
 *
 * This is deliberately not a verified construction receipt. The final
 * root proves that the native reference ancestry is internally
 * consistent,
 * but it does not authenticate omitted ancestry. A production test must
 * pass this
 * exact setup, payload, and resolved manifest through
 * `ConstructionParentVerifier` before treating the construction as
 * accepted.
 */
struct NativeConstructionWitnessFixture {
    purify::accountable::ConstructionReceiptAccumulator accumulator;
    purify::accountable::ResolvedConstructionSetup setup;
    purify::accountable::ConstructionReceiptPayload payload;
    std::vector<purify::accountable::ResolvedConstructionReceiptEntry>
        resolved_entries;
    std::vector<EscrowedAnchorFixture> anchors;
    purify::accountable::ConstructionReceiptStatementDigest statement;
    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        decided_reference_root;
};

[[nodiscard]] purify::Result<CoalitionFixture> make_all_evil_coalition(
    purify_secp_context* secp_context);

[[nodiscard]] purify::Result<NativeConstructionWitnessFixture>
make_native_construction_witness(
    const CoalitionFixture& coalition, std::size_t anchor_count,
    purify_secp_context* secp_context);

[[nodiscard]] purify::Result<purify::accountable::ExposedCoalitionKey>
expose_conflicting_coalition_key(
    CoalitionFixture& coalition, purify_secp_context* secp_context);

} // namespace purify_test::slashability
