// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <vector>

#include "purify/puresign/accountable_responses.hpp"
#include "purify/puresign/construction_leaf_accumulation.hpp"
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
    purify::accountable::ConstructionLeafParentConstants parent_constants;
    purify::Bytes reduction_proof;
    purify::Bytes parent_step_proof;
};

/**
 * A native accumulation reference for setup and ordered anchor claims.
 *
 * This is neither a verified construction receipt nor a complete replay
 * of the Nova relation. The decided root checks the native setup
 * seed, anchor reductions, and ordered accumulation steps. Only Nova
 * binds the statement, manifest, count, and index transitions. A
 * production test must pass this exact setup, payload, and resolved
 * manifest through
 * `ConstructionParentVerifier` before treating the construction as
 * accepted.
 */
struct NativeAccumulationReferenceFixture {
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

[[nodiscard]] purify::Result<NativeAccumulationReferenceFixture>
make_native_accumulation_reference(
    const CoalitionFixture& coalition, std::size_t anchor_count,
    purify_secp_context* secp_context);

/**
 * Serializes the public witness needed to prove this exact construction.
 *
 * The fixed version selects the compiled parent suite. The bundle carries no
 * coalition or anchor secret and cannot select another basis, relation, or
 * verifier artifact.
 */
[[nodiscard]] purify::Result<purify::Bytes>
serialize_parent_prover_fixture(
    const NativeAccumulationReferenceFixture& fixture,
    purify_secp_context* secp_context);

/**
 * Sign one construction statement and one changed body with the same
 * proved nonces. The changed body has no parent-receipt fixture; this
 * demonstrates accountable response extraction, not two accepted
 * construction receipts.
 */
[[nodiscard]] purify::Result<purify::accountable::ExposedCoalitionKey>
expose_conflicting_coalition_key(
    CoalitionFixture& coalition,
    const purify::accountable::ConstructionReceiptStatementDigest&
        first_statement,
    purify_secp_context* secp_context);

} // namespace purify_test::slashability
