// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <utility>

#include "purify/api.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable_roster.hpp"

namespace purify::accountable {

class RecoveryRootSetupAccumulator;

/** Transparent proof linking the aggregate signing scalar to a recovery root. */
class RecoveryRootSetupProof {
public:
    static constexpr unsigned char kSerializationVersion = 1;
    static constexpr std::size_t kInnerProofSize = 844;
    static constexpr std::size_t kSerializedSize = 163 + kInnerProofSize;

    RecoveryRootSetupProof(const RecoveryRootSetupProof&) = default;
    RecoveryRootSetupProof& operator=(const RecoveryRootSetupProof&) = default;
    RecoveryRootSetupProof(RecoveryRootSetupProof&&) noexcept = default;
    RecoveryRootSetupProof& operator=(RecoveryRootSetupProof&&) noexcept =
        default;

    [[nodiscard]] Result<Bytes> serialize(
        purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<RecoveryRootSetupProof> deserialize(
        std::span<const unsigned char> encoded,
        purify_secp_context* secp_context);

private:
    RecoveryRootSetupProof() = default;
    explicit RecoveryRootSetupProof(
        bppp::ExperimentalCircuitZkNormArgProof&& proof);

    [[nodiscard]] Status validate_encoding(
        purify_secp_context* secp_context) const;
    [[nodiscard]] bppp::ExperimentalCircuitZkNormArgProof
    circuit_proof() const;

    bppp::PointBytes raw_commitment_{};
    bppp::PointBytes mask_commitment_{};
    bppp::ScalarBytes t2_{};
    std::array<unsigned char, 32> public_commitment_dlog_nonce_{};
    bppp::ScalarBytes public_commitment_dlog_response_{};
    Bytes norm_proof_;

    friend Result<RecoveryRootSetupProof> prove_recovery_root_setup(
        const NonceHostBoundSigningRoster&, const UInt512&,
        const FieldElement&, purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
    friend Result<RecoveryBoundSigningRoster> verify_recovery_root_setup(
        NonceHostBoundSigningRoster, const UInt512&,
        const RecoveryRootSetupProof&, purify_secp_context*);
    friend class RecoveryRootSetupAccumulator;
};

/** Derive the canonical companion-curve recovery key from an extracted q. */
[[nodiscard]] Result<GeneratedKey> derive_recovery_root(
    const FieldElement& signing_scalar);

/**
 * Construct the transparent setup proof for a known aggregate signing scalar.
 *
 * This centralized API is also the reference relation for a future MPC prover.
 * It proves that the exact even-Y aggregate point and registered recovery root
 * are both derived from `signing_scalar`. Proof randomness is derived from the
 * secret witness and is never caller supplied. A future MPC implementation
 * must jointly derive and keep the equivalent prover seed secret.
 */
[[nodiscard]] Result<RecoveryRootSetupProof> prove_recovery_root_setup(
    const NonceHostBoundSigningRoster& roster,
    const UInt512& recovery_root, const FieldElement& signing_scalar,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/**
 * Verify aggregate-key knowledge and the recovery-root relation.
 *
 * The circuit wrapper's external-commitment proof establishes knowledge of the
 * exact final aggregate signing scalar. The root relation derives the exact
 * registered companion root from that same witness. Success is the sole
 * cryptographic constructor for `RecoveryBoundSigningRoster`; member consent is
 * separate application policy.
 */
[[nodiscard]] Result<RecoveryBoundSigningRoster> verify_recovery_root_setup(
    NonceHostBoundSigningRoster roster, const UInt512& recovery_root,
    const RecoveryRootSetupProof& proof,
    purify_secp_context* secp_context);

/** Validate an exposed scalar and recover the exact registered companion key. */
[[nodiscard]] Result<GeneratedKey> recover_registered_root(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    purify_secp_context* secp_context);

} // namespace purify::accountable
