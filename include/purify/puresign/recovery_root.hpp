// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <utility>

#include "purify/api.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable_roster.hpp"

namespace purify::accountable {

class RecoveryRootSetupAccumulator;
class RecoveryRootContribution;

/** Exact signed companion-curve points for one normalized MuSig share. */
class RecoveryRootShare {
public:
    static constexpr std::size_t kSerializedSize = 66;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<RecoveryRootShare> deserialize(
        std::span<const unsigned char> encoded);

    [[nodiscard]] const AffinePoint& first() const noexcept {
        return first_;
    }

    [[nodiscard]] const AffinePoint& second() const noexcept {
        return second_;
    }

private:
    RecoveryRootShare(AffinePoint first, AffinePoint second)
        : first_(std::move(first)), second_(std::move(second)) {}

    AffinePoint first_;
    AffinePoint second_;

    friend Result<RecoveryRootContribution>
    prove_recovery_root_contribution(
        const NonceHostBoundSigningRoster&, const CoalitionFormation&,
        std::size_t, const FieldElement&, purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
};

/** Validated full-point sum of one ordered roster's recovery shares. */
class RecoveryRootShareAggregate {
public:
    [[nodiscard]] std::size_t member_count() const noexcept {
        return member_count_;
    }

    [[nodiscard]] const AffinePoint& first_sum() const noexcept {
        return first_sum_;
    }

    [[nodiscard]] const AffinePoint& second_sum() const noexcept {
        return second_sum_;
    }

    [[nodiscard]] const UInt512& recovery_root() const noexcept {
        return recovery_root_;
    }

private:
    RecoveryRootShareAggregate(std::size_t member_count,
                               AffinePoint first_sum,
                               AffinePoint second_sum,
                               UInt512 recovery_root)
        : member_count_(member_count),
          first_sum_(std::move(first_sum)),
          second_sum_(std::move(second_sum)),
          recovery_root_(recovery_root) {}

    std::size_t member_count_ = 0;
    AffinePoint first_sum_{};
    AffinePoint second_sum_{};
    UInt512 recovery_root_{};

    friend Result<RecoveryRootShareAggregate>
    aggregate_recovery_root_shares(
        std::span<const RecoveryRootShare>);
};

/** Sum the exact signed shares in roster order without authorizing the root. */
[[nodiscard]] Result<RecoveryRootShareAggregate>
aggregate_recovery_root_shares(
    std::span<const RecoveryRootShare> ordered_shares);

/** Transparent mapping proof for one formation-bound effective MuSig share. */
class RecoveryRootContribution {
public:
    static constexpr unsigned char kSerializationVersion = 1;
    static constexpr std::size_t kNormProofSize = 974;
    static constexpr std::size_t kProofSerializedSize =
        162 + kNormProofSize;
    static constexpr std::size_t kSerializedSize =
        1 + RecoveryRootShare::kSerializedSize + kProofSerializedSize;

    RecoveryRootContribution(const RecoveryRootContribution&) = default;
    RecoveryRootContribution& operator=(
        const RecoveryRootContribution&) = default;
    RecoveryRootContribution(RecoveryRootContribution&&) noexcept = default;
    RecoveryRootContribution& operator=(
        RecoveryRootContribution&&) noexcept = default;

    [[nodiscard]] const RecoveryRootShare& share() const noexcept {
        return share_;
    }

    [[nodiscard]] Result<Bytes> serialize(
        purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<RecoveryRootContribution> deserialize(
        std::span<const unsigned char> encoded,
        purify_secp_context* secp_context);

private:
    explicit RecoveryRootContribution(RecoveryRootShare share)
        : share_(std::move(share)) {}

    [[nodiscard]] Status validate_encoding(
        purify_secp_context* secp_context) const;

    RecoveryRootShare share_;
    bppp::PointBytes raw_commitment_{};
    bppp::PointBytes mask_commitment_{};
    bppp::ScalarBytes t2_{};
    std::array<unsigned char, 32> public_commitment_dlog_nonce_{};
    bppp::ScalarBytes public_commitment_dlog_response_{};
    Bytes norm_proof_;

    friend Result<RecoveryRootContribution>
    prove_recovery_root_contribution(
        const NonceHostBoundSigningRoster&, const CoalitionFormation&,
        std::size_t, const FieldElement&, purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
    friend Result<bool> verify_recovery_root_contribution(
        const NonceHostBoundSigningRoster&, const CoalitionFormation&,
        std::size_t, const RecoveryRootContribution&, purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
};

static_assert(RecoveryRootContribution::kProofSerializedSize == 1136);
static_assert(RecoveryRootContribution::kSerializedSize == 1203);

struct RecoveryRootContributionCircuitShape {
    std::size_t relation_multiplications = 0;
    std::size_t padded_gates = 0;
};

/** Return the fixed centered-share circuit shape for qualification tests. */
[[nodiscard]] Result<RecoveryRootContributionCircuitShape>
recovery_root_contribution_circuit_shape_for_testing(
    const RecoveryRootShare& share);

/** Prove one member's exact effective share on secp and both Purify curves. */
[[nodiscard]] Result<RecoveryRootContribution>
prove_recovery_root_contribution(
    const NonceHostBoundSigningRoster& roster,
    const CoalitionFormation& formation, std::size_t member_index,
    const FieldElement& member_secret,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** Verify one ordered, formation-bound member contribution. */
[[nodiscard]] Result<bool> verify_recovery_root_contribution(
    const NonceHostBoundSigningRoster& roster,
    const CoalitionFormation& formation, std::size_t member_index,
    const RecoveryRootContribution& contribution,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** Transparent proof linking the aggregate signing scalar to a recovery root. */
class RecoveryRootSetupProof {
public:
    static constexpr unsigned char kSerializationVersion = 2;
    static constexpr std::size_t kNormProofSize = 844;
    static constexpr std::size_t kSerializedSize = 163 + kNormProofSize;

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

    [[nodiscard]] Status validate_encoding(
        purify_secp_context* secp_context) const;

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

static_assert(RecoveryRootSetupProof::kSerializedSize == 1007);

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

/** Validate an exposed scalar and recover the exact registered companion key. */
[[nodiscard]] Result<GeneratedKey> recover_registered_root(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    purify_secp_context* secp_context);

} // namespace purify::accountable
