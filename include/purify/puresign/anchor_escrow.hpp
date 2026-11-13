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

class ConstructionLeafAccumulator;
class VerifiedDistributedRecoverySetup;

/**
 * Digest of the application statement protected by one anchor escrow.
 *
 * Applications must commit the anchor/member identity, contract or bond,
 * purpose, and any domain or epoch fields that distinguish this escrow. The
 * digest must not include the escrow record itself.
 */
using AnchorEscrowContextDigest = std::array<unsigned char, 32>;

/** Canonical x-only BIP340 key authorized to punish one anchor. */
class AnchorPunishmentPublicKey {
public:
    AnchorPunishmentPublicKey(const AnchorPunishmentPublicKey&) = default;
    AnchorPunishmentPublicKey& operator=(
        const AnchorPunishmentPublicKey&) = default;
    AnchorPunishmentPublicKey(AnchorPunishmentPublicKey&&) noexcept =
        default;
    AnchorPunishmentPublicKey& operator=(
        AnchorPunishmentPublicKey&&) noexcept = default;

    [[nodiscard]] static Result<AnchorPunishmentPublicKey> create(
        const std::array<unsigned char, 32>& xonly,
        purify_secp_context* secp_context);

    [[nodiscard]] const std::array<unsigned char, 32>& xonly() const noexcept {
        return xonly_;
    }

    friend bool operator==(const AnchorPunishmentPublicKey&,
                           const AnchorPunishmentPublicKey&) = default;

private:
    explicit AnchorPunishmentPublicKey(
        const std::array<unsigned char, 32>& xonly) : xonly_(xonly) {}

    std::array<unsigned char, 32> xonly_{};

    friend class AnchorPunishmentKey;
};

/** Move-only recovered BIP340 punishment key with an even-Y secret. */
class AnchorPunishmentKey {
public:
    AnchorPunishmentKey(const AnchorPunishmentKey&) = delete;
    AnchorPunishmentKey& operator=(const AnchorPunishmentKey&) = delete;
    AnchorPunishmentKey(AnchorPunishmentKey&&) noexcept = default;
    AnchorPunishmentKey& operator=(AnchorPunishmentKey&&) noexcept = default;

    /** Parse and normalize one secret to its even-Y BIP340 representative. */
    [[nodiscard]] static Result<AnchorPunishmentKey> from_secret(
        std::array<unsigned char, 32> secret,
        purify_secp_context* secp_context);

    [[nodiscard]] const Bip340Key& bip340_key() const noexcept {
        return key_;
    }

    [[nodiscard]] const AnchorPunishmentPublicKey& public_key() const
        noexcept {
        return public_key_;
    }

private:
    explicit AnchorPunishmentKey(Bip340Key key)
        : key_(std::move(key)), public_key_(key_.xonly_pubkey) {}

    Bip340Key key_;
    AnchorPunishmentPublicKey public_key_;
};

/** Public ciphertext carrying one BIP340 punishment scalar. */
struct AnchorEscrowCiphertext {
    static constexpr std::size_t kSerializedSize = 96;

    UInt512 ephemeral_key{};
    FieldElement masked_scalar{};
};

/**
 * Fixed-size proof that one exact BIP340 punishment scalar is encrypted to a
 * recovery-bound coalition. Record version 4 fixes Purify's modern tagged
 * field-hash suite; legacy-hash builds reject proof construction and
 * verification. Parsing is syntax only.
 */
class AnchorEscrowRecord {
public:
    static constexpr unsigned char kSerializationVersion = 4;
    static constexpr std::size_t kNormProofSize = 974;
    static constexpr std::size_t kProofPayloadSize = 1136;
    static constexpr std::size_t kSerializedSize =
        1 + AnchorEscrowCiphertext::kSerializedSize + kProofPayloadSize;

    AnchorEscrowRecord(const AnchorEscrowRecord&) = default;
    AnchorEscrowRecord& operator=(const AnchorEscrowRecord&) = default;
    AnchorEscrowRecord(AnchorEscrowRecord&&) noexcept = default;
    AnchorEscrowRecord& operator=(AnchorEscrowRecord&&) noexcept = default;

    [[nodiscard]] const AnchorEscrowCiphertext& ciphertext() const noexcept {
        return ciphertext_;
    }

    [[nodiscard]] Result<Bytes> serialize(
        purify_secp_context* secp_context) const;
    [[nodiscard]] static Result<AnchorEscrowRecord> deserialize(
        std::span<const unsigned char> encoded,
        purify_secp_context* secp_context);

private:
    AnchorEscrowRecord() = default;

    [[nodiscard]] Status validate_encoding(
        purify_secp_context* secp_context) const;

    AnchorEscrowCiphertext ciphertext_{};
    bppp::PointBytes raw_commitment_{};
    bppp::PointBytes mask_commitment_{};
    bppp::ScalarBytes t2_{};
    std::array<unsigned char, 32> public_commitment_dlog_nonce_{};
    bppp::ScalarBytes public_commitment_dlog_response_{};
    Bytes norm_proof_;

    friend Result<AnchorEscrowRecord> create_anchor_escrow(
        const RecoveryBoundSigningRoster&, const UInt512&,
        const AnchorPunishmentKey&, const AnchorEscrowContextDigest&,
        purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
    friend Result<AnchorEscrowRecord>
    create_anchor_escrow_with_aux_randomness(
        const RecoveryBoundSigningRoster&, const UInt512&,
        const AnchorPunishmentKey&, const AnchorEscrowContextDigest&,
        const bppp::ScalarBytes&,
        purify_secp_context*, bppp::ExperimentalCircuitBackend*);
    friend Result<bool> verify_anchor_escrow(
        const RecoveryBoundSigningRoster&, const UInt512&,
        const AnchorPunishmentPublicKey&, const AnchorEscrowContextDigest&,
        const AnchorEscrowRecord&,
        purify_secp_context*, bppp::ExperimentalCircuitBackend*);
    friend class ConstructionLeafAccumulator;
};

static_assert(AnchorEscrowRecord::kProofPayloadSize ==
              2 * bppp::PointBytes{}.size() +
                  2 * bppp::ScalarBytes{}.size() +
                  std::array<unsigned char, 32>{}.size() +
                  AnchorEscrowRecord::kNormProofSize);
static_assert(AnchorEscrowRecord::kSerializedSize == 1233);

/**
 * Encrypt an anchor's existing punishment scalar to a verified coalition root.
 *
 * Operating-system auxiliary randomness is hedged with the punishment secret
 * and exact roster, root, and context statement. Separately tagged derivations
 * produce the ephemeral key and proof seed. The proof binds the exact
 * advertised anchor root, canonical punishment key, ciphertext,
 * recovery-bound roster, and application context. The advertised anchor root
 * must differ from the coalition recovery root so exposure cannot directly
 * reconstruct the advertised anchor key.
 */
[[nodiscard]] Result<AnchorEscrowRecord> create_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** Verify the exact public statement carried by an anchor escrow. */
[[nodiscard]] Result<bool> verify_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/**
 * After a coalition scalar is exposed, recover the anchor punishment key.
 *
 * This centralized path first checks that the scalar recovers the roster's
 * registered root, then verifies the escrow proof, decrypts the punishment
 * scalar, and checks its normalized even-Y BIP340 key against the exact
 * advertised punishment key. Distributed receipts use the separately typed
 * aggregate-bound recovery operation below.
 */
[[nodiscard]] Result<AnchorPunishmentKey> recover_escrowed_anchor(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** Recover an escrow through an authenticated distributed setup aggregate. */
[[nodiscard]] Result<AnchorPunishmentKey>
recover_distributed_escrowed_anchor(
    const VerifiedDistributedRecoverySetup& setup,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify::accountable
