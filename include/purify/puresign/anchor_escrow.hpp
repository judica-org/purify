// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "purify/api.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable_roster.hpp"

namespace purify::accountable {

class AnchorEscrowAccumulator;

/**
 * Digest of the application statement protected by one anchor escrow.
 *
 * Applications must commit the anchor/member identity, contract or bond,
 * purpose, and any domain or epoch fields that distinguish this escrow. The
 * digest must not include the escrow record itself.
 */
using AnchorEscrowContextDigest = std::array<unsigned char, 32>;

/** Public ciphertext carrying both scalars of one Purify recovery key. */
struct AnchorEscrowCiphertext {
    static constexpr std::size_t kSerializedSize = 192;

    std::array<UInt512, 2> ephemeral_keys{};
    std::array<FieldElement, 2> masked_scalars{};
};

/**
 * Fixed-size proof that an exact anchor recovery key is encrypted to a
 * recovery-bound coalition.
 */
class AnchorEscrowRecord {
public:
    static constexpr unsigned char kSerializationVersion = 2;
    static constexpr std::size_t kNormProofSize = 974;
    static constexpr std::size_t kProofPayloadSize = 1072;
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
    Bytes norm_proof_;

    friend Result<AnchorEscrowRecord> create_anchor_escrow(
        const RecoveryBoundSigningRoster&, const GeneratedKey&,
        const AnchorEscrowContextDigest&, purify_secp_context*,
        bppp::ExperimentalCircuitBackend*);
    friend Result<AnchorEscrowRecord>
    create_anchor_escrow_with_aux_randomness(
        const RecoveryBoundSigningRoster&, const GeneratedKey&,
        const AnchorEscrowContextDigest&, const bppp::ScalarBytes&,
        purify_secp_context*, bppp::ExperimentalCircuitBackend*);
    friend Result<bool> verify_anchor_escrow(
        const RecoveryBoundSigningRoster&, const UInt512&,
        const AnchorEscrowContextDigest&, const AnchorEscrowRecord&,
        purify_secp_context*, bppp::ExperimentalCircuitBackend*);
    friend class AnchorEscrowAccumulator;
};

static_assert(AnchorEscrowRecord::kProofPayloadSize ==
              2 * bppp::PointBytes{}.size() +
                  bppp::ScalarBytes{}.size() +
                  AnchorEscrowRecord::kNormProofSize);
static_assert(AnchorEscrowRecord::kSerializedSize == 1265);

/**
 * Encrypt an existing anchor recovery key to a verified coalition root.
 *
 * Operating-system auxiliary randomness is hedged with the anchor secret and
 * exact roster, root, and context statement. Separately tagged derivations
 * produce both ephemeral keys and the proof seed. The proof binds the exact
 * advertised anchor root, ciphertext, recovery-bound roster, and application
 * context.
 */
[[nodiscard]] Result<AnchorEscrowRecord> create_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/** Verify the exact public statement carried by an anchor escrow. */
[[nodiscard]] Result<bool> verify_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

/**
 * After a coalition scalar is exposed, verify and decrypt its exact anchor.
 *
 * This is intentionally the only public decryption operation: it first checks
 * that the scalar recovers the roster's registered root, then verifies the
 * escrow proof, and finally checks the recovered key against the advertised
 * anchor root.
 */
[[nodiscard]] Result<GeneratedKey> recover_escrowed_anchor(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache = nullptr);

} // namespace purify::accountable
