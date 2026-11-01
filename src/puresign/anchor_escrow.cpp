// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/anchor_escrow.hpp"
#include "purify/puresign/anchor_escrow_accumulation.hpp"
#include "../protocol/algebraic_circuit_accumulation.hpp"
#include "../protocol/algebraic_circuit_proof.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "purify/puresign/recovery_root.hpp"
#include "purify/secp_bridge.h"
#include "anchor_escrow_internal.hpp"

namespace purify::accountable {
namespace {

using PointBytes = bppp::PointBytes;
using PointPair = std::pair<JacobianPoint, JacobianPoint>;

const TaggedHash kRandomnessStatementHash(
    "Purify/Accountable/AnchorEscrowRandomnessStatement/v1");
const TaggedHash kRandomnessMasterHash(
    "Purify/Accountable/AnchorEscrowRandomnessMaster/v1");
const TaggedHash kFirstEphemeralHash(
    "Purify/Accountable/AnchorEscrowFirstEphemeral/v1");
const TaggedHash kSecondEphemeralHash(
    "Purify/Accountable/AnchorEscrowSecondEphemeral/v1");
const TaggedHash kProofSeedHash(
    "Purify/Accountable/AnchorEscrowProofSeed/v2");

template <typename T>
class WipeObjectOnDestruction {
public:
    explicit WipeObjectOnDestruction(T& value) noexcept : value_(&value) {
        static_assert(std::is_trivially_destructible_v<T>);
    }
    WipeObjectOnDestruction(const WipeObjectOnDestruction&) = delete;
    WipeObjectOnDestruction& operator=(const WipeObjectOnDestruction&) =
        delete;
    ~WipeObjectOnDestruction() {
        detail::secure_clear_bytes(value_, sizeof(T));
    }

private:
    T* value_;
};

template <typename T>
class WipeVectorOnDestruction {
public:
    explicit WipeVectorOnDestruction(std::vector<T>& value) noexcept
        : value_(&value) {
        static_assert(std::is_trivially_destructible_v<T>);
    }
    WipeVectorOnDestruction(const WipeVectorOnDestruction&) = delete;
    WipeVectorOnDestruction& operator=(const WipeVectorOnDestruction&) =
        delete;
    ~WipeVectorOnDestruction() {
        detail::secure_clear_bytes(value_->data(),
                                   value_->size() * sizeof(T));
    }

private:
    std::vector<T>* value_;
};

struct SecretBytes32 {
    bppp::ScalarBytes value{};

    SecretBytes32() = default;
    SecretBytes32(const SecretBytes32&) = delete;
    SecretBytes32& operator=(const SecretBytes32&) = delete;
    ~SecretBytes32() {
        detail::secure_clear_bytes(value.data(), value.size());
    }
};

class WipeAssignmentOnDestruction {
public:
    explicit WipeAssignmentOnDestruction(BulletproofAssignmentData& value)
        : value_(&value) {}
    WipeAssignmentOnDestruction(const WipeAssignmentOnDestruction&) = delete;
    WipeAssignmentOnDestruction& operator=(
        const WipeAssignmentOnDestruction&) = delete;
    ~WipeAssignmentOnDestruction() {
        wipe(value_->left);
        wipe(value_->right);
        wipe(value_->output);
        wipe(value_->commitments);
    }

private:
    static void wipe(BulletproofWitnessColumn& values) {
        detail::secure_clear_bytes(values.data(),
                                   values.size() * sizeof(FieldElement));
    }

    BulletproofAssignmentData* value_;
};

struct EscrowOpening {
    const SecretKey& payload;
    std::array<const GeneratedKey*, 2> ephemeral;
};

Status require_roster(const RecoveryBoundSigningRoster& roster,
                      const char* label) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput, label);
    }
    return {};
}

Result<PointPair> decode_root(const UInt512& encoded,
                              const char* label) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, unpack_public(encoded), label);
    PURIFY_ASSIGN_OR_RETURN(const auto& first_x,
                            FieldElement::try_from_uint256(coords.first),
                            label);
    PURIFY_ASSIGN_OR_RETURN(const auto& second_x,
                            FieldElement::try_from_uint256(coords.second),
                            label);
    const auto first = curve1().lift_x(first_x);
    const auto second = curve2().lift_x(second_x);
    if (!first || !second || first->infinity || second->infinity ||
        !curve1().mul(*first, order_n1()).infinity ||
        !curve2().mul(*second, order_n2()).infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    return PointPair{*first, *second};
}

Result<GeneratedKey> key_from_scalars(UInt256 first, UInt256 second) {
    WipeObjectOnDestruction first_guard(first);
    WipeObjectOnDestruction second_guard(second);
    if (first.is_zero() || second.is_zero() || half_n1() < first ||
        half_n2() < second) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "anchor_escrow:canonical_plaintext");
    }
    first.sub_assign(UInt256::one());
    second.sub_assign(UInt256::one());
    auto packed = multiply(half_n1(), second);
    WipeObjectOnDestruction packed_guard(packed);
    packed.add_assign(widen<8>(first));
    PURIFY_ASSIGN_OR_RETURN(auto secret, SecretKey::from_packed(packed),
                            "anchor_escrow:plaintext_secret");
    return derive_key(std::move(secret));
}

Result<FieldElement> shared_pad(const SecretKey& secret,
                                const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(auto scalars, unpack_secret(secret.packed()),
                            "anchor_escrow:shared_secret");
    WipeObjectOnDestruction scalars_guard(scalars);
    PURIFY_ASSIGN_OR_RETURN(const auto& points,
                            decode_root(peer, "anchor_escrow:shared_peer"),
                            "anchor_escrow:shared_peer");
    PURIFY_ASSIGN_OR_RETURN(
        auto first,
        curve1().mul_secret_affine(points.first, scalars.first),
        "anchor_escrow:shared_first");
    WipeObjectOnDestruction first_guard(first);
    PURIFY_ASSIGN_OR_RETURN(
        auto second,
        curve2().mul_secret_affine(points.second, scalars.second),
        "anchor_escrow:shared_second");
    WipeObjectOnDestruction second_guard(second);
    return combine(first.x, second.x);
}

Result<AnchorEscrowCiphertext> encrypt_anchor(
    const UInt512& recipient, const EscrowOpening& opening) {
    if (opening.ephemeral[0]->public_key ==
        opening.ephemeral[1]->public_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:duplicate_ephemeral");
    }
    PURIFY_ASSIGN_OR_RETURN(auto payload,
                            unpack_secret(opening.payload.packed()),
                            "anchor_escrow:payload");
    WipeObjectOnDestruction payload_guard(payload);
    AnchorEscrowCiphertext out;
    for (std::size_t i = 0; i < out.ephemeral_keys.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pad,
            shared_pad(opening.ephemeral[i]->secret, recipient),
            "anchor_escrow:encrypt_pad");
        WipeObjectOnDestruction pad_guard(pad);
        out.ephemeral_keys[i] = opening.ephemeral[i]->public_key;
        const auto& value = i == 0 ? payload.first : payload.second;
        FieldElement plaintext = FieldElement::from_uint256(value);
        WipeObjectOnDestruction plaintext_guard(plaintext);
        out.masked_scalars[i] = plaintext + pad;
    }
    return out;
}

Expr exceeds_bound(Transcript& transcript, const std::vector<Expr>& bits,
                   const UInt256& bound) {
    Expr equal_prefix(1);
    Expr exceeds(0);
    for (std::size_t i = bits.size(); i != 0; --i) {
        const Expr same_and_one =
            transcript.mul(equal_prefix, bits[i - 1]);
        if (bound.bit(i - 1)) {
            equal_prefix = same_and_one;
        } else {
            exceeds = exceeds + same_and_one;
            equal_prefix = equal_prefix - same_and_one;
        }
    }
    return exceeds;
}

std::vector<Expr> ordinary_bits(Transcript& transcript,
                                const std::optional<UInt256>& value) {
    std::vector<Expr> bits;
    bits.reserve(255);
    for (std::size_t i = 0; i < 255; ++i) {
        auto bit = value
                       ? std::optional<FieldElement>(
                             FieldElement::from_u64(value->bit(i)))
                       : std::nullopt;
        WipeObjectOnDestruction bit_guard(bit);
        bits.push_back(transcript.boolean(transcript.secret(bit)));
    }
    return bits;
}

std::vector<Expr> signed_window_bits(Transcript& transcript,
                                     const std::vector<Expr>& ordinary) {
    auto bits = ordinary;
    for (std::size_t i = 3; i < bits.size(); i += 3) {
        bits[i] = Expr(1) - ordinary[i];
        for (std::size_t offset : {1U, 2U}) {
            bits[i - offset] =
                Expr(1) - ordinary[i] - ordinary[i - offset] +
                2 * transcript.mul(ordinary[i], ordinary[i - offset]);
        }
    }
    return bits;
}

Expr canonical_payload(Transcript& transcript, const std::vector<Expr>& bits,
                       UInt256 limit) {
    limit.sub_assign(UInt256::one());
    transcript.equal(exceeds_bound(transcript, bits, limit), Expr(0));
    Expr value(1);
    FieldElement power = FieldElement::one();
    for (const auto& bit : bits) {
        value = value + power * bit;
        power = power + power;
    }
    return value;
}

Result<CircuitMainResult> escrow_relation(
    Transcript& transcript, const UInt512& recipient,
    const AnchorEscrowCiphertext& ciphertext,
    const EscrowOpening* opening) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& receiver,
        decode_root(recipient, "anchor_escrow:recipient"),
        "anchor_escrow:recipient");
    std::array<std::pair<UInt256, UInt256>, 2> ephemeral_coords;
    for (std::size_t i = 0; i < ciphertext.ephemeral_keys.size(); ++i) {
        PURIFY_RETURN_IF_ERROR(
            decode_root(ciphertext.ephemeral_keys[i],
                        "anchor_escrow:ephemeral"),
            "anchor_escrow:ephemeral");
        PURIFY_ASSIGN_OR_RETURN(
            ephemeral_coords[i], unpack_public(ciphertext.ephemeral_keys[i]),
            "anchor_escrow:ephemeral_coords");
    }

    std::array<std::optional<UInt256>, 2> payload_values;
    WipeObjectOnDestruction payload_values_guard(payload_values);
    if (opening != nullptr) {
        PURIFY_ASSIGN_OR_RETURN(auto pair,
                                unpack_secret(opening->payload.packed()),
                                "anchor_escrow:payload_witness");
        WipeObjectOnDestruction pair_guard(pair);
        payload_values = {pair.first, pair.second};
        for (auto& value : payload_values) {
            value->sub_assign(UInt256::one());
        }
    }

    std::array<std::vector<Expr>, 2> payload_bits{
        ordinary_bits(transcript, payload_values[0]),
        ordinary_bits(transcript, payload_values[1])};
    std::array<std::array<std::vector<Expr>, 2>, 2> ephemeral_bits;
    for (std::size_t i = 0; i < ephemeral_bits.size(); ++i) {
        std::array<std::vector<int>, 2> values{
            std::vector<int>(255, -1), std::vector<int>(255, -1)};
        WipeVectorOnDestruction first_values_guard(values[0]);
        WipeVectorOnDestruction second_values_guard(values[1]);
        if (opening != nullptr) {
            PURIFY_ASSIGN_OR_RETURN(
                auto pair,
                unpack_secret(opening->ephemeral[i]->secret.packed()),
                "anchor_escrow:ephemeral_secret");
            WipeObjectOnDestruction pair_guard(pair);
            PURIFY_ASSIGN_OR_RETURN(
                values[0], key_to_bits(pair.first, half_n1()),
                "anchor_escrow:ephemeral_first_bits");
            PURIFY_ASSIGN_OR_RETURN(
                values[1], key_to_bits(pair.second, half_n2()),
                "anchor_escrow:ephemeral_second_bits");
        }
        for (std::size_t component = 0; component < 2; ++component) {
            auto& bits = ephemeral_bits[i][component];
            bits.reserve(255);
            for (const int& bit : values[component]) {
                auto bit_value =
                    bit < 0
                        ? std::optional<FieldElement>{}
                        : std::optional<FieldElement>(
                              FieldElement::from_int(bit));
                WipeObjectOnDestruction bit_value_guard(bit_value);
                bits.push_back(transcript.boolean(
                    transcript.secret(bit_value)));
            }
        }
    }

    const std::array<Expr, 2> plaintext{
        canonical_payload(transcript, payload_bits[0], half_n1()),
        canonical_payload(transcript, payload_bits[1], half_n2())};
    const auto first_bits = signed_window_bits(transcript, payload_bits[0]);
    const auto second_bits = signed_window_bits(transcript, payload_bits[1]);
    const Expr first_key = circuit_ec_multiply_x(
        curve1(), transcript, generator1(), first_bits);
    const Expr second_key = circuit_ec_multiply_x(
        curve2(), transcript, generator2(), second_bits);
    for (std::size_t i = 0; i < ephemeral_bits.size(); ++i) {
        const auto& bits = ephemeral_bits[i];
        const Expr ephemeral_first = circuit_ec_multiply_x(
            curve1(), transcript, generator1(), bits[0]);
        const Expr ephemeral_second = circuit_ec_multiply_x(
            curve2(), transcript, generator2(), bits[1]);
        transcript.equal(
            ephemeral_first,
            Expr(FieldElement::from_uint256(ephemeral_coords[i].first)));
        transcript.equal(
            ephemeral_second,
            Expr(FieldElement::from_uint256(ephemeral_coords[i].second)));
        const Expr shared_first = circuit_ec_multiply_x(
            curve1(), transcript, receiver.first, bits[0]);
        const Expr shared_second = circuit_ec_multiply_x(
            curve2(), transcript, receiver.second, bits[1]);
        transcript.equal(
            plaintext[i] +
                circuit_combine(transcript, shared_first, shared_second),
            Expr(ciphertext.masked_scalars[i]));
    }
    return CircuitMainResult{Expr(1), first_key, second_key, 6 * 255};
}

Result<NativeBulletproofCircuit> public_escrow_circuit(
    const UInt512& recipient, const UInt512& payload,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(decode_root(payload, "anchor_escrow:anchor_root"),
                           "anchor_escrow:anchor_root");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto& relation,
        escrow_relation(transcript, recipient, ciphertext, nullptr),
        "anchor_escrow:relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "anchor_escrow:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x,
                              relation.out),
        "anchor_escrow:bind_anchor");
    return bp.native_circuit();
}

Result<BulletproofAssignmentData> escrow_assignment(
    const UInt512& recipient, const UInt512& payload,
    const AnchorEscrowCiphertext& ciphertext,
    const EscrowOpening& opening) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto& relation,
        escrow_relation(transcript, recipient, ciphertext, &opening),
        "anchor_escrow:witness_relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "anchor_escrow:lower_witness");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x,
                              relation.out),
        "anchor_escrow:bind_witness");
    return bp.assignment_data(transcript.varmap(), FieldElement::one());
}

Bytes ciphertext_bytes(const AnchorEscrowCiphertext& ciphertext) {
    Bytes out;
    out.reserve(AnchorEscrowCiphertext::kSerializedSize);
    for (std::size_t i = 0; i < ciphertext.ephemeral_keys.size(); ++i) {
        const auto ephemeral = ciphertext.ephemeral_keys[i].to_bytes_be();
        const auto masked = ciphertext.masked_scalars[i].to_bytes_be();
        out.insert(out.end(), ephemeral.begin(), ephemeral.end());
        out.insert(out.end(), masked.begin(), masked.end());
    }
    assert(out.size() == AnchorEscrowCiphertext::kSerializedSize);
    return out;
}

PointBytes roster_point(const RecoveryBoundSigningRoster& roster) {
    PointBytes out{};
    out[0] = 0x02;
    std::copy(roster.signing_key().begin(), roster.signing_key().end(),
              out.begin() + 1);
    return out;
}

Result<bppp::ScalarBytes> escrow_randomness_statement(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest) {
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:randomness_roster");
    const auto recovery_root = roster.recovery_root().to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto signing_key = roster_point(roster);
    return kRandomnessStatementHash.digest_many<7>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root, anchor_root,
        context_digest,
    });
}

Result<Bytes> escrow_binding(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:roster");
    const auto recovery_root = roster.recovery_root().to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto signing_key = roster_point(roster);
    static const TaggedHash hash("Purify/Accountable/AnchorEscrow/v2");
    const auto digest = hash.digest_many<8>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root, anchor_root, encrypted,
        context_digest,
    });
    return Bytes(digest.begin(), digest.end());
}

bool has_zero_dlog(
    const bppp::candidate::CircuitZkNormArgProofV4& proof) {
    return std::all_of(
               proof.public_commitment_dlog_nonce.begin(),
               proof.public_commitment_dlog_nonce.end(),
               [](unsigned char byte) { return byte == 0; }) &&
           std::all_of(
               proof.public_commitment_dlog_response.begin(),
               proof.public_commitment_dlog_response.end(),
               [](unsigned char byte) { return byte == 0; });
}

Result<GeneratedKey> decrypt_anchor(
    const GeneratedKey& recipient, const UInt512& advertised_anchor_root,
    const AnchorEscrowCiphertext& ciphertext) {
    std::array<UInt256, 2> plaintext;
    WipeObjectOnDestruction plaintext_guard(plaintext);
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pad, shared_pad(recipient.secret,
                                 ciphertext.ephemeral_keys[i]),
            "anchor_escrow:decrypt_pad");
        WipeObjectOnDestruction pad_guard(pad);
        plaintext[i] =
            (ciphertext.masked_scalars[i] - pad).to_uint256();
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto recovered, key_from_scalars(plaintext[0], plaintext[1]),
        "anchor_escrow:decrypt_plaintext");
    if (recovered.public_key != advertised_anchor_root) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:wrong_plaintext");
    }
    return recovered;
}

} // namespace

Status AnchorEscrowRecord::validate_encoding(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:record"),
        "anchor_escrow:record");
    for (const auto& ephemeral : ciphertext_.ephemeral_keys) {
        PURIFY_RETURN_IF_ERROR(
            decode_root(ephemeral, "anchor_escrow:ciphertext_ephemeral"),
            "anchor_escrow:ciphertext_ephemeral");
    }
    if (ciphertext_.ephemeral_keys[0] ==
        ciphertext_.ephemeral_keys[1]) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:duplicate_ephemeral");
    }
    static constexpr std::size_t kRoundCount = 14;
    static_assert(kNormProofSize == 65 * kRoundCount + 64);
    const bppp::candidate::CircuitZkNormArgProofV4 proof{
        raw_commitment_, mask_commitment_, t2_, {}, {}, norm_proof_};
    return bppp::candidate::
        validate_circuit_zk_norm_arg_proof_v4_fixed_encoding(
            proof, bppp::candidate::CircuitCommitmentModeV4::Hidden,
            kRoundCount, secp_context);
}

Result<Bytes> AnchorEscrowRecord::serialize(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(validate_encoding(secp_context),
                           "anchor_escrow:serialize");
    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    const auto encrypted = ciphertext_bytes(ciphertext_);
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    out.insert(out.end(), raw_commitment_.begin(), raw_commitment_.end());
    out.insert(out.end(), mask_commitment_.begin(), mask_commitment_.end());
    out.insert(out.end(), t2_.begin(), t2_.end());
    out.insert(out.end(), norm_proof_.begin(), norm_proof_.end());
    assert(out.size() == kSerializedSize);
    return out;
}

Result<AnchorEscrowRecord> AnchorEscrowRecord::deserialize(
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context) {
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "anchor_escrow:deserialize_size");
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "anchor_escrow:deserialize_version");
    }
    AnchorEscrowRecord out;
    std::size_t offset = 1;
    for (std::size_t i = 0; i < out.ciphertext_.ephemeral_keys.size(); ++i) {
        out.ciphertext_.ephemeral_keys[i] =
            UInt512::from_bytes_be(encoded.data() + offset, 64);
        offset += 64;
        std::array<unsigned char, 32> masked{};
        std::copy_n(encoded.begin() + offset, masked.size(), masked.begin());
        offset += masked.size();
        PURIFY_ASSIGN_OR_RETURN(
            out.ciphertext_.masked_scalars[i],
            FieldElement::try_from_bytes32(masked),
            "anchor_escrow:deserialize_masked");
    }
    std::copy_n(encoded.begin() + offset, out.raw_commitment_.size(),
                out.raw_commitment_.begin());
    offset += out.raw_commitment_.size();
    std::copy_n(encoded.begin() + offset, out.mask_commitment_.size(),
                out.mask_commitment_.begin());
    offset += out.mask_commitment_.size();
    std::copy_n(encoded.begin() + offset, out.t2_.size(),
                out.t2_.begin());
    offset += out.t2_.size();
    out.norm_proof_.assign(encoded.begin() + offset, encoded.end());
    PURIFY_RETURN_IF_ERROR(out.validate_encoding(secp_context),
                           "anchor_escrow:deserialize");
    return out;
}

Result<AnchorEscrowRecord> create_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create"),
        "anchor_escrow:create");
    SecretBytes32 auxiliary_randomness;
    PURIFY_RETURN_IF_ERROR(fill_secure_random(auxiliary_randomness.value),
                           "anchor_escrow:auxiliary_randomness");
    return create_anchor_escrow_with_aux_randomness(
        roster, anchor_recovery_key, context_digest,
        auxiliary_randomness.value, secp_context, cache);
}

Result<AnchorEscrowRecord> create_anchor_escrow_with_aux_randomness(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create_aux"),
        "anchor_escrow:create_aux");
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:create_roster");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& derived_anchor, derive_key(anchor_recovery_key.secret),
        "anchor_escrow:derive_anchor");
    if (derived_anchor.public_key != anchor_recovery_key.public_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:anchor_keypair");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& randomness_statement,
        escrow_randomness_statement(roster,
                                    anchor_recovery_key.public_key,
                                    context_digest),
        "anchor_escrow:randomness_statement");
    auto packed_anchor = anchor_recovery_key.secret.packed().to_bytes_be();
    WipeObjectOnDestruction packed_anchor_guard(packed_anchor);
    SecretBytes32 randomness_master;
    {
        auto digest = kRandomnessMasterHash.digest_many<3>({
            auxiliary_randomness, packed_anchor, randomness_statement});
        WipeObjectOnDestruction digest_guard(digest);
        randomness_master.value = digest;
    }
    SecretBytes32 first_seed;
    {
        auto digest = kFirstEphemeralHash.digest(randomness_master.value);
        WipeObjectOnDestruction digest_guard(digest);
        first_seed.value = digest;
    }
    SecretBytes32 second_seed;
    {
        auto digest = kSecondEphemeralHash.digest(randomness_master.value);
        WipeObjectOnDestruction digest_guard(digest);
        second_seed.value = digest;
    }
    PURIFY_ASSIGN_OR_RETURN(auto first_ephemeral,
                            generate_key(first_seed.value),
                            "anchor_escrow:first_ephemeral");
    PURIFY_ASSIGN_OR_RETURN(auto second_ephemeral,
                            generate_key(second_seed.value),
                            "anchor_escrow:second_ephemeral");
    if (first_ephemeral.public_key == second_ephemeral.public_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:duplicate_ephemeral");
    }
    const EscrowOpening opening{
        anchor_recovery_key.secret,
        {&first_ephemeral, &second_ephemeral},
    };
    PURIFY_ASSIGN_OR_RETURN(
        const auto& ciphertext,
        encrypt_anchor(roster.recovery_root(), opening),
        "anchor_escrow:encrypt");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit,
        public_escrow_circuit(roster.recovery_root(),
                              anchor_recovery_key.public_key, ciphertext),
        "anchor_escrow:public_circuit");
    PURIFY_ASSIGN_OR_RETURN(
        auto assignment,
        escrow_assignment(roster.recovery_root(),
                          anchor_recovery_key.public_key, ciphertext,
                          opening),
        "anchor_escrow:assignment");
    WipeAssignmentOnDestruction assignment_guard(assignment);
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding,
        escrow_binding(roster, anchor_recovery_key.public_key,
                       context_digest, ciphertext),
        "anchor_escrow:binding");
    SecretBytes32 prover_seed;
    {
        auto digest = kProofSeedHash.digest_many<2>({
            randomness_master.value, binding});
        WipeObjectOnDestruction digest_guard(digest);
        prover_seed.value = digest;
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::prove_circuit_zk_norm_arg_v4(
            circuit, assignment, prover_seed.value, secp_context, binding,
            cache),
        "anchor_escrow:prove");
    if (!has_zero_dlog(publication.proof)) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "anchor_escrow:unexpected_dlog");
    }
    AnchorEscrowRecord record;
    record.ciphertext_ = ciphertext;
    record.raw_commitment_ = publication.proof.raw_commitment;
    record.mask_commitment_ = publication.proof.mask_commitment;
    record.t2_ = publication.proof.t2;
    record.norm_proof_ = std::move(publication.proof.norm_proof);
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context),
                           "anchor_escrow:proof_encoding");
    return record;
}

Result<bool> verify_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:verify"),
        "anchor_escrow:verify");
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:verify_roster");
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context),
                           "anchor_escrow:verify_record");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit,
        public_escrow_circuit(roster.recovery_root(),
                              advertised_anchor_root, record.ciphertext_),
        "anchor_escrow:verify_circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding,
        escrow_binding(roster, advertised_anchor_root, context_digest,
                       record.ciphertext_),
        "anchor_escrow:verify_binding");
    bppp::candidate::CircuitZkNormArgProofV4 proof{
        record.raw_commitment_, record.mask_commitment_, record.t2_,
        {}, {}, record.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
            circuit, std::move(proof), secp_context, binding),
        "anchor_escrow:publication");
    return bppp::candidate::verify_circuit_zk_norm_arg_v4(
        circuit, publication, secp_context, binding, cache);
}

Result<AnchorEscrowAccumulator> AnchorEscrowAccumulator::create(
    purify_secp_context* secp_context) {
    static_assert(AnchorEscrowRecord::kNormProofSize == 65 * 14 + 64);
    PURIFY_ASSIGN_OR_RETURN(
        auto basis,
        bppp::accumulation::Basis::create(
            kNormVectorLength, kNormVectorLength,
            "Purify/Accountable/AnchorEscrowAccumulation/v2",
            secp_context),
        "anchor_escrow_accumulation:basis");
    return AnchorEscrowAccumulator(std::move(basis));
}

Result<PreparedAnchorEscrow>
AnchorEscrowAccumulator::prepare(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "anchor_escrow_accumulation:prepare"),
        "anchor_escrow_accumulation:prepare");
    PURIFY_RETURN_IF_ERROR(
        require_roster(roster, "anchor_escrow_accumulation:empty_roster"),
        "anchor_escrow_accumulation:roster");
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context),
                           "anchor_escrow_accumulation:record");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit,
        public_escrow_circuit(roster.recovery_root(),
                              advertised_anchor_root, record.ciphertext_),
        "anchor_escrow_accumulation:circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding,
        escrow_binding(roster, advertised_anchor_root, context_digest,
                       record.ciphertext_),
        "anchor_escrow_accumulation:binding");
    bppp::candidate::CircuitZkNormArgProofV4 proof{
        record.raw_commitment_, record.mask_commitment_, record.t2_,
        {}, {}, record.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
            circuit, std::move(proof), secp_context, binding),
        "anchor_escrow_accumulation:publication");
    const auto precommitment = publication.precommitment.bytes();
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        bppp::candidate::prepare_circuit_zk_norm_arg_v4(
            circuit, publication, secp_context, binding, cache),
        "anchor_escrow_accumulation:outer");
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "anchor_escrow_accumulation:outer");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto norm,
        bppp::accumulation::
            prepare_v4_circuit_norm_for_algebraic_reduction(
                basis_, std::move(*prepared), secp_context),
        "anchor_escrow_accumulation:norm");
    return PreparedAnchorEscrow(precommitment, std::move(norm));
}

Result<GeneratedKey> recover_escrowed_anchor(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recipient,
        recover_registered_root(roster, exposed_signing_scalar,
                                secp_context),
        "anchor_escrow:recover_recipient");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& accepted,
        verify_anchor_escrow(roster, advertised_anchor_root, context_digest,
                             record, secp_context, cache),
        "anchor_escrow:recover_verify");
    if (!accepted) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "anchor_escrow:invalid_proof");
    }
    return decrypt_anchor(recipient, advertised_anchor_root,
                          record.ciphertext());
}

} // namespace purify::accountable
