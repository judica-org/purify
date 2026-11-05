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
#include <string_view>
#include <utility>
#include <vector>

#include "purify/puresign/recovery_root.hpp"
#include "purify/secp_bridge.h"
#include "anchor_escrow_internal.hpp"
#include "secure_cleanup.hpp"

namespace purify::accountable {
namespace {

using PointBytes = bppp::PointBytes;
using PointPair = std::pair<JacobianPoint, JacobianPoint>;

const TaggedHash kRandomnessStatementHash(
    "Purify/Accountable/AnchorEscrowRandomnessStatement/v2");
const TaggedHash kRandomnessMasterHash(
    "Purify/Accountable/AnchorEscrowRandomnessMaster/v2");
const TaggedHash kFirstEphemeralHash(
    "Purify/Accountable/AnchorEscrowFirstEphemeral/v2");
const TaggedHash kSecondEphemeralHash(
    "Purify/Accountable/AnchorEscrowSecondEphemeral/v2");
const TaggedHash kProofSeedHash(
    "Purify/Accountable/AnchorEscrowProofSeed/v3");

Status require_anchor_v3_hash_suite(const char* label) {
#if PURIFY_USE_LEGACY_FIELD_HASHES
    return unexpected_error(ErrorCode::UnsupportedSymbol, label);
#else
    (void)label;
    return {};
#endif
}

const Bytes& anchor_punishment_evaluation_input() {
    static const Bytes input = bytes_from_ascii(
        "Purify/Accountable/AnchorPunishmentKey/v1");
    return input;
}

Bytes evaluation_curve_input(std::string_view prefix) {
    Bytes input;
    const auto& message = anchor_punishment_evaluation_input();
    input.reserve(prefix.size() + message.size());
    input.insert(input.end(), prefix.begin(), prefix.end());
    input.insert(input.end(), message.begin(), message.end());
    return input;
}

using ::purify::detail::WipeOnDestruction;

using SecretBytes32 = ::purify::detail::Secret<bppp::ScalarBytes>;

struct EscrowOpening {
    const SecretKey& payload;
    std::array<const GeneratedKey*, 2> ephemeral;
    const FieldElement& punishment_scalar;
    bool negate_punishment_scalar;
};

struct PunishmentEvaluation {
    FieldElement normalized_scalar;
    bool negated;
    Bip340Key key;

    PunishmentEvaluation(const FieldElement& scalar, const bool& negate,
                         Bip340Key bip340)
        : normalized_scalar(scalar), negated(negate),
          key(std::move(bip340)) {}
    PunishmentEvaluation(const PunishmentEvaluation&) = delete;
    PunishmentEvaluation& operator=(const PunishmentEvaluation&) = delete;
    PunishmentEvaluation(PunishmentEvaluation&& other) noexcept
        : normalized_scalar(other.normalized_scalar),
          negated(other.negated), key(std::move(other.key)) {
        detail::secure_clear_bytes(&other.normalized_scalar,
                                   sizeof(other.normalized_scalar));
        detail::secure_clear_bytes(&other.negated, sizeof(other.negated));
    }
    PunishmentEvaluation& operator=(PunishmentEvaluation&&) = delete;
    ~PunishmentEvaluation() {
        detail::secure_clear_bytes(&normalized_scalar,
                                   sizeof(normalized_scalar));
        detail::secure_clear_bytes(&negated, sizeof(negated));
    }
};

PointBytes punishment_point(const AnchorPunishmentPublicKey& key) {
    PointBytes out{};
    out[0] = 0x02;
    std::copy(key.xonly().begin(), key.xonly().end(), out.begin() + 1);
    return out;
}

Result<PointPair> punishment_message_points() {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& first,
        hash_to_curve(evaluation_curve_input("Eval/1/"), curve1()),
        "anchor_escrow:punishment_message_first");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& second,
        hash_to_curve(evaluation_curve_input("Eval/2/"), curve2()),
        "anchor_escrow:punishment_message_second");
    return PointPair{first, second};
}

Result<PunishmentEvaluation> evaluate_punishment_key(
    const GeneratedKey& anchor_recovery_key,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite(
            "anchor_escrow:punishment_hash_suite"),
        "anchor_escrow:punishment_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "anchor_escrow:punishment_context"),
        "anchor_escrow:punishment_context");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& derived_anchor,
        derive_key(anchor_recovery_key.secret),
        "anchor_escrow:punishment_anchor");
    if (derived_anchor.public_key != anchor_recovery_key.public_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:punishment_keypair");
    }
    auto raw_scalar = eval(anchor_recovery_key.secret,
                           anchor_punishment_evaluation_input());
    if (!raw_scalar) {
        return unexpected_error(raw_scalar.error(),
                                "anchor_escrow:punishment_evaluation");
    }
    WipeOnDestruction raw_scalar_guard(*raw_scalar);
    auto raw_bytes = raw_scalar->to_bytes_be();
    WipeOnDestruction raw_bytes_guard(raw_bytes);
    Bip340Key key;
    key.seckey = raw_bytes;
    if (purify_bip340_key_from_seckey(
            secp_context, key.seckey.data(), key.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "anchor_escrow:zero_punishment_scalar");
    }
    unsigned char difference = 0;
    for (std::size_t i = 0; i < raw_bytes.size(); ++i) {
        difference |= raw_bytes[i] ^ key.seckey[i];
    }
    bool negated = difference != 0;
    detail::secure_clear_bytes(&difference, sizeof(difference));
    WipeOnDestruction negated_guard(negated);
    auto normalized = FieldElement::try_from_bytes32(key.seckey);
    if (!normalized) {
        return unexpected_error(
            normalized.error(),
            "anchor_escrow:normalized_punishment_scalar");
    }
    WipeOnDestruction normalized_guard(*normalized);
    return PunishmentEvaluation(*normalized, negated,
                                std::move(key));
}

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
    WipeOnDestruction first_guard(first);
    WipeOnDestruction second_guard(second);
    if (first.is_zero() || second.is_zero() || half_n1() < first ||
        half_n2() < second) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "anchor_escrow:canonical_plaintext");
    }
    first.sub_assign(UInt256::one());
    second.sub_assign(UInt256::one());
    auto packed = multiply(half_n1(), second);
    WipeOnDestruction packed_guard(packed);
    packed.add_assign(widen<8>(first));
    PURIFY_ASSIGN_OR_RETURN(auto secret, SecretKey::from_packed(packed),
                            "anchor_escrow:plaintext_secret");
    return derive_key(std::move(secret));
}

Result<FieldElement> shared_pad(const SecretKey& secret,
                                const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(auto scalars, unpack_secret(secret.packed()),
                            "anchor_escrow:shared_secret");
    WipeOnDestruction scalars_guard(scalars);
    PURIFY_ASSIGN_OR_RETURN(const auto& points,
                            decode_root(peer, "anchor_escrow:shared_peer"),
                            "anchor_escrow:shared_peer");
    PURIFY_ASSIGN_OR_RETURN(
        auto first,
        curve1().mul_secret_affine(points.first, scalars.first),
        "anchor_escrow:shared_first");
    WipeOnDestruction first_guard(first);
    PURIFY_ASSIGN_OR_RETURN(
        auto second,
        curve2().mul_secret_affine(points.second, scalars.second),
        "anchor_escrow:shared_second");
    WipeOnDestruction second_guard(second);
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
    WipeOnDestruction payload_guard(payload);
    AnchorEscrowCiphertext out;
    for (std::size_t i = 0; i < out.ephemeral_keys.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pad,
            shared_pad(opening.ephemeral[i]->secret, recipient),
            "anchor_escrow:encrypt_pad");
        WipeOnDestruction pad_guard(pad);
        out.ephemeral_keys[i] = opening.ephemeral[i]->public_key;
        const auto& value = i == 0 ? payload.first : payload.second;
        FieldElement plaintext = FieldElement::from_uint256(value);
        WipeOnDestruction plaintext_guard(plaintext);
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
        WipeOnDestruction bit_guard(bit);
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
    const PointPair& punishment_messages,
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
    WipeOnDestruction payload_values_guard(payload_values);
    if (opening != nullptr) {
        PURIFY_ASSIGN_OR_RETURN(auto pair,
                                unpack_secret(opening->payload.packed()),
                                "anchor_escrow:payload_witness");
        WipeOnDestruction pair_guard(pair);
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
        WipeOnDestruction first_values_guard(values[0]);
        WipeOnDestruction second_values_guard(values[1]);
        if (opening != nullptr) {
            PURIFY_ASSIGN_OR_RETURN(
                auto pair,
                unpack_secret(opening->ephemeral[i]->secret.packed()),
                "anchor_escrow:ephemeral_secret");
            WipeOnDestruction pair_guard(pair);
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
                WipeOnDestruction bit_value_guard(bit_value);
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
    const Expr punishment_first = circuit_ec_multiply_x(
        curve1(), transcript, punishment_messages.first, first_bits);
    const Expr punishment_second = circuit_ec_multiply_x(
        curve2(), transcript, punishment_messages.second, second_bits);
    const Expr raw_punishment = circuit_combine(
        transcript, punishment_first, punishment_second);
    auto negate_value =
        opening == nullptr
            ? std::optional<FieldElement>{}
            : std::optional<FieldElement>(FieldElement::from_u64(
                  opening->negate_punishment_scalar ? 1 : 0));
    WipeOnDestruction negate_value_guard(negate_value);
    const Expr negate = transcript.boolean(transcript.secret(negate_value));
    const Expr punishment =
        raw_punishment - 2 * transcript.mul(negate, raw_punishment);
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
    return CircuitMainResult{punishment, first_key, second_key,
                             6 * 255 + 1};
}

Result<NativeBulletproofCircuit> public_escrow_circuit(
    const UInt512& recipient, const UInt512& payload,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(decode_root(payload, "anchor_escrow:anchor_root"),
                           "anchor_escrow:anchor_root");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto& punishment_messages, punishment_message_points(),
        "anchor_escrow:public_punishment_messages");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& relation,
        escrow_relation(transcript, recipient, ciphertext,
                        punishment_messages, nullptr),
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
        const auto& punishment_messages, punishment_message_points(),
        "anchor_escrow:witness_punishment_messages");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& relation,
        escrow_relation(transcript, recipient, ciphertext,
                        punishment_messages, &opening),
        "anchor_escrow:witness_relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "anchor_escrow:lower_witness");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x,
                              relation.out),
        "anchor_escrow:bind_witness");
    return bp.assignment_data(transcript.varmap(),
                              opening.punishment_scalar);
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
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest) {
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:randomness_roster");
    const auto recovery_root = roster.recovery_root().to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto signing_key = roster_point(roster);
    const auto punishment = punishment_point(punishment_key);
    return kRandomnessStatementHash.digest_many<8>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root, anchor_root,
        punishment, context_digest,
    });
}

Result<Bytes> escrow_binding(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:roster");
    const auto recovery_root = roster.recovery_root().to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto signing_key = roster_point(roster);
    const auto punishment = punishment_point(punishment_key);
    static const TaggedHash hash("Purify/Accountable/AnchorEscrow/v3");
    const auto digest = hash.digest_many<9>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root, anchor_root, encrypted,
        punishment, context_digest,
    });
    return Bytes(digest.begin(), digest.end());
}

Result<GeneratedKey> decrypt_anchor(
    const GeneratedKey& recipient, const UInt512& advertised_anchor_root,
    const AnchorEscrowCiphertext& ciphertext) {
    std::array<UInt256, 2> plaintext;
    WipeOnDestruction plaintext_guard(plaintext);
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pad, shared_pad(recipient.secret,
                                 ciphertext.ephemeral_keys[i]),
            "anchor_escrow:decrypt_pad");
        WipeOnDestruction pad_guard(pad);
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

Result<AnchorPunishmentPublicKey> AnchorPunishmentPublicKey::create(
    const std::array<unsigned char, 32>& xonly,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "anchor_escrow:punishment_public_key"),
        "anchor_escrow:punishment_public_key");
    if (purify_bip340_validate_xonly_pubkey(secp_context, xonly.data()) ==
        0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "anchor_escrow:punishment_public_key");
    }
    return AnchorPunishmentPublicKey(xonly);
}

Result<AnchorPunishmentKey> derive_anchor_punishment_key(
    const GeneratedKey& anchor_recovery_key,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto evaluated,
        evaluate_punishment_key(anchor_recovery_key, secp_context),
        "anchor_escrow:derive_punishment_key");
    return AnchorPunishmentKey(std::move(evaluated.key));
}

Result<AnchorEscrowCircuitShape>
anchor_escrow_circuit_shape_for_testing(
    const UInt512& recipient, const UInt512& anchor_root,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite("anchor_escrow:shape_hash_suite"),
        "anchor_escrow:shape_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        decode_root(anchor_root, "anchor_escrow:shape_anchor_root"),
        "anchor_escrow:shape_anchor_root");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto& punishment_messages, punishment_message_points(),
        "anchor_escrow:shape_punishment_messages");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& relation,
        escrow_relation(transcript, recipient, ciphertext,
                        punishment_messages, nullptr),
        "anchor_escrow:shape_relation");
    const auto unpadded_gates = transcript.muls().size();
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "anchor_escrow:shape_lower");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(anchor_root, relation.p1x, relation.p2x,
                              relation.out),
        "anchor_escrow:shape_bind");
    return AnchorEscrowCircuitShape{
        unpadded_gates, bp.native_circuit().n_gates};
}

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
        raw_commitment_, mask_commitment_, t2_,
        public_commitment_dlog_nonce_,
        public_commitment_dlog_response_, norm_proof_};
    return bppp::candidate::
        validate_circuit_zk_norm_arg_proof_v4_fixed_encoding(
            proof, bppp::candidate::CircuitCommitmentModeV4::Public,
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
    out.insert(out.end(), public_commitment_dlog_nonce_.begin(),
               public_commitment_dlog_nonce_.end());
    out.insert(out.end(), public_commitment_dlog_response_.begin(),
               public_commitment_dlog_response_.end());
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
    std::copy_n(encoded.begin() + offset,
                out.public_commitment_dlog_nonce_.size(),
                out.public_commitment_dlog_nonce_.begin());
    offset += out.public_commitment_dlog_nonce_.size();
    std::copy_n(encoded.begin() + offset,
                out.public_commitment_dlog_response_.size(),
                out.public_commitment_dlog_response_.begin());
    offset += out.public_commitment_dlog_response_.size();
    out.norm_proof_.assign(encoded.begin() + offset, encoded.end());
    PURIFY_RETURN_IF_ERROR(out.validate_encoding(secp_context),
                           "anchor_escrow:deserialize");
    return out;
}

Result<AnchorEscrowRecord> create_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite("anchor_escrow:create_hash_suite"),
        "anchor_escrow:create_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create"),
        "anchor_escrow:create");
    SecretBytes32 auxiliary_randomness;
    PURIFY_RETURN_IF_ERROR(fill_secure_random(auxiliary_randomness.value),
                           "anchor_escrow:auxiliary_randomness");
    return create_anchor_escrow_with_aux_randomness(
        roster, anchor_recovery_key, punishment_key, context_digest,
        auxiliary_randomness.value, secp_context, cache);
}

Result<AnchorEscrowRecord> create_anchor_escrow_with_aux_randomness(
    const RecoveryBoundSigningRoster& roster,
    const GeneratedKey& anchor_recovery_key,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite(
            "anchor_escrow:create_aux_hash_suite"),
        "anchor_escrow:create_aux_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create_aux"),
        "anchor_escrow:create_aux");
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:create_roster");
    PURIFY_ASSIGN_OR_RETURN(
        auto punishment_evaluation,
        evaluate_punishment_key(anchor_recovery_key, secp_context),
        "anchor_escrow:evaluate_punishment");
    if (punishment_evaluation.key.xonly_pubkey != punishment_key.xonly()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:punishment_key");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& randomness_statement,
        escrow_randomness_statement(roster,
                                    anchor_recovery_key.public_key,
                                    punishment_key,
                                    context_digest),
        "anchor_escrow:randomness_statement");
    auto packed_anchor = anchor_recovery_key.secret.packed().to_bytes_be();
    WipeOnDestruction packed_anchor_guard(packed_anchor);
    SecretBytes32 randomness_master;
    {
        auto digest = kRandomnessMasterHash.digest_many<3>({
            auxiliary_randomness, packed_anchor, randomness_statement});
        WipeOnDestruction digest_guard(digest);
        randomness_master.value = digest;
    }
    SecretBytes32 first_seed;
    {
        auto digest = kFirstEphemeralHash.digest(randomness_master.value);
        WipeOnDestruction digest_guard(digest);
        first_seed.value = digest;
    }
    SecretBytes32 second_seed;
    {
        auto digest = kSecondEphemeralHash.digest(randomness_master.value);
        WipeOnDestruction digest_guard(digest);
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
    EscrowOpening opening{
        anchor_recovery_key.secret,
        {&first_ephemeral, &second_ephemeral},
        punishment_evaluation.normalized_scalar,
        punishment_evaluation.negated,
    };
    WipeOnDestruction opening_sign_guard(
        opening.negate_punishment_scalar);
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
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding,
        escrow_binding(roster, anchor_recovery_key.public_key,
                       punishment_key, context_digest, ciphertext),
        "anchor_escrow:binding");
    SecretBytes32 prover_seed;
    {
        auto digest = kProofSeedHash.digest_many<2>({
            randomness_master.value, binding});
        WipeOnDestruction digest_guard(digest);
        prover_seed.value = digest;
    }
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            prove_circuit_zk_norm_arg_v4_with_public_commitments(
                circuit, assignment, prover_seed.value, outputs,
                secp_context, binding, cache),
        "anchor_escrow:prove");
    AnchorEscrowRecord record;
    record.ciphertext_ = ciphertext;
    record.raw_commitment_ = publication.proof.raw_commitment;
    record.mask_commitment_ = publication.proof.mask_commitment;
    record.t2_ = publication.proof.t2;
    record.public_commitment_dlog_nonce_ =
        publication.proof.public_commitment_dlog_nonce;
    record.public_commitment_dlog_response_ =
        publication.proof.public_commitment_dlog_response;
    record.norm_proof_ = std::move(publication.proof.norm_proof);
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context),
                           "anchor_escrow:proof_encoding");
    return record;
}

Result<bool> verify_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite("anchor_escrow:verify_hash_suite"),
        "anchor_escrow:verify_hash_suite");
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
        escrow_binding(roster, advertised_anchor_root, punishment_key,
                       context_digest, record.ciphertext_),
        "anchor_escrow:verify_binding");
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    bppp::candidate::CircuitZkNormArgProofV4 proof{
        record.raw_commitment_, record.mask_commitment_, record.t2_,
        record.public_commitment_dlog_nonce_,
        record.public_commitment_dlog_response_, record.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
                circuit, std::move(proof), outputs, secp_context, binding),
        "anchor_escrow:publication");
    return bppp::candidate::
        verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, publication, outputs, secp_context, binding, cache);
}

Result<AnchorEscrowAccumulator> AnchorEscrowAccumulator::create(
    purify_secp_context* secp_context) {
    static_assert(AnchorEscrowRecord::kNormProofSize == 65 * 14 + 64);
    PURIFY_ASSIGN_OR_RETURN(
        auto basis,
        bppp::accumulation::Basis::create(
            kNormVectorLength, kNormVectorLength,
            "Purify/Accountable/AnchorEscrowAccumulation/v3",
            secp_context),
        "anchor_escrow_accumulation:basis");
    return AnchorEscrowAccumulator(std::move(basis));
}

Result<AnchorEscrowParentConstants>
AnchorEscrowAccumulator::derive_parent_constants(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext,
    const bppp::ScalarBytes& circuit_precommitment,
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite(
            "anchor_escrow_parent:hash_suite"),
        "anchor_escrow_parent:hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow_parent:context"),
        "anchor_escrow_parent:context");
    PURIFY_RETURN_IF_ERROR(
        require_roster(roster, "anchor_escrow_parent:empty_roster"),
        "anchor_escrow_parent:roster");
    if (ciphertext.ephemeral_keys[0] == ciphertext.ephemeral_keys[1]) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow_parent:duplicate_ephemeral");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto precommitment,
        bppp::candidate::CircuitPrecommitmentDigestV4::parse(
            circuit_precommitment),
        "anchor_escrow_parent:precommitment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit,
        public_escrow_circuit(roster.recovery_root(),
                              advertised_anchor_root, ciphertext),
        "anchor_escrow_parent:circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto binding,
        escrow_binding(roster, advertised_anchor_root, punishment_key,
                       context_digest, ciphertext),
        "anchor_escrow_parent:binding");
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    PURIFY_ASSIGN_OR_RETURN(
        auto constants,
        bppp::candidate::
            derive_circuit_norm_parent_constants_v4_with_public_commitments(
                circuit, precommitment, outputs, secp_context, binding),
        "anchor_escrow_parent:derive");
    return AnchorEscrowParentConstants{
        std::move(constants.circuit_binding_digest),
        std::move(constants.raw_generator_digest),
        std::move(constants.coefficient_commitment),
        std::move(constants.anchored_offset)};
}

Result<PreparedAnchorEscrow>
AnchorEscrowAccumulator::prepare(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) const {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite(
            "anchor_escrow_accumulation:prepare_hash_suite"),
        "anchor_escrow_accumulation:prepare_hash_suite");
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
        escrow_binding(roster, advertised_anchor_root, punishment_key,
                       context_digest, record.ciphertext_),
        "anchor_escrow_accumulation:binding");
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    bppp::candidate::CircuitZkNormArgProofV4 proof{
        record.raw_commitment_, record.mask_commitment_, record.t2_,
        record.public_commitment_dlog_nonce_,
        record.public_commitment_dlog_response_, record.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
                circuit, std::move(proof), outputs, secp_context, binding),
        "anchor_escrow_accumulation:publication");
    const auto circuit_precommitment =
        publication.precommitment.bytes();
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        bppp::candidate::
            prepare_circuit_zk_norm_arg_v4_with_public_commitments(
                circuit, publication, outputs, secp_context, binding,
                cache),
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
    return PreparedAnchorEscrow(circuit_precommitment, std::move(norm));
}

Result<AnchorPunishmentKey> recover_escrowed_anchor(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v3_hash_suite("anchor_escrow:recover_hash_suite"),
        "anchor_escrow:recover_hash_suite");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recipient,
        recover_registered_root(roster, exposed_signing_scalar,
                                secp_context),
        "anchor_escrow:recover_recipient");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& accepted,
        verify_anchor_escrow(roster, advertised_anchor_root,
                             punishment_key, context_digest, record,
                             secp_context, cache),
        "anchor_escrow:recover_verify");
    if (!accepted) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "anchor_escrow:invalid_proof");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto recovered_anchor,
        decrypt_anchor(recipient, advertised_anchor_root,
                       record.ciphertext()),
        "anchor_escrow:recover_anchor");
    PURIFY_ASSIGN_OR_RETURN(
        auto recovered_punishment,
        derive_anchor_punishment_key(recovered_anchor, secp_context),
        "anchor_escrow:recover_punishment");
    if (recovered_punishment.public_key() != punishment_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:recovered_punishment_key");
    }
    return std::move(recovered_punishment);
}

} // namespace purify::accountable
