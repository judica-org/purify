// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/recovery_root.hpp"
#include "purify/puresign/recovery_root_accumulation.hpp"
#include "recovery_root_internal.hpp"
#include "../protocol/algebraic_circuit_accumulation.hpp"
#include "../protocol/algebraic_circuit_proof.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "purify/puresign/accountable.hpp"
#include "purify/secp_bridge.h"
#include "../bridge/bppp_bridge.h"
#include "secure_cleanup.hpp"

namespace purify::accountable {
namespace {

using PointBytes = bppp::PointBytes;
using ::purify::detail::WipeOnDestruction;

using SecretScalarBytes = ::purify::detail::Secret<bppp::ScalarBytes>;

struct CenteredScalarRelation {
    Expr sign;
    Expr magnitude;
    std::vector<Expr> recoded_bits;
    std::size_t n_bits = 0;
};

struct ContributionRelation {
    Expr output;
    std::size_t n_bits = 0;
};

UInt256 half_secp_order() {
    return prime_p().shifted_right(1);
}

struct CanonicalScalar {
    UInt256 magnitude{};
    bool negated = false;
};

CanonicalScalar canonical_scalar(const FieldElement& scalar) {
    CanonicalScalar out{scalar.to_uint256(), false};
    FieldElement negative_scalar = scalar.negate();
    WipeOnDestruction negative_scalar_guard(negative_scalar);
    UInt256 negative = negative_scalar.to_uint256();
    WipeOnDestruction negative_guard(negative);
    out.negated = half_secp_order() < out.magnitude;
    out.magnitude.conditional_assign(negative, out.negated);
    return out;
}

UInt256 magnitude(const FieldElement& scalar) {
    auto canonical = canonical_scalar(scalar);
    WipeOnDestruction canonical_guard(canonical);
    return canonical.magnitude;
}

std::array<unsigned char, 8> encode_u64(std::size_t value) {
    std::array<unsigned char, 8> out{};
    const auto encoded = static_cast<std::uint64_t>(value);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[out.size() - 1 - i] =
            static_cast<unsigned char>(encoded >> (8 * i));
    }
    return out;
}

PointBytes roster_point(const NonceHostBoundSigningRoster& roster) {
    PointBytes out{};
    out[0] = 0x02;
    std::copy(roster.signing_key().begin(), roster.signing_key().end(),
              out.begin() + 1);
    return out;
}

Result<PointBytes> secp_point(const FieldElement& value,
                              purify_secp_context* context) {
    const bppp::ScalarBytes zero{};
    const auto generator = bppp::base_generator(context);
    SecretScalarBytes encoded_value;
    purify_scalar_get_b32(
        encoded_value.value.data(),
        &::purify::detail::FieldElementAccess::raw(value));
    return bppp::pedersen_commit_char(zero, encoded_value.value, context,
                                      generator, generator);
}

Result<PointBytes> weighted_member_point(
    const NonceHostBoundSigningRoster& roster, std::size_t member_index,
    purify_secp_context* secp_context) {
    if (member_index >= roster.members().size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "recovery_contribution:member_index");
    }
    const auto& member = roster.members()[member_index];
    const auto coefficient = member.coefficient.to_bytes_be();
    PointBytes weighted{};
    if (purify_point_scale(secp_context, member.public_key.data(),
                           coefficient.data(), weighted.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "recovery_contribution:weighted_key");
    }
    return weighted;
}

Result<AffinePoint> decode_companion_point(
    std::span<const unsigned char> encoded, const EllipticCurve& curve,
    const char* label) {
    if (encoded.size() != 33) {
        return unexpected_error(ErrorCode::InvalidFixedSize, label);
    }
    if (encoded[0] != 0x02 && encoded[0] != 0x03) {
        return unexpected_error(ErrorCode::RangeViolation, label);
    }
    std::array<unsigned char, 32> x_bytes{};
    std::copy(encoded.begin() + 1, encoded.end(), x_bytes.begin());
    PURIFY_ASSIGN_OR_RETURN(const auto x,
                            FieldElement::try_from_bytes32(x_bytes), label);
    auto point = curve.lift_x(x);
    if (!point || point->infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    auto affine = curve.affine(*point);
    if (affine.y.is_odd() != (encoded[0] == 0x03)) {
        affine.y = affine.y.negate();
    }
    const JacobianPoint exact{
        affine.x, affine.y, FieldElement::one(), false};
    if (!curve.mul(exact, curve.order()).infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    return affine;
}

Status validate_companion_point(const AffinePoint& point,
                                const EllipticCurve& curve,
                                const char* label) {
    if (point.infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    const auto lifted = curve.lift_x(point.x);
    if (!lifted || lifted->infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    const auto affine = curve.affine(*lifted);
    if (point.y != affine.y && point.y != affine.y.negate()) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    const JacobianPoint exact{
        point.x, point.y, FieldElement::one(), false};
    if (!curve.mul(exact, curve.order()).infinity) {
        return unexpected_error(ErrorCode::BackendRejectedInput, label);
    }
    return {};
}

Status validate_recovery_root_share_count(std::size_t member_count) {
    if (member_count == 0) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "recovery_share_aggregate:empty");
    }
    if (member_count > RecoveryRootShareAggregate::kMaxMembers) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_share_aggregate:member_count");
    }
    return {};
}

void append_companion_point(Bytes& out, const AffinePoint& point) {
    assert(!point.infinity && "serialized companion point must be finite");
    out.push_back(static_cast<unsigned char>(point.y.is_odd() ? 0x03 : 0x02));
    const auto x = point.x.to_bytes_be();
    out.insert(out.end(), x.begin(), x.end());
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

Result<CenteredScalarRelation> centered_scalar_relation(
    Transcript& transcript,
    const FieldElement* scalar = nullptr) {
    if (scalar && scalar->is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_root:zero_witness");
    }
    std::optional<UInt256> value;
    std::optional<FieldElement> sign_value;
    WipeOnDestruction value_guard(value);
    WipeOnDestruction sign_value_guard(sign_value);
    if (scalar) {
        auto canonical = canonical_scalar(*scalar);
        WipeOnDestruction canonical_guard(canonical);
        value = canonical.magnitude;
        value->sub_assign(UInt256::one());
        sign_value = FieldElement::from_u64(canonical.negated);
    }
    const auto bits = ordinary_bits(transcript, value);
    const Expr sign = transcript.boolean(transcript.secret(sign_value));
    auto bound = half_secp_order();
    bound.sub_assign(UInt256::one());
    transcript.equal(exceeds_bound(transcript, bits, bound), Expr(0));
    Expr scalar_value(1);
    FieldElement power = FieldElement::one();
    for (const auto& bit : bits) {
        scalar_value = scalar_value + power * bit;
        power = power + power;
    }
    return CenteredScalarRelation{
        sign, scalar_value, signed_window_bits(transcript, bits),
        bits.size() + 1};
}

Result<CircuitMainResult> setup_relation(
    Transcript& transcript,
    const FieldElement* scalar = nullptr) {
    PURIFY_ASSIGN_OR_RETURN(
        auto centered, centered_scalar_relation(transcript, scalar),
        "recovery_root:centered_scalar");
    const Expr first = circuit_ec_multiply_x(
        curve1(), transcript, generator1(), centered.recoded_bits);
    const Expr second = circuit_ec_multiply_x(
        curve2(), transcript, generator2(), centered.recoded_bits);
    return CircuitMainResult{
        transcript.mul(Expr(1) - 2 * centered.sign,
                       centered.magnitude),
        first, second, centered.n_bits};
}

Result<ContributionRelation> contribution_relation(
    Transcript& transcript, const RecoveryRootShare& share,
    const FieldElement* scalar = nullptr) {
    PURIFY_ASSIGN_OR_RETURN(
        auto centered, centered_scalar_relation(transcript, scalar),
        "recovery_contribution:centered_scalar");
    auto first = circuit_ec_multiply_point(
        curve1(), transcript, generator1(), centered.recoded_bits);
    auto second = circuit_ec_multiply_point(
        curve2(), transcript, generator2(), centered.recoded_bits);
    first = circuit_optionally_negate_ec(first, transcript, centered.sign);
    second = circuit_optionally_negate_ec(second, transcript,
                                          centered.sign);
    transcript.equal(first.first, Expr(share.first().x));
    transcript.equal(first.second, Expr(share.first().y));
    transcript.equal(second.first, Expr(share.second().x));
    transcript.equal(second.second, Expr(share.second().y));
    return ContributionRelation{
        transcript.mul(Expr(1) - 2 * centered.sign,
                       centered.magnitude),
        centered.n_bits};
}

Result<NativeBulletproofCircuit> public_setup_circuit(const UInt512& root) {
    PURIFY_RETURN_IF_ERROR(validate_public_points(root),
                           "recovery_root:root");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, setup_relation(transcript),
                            "recovery_root:relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "recovery_root:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(root, relation.p1x, relation.p2x, relation.out),
        "recovery_root:bind");
    return bp.native_circuit();
}

Result<BulletproofAssignmentData> setup_assignment(
    const UInt512& root, const FieldElement& scalar) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation,
                            setup_relation(transcript, &scalar),
                            "recovery_root:witness");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "recovery_root:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(root, relation.p1x, relation.p2x, relation.out),
        "recovery_root:bind");
    return bp.assignment_data(transcript.varmap(), scalar);
}

Result<NativeBulletproofCircuit> contribution_circuit(
    const RecoveryRootShare& share,
    std::size_t* relation_multiplications = nullptr) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto relation, contribution_relation(transcript, share),
        "recovery_contribution:relation");
    if (relation_multiplications != nullptr) {
        *relation_multiplications = transcript.muls().size();
    }
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits,
                                              8192),
                           "recovery_contribution:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.bind_output_to_commitment(relation.output),
        "recovery_contribution:bind_output");
    return bp.native_circuit();
}

Result<BulletproofAssignmentData> contribution_assignment(
    const RecoveryRootShare& share, const FieldElement& effective_scalar) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto relation,
        contribution_relation(transcript, share, &effective_scalar),
        "recovery_contribution:witness_relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits,
                                              8192),
                           "recovery_contribution:lower_witness");
    PURIFY_RETURN_IF_ERROR(
        bp.bind_output_to_commitment(relation.output),
        "recovery_contribution:bind_output_witness");
    return bp.assignment_data(transcript.varmap(), effective_scalar);
}

Result<Bytes> setup_binding(const NonceHostBoundSigningRoster& roster,
                            const UInt512& root) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "recovery_root:empty_roster");
    }
    if (!size_fits_u64(roster.members().size())) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_root:roster_size");
    }
    const auto root_bytes = root.to_bytes_be();
    const auto count = encode_u64(roster.members().size());
    const auto key = roster_point(roster);
    static const TaggedHash hash(
        "Purify/Accountable/RecoveryRootSetup/v2");
    const auto digest = hash.digest_many<6>({
        roster.key_list_hash(), key, count, root_bytes,
        roster.coalition_core_digest(), roster.nonce_host_commitment(),
    });
    return Bytes(digest.begin(), digest.end());
}

Result<Bytes> contribution_binding(
    const NonceHostBoundSigningRoster& roster,
    const CoalitionFormation& formation, std::size_t member_index,
    const RecoveryRootShare& share) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput,
                                "recovery_contribution:empty_roster");
    }
    if (member_index >= roster.members().size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "recovery_contribution:member_index");
    }
    if (formation.core_digest() != roster.coalition_core_digest()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_contribution:formation_core");
    }
    if (!size_fits_u64(roster.members().size()) ||
        !size_fits_u64(member_index)) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_contribution:roster_size");
    }
    const auto& member = roster.members()[member_index];
    const auto count = encode_u64(roster.members().size());
    const auto index = encode_u64(member_index);
    const auto aggregate_key = roster_point(roster);
    const auto coefficient = member.coefficient.to_bytes_be();
    const std::array<unsigned char, 1> aggregate_parity{
        static_cast<unsigned char>(roster.aggregate_was_negated())};
    const auto encoded_share = share.serialize();
    static const TaggedHash hash(
        "Purify/Accountable/RecoveryRootContribution/v1");
    const auto digest = hash.digest_many<11>({
        roster.key_list_hash(), aggregate_key, count, index,
        member.public_key, coefficient, aggregate_parity, encoded_share,
        formation.permit_id(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(),
    });
    return Bytes(digest.begin(), digest.end());
}

} // namespace

Bytes RecoveryRootShare::serialize() const {
    Bytes out;
    out.reserve(kSerializedSize);
    append_companion_point(out, first_);
    append_companion_point(out, second_);
    assert(out.size() == kSerializedSize);
    return out;
}

Result<RecoveryRootShare> RecoveryRootShare::deserialize(
    std::span<const unsigned char> encoded) {
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "recovery_contribution:share_size");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto first,
        decode_companion_point(encoded.first<33>(), curve1(),
                               "recovery_contribution:first_share"),
        "recovery_contribution:first_share");
    PURIFY_ASSIGN_OR_RETURN(
        auto second,
        decode_companion_point(encoded.subspan<33, 33>(), curve2(),
                               "recovery_contribution:second_share"),
        "recovery_contribution:second_share");
    return RecoveryRootShare(std::move(first), std::move(second));
}

Result<RecoveryRootShareAggregate> aggregate_recovery_root_shares(
    std::span<const RecoveryRootShare> ordered_shares) {
    PURIFY_RETURN_IF_ERROR(
        validate_recovery_root_share_count(ordered_shares.size()),
        "recovery_share_aggregate:member_count");
    auto first_sum = JacobianPoint::infinity_point();
    auto second_sum = JacobianPoint::infinity_point();
    for (const auto& share : ordered_shares) {
        PURIFY_RETURN_IF_ERROR(
            validate_companion_point(
                share.first(), curve1(),
                "recovery_share_aggregate:first_share"),
            "recovery_share_aggregate:first_share");
        PURIFY_RETURN_IF_ERROR(
            validate_companion_point(
                share.second(), curve2(),
                "recovery_share_aggregate:second_share"),
            "recovery_share_aggregate:second_share");
        first_sum = curve1().add_mixed(first_sum, share.first());
        second_sum = curve2().add_mixed(second_sum, share.second());
    }
    if (first_sum.infinity || second_sum.infinity) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "recovery_share_aggregate:infinite_sum");
    }
    auto first_affine = curve1().affine(first_sum);
    auto second_affine = curve2().affine(second_sum);
    PURIFY_RETURN_IF_ERROR(
        validate_companion_point(
            first_affine, curve1(),
            "recovery_share_aggregate:first_sum"),
        "recovery_share_aggregate:first_sum");
    PURIFY_RETURN_IF_ERROR(
        validate_companion_point(
            second_affine, curve2(),
            "recovery_share_aggregate:second_sum"),
        "recovery_share_aggregate:second_sum");
    const auto root = pack_public(first_affine.x.to_uint256(),
                                  second_affine.x.to_uint256());
    return RecoveryRootShareAggregate(
        ordered_shares.size(), std::move(first_affine),
        std::move(second_affine), root);
}

Status RecoveryRootContribution::validate_encoding(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "recovery_contribution:proof_encoding"),
        "recovery_contribution:proof_encoding");
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

Result<Bytes> RecoveryRootContribution::serialize(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(validate_encoding(secp_context),
                           "recovery_contribution:serialize");
    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    const auto encoded_share = share_.serialize();
    out.insert(out.end(), encoded_share.begin(), encoded_share.end());
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

Result<RecoveryRootContribution> RecoveryRootContribution::deserialize(
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context) {
    static constexpr std::size_t kProofOffset =
        1 + RecoveryRootShare::kSerializedSize;
    static constexpr std::size_t kNormOffset = kProofOffset + 162;
    static_assert(kNormOffset + kNormProofSize == kSerializedSize);
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "recovery_contribution:deserialize_size");
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "recovery_contribution:deserialize_version");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto share,
        RecoveryRootShare::deserialize(
            encoded.subspan(1, RecoveryRootShare::kSerializedSize)),
        "recovery_contribution:deserialize_share");
    RecoveryRootContribution out(std::move(share));
    std::size_t offset = kProofOffset;
    std::copy_n(encoded.begin() + offset, out.raw_commitment_.size(),
                out.raw_commitment_.begin());
    offset += out.raw_commitment_.size();
    std::copy_n(encoded.begin() + offset, out.mask_commitment_.size(),
                out.mask_commitment_.begin());
    offset += out.mask_commitment_.size();
    std::copy_n(encoded.begin() + offset, out.t2_.size(), out.t2_.begin());
    offset += out.t2_.size();
    std::copy_n(encoded.begin() + offset,
                out.public_commitment_dlog_nonce_.size(),
                out.public_commitment_dlog_nonce_.begin());
    offset += out.public_commitment_dlog_nonce_.size();
    std::copy_n(encoded.begin() + offset,
                out.public_commitment_dlog_response_.size(),
                out.public_commitment_dlog_response_.begin());
    offset += out.public_commitment_dlog_response_.size();
    assert(offset == kNormOffset);
    out.norm_proof_.assign(encoded.begin() + offset, encoded.end());
    PURIFY_RETURN_IF_ERROR(out.validate_encoding(secp_context),
                           "recovery_contribution:deserialize");
    return out;
}

Result<RecoveryRootContributionCircuitShape>
recovery_root_contribution_circuit_shape_for_testing(
    const RecoveryRootShare& share) {
    std::size_t relation_multiplications = 0;
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit,
        contribution_circuit(share, &relation_multiplications),
        "recovery_contribution:shape");
    return RecoveryRootContributionCircuitShape{
        relation_multiplications, circuit.n_gates};
}

namespace testing {

Status recovery_root_share_count_valid_for_testing(
    std::size_t member_count) {
    return validate_recovery_root_share_count(member_count);
}

Result<bool> recovery_root_contribution_assignment_satisfies_for_testing(
    const RecoveryRootShare& share,
    const FieldElement& effective_scalar) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit, contribution_circuit(share),
        "recovery_contribution:test_circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto assignment,
        contribution_assignment(share, effective_scalar),
        "recovery_contribution:test_assignment");
    return circuit.evaluate(assignment);
}

} // namespace testing

Result<RecoveryRootContribution> prove_recovery_root_contribution(
    const NonceHostBoundSigningRoster& roster,
    const CoalitionFormation& formation, std::size_t member_index,
    const FieldElement& member_secret,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_contribution:prove"),
        "recovery_contribution:prove");
    if (member_secret.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_contribution:zero_member_secret");
    }
    if (member_index >= roster.members().size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "recovery_contribution:member_index");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto member_point, secp_point(member_secret, secp_context),
        "recovery_contribution:member_point");
    if (member_point != roster.members()[member_index].public_key) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_contribution:member_secret");
    }
    auto effective_scalar =
        roster.members()[member_index].coefficient * member_secret;
    WipeOnDestruction effective_scalar_guard(effective_scalar);
    if (effective_scalar.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_contribution:zero_effective_scalar");
    }
    auto centered = canonical_scalar(effective_scalar);
    WipeOnDestruction centered_guard(centered);
    PURIFY_ASSIGN_OR_RETURN(
        auto first,
        curve1().mul_secret_affine(generator1(), centered.magnitude),
        "recovery_contribution:first_share");
    PURIFY_ASSIGN_OR_RETURN(
        auto second,
        curve2().mul_secret_affine(generator2(), centered.magnitude),
        "recovery_contribution:second_share");
    first.y.conditional_assign(first.y.negate(), centered.negated);
    second.y.conditional_assign(second.y.negate(), centered.negated);
    RecoveryRootContribution contribution(
        RecoveryRootShare(std::move(first), std::move(second)));
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit, contribution_circuit(contribution.share_),
        "recovery_contribution:circuit");
    PURIFY_ASSIGN_OR_RETURN(
        auto assignment,
        contribution_assignment(contribution.share_, effective_scalar),
        "recovery_contribution:assignment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto binding,
        contribution_binding(roster, formation, member_index,
                             contribution.share_),
        "recovery_contribution:binding");
    SecretScalarBytes effective_bytes;
    purify_scalar_get_b32(
        effective_bytes.value.data(),
        &::purify::detail::FieldElementAccess::raw(effective_scalar));
    static const TaggedHash prover_seed_hash(
        "Purify/Accountable/RecoveryRootContributionProverSeed/v1");
    SecretScalarBytes prover_seed;
    prover_seed.value = prover_seed_hash.digest_many<2>({
        effective_bytes.value, binding});
    PURIFY_ASSIGN_OR_RETURN(
        const auto weighted,
        weighted_member_point(roster, member_index, secp_context),
        "recovery_contribution:weighted_key");
    const std::array<PointBytes, 1> outputs{weighted};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            prove_circuit_zk_norm_arg_v4_with_public_commitments(
                circuit, assignment, prover_seed.value, outputs,
                secp_context, binding, cache),
        "recovery_contribution:prove_circuit");
    contribution.raw_commitment_ = publication.proof.raw_commitment;
    contribution.mask_commitment_ = publication.proof.mask_commitment;
    contribution.t2_ = publication.proof.t2;
    contribution.public_commitment_dlog_nonce_ =
        publication.proof.public_commitment_dlog_nonce;
    contribution.public_commitment_dlog_response_ =
        publication.proof.public_commitment_dlog_response;
    contribution.norm_proof_ = std::move(publication.proof.norm_proof);
    PURIFY_RETURN_IF_ERROR(contribution.validate_encoding(secp_context),
                           "recovery_contribution:proof_encoding");
    return contribution;
}

Result<bool> verify_recovery_root_contribution(
    const NonceHostBoundSigningRoster& roster,
    const CoalitionFormation& formation, std::size_t member_index,
    const RecoveryRootContribution& contribution,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_contribution:verify"),
        "recovery_contribution:verify");
    PURIFY_RETURN_IF_ERROR(contribution.validate_encoding(secp_context),
                           "recovery_contribution:proof_encoding");
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit, contribution_circuit(contribution.share_),
        "recovery_contribution:circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto binding,
        contribution_binding(roster, formation, member_index,
                             contribution.share_),
        "recovery_contribution:binding");
    PURIFY_ASSIGN_OR_RETURN(
        const auto weighted,
        weighted_member_point(roster, member_index, secp_context),
        "recovery_contribution:weighted_key");
    const std::array<PointBytes, 1> outputs{weighted};
    bppp::candidate::CircuitZkNormArgProofV4 proof{
        contribution.raw_commitment_, contribution.mask_commitment_,
        contribution.t2_, contribution.public_commitment_dlog_nonce_,
        contribution.public_commitment_dlog_response_,
        contribution.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
                circuit, std::move(proof), outputs, secp_context, binding),
        "recovery_contribution:publication");
    return bppp::candidate::
        verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, publication, outputs, secp_context, binding, cache);
}

Status RecoveryRootSetupProof::validate_encoding(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_root:proof_encoding"),
        "recovery_root:proof_encoding");
    static constexpr std::size_t kRoundCount = 12;
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

Result<Bytes> RecoveryRootSetupProof::serialize(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(validate_encoding(secp_context),
                           "recovery_root:serialize");
    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    out.insert(out.end(), raw_commitment_.begin(), raw_commitment_.end());
    out.insert(out.end(), mask_commitment_.begin(), mask_commitment_.end());
    out.insert(out.end(), t2_.begin(), t2_.end());
    out.insert(out.end(), public_commitment_dlog_nonce_.begin(),
               public_commitment_dlog_nonce_.end());
    out.insert(out.end(),
               public_commitment_dlog_response_.begin(),
               public_commitment_dlog_response_.end());
    out.insert(out.end(), norm_proof_.begin(), norm_proof_.end());
    assert(out.size() == kSerializedSize);
    return out;
}

Result<RecoveryRootSetupProof> RecoveryRootSetupProof::deserialize(
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context) {
    constexpr std::size_t header_size = 163;
    static_assert(header_size + kNormProofSize == kSerializedSize);
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize,
                                "recovery_root:deserialize_header");
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol,
                                "recovery_root:deserialize_version");
    }
    RecoveryRootSetupProof out;
    std::copy_n(encoded.begin() + 1, 33,
                out.raw_commitment_.begin());
    std::copy_n(encoded.begin() + 34, 33,
                out.mask_commitment_.begin());
    std::copy_n(encoded.begin() + 67, 32,
                out.t2_.begin());
    std::copy_n(encoded.begin() + 99, 32,
                out.public_commitment_dlog_nonce_.begin());
    std::copy_n(encoded.begin() + 131, 32,
                out.public_commitment_dlog_response_.begin());
    out.norm_proof_.assign(encoded.begin() + header_size, encoded.end());
    PURIFY_RETURN_IF_ERROR(out.validate_encoding(secp_context),
                           "recovery_root:deserialize");
    return out;
}

Result<GeneratedKey> derive_recovery_root(
    const FieldElement& signing_scalar) {
    if (signing_scalar.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_root:zero_scalar");
    }
    auto first = magnitude(signing_scalar);
    WipeOnDestruction first_guard(first);
    auto second = first;
    WipeOnDestruction second_guard(second);
    auto reduced_second = order_n2();
    WipeOnDestruction reduced_second_guard(reduced_second);
    reduced_second.sub_assign(first);
    second.conditional_assign(reduced_second, half_n2() < second);
    PURIFY_ASSIGN_OR_RETURN(auto packed, pack_secret(first, second),
                            "recovery_root:pack");
    WipeOnDestruction packed_guard(packed);
    PURIFY_ASSIGN_OR_RETURN(auto secret, SecretKey::from_packed(packed),
                            "recovery_root:secret");
    return derive_key(std::move(secret));
}

Result<RecoveryRootSetupProof> prove_recovery_root_setup(
    const NonceHostBoundSigningRoster& roster,
    const UInt512& recovery_root, const FieldElement& signing_scalar,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_root:prove"),
        "recovery_root:prove");
    if (signing_scalar.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "recovery_root:zero_signing_scalar");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& scalar_point,
                            secp_point(signing_scalar, secp_context),
                            "recovery_root:signing_point");
    if (scalar_point != roster_point(roster)) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_root:signing_scalar");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& expected_root,
                            derive_recovery_root(signing_scalar),
                            "recovery_root:derive");
    if (expected_root.public_key != recovery_root) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_root:expected_root");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            public_setup_circuit(recovery_root),
                            "recovery_root:public_circuit");
    PURIFY_ASSIGN_OR_RETURN(auto assignment,
                            setup_assignment(recovery_root, signing_scalar),
                            "recovery_root:assignment");
    PURIFY_ASSIGN_OR_RETURN(const auto& binding,
                            setup_binding(roster, recovery_root),
                            "recovery_root:binding");
    SecretScalarBytes encoded_scalar;
    purify_scalar_get_b32(
        encoded_scalar.value.data(),
        &::purify::detail::FieldElementAccess::raw(signing_scalar));
    SecretScalarBytes secret_prover_seed;
    static const TaggedHash prover_seed_hash(
        "Purify/Accountable/RecoveryRootProverSeed/v2");
    auto prover_seed = prover_seed_hash.digest_many<2>(
        {encoded_scalar.value, binding});
    WipeOnDestruction prover_seed_guard(prover_seed);
    secret_prover_seed.value = prover_seed;
    const std::array<PointBytes, 1> outputs{roster_point(roster)};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            prove_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, assignment, secret_prover_seed.value, outputs,
            secp_context, binding,
            cache),
        "recovery_root:prove_circuit");
    RecoveryRootSetupProof proof;
    proof.raw_commitment_ = publication.proof.raw_commitment;
    proof.mask_commitment_ = publication.proof.mask_commitment;
    proof.t2_ = publication.proof.t2;
    proof.public_commitment_dlog_nonce_ =
        publication.proof.public_commitment_dlog_nonce;
    proof.public_commitment_dlog_response_ =
        publication.proof.public_commitment_dlog_response;
    proof.norm_proof_ = std::move(publication.proof.norm_proof);
    return proof;
}

Result<RecoveryRootSetupAccumulator>
RecoveryRootSetupAccumulator::create(
    purify_secp_context* secp_context) {
    static_assert(RecoveryRootSetupProof::kNormProofSize == 65 * 12 + 64);
    PURIFY_ASSIGN_OR_RETURN(
        auto basis,
        bppp::accumulation::Basis::create(
            kNormVectorLength, kNormVectorLength,
            "Purify/Accountable/RecoveryRootSetupAccumulation/v2",
            secp_context),
        "recovery_root_accumulation:basis");
    return RecoveryRootSetupAccumulator(std::move(basis));
}

Result<bppp::accumulation::AlgebraicPreparedNorm>
RecoveryRootSetupAccumulator::prepare(
    const NonceHostBoundSigningRoster& roster,
    const UInt512& recovery_root,
    const RecoveryRootSetupProof& proof,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "recovery_root_accumulation:prepare"),
        "recovery_root_accumulation:prepare");
    PURIFY_RETURN_IF_ERROR(proof.validate_encoding(secp_context),
                           "recovery_root_accumulation:proof");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit, public_setup_circuit(recovery_root),
        "recovery_root_accumulation:circuit");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding, setup_binding(roster, recovery_root),
        "recovery_root_accumulation:binding");
    const std::array<PointBytes, 1> outputs{roster_point(roster)};
    bppp::candidate::CircuitZkNormArgProofV4 circuit_proof{
        proof.raw_commitment_, proof.mask_commitment_, proof.t2_,
        proof.public_commitment_dlog_nonce_,
        proof.public_commitment_dlog_response_, proof.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, std::move(circuit_proof), outputs, secp_context,
            binding),
        "recovery_root_accumulation:publication");
    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        bppp::candidate::
            prepare_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, publication, outputs, secp_context, binding, cache),
        "recovery_root_accumulation:outer");
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "recovery_root_accumulation:outer");
    }
    return bppp::accumulation::
        prepare_v4_circuit_norm_for_algebraic_reduction(
            basis_, std::move(*prepared), secp_context);
}

Result<RecoveryBoundSigningRoster> verify_recovery_root_setup(
    NonceHostBoundSigningRoster roster, const UInt512& recovery_root,
    const RecoveryRootSetupProof& proof,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_root:verify"),
        "recovery_root:verify");
    PURIFY_RETURN_IF_ERROR(proof.validate_encoding(secp_context),
                           "recovery_root:verify_encoding");
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            public_setup_circuit(recovery_root),
                            "recovery_root:public_circuit");
    PURIFY_ASSIGN_OR_RETURN(const auto& binding,
                            setup_binding(roster, recovery_root),
                            "recovery_root:binding");
    const std::array<PointBytes, 1> outputs{roster_point(roster)};
    bppp::candidate::CircuitZkNormArgProofV4 circuit_proof{
        proof.raw_commitment_, proof.mask_commitment_, proof.t2_,
        proof.public_commitment_dlog_nonce_,
        proof.public_commitment_dlog_response_, proof.norm_proof_};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::
            reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, std::move(circuit_proof), outputs, secp_context,
            binding),
        "recovery_root:publication");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& root_valid,
        bppp::candidate::
            verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, publication, outputs, secp_context, binding),
        "recovery_root:verify_circuit");
    if (!root_valid) {
        return unexpected_error(ErrorCode::EquationMismatch,
                                "recovery_root:setup_proof");
    }
    return RecoveryBoundSigningRoster(std::move(roster), recovery_root);
}

Result<GeneratedKey> recover_registered_root(
    const RecoveryBoundSigningRoster& roster,
    const FieldElement& exposed_signing_scalar,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "recovery_root:recover"),
        "recovery_root:recover");
    PURIFY_ASSIGN_OR_RETURN(const auto& point,
                            secp_point(exposed_signing_scalar, secp_context),
                            "recovery_root:recovered_point");
    PointBytes expected{};
    expected[0] = 0x02;
    std::copy(roster.signing_key().begin(), roster.signing_key().end(),
              expected.begin() + 1);
    if (point != expected) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_root:exact_signing_key");
    }
    PURIFY_ASSIGN_OR_RETURN(auto root,
                            derive_recovery_root(exposed_signing_scalar),
                            "recovery_root:derive_exposed");
    if (root.public_key != roster.recovery_root()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "recovery_root:exact_registered_root");
    }
    return root;
}

} // namespace purify::accountable
