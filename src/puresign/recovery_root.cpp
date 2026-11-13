// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/recovery_root.hpp"
#include "purify/puresign/recovery_root_accumulation.hpp"
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
#include "secure_cleanup.hpp"

namespace purify::accountable {
namespace {

using PointBytes = bppp::PointBytes;
using ::purify::detail::WipeOnDestruction;

using SecretScalarBytes = ::purify::detail::Secret<bppp::ScalarBytes>;

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
        &detail::FieldElementAccess::raw(value));
    return bppp::pedersen_commit_char(zero, encoded_value.value, context,
                                      generator, generator);
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

Result<CircuitMainResult> setup_relation(
    Transcript& transcript,
    const std::optional<FieldElement>& scalar = std::nullopt) {
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
    const auto recoded = signed_window_bits(transcript, bits);
    const Expr first = circuit_ec_multiply_x(
        curve1(), transcript, generator1(), recoded);
    const Expr second = circuit_ec_multiply_x(
        curve2(), transcript, generator2(), recoded);
    return CircuitMainResult{
        transcript.mul(Expr(1) - 2 * sign, scalar_value), first, second,
        bits.size() + 1};
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
                            setup_relation(transcript, scalar),
                            "recovery_root:witness");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits),
                           "recovery_root:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.add_pubkey_and_out(root, relation.p1x, relation.p2x, relation.out),
        "recovery_root:bind");
    return bp.assignment_data(transcript.varmap(), scalar);
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

} // namespace

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
        &detail::FieldElementAccess::raw(signing_scalar));
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
