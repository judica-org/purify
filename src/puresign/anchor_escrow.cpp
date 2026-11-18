// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/anchor_escrow.hpp"
#include "purify/puresign/construction_leaf_accumulation.hpp"
#include "../protocol/algebraic_circuit_accumulation.hpp"
#include "../protocol/algebraic_circuit_proof.hpp"
#include "../protocol/circuit_zk_norm_arg_proof_v4_codec.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <optional>
#include <utility>
#include <vector>

#include "purify/puresign/recovery_root.hpp"
#include "purify/secp_bridge.h"
#include "anchor_escrow_internal.hpp"
#include "secure_cleanup.hpp"

namespace purify::accountable {
namespace {

using PointBytes = bppp::PointBytes;

const TaggedHash kRandomnessStatementHash(
    "Purify/Accountable/AnchorEscrowRandomnessStatement/v4");
const TaggedHash kRandomnessMasterHash(
    "Purify/Accountable/AnchorEscrowRandomnessMaster/v4");
const TaggedHash kEphemeralHash(
    "Purify/Accountable/AnchorEscrowEphemeral/v4");
const TaggedHash kProofSeedHash(
    "Purify/Accountable/AnchorEscrowProofSeed/v4");

Status require_anchor_v4_hash_suite() {
#if PURIFY_USE_LEGACY_FIELD_HASHES
    return unexpected_error(ErrorCode::UnsupportedSymbol);
#else
    return {};
#endif
}

using ::purify::detail::WipeOnDestruction;

using SecretBytes32 = ::purify::detail::Secret<bppp::ScalarBytes>;

struct EscrowOpening {
    const GeneratedKey& ephemeral;
    const FieldElement& punishment_scalar;
};

PointBytes punishment_point(const AnchorPunishmentPublicKey& key) {
    PointBytes out{};
    out[0] = 0x02;
    std::copy(key.xonly().begin(), key.xonly().end(), out.begin() + 1);
    return out;
}

Status require_roster(const NonceHostBoundSigningRoster& roster) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    return {};
}

Status require_distinct_anchor_root(
    const UInt512& recovery_root,
    const UInt512& advertised_anchor_root) {
    if (advertised_anchor_root == recovery_root) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return {};
}

Result<FieldElement> shared_pad(const SecretKey& secret,
                                const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(auto scalars, unpack_secret(secret.packed()));
    WipeOnDestruction scalars_guard(scalars);
    PURIFY_ASSIGN_OR_RETURN(const auto& points, unpack_public_points(peer));
    PURIFY_ASSIGN_OR_RETURN(
        auto first, curve1().mul_secret_affine(points.first, scalars.first));
    WipeOnDestruction first_guard(first);
    PURIFY_ASSIGN_OR_RETURN(
        auto second, curve2().mul_secret_affine(points.second, scalars.second));
    WipeOnDestruction second_guard(second);
    return combine(first.x, second.x);
}

Result<AnchorEscrowCiphertext> encrypt_anchor(
    const UInt512& recipient, const EscrowOpening& opening) {
    PURIFY_ASSIGN_OR_RETURN(auto pad,
                            shared_pad(opening.ephemeral.secret, recipient));
    WipeOnDestruction pad_guard(pad);
    AnchorEscrowCiphertext out;
    out.ephemeral_key = opening.ephemeral.public_key;
    out.masked_scalar = opening.punishment_scalar + pad;
    return out;
}

Result<Expr> escrow_relation(
    Transcript& transcript, const UInt512& recipient,
    const AnchorEscrowCiphertext& ciphertext,
    const EscrowOpening* opening) {
    PURIFY_ASSIGN_OR_RETURN(const auto& receiver,
                            unpack_public_points(recipient));
    PURIFY_RETURN_IF_ERROR(validate_public_points(ciphertext.ephemeral_key));
    PURIFY_ASSIGN_OR_RETURN(const auto ephemeral_coords,
                            unpack_public(ciphertext.ephemeral_key));

    std::array<std::vector<int>, 2> values{
        std::vector<int>(255, -1), std::vector<int>(255, -1)};
    WipeOnDestruction first_values_guard(values[0]);
    WipeOnDestruction second_values_guard(values[1]);
    if (opening != nullptr) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pair, unpack_secret(opening->ephemeral.secret.packed()));
        WipeOnDestruction pair_guard(pair);
        PURIFY_ASSIGN_OR_RETURN(values[0], key_to_bits(pair.first, half_n1()));
        PURIFY_ASSIGN_OR_RETURN(values[1], key_to_bits(pair.second, half_n2()));
    }
    std::array<std::vector<Expr>, 2> ephemeral_bits;
    for (std::size_t component = 0; component < 2; ++component) {
        auto& bits = ephemeral_bits[component];
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

    auto punishment_value =
        opening == nullptr
            ? std::optional<FieldElement>{}
            : std::optional<FieldElement>(opening->punishment_scalar);
    WipeOnDestruction punishment_value_guard(punishment_value);
    const Expr punishment = transcript.secret(punishment_value);
    const Expr ephemeral_first = circuit_ec_multiply_x(
        curve1(), transcript, generator1(), ephemeral_bits[0]);
    const Expr ephemeral_second = circuit_ec_multiply_x(
        curve2(), transcript, generator2(), ephemeral_bits[1]);
    transcript.equal(
        ephemeral_first,
        Expr(FieldElement::from_uint256(ephemeral_coords.first)));
    transcript.equal(
        ephemeral_second,
        Expr(FieldElement::from_uint256(ephemeral_coords.second)));
    const Expr shared_first = circuit_ec_multiply_x(
        curve1(), transcript, receiver.first, ephemeral_bits[0]);
    const Expr shared_second = circuit_ec_multiply_x(
        curve2(), transcript, receiver.second, ephemeral_bits[1]);
    transcript.equal(
        punishment + circuit_combine(
                         transcript, shared_first, shared_second),
        Expr(ciphertext.masked_scalar));
    return punishment;
}

Result<NativeBulletproofCircuit> public_escrow_circuit(
    const UInt512& recipient, const AnchorEscrowCiphertext& ciphertext) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto output,
        escrow_relation(transcript, recipient, ciphertext, nullptr));
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192));
    PURIFY_RETURN_IF_ERROR(bp.bind_output_to_commitment(output));
    return bp.native_circuit();
}

Result<BulletproofAssignmentData> escrow_assignment(
    const UInt512& recipient, const AnchorEscrowCiphertext& ciphertext,
    const EscrowOpening& opening) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto output,
        escrow_relation(transcript, recipient, ciphertext, &opening));
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192));
    PURIFY_RETURN_IF_ERROR(bp.bind_output_to_commitment(output));
    return bp.assignment_data(transcript.varmap(),
                              opening.punishment_scalar);
}

Bytes ciphertext_bytes(const AnchorEscrowCiphertext& ciphertext) {
    Bytes out;
    out.reserve(AnchorEscrowCiphertext::kSerializedSize);
    const auto ephemeral = ciphertext.ephemeral_key.to_bytes_be();
    const auto masked = ciphertext.masked_scalar.to_bytes_be();
    out.insert(out.end(), ephemeral.begin(), ephemeral.end());
    out.insert(out.end(), masked.begin(), masked.end());
    assert(out.size() == AnchorEscrowCiphertext::kSerializedSize);
    return out;
}

PointBytes roster_point(const NonceHostBoundSigningRoster& roster) {
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
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_RETURN_IF_ERROR(require_distinct_anchor_root(
        roster.recovery_root(), advertised_anchor_root));
    PURIFY_RETURN_IF_ERROR(validate_public_points(advertised_anchor_root));
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
    const NonceHostBoundSigningRoster& roster,
    const UInt512& recovery_root,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_RETURN_IF_ERROR(
        require_distinct_anchor_root(recovery_root, advertised_anchor_root));
    PURIFY_RETURN_IF_ERROR(validate_public_points(advertised_anchor_root));
    const auto recovery_root_bytes = recovery_root.to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto signing_key = roster_point(roster);
    const auto punishment = punishment_point(punishment_key);
    static const TaggedHash hash("Purify/Accountable/AnchorEscrow/v4");
    const auto digest = hash.digest_many<9>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root_bytes, anchor_root,
        encrypted,
        punishment, context_digest,
    });
    return Bytes(digest.begin(), digest.end());
}

Result<Bytes> escrow_binding(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext) {
    return escrow_binding(roster, roster.recovery_root(),
                          advertised_anchor_root, punishment_key,
                          context_digest, ciphertext);
}

Result<AnchorPunishmentKey> decrypt_punishment(
    const GeneratedKey& recipient,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowCiphertext& ciphertext,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto pad, shared_pad(recipient.secret, ciphertext.ephemeral_key));
    WipeOnDestruction pad_guard(pad);
    auto plaintext = (ciphertext.masked_scalar - pad).to_bytes_be();
    WipeOnDestruction plaintext_guard(plaintext);
    PURIFY_ASSIGN_OR_RETURN(auto recovered, AnchorPunishmentKey::from_secret(
                                                plaintext, secp_context));
    if (recovered.bip340_key().seckey != plaintext) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (recovered.public_key() != punishment_key) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    return recovered;
}

} // namespace

Result<AnchorPunishmentPublicKey> AnchorPunishmentPublicKey::create(
    const std::array<unsigned char, 32>& xonly,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, xonly.data()) ==
        0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return AnchorPunishmentPublicKey(xonly);
}

Result<AnchorPunishmentKey> AnchorPunishmentKey::from_secret(
    std::array<unsigned char, 32> secret,
    purify_secp_context* secp_context) {
    WipeOnDestruction secret_guard(secret);
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    Bip340Key key;
    key.seckey = secret;
    if (purify_bip340_key_from_seckey(
            secp_context, key.seckey.data(), key.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    return AnchorPunishmentKey(std::move(key));
}

Result<AnchorEscrowCircuitShape>
anchor_escrow_circuit_shape_for_testing(
    const UInt512& recipient,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto output,
        escrow_relation(transcript, recipient, ciphertext, nullptr));
    const auto relation_multiplications = transcript.muls().size();
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192));
    PURIFY_RETURN_IF_ERROR(bp.bind_output_to_commitment(output));
    return AnchorEscrowCircuitShape{
        relation_multiplications, bp.native_circuit().n_gates};
}

Status AnchorEscrowRecord::validate_encoding(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    PURIFY_RETURN_IF_ERROR(validate_public_points(ciphertext_.ephemeral_key));
    static constexpr std::size_t kRoundCount = 14;
    static_assert(kNormProofSize == 65 * kRoundCount + 64);
    return bppp::candidate::
        validate_circuit_zk_norm_arg_proof_v4_fixed_encoding(
            proof_, bppp::candidate::CircuitCommitmentModeV4::Public,
            kRoundCount, secp_context);
}

Result<Bytes> AnchorEscrowRecord::serialize(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(validate_encoding(secp_context));
    Bytes out;
    out.reserve(kSerializedSize);
    out.push_back(kSerializationVersion);
    const auto encrypted = ciphertext_bytes(ciphertext_);
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    bppp::candidate::append_circuit_proof_body_v4(out, proof_);
    assert(out.size() == kSerializedSize);
    return out;
}

Result<AnchorEscrowRecord> AnchorEscrowRecord::deserialize(
    std::span<const unsigned char> encoded,
    purify_secp_context* secp_context) {
    if (encoded.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize);
    }
    if (encoded[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::UnsupportedSymbol);
    }
    AnchorEscrowRecord out;
    std::size_t offset = 1;
    out.ciphertext_.ephemeral_key =
        UInt512::from_bytes_be(encoded.data() + offset, 64);
    offset += 64;
    std::array<unsigned char, 32> masked{};
    std::copy_n(encoded.begin() + offset, masked.size(), masked.begin());
    PURIFY_ASSIGN_OR_RETURN(out.ciphertext_.masked_scalar,
                            FieldElement::try_from_bytes32(masked));
    out.proof_ = bppp::candidate::read_circuit_proof_body_v4(
        encoded.last<kProofPayloadSize>());
    PURIFY_RETURN_IF_ERROR(out.validate_encoding(secp_context));
    return out;
}

Result<AnchorEscrowRecord> create_anchor_escrow(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    SecretBytes32 auxiliary_randomness;
    PURIFY_RETURN_IF_ERROR(fill_secure_random(auxiliary_randomness.value));
    return create_anchor_escrow_with_aux_randomness(
        roster, advertised_anchor_root, punishment_key, context_digest,
        auxiliary_randomness.value, secp_context, cache);
}

Result<AnchorEscrowRecord> create_anchor_escrow_with_aux_randomness(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const bppp::ScalarBytes& auxiliary_randomness,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_ASSIGN_OR_RETURN(const auto& randomness_statement,
                            escrow_randomness_statement(
                                roster, advertised_anchor_root,
                                punishment_key.public_key(), context_digest));
    const auto& punishment_secret = punishment_key.bip340_key().seckey;
    PURIFY_ASSIGN_OR_RETURN(auto punishment_scalar,
                            FieldElement::try_from_bytes32(punishment_secret));
    WipeOnDestruction punishment_scalar_guard(punishment_scalar);
    SecretBytes32 randomness_master;
    {
        auto digest = kRandomnessMasterHash.digest_many<3>({
            auxiliary_randomness, punishment_secret, randomness_statement});
        WipeOnDestruction digest_guard(digest);
        randomness_master.value = digest;
    }
    SecretBytes32 ephemeral_seed;
    {
        auto digest = kEphemeralHash.digest(randomness_master.value);
        WipeOnDestruction digest_guard(digest);
        ephemeral_seed.value = digest;
    }
    PURIFY_ASSIGN_OR_RETURN(auto ephemeral, generate_key(ephemeral_seed.value));
    EscrowOpening opening{
        ephemeral,
        punishment_scalar,
    };
    PURIFY_ASSIGN_OR_RETURN(const auto& ciphertext,
                            encrypt_anchor(roster.recovery_root(), opening));
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit,
        public_escrow_circuit(roster.recovery_root(), ciphertext));
    PURIFY_ASSIGN_OR_RETURN(
        auto assignment,
        escrow_assignment(roster.recovery_root(), ciphertext, opening));
    PURIFY_ASSIGN_OR_RETURN(const auto& binding,
                            escrow_binding(roster, advertised_anchor_root,
                                           punishment_key.public_key(),
                                           context_digest, ciphertext));
    SecretBytes32 prover_seed;
    {
        auto digest = kProofSeedHash.digest_many<2>({
            randomness_master.value, binding});
        WipeOnDestruction digest_guard(digest);
        prover_seed.value = digest;
    }
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key.public_key())};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::prove_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, assignment, prover_seed.value, outputs, secp_context,
            binding, cache));
    AnchorEscrowRecord record;
    record.ciphertext_ = ciphertext;
    record.proof_ = std::move(publication.proof);
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context));
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
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context));
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            public_escrow_circuit(roster.recovery_root(), record.ciphertext_));
    PURIFY_ASSIGN_OR_RETURN(const auto& binding,
                            escrow_binding(roster, advertised_anchor_root, punishment_key,
                                           context_digest, record.ciphertext_));
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, record.proof_, outputs, secp_context, binding));
    return bppp::candidate::
        verify_circuit_zk_norm_arg_v4_with_public_commitments(
            circuit, publication, outputs, secp_context, binding, cache);
}

Result<ConstructionLeafAccumulator> ConstructionLeafAccumulator::create(
    purify_secp_context* secp_context) {
    static_assert(AnchorEscrowRecord::kNormProofSize == 65 * 14 + 64);
    static_assert(RecoveryRootContribution::kNormProofSize ==
                  AnchorEscrowRecord::kNormProofSize);
    PURIFY_ASSIGN_OR_RETURN(
        auto basis, bppp::accumulation::Basis::create(
                        kNormVectorLength, kNormVectorLength,
                        "Purify/Accountable/ConstructionLeafAccumulation/v1",
                        secp_context));
    return ConstructionLeafAccumulator(std::move(basis));
}

Result<ConstructionLeafParentConstants>
ConstructionLeafAccumulator::derive_parent_constants(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext,
    const bppp::ScalarBytes& circuit_precommitment,
    purify_secp_context* secp_context) const {
    return derive_pending_anchor_parent_constants(
        roster, roster.recovery_root(), advertised_anchor_root,
        punishment_key, context_digest, ciphertext,
        circuit_precommitment, secp_context);
}

Result<ConstructionLeafParentConstants>
ConstructionLeafAccumulator::derive_pending_anchor_parent_constants(
    const NonceHostBoundSigningRoster& roster,
    const UInt512& recovery_root,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowCiphertext& ciphertext,
    const bppp::ScalarBytes& circuit_precommitment,
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_ASSIGN_OR_RETURN(
        const auto precommitment,
        bppp::candidate::CircuitPrecommitmentDigestV4::parse(
            circuit_precommitment));
    PURIFY_ASSIGN_OR_RETURN(const auto circuit,
                            public_escrow_circuit(recovery_root, ciphertext));
    PURIFY_ASSIGN_OR_RETURN(
        const auto binding,
        escrow_binding(roster, recovery_root, advertised_anchor_root,
                       punishment_key, context_digest, ciphertext));
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    PURIFY_ASSIGN_OR_RETURN(
        auto constants,
        bppp::candidate::
            derive_circuit_norm_parent_constants_v4_with_public_commitments(
                circuit, precommitment, outputs, secp_context, binding));
    return ConstructionLeafParentConstants{
        std::move(constants.circuit_binding_digest),
        std::move(constants.raw_generator_digest),
        std::move(constants.coefficient_commitment),
        std::move(constants.anchored_offset)};
}

Result<PreparedConstructionLeaf>
ConstructionLeafAccumulator::prepare(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) const {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    PURIFY_RETURN_IF_ERROR(require_roster(roster));
    PURIFY_RETURN_IF_ERROR(record.validate_encoding(secp_context));
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            public_escrow_circuit(roster.recovery_root(), record.ciphertext_));
    PURIFY_ASSIGN_OR_RETURN(const auto& binding,
                            escrow_binding(roster, advertised_anchor_root, punishment_key,
                                           context_digest, record.ciphertext_));
    const std::array<PointBytes, 1> outputs{
        punishment_point(punishment_key)};
    PURIFY_ASSIGN_OR_RETURN(
        auto publication,
        bppp::candidate::reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
            circuit, record.proof_, outputs, secp_context, binding));
    const auto circuit_precommitment =
        publication.precommitment.bytes();
    PURIFY_ASSIGN_OR_RETURN(auto prepared,
                            bppp::candidate::prepare_circuit_zk_norm_arg_v4_with_public_commitments(
                                circuit, publication, outputs, secp_context, binding, cache));
    if (!prepared.has_value()) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto norm,
                            bppp::accumulation::prepare_v4_circuit_norm_for_algebraic_reduction(
                                basis_, std::move(*prepared), secp_context));
    return PreparedConstructionLeaf(circuit_precommitment, std::move(norm));
}

Result<AnchorPunishmentKey> recover_distributed_escrowed_anchor(
    const VerifiedDistributedRecoverySetup& setup,
    const FieldElement& exposed_signing_scalar,
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    const AnchorEscrowRecord& record,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recipient,
        recover_aggregated_recovery_root(setup.roster(), setup.aggregate(),
                                         exposed_signing_scalar, secp_context));
    PURIFY_ASSIGN_OR_RETURN(const auto accepted,
                            verify_anchor_escrow(setup.roster(),
                                                 advertised_anchor_root,
                                                 punishment_key, context_digest,
                                                 record, secp_context, cache));
    if (!accepted) {
        return unexpected_error(ErrorCode::EquationMismatch);
    }
    return recover_authenticated_anchor_ciphertext(
        recipient, punishment_key, record.ciphertext(), secp_context);
}

Result<AnchorPunishmentKey> recover_authenticated_anchor_ciphertext(
    const GeneratedKey& recovered_recipient,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowCiphertext& ciphertext,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(require_anchor_v4_hash_suite());
    return decrypt_punishment(recovered_recipient, punishment_key,
                              ciphertext, secp_context);
}

} // namespace purify::accountable
