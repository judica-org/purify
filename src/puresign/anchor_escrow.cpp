// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/anchor_escrow.hpp"
#include "purify/puresign/construction_leaf_accumulation.hpp"
#include "../protocol/algebraic_circuit_accumulation.hpp"
#include "../protocol/algebraic_circuit_proof.hpp"

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

Status require_anchor_v4_hash_suite(const char* label) {
#if PURIFY_USE_LEGACY_FIELD_HASHES
    return unexpected_error(ErrorCode::UnsupportedSymbol, label);
#else
    (void)label;
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

Status require_roster(const RecoveryBoundSigningRoster& roster,
                      const char* label) {
    if (roster.members().empty()) {
        return unexpected_error(ErrorCode::EmptyInput, label);
    }
    return {};
}

Status require_distinct_anchor_root(
    const RecoveryBoundSigningRoster& roster,
    const UInt512& advertised_anchor_root,
    const char* label) {
    if (advertised_anchor_root == roster.recovery_root()) {
        return unexpected_error(ErrorCode::BindingMismatch, label);
    }
    return {};
}

Result<FieldElement> shared_pad(const SecretKey& secret,
                                const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(auto scalars, unpack_secret(secret.packed()),
                            "anchor_escrow:shared_secret");
    WipeOnDestruction scalars_guard(scalars);
    PURIFY_ASSIGN_OR_RETURN(const auto& points,
                            unpack_public_points(peer),
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
    PURIFY_ASSIGN_OR_RETURN(
        auto pad,
        shared_pad(opening.ephemeral.secret, recipient),
        "anchor_escrow:encrypt_pad");
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
    PURIFY_ASSIGN_OR_RETURN(
        const auto& receiver,
        unpack_public_points(recipient),
        "anchor_escrow:recipient");
    PURIFY_RETURN_IF_ERROR(
        validate_public_points(ciphertext.ephemeral_key),
        "anchor_escrow:ephemeral");
    PURIFY_ASSIGN_OR_RETURN(
        const auto ephemeral_coords,
        unpack_public(ciphertext.ephemeral_key),
        "anchor_escrow:ephemeral_coords");

    std::array<std::vector<int>, 2> values{
        std::vector<int>(255, -1), std::vector<int>(255, -1)};
    WipeOnDestruction first_values_guard(values[0]);
    WipeOnDestruction second_values_guard(values[1]);
    if (opening != nullptr) {
        PURIFY_ASSIGN_OR_RETURN(
            auto pair,
            unpack_secret(opening->ephemeral.secret.packed()),
            "anchor_escrow:ephemeral_secret");
        WipeOnDestruction pair_guard(pair);
        PURIFY_ASSIGN_OR_RETURN(
            values[0], key_to_bits(pair.first, half_n1()),
            "anchor_escrow:ephemeral_first_bits");
        PURIFY_ASSIGN_OR_RETURN(
            values[1], key_to_bits(pair.second, half_n2()),
            "anchor_escrow:ephemeral_second_bits");
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
        escrow_relation(transcript, recipient, ciphertext, nullptr),
        "anchor_escrow:relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192),
                           "anchor_escrow:lower");
    PURIFY_RETURN_IF_ERROR(
        bp.bind_output_to_commitment(output),
        "anchor_escrow:bind_punishment");
    return bp.native_circuit();
}

Result<BulletproofAssignmentData> escrow_assignment(
    const UInt512& recipient, const AnchorEscrowCiphertext& ciphertext,
    const EscrowOpening& opening) {
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto output,
        escrow_relation(transcript, recipient, ciphertext, &opening),
        "anchor_escrow:witness_relation");
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192),
                           "anchor_escrow:lower_witness");
    PURIFY_RETURN_IF_ERROR(
        bp.bind_output_to_commitment(output),
        "anchor_escrow:bind_punishment_witness");
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
    PURIFY_RETURN_IF_ERROR(
        require_distinct_anchor_root(
            roster, advertised_anchor_root,
            "anchor_escrow:recovery_root_alias"),
        "anchor_escrow:randomness_anchor_root");
    PURIFY_RETURN_IF_ERROR(
        validate_public_points(advertised_anchor_root),
        "anchor_escrow:randomness_anchor_root");
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
    PURIFY_RETURN_IF_ERROR(
        require_distinct_anchor_root(
            roster, advertised_anchor_root,
            "anchor_escrow:recovery_root_alias"),
        "anchor_escrow:binding_anchor_root");
    PURIFY_RETURN_IF_ERROR(
        validate_public_points(advertised_anchor_root),
        "anchor_escrow:binding_anchor_root");
    const auto recovery_root = roster.recovery_root().to_bytes_be();
    const auto anchor_root = advertised_anchor_root.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto signing_key = roster_point(roster);
    const auto punishment = punishment_point(punishment_key);
    static const TaggedHash hash("Purify/Accountable/AnchorEscrow/v4");
    const auto digest = hash.digest_many<9>({
        signing_key, roster.key_list_hash(), roster.coalition_core_digest(),
        roster.nonce_host_commitment(), recovery_root, anchor_root, encrypted,
        punishment, context_digest,
    });
    return Bytes(digest.begin(), digest.end());
}

Result<AnchorPunishmentKey> decrypt_punishment(
    const GeneratedKey& recipient,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowCiphertext& ciphertext,
    purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto pad,
        shared_pad(recipient.secret, ciphertext.ephemeral_key),
        "anchor_escrow:decrypt_pad");
    WipeOnDestruction pad_guard(pad);
    auto plaintext = (ciphertext.masked_scalar - pad).to_bytes_be();
    WipeOnDestruction plaintext_guard(plaintext);
    PURIFY_ASSIGN_OR_RETURN(
        auto recovered,
        AnchorPunishmentKey::from_secret(plaintext, secp_context),
        "anchor_escrow:decrypt_plaintext");
    if (recovered.bip340_key().seckey != plaintext) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "anchor_escrow:noncanonical_plaintext");
    }
    if (recovered.public_key() != punishment_key) {
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

Result<AnchorPunishmentKey> AnchorPunishmentKey::from_secret(
    std::array<unsigned char, 32> secret,
    purify_secp_context* secp_context) {
    WipeOnDestruction secret_guard(secret);
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context,
                             "anchor_escrow:punishment_secret"),
        "anchor_escrow:punishment_secret");
    Bip340Key key;
    key.seckey = secret;
    if (purify_bip340_key_from_seckey(
            secp_context, key.seckey.data(), key.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "anchor_escrow:punishment_secret");
    }
    return AnchorPunishmentKey(std::move(key));
}

Result<AnchorEscrowCircuitShape>
anchor_escrow_circuit_shape_for_testing(
    const UInt512& recipient,
    const AnchorEscrowCiphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite("anchor_escrow:shape_hash_suite"),
        "anchor_escrow:shape_hash_suite");
    Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(
        const auto output,
        escrow_relation(transcript, recipient, ciphertext, nullptr),
        "anchor_escrow:shape_relation");
    const auto relation_multiplications = transcript.muls().size();
    BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, 2 * 255, 8192),
                           "anchor_escrow:shape_lower");
    PURIFY_RETURN_IF_ERROR(
        bp.bind_output_to_commitment(output),
        "anchor_escrow:shape_bind");
    return AnchorEscrowCircuitShape{
        relation_multiplications, bp.native_circuit().n_gates};
}

Status AnchorEscrowRecord::validate_encoding(
    purify_secp_context* secp_context) const {
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:record"),
        "anchor_escrow:record");
    PURIFY_RETURN_IF_ERROR(
        validate_public_points(ciphertext_.ephemeral_key),
        "anchor_escrow:ciphertext_ephemeral");
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
    out.ciphertext_.ephemeral_key =
        UInt512::from_bytes_be(encoded.data() + offset, 64);
    offset += 64;
    std::array<unsigned char, 32> masked{};
    std::copy_n(encoded.begin() + offset, masked.size(), masked.begin());
    offset += masked.size();
    PURIFY_ASSIGN_OR_RETURN(
        out.ciphertext_.masked_scalar,
        FieldElement::try_from_bytes32(masked),
        "anchor_escrow:deserialize_masked");
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
    const UInt512& advertised_anchor_root,
    const AnchorPunishmentKey& punishment_key,
    const AnchorEscrowContextDigest& context_digest,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* cache) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite("anchor_escrow:create_hash_suite"),
        "anchor_escrow:create_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create"),
        "anchor_escrow:create");
    SecretBytes32 auxiliary_randomness;
    PURIFY_RETURN_IF_ERROR(fill_secure_random(auxiliary_randomness.value),
                           "anchor_escrow:auxiliary_randomness");
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
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite(
            "anchor_escrow:create_aux_hash_suite"),
        "anchor_escrow:create_aux_hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow:create_aux"),
        "anchor_escrow:create_aux");
    PURIFY_RETURN_IF_ERROR(require_roster(roster,
                                         "anchor_escrow:empty_roster"),
                           "anchor_escrow:create_roster");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& randomness_statement,
        escrow_randomness_statement(roster,
                                    advertised_anchor_root,
                                    punishment_key.public_key(),
                                    context_digest),
        "anchor_escrow:randomness_statement");
    const auto& punishment_secret = punishment_key.bip340_key().seckey;
    PURIFY_ASSIGN_OR_RETURN(
        auto punishment_scalar,
        FieldElement::try_from_bytes32(punishment_secret),
        "anchor_escrow:punishment_scalar");
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
    PURIFY_ASSIGN_OR_RETURN(auto ephemeral,
                            generate_key(ephemeral_seed.value),
                            "anchor_escrow:ephemeral");
    EscrowOpening opening{
        ephemeral,
        punishment_scalar,
    };
    PURIFY_ASSIGN_OR_RETURN(
        const auto& ciphertext,
        encrypt_anchor(roster.recovery_root(), opening),
        "anchor_escrow:encrypt");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& circuit,
        public_escrow_circuit(roster.recovery_root(), ciphertext),
        "anchor_escrow:public_circuit");
    PURIFY_ASSIGN_OR_RETURN(
        auto assignment,
        escrow_assignment(roster.recovery_root(), ciphertext, opening),
        "anchor_escrow:assignment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto& binding,
        escrow_binding(roster, advertised_anchor_root,
                       punishment_key.public_key(), context_digest,
                       ciphertext),
        "anchor_escrow:binding");
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
        require_anchor_v4_hash_suite("anchor_escrow:verify_hash_suite"),
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
        public_escrow_circuit(roster.recovery_root(), record.ciphertext_),
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

Result<ConstructionLeafAccumulator> ConstructionLeafAccumulator::create(
    purify_secp_context* secp_context) {
    static_assert(AnchorEscrowRecord::kNormProofSize == 65 * 14 + 64);
    PURIFY_ASSIGN_OR_RETURN(
        auto basis,
        bppp::accumulation::Basis::create(
            kNormVectorLength, kNormVectorLength,
            "Purify/Accountable/AnchorEscrowAccumulation/v4",
            secp_context),
        "anchor_escrow_accumulation:basis");
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
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite(
            "anchor_escrow_parent:hash_suite"),
        "anchor_escrow_parent:hash_suite");
    PURIFY_RETURN_IF_ERROR(
        require_secp_context(secp_context, "anchor_escrow_parent:context"),
        "anchor_escrow_parent:context");
    PURIFY_RETURN_IF_ERROR(
        require_roster(roster, "anchor_escrow_parent:empty_roster"),
        "anchor_escrow_parent:roster");
    PURIFY_ASSIGN_OR_RETURN(
        const auto precommitment,
        bppp::candidate::CircuitPrecommitmentDigestV4::parse(
            circuit_precommitment),
        "anchor_escrow_parent:precommitment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto circuit,
        public_escrow_circuit(roster.recovery_root(), ciphertext),
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
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite(
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
        public_escrow_circuit(roster.recovery_root(), record.ciphertext_),
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
    return PreparedConstructionLeaf(circuit_precommitment, std::move(norm));
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
        require_anchor_v4_hash_suite("anchor_escrow:recover_hash_suite"),
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
    return recover_authenticated_anchor_ciphertext(
        recipient, punishment_key, record.ciphertext(), secp_context);
}

Result<AnchorPunishmentKey> recover_authenticated_anchor_ciphertext(
    const GeneratedKey& recovered_recipient,
    const AnchorPunishmentPublicKey& punishment_key,
    const AnchorEscrowCiphertext& ciphertext,
    purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(
        require_anchor_v4_hash_suite(
            "anchor_escrow:recover_authenticated_hash_suite"),
        "anchor_escrow:recover_authenticated_hash_suite");
    return decrypt_punishment(recovered_recipient, punishment_key,
                              ciphertext, secp_context);
}

} // namespace purify::accountable
