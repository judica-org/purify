// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_puresign_plusplus.cpp
 * @brief Experimental BPPP-backed PureSign proof(R) helpers.
 */

#include "purify/puresign_plusplus.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

#include "purify_secp_bridge.h"

namespace purify::puresign_plusplus {
namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageProofTag = "PureSign/BPPP/Proof/Message/V1";
constexpr std::string_view kTopicProofTag = "PureSign/BPPP/Proof/Topic/V1";

using Scope = PreparedNonce::Scope;

Bytes copy_bytes(std::span<const unsigned char> input) {
    return Bytes(input.begin(), input.end());
}

Bytes tagged_eval_input(std::string_view tag, std::span<const unsigned char> input) {
    Bytes out;
    out.reserve(tag.size() + input.size());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), input.begin(), input.end());
    return out;
}

void append_u32_le(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
    }
}

std::optional<std::uint32_t> read_u32_le(std::span<const unsigned char> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    if (offset + 4 > bytes.size()) {
        return std::nullopt;
    }
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(bytes[offset + i]) << (8 * i);
    }
    return value;
}

std::string_view proof_tag_for_scope(Scope scope) {
    return scope == Scope::Message ? kMessageProofTag : kTopicProofTag;
}

Bytes proof_statement_binding(Scope scope) {
    return bytes_from_ascii(proof_tag_for_scope(scope));
}

Scalar32 derive_proof_nonce_seed(const UInt512& secret, Scope scope, std::span<const unsigned char> eval_input) {
    std::array<unsigned char, 64> secret_bytes = secret.to_bytes_be();
    Bytes key(secret_bytes.begin(), secret_bytes.end());
    Bytes data = bytes_from_ascii(proof_tag_for_scope(scope));
    data.insert(data.end(), eval_input.begin(), eval_input.end());
    Bytes digest = hmac_sha256(key, data);
    Scalar32 out{};
    assert(digest.size() == out.size() && "hmac_sha256() should return 32 bytes");
    std::copy(digest.begin(), digest.end(), out.begin());
    return out;
}

bool is_power_of_two_size(std::size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

Status validate_public_key_bundle(const PublicKey& public_key) {
    Status pubkey_status = validate_public_key(public_key.purify_pubkey);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "puresign_plusplus:validate_public_key_bundle:purify_pubkey");
    }
    if (purify_bip340_validate_xonly_pubkey(public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "puresign_plusplus:validate_public_key_bundle:bip340_pubkey");
    }
    return {};
}

template <typename CircuitLike>
Status validate_proof_cache_circuit(const CircuitLike& circuit, const char* context) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    if (!is_power_of_two_size(circuit.n_gates)) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    if (circuit.n_commitments != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions, context);
    }
    return {};
}

Status validate_message_proof_cache(const MessageProofCache& cache) {
    if (cache.eval_input != tagged_eval_input(kMessageNonceTag, cache.message)) {
        return unexpected_error(ErrorCode::BindingMismatch, "validate_message_proof_cache:eval_input");
    }
    return {};
}

Status validate_topic_proof_cache(const TopicProofCache& cache) {
    if (cache.topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "validate_topic_proof_cache:empty_topic");
    }
    if (cache.eval_input != tagged_eval_input(kTopicNonceTag, cache.topic)) {
        return unexpected_error(ErrorCode::BindingMismatch, "validate_topic_proof_cache:eval_input");
    }
    return {};
}

Result<bppp::PointBytes> commitment_point_from_scalar(const FieldElement& scalar) {
    Scalar32 blind{};
    return bppp::pedersen_commit_char(blind, bppp::scalar_bytes(scalar), bppp::base_generator());
}

Result<bool> nonce_proof_matches_nonce(const NonceProof& nonce_proof) {
    XOnly32 xonly{};
    int parity = 0;
    if (purify_bip340_xonly_from_point(nonce_proof.commitment_point.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "nonce_proof_matches_nonce:invalid_commitment_point");
    }
    (void)parity;
    return xonly == nonce_proof.nonce.xonly;
}

Result<NonceProof> build_nonce_proof_from_template(const UInt512& secret,
                                                   Scope scope,
                                                   const Nonce& expected_nonce,
                                                   std::span<const unsigned char> eval_input,
                                                   const NativeBulletproofCircuitTemplate& circuit_template) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(copy_bytes(eval_input), secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "build_nonce_proof_from_template:prove_assignment_data");
    }
    Result<bool> partial_ok = circuit_template.partial_evaluate(witness->assignment);
    if (!partial_ok.has_value()) {
        return unexpected_error(partial_ok.error(), "build_nonce_proof_from_template:partial_evaluate");
    }
    if (!*partial_ok) {
        return unexpected_error(ErrorCode::BindingMismatch, "build_nonce_proof_from_template:partial_evaluate_false");
    }
    Result<bool> final_ok = circuit_template.final_evaluate(witness->assignment, witness->public_key);
    if (!final_ok.has_value()) {
        return unexpected_error(final_ok.error(), "build_nonce_proof_from_template:final_evaluate");
    }
    if (!*final_ok) {
        return unexpected_error(ErrorCode::BindingMismatch, "build_nonce_proof_from_template:final_evaluate_false");
    }
    Result<NativeBulletproofCircuit> circuit = circuit_template.instantiate(witness->public_key);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "build_nonce_proof_from_template:instantiate");
    }
    Status circuit_status =
        validate_proof_cache_circuit(*circuit, "build_nonce_proof_from_template:circuit_shape");
    if (!circuit_status.has_value()) {
        return unexpected_error(circuit_status.error(),
                                "build_nonce_proof_from_template:validate_proof_cache_circuit");
    }

    Result<bppp::PointBytes> commitment_point =
        commitment_point_from_scalar(witness->assignment.commitments.front());
    if (!commitment_point.has_value()) {
        return unexpected_error(commitment_point.error(),
                                "build_nonce_proof_from_template:commitment_point_from_scalar");
    }
    Scalar32 proof_nonce = derive_proof_nonce_seed(secret, scope, eval_input);
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{*commitment_point};
    Result<bppp::ExperimentalCircuitZkNormArgProof> proof =
        bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            *circuit, witness->assignment, proof_nonce, public_commitments, statement_binding);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(),
                                "build_nonce_proof_from_template:prove_experimental_circuit_zk_norm_arg_with_public_commitments");
    }

    NonceProof out{};
    out.nonce = expected_nonce;
    out.commitment_point = *commitment_point;
    out.proof = std::move(*proof);
    Result<bool> match = nonce_proof_matches_nonce(out);
    if (!match.has_value()) {
        return unexpected_error(match.error(), "build_nonce_proof_from_template:nonce_proof_matches_nonce");
    }
    if (!*match) {
        return unexpected_error(ErrorCode::InternalMismatch, "build_nonce_proof_from_template:nonce_mismatch");
    }
    return out;
}

Result<NonceProof> build_nonce_proof(const UInt512& secret,
                                     Scope scope,
                                     std::span<const unsigned char> input,
                                     const Nonce& expected_nonce) {
    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    Result<NativeBulletproofCircuitTemplate> circuit_template =
        verifier_circuit_template(tagged_eval_input(nonce_tag, input));
    if (!circuit_template.has_value()) {
        return unexpected_error(circuit_template.error(), "build_nonce_proof:verifier_circuit_template");
    }
    Bytes eval_input = tagged_eval_input(nonce_tag, input);
    return build_nonce_proof_from_template(secret, scope, expected_nonce, eval_input, *circuit_template);
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key,
                                             const NativeBulletproofCircuit& circuit,
                                             const NonceProof& nonce_proof,
                                             Scope scope,
                                             const char* context) {
    Status key_status = validate_public_key_bundle(public_key);
    if (!key_status.has_value()) {
        return unexpected_error(key_status.error(), context);
    }
    Status circuit_status = validate_proof_cache_circuit(circuit, context);
    if (!circuit_status.has_value()) {
        return unexpected_error(circuit_status.error(), context);
    }
    Result<bool> match = nonce_proof_matches_nonce(nonce_proof);
    if (!match.has_value()) {
        return unexpected_error(match.error(), context);
    }
    if (!*match) {
        return false;
    }
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{nonce_proof.commitment_point};
    return bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, nonce_proof.proof, public_commitments, statement_binding);
}

}  // namespace

Result<Bytes> NonceProof::serialize() const {
    Result<bool> match = nonce_proof_matches_nonce(*this);
    if (!match.has_value()) {
        return unexpected_error(match.error(), "NonceProof::serialize:nonce_proof_matches_nonce");
    }
    if (!*match) {
        return unexpected_error(ErrorCode::BindingMismatch, "NonceProof::serialize:nonce_mismatch");
    }
    if (proof.proof.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize, "NonceProof::serialize:proof_size");
    }

    Bytes out;
    out.reserve(1 + 4 + 32 + 33 + 33 + 33 + 32 + proof.proof.size());
    out.push_back(kSerializationVersion);
    append_u32_le(out, static_cast<std::uint32_t>(proof.proof.size()));
    out.insert(out.end(), nonce.xonly.begin(), nonce.xonly.end());
    out.insert(out.end(), commitment_point.begin(), commitment_point.end());
    out.insert(out.end(), proof.a_commitment.begin(), proof.a_commitment.end());
    out.insert(out.end(), proof.s_commitment.begin(), proof.s_commitment.end());
    out.insert(out.end(), proof.t2.begin(), proof.t2.end());
    out.insert(out.end(), proof.proof.begin(), proof.proof.end());
    return out;
}

Result<NonceProof> NonceProof::deserialize(std::span<const unsigned char> serialized) {
    constexpr std::size_t kHeaderSize = 1 + 4 + 32 + 33 + 33 + 33 + 32;
    if (serialized.size() < kHeaderSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "NonceProof::deserialize:header");
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "NonceProof::deserialize:version");
    }
    std::optional<std::uint32_t> proof_size = read_u32_le(serialized, 1);
    assert(proof_size.has_value() && "header length check should guarantee a u32 proof size");
    if (kHeaderSize + *proof_size != serialized.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "NonceProof::deserialize:proof_size");
    }

    NonceProof out{};
    std::copy_n(serialized.begin() + 5, 32, out.nonce.xonly.begin());
    if (purify_bip340_validate_xonly_pubkey(out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "NonceProof::deserialize:nonce");
    }
    std::copy_n(serialized.begin() + 37, 33, out.commitment_point.begin());
    std::copy_n(serialized.begin() + 70, 33, out.proof.a_commitment.begin());
    std::copy_n(serialized.begin() + 103, 33, out.proof.s_commitment.begin());
    std::copy_n(serialized.begin() + 136, 32, out.proof.t2.begin());
    out.proof.proof.assign(serialized.begin() + 168, serialized.end());

    Result<bool> match = nonce_proof_matches_nonce(out);
    if (!match.has_value()) {
        return unexpected_error(match.error(), "NonceProof::deserialize:nonce_proof_matches_nonce");
    }
    if (!*match) {
        return unexpected_error(ErrorCode::BindingMismatch, "NonceProof::deserialize:nonce_mismatch");
    }
    return out;
}

Result<Bytes> ProvenSignature::serialize() const {
    Result<Bytes> nonce_proof_bytes = nonce_proof.serialize();
    if (!nonce_proof_bytes.has_value()) {
        return unexpected_error(nonce_proof_bytes.error(), "ProvenSignature::serialize:nonce_proof");
    }
    if (nonce_proof_bytes->size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return unexpected_error(ErrorCode::UnexpectedSize, "ProvenSignature::serialize:nonce_proof_size");
    }

    Bytes out;
    out.reserve(1 + 4 + nonce_proof_bytes->size() + 64);
    out.push_back(kSerializationVersion);
    append_u32_le(out, static_cast<std::uint32_t>(nonce_proof_bytes->size()));
    out.insert(out.end(), nonce_proof_bytes->begin(), nonce_proof_bytes->end());
    out.insert(out.end(), signature.bytes.begin(), signature.bytes.end());
    return out;
}

Result<ProvenSignature> ProvenSignature::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() < 69) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ProvenSignature::deserialize:header");
    }
    if (serialized[0] != kSerializationVersion) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "ProvenSignature::deserialize:version");
    }
    std::optional<std::uint32_t> nonce_proof_size = read_u32_le(serialized, 1);
    assert(nonce_proof_size.has_value() && "header length check should guarantee a u32 nonce proof size");
    if (5 + *nonce_proof_size + 64 != serialized.size()) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "ProvenSignature::deserialize:size");
    }

    Result<NonceProof> nonce_proof_value = NonceProof::deserialize(serialized.subspan(5, *nonce_proof_size));
    if (!nonce_proof_value.has_value()) {
        return unexpected_error(nonce_proof_value.error(), "ProvenSignature::deserialize:nonce_proof");
    }
    Result<Signature> signature_value = Signature::deserialize(serialized.subspan(5 + *nonce_proof_size, 64));
    if (!signature_value.has_value()) {
        return unexpected_error(signature_value.error(), "ProvenSignature::deserialize:signature");
    }
    return ProvenSignature{*signature_value, *nonce_proof_value};
}

Result<PublicKey> derive_public_key(const UInt512& secret) {
    return purify::puresign::derive_public_key(secret);
}

Result<MessageProofCache> build_message_proof_cache(std::span<const unsigned char> message) {
    return purify::puresign::build_message_proof_cache(message);
}

Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic) {
    return purify::puresign::build_topic_proof_cache(topic);
}

Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message) {
    return purify::puresign::prepare_message_nonce(secret, message);
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                std::span<const unsigned char> message) {
    Result<PreparedNonce> prepared = purify::puresign::prepare_message_nonce(secret, message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "prepare_message_nonce_with_proof:prepare_message_nonce");
    }
    Result<NonceProof> proof = build_nonce_proof(secret, Scope::Message, message, prepared->public_nonce());
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_message_nonce_with_proof:build_nonce_proof");
    }
    return PreparedNonceWithProof(std::move(*prepared), std::move(*proof));
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                const MessageProofCache& cache) {
    Status cache_status = validate_message_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "prepare_message_nonce_with_proof:validate_message_proof_cache");
    }
    Result<PreparedNonce> prepared = purify::puresign::prepare_message_nonce(secret, cache.message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "prepare_message_nonce_with_proof:prepare_message_nonce");
    }
    Result<NonceProof> proof =
        build_nonce_proof_from_template(secret, Scope::Message, prepared->public_nonce(),
                                        cache.eval_input, cache.circuit_template);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_message_nonce_with_proof:build_nonce_proof_from_template");
    }
    return PreparedNonceWithProof(std::move(*prepared), std::move(*proof));
}

Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic) {
    return purify::puresign::prepare_topic_nonce(secret, topic);
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              std::span<const unsigned char> topic) {
    Result<PreparedNonce> prepared = purify::puresign::prepare_topic_nonce(secret, topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "prepare_topic_nonce_with_proof:prepare_topic_nonce");
    }
    Result<NonceProof> proof = build_nonce_proof(secret, Scope::Topic, topic, prepared->public_nonce());
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_topic_nonce_with_proof:build_nonce_proof");
    }
    return PreparedNonceWithProof(std::move(*prepared), std::move(*proof));
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              const TopicProofCache& cache) {
    Status cache_status = validate_topic_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "prepare_topic_nonce_with_proof:validate_topic_proof_cache");
    }
    Result<PreparedNonce> prepared = purify::puresign::prepare_topic_nonce(secret, cache.topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "prepare_topic_nonce_with_proof:prepare_topic_nonce");
    }
    Result<NonceProof> proof =
        build_nonce_proof_from_template(secret, Scope::Topic, prepared->public_nonce(),
                                        cache.eval_input, cache.circuit_template);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_topic_nonce_with_proof:build_nonce_proof_from_template");
    }
    return PreparedNonceWithProof(std::move(*prepared), std::move(*proof));
}

Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message) {
    return purify::puresign::sign_message(secret, message);
}

Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared) {
    return purify::puresign::sign_message_with_prepared(secret, message, std::move(prepared));
}

Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret,
                                                         std::span<const unsigned char> message,
                                                         PreparedNonceWithProof&& prepared) {
    NonceProof nonce_proof = prepared.proof_;
    Result<Signature> signature = purify::puresign::sign_message_with_prepared(secret, message,
                                                                               std::move(prepared.prepared_));
    if (!signature.has_value()) {
        return unexpected_error(signature.error(), "sign_message_with_prepared_proof:sign_message_with_prepared");
    }
    if (signature->nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_message_with_prepared_proof:nonce_mismatch");
    }
    return ProvenSignature{*signature, std::move(nonce_proof)};
}

Result<Signature> sign_with_topic(const UInt512& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic) {
    return purify::puresign::sign_with_topic(secret, message, topic);
}

Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared) {
    return purify::puresign::sign_with_prepared_topic(secret, message, std::move(prepared));
}

Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret,
                                                       std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared) {
    NonceProof nonce_proof = prepared.proof_;
    Result<Signature> signature = purify::puresign::sign_with_prepared_topic(secret, message,
                                                                             std::move(prepared.prepared_));
    if (!signature.has_value()) {
        return unexpected_error(signature.error(), "sign_with_prepared_topic_proof:sign_with_prepared_topic");
    }
    if (signature->nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "sign_with_prepared_topic_proof:nonce_mismatch");
    }
    return ProvenSignature{*signature, std::move(nonce_proof)};
}

Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, std::span<const unsigned char> message) {
    Result<PreparedNonceWithProof> prepared = prepare_message_nonce_with_proof(secret, message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(secret, message, std::move(*prepared));
}

Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, const MessageProofCache& cache) {
    Result<PreparedNonceWithProof> prepared =
        purify::puresign_plusplus::prepare_message_nonce_with_proof(secret, cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(secret, cache.message, std::move(*prepared));
}

Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic) {
    Result<PreparedNonceWithProof> prepared = prepare_topic_nonce_with_proof(secret, topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(secret, message, std::move(*prepared));
}

Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache) {
    Result<PreparedNonceWithProof> prepared =
        purify::puresign_plusplus::prepare_topic_nonce_with_proof(secret, cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(secret, message, std::move(*prepared));
}

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature) {
    return purify::puresign::verify_signature(public_key, message, signature);
}

Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof) {
    Result<NativeBulletproofCircuit> circuit =
        verifier_circuit(tagged_eval_input(kMessageNonceTag, message), public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_message_nonce_proof:verifier_circuit");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Message,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit");
}

Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof) {
    Status cache_status = validate_message_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "verify_message_nonce_proof:validate_message_proof_cache");
    }
    Result<NativeBulletproofCircuit> circuit = cache.circuit_template.instantiate(public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_message_nonce_proof:instantiate");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Message,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit");
}

Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_topic_nonce_proof:empty_topic");
    }
    Result<NativeBulletproofCircuit> circuit =
        verifier_circuit(tagged_eval_input(kTopicNonceTag, topic), public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_topic_nonce_proof:verifier_circuit");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Topic,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit");
}

Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof) {
    Status cache_status = validate_topic_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "verify_topic_nonce_proof:validate_topic_proof_cache");
    }
    Result<NativeBulletproofCircuit> circuit = cache.circuit_template.instantiate(public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_topic_nonce_proof:instantiate");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Topic,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit");
}

Result<bool> verify_message_signature_with_proof(const PublicKey& public_key,
                                                 std::span<const unsigned char> message,
                                                 const ProvenSignature& signature) {
    Result<bool> sig_ok = purify::puresign_plusplus::verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_message_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(public_key, message, signature.nonce_proof);
}

Result<bool> verify_message_signature_with_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                                 const ProvenSignature& signature) {
    Result<bool> sig_ok = purify::puresign_plusplus::verify_signature(public_key, cache.message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_message_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(cache, public_key, signature.nonce_proof);
}

Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature) {
    Result<bool> sig_ok = purify::puresign_plusplus::verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_topic_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(public_key, topic, signature.nonce_proof);
}

Result<bool> verify_topic_signature_with_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               const ProvenSignature& signature) {
    Result<bool> sig_ok = purify::puresign_plusplus::verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_topic_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(cache, public_key, signature.nonce_proof);
}

}  // namespace purify::puresign_plusplus
