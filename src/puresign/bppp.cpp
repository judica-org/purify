// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/bppp.cpp
 * @brief Experimental BPPP-backed PureSign proof(R) helpers.
 */

#include "purify/puresign/bppp.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

#include "detail/common.hpp"
#include "purify_secp_bridge.h"

namespace purify::puresign_plusplus {

namespace api_impl {

Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared);
Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared);

}  // namespace api_impl

namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageBindingTag = "PureSign/Binding/Message";
constexpr std::string_view kTopicBindingTag = "PureSign/Binding/Topic";
constexpr std::string_view kMessageProofTag = "PureSign/BPPP/Proof/Message/V1";
constexpr std::string_view kTopicProofTag = "PureSign/BPPP/Proof/Topic/V1";

using Scope = PreparedNonce::Scope;

const TaggedHash& binding_tagged_hash(Scope scope) {
    static const TaggedHash kMessageBindingTaggedHash(kMessageBindingTag);
    static const TaggedHash kTopicBindingTaggedHash(kTopicBindingTag);
    return scope == Scope::Message ? kMessageBindingTaggedHash : kTopicBindingTaggedHash;
}

const TaggedHash& proof_tagged_hash(Scope scope) {
    static const TaggedHash kMessageProofTaggedHash(kMessageProofTag);
    static const TaggedHash kTopicProofTaggedHash(kTopicProofTag);
    return scope == Scope::Message ? kMessageProofTaggedHash : kTopicProofTaggedHash;
}

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

Status validate_puresign_field_alignment() {
    if (prime_p() != secp256k1_order()) {
        return unexpected_error(ErrorCode::InternalMismatch, "puresign_plusplus:field_order_mismatch");
    }
    return {};
}

const unsigned char* nullable_data(std::span<const unsigned char> input) {
    return input.empty() ? nullptr : input.data();
}

XOnly32 binding_digest(const TaggedHash& tag, std::span<const unsigned char> input) {
    XOnly32 out{};
    out = tag.digest(input);
    return out;
}

std::string_view proof_tag_for_scope(Scope scope) {
    return scope == Scope::Message ? kMessageProofTag : kTopicProofTag;
}

Bytes proof_statement_binding(Scope scope) {
    return bytes_from_ascii(proof_tag_for_scope(scope));
}

Scalar32 derive_proof_nonce_seed(const UInt512& secret, Scope scope, std::span<const unsigned char> eval_input) {
    std::array<unsigned char, 64> secret_bytes = secret.to_bytes_be();
    Scalar32 out{};
    std::array digest_segments{
        std::span<const unsigned char>(secret_bytes.data(), secret_bytes.size()),
        eval_input,
    };
    out = proof_tagged_hash(scope).digest_many(digest_segments);
    return out;
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

Status validate_message_proof_cache(const MessageProofCache& cache) {
    return detail::validate_message_proof_cache(cache, kMessageNonceTag);
}

Status validate_topic_proof_cache(const TopicProofCache& cache) {
    return detail::validate_topic_proof_cache(cache, kTopicNonceTag);
}

struct DerivedNonceData {
    Scope scope = Scope::Message;
    Scalar32 scalar{};
    Nonce nonce{};
    XOnly32 signer_pubkey{};
    XOnly32 binding_digest{};
    Bytes eval_input;
};

Result<DerivedNonceData> derive_nonce_data(const UInt512& secret,
                                           Scope scope,
                                           std::span<const unsigned char> input) {
    Status field_status = validate_puresign_field_alignment();
    if (!field_status.has_value()) {
        return unexpected_error(field_status.error(), "derive_nonce_data:validate_puresign_field_alignment");
    }

    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "derive_nonce_data:derive_bip340_key");
    }

    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    const TaggedHash& binding_hash = binding_tagged_hash(scope);

    DerivedNonceData out{};
    out.scope = scope;
    out.signer_pubkey = signer->xonly_pubkey;
    out.binding_digest = binding_digest(binding_hash, input);
    out.eval_input = detail::tagged_eval_input(nonce_tag, input);

    Result<FieldElement> nonce_value = eval(secret, out.eval_input);
    if (!nonce_value.has_value()) {
        return unexpected_error(nonce_value.error(), "derive_nonce_data:eval");
    }
    out.scalar = nonce_value->to_bytes_be();
    if (std::all_of(out.scalar.begin(), out.scalar.end(), [](unsigned char byte) { return byte == 0; })) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:zero_nonce");
    }

    if (purify_bip340_nonce_from_scalar(out.scalar.data(), out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:bip340_nonce_from_scalar");
    }
    return out;
}

Result<DerivedNonceData> prepare_nonce_data_impl(const UInt512& secret,
                                                 Scope scope,
                                                 std::span<const unsigned char> input) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prepare_nonce_data_impl:empty_topic");
    }

    Result<DerivedNonceData> nonce_data = derive_nonce_data(secret, scope, input);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_nonce_data_impl:derive_nonce_data");
    }
    return nonce_data;
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
                                                   const NativeBulletproofCircuitTemplate& circuit_template,
                                                   bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(detail::copy_bytes(eval_input), secret);
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
        detail::validate_proof_cache_circuit(*circuit, "build_nonce_proof_from_template:circuit_shape");
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
            *circuit, witness->assignment, proof_nonce, public_commitments, statement_binding, circuit_cache);
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
                                     const Nonce& expected_nonce,
                                     bppp::ExperimentalCircuitCache* circuit_cache) {
    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    Result<NativeBulletproofCircuitTemplate> circuit_template =
        verifier_circuit_template(detail::tagged_eval_input(nonce_tag, input));
    if (!circuit_template.has_value()) {
        return unexpected_error(circuit_template.error(), "build_nonce_proof:verifier_circuit_template");
    }
    Bytes eval_input = detail::tagged_eval_input(nonce_tag, input);
    return build_nonce_proof_from_template(secret, scope, expected_nonce, eval_input, *circuit_template,
                                           circuit_cache);
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key,
                                             const NativeBulletproofCircuit& circuit,
                                             const NonceProof& nonce_proof,
                                             Scope scope,
                                             const char* context,
                                             bppp::ExperimentalCircuitCache* circuit_cache) {
    Status key_status = validate_public_key_bundle(public_key);
    if (!key_status.has_value()) {
        return unexpected_error(key_status.error(), context);
    }
    Status circuit_status = detail::validate_proof_cache_circuit(circuit, context);
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
        circuit, nonce_proof.proof, public_commitments, statement_binding, circuit_cache);
}

}  // namespace

Bytes Nonce::serialize() const {
    return Bytes(xonly.begin(), xonly.end());
}

Result<Nonce> Nonce::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Nonce::deserialize:size");
    }
    Nonce out{};
    std::copy(serialized.begin(), serialized.end(), out.xonly.begin());
    if (purify_bip340_validate_xonly_pubkey(out.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "Nonce::deserialize:bip340_validate_xonly_pubkey");
    }
    return out;
}

Nonce Signature::nonce() const {
    Nonce out{};
    std::copy(bytes.begin(), bytes.begin() + 32, out.xonly.begin());
    return out;
}

Scalar32 Signature::s() const {
    Scalar32 out{};
    std::copy(bytes.begin() + 32, bytes.end(), out.begin());
    return out;
}

Bytes Signature::serialize() const {
    return Bytes(bytes.begin(), bytes.end());
}

Result<Signature> Signature::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "Signature::deserialize:size");
    }
    Signature out{};
    std::copy(serialized.begin(), serialized.end(), out.bytes.begin());
    if (purify_bip340_validate_signature(out.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "Signature::deserialize:bip340_validate_signature");
    }
    return out;
}

Result<MessageProofCache> MessageProofCache::build(std::span<const unsigned char> message) {
    Bytes eval_input = detail::tagged_eval_input(kMessageNonceTag, message);
    Result<NativeBulletproofCircuitTemplate> circuit_template = verifier_circuit_template(eval_input);
    if (!circuit_template.has_value()) {
        return unexpected_error(circuit_template.error(), "MessageProofCache::build:verifier_circuit_template");
    }
    MessageProofCache cache{};
    cache.message = detail::copy_bytes(message);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(*circuit_template);
    return cache;
}

Result<TopicProofCache> TopicProofCache::build(std::span<const unsigned char> topic) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "TopicProofCache::build:empty_topic");
    }
    Bytes eval_input = detail::tagged_eval_input(kTopicNonceTag, topic);
    Result<NativeBulletproofCircuitTemplate> circuit_template = verifier_circuit_template(eval_input);
    if (!circuit_template.has_value()) {
        return unexpected_error(circuit_template.error(), "TopicProofCache::build:verifier_circuit_template");
    }
    TopicProofCache cache{};
    cache.topic = detail::copy_bytes(topic);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(*circuit_template);
    return cache;
}

PreparedNonce::PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                             const XOnly32& signer_pubkey, const XOnly32& binding_digest)
    : scope_(scope), scalar_(scalar), nonce_(nonce), signer_pubkey_(signer_pubkey), binding_digest_(binding_digest) {}

PreparedNonce PreparedNonce::from_parts(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                                        const XOnly32& signer_pubkey, const XOnly32& binding_digest) {
    return PreparedNonce(scope, scalar, nonce, signer_pubkey, binding_digest);
}

PreparedNonce::PreparedNonce(PreparedNonce&& other) noexcept
    : scope_(other.scope_), scalar_(other.scalar_), nonce_(other.nonce_),
      signer_pubkey_(other.signer_pubkey_), binding_digest_(other.binding_digest_) {
    other.clear();
}

PreparedNonce& PreparedNonce::operator=(PreparedNonce&& other) noexcept {
    if (this != &other) {
        clear();
        scope_ = other.scope_;
        scalar_ = other.scalar_;
        nonce_ = other.nonce_;
        signer_pubkey_ = other.signer_pubkey_;
        binding_digest_ = other.binding_digest_;
        other.clear();
    }
    return *this;
}

PreparedNonce::~PreparedNonce() {
    clear();
}

void PreparedNonce::clear() noexcept {
    std::fill(scalar_.begin(), scalar_.end(), 0);
}

Result<Signature> PreparedNonce::sign_message(const Bip340Key& signer,
                                              std::span<const unsigned char> message) && {
    if (scope_ != Scope::Message) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:scope");
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:signer_pubkey");
    }
    if (binding_digest_ != binding_digest(binding_tagged_hash(Scope::Message), message)) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:message_binding");
    }

    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "PreparedNonce::sign_message:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_message:nonce_mismatch");
    }
    if (purify_bip340_verify(out.bytes.data(), nullable_data(message), message.size(), signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_message:self_verify");
    }
    return out;
}

Result<Signature> PreparedNonce::sign_topic_message(const Bip340Key& signer,
                                                    std::span<const unsigned char> message) && {
    if (scope_ != Scope::Topic) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_topic_message:scope");
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_topic_message:signer_pubkey");
    }

    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "PreparedNonce::sign_topic_message:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_topic_message:nonce_mismatch");
    }
    if (purify_bip340_verify(out.bytes.data(), nullable_data(message), message.size(), signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_topic_message:self_verify");
    }
    return out;
}

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
    detail::append_u32_le(out, static_cast<std::uint32_t>(proof.proof.size()));
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
    std::optional<std::uint32_t> proof_size = detail::read_u32_le(serialized, 1);
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
    detail::append_u32_le(out, static_cast<std::uint32_t>(nonce_proof_bytes->size()));
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
    std::optional<std::uint32_t> nonce_proof_size = detail::read_u32_le(serialized, 1);
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

PreparedNonceWithProof PreparedNonceWithProof::from_parts(PreparedNonce prepared, NonceProof proof) {
    return PreparedNonceWithProof(std::move(prepared), std::move(proof));
}

Result<ProvenSignature> PreparedNonceWithProof::sign_message(const UInt512& secret,
                                                             std::span<const unsigned char> message) && {
    Result<KeyPair> key_pair = KeyPair::from_secret(secret);
    if (!key_pair.has_value()) {
        return unexpected_error(key_pair.error(), "PreparedNonceWithProof::sign_message:from_secret");
    }
    NonceProof nonce_proof = std::move(proof_);
    Result<Signature> signature = key_pair->sign_message_with_prepared(message, std::move(prepared_));
    if (!signature.has_value()) {
        return unexpected_error(signature.error(), "PreparedNonceWithProof::sign_message:sign_message_with_prepared");
    }
    if (signature->nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonceWithProof::sign_message:nonce_mismatch");
    }
    return ProvenSignature{*signature, std::move(nonce_proof)};
}

Result<ProvenSignature> PreparedNonceWithProof::sign_topic_message(const UInt512& secret,
                                                                   std::span<const unsigned char> message) && {
    Result<KeyPair> key_pair = KeyPair::from_secret(secret);
    if (!key_pair.has_value()) {
        return unexpected_error(key_pair.error(), "PreparedNonceWithProof::sign_topic_message:from_secret");
    }
    NonceProof nonce_proof = std::move(proof_);
    Result<Signature> signature = key_pair->sign_with_prepared_topic(message, std::move(prepared_));
    if (!signature.has_value()) {
        return unexpected_error(signature.error(),
                                "PreparedNonceWithProof::sign_topic_message:sign_with_prepared_topic");
    }
    if (signature->nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonceWithProof::sign_topic_message:nonce_mismatch");
    }
    return ProvenSignature{*signature, std::move(nonce_proof)};
}

namespace api_impl {

Result<PublicKey> derive_public_key(const UInt512& secret) {
    Result<GeneratedKey> purify_key = derive_key(secret);
    if (!purify_key.has_value()) {
        return unexpected_error(purify_key.error(), "derive_public_key:derive_key");
    }
    Result<Bip340Key> bip340_key = derive_bip340_key(secret);
    if (!bip340_key.has_value()) {
        return unexpected_error(bip340_key.error(), "derive_public_key:derive_bip340_key");
    }
    return PublicKey{purify_key->public_key, bip340_key->xonly_pubkey};
}

Result<MessageProofCache> build_message_proof_cache(std::span<const unsigned char> message) {
    return MessageProofCache::build(message);
}

Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic) {
    return TopicProofCache::build(topic);
}

Result<PreparedNonce> prepare_message_nonce(const UInt512& secret, std::span<const unsigned char> message) {
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Message, message);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_message_nonce:prepare_nonce_data_impl");
    }
    return PreparedNonce::from_parts(Scope::Message, nonce_data->scalar, nonce_data->nonce,
                                     nonce_data->signer_pubkey, nonce_data->binding_digest);
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                std::span<const unsigned char> message,
                                                                bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Message, message);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    }
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data->scalar,
                                                       nonce_data->nonce, nonce_data->signer_pubkey,
                                                       nonce_data->binding_digest);
    Result<NonceProof> proof = build_nonce_proof(secret, Scope::Message, message, prepared.public_nonce(),
                                                 circuit_cache);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_message_nonce_with_proof:build_nonce_proof");
    }
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(*proof));
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const UInt512& secret,
                                                                const MessageProofCache& cache,
                                                                bppp::ExperimentalCircuitCache* circuit_cache) {
    Status cache_status = validate_message_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "prepare_message_nonce_with_proof:validate_message_proof_cache");
    }
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Message, cache.message);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    }
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data->scalar,
                                                       nonce_data->nonce, nonce_data->signer_pubkey,
                                                       nonce_data->binding_digest);
    Result<NonceProof> proof =
        build_nonce_proof_from_template(secret, Scope::Message, prepared.public_nonce(),
                                        cache.eval_input, cache.circuit_template,
                                        circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_message_nonce_with_proof:build_nonce_proof_from_template");
    }
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(*proof));
}

Result<PreparedNonce> prepare_topic_nonce(const UInt512& secret, std::span<const unsigned char> topic) {
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Topic, topic);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_topic_nonce:prepare_nonce_data_impl");
    }
    return PreparedNonce::from_parts(Scope::Topic, nonce_data->scalar, nonce_data->nonce,
                                     nonce_data->signer_pubkey, nonce_data->binding_digest);
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              std::span<const unsigned char> topic,
                                                              bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Topic, topic);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    }
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data->scalar,
                                                       nonce_data->nonce, nonce_data->signer_pubkey,
                                                       nonce_data->binding_digest);
    Result<NonceProof> proof = build_nonce_proof(secret, Scope::Topic, topic, prepared.public_nonce(),
                                                 circuit_cache);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_topic_nonce_with_proof:build_nonce_proof");
    }
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(*proof));
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const UInt512& secret,
                                                              const TopicProofCache& cache,
                                                              bppp::ExperimentalCircuitCache* circuit_cache) {
    Status cache_status = validate_topic_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "prepare_topic_nonce_with_proof:validate_topic_proof_cache");
    }
    Result<DerivedNonceData> nonce_data = prepare_nonce_data_impl(secret, Scope::Topic, cache.topic);
    if (!nonce_data.has_value()) {
        return unexpected_error(nonce_data.error(), "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    }
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data->scalar,
                                                       nonce_data->nonce, nonce_data->signer_pubkey,
                                                       nonce_data->binding_digest);
    Result<NonceProof> proof =
        build_nonce_proof_from_template(secret, Scope::Topic, prepared.public_nonce(),
                                        cache.eval_input, cache.circuit_template,
                                        circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
    if (!proof.has_value()) {
        return unexpected_error(proof.error(), "prepare_topic_nonce_with_proof:build_nonce_proof_from_template");
    }
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(*proof));
}

Result<Signature> sign_message(const UInt512& secret, std::span<const unsigned char> message) {
    Result<PreparedNonce> prepared = prepare_message_nonce(secret, message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message:prepare_message_nonce");
    }
    return sign_message_with_prepared(secret, message, std::move(*prepared));
}

Result<Signature> sign_message_with_prepared(const UInt512& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared) {
    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "sign_message_with_prepared:derive_bip340_key");
    }
    return std::move(prepared).sign_message(*signer, message);
}

Result<ProvenSignature> sign_message_with_prepared_proof(const UInt512& secret,
                                                         std::span<const unsigned char> message,
                                                         PreparedNonceWithProof&& prepared) {
    return std::move(prepared).sign_message(secret, message);
}

Result<Signature> sign_with_topic(const UInt512& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic) {
    Result<PreparedNonce> prepared = prepare_topic_nonce(secret, topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic:prepare_topic_nonce");
    }
    return sign_with_prepared_topic(secret, message, std::move(*prepared));
}

Result<Signature> sign_with_prepared_topic(const UInt512& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared) {
    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "sign_with_prepared_topic:derive_bip340_key");
    }
    return std::move(prepared).sign_topic_message(*signer, message);
}

Result<ProvenSignature> sign_with_prepared_topic_proof(const UInt512& secret,
                                                       std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared) {
    return std::move(prepared).sign_topic_message(secret, message);
}

Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, std::span<const unsigned char> message,
                                                bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<PreparedNonceWithProof> prepared = prepare_message_nonce_with_proof(secret, message, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(secret, message, std::move(*prepared));
}

Result<ProvenSignature> sign_message_with_proof(const UInt512& secret, const MessageProofCache& cache,
                                                bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<PreparedNonceWithProof> prepared =
        prepare_message_nonce_with_proof(secret, cache, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(secret, cache.message, std::move(*prepared));
}

Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic,
                                              bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<PreparedNonceWithProof> prepared = prepare_topic_nonce_with_proof(secret, topic, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(secret, message, std::move(*prepared));
}

Result<ProvenSignature> sign_with_topic_proof(const UInt512& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache,
                                              bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<PreparedNonceWithProof> prepared =
        prepare_topic_nonce_with_proof(secret, cache, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(secret, message, std::move(*prepared));
}

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature) {
    Status pubkey_status = validate_public_key(public_key.purify_pubkey);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "verify_signature:validate_public_key");
    }
    if (purify_bip340_validate_xonly_pubkey(public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_xonly_pubkey");
    }
    if (purify_bip340_validate_signature(signature.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_signature");
    }
    return purify_bip340_verify(signature.bytes.data(), nullable_data(message), message.size(),
                                public_key.bip340_pubkey.data()) != 0;
}

Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof,
                                        bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<NativeBulletproofCircuit> circuit =
        verifier_circuit(detail::tagged_eval_input(kMessageNonceTag, message), public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_message_nonce_proof:verifier_circuit");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Message,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof,
                                        bppp::ExperimentalCircuitCache* circuit_cache) {
    Status cache_status = validate_message_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "verify_message_nonce_proof:validate_message_proof_cache");
    }
    Result<NativeBulletproofCircuit> circuit = cache.circuit_template.instantiate(public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_message_nonce_proof:instantiate");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Message,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof,
                                      bppp::ExperimentalCircuitCache* circuit_cache) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_topic_nonce_proof:empty_topic");
    }
    Result<NativeBulletproofCircuit> circuit =
        verifier_circuit(detail::tagged_eval_input(kTopicNonceTag, topic), public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_topic_nonce_proof:verifier_circuit");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Topic,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof,
                                      bppp::ExperimentalCircuitCache* circuit_cache) {
    Status cache_status = validate_topic_proof_cache(cache);
    if (!cache_status.has_value()) {
        return unexpected_error(cache_status.error(), "verify_topic_nonce_proof:validate_topic_proof_cache");
    }
    Result<NativeBulletproofCircuit> circuit = cache.circuit_template.instantiate(public_key.purify_pubkey);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "verify_topic_nonce_proof:instantiate");
    }
    return verify_nonce_proof_with_circuit(public_key, *circuit, nonce_proof, Scope::Topic,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_message_signature_with_proof(const PublicKey& public_key,
                                                 std::span<const unsigned char> message,
                                                 const ProvenSignature& signature,
                                                 bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<bool> sig_ok = verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_message_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(public_key, message, signature.nonce_proof, circuit_cache);
}

Result<bool> verify_message_signature_with_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                                 const ProvenSignature& signature,
                                                 bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<bool> sig_ok = verify_signature(public_key, cache.message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_message_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(cache, public_key, signature.nonce_proof, circuit_cache);
}

Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature,
                                               bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<bool> sig_ok = verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_topic_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(public_key, topic, signature.nonce_proof, circuit_cache);
}

Result<bool> verify_topic_signature_with_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               const ProvenSignature& signature,
                                               bppp::ExperimentalCircuitCache* circuit_cache) {
    Result<bool> sig_ok = verify_signature(public_key, message, signature.signature);
    if (!sig_ok.has_value()) {
        return unexpected_error(sig_ok.error(), "verify_topic_signature_with_proof:verify_signature");
    }
    if (!*sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(cache, public_key, signature.nonce_proof, circuit_cache);
}

}  // namespace api_impl

Bytes PublicKey::serialize() const {
    Bytes out;
    out.reserve(kSerializedSize);
    std::array<unsigned char, 64> packed = purify_pubkey.to_bytes_be();
    out.insert(out.end(), packed.begin(), packed.end());
    out.insert(out.end(), bip340_pubkey.begin(), bip340_pubkey.end());
    return out;
}

Result<PublicKey> PublicKey::deserialize(std::span<const unsigned char> serialized) {
    if (serialized.size() != kSerializedSize) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "PublicKey::deserialize:size");
    }
    UInt512 purify_pubkey = UInt512::from_bytes_be(serialized.data(), 64);
    Status pubkey_status = validate_public_key(purify_pubkey);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "PublicKey::deserialize:validate_public_key");
    }

    PublicKey out{};
    out.purify_pubkey = purify_pubkey;
    std::copy(serialized.begin() + 64, serialized.end(), out.bip340_pubkey.begin());
    if (purify_bip340_validate_xonly_pubkey(out.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "PublicKey::deserialize:bip340_validate_xonly_pubkey");
    }
    return out;
}

Result<PublicKey> PublicKey::from_secret(const UInt512& secret) {
    return api_impl::derive_public_key(secret);
}

Result<bool> PublicKey::verify_signature(std::span<const unsigned char> message, const Signature& signature) const {
    return api_impl::verify_signature(*this, message, signature);
}

Result<bool> PublicKey::verify_message_nonce_proof(std::span<const unsigned char> message,
                                                   const NonceProof& nonce_proof,
                                                   bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(*this, message, nonce_proof, circuit_cache);
}

Result<bool> PublicKey::verify_message_nonce_proof(const MessageProofCache& cache, const NonceProof& nonce_proof,
                                                   bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(cache, *this, nonce_proof, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(std::span<const unsigned char> topic,
                                                 const NonceProof& nonce_proof,
                                                 bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(*this, topic, nonce_proof, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(const TopicProofCache& cache, const NonceProof& nonce_proof,
                                                 bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(cache, *this, nonce_proof, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(std::span<const unsigned char> message,
                                                            const ProvenSignature& signature,
                                                            bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(*this, message, signature, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(const MessageProofCache& cache,
                                                            const ProvenSignature& signature,
                                                            bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(cache, *this, signature, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(std::span<const unsigned char> message,
                                                          std::span<const unsigned char> topic,
                                                          const ProvenSignature& signature,
                                                          bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(*this, message, topic, signature, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(const TopicProofCache& cache,
                                                          std::span<const unsigned char> message,
                                                          const ProvenSignature& signature,
                                                          bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(cache, *this, message, signature, circuit_cache);
}

Result<KeyPair> KeyPair::from_secret(const UInt512& secret) {
    Result<Bip340Key> signer = derive_bip340_key(secret);
    if (!signer.has_value()) {
        return unexpected_error(signer.error(), "KeyPair::from_secret:derive_bip340_key");
    }
    Result<PublicKey> public_key = PublicKey::from_secret(secret);
    if (!public_key.has_value()) {
        return unexpected_error(public_key.error(), "KeyPair::from_secret:from_secret");
    }
    return KeyPair(secret, std::move(*signer), std::move(*public_key));
}

Result<PreparedNonce> KeyPair::prepare_message_nonce(std::span<const unsigned char> message) const {
    return api_impl::prepare_message_nonce(secret_, message);
}

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(
    std::span<const unsigned char> message,
    bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, message, circuit_cache);
}

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(
    const MessageProofCache& cache,
    bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, cache, circuit_cache);
}

Result<PreparedNonce> KeyPair::prepare_topic_nonce(std::span<const unsigned char> topic) const {
    return api_impl::prepare_topic_nonce(secret_, topic);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(
    std::span<const unsigned char> topic,
    bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, topic, circuit_cache);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(
    const TopicProofCache& cache,
    bppp::ExperimentalCircuitCache* circuit_cache) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, cache, circuit_cache);
}

Result<Signature> KeyPair::sign_message(std::span<const unsigned char> message) const {
    Result<PreparedNonce> prepared = prepare_message_nonce(message);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_message:prepare_message_nonce");
    }
    return sign_message_with_prepared(message, std::move(*prepared));
}

Result<Signature> KeyPair::sign_message_with_prepared(std::span<const unsigned char> message,
                                                      PreparedNonce&& prepared) const {
    return std::move(prepared).sign_message(signer_, message);
}

Result<ProvenSignature> KeyPair::sign_message_with_prepared_proof(std::span<const unsigned char> message,
                                                                  PreparedNonceWithProof&& prepared) const {
    return std::move(prepared).sign_message(secret_, message);
}

Result<Signature> KeyPair::sign_with_topic(std::span<const unsigned char> message,
                                           std::span<const unsigned char> topic) const {
    Result<PreparedNonce> prepared = prepare_topic_nonce(topic);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_with_topic:prepare_topic_nonce");
    }
    return sign_with_prepared_topic(message, std::move(*prepared));
}

Result<Signature> KeyPair::sign_with_prepared_topic(std::span<const unsigned char> message,
                                                    PreparedNonce&& prepared) const {
    return std::move(prepared).sign_topic_message(signer_, message);
}

Result<ProvenSignature> KeyPair::sign_with_prepared_topic_proof(std::span<const unsigned char> message,
                                                                PreparedNonceWithProof&& prepared) const {
    return std::move(prepared).sign_topic_message(secret_, message);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(std::span<const unsigned char> message,
                                                         bppp::ExperimentalCircuitCache* circuit_cache) const {
    Result<PreparedNonceWithProof> prepared = prepare_message_nonce_with_proof(message, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(message, std::move(*prepared));
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(const MessageProofCache& cache,
                                                         bppp::ExperimentalCircuitCache* circuit_cache) const {
    Result<PreparedNonceWithProof> prepared = prepare_message_nonce_with_proof(cache, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    }
    return sign_message_with_prepared_proof(cache.message, std::move(*prepared));
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       std::span<const unsigned char> topic,
                                                       bppp::ExperimentalCircuitCache* circuit_cache) const {
    Result<PreparedNonceWithProof> prepared = prepare_topic_nonce_with_proof(topic, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(message, std::move(*prepared));
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       const TopicProofCache& cache,
                                                       bppp::ExperimentalCircuitCache* circuit_cache) const {
    Result<PreparedNonceWithProof> prepared = prepare_topic_nonce_with_proof(cache, circuit_cache);
    if (!prepared.has_value()) {
        return unexpected_error(prepared.error(), "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    }
    return sign_with_prepared_topic_proof(message, std::move(*prepared));
}

}  // namespace purify::puresign_plusplus
