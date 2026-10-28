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
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>

#include "detail/common.hpp"
#include "purify/secp_bridge.h"

namespace purify::puresign_plusplus {

namespace api_impl {

Result<Signature> sign_message_with_prepared(const SecretKey& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared, purify_secp_context* secp_context);
Result<Signature> sign_with_prepared_topic(const SecretKey& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared, purify_secp_context* secp_context);

}  // namespace api_impl

namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageBindingTag = "PureSign/Binding/Message";
constexpr std::string_view kTopicBindingTag = "PureSign/Binding/Topic";
constexpr std::string_view kMessageProofTag = "PureSign/BPPP/Proof/Message/V1";
constexpr std::string_view kTopicProofTag = "PureSign/BPPP/Proof/Topic/V1";

using Scope = PreparedNonce::Scope;

bool puresign_bppp_trace_enabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("PURIFY_BPPP_TRACE");
        return value != nullptr && value[0] != '\0' && value[0] != '0';
    }();
    return enabled;
}

void puresign_bppp_trace(const char* fmt, ...) {
    if (!puresign_bppp_trace_enabled()) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    std::fputs("[purify:puresign-bppp] ", stderr);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    std::fflush(stderr);
    va_end(args);
}

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

Scalar32 derive_proof_nonce_seed(const SecretKey& secret, Scope scope, std::span<const unsigned char> eval_input) {
    std::array<unsigned char, 64> secret_bytes = secret.packed().to_bytes_be();
    Scalar32 out{};
    std::array digest_segments{
        std::span<const unsigned char>(secret_bytes.data(), secret_bytes.size()),
        eval_input,
    };
    out = proof_tagged_hash(scope).digest_many(digest_segments);
    detail::secure_clear_bytes(secret_bytes.data(), secret_bytes.size());
    return out;
}

Status validate_public_key_bundle(const PublicKey& public_key, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(public_key.purify_pubkey),
                           "puresign_plusplus:validate_public_key_bundle:purify_pubkey");
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "puresign_plusplus:validate_public_key_bundle:secp_context"),
                           "puresign_plusplus:validate_public_key_bundle:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, public_key.bip340_pubkey.data()) == 0) {
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

Result<DerivedNonceData> derive_nonce_data(const SecretKey& secret,
                                           Scope scope,
                                           std::span<const unsigned char> input,
                                           purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_puresign_field_alignment(), "derive_nonce_data:validate_puresign_field_alignment");
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context), "derive_nonce_data:derive_bip340_key");

    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    const TaggedHash& binding_hash = binding_tagged_hash(scope);

    DerivedNonceData out{};
    out.scope = scope;
    out.signer_pubkey = signer.xonly_pubkey;
    out.binding_digest = binding_digest(binding_hash, input);
    out.eval_input = detail::tagged_eval_input(nonce_tag, input);

    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_value, eval(secret, out.eval_input), "derive_nonce_data:eval");
    out.scalar = nonce_value.to_bytes_be();
    if (std::all_of(out.scalar.begin(), out.scalar.end(), [](unsigned char byte) { return byte == 0; })) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:zero_nonce");
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "derive_nonce_data:secp_context"),
                           "derive_nonce_data:secp_context");
    if (purify_bip340_nonce_from_scalar(secp_context, out.scalar.data(), out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:bip340_nonce_from_scalar");
    }
    return out;
}

Result<DerivedNonceData> prepare_nonce_data_impl(const SecretKey& secret,
                                                 Scope scope,
                                                 std::span<const unsigned char> input,
                                                 purify_secp_context* secp_context) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prepare_nonce_data_impl:empty_topic");
    }
    PURIFY_ASSIGN_OR_RETURN(auto nonce_data, derive_nonce_data(secret, scope, input, secp_context),
                            "prepare_nonce_data_impl:derive_nonce_data");
    return nonce_data;
}

Result<bppp::PointBytes> commitment_point_from_scalar(const FieldElement& scalar,
                                                      purify_secp_context* secp_context) {
    Scalar32 blind{};
    return bppp::pedersen_commit_char(blind, bppp::scalar_bytes(scalar), secp_context,
                                      bppp::base_generator(secp_context), bppp::base_generator(secp_context));
}

Result<bool> nonce_proof_matches_nonce(const NonceProof& nonce_proof,
                                       purify_secp_context* secp_context) {
    XOnly32 xonly{};
    int parity = 0;
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_proof_matches_nonce:secp_context"),
                           "nonce_proof_matches_nonce:secp_context");
    if (purify_bip340_xonly_from_point(secp_context, nonce_proof.commitment_point.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "nonce_proof_matches_nonce:invalid_commitment_point");
    }
    (void)parity;
    return xonly == nonce_proof.nonce.xonly;
}

Result<NonceProof> build_nonce_proof_from_template(const SecretKey& secret,
                                                   Scope scope,
                                                   const Nonce& expected_nonce,
                                                   std::span<const unsigned char> eval_input,
                                                   const NativeBulletproofCircuitTemplate& circuit_template,
                                                   purify_secp_context* secp_context,
                                                   bppp::ExperimentalCircuitBackend* circuit_cache) {
    puresign_bppp_trace("build_nonce_proof scope=%s eval_input=%zu cache=%p",
                        scope == Scope::Message ? "message" : "topic", eval_input.size(),
                        static_cast<void*>(circuit_cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(detail::copy_bytes(eval_input), secret),
                            "build_nonce_proof_from_template:prove_assignment_data");
    PURIFY_ASSIGN_OR_RETURN(auto partial_ok, circuit_template.partial_evaluate(witness.assignment),
                            "build_nonce_proof_from_template:partial_evaluate");
    if (!partial_ok) {
        return unexpected_error(ErrorCode::BindingMismatch, "build_nonce_proof_from_template:partial_evaluate_false");
    }
    PURIFY_ASSIGN_OR_RETURN(auto final_ok, circuit_template.final_evaluate(witness.assignment, witness.public_key),
                            "build_nonce_proof_from_template:final_evaluate");
    if (!final_ok) {
        return unexpected_error(ErrorCode::BindingMismatch, "build_nonce_proof_from_template:final_evaluate_false");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, circuit_template.instantiate(witness.public_key),
                            "build_nonce_proof_from_template:instantiate");
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit, "build_nonce_proof_from_template:circuit_shape"),
                           "build_nonce_proof_from_template:validate_proof_cache_circuit");

    PURIFY_ASSIGN_OR_RETURN(auto commitment_point, commitment_point_from_scalar(witness.assignment.commitments.front(), secp_context),
                            "build_nonce_proof_from_template:commitment_point_from_scalar");
    Scalar32 proof_nonce = derive_proof_nonce_seed(secret, scope, eval_input);
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{commitment_point};
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
            circuit, witness.assignment, proof_nonce, public_commitments, secp_context, statement_binding, circuit_cache),
        "build_nonce_proof_from_template:prove_experimental_circuit_zk_norm_arg_with_public_commitments");
    puresign_bppp_trace("build_nonce_proof built proof_len=%zu commitment0=%02x", proof.proof.size(),
                        static_cast<unsigned int>(commitment_point.front()));

    NonceProof out{};
    out.nonce = expected_nonce;
    out.commitment_point = commitment_point;
    out.proof = std::move(proof);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(out, secp_context),
                            "build_nonce_proof_from_template:nonce_proof_matches_nonce");
    if (!match) {
        return unexpected_error(ErrorCode::InternalMismatch, "build_nonce_proof_from_template:nonce_mismatch");
    }
    return out;
}

Result<NonceProof> build_nonce_proof(const SecretKey& secret,
                                     Scope scope,
                                     std::span<const unsigned char> input,
                                     const Nonce& expected_nonce,
                                     purify_secp_context* secp_context,
                                     bppp::ExperimentalCircuitBackend* circuit_cache) {
    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit_template, verifier_circuit_template(detail::tagged_eval_input(nonce_tag, input)),
                            "build_nonce_proof:verifier_circuit_template");
    Bytes eval_input = detail::tagged_eval_input(nonce_tag, input);
    return build_nonce_proof_from_template(secret, scope, expected_nonce, eval_input, circuit_template, secp_context,
                                           circuit_cache);
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key,
                                             const NativeBulletproofCircuit& circuit,
                                             const NonceProof& nonce_proof,
                                             Scope scope,
                                             purify_secp_context* secp_context,
                                             const char* context,
                                             bppp::ExperimentalCircuitBackend* circuit_cache) {
    puresign_bppp_trace("verify_nonce_proof context=%s scope=%s proof_len=%zu cache=%p",
                        context, scope == Scope::Message ? "message" : "topic", nonce_proof.proof.proof.size(),
                        static_cast<void*>(circuit_cache));
    PURIFY_RETURN_IF_ERROR(validate_public_key_bundle(public_key, secp_context), context);
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit, context), context);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(nonce_proof, secp_context), context);
    if (!match) {
        return false;
    }
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{nonce_proof.commitment_point};
    auto verified = bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, nonce_proof.proof, public_commitments, secp_context, statement_binding, circuit_cache);
    puresign_bppp_trace("verify_nonce_proof result_has_value=%d result=%d", verified.has_value() ? 1 : 0,
                        verified.has_value() && *verified ? 1 : 0);
    return verified;
}

}  // namespace

Result<MessageProofCache> MessageProofCache::build(std::span<const unsigned char> message) {
    Bytes eval_input = detail::tagged_eval_input(kMessageNonceTag, message);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input),
                            "MessageProofCache::build:verifier_circuit_template");
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest(),
                            "MessageProofCache::build:integrity_digest");
    MessageProofCache cache{};
    cache.message = detail::copy_bytes(message);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
    return cache;
}

Result<TopicProofCache> TopicProofCache::build(std::span<const unsigned char> topic) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "TopicProofCache::build:empty_topic");
    }
    Bytes eval_input = detail::tagged_eval_input(kTopicNonceTag, topic);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input),
                            "TopicProofCache::build:verifier_circuit_template");
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest(),
                            "TopicProofCache::build:integrity_digest");
    TopicProofCache cache{};
    cache.topic = detail::copy_bytes(topic);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
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
    std::fill(scalar_.begin(), scalar_.end(), static_cast<unsigned char>(0));
}

Result<Signature> PreparedNonce::sign_message(const Bip340Key& signer,
                                              std::span<const unsigned char> message,
                                              purify_secp_context* secp_context) && {
    if (scope_ != Scope::Message) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:scope");
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:signer_pubkey");
    }
    if (binding_digest_ != binding_digest(binding_tagged_hash(Scope::Message), message)) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_message:message_binding");
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "PreparedNonce::sign_message:secp_context"),
                           "PreparedNonce::sign_message:secp_context");
    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "PreparedNonce::sign_message:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_message:nonce_mismatch");
    }
    if (purify_bip340_verify(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                             signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_message:self_verify");
    }
    return out;
}

Result<Signature> PreparedNonce::sign_topic_message(const Bip340Key& signer,
                                                    std::span<const unsigned char> message,
                                                    purify_secp_context* secp_context) && {
    if (scope_ != Scope::Topic) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_topic_message:scope");
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch, "PreparedNonce::sign_topic_message:signer_pubkey");
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "PreparedNonce::sign_topic_message:secp_context"),
                           "PreparedNonce::sign_topic_message:secp_context");
    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "PreparedNonce::sign_topic_message:sign_with_fixed_nonce");
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_topic_message:nonce_mismatch");
    }
    if (purify_bip340_verify(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                             signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonce::sign_topic_message:self_verify");
    }
    return out;
}

PreparedNonceWithProof PreparedNonceWithProof::from_parts(PreparedNonce prepared, NonceProof proof) {
    return PreparedNonceWithProof(std::move(prepared), std::move(proof));
}

Result<ProvenSignature> PreparedNonceWithProof::sign_message(const SecretKey& secret,
                                                             std::span<const unsigned char> message,
                                                             purify_secp_context* secp_context) && {
    NonceProof nonce_proof = std::move(proof_);
    PURIFY_ASSIGN_OR_RETURN(auto signature,
                            api_impl::sign_message_with_prepared(secret, message, std::move(prepared_), secp_context),
                            "PreparedNonceWithProof::sign_message:sign_message_with_prepared");
    if (signature.nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonceWithProof::sign_message:nonce_mismatch");
    }
    return ProvenSignature{signature, std::move(nonce_proof)};
}

Result<ProvenSignature> PreparedNonceWithProof::sign_topic_message(const SecretKey& secret,
                                                                   std::span<const unsigned char> message,
                                                                   purify_secp_context* secp_context) && {
    NonceProof nonce_proof = std::move(proof_);
    PURIFY_ASSIGN_OR_RETURN(auto signature,
                            api_impl::sign_with_prepared_topic(secret, message, std::move(prepared_), secp_context),
                            "PreparedNonceWithProof::sign_topic_message:sign_with_prepared_topic");
    if (signature.nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch, "PreparedNonceWithProof::sign_topic_message:nonce_mismatch");
    }
    return ProvenSignature{signature, std::move(nonce_proof)};
}

namespace api_impl {

Result<PublicKey> derive_public_key(const SecretKey& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& purify_key, derive_key(secret), "derive_public_key:derive_key");
    PURIFY_ASSIGN_OR_RETURN(const auto& bip340_key, derive_bip340_key(secret, secp_context), "derive_public_key:derive_bip340_key");
    return PublicKey{purify_key.public_key, bip340_key.xonly_pubkey};
}

Result<MessageProofCache> build_message_proof_cache(std::span<const unsigned char> message) {
    return MessageProofCache::build(message);
}

Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic) {
    return TopicProofCache::build(topic);
}

Result<PreparedNonce> prepare_message_nonce(const SecretKey& secret, std::span<const unsigned char> message,
                                            purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, message, secp_context),
                            "prepare_message_nonce:prepare_nonce_data_impl");
    return PreparedNonce::from_parts(Scope::Message, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                std::span<const unsigned char> message,
                                                                purify_secp_context* secp_context,
                                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, message, secp_context),
                            "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, Scope::Message, message, prepared.public_nonce(), secp_context,
                                                          circuit_cache),
                            "prepare_message_nonce_with_proof:build_nonce_proof");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                const MessageProofCache& cache,
                                                                purify_secp_context* secp_context,
                                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache),
                           "prepare_message_nonce_with_proof:validate_message_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, cache.message, secp_context),
                            "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        build_nonce_proof_from_template(secret, Scope::Message, prepared.public_nonce(),
                                        cache.eval_input, cache.circuit_template, secp_context,
                                        circuit_cache != nullptr ? circuit_cache : &cache.backend_cache),
        "prepare_message_nonce_with_proof:build_nonce_proof_from_template");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonce> prepare_topic_nonce(const SecretKey& secret, std::span<const unsigned char> topic,
                                          purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, topic, secp_context),
                            "prepare_topic_nonce:prepare_nonce_data_impl");
    return PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              std::span<const unsigned char> topic,
                                                              purify_secp_context* secp_context,
                                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, topic, secp_context),
                            "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, Scope::Topic, topic, prepared.public_nonce(), secp_context,
                                                          circuit_cache),
                            "prepare_topic_nonce_with_proof:build_nonce_proof");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              const TopicProofCache& cache,
                                                              purify_secp_context* secp_context,
                                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache),
                           "prepare_topic_nonce_with_proof:validate_topic_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, cache.topic, secp_context),
                            "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        build_nonce_proof_from_template(secret, Scope::Topic, prepared.public_nonce(),
                                        cache.eval_input, cache.circuit_template, secp_context,
                                        circuit_cache != nullptr ? circuit_cache : &cache.backend_cache),
        "prepare_topic_nonce_with_proof:build_nonce_proof_from_template");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<Signature> sign_message(const SecretKey& secret, std::span<const unsigned char> message,
                               purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce(secret, message, secp_context), "sign_message:prepare_message_nonce");
    return sign_message_with_prepared(secret, message, std::move(prepared), secp_context);
}

Result<Signature> sign_message_with_prepared(const SecretKey& secret, std::span<const unsigned char> message,
                                             PreparedNonce&& prepared, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context), "sign_message_with_prepared:derive_bip340_key");
    return std::move(prepared).sign_message(signer, message, secp_context);
}

Result<ProvenSignature> sign_message_with_prepared_proof(const SecretKey& secret,
                                                         std::span<const unsigned char> message,
                                                         PreparedNonceWithProof&& prepared,
                                                         purify_secp_context* secp_context) {
    return std::move(prepared).sign_message(secret, message, secp_context);
}

Result<Signature> sign_with_topic(const SecretKey& secret, std::span<const unsigned char> message,
                                  std::span<const unsigned char> topic,
                                  purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce(secret, topic, secp_context), "sign_with_topic:prepare_topic_nonce");
    return sign_with_prepared_topic(secret, message, std::move(prepared), secp_context);
}

Result<Signature> sign_with_prepared_topic(const SecretKey& secret, std::span<const unsigned char> message,
                                           PreparedNonce&& prepared, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context), "sign_with_prepared_topic:derive_bip340_key");
    return std::move(prepared).sign_topic_message(signer, message, secp_context);
}

Result<ProvenSignature> sign_with_prepared_topic_proof(const SecretKey& secret,
                                                       std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared,
                                                       purify_secp_context* secp_context) {
    return std::move(prepared).sign_topic_message(secret, message, secp_context);
}

Result<ProvenSignature> sign_message_with_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                                purify_secp_context* secp_context,
                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, message, secp_context, circuit_cache),
                            "sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_message_with_proof(const SecretKey& secret, const MessageProofCache& cache,
                                                purify_secp_context* secp_context,
                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, cache, secp_context, circuit_cache),
                            "sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(secret, cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic,
                                              purify_secp_context* secp_context,
                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, topic, secp_context, circuit_cache),
                            "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache,
                                              purify_secp_context* secp_context,
                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, cache, secp_context, circuit_cache),
                            "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(secret, message, std::move(prepared), secp_context);
}

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(public_key.purify_pubkey), "verify_signature:validate_public_key");
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "verify_signature:secp_context"),
                           "verify_signature:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_xonly_pubkey");
    }
    if (purify_bip340_validate_signature(secp_context, signature.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "verify_signature:bip340_validate_signature");
    }
    return purify_bip340_verify(secp_context, signature.bytes.data(), nullable_data(message), message.size(),
                                public_key.bip340_pubkey.data()) != 0;
}

Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof,
                                        purify_secp_context* secp_context,
                                        bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            verifier_circuit(detail::tagged_eval_input(kMessageNonceTag, message), public_key.purify_pubkey),
                            "verify_message_nonce_proof:verifier_circuit");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Message, secp_context,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof,
                                        purify_secp_context* secp_context,
                                        bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache), "verify_message_nonce_proof:validate_message_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate(public_key.purify_pubkey),
                            "verify_message_nonce_proof:instantiate");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Message, secp_context,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      bppp::ExperimentalCircuitBackend* circuit_cache) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_topic_nonce_proof:empty_topic");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            verifier_circuit(detail::tagged_eval_input(kTopicNonceTag, topic), public_key.purify_pubkey),
                            "verify_topic_nonce_proof:verifier_circuit");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Topic, secp_context,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache), "verify_topic_nonce_proof:validate_topic_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate(public_key.purify_pubkey),
                            "verify_topic_nonce_proof:instantiate");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Topic, secp_context,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_message_signature_with_proof(const PublicKey& public_key,
                                                 std::span<const unsigned char> message,
                                                 const ProvenSignature& signature,
                                                 purify_secp_context* secp_context,
                                                 bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context),
                            "verify_message_signature_with_proof:verify_signature");
    if (!sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(public_key, message, signature.nonce_proof, secp_context, circuit_cache);
}

Result<bool> verify_message_signature_with_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                                 const ProvenSignature& signature,
                                                 purify_secp_context* secp_context,
                                                 bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, cache.message, signature.signature, secp_context),
                            "verify_message_signature_with_proof:verify_signature");
    if (!sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_message_nonce_proof(cache, public_key, signature.nonce_proof, secp_context, circuit_cache);
}

Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature,
                                               purify_secp_context* secp_context,
                                               bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context),
                            "verify_topic_signature_with_proof:verify_signature");
    if (!sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(public_key, topic, signature.nonce_proof, secp_context, circuit_cache);
}

Result<bool> verify_topic_signature_with_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                               std::span<const unsigned char> message,
                                               const ProvenSignature& signature,
                                               purify_secp_context* secp_context,
                                               bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context),
                            "verify_topic_signature_with_proof:verify_signature");
    if (!sig_ok) {
        return false;
    }
    if (signature.signature.nonce().xonly != signature.nonce_proof.nonce.xonly) {
        return false;
    }
    return verify_topic_nonce_proof(cache, public_key, signature.nonce_proof, secp_context, circuit_cache);
}

}  // namespace api_impl

Result<PublicKey> PublicKey::from_secret(const SecretKey& secret, purify_secp_context* secp_context) {
    return api_impl::derive_public_key(secret, secp_context);
}

Result<bool> PublicKey::verify_signature(std::span<const unsigned char> message, const Signature& signature,
                                         purify_secp_context* secp_context) const {
    return api_impl::verify_signature(*this, message, signature, secp_context);
}

Result<bool> PublicKey::verify_message_nonce_proof(std::span<const unsigned char> message,
                                                   const NonceProof& nonce_proof,
                                                   purify_secp_context* secp_context,
                                                   bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(*this, message, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_nonce_proof(const MessageProofCache& cache, const NonceProof& nonce_proof,
                                                   purify_secp_context* secp_context,
                                                   bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(cache, *this, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(std::span<const unsigned char> topic,
                                                 const NonceProof& nonce_proof,
                                                 purify_secp_context* secp_context,
                                                 bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(*this, topic, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(const TopicProofCache& cache, const NonceProof& nonce_proof,
                                                 purify_secp_context* secp_context,
                                                 bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(cache, *this, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(std::span<const unsigned char> message,
                                                            const ProvenSignature& signature,
                                                            purify_secp_context* secp_context,
                                                            bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(*this, message, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(const MessageProofCache& cache,
                                                            const ProvenSignature& signature,
                                                            purify_secp_context* secp_context,
                                                            bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(cache, *this, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(std::span<const unsigned char> message,
                                                          std::span<const unsigned char> topic,
                                                          const ProvenSignature& signature,
                                                          purify_secp_context* secp_context,
                                                          bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(*this, message, topic, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(const TopicProofCache& cache,
                                                          std::span<const unsigned char> message,
                                                          const ProvenSignature& signature,
                                                          purify_secp_context* secp_context,
                                                          bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(cache, *this, message, signature, secp_context, circuit_cache);
}

Result<KeyPair> KeyPair::from_secret(const SecretKey& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, secret.clone(), "KeyPair::from_secret:clone");
    return KeyPair::from_secret(std::move(owned_secret), secp_context);
}

Result<KeyPair> KeyPair::from_secret(SecretKey&& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto public_key, PublicKey::from_secret(secret, secp_context), "KeyPair::from_secret:from_secret");
    return KeyPair(std::move(secret), std::move(public_key));
}

Result<PreparedNonce> KeyPair::prepare_message_nonce(std::span<const unsigned char> message,
                                                     purify_secp_context* secp_context) const {
    return api_impl::prepare_message_nonce(secret_, message, secp_context);
}

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(
    std::span<const unsigned char> message,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, message, secp_context, circuit_cache);
}

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(
    const MessageProofCache& cache,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, cache, secp_context, circuit_cache);
}

Result<PreparedNonce> KeyPair::prepare_topic_nonce(std::span<const unsigned char> topic,
                                                   purify_secp_context* secp_context) const {
    return api_impl::prepare_topic_nonce(secret_, topic, secp_context);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(
    std::span<const unsigned char> topic,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, topic, secp_context, circuit_cache);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(
    const TopicProofCache& cache,
    purify_secp_context* secp_context,
    bppp::ExperimentalCircuitBackend* circuit_cache) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, cache, secp_context, circuit_cache);
}

Result<Signature> KeyPair::sign_message(std::span<const unsigned char> message,
                                        purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce(message, secp_context), "KeyPair::sign_message:prepare_message_nonce");
    return sign_message_with_prepared(message, std::move(prepared), secp_context);
}

Result<Signature> KeyPair::sign_message_with_prepared(std::span<const unsigned char> message,
                                                      PreparedNonce&& prepared,
                                                      purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret_, secp_context), "KeyPair::sign_message_with_prepared:derive_bip340_key");
    return std::move(prepared).sign_message(signer, message, secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_prepared_proof(std::span<const unsigned char> message,
                                                                  PreparedNonceWithProof&& prepared,
                                                                  purify_secp_context* secp_context) const {
    return std::move(prepared).sign_message(secret_, message, secp_context);
}

Result<Signature> KeyPair::sign_with_topic(std::span<const unsigned char> message,
                                           std::span<const unsigned char> topic,
                                           purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce(topic, secp_context), "KeyPair::sign_with_topic:prepare_topic_nonce");
    return sign_with_prepared_topic(message, std::move(prepared), secp_context);
}

Result<Signature> KeyPair::sign_with_prepared_topic(std::span<const unsigned char> message,
                                                    PreparedNonce&& prepared,
                                                    purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret_, secp_context), "KeyPair::sign_with_prepared_topic:derive_bip340_key");
    return std::move(prepared).sign_topic_message(signer, message, secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_prepared_topic_proof(std::span<const unsigned char> message,
                                                                PreparedNonceWithProof&& prepared,
                                                                purify_secp_context* secp_context) const {
    return std::move(prepared).sign_topic_message(secret_, message, secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(std::span<const unsigned char> message,
                                                         purify_secp_context* secp_context,
                                                         bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(message, secp_context, circuit_cache),
                            "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(const MessageProofCache& cache,
                                                         purify_secp_context* secp_context,
                                                         bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(cache, secp_context, circuit_cache),
                            "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       std::span<const unsigned char> topic,
                                                       purify_secp_context* secp_context,
                                                       bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(topic, secp_context, circuit_cache),
                            "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       const TopicProofCache& cache,
                                                       purify_secp_context* secp_context,
                                                       bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(cache, secp_context, circuit_cache),
                            "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

}  // namespace purify::puresign_plusplus
