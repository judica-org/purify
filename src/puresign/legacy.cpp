// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/legacy.cpp
 * @brief Purify-derived BIP340 signing helpers with prepared nonces and wire-format artifacts.
 */

#include "purify/puresign/legacy.hpp"

#include <algorithm>
#include <cstring>

#include "bulletproof_internal.hpp"
#include "detail/common.hpp"
#include "purify/bppp.hpp"
#include "purify/curve.hpp"

namespace purify::puresign {

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
constexpr std::string_view kMessageProofTag = "PureSign/Proof/Message/V1";
constexpr std::string_view kTopicProofTag = "PureSign/Proof/Topic/V1";
const TaggedHash kMessageBindingTaggedHash(kMessageBindingTag);
const TaggedHash kTopicBindingTaggedHash(kTopicBindingTag);
const TaggedHash kMessageProofTaggedHash(kMessageProofTag);
const TaggedHash kTopicProofTaggedHash(kTopicProofTag);

const TaggedHash& binding_tagged_hash(PreparedNonce::Scope scope) {
    return scope == PreparedNonce::Scope::Message ? kMessageBindingTaggedHash : kTopicBindingTaggedHash;
}

const TaggedHash& proof_tagged_hash(PreparedNonce::Scope scope) {
    return scope == PreparedNonce::Scope::Message ? kMessageProofTaggedHash : kTopicProofTaggedHash;
}

const UInt256& secp256k1_order() {
    static const UInt256 value =
        UInt256::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

Status validate_puresign_field_alignment() {
    if (prime_p() != secp256k1_order()) {
        return unexpected_error(ErrorCode::InternalMismatch, "puresign:field_order_mismatch");
    }
    return {};
}

Status validate_public_key_bundle(const PublicKey& public_key, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(public_key.purify_pubkey),
                           "puresign:validate_public_key_bundle:purify_pubkey");
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "puresign:validate_public_key_bundle:secp_context"),
                           "puresign:validate_public_key_bundle:secp_context");
    if (purify_bip340_validate_xonly_pubkey(secp_context, public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "puresign:validate_public_key_bundle:bip340_pubkey");
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

std::string_view proof_tag_for_scope(PreparedNonce::Scope scope) {
    return scope == PreparedNonce::Scope::Message ? kMessageProofTag : kTopicProofTag;
}

Bytes proof_statement_binding(PreparedNonce::Scope scope) {
    return bytes_from_ascii(proof_tag_for_scope(scope));
}

Scalar32 derive_proof_nonce_seed(const SecretKey& secret, PreparedNonce::Scope scope, std::span<const unsigned char> eval_input) {
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

Result<bool> nonce_proof_matches_nonce(const NonceProof& nonce_proof, purify_secp_context* secp_context) {
    XOnly32 xonly{};
    int parity = 0;
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "nonce_proof_matches_nonce:secp_context"),
                           "nonce_proof_matches_nonce:secp_context");
    if (purify_bip340_xonly_from_point(secp_context, nonce_proof.proof.commitment.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "nonce_proof_matches_nonce:invalid_commitment");
    }
    (void)parity;
    return xonly == nonce_proof.nonce.xonly;
}

Status validate_message_proof_cache(const MessageProofCache& cache) {
    return detail::validate_message_proof_cache(cache, kMessageNonceTag);
}

Status validate_topic_proof_cache(const TopicProofCache& cache) {
    return detail::validate_topic_proof_cache(cache, kTopicNonceTag);
}

struct DerivedNonceData {
    PreparedNonce::Scope scope;
    Scalar32 scalar{};
    Nonce nonce{};
    XOnly32 signer_pubkey{};
    XOnly32 binding_digest{};
    Bytes eval_input;
};

Result<NonceProof> build_nonce_proof_from_template(const SecretKey& secret, const DerivedNonceData& nonce_data,
                                                   const NativeBulletproofCircuitTemplate& circuit_template,
                                                   purify_secp_context* secp_context,
                                                   ExperimentalBulletproofBackendCache* backend_cache = nullptr) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(nonce_data.eval_input, secret),
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
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, circuit_template.instantiate_packed(witness.public_key),
                            "build_nonce_proof_from_template:instantiate_packed");
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit, "build_nonce_proof_from_template:circuit_shape"),
                           "build_nonce_proof_from_template:validate_proof_cache_circuit");

    Scalar32 proof_nonce = derive_proof_nonce_seed(secret, nonce_data.scope, nonce_data.eval_input);
    Bytes statement_binding = proof_statement_binding(nonce_data.scope);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof,
        prove_experimental_circuit_assume_valid(circuit, witness.assignment, proof_nonce,
                                                bppp::base_generator(secp_context), secp_context,
                                                statement_binding, std::nullopt,
                                                backend_cache),
        "build_nonce_proof_from_template:prove_experimental_circuit");

    NonceProof out{};
    out.nonce = nonce_data.nonce;
    out.proof = std::move(proof);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(out, secp_context),
                            "build_nonce_proof_from_template:nonce_proof_matches_nonce");
    if (!match) {
        return unexpected_error(ErrorCode::InternalMismatch, "build_nonce_proof_from_template:nonce_mismatch");
    }
    return out;
}

Result<DerivedNonceData> derive_nonce_data(const SecretKey& secret, PreparedNonce::Scope scope,
                                           std::span<const unsigned char> input,
                                           purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_puresign_field_alignment(), "derive_nonce_data:validate_puresign_field_alignment");
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context), "derive_nonce_data:derive_bip340_key");

    const std::string_view nonce_tag = scope == PreparedNonce::Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    const TaggedHash& binding_hash = binding_tagged_hash(scope);

    DerivedNonceData out{};
    out.scope = scope;
    out.signer_pubkey = signer.xonly_pubkey;
    out.binding_digest = binding_digest(binding_hash, input);

    out.eval_input = detail::tagged_eval_input(nonce_tag, input);
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_value, eval(secret, out.eval_input), "derive_nonce_data:eval");
    out.scalar = nonce_value.to_bytes_be();
    if (std::all_of(out.scalar.begin(), out.scalar.end(), [](unsigned char byte) { return byte == 0; })) {
        /* This rejects the unique invalid Schnorr nonce. Since Purify outputs a field element
         * modulo the secp256k1 group order, the failure probability is exactly 1/n, which is
         * negligible for n ~= 2^256.
         */
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:zero_nonce");
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "derive_nonce_data:secp_context"),
                           "derive_nonce_data:secp_context");
    if (purify_bip340_nonce_from_scalar(secp_context, out.scalar.data(), out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput, "derive_nonce_data:bip340_nonce_from_scalar");
    }
    return out;
}

Result<NonceProof> build_nonce_proof(const SecretKey& secret,
                                     const DerivedNonceData& nonce_data,
                                     purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit_template, verifier_circuit_template(nonce_data.eval_input),
                            "build_nonce_proof:verifier_circuit_template");
    return build_nonce_proof_from_template(secret, nonce_data, circuit_template, secp_context);
}

Result<DerivedNonceData> prepare_nonce_data_impl(const SecretKey& secret, PreparedNonce::Scope scope,
                                                 std::span<const unsigned char> input,
                                                 purify_secp_context* secp_context) {
    if (scope == PreparedNonce::Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "prepare_nonce_data_impl:empty_topic");
    }
    PURIFY_ASSIGN_OR_RETURN(auto nonce_data, derive_nonce_data(secret, scope, input, secp_context),
                            "prepare_nonce_data_impl:derive_nonce_data");
    return nonce_data;
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key, const NativeBulletproofCircuit& circuit,
                                             const NonceProof& nonce_proof, PreparedNonce::Scope scope,
                                             purify_secp_context* secp_context,
                                             const char* context,
                                             ExperimentalBulletproofBackendCache* backend_cache = nullptr) {
    PURIFY_RETURN_IF_ERROR(validate_public_key_bundle(public_key, secp_context), context);
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit, context), context);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(nonce_proof, secp_context), context);
    if (!match) {
        return false;
    }
    Bytes statement_binding = proof_statement_binding(scope);
    return verify_experimental_circuit(circuit, nonce_proof.proof, bppp::base_generator(secp_context), secp_context, statement_binding,
                                       backend_cache);
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key,
                                             const NativeBulletproofCircuit::PackedWithSlack& circuit,
                                             const NonceProof& nonce_proof, PreparedNonce::Scope scope,
                                             purify_secp_context* secp_context,
                                             const char* context,
                                             ExperimentalBulletproofBackendCache* backend_cache = nullptr) {
    PURIFY_RETURN_IF_ERROR(validate_public_key_bundle(public_key, secp_context), context);
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit, context), context);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(nonce_proof, secp_context), context);
    if (!match) {
        return false;
    }
    Bytes statement_binding = proof_statement_binding(scope);
    return verify_experimental_circuit(circuit, nonce_proof.proof, bppp::base_generator(secp_context), secp_context, statement_binding,
                                       backend_cache);
}

}  // namespace

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
    if (binding_digest_ != binding_digest(kMessageBindingTaggedHash, message)) {
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
    Bytes eval_input = detail::tagged_eval_input(kMessageNonceTag, message);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input),
                            "build_message_proof_cache:verifier_circuit_template");
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest(),
                            "build_message_proof_cache:integrity_digest");
    MessageProofCache cache{};
    cache.message = detail::copy_bytes(message);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
    return cache;
}

Result<TopicProofCache> build_topic_proof_cache(std::span<const unsigned char> topic) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "build_topic_proof_cache:empty_topic");
    }
    Bytes eval_input = detail::tagged_eval_input(kTopicNonceTag, topic);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input),
                            "build_topic_proof_cache:verifier_circuit_template");
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest(),
                            "build_topic_proof_cache:integrity_digest");
    TopicProofCache cache{};
    cache.topic = detail::copy_bytes(topic);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
    return cache;
}

Result<PreparedNonce> prepare_message_nonce(const SecretKey& secret, std::span<const unsigned char> message,
                                            purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Message, message, secp_context),
                            "prepare_message_nonce:prepare_nonce_data_impl");
    return PreparedNonce::from_parts(PreparedNonce::Scope::Message, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                std::span<const unsigned char> message,
                                                                purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Message, message, secp_context),
                            "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(PreparedNonce::Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, nonce_data, secp_context),
                            "prepare_message_nonce_with_proof:build_nonce_proof");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                const MessageProofCache& cache,
                                                                purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache),
                           "prepare_message_nonce_with_proof:validate_message_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Message, cache.message, secp_context),
                            "prepare_message_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(PreparedNonce::Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof,
                            build_nonce_proof_from_template(secret, nonce_data, cache.circuit_template, secp_context,
                                                            &cache.backend_cache),
                            "prepare_message_nonce_with_proof:build_nonce_proof_from_template");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonce> prepare_topic_nonce(const SecretKey& secret, std::span<const unsigned char> topic,
                                          purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Topic, topic, secp_context),
                            "prepare_topic_nonce:prepare_nonce_data_impl");
    return PreparedNonce::from_parts(PreparedNonce::Scope::Topic, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              std::span<const unsigned char> topic,
                                                              purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Topic, topic, secp_context),
                            "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(PreparedNonce::Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, nonce_data, secp_context),
                            "prepare_topic_nonce_with_proof:build_nonce_proof");
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              const TopicProofCache& cache,
                                                              purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache),
                           "prepare_topic_nonce_with_proof:validate_topic_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            prepare_nonce_data_impl(secret, PreparedNonce::Scope::Topic, cache.topic, secp_context),
                            "prepare_topic_nonce_with_proof:prepare_nonce_data_impl");
    PreparedNonce prepared = PreparedNonce::from_parts(PreparedNonce::Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof,
                            build_nonce_proof_from_template(secret, nonce_data, cache.circuit_template, secp_context,
                                                            &cache.backend_cache),
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

Result<ProvenSignature> sign_message_with_prepared_proof(const SecretKey& secret, std::span<const unsigned char> message,
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

Result<ProvenSignature> sign_with_prepared_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                                       PreparedNonceWithProof&& prepared,
                                                       purify_secp_context* secp_context) {
    return std::move(prepared).sign_topic_message(secret, message, secp_context);
}

Result<ProvenSignature> sign_message_with_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                                purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, message, secp_context),
                            "sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_message_with_proof(const SecretKey& secret, const MessageProofCache& cache,
                                                purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, cache, secp_context),
                            "sign_message_with_proof:prepare_message_nonce_with_proof_cache");
    return sign_message_with_prepared_proof(secret, cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic,
                                              purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, topic, secp_context),
                            "sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache,
                                              purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, cache, secp_context),
                            "sign_with_topic_proof:prepare_topic_nonce_with_proof_cache");
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
                                        ExperimentalBulletproofBackendCache* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            verifier_circuit(detail::tagged_eval_input(kMessageNonceTag, message), public_key.purify_pubkey),
                            "verify_message_nonce_proof:verifier_circuit");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, PreparedNonce::Scope::Message, secp_context,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof,
                                        purify_secp_context* secp_context,
                                        ExperimentalBulletproofBackendCache* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache), "verify_message_nonce_proof:validate_message_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate_packed(public_key.purify_pubkey),
                            "verify_message_nonce_proof:instantiate_packed");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, PreparedNonce::Scope::Message, secp_context,
                                           "verify_message_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      ExperimentalBulletproofBackendCache* circuit_cache) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "verify_topic_nonce_proof:empty_topic");
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            verifier_circuit(detail::tagged_eval_input(kTopicNonceTag, topic), public_key.purify_pubkey),
                            "verify_topic_nonce_proof:verifier_circuit");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, PreparedNonce::Scope::Topic, secp_context,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache);
}

Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      ExperimentalBulletproofBackendCache* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache), "verify_topic_nonce_proof:validate_topic_proof_cache");
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate_packed(public_key.purify_pubkey),
                            "verify_topic_nonce_proof:instantiate_packed");
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, PreparedNonce::Scope::Topic, secp_context,
                                           "verify_topic_nonce_proof:verify_nonce_proof_with_circuit",
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_message_signature_with_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                                 const ProvenSignature& signature,
                                                 purify_secp_context* secp_context,
                                                 ExperimentalBulletproofBackendCache* circuit_cache) {
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
                                                 ExperimentalBulletproofBackendCache* circuit_cache) {
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

Result<bool> verify_topic_signature_with_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                               std::span<const unsigned char> topic,
                                               const ProvenSignature& signature,
                                               purify_secp_context* secp_context,
                                               ExperimentalBulletproofBackendCache* circuit_cache) {
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
                                               ExperimentalBulletproofBackendCache* circuit_cache) {
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
                                                   ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(*this, message, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_nonce_proof(const MessageProofCache& cache, const NonceProof& nonce_proof,
                                                   purify_secp_context* secp_context,
                                                   ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_message_nonce_proof(cache, *this, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(std::span<const unsigned char> topic,
                                                 const NonceProof& nonce_proof,
                                                 purify_secp_context* secp_context,
                                                 ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(*this, topic, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_nonce_proof(const TopicProofCache& cache, const NonceProof& nonce_proof,
                                                 purify_secp_context* secp_context,
                                                 ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_topic_nonce_proof(cache, *this, nonce_proof, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(std::span<const unsigned char> message,
                                                            const ProvenSignature& signature,
                                                            purify_secp_context* secp_context,
                                                            ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(*this, message, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_message_signature_with_proof(const MessageProofCache& cache,
                                                            const ProvenSignature& signature,
                                                            purify_secp_context* secp_context,
                                                            ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_message_signature_with_proof(cache, *this, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(std::span<const unsigned char> message,
                                                          std::span<const unsigned char> topic,
                                                          const ProvenSignature& signature,
                                                          purify_secp_context* secp_context,
                                                          ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(*this, message, topic, signature, secp_context, circuit_cache);
}

Result<bool> PublicKey::verify_topic_signature_with_proof(const TopicProofCache& cache,
                                                          std::span<const unsigned char> message,
                                                          const ProvenSignature& signature,
                                                          purify_secp_context* secp_context,
                                                          ExperimentalBulletproofBackendCache* circuit_cache) const {
    return api_impl::verify_topic_signature_with_proof(cache, *this, message, signature, secp_context, circuit_cache);
}

Result<MessageProofCache> MessageProofCache::build(std::span<const unsigned char> message) {
    return api_impl::build_message_proof_cache(message);
}

Result<TopicProofCache> TopicProofCache::build(std::span<const unsigned char> topic) {
    return api_impl::build_topic_proof_cache(topic);
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

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(std::span<const unsigned char> message,
                                                                         purify_secp_context* secp_context) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, message, secp_context);
}

Result<PreparedNonceWithProof> KeyPair::prepare_message_nonce_with_proof(const MessageProofCache& cache,
                                                                         purify_secp_context* secp_context) const {
    return api_impl::prepare_message_nonce_with_proof(secret_, cache, secp_context);
}

Result<PreparedNonce> KeyPair::prepare_topic_nonce(std::span<const unsigned char> topic,
                                                   purify_secp_context* secp_context) const {
    return api_impl::prepare_topic_nonce(secret_, topic, secp_context);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(std::span<const unsigned char> topic,
                                                                       purify_secp_context* secp_context) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, topic, secp_context);
}

Result<PreparedNonceWithProof> KeyPair::prepare_topic_nonce_with_proof(const TopicProofCache& cache,
                                                                       purify_secp_context* secp_context) const {
    return api_impl::prepare_topic_nonce_with_proof(secret_, cache, secp_context);
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
                                                         purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(message, secp_context),
                            "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(const MessageProofCache& cache,
                                                         purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(cache, secp_context),
                            "KeyPair::sign_message_with_proof:prepare_message_nonce_with_proof");
    return sign_message_with_prepared_proof(cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       std::span<const unsigned char> topic,
                                                       purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(topic, secp_context),
                            "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       const TopicProofCache& cache,
                                                       purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(cache, secp_context),
                            "KeyPair::sign_with_topic_proof:prepare_topic_nonce_with_proof");
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

}  // namespace purify::puresign
