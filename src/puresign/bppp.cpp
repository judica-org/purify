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
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include "detail/common.hpp"
#include "purify/secp_bridge.h"
#include "secure_cleanup.hpp"

namespace purify::puresign_plusplus {

namespace api_impl {

Result<Signature> sign_message_with_prepared(const SecretKey& secret, std::span<const unsigned char> message,
                                             PreparedNonce prepared, purify_secp_context* secp_context);
Result<Signature> sign_with_prepared_topic(const SecretKey& secret, std::span<const unsigned char> message,
                                           PreparedNonce prepared, purify_secp_context* secp_context);

}  // namespace api_impl

namespace {

constexpr std::string_view kMessageNonceTag = "PureSign/Nonce/Message/";
constexpr std::string_view kTopicNonceTag = "PureSign/Nonce/Topic/";
constexpr std::string_view kMessageBindingTag = "PureSign/Binding/Message";
constexpr std::string_view kTopicBindingTag = "PureSign/Binding/Topic";
constexpr std::string_view kMessageProofTag = "PureSign/BPPP/Proof/Message/V1";
constexpr std::string_view kTopicProofTag = "PureSign/BPPP/Proof/Topic/V1";

using Scope = PreparedNonce::Scope;
using ::purify::detail::WipeOnDestruction;

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
        return unexpected_error(ErrorCode::InternalMismatch);
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

using SecretProofSeed = ::purify::detail::Secret<Scalar32>;
using SecretPackedKeyBytes =
    ::purify::detail::Secret<std::array<unsigned char, 64>>;

void derive_secret_prover_seed(const SecretKey& secret, Scope scope,
                               std::span<const unsigned char> eval_input,
                               SecretProofSeed& out) {
    SecretPackedKeyBytes secret_bytes;
    ::purify::detail::BigUIntCBridge<8>::to_bytes_be(
        secret_bytes.value.data(), secret.packed().limbs.data());
    std::array digest_segments{
        std::span<const unsigned char>(secret_bytes.value.data(), secret_bytes.value.size()),
        eval_input,
    };
    Scalar32 digest = proof_tagged_hash(scope).digest_many(digest_segments);
    out.value = digest;
    detail::secure_clear_bytes(digest.data(), digest.size());
}

Status validate_public_key_bundle(const PublicKey& public_key, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(public_key.purify_pubkey));
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
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

    DerivedNonceData() = default;
    DerivedNonceData(const DerivedNonceData&) = delete;
    DerivedNonceData& operator=(const DerivedNonceData&) = delete;
    DerivedNonceData(DerivedNonceData&& other) noexcept
        : scope(other.scope), scalar(other.scalar), nonce(other.nonce),
          signer_pubkey(other.signer_pubkey), binding_digest(other.binding_digest),
          eval_input(std::move(other.eval_input)) {
        other.clear();
    }
    DerivedNonceData& operator=(DerivedNonceData&& other) noexcept {
        if (this != &other) {
            clear();
            scope = other.scope;
            scalar = other.scalar;
            nonce = other.nonce;
            signer_pubkey = other.signer_pubkey;
            binding_digest = other.binding_digest;
            eval_input = std::move(other.eval_input);
            other.clear();
        }
        return *this;
    }
    ~DerivedNonceData() { clear(); }

private:
    void clear() noexcept {
        detail::secure_clear_bytes(scalar.data(), scalar.size());
    }
};

Result<DerivedNonceData> derive_nonce_data(const SecretKey& secret,
                                           Scope scope,
                                           std::span<const unsigned char> input,
                                           purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_puresign_field_alignment());
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context));

    const std::string_view nonce_tag = scope == Scope::Message ? kMessageNonceTag : kTopicNonceTag;
    const TaggedHash& binding_hash = binding_tagged_hash(scope);

    DerivedNonceData out{};
    out.scope = scope;
    out.signer_pubkey = signer.xonly_pubkey;
    out.binding_digest = binding_digest(binding_hash, input);
    out.eval_input = detail::tagged_eval_input(nonce_tag, input);

    auto nonce_value = eval(secret, out.eval_input);
    if (!nonce_value.has_value()) {
        return unexpected_error(nonce_value.error());
    }
    if (nonce_value->is_zero()) {
        detail::secure_clear_bytes(&*nonce_value, sizeof(*nonce_value));
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    static_assert(std::is_trivially_destructible_v<FieldElement>);
    purify_scalar_get_b32(
        out.scalar.data(),
        &::purify::detail::FieldElementAccess::raw(*nonce_value));
    detail::secure_clear_bytes(&*nonce_value, sizeof(*nonce_value));

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_nonce_from_scalar(secp_context, out.scalar.data(), out.nonce.xonly.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return out;
}

Result<DerivedNonceData> prepare_nonce_data_impl(const SecretKey& secret,
                                                 Scope scope,
                                                 std::span<const unsigned char> input,
                                                 purify_secp_context* secp_context) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_ASSIGN_OR_RETURN(auto nonce_data, derive_nonce_data(secret, scope, input, secp_context));
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
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_xonly_from_point(secp_context, nonce_proof.commitment_point.data(), xonly.data(), &parity) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
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
    auto witness_result = prove_assignment_data(detail::copy_bytes(eval_input), secret);
    if (!witness_result.has_value()) {
        return unexpected_error(witness_result.error());
    }
    BulletproofWitnessData& witness = *witness_result;
    PURIFY_ASSIGN_OR_RETURN(auto partial_ok, circuit_template.partial_evaluate(witness.assignment));
    if (!partial_ok) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto final_ok, circuit_template.final_evaluate(witness.assignment, witness.public_key));
    if (!final_ok) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, circuit_template.instantiate(witness.public_key));
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit));

    PURIFY_ASSIGN_OR_RETURN(auto commitment_point, commitment_point_from_scalar(witness.assignment.commitments.front(), secp_context));
    SecretProofSeed secret_prover_seed;
    derive_secret_prover_seed(secret, scope, eval_input, secret_prover_seed);
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{commitment_point};
    PURIFY_ASSIGN_OR_RETURN(auto proof, bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
                                            circuit, witness.assignment, secret_prover_seed.value, public_commitments,
                                            secp_context, statement_binding, circuit_cache));

    NonceProof out{};
    out.nonce = expected_nonce;
    out.commitment_point = commitment_point;
    out.proof = std::move(proof);
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(out, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::InternalMismatch);
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
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit_template, verifier_circuit_template(detail::tagged_eval_input(nonce_tag, input)));
    Bytes eval_input = detail::tagged_eval_input(nonce_tag, input);
    return build_nonce_proof_from_template(secret, scope, expected_nonce, eval_input, circuit_template, secp_context,
                                           circuit_cache);
}

Result<bool> verify_nonce_proof_with_circuit(const PublicKey& public_key,
                                             const NativeBulletproofCircuit& circuit,
                                             const NonceProof& nonce_proof,
                                             Scope scope,
                                             purify_secp_context* secp_context,
                                             bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_public_key_bundle(public_key, secp_context));
    PURIFY_RETURN_IF_ERROR(detail::validate_proof_cache_circuit(circuit));
    PURIFY_ASSIGN_OR_RETURN(auto match, nonce_proof_matches_nonce(nonce_proof, secp_context));
    if (!match) {
        return false;
    }
    Bytes statement_binding = proof_statement_binding(scope);
    std::array<bppp::PointBytes, 1> public_commitments{nonce_proof.commitment_point};
    return bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, nonce_proof.proof, public_commitments, secp_context, statement_binding, circuit_cache);
}

}  // namespace

Result<MessageProofCache> MessageProofCache::build(std::span<const unsigned char> message) {
    Bytes eval_input = detail::tagged_eval_input(kMessageNonceTag, message);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input));
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest());
    MessageProofCache cache{};
    cache.message = detail::copy_bytes(message);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
    return cache;
}

Result<TopicProofCache> TopicProofCache::build(std::span<const unsigned char> topic) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    Bytes eval_input = detail::tagged_eval_input(kTopicNonceTag, topic);
    PURIFY_ASSIGN_OR_RETURN(auto circuit_template, verifier_circuit_template(eval_input));
    PURIFY_ASSIGN_OR_RETURN(auto template_digest, circuit_template.integrity_digest());
    TopicProofCache cache{};
    cache.topic = detail::copy_bytes(topic);
    cache.eval_input = std::move(eval_input);
    cache.circuit_template = std::move(circuit_template);
    cache.template_digest = std::move(template_digest);
    return cache;
}

PreparedNonce::PreparedNonce(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                             const XOnly32& signer_pubkey, const XOnly32& binding_digest)
    : scope_(scope), scalar_(scalar), nonce_(nonce),
      signer_pubkey_(signer_pubkey), binding_digest_(binding_digest),
      available_(true) {}

PreparedNonce PreparedNonce::from_parts(Scope scope, const Scalar32& scalar, const Nonce& nonce,
                                        const XOnly32& signer_pubkey, const XOnly32& binding_digest) {
    return PreparedNonce(scope, scalar, nonce, signer_pubkey, binding_digest);
}

PreparedNonce::PreparedNonce(PreparedNonce&& other) noexcept
    : scope_(other.scope_), scalar_(other.scalar_), nonce_(other.nonce_),
      signer_pubkey_(other.signer_pubkey_), binding_digest_(other.binding_digest_),
      available_(other.available_) {
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
        available_ = other.available_;
        other.clear();
    }
    return *this;
}

PreparedNonce::~PreparedNonce() {
    clear();
}

void PreparedNonce::clear() noexcept {
    detail::secure_clear_bytes(scalar_.data(), scalar_.size());
    available_ = false;
}

Result<Signature> PreparedNonce::sign_message(const Bip340Key& signer,
                                              std::span<const unsigned char> message,
                                              purify_secp_context* secp_context) && {
    if (!available_) {
        return unexpected_error(ErrorCode::UninitializedState);
    }
    available_ = false;
    WipeOnDestruction burn(scalar_);
    if (scope_ != Scope::Message) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (binding_digest_ != binding_digest(binding_tagged_hash(Scope::Message), message)) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    if (purify_bip340_verify(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                             signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return out;
}

Result<Signature> PreparedNonce::sign_topic_message(const Bip340Key& signer,
                                                    std::span<const unsigned char> message,
                                                    purify_secp_context* secp_context) && {
    if (!available_) {
        return unexpected_error(ErrorCode::UninitializedState);
    }
    available_ = false;
    WipeOnDestruction burn(scalar_);
    if (scope_ != Scope::Topic) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    if (signer_pubkey_ != signer.xonly_pubkey) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }

    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    Signature out{};
    if (purify_bip340_sign_with_fixed_nonce(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                                            signer.seckey.data(), scalar_.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    if (out.nonce().xonly != nonce_.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    if (purify_bip340_verify(secp_context, out.bytes.data(), nullable_data(message), message.size(),
                             signer.xonly_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return out;
}

PreparedNonceWithProof PreparedNonceWithProof::from_parts(PreparedNonce prepared, NonceProof proof) {
    return PreparedNonceWithProof(std::move(prepared), std::move(proof));
}

Result<Scalar32> PreparedNonceWithProof::raw_scalar() const {
    if (!prepared_.available()) {
        return unexpected_error(ErrorCode::UninitializedState);
    }
    if (proof_.commitment_point[0] != 0x02 &&
        proof_.commitment_point[0] != 0x03) {
        return unexpected_error(ErrorCode::RangeViolation);
    }
    if (!std::equal(proof_.commitment_point.begin() + 1,
                    proof_.commitment_point.end(),
                    prepared_.public_nonce().xonly.begin())) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto out, prepared_.scalar());
    if (proof_.commitment_point[0] == 0x03) {
        purify_scalar scalar{};
        int overflow = 0;
        purify_scalar_set_b32(&scalar, out.data(), &overflow);
        if (overflow != 0 || purify_scalar_is_zero(&scalar) != 0) {
            detail::secure_clear_bytes(&scalar, sizeof(scalar));
            detail::secure_clear_bytes(out.data(), out.size());
            return unexpected_error(ErrorCode::InternalMismatch);
        }
        purify_scalar_negate(&scalar, &scalar);
        purify_scalar_get_b32(out.data(), &scalar);
        detail::secure_clear_bytes(&scalar, sizeof(scalar));
    }
    return out;
}

Result<ProvenSignature> PreparedNonceWithProof::sign_message(const SecretKey& secret,
                                                             std::span<const unsigned char> message,
                                                             purify_secp_context* secp_context) && {
    NonceProof nonce_proof = std::move(proof_);
    PURIFY_ASSIGN_OR_RETURN(auto signature,
                            api_impl::sign_message_with_prepared(secret, message, std::move(prepared_), secp_context));
    if (signature.nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return ProvenSignature{signature, std::move(nonce_proof)};
}

Result<ProvenSignature> PreparedNonceWithProof::sign_topic_message(const SecretKey& secret,
                                                                   std::span<const unsigned char> message,
                                                                   purify_secp_context* secp_context) && {
    NonceProof nonce_proof = std::move(proof_);
    PURIFY_ASSIGN_OR_RETURN(auto signature,
                            api_impl::sign_with_prepared_topic(secret, message, std::move(prepared_), secp_context));
    if (signature.nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return ProvenSignature{signature, std::move(nonce_proof)};
}

namespace api_impl {

Result<PublicKey> derive_public_key(const SecretKey& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& purify_key, derive_key(secret));
    PURIFY_ASSIGN_OR_RETURN(const auto& bip340_key, derive_bip340_key(secret, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, message, secp_context));
    return PreparedNonce::from_parts(Scope::Message, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                std::span<const unsigned char> message,
                                                                purify_secp_context* secp_context,
                                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, message, secp_context));
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, Scope::Message, message, prepared.public_nonce(),
                                                          secp_context, circuit_cache));
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_message_nonce_with_proof(const SecretKey& secret,
                                                                const MessageProofCache& cache,
                                                                purify_secp_context* secp_context,
                                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Message, cache.message, secp_context));
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Message, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof, build_nonce_proof_from_template(secret, Scope::Message, prepared.public_nonce(), cache.eval_input,
                                                    cache.circuit_template, secp_context,
                                                    circuit_cache != nullptr ? circuit_cache : &cache.backend_cache));
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonce> prepare_topic_nonce(const SecretKey& secret, std::span<const unsigned char> topic,
                                          purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, topic, secp_context));
    return PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar, nonce_data.nonce,
                                     nonce_data.signer_pubkey, nonce_data.binding_digest);
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              std::span<const unsigned char> topic,
                                                              purify_secp_context* secp_context,
                                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, topic, secp_context));
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof(secret, Scope::Topic, topic, prepared.public_nonce(),
                                                          secp_context, circuit_cache));
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<PreparedNonceWithProof> prepare_topic_nonce_with_proof(const SecretKey& secret,
                                                              const TopicProofCache& cache,
                                                              purify_secp_context* secp_context,
                                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, prepare_nonce_data_impl(secret, Scope::Topic, cache.topic, secp_context));
    PreparedNonce prepared = PreparedNonce::from_parts(Scope::Topic, nonce_data.scalar,
                                                       nonce_data.nonce, nonce_data.signer_pubkey,
                                                       nonce_data.binding_digest);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof, build_nonce_proof_from_template(secret, Scope::Topic, prepared.public_nonce(), cache.eval_input,
                                                    cache.circuit_template, secp_context,
                                                    circuit_cache != nullptr ? circuit_cache : &cache.backend_cache));
    return PreparedNonceWithProof::from_parts(std::move(prepared), std::move(proof));
}

Result<Signature> sign_message(const SecretKey& secret, std::span<const unsigned char> message,
                               purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce(secret, message, secp_context));
    return sign_message_with_prepared(secret, message, std::move(prepared), secp_context);
}

Result<Signature> sign_message_with_prepared(const SecretKey& secret, std::span<const unsigned char> message,
                                             PreparedNonce prepared, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce(secret, topic, secp_context));
    return sign_with_prepared_topic(secret, message, std::move(prepared), secp_context);
}

Result<Signature> sign_with_prepared_topic(const SecretKey& secret, std::span<const unsigned char> message,
                                           PreparedNonce prepared, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& signer, derive_bip340_key(secret, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, message, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_message_with_proof(const SecretKey& secret, const MessageProofCache& cache,
                                                purify_secp_context* secp_context,
                                                bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(secret, cache, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(secret, cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              std::span<const unsigned char> topic,
                                              purify_secp_context* secp_context,
                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, topic, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(secret, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> sign_with_topic_proof(const SecretKey& secret, std::span<const unsigned char> message,
                                              const TopicProofCache& cache,
                                              purify_secp_context* secp_context,
                                              bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(secret, cache, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(secret, message, std::move(prepared), secp_context);
}

Result<bool> verify_signature(const PublicKey& public_key, std::span<const unsigned char> message,
                              const Signature& signature, purify_secp_context* secp_context) {
    PURIFY_RETURN_IF_ERROR(validate_public_key(public_key.purify_pubkey));
    PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context));
    if (purify_bip340_validate_xonly_pubkey(secp_context, public_key.bip340_pubkey.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    if (purify_bip340_validate_signature(secp_context, signature.bytes.data()) == 0) {
        return unexpected_error(ErrorCode::BackendRejectedInput);
    }
    return purify_bip340_verify(secp_context, signature.bytes.data(), nullable_data(message), message.size(),
                                public_key.bip340_pubkey.data()) != 0;
}

Result<bool> verify_message_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> message,
                                        const NonceProof& nonce_proof,
                                        purify_secp_context* secp_context,
                                        bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, verifier_circuit(detail::tagged_eval_input(kMessageNonceTag, message),
                                                                  public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Message, secp_context,
                                           circuit_cache);
}

Result<bool> verify_message_nonce_proof(const MessageProofCache& cache, const PublicKey& public_key,
                                        const NonceProof& nonce_proof,
                                        purify_secp_context* secp_context,
                                        bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_message_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate(public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Message, secp_context,
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_topic_nonce_proof(const PublicKey& public_key, std::span<const unsigned char> topic,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      bppp::ExperimentalCircuitBackend* circuit_cache) {
    if (topic.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, verifier_circuit(detail::tagged_eval_input(kTopicNonceTag, topic),
                                                                  public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Topic, secp_context, circuit_cache);
}

Result<bool> verify_topic_nonce_proof(const TopicProofCache& cache, const PublicKey& public_key,
                                      const NonceProof& nonce_proof,
                                      purify_secp_context* secp_context,
                                      bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_topic_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, cache.circuit_template.instantiate(public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, Scope::Topic, secp_context,
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

Result<bool> verify_message_signature_with_proof(const PublicKey& public_key,
                                                 std::span<const unsigned char> message,
                                                 const ProvenSignature& signature,
                                                 purify_secp_context* secp_context,
                                                 bppp::ExperimentalCircuitBackend* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, cache.message, signature.signature, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto sig_ok, verify_signature(public_key, message, signature.signature, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, secret.clone());
    return KeyPair::from_secret(std::move(owned_secret), secp_context);
}

Result<KeyPair> KeyPair::from_secret(SecretKey&& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto public_key, PublicKey::from_secret(secret, secp_context));
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
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce(message, secp_context));
    return sign_message_with_prepared(message, std::move(prepared), secp_context);
}

Result<Signature> KeyPair::sign_message_with_prepared(std::span<const unsigned char> message,
                                                      PreparedNonce&& prepared,
                                                      purify_secp_context* secp_context) const {
    return api_impl::sign_message_with_prepared(
        secret_, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_prepared_proof(std::span<const unsigned char> message,
                                                                  PreparedNonceWithProof&& prepared,
                                                                  purify_secp_context* secp_context) const {
    return std::move(prepared).sign_message(secret_, message, secp_context);
}

Result<Signature> KeyPair::sign_with_topic(std::span<const unsigned char> message,
                                           std::span<const unsigned char> topic,
                                           purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce(topic, secp_context));
    return sign_with_prepared_topic(message, std::move(prepared), secp_context);
}

Result<Signature> KeyPair::sign_with_prepared_topic(std::span<const unsigned char> message,
                                                    PreparedNonce&& prepared,
                                                    purify_secp_context* secp_context) const {
    return api_impl::sign_with_prepared_topic(
        secret_, message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_prepared_topic_proof(std::span<const unsigned char> message,
                                                                PreparedNonceWithProof&& prepared,
                                                                purify_secp_context* secp_context) const {
    return std::move(prepared).sign_topic_message(secret_, message, secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(std::span<const unsigned char> message,
                                                         purify_secp_context* secp_context,
                                                         bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(message, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_message_with_proof(const MessageProofCache& cache,
                                                         purify_secp_context* secp_context,
                                                         bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(cache, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(cache.message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       std::span<const unsigned char> topic,
                                                       purify_secp_context* secp_context,
                                                       bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(topic, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

Result<ProvenSignature> KeyPair::sign_with_topic_proof(std::span<const unsigned char> message,
                                                       const TopicProofCache& cache,
                                                       purify_secp_context* secp_context,
                                                       bppp::ExperimentalCircuitBackend* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(cache, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

}  // namespace purify::puresign_plusplus
