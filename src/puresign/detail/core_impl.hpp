// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file puresign/detail/core_impl.hpp
 * @brief Definitions of the PureSign templates declared in `purify/puresign/core.hpp`.
 *
 * Each proof-system backend defines its `Backend::Ops` and then explicitly instantiates the
 * templates in its own translation unit; `core.cpp` defines the parts that need no backend.
 *
 * `Backend::Ops` supplies:
 * - `kMessageProofTag`, `kTopicProofTag`: the tag bound into the proof statement and prover seed.
 * - `instantiate(circuit_template, purify_pubkey)`: the circuit form the proof system works over.
 * - `prove(circuit, assignment, prover_seed, nonce, statement_binding, secp_context, circuit_cache)`.
 * - `verify(circuit, nonce_proof, statement_binding, secp_context, circuit_cache)`.
 * - `matches_nonce(nonce_proof, secp_context)`: whether the point the proof binds is its nonce.
 * - `raw_scalar(prepared, nonce_proof)`: only when `Backend::kProofBindsRawPoint`.
 */

#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <utility>

#include "purify/curve.hpp"
#include "purify/puresign/core.hpp"
#include "secure_cleanup.hpp"

namespace purify::puresign_core::detail {

using Scope = PreparedNonce::Scope;

/** The Purify evaluation input a nonce of this scope is derived from. */
Bytes nonce_eval_input(Scope scope, std::span<const unsigned char> input);

inline constexpr std::size_t kPackedPurifyKeySize = 64;
inline constexpr std::size_t kPublicKeySerializedSize = kPackedPurifyKeySize + sizeof(XOnly32);

/** The Purify and BIP340 halves of a public-key bundle. */
struct PublicKeyParts {
    UInt512 purify_pubkey;
    XOnly32 bip340_pubkey{};
};

Bytes serialize_public_key(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey);
Result<PublicKeyParts> deserialize_public_key(std::span<const unsigned char> serialized,
                                              purify_secp_context* secp_context);
Result<PublicKeyParts> derive_public_key(const SecretKey& secret, purify_secp_context* secp_context);
Status validate_public_key_bundle(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey,
                                  purify_secp_context* secp_context);
Result<bool> verify_bip340_signature(const UInt512& purify_pubkey, const XOnly32& bip340_pubkey,
                                     std::span<const unsigned char> message, const Signature& signature,
                                     purify_secp_context* secp_context);

/** Whether a compressed point has the x coordinate of `nonce`. */
Result<bool> nonce_matches_point(const Nonce& nonce, const std::array<unsigned char, 33>& point,
                                 purify_secp_context* secp_context);

/** Everything one deterministic nonce derivation produces. The scalar is erased on destruction. */
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
    DerivedNonceData(DerivedNonceData&& other) noexcept;
    DerivedNonceData& operator=(DerivedNonceData&& other) noexcept;
    ~DerivedNonceData();
};

/** Derives the nonce for `(secret, scope, input)`. A topic must be non-empty. */
Result<DerivedNonceData> derive_nonce_data(const SecretKey& secret, Scope scope,
                                           std::span<const unsigned char> input,
                                           purify_secp_context* secp_context);
PreparedNonce prepared_nonce(const DerivedNonceData& nonce_data);
Result<PreparedNonce> prepare_nonce(const SecretKey& secret, Scope scope, std::span<const unsigned char> input,
                                    purify_secp_context* secp_context);
Result<Signature> sign_with_prepared(const SecretKey& secret, Scope scope, std::span<const unsigned char> message,
                                     PreparedNonce prepared, purify_secp_context* secp_context);

using SecretProofSeed = ::purify::detail::Secret<Scalar32>;

/** Derives the deterministic prover seed for one proof from the secret and its evaluation input. */
void derive_secret_prover_seed(const SecretKey& secret, const TaggedHash& proof_hash,
                               std::span<const unsigned char> eval_input, SecretProofSeed& out);

/** The backend-independent contents of a message or topic proof cache. */
struct ProofCacheParts {
    Bytes eval_input;
    NativeBulletproofCircuitTemplate circuit_template;
    Bytes template_digest;
};

Result<ProofCacheParts> build_proof_cache_parts(Scope scope, std::span<const unsigned char> input);
Status validate_proof_cache_parts(Scope scope, const Bytes& input, const Bytes& eval_input,
                                  const NativeBulletproofCircuitTemplate& circuit_template,
                                  const Bytes& template_digest);

inline std::size_t circuit_n_gates(const NativeBulletproofCircuit& circuit) {
    return circuit.n_gates;
}

inline std::size_t circuit_n_gates(const NativeBulletproofCircuit::PackedWithSlack& circuit) {
    return circuit.n_gates();
}

inline std::size_t circuit_n_commitments(const NativeBulletproofCircuit& circuit) {
    return circuit.n_commitments;
}

inline std::size_t circuit_n_commitments(const NativeBulletproofCircuit::PackedWithSlack& circuit) {
    return circuit.n_commitments();
}

/** A nonce-proof circuit has a power-of-two gate count and commits to exactly the nonce. */
template <typename CircuitLike>
Status validate_proof_circuit(const CircuitLike& circuit) {
    if (!circuit.has_valid_shape()) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (!is_power_of_two_size(circuit_n_gates(circuit))) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    if (circuit_n_commitments(circuit) != 1) {
        return unexpected_error(ErrorCode::InvalidDimensions);
    }
    return {};
}

template <typename Backend>
constexpr Scope scope_of(const MessageProofCache<Backend>&) noexcept {
    return Scope::Message;
}

template <typename Backend>
constexpr Scope scope_of(const TopicProofCache<Backend>&) noexcept {
    return Scope::Topic;
}

template <typename Backend>
const Bytes& bound_input(const MessageProofCache<Backend>& cache) noexcept {
    return cache.message;
}

template <typename Backend>
const Bytes& bound_input(const TopicProofCache<Backend>& cache) noexcept {
    return cache.topic;
}

template <typename Cache>
Status validate_proof_cache(const Cache& cache) {
    return validate_proof_cache_parts(scope_of(cache), bound_input(cache), cache.eval_input,
                                      cache.circuit_template, cache.template_digest);
}

template <typename Backend>
constexpr std::string_view proof_tag(Scope scope) noexcept {
    return scope == Scope::Message ? Backend::Ops::kMessageProofTag : Backend::Ops::kTopicProofTag;
}

template <typename Backend>
const TaggedHash& proof_tagged_hash(Scope scope) {
    static const TaggedHash message_hash(Backend::Ops::kMessageProofTag);
    static const TaggedHash topic_hash(Backend::Ops::kTopicProofTag);
    return scope == Scope::Message ? message_hash : topic_hash;
}

/** Proves that `nonce_data.nonce` is the Purify evaluation the circuit template describes. */
template <typename Backend>
Result<typename Backend::NonceProof> build_nonce_proof(const SecretKey& secret,
                                                       const DerivedNonceData& nonce_data,
                                                       const NativeBulletproofCircuitTemplate& circuit_template,
                                                       purify_secp_context* secp_context,
                                                       typename Backend::CircuitCache* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& witness, prove_assignment_data(nonce_data.eval_input, secret));
    PURIFY_ASSIGN_OR_RETURN(auto partial_ok, circuit_template.partial_evaluate(witness.assignment));
    if (!partial_ok) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(auto final_ok, circuit_template.final_evaluate(witness.assignment, witness.public_key));
    if (!final_ok) {
        return unexpected_error(ErrorCode::BindingMismatch);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, Backend::Ops::instantiate(circuit_template, witness.public_key));
    PURIFY_RETURN_IF_ERROR(validate_proof_circuit(circuit));

    SecretProofSeed prover_seed;
    derive_secret_prover_seed(secret, proof_tagged_hash<Backend>(nonce_data.scope), nonce_data.eval_input,
                              prover_seed);
    const Bytes statement_binding = bytes_from_ascii(proof_tag<Backend>(nonce_data.scope));
    PURIFY_ASSIGN_OR_RETURN(auto nonce_proof,
                            Backend::Ops::prove(circuit, witness.assignment, prover_seed.value, nonce_data.nonce,
                                                statement_binding, secp_context, circuit_cache));
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(nonce_proof, secp_context));
    if (!match) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return nonce_proof;
}

template <typename Backend>
Result<PreparedNonceWithProof<Backend>> prepare_nonce_with_proof(const SecretKey& secret, Scope scope,
                                                                 std::span<const unsigned char> input,
                                                                 purify_secp_context* secp_context,
                                                                 typename Backend::CircuitCache* circuit_cache) {
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data, derive_nonce_data(secret, scope, input, secp_context));
    PreparedNonce prepared = prepared_nonce(nonce_data);
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit_template, verifier_circuit_template(nonce_data.eval_input));
    PURIFY_ASSIGN_OR_RETURN(auto proof, build_nonce_proof<Backend>(secret, nonce_data, circuit_template,
                                                                    secp_context, circuit_cache));
    return PreparedNonceWithProof<Backend>::from_parts(std::move(prepared), std::move(proof));
}

/** `Cache` is the backend's message or topic proof cache; its own backend cache is the default. */
template <typename Backend, typename Cache>
Result<PreparedNonceWithProof<Backend>> prepare_cached_nonce_with_proof(
    const SecretKey& secret, const Cache& cache, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& nonce_data,
                            derive_nonce_data(secret, scope_of(cache), bound_input(cache), secp_context));
    PreparedNonce prepared = prepared_nonce(nonce_data);
    PURIFY_ASSIGN_OR_RETURN(
        auto proof, build_nonce_proof<Backend>(secret, nonce_data, cache.circuit_template, secp_context,
                                               circuit_cache != nullptr ? circuit_cache : &cache.backend_cache));
    return PreparedNonceWithProof<Backend>::from_parts(std::move(prepared), std::move(proof));
}

template <typename Backend>
Result<typename Backend::ProvenSignature> sign_with_prepared_proof(const SecretKey& secret, Scope scope,
                                                                   std::span<const unsigned char> message,
                                                                   PreparedNonce prepared,
                                                                   typename Backend::NonceProof nonce_proof,
                                                                   purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto signature,
                            sign_with_prepared(secret, scope, message, std::move(prepared), secp_context));
    if (signature.nonce().xonly != nonce_proof.nonce.xonly) {
        return unexpected_error(ErrorCode::InternalMismatch);
    }
    return typename Backend::ProvenSignature{signature, std::move(nonce_proof)};
}

template <typename Backend, typename CircuitLike>
Result<bool> verify_nonce_proof_with_circuit(const PublicKey<Backend>& public_key, const CircuitLike& circuit,
                                             const typename Backend::NonceProof& nonce_proof, Scope scope,
                                             purify_secp_context* secp_context,
                                             typename Backend::CircuitCache* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(
        validate_public_key_bundle(public_key.purify_pubkey, public_key.bip340_pubkey, secp_context));
    PURIFY_RETURN_IF_ERROR(validate_proof_circuit(circuit));
    PURIFY_ASSIGN_OR_RETURN(auto match, Backend::Ops::matches_nonce(nonce_proof, secp_context));
    if (!match) {
        return false;
    }
    const Bytes statement_binding = bytes_from_ascii(proof_tag<Backend>(scope));
    return Backend::Ops::verify(circuit, nonce_proof, statement_binding, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> verify_nonce_proof(const PublicKey<Backend>& public_key, Scope scope,
                                std::span<const unsigned char> input,
                                const typename Backend::NonceProof& nonce_proof,
                                purify_secp_context* secp_context,
                                typename Backend::CircuitCache* circuit_cache) {
    if (scope == Scope::Topic && input.empty()) {
        return unexpected_error(ErrorCode::EmptyInput);
    }
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            verifier_circuit(nonce_eval_input(scope, input), public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, scope, secp_context, circuit_cache);
}

template <typename Backend, typename Cache>
Result<bool> verify_cached_nonce_proof(const PublicKey<Backend>& public_key, const Cache& cache,
                                       const typename Backend::NonceProof& nonce_proof,
                                       purify_secp_context* secp_context,
                                       typename Backend::CircuitCache* circuit_cache) {
    PURIFY_RETURN_IF_ERROR(validate_proof_cache(cache));
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit,
                            Backend::Ops::instantiate(cache.circuit_template, public_key.purify_pubkey));
    return verify_nonce_proof_with_circuit(public_key, circuit, nonce_proof, scope_of(cache), secp_context,
                                           circuit_cache != nullptr ? circuit_cache : &cache.backend_cache);
}

/** Whether `signature` is valid for `message` and carries the nonce its proof is about. */
template <typename Backend>
Result<bool> signature_matches_proof(const PublicKey<Backend>& public_key,
                                     std::span<const unsigned char> message,
                                     const typename Backend::ProvenSignature& signature,
                                     purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto signature_ok, public_key.verify_signature(message, signature.signature, secp_context));
    return signature_ok && signature.signature.nonce().xonly == signature.nonce_proof.nonce.xonly;
}

}  // namespace purify::puresign_core::detail

namespace purify::puresign_core {

template <typename Backend>
Bytes PublicKey<Backend>::serialize() const {
    static_assert(kSerializedSize == detail::kPublicKeySerializedSize);
    return detail::serialize_public_key(purify_pubkey, bip340_pubkey);
}

template <typename Backend>
Result<PublicKey<Backend>> PublicKey<Backend>::deserialize(std::span<const unsigned char> serialized,
                                                           purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& parts, detail::deserialize_public_key(serialized, secp_context));
    return PublicKey{parts.purify_pubkey, parts.bip340_pubkey};
}

template <typename Backend>
Result<PublicKey<Backend>> PublicKey<Backend>::from_secret(const SecretKey& secret,
                                                           purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(const auto& parts, detail::derive_public_key(secret, secp_context));
    return PublicKey{parts.purify_pubkey, parts.bip340_pubkey};
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_signature(std::span<const unsigned char> message,
                                                  const Signature& signature,
                                                  purify_secp_context* secp_context) const {
    return detail::verify_bip340_signature(purify_pubkey, bip340_pubkey, message, signature, secp_context);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_message_nonce_proof(
    std::span<const unsigned char> message, const typename Backend::NonceProof& nonce_proof,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    return detail::verify_nonce_proof(*this, detail::Scope::Message, message, nonce_proof, secp_context,
                                      circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_message_nonce_proof(
    const MessageProofCache<Backend>& cache, const typename Backend::NonceProof& nonce_proof,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    return detail::verify_cached_nonce_proof(*this, cache, nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_topic_nonce_proof(
    std::span<const unsigned char> topic, const typename Backend::NonceProof& nonce_proof,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    return detail::verify_nonce_proof(*this, detail::Scope::Topic, topic, nonce_proof, secp_context,
                                      circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_topic_nonce_proof(
    const TopicProofCache<Backend>& cache, const typename Backend::NonceProof& nonce_proof,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    return detail::verify_cached_nonce_proof(*this, cache, nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_message_signature_with_proof(
    std::span<const unsigned char> message, const typename Backend::ProvenSignature& signature,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto matches, detail::signature_matches_proof(*this, message, signature, secp_context));
    if (!matches) {
        return false;
    }
    return verify_message_nonce_proof(message, signature.nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_message_signature_with_proof(
    const MessageProofCache<Backend>& cache, const typename Backend::ProvenSignature& signature,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto matches,
                            detail::signature_matches_proof(*this, cache.message, signature, secp_context));
    if (!matches) {
        return false;
    }
    return verify_message_nonce_proof(cache, signature.nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_topic_signature_with_proof(
    std::span<const unsigned char> message, std::span<const unsigned char> topic,
    const typename Backend::ProvenSignature& signature, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto matches, detail::signature_matches_proof(*this, message, signature, secp_context));
    if (!matches) {
        return false;
    }
    return verify_topic_nonce_proof(topic, signature.nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<bool> PublicKey<Backend>::verify_topic_signature_with_proof(
    const TopicProofCache<Backend>& cache, std::span<const unsigned char> message,
    const typename Backend::ProvenSignature& signature, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto matches, detail::signature_matches_proof(*this, message, signature, secp_context));
    if (!matches) {
        return false;
    }
    return verify_topic_nonce_proof(cache, signature.nonce_proof, secp_context, circuit_cache);
}

template <typename Backend>
Result<MessageProofCache<Backend>> MessageProofCache<Backend>::build(std::span<const unsigned char> message) {
    PURIFY_ASSIGN_OR_RETURN(auto parts, detail::build_proof_cache_parts(detail::Scope::Message, message));
    MessageProofCache cache{};
    cache.message = Bytes(message.begin(), message.end());
    cache.eval_input = std::move(parts.eval_input);
    cache.circuit_template = std::move(parts.circuit_template);
    cache.template_digest = std::move(parts.template_digest);
    return cache;
}

template <typename Backend>
Result<TopicProofCache<Backend>> TopicProofCache<Backend>::build(std::span<const unsigned char> topic) {
    PURIFY_ASSIGN_OR_RETURN(auto parts, detail::build_proof_cache_parts(detail::Scope::Topic, topic));
    TopicProofCache cache{};
    cache.topic = Bytes(topic.begin(), topic.end());
    cache.eval_input = std::move(parts.eval_input);
    cache.circuit_template = std::move(parts.circuit_template);
    cache.template_digest = std::move(parts.template_digest);
    return cache;
}

template <typename Backend>
PreparedNonceWithProof<Backend> PreparedNonceWithProof<Backend>::from_parts(PreparedNonce prepared,
                                                                            typename Backend::NonceProof proof) {
    return PreparedNonceWithProof(std::move(prepared), std::move(proof));
}

template <typename Backend>
Result<Scalar32> PreparedNonceWithProof<Backend>::raw_scalar() const
    requires(Backend::kProofBindsRawPoint)
{
    return Backend::Ops::raw_scalar(prepared_, proof_);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> PreparedNonceWithProof<Backend>::sign_message(
    const SecretKey& secret, std::span<const unsigned char> message, purify_secp_context* secp_context) && {
    return detail::sign_with_prepared_proof<Backend>(secret, detail::Scope::Message, message, std::move(prepared_),
                                                     std::move(proof_), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> PreparedNonceWithProof<Backend>::sign_topic_message(
    const SecretKey& secret, std::span<const unsigned char> message, purify_secp_context* secp_context) && {
    return detail::sign_with_prepared_proof<Backend>(secret, detail::Scope::Topic, message, std::move(prepared_),
                                                     std::move(proof_), secp_context);
}

template <typename Backend>
Result<KeyPair<Backend>> KeyPair<Backend>::from_secret(const SecretKey& secret,
                                                       purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto owned_secret, secret.clone());
    return KeyPair::from_secret(std::move(owned_secret), secp_context);
}

template <typename Backend>
Result<KeyPair<Backend>> KeyPair<Backend>::from_secret(SecretKey&& secret, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto public_key, PublicKey<Backend>::from_secret(secret, secp_context));
    return KeyPair(std::move(secret), std::move(public_key));
}

template <typename Backend>
Result<PreparedNonce> KeyPair<Backend>::prepare_message_nonce(std::span<const unsigned char> message,
                                                              purify_secp_context* secp_context) const {
    return detail::prepare_nonce(secret_, detail::Scope::Message, message, secp_context);
}

template <typename Backend>
Result<PreparedNonceWithProof<Backend>> KeyPair<Backend>::prepare_message_nonce_with_proof(
    std::span<const unsigned char> message, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    return detail::prepare_nonce_with_proof<Backend>(secret_, detail::Scope::Message, message, secp_context,
                                                     circuit_cache);
}

template <typename Backend>
Result<PreparedNonceWithProof<Backend>> KeyPair<Backend>::prepare_message_nonce_with_proof(
    const MessageProofCache<Backend>& cache, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    return detail::prepare_cached_nonce_with_proof<Backend>(secret_, cache, secp_context, circuit_cache);
}

template <typename Backend>
Result<PreparedNonce> KeyPair<Backend>::prepare_topic_nonce(std::span<const unsigned char> topic,
                                                            purify_secp_context* secp_context) const {
    return detail::prepare_nonce(secret_, detail::Scope::Topic, topic, secp_context);
}

template <typename Backend>
Result<PreparedNonceWithProof<Backend>> KeyPair<Backend>::prepare_topic_nonce_with_proof(
    std::span<const unsigned char> topic, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    return detail::prepare_nonce_with_proof<Backend>(secret_, detail::Scope::Topic, topic, secp_context,
                                                     circuit_cache);
}

template <typename Backend>
Result<PreparedNonceWithProof<Backend>> KeyPair<Backend>::prepare_topic_nonce_with_proof(
    const TopicProofCache<Backend>& cache, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    return detail::prepare_cached_nonce_with_proof<Backend>(secret_, cache, secp_context, circuit_cache);
}

template <typename Backend>
Result<Signature> KeyPair<Backend>::sign_message(std::span<const unsigned char> message,
                                                 purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce(message, secp_context));
    return sign_message_with_prepared(message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<Signature> KeyPair<Backend>::sign_message_with_prepared(std::span<const unsigned char> message,
                                                               PreparedNonce&& prepared,
                                                               purify_secp_context* secp_context) const {
    return detail::sign_with_prepared(secret_, detail::Scope::Message, message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_message_with_prepared_proof(
    std::span<const unsigned char> message, PreparedNonceWithProof<Backend>&& prepared,
    purify_secp_context* secp_context) const {
    return std::move(prepared).sign_message(secret_, message, secp_context);
}

template <typename Backend>
Result<Signature> KeyPair<Backend>::sign_with_topic(std::span<const unsigned char> message,
                                                    std::span<const unsigned char> topic,
                                                    purify_secp_context* secp_context) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce(topic, secp_context));
    return sign_with_prepared_topic(message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<Signature> KeyPair<Backend>::sign_with_prepared_topic(std::span<const unsigned char> message,
                                                             PreparedNonce&& prepared,
                                                             purify_secp_context* secp_context) const {
    return detail::sign_with_prepared(secret_, detail::Scope::Topic, message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_with_prepared_topic_proof(
    std::span<const unsigned char> message, PreparedNonceWithProof<Backend>&& prepared,
    purify_secp_context* secp_context) const {
    return std::move(prepared).sign_topic_message(secret_, message, secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_message_with_proof(
    std::span<const unsigned char> message, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(message, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_message_with_proof(
    const MessageProofCache<Backend>& cache, purify_secp_context* secp_context,
    typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_message_nonce_with_proof(cache, secp_context, circuit_cache));
    return sign_message_with_prepared_proof(cache.message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_with_topic_proof(
    std::span<const unsigned char> message, std::span<const unsigned char> topic,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(topic, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

template <typename Backend>
Result<typename Backend::ProvenSignature> KeyPair<Backend>::sign_with_topic_proof(
    std::span<const unsigned char> message, const TopicProofCache<Backend>& cache,
    purify_secp_context* secp_context, typename Backend::CircuitCache* circuit_cache) const {
    PURIFY_ASSIGN_OR_RETURN(auto prepared, prepare_topic_nonce_with_proof(cache, secp_context, circuit_cache));
    return sign_with_prepared_topic_proof(message, std::move(prepared), secp_context);
}

}  // namespace purify::puresign_core
