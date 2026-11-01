// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp.cpp
 * @brief C++ convenience wrappers over the low-level BPPP C bridge.
 */

#include "purify/bppp.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "bppp_bridge.h"
#include "algebraic_circuit_proof.hpp"
#include "bppp_internal.hpp"
#include "bulletproof_internal.hpp"
#include "purify/secp_bridge.h"

namespace purify::bppp {

struct BpppBackendResourcesDeleter {
  void operator()(purify_bppp_backend_resources *resources) const noexcept {
    purify_bppp_backend_resources_destroy(resources);
  }
};

using OwnedBpppBackendResources =
    std::unique_ptr<purify_bppp_backend_resources, BpppBackendResourcesDeleter>;

using GeneratorBackendCacheKey = std::array<unsigned char, 32>;

template <typename Digest>
std::size_t digest_prefix_hash(const Digest &digest) noexcept {
  static_assert(sizeof(std::size_t) <= std::tuple_size_v<Digest>,
                "digest prefix hash must fit within digest output");
  std::size_t out = 0;
  std::memcpy(&out, digest.data(), sizeof(std::size_t));
  return out;
}

struct GeneratorBackendCacheKeyHash {
  std::size_t operator()(const GeneratorBackendCacheKey &key) const noexcept {
    return digest_prefix_hash(key);
  }
};

using CircuitNormArgPublicDataCacheKey = std::array<unsigned char, 32>;
using CircuitNormArgPublicDataCacheKeyHash = GeneratorBackendCacheKeyHash;

GeneratorBackendCacheKey generator_backend_cache_key(
    std::span<const PointBytes> generators) {
  GeneratorBackendCacheKey key{};
  auto serialized_view = std::as_bytes(generators);
  const unsigned char *serialized =
      serialized_view.empty()
          ? nullptr
          : reinterpret_cast<const unsigned char *>(serialized_view.data());
  purify_sha256(key.data(), serialized, serialized_view.size());
  return key;
}

ExperimentalCircuitBackend::~ExperimentalCircuitBackend() = default;

std::shared_ptr<const void>
detail::ExperimentalCircuitBackendAccess::find_public_data(
    const ExperimentalCircuitBackend *backend,
    const std::array<unsigned char, 32> &key) {
  return backend != nullptr ? backend->find_public_data_impl(key)
                            : std::shared_ptr<const void>{};
}

void detail::ExperimentalCircuitBackendAccess::insert_public_data(
    ExperimentalCircuitBackend *backend, std::array<unsigned char, 32> key,
    std::shared_ptr<const void> value) {
  if (backend != nullptr) {
    backend->insert_public_data_impl(std::move(key), std::move(value));
  }
}

purify_bppp_backend_resources *
detail::ExperimentalCircuitBackendAccess::get_or_create_backend_resources(
    ExperimentalCircuitBackend *backend,
    std::span<const PointBytes> generators,
    purify_secp_context *secp_context) {
  return backend != nullptr
             ? backend->get_or_create_backend_resources_impl(generators,
                                                             secp_context)
             : nullptr;
}

struct ExperimentalCircuitCacheLine::Impl {
  GeneratorBackendCacheKey backend_key{};
  bool has_backend_key = false;
  OwnedBpppBackendResources backend_resources;
};

struct ExperimentalCircuitCache::Impl {
  std::unordered_map<CircuitNormArgPublicDataCacheKey,
                     std::shared_ptr<const void>,
                     CircuitNormArgPublicDataCacheKeyHash>
      public_data;
  std::unordered_map<GeneratorBackendCacheKey, OwnedBpppBackendResources,
                     GeneratorBackendCacheKeyHash>
      backend_resources;
};

ExperimentalCircuitCacheLine::ExperimentalCircuitCacheLine()
    : impl_(std::make_unique<Impl>()) {}

ExperimentalCircuitCacheLine::ExperimentalCircuitCacheLine(
    ExperimentalCircuitCacheLine &&other) noexcept = default;

ExperimentalCircuitCacheLine &ExperimentalCircuitCacheLine::operator=(
    ExperimentalCircuitCacheLine &&other) noexcept = default;

ExperimentalCircuitCacheLine::~ExperimentalCircuitCacheLine() = default;

bool ExperimentalCircuitCacheLine::empty() const noexcept {
  return impl_ == nullptr || impl_->backend_resources == nullptr;
}

std::shared_ptr<const void> ExperimentalCircuitCacheLine::find_public_data_impl(
    const std::array<unsigned char, 32> &key) const {
  (void)key;
  return {};
}

void ExperimentalCircuitCacheLine::insert_public_data_impl(
    std::array<unsigned char, 32> key, std::shared_ptr<const void> value) {
  (void)key;
  (void)value;
}

purify_bppp_backend_resources *
ExperimentalCircuitCacheLine::get_or_create_backend_resources_impl(
    std::span<const PointBytes> generators,
    purify_secp_context *secp_context) {
  (void)secp_context;
  if (impl_ == nullptr || impl_->backend_resources == nullptr ||
      generators.empty() || !impl_->has_backend_key) {
    return nullptr;
  }
  return generator_backend_cache_key(generators) == impl_->backend_key
             ? impl_->backend_resources.get()
             : nullptr;
}

ExperimentalCircuitCache::ExperimentalCircuitCache()
    : impl_(std::make_unique<Impl>()) {}

ExperimentalCircuitCache::ExperimentalCircuitCache(
    ExperimentalCircuitCache &&other) noexcept = default;

ExperimentalCircuitCache &ExperimentalCircuitCache::operator=(
    ExperimentalCircuitCache &&other) noexcept = default;

ExperimentalCircuitCache::~ExperimentalCircuitCache() = default;

void ExperimentalCircuitCache::clear() {
  if (impl_ != nullptr) {
    impl_->public_data.clear();
    impl_->backend_resources.clear();
  }
}

std::size_t ExperimentalCircuitCache::size() const noexcept {
  return impl_ != nullptr
             ? impl_->public_data.size() + impl_->backend_resources.size()
             : 0;
}

Result<ExperimentalCircuitCacheLine> ExperimentalCircuitCache::clone_line_for_thread(
    std::span<const PointBytes> generators) const {
  ExperimentalCircuitCacheLine clone;
  if (impl_ == nullptr || generators.empty()) {
    return clone;
  }

  const GeneratorBackendCacheKey key = generator_backend_cache_key(generators);
  auto it = impl_->backend_resources.find(key);
  if (it == impl_->backend_resources.end()) {
    return clone;
  }

  purify_bppp_backend_resources* cloned =
      purify_bppp_backend_resources_clone(it->second.get());
  if (cloned == nullptr) {
    return unexpected_error(
        ErrorCode::BackendRejectedInput,
        "ExperimentalCircuitCache::clone_line_for_thread:backend_resources");
  }
  clone.impl_->backend_key = key;
  clone.impl_->has_backend_key = true;
  clone.impl_->backend_resources.reset(cloned);
  return clone;
}

std::shared_ptr<const void> ExperimentalCircuitCache::find_public_data(
    const std::array<unsigned char, 32> &key) const {
  return find_public_data_impl(key);
}

void ExperimentalCircuitCache::insert_public_data(
    std::array<unsigned char, 32> key,
    std::shared_ptr<const void> value) {
  insert_public_data_impl(std::move(key), std::move(value));
}

purify_bppp_backend_resources *
ExperimentalCircuitCache::get_or_create_backend_resources(
    std::span<const PointBytes> generators,
    purify_secp_context *secp_context) {
  return get_or_create_backend_resources_impl(generators, secp_context);
}

std::shared_ptr<const void> ExperimentalCircuitCache::find_public_data_impl(
    const std::array<unsigned char, 32> &key) const {
  if (impl_ == nullptr) {
    return {};
  }
  auto it = impl_->public_data.find(key);
  if (it == impl_->public_data.end()) {
    return {};
  }
  return it->second;
}

void ExperimentalCircuitCache::insert_public_data_impl(
    std::array<unsigned char, 32> key,
    std::shared_ptr<const void> value) {
  if (impl_ == nullptr) {
    return;
  }
  impl_->public_data.emplace(std::move(key), std::move(value));
}

purify_bppp_backend_resources *
ExperimentalCircuitCache::get_or_create_backend_resources_impl(
    std::span<const PointBytes> generators,
    purify_secp_context *secp_context) {
  if (impl_ == nullptr || secp_context == nullptr || generators.empty()) {
    return nullptr;
  }

  auto serialized_view = std::as_bytes(generators);
  const unsigned char *serialized =
      serialized_view.empty()
          ? nullptr
          : reinterpret_cast<const unsigned char *>(serialized_view.data());

  GeneratorBackendCacheKey key = generator_backend_cache_key(generators);

  auto it = impl_->backend_resources.find(key);
  if (it != impl_->backend_resources.end()) {
    return it->second.get();
  }

  purify_bppp_backend_resources *created =
      purify_bppp_backend_resources_create(secp_context, serialized,
                                           generators.size());
  if (created == nullptr) {
    return nullptr;
  }

  auto inserted =
      impl_->backend_resources.emplace(key, OwnedBpppBackendResources(created));
  return inserted.first->second.get();
}

namespace {

struct SecretBytes {
  Bytes value;

  SecretBytes() = default;
  SecretBytes(const SecretBytes &) = delete;
  SecretBytes &operator=(const SecretBytes &) = delete;
  ~SecretBytes() {
    ::purify::detail::secure_clear_bytes(value.data(), value.size());
  }
};

struct SecretScalarBytes {
  ScalarBytes value{};

  SecretScalarBytes() = default;
  SecretScalarBytes(const SecretScalarBytes &) = delete;
  SecretScalarBytes &operator=(const SecretScalarBytes &) = delete;
  ~SecretScalarBytes() {
    ::purify::detail::secure_clear_bytes(value.data(), value.size());
  }
};

template <typename T> class WipeObjectOnDestruction {
public:
  explicit WipeObjectOnDestruction(T &value) noexcept : value_(&value) {
    static_assert(std::is_trivially_destructible_v<T>);
  }
  WipeObjectOnDestruction(const WipeObjectOnDestruction &) = delete;
  WipeObjectOnDestruction &
  operator=(const WipeObjectOnDestruction &) = delete;
  ~WipeObjectOnDestruction() {
    ::purify::detail::secure_clear_bytes(value_, sizeof(T));
  }

private:
  T *value_;
};

template <typename T> class WipeVectorOnDestruction {
public:
  explicit WipeVectorOnDestruction(std::vector<T> &value) noexcept
      : value_(&value) {
    static_assert(std::is_trivially_destructible_v<T>);
  }
  WipeVectorOnDestruction(const WipeVectorOnDestruction &) = delete;
  WipeVectorOnDestruction &
  operator=(const WipeVectorOnDestruction &) = delete;
  ~WipeVectorOnDestruction() {
    ::purify::detail::secure_clear_bytes(value_->data(),
                                         value_->size() * sizeof(T));
  }

private:
  std::vector<T> *value_;
};

void secure_clear_field_element(FieldElement &value) noexcept {
  static_assert(std::is_trivially_destructible_v<FieldElement>);
  ::purify::detail::secure_clear_bytes(&value, sizeof(value));
}

template <typename ByteArray> constexpr void assert_packed_byte_array_layout() {
  static_assert(
      std::is_same_v<typename ByteArray::value_type, unsigned char>,
      "byte-span bridge helpers require unsigned-char array elements");
  static_assert(
      std::is_trivially_copyable_v<ByteArray>,
      "byte-span bridge helpers require trivially copyable array wrappers");
  static_assert(
      std::is_standard_layout_v<ByteArray>,
      "byte-span bridge helpers require standard-layout array wrappers");
  static_assert(alignof(ByteArray) == alignof(unsigned char),
                "byte-span bridge helpers require byte-aligned array wrappers");
  static_assert(sizeof(ByteArray) == std::tuple_size_v<ByteArray>,
                "byte-span bridge helpers require tightly packed byte arrays "
                "with no padding");
}

template <typename ByteArray>
std::span<const unsigned char> byte_span(const std::vector<ByteArray> &values) {
  assert_packed_byte_array_layout<ByteArray>();
  auto bytes =
      std::as_bytes(std::span<const ByteArray>(values.data(), values.size()));
  return {reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size()};
}

template <typename ByteArray>
std::span<unsigned char> writable_byte_span(std::vector<ByteArray> &values) {
  assert_packed_byte_array_layout<ByteArray>();
  auto bytes = std::as_writable_bytes(
      std::span<ByteArray>(values.data(), values.size()));
  return {reinterpret_cast<unsigned char *>(bytes.data()), bytes.size()};
}

/** @brief Returns true when a bridge call signals success. */
bool require_ok(int ok) { return ok != 0; }

constexpr std::string_view kCircuitNormArgRhoTag =
    "Purify/BPPP/CircuitNormArgV3/Rho";
constexpr std::string_view kCircuitNormArgMulTag =
    "Purify/BPPP/CircuitNormArgV3/Mul";
constexpr std::string_view kCircuitNormArgConstraintTag =
    "Purify/BPPP/CircuitNormArgV3/Constraint";
constexpr std::string_view kCircuitNormArgPublicCommitmentTag =
    "Purify/BPPP/CircuitNormArgV3/PublicCommitments";
constexpr std::string_view kCircuitNormArgPrecommitTag =
    "Purify/BPPP/CircuitNormArgV3/Precommit";
constexpr std::string_view kCircuitZkBlindTag =
    "Purify/BPPP/CircuitNormArgV3/ZKBlind";
constexpr std::string_view kCircuitZkMaskNTag =
    "Purify/BPPP/CircuitNormArgV3/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLTag =
    "Purify/BPPP/CircuitNormArgV3/ZKMaskL";
constexpr std::string_view kCircuitZkChallengeTag =
    "Purify/BPPP/CircuitNormArgV3/ZKChallenge";
constexpr std::string_view kCircuitDlogBatchTag =
    "Purify/BPPP/CircuitNormArgV3/DLogBatch";
constexpr std::string_view kCircuitDlogNonceTag =
    "Purify/BPPP/CircuitNormArgV3/DLogNonce";
constexpr std::string_view kCircuitDlogChallengeTag =
    "Purify/BPPP/CircuitNormArgV3/DLogChallenge";
constexpr std::string_view kCircuitZkBlindV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKBlind";
constexpr std::string_view kCircuitZkMaskNV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/ZKMaskL";
constexpr std::string_view kCircuitDlogNonceV4Tag =
    "Purify/BPPP/CircuitNormArg/v4/DLogNonce";
const TaggedHash kCircuitNormArgRhoTaggedHash(kCircuitNormArgRhoTag);
const TaggedHash kCircuitNormArgMulTaggedHash(kCircuitNormArgMulTag);
const TaggedHash kCircuitNormArgConstraintTaggedHash(kCircuitNormArgConstraintTag);
const TaggedHash kCircuitNormArgPrecommitTaggedHash(kCircuitNormArgPrecommitTag);
const TaggedHash kCircuitZkBlindTaggedHash(kCircuitZkBlindTag);
const TaggedHash kCircuitZkMaskNTaggedHash(kCircuitZkMaskNTag);
const TaggedHash kCircuitZkMaskLTaggedHash(kCircuitZkMaskLTag);
const TaggedHash kCircuitZkChallengeTaggedHash(kCircuitZkChallengeTag);
const TaggedHash kCircuitDlogBatchTaggedHash(kCircuitDlogBatchTag);
const TaggedHash kCircuitDlogNonceTaggedHash(kCircuitDlogNonceTag);
const TaggedHash kCircuitDlogChallengeTaggedHash(kCircuitDlogChallengeTag);
const TaggedHash kCircuitZkBlindV4TaggedHash(kCircuitZkBlindV4Tag);
const TaggedHash kCircuitZkMaskNV4TaggedHash(kCircuitZkMaskNV4Tag);
const TaggedHash kCircuitZkMaskLV4TaggedHash(kCircuitZkMaskLV4Tag);
const TaggedHash kCircuitDlogNonceV4TaggedHash(kCircuitDlogNonceV4Tag);

struct ResolvedBpppGeneratorBackend {
  std::span<const unsigned char> serialized_bytes{};
  std::size_t generator_count = 0;
  purify_bppp_backend_resources *backend_resources = nullptr;
};

ResolvedBpppGeneratorBackend resolve_bppp_generator_backend(
    ExperimentalCircuitBackend *cache,
    const std::vector<PointBytes> &serialized_generators,
    purify_secp_context *secp_context) {
  ResolvedBpppGeneratorBackend out;
  out.serialized_bytes = byte_span(serialized_generators);
  out.generator_count = serialized_generators.size();

  if (cache == nullptr || serialized_generators.empty()) {
    return out;
  }
  out.backend_resources =
      detail::ExperimentalCircuitBackendAccess::get_or_create_backend_resources(
          cache, serialized_generators, secp_context);
  return out;
}

Result<std::size_t> round_up_power_of_two(std::size_t value,
                                          const char *context) {
  if (value == 0) {
    return unexpected_error(ErrorCode::Overflow, context);
  }
  std::size_t out = 1;
  while (out < value) {
    if (out > std::numeric_limits<std::size_t>::max() / 2) {
      return unexpected_error(ErrorCode::Overflow, context);
    }
    out <<= 1;
  }
  return out;
}

void append_u64_le(Bytes &out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
  }
}

Result<FieldElement> derive_nonzero_scalar(std::span<const unsigned char> seed,
                                           const TaggedHash& tag,
                                           std::size_t index) {
  Bytes prefix(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index,
                          narrow_size_to_u64(index,
                                             "derive_nonzero_scalar:index"),
                          "derive_nonzero_scalar:index");
  append_u64_le(prefix, encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Bytes input = prefix;
    append_u64_le(input, counter);
    ScalarBytes candidate_bytes{};
    candidate_bytes =
        tag.digest(std::span<const unsigned char>(input.data(), input.size()));
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes);
    if (candidate.has_value() && !candidate->is_zero()) {
      return candidate;
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch,
                          "derive_nonzero_scalar:exhausted");
}

Status derive_scalar(FieldElement &out, std::span<const unsigned char> seed,
                     const TaggedHash &tag, std::size_t index,
                     std::uint64_t attempt = 0) {
  SecretBytes prefix;
  prefix.value.reserve(seed.size() + 2 * sizeof(std::uint64_t));
  prefix.value.assign(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index,
                          narrow_size_to_u64(index, "derive_scalar:index"),
                          "derive_scalar:index");
  append_u64_le(prefix.value, encoded_index);
  append_u64_le(prefix.value, attempt);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    SecretBytes input;
    input.value.reserve(prefix.value.size() + sizeof(std::uint64_t));
    input.value.assign(prefix.value.begin(), prefix.value.end());
    append_u64_le(input.value, counter);
    SecretScalarBytes candidate_bytes;
    ScalarBytes digest = tag.digest(std::span<const unsigned char>(
        input.value.data(), input.value.size()));
    candidate_bytes.value = digest;
    ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes.value);
    if (candidate.has_value()) {
      out = *candidate;
      secure_clear_field_element(*candidate);
      return {};
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch,
                          "derive_scalar:exhausted");
}

Status derive_secret_nonzero_scalar(FieldElement &out,
                                    std::span<const unsigned char> seed,
                                    const TaggedHash &tag,
                                    std::size_t index) {
  SecretBytes prefix;
  prefix.value.reserve(seed.size() + sizeof(std::uint64_t));
  prefix.value.assign(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(
      const auto &encoded_index,
      narrow_size_to_u64(index, "derive_secret_nonzero_scalar:index"),
      "derive_secret_nonzero_scalar:index");
  append_u64_le(prefix.value, encoded_index);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    SecretBytes input;
    input.value.reserve(prefix.value.size() + sizeof(std::uint64_t));
    input.value.assign(prefix.value.begin(), prefix.value.end());
    append_u64_le(input.value, counter);
    SecretScalarBytes candidate_bytes;
    ScalarBytes digest = tag.digest(std::span<const unsigned char>(
        input.value.data(), input.value.size()));
    candidate_bytes.value = digest;
    ::purify::detail::secure_clear_bytes(digest.data(), digest.size());
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes.value);
    if (candidate.has_value()) {
      if (!candidate->is_zero()) {
        out = *candidate;
        secure_clear_field_element(*candidate);
        return {};
      }
      secure_clear_field_element(*candidate);
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch,
                          "derive_secret_nonzero_scalar:exhausted");
}

FieldElement weighted_bppp_inner_product(std::span<const FieldElement> lhs,
                                         std::span<const FieldElement> rhs,
                                         const FieldElement &rho) {
  assert(lhs.size() == rhs.size() &&
         "weighted_bppp_inner_product requires matching vector lengths");
  FieldElement mu = rho * rho;
  FieldElement weight = mu;
  FieldElement total = FieldElement::zero();
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    total = total + (weight * lhs[i] * rhs[i]);
    weight = weight * mu;
  }
  return total;
}

struct CircuitNormArgPublicData {
  FieldElement rho = FieldElement::zero();
  FieldElement mul_scale = FieldElement::zero();
  FieldElement mul_ratio = FieldElement::zero();
  ScalarBytes rho_bytes{};
  FieldElement target = FieldElement::zero();
  Bytes challenge_digest;
  std::vector<PointBytes> generators;
  std::vector<PointBytes> raw_generators;
  std::vector<PointBytes> raw_generator_points;
  std::vector<FieldElement> c_vec;
  std::vector<ScalarBytes> c_vec_bytes;
  std::vector<FieldElement> public_commitment_coeffs;
  std::vector<FieldElement> plus_shift;
  std::vector<FieldElement> minus_shift;
  std::vector<FieldElement> plus_terms;
  std::vector<FieldElement> minus_terms;
  std::size_t n_vec_len = 0;
  std::size_t used_l = 0;
};

using CircuitNormArgPublicDataPtr =
    std::shared_ptr<const CircuitNormArgPublicData>;

struct CircuitNormArgReduction {
  CircuitNormArgPublicDataPtr public_data;
  std::vector<FieldElement> n_vec;
  std::vector<FieldElement> l_vec;
};

struct CircuitNormArgChallenges {
  FieldElement rho;
  FieldElement mul_scale;
  FieldElement mul_ratio;
  FieldElement row_ratio;
};

Result<PointBytes> point_scale(const PointBytes &point,
                               const FieldElement &scalar,
                               purify_secp_context *secp_context);
Result<PointBytes> generator_scale(const PointBytes &generator,
                                   const FieldElement &scalar,
                                   purify_secp_context *secp_context);
Result<PointBytes> generator_to_point(const PointBytes &generator,
                                      purify_secp_context *secp_context);
Result<PointBytes>
commit_norm_arg_witness_only(const NormArgInputs &inputs,
                             purify_secp_context *secp_context,
                             ExperimentalCircuitBackend *cache);

Result<Bytes> circuit_norm_arg_precommit_digest(
    std::span<const unsigned char> binding_digest,
    const PointBytes &raw_commitment) {
  Bytes seed(binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), raw_commitment.begin(), raw_commitment.end());
  const ScalarBytes digest = kCircuitNormArgPrecommitTaggedHash.digest(seed);
  return Bytes(digest.begin(), digest.end());
}

struct CircuitNormArgDimensions {
  std::size_t gate_count = 0;
  std::size_t n_vec_len = 0;
  std::size_t l_vec_len = 0;
  std::size_t used_l = 0;
};

Result<CircuitNormArgDimensions> circuit_norm_arg_dimensions(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments) {
  CircuitNormArgDimensions out;
  const std::size_t committed_values =
      externalize_commitments ? 0 : circuit.n_commitments;
  std::size_t minimum_gate_count = 0;
  if (!checked_add_size(committed_values, 1, minimum_gate_count)) {
    return unexpected_error(ErrorCode::Overflow,
                            "circuit_norm_arg_dimensions:minimum_gate_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      out.gate_count,
      round_up_power_of_two(std::max(circuit.n_gates, minimum_gate_count),
                            "circuit_norm_arg_dimensions:gate_count"),
      "circuit_norm_arg_dimensions:gate_count");
  if (!checked_add_size(out.gate_count, committed_values, out.used_l)) {
    return unexpected_error(ErrorCode::Overflow,
                            "circuit_norm_arg_dimensions:used_l");
  }
  if (!checked_mul_size(out.gate_count, 2, out.n_vec_len)) {
    return unexpected_error(ErrorCode::Overflow,
                            "circuit_norm_arg_dimensions:n_vec_len");
  }
  out.l_vec_len = out.n_vec_len;
  assert(out.used_l < out.l_vec_len &&
         "virtual gate padding must leave a hiding coordinate");
  return out;
}

Result<NormArgInputs> build_raw_circuit_norm_arg_inputs(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    std::span<const FieldElement> padding,
    bool externalize_commitments,
    purify_secp_context *secp_context) {
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "build_raw_circuit_norm_arg_inputs:assignment_shape");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments),
      "build_raw_circuit_norm_arg_inputs:dimensions");
  const std::size_t padding_size = dimensions.l_vec_len - dimensions.used_l;
  if (!padding.empty() && padding.size() != padding_size) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "build_raw_circuit_norm_arg_inputs:padding_size");
  }

  std::size_t generator_count = 0;
  if (!checked_add_size(dimensions.n_vec_len, dimensions.l_vec_len,
                        generator_count)) {
    return unexpected_error(ErrorCode::Overflow,
                            "build_raw_circuit_norm_arg_inputs:generator_count");
  }

  NormArgInputs out;
  PURIFY_ASSIGN_OR_RETURN(
      out.generators, create_generators(generator_count, secp_context),
      "build_raw_circuit_norm_arg_inputs:create_generators");
  std::vector<FieldElement> raw_n(dimensions.n_vec_len,
                                  FieldElement::zero());
  std::vector<FieldElement> raw_l(dimensions.l_vec_len,
                                  FieldElement::zero());
  WipeVectorOnDestruction raw_n_wiper(raw_n);
  WipeVectorOnDestruction raw_l_wiper(raw_l);
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    raw_n[2 * i] = assignment.left[i] + assignment.right[i];
    raw_n[2 * i + 1] = assignment.left[i] - assignment.right[i];
    raw_l[i] = assignment.output[i];
  }
  if (!externalize_commitments) {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      raw_l[dimensions.gate_count + i] = assignment.commitments[i];
    }
  }
  if (!padding.empty()) {
    std::copy(padding.begin(), padding.end(),
              raw_l.begin() + dimensions.used_l);
  }
  out.n_vec = scalar_bytes(raw_n);
  out.l_vec = scalar_bytes(raw_l);
  return out;
}

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data_impl(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes *raw_commitment,
    purify_secp_context *secp_context,
    bool externalize_commitments = false,
    ExperimentalCircuitBackend *cache = nullptr,
    const CircuitNormArgChallenges *explicit_challenges = nullptr) {
  (void)cache;
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "build_circuit_norm_arg_public_data:secp_context"),
      "build_circuit_norm_arg_public_data:secp_context");
  if (!circuit.has_valid_shape()) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "build_circuit_norm_arg_public_data:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "build_circuit_norm_arg_public_data:n_gates_power_of_two");
  }

  Bytes challenge_digest;
  FieldElement rho = FieldElement::zero();
  FieldElement mul_scale = FieldElement::zero();
  FieldElement mul_ratio = FieldElement::zero();
  FieldElement row_ratio = FieldElement::zero();
  if (explicit_challenges != nullptr) {
    rho = explicit_challenges->rho;
    mul_scale = explicit_challenges->mul_scale;
    mul_ratio = explicit_challenges->mul_ratio;
    row_ratio = explicit_challenges->row_ratio;
  } else {
    if (raw_commitment == nullptr) {
      return unexpected_error(
          ErrorCode::InternalMismatch,
          "build_circuit_norm_arg_public_data:raw_commitment");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &binding_digest,
        experimental_circuit_binding_digest(circuit, statement_binding),
        "build_circuit_norm_arg_public_data:binding_digest");
    PURIFY_ASSIGN_OR_RETURN(
        challenge_digest,
        circuit_norm_arg_precommit_digest(binding_digest, *raw_commitment),
        "build_circuit_norm_arg_public_data:challenge_digest");
    PURIFY_ASSIGN_OR_RETURN(
        rho,
        derive_nonzero_scalar(challenge_digest, kCircuitNormArgRhoTaggedHash,
                              0),
        "build_circuit_norm_arg_public_data:rho");
    PURIFY_ASSIGN_OR_RETURN(
        mul_scale,
        derive_nonzero_scalar(challenge_digest, kCircuitNormArgMulTaggedHash,
                              0),
        "build_circuit_norm_arg_public_data:mul_scale");
    PURIFY_ASSIGN_OR_RETURN(
        mul_ratio,
        derive_nonzero_scalar(challenge_digest, kCircuitNormArgMulTaggedHash,
                              1),
        "build_circuit_norm_arg_public_data:mul_ratio");
    if (!circuit.c.empty()) {
      PURIFY_ASSIGN_OR_RETURN(
          row_ratio,
          derive_nonzero_scalar(challenge_digest,
                                kCircuitNormArgConstraintTaggedHash, 0),
          "build_circuit_norm_arg_public_data:constraint_ratio");
    }
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments),
      "build_circuit_norm_arg_public_data:dimensions");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &sqrt_minus_one, detail::canonical_sqrt_minus_one(),
      "build_circuit_norm_arg_public_data:sqrt_minus_one");

  const FieldElement zero = FieldElement::zero();
  const FieldElement two = FieldElement::from_int(2);
  const FieldElement four = FieldElement::from_int(4);
  const FieldElement inv2 = two.inverse();

  std::vector<FieldElement> mul_weights(dimensions.gate_count, zero);
  std::vector<FieldElement> plus_terms(dimensions.gate_count, zero);
  std::vector<FieldElement> minus_terms(dimensions.gate_count, zero);
  FieldElement mul_term = mul_scale;
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    plus_terms[i] = mul_term;
    minus_terms[i] = sqrt_minus_one * mul_term;
    mul_weights[i] = four * mul_term * mul_term;
    mul_term = mul_term * mul_ratio;
  }

  std::vector<FieldElement> row_weights(circuit.c.size(), zero);
  if (!row_weights.empty()) {
    FieldElement row_weight = row_ratio;
    for (FieldElement &weight : row_weights) {
      weight = row_weight;
      row_weight = row_weight * row_ratio;
    }
  }

  std::vector<FieldElement> left_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> right_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> output_coeffs(dimensions.gate_count, zero);
  std::vector<FieldElement> commitment_coeffs(circuit.n_commitments, zero);
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    output_coeffs[i] = mul_weights[i].negate();
  }

  FieldElement constant = zero;
  for (std::size_t j = 0; j < circuit.c.size(); ++j) {
    constant = constant - (row_weights[j] * circuit.c[j]);
  }

  auto accumulate_coeffs =
      [&](const std::vector<NativeBulletproofCircuitRow> &rows,
          std::vector<FieldElement> &coeffs, bool negate_entries) {
        for (std::size_t i = 0; i < rows.size(); ++i) {
          for (const NativeBulletproofCircuitTerm &entry : rows[i].entries) {
            const FieldElement scalar =
                negate_entries ? entry.scalar.negate() : entry.scalar;
            coeffs[i] = coeffs[i] + (row_weights[entry.idx] * scalar);
          }
        }
      };
  accumulate_coeffs(circuit.wl, left_coeffs, false);
  accumulate_coeffs(circuit.wr, right_coeffs, false);
  accumulate_coeffs(circuit.wo, output_coeffs, false);
  accumulate_coeffs(circuit.wv, commitment_coeffs, true);

  auto out = std::make_shared<CircuitNormArgPublicData>();
  out->rho = rho;
  out->rho_bytes = scalar_bytes(rho);
  out->mul_scale = mul_scale;
  out->mul_ratio = mul_ratio;
  out->challenge_digest = challenge_digest;
  out->plus_terms = std::move(plus_terms);
  out->minus_terms = std::move(minus_terms);
  out->plus_shift.resize(dimensions.gate_count, zero);
  out->minus_shift.resize(dimensions.gate_count, zero);

  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    const FieldElement d_plus = out->plus_terms[i] * out->plus_terms[i];
    const FieldElement d_minus = d_plus.negate();
    const FieldElement e_plus = (left_coeffs[i] + right_coeffs[i]) * inv2;
    const FieldElement e_minus = (left_coeffs[i] - right_coeffs[i]) * inv2;

    out->plus_shift[i] = e_plus * (two * d_plus).inverse();
    out->minus_shift[i] = e_minus * (two * d_minus).inverse();
    constant = constant - ((e_plus * e_plus) * (four * d_plus).inverse());
    constant = constant - ((e_minus * e_minus) * (four * d_minus).inverse());
  }

  out->used_l = dimensions.used_l;
  out->n_vec_len = dimensions.n_vec_len;
  out->c_vec.assign(dimensions.l_vec_len, zero);
  for (std::size_t i = 0; i < dimensions.gate_count; ++i) {
    out->c_vec[i] = output_coeffs[i];
  }
  if (externalize_commitments) {
    out->public_commitment_coeffs = std::move(commitment_coeffs);
  } else {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out->c_vec[dimensions.gate_count + i] = commitment_coeffs[i];
    }
  }
  out->target = constant.negate();
  out->c_vec_bytes = scalar_bytes(out->c_vec);

  std::size_t raw_n_value_count = 0;
  if (!checked_mul_size(dimensions.gate_count, 2, raw_n_value_count)) {
    return unexpected_error(ErrorCode::Overflow,
                            "build_circuit_norm_arg_public_data:raw_n_value_count");
  }
  std::size_t generator_count = 0;
  if (!checked_add_size(out->n_vec_len, out->c_vec.size(),
                        generator_count)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "build_circuit_norm_arg_public_data:generator_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto generators, create_generators(generator_count, secp_context),
      "build_circuit_norm_arg_public_data:create_generators");
  out->raw_generators = generators;
  out->generators = std::move(generators);
  out->raw_generator_points.reserve(raw_n_value_count);
  for (std::size_t i = 0; i < raw_n_value_count; ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        auto point, generator_to_point(out->raw_generators[i], secp_context),
        "build_circuit_norm_arg_public_data:generator_to_point");
    out->raw_generator_points.push_back(point);
  }

  FieldElement rho_power = rho;
  FieldElement generator_term = mul_scale;
  for (std::size_t i = 0; i < out->n_vec_len; ++i) {
    const FieldElement term =
        (i % 2 == 0) ? generator_term : sqrt_minus_one * generator_term;
    PURIFY_ASSIGN_OR_RETURN(
        out->generators[i],
        generator_scale(out->raw_generators[i],
                        rho_power * term.inverse(), secp_context),
        "build_circuit_norm_arg_public_data:scale_generator");
    if (i % 2 == 1) {
      generator_term = generator_term * mul_ratio;
    }
    rho_power = rho_power * rho;
  }
  CircuitNormArgPublicDataPtr shared = out;
  return shared;
}

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    bool externalize_commitments = false,
    ExperimentalCircuitBackend *cache = nullptr,
    const CircuitNormArgChallenges *explicit_challenges = nullptr) {
  return build_circuit_norm_arg_public_data_impl(
      circuit, statement_binding, &raw_commitment, secp_context,
      externalize_commitments, cache, explicit_challenges);
}

Result<CircuitNormArgPublicDataPtr>
build_circuit_norm_arg_public_data_from_challenges(
    const NativeBulletproofCircuit &circuit,
    purify_secp_context *secp_context, bool externalize_commitments,
    ExperimentalCircuitBackend *cache,
    const CircuitNormArgChallenges &explicit_challenges) {
  return build_circuit_norm_arg_public_data_impl(
      circuit, {}, nullptr, secp_context, externalize_commitments, cache,
      &explicit_challenges);
}

Result<CircuitNormArgReduction> reduce_experimental_circuit_to_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &raw_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments = false,
    ExperimentalCircuitBackend *cache = nullptr,
    const CircuitNormArgChallenges *explicit_challenges = nullptr) {
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "reduce_experimental_circuit_to_norm_arg:assignment_shape");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(circuit, statement_binding,
                                         raw_commitment, secp_context,
                                         externalize_commitments, cache,
                                         explicit_challenges),
      "reduce_experimental_circuit_to_norm_arg:public_data");

  CircuitNormArgReduction out;
  out.public_data = public_data;
  out.n_vec.assign(out.public_data->n_vec_len, FieldElement::zero());
  out.l_vec.assign(out.public_data->c_vec.size(), FieldElement::zero());

  const FieldElement rho_inv = out.public_data->rho.inverse();
  FieldElement rho_weight_inv = rho_inv;
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    FieldElement plus_value = assignment.left[i] + assignment.right[i] +
                              out.public_data->plus_shift[i];
    WipeObjectOnDestruction plus_value_wiper(plus_value);
    out.n_vec[2 * i] =
        out.public_data->plus_terms[i] * plus_value * rho_weight_inv;
    rho_weight_inv = rho_weight_inv * rho_inv;

    FieldElement minus_value = assignment.left[i] - assignment.right[i] +
                               out.public_data->minus_shift[i];
    WipeObjectOnDestruction minus_value_wiper(minus_value);
    out.n_vec[2 * i + 1] =
        out.public_data->minus_terms[i] * minus_value * rho_weight_inv;
    rho_weight_inv = rho_weight_inv * rho_inv;

    out.l_vec[i] = assignment.output[i];
  }
  if (!externalize_commitments) {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out.l_vec[out.public_data->plus_terms.size() + i] =
          assignment.commitments[i];
    }
  }
  return out;
}

NormArgInputs build_norm_arg_inputs(const CircuitNormArgReduction &reduction) {
  NormArgInputs inputs;
  inputs.rho = reduction.public_data->rho_bytes;
  inputs.generators = reduction.public_data->generators;
  inputs.n_vec = scalar_bytes(reduction.n_vec);
  inputs.l_vec = scalar_bytes(reduction.l_vec);
  inputs.c_vec = reduction.public_data->c_vec_bytes;
  return inputs;
}

Result<PointBytes>
commit_norm_arg_witness_only(const NormArgInputs &inputs,
                             purify_secp_context *secp_context,
                             ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "commit_norm_arg_witness_only:secp_context"),
      "commit_norm_arg_witness_only:secp_context");
  if (inputs.n_vec.empty() || inputs.l_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "commit_norm_arg_witness_only:empty_vectors");
  }
  if (!inputs.generators.empty() &&
      inputs.generators.size() != inputs.n_vec.size() + inputs.l_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "commit_norm_arg_witness_only:generator_size");
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated, create_generators(inputs.n_vec.size() + inputs.l_vec.size(), secp_context),
        "commit_norm_arg_witness_only:create_generators");
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  PointBytes commitment{};
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_commit_witness_only_with_resources(
                resolved.backend_resources, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), commitment.data())
          : purify_bppp_commit_witness_only(
                secp_context, resolved.serialized_bytes.data(),
                resolved.generator_count,
                n_vec.data(), inputs.n_vec.size(), l_vec.data(),
                inputs.l_vec.size(), commitment.data());
  if (!require_ok(ok)) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "commit_norm_arg_witness_only:backend");
  }
  return commitment;
}

Result<PointBytes> offset_commitment(const PointBytes &commitment,
                                     const FieldElement &scalar,
                                     purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "offset_commitment:secp_context"),
                         "offset_commitment:secp_context");
  if (!require_ok(purify_bppp_offset_commitment(secp_context, commitment.data(),
                                                scalar32.value.data(),
                                                out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "offset_commitment:backend");
  }
  return out;
}

Result<PointBytes> point_scale(const PointBytes &point,
                               const FieldElement &scalar,
                               purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "point_scale:secp_context"),
                         "point_scale:secp_context");
  if (!require_ok(
          purify_point_scale(secp_context, point.data(),
                             scalar32.value.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "point_scale:backend");
  }
  return out;
}

Result<PointBytes> generator_scale(const PointBytes &generator,
                                   const FieldElement &scalar,
                                   purify_secp_context *secp_context) {
  PointBytes out{};
  SecretScalarBytes scalar32;
  purify_scalar_get_b32(
      scalar32.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "generator_scale:secp_context"),
      "generator_scale:secp_context");
  if (!require_ok(purify_bppp_scale_generator(
          secp_context, generator.data(), scalar32.value.data(),
          out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "generator_scale:backend");
  }
  return out;
}

Result<PointBytes> generator_to_point(const PointBytes &generator,
                                      purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "generator_to_point:secp_context"),
      "generator_to_point:secp_context");
  if (!require_ok(purify_bppp_generator_to_point(
          secp_context, generator.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "generator_to_point:backend");
  }
  return out;
}

Result<PointBytes> point_add(const PointBytes &lhs,
                             const PointBytes &rhs,
                             purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "point_add:secp_context"),
                         "point_add:secp_context");
  if (!require_ok(
          purify_point_add(secp_context, lhs.data(), rhs.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "point_add:backend");
  }
  return out;
}

Result<PointBytes> point_add_allow_infinity(
    const PointBytes &lhs, const PointBytes &rhs,
    purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context,
                           "point_add_allow_infinity:secp_context"),
      "point_add_allow_infinity:secp_context");
  if (!require_ok(purify_point_add_allow_infinity(
          secp_context, lhs.data(), rhs.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "point_add_allow_infinity:backend");
  }
  return out;
}

Result<PointBytes> point_subtract_allow_infinity(
    const PointBytes &lhs, const PointBytes &rhs,
    purify_secp_context *secp_context) {
  PointBytes out{};
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context,
                           "point_subtract_allow_infinity:secp_context"),
      "point_subtract_allow_infinity:secp_context");
  if (!require_ok(purify_point_subtract_allow_infinity(
          secp_context, lhs.data(), rhs.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "point_subtract_allow_infinity:backend");
  }
  return out;
}

Result<PointBytes> point_from_scalar_base(const FieldElement &scalar,
                                          purify_secp_context *secp_context) {
  ScalarBytes blind{};
  SecretScalarBytes value;
  purify_scalar_get_b32(
      value.value.data(),
      &::purify::detail::FieldElementAccess::raw(scalar));
  return pedersen_commit_char(blind, value.value, secp_context,
                              base_generator(secp_context),
                              base_generator(secp_context));
}

struct BatchedPublicCommitment {
  PointBytes point{};
  std::vector<FieldElement> weights;
};

Result<BatchedPublicCommitment> batch_public_commitments_with_eta(
    std::span<const PointBytes> public_commitments,
    const FieldElement &eta,
    purify_secp_context *secp_context) {
  if (public_commitments.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "batch_public_commitments:empty");
  }

  BatchedPublicCommitment out;
  out.point = public_commitments.front();
  out.weights.reserve(public_commitments.size());
  out.weights.push_back(FieldElement::one());
  FieldElement weight = eta;
  for (std::size_t i = 1; i < public_commitments.size(); ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &scaled,
        point_scale(public_commitments[i], weight, secp_context),
        "batch_public_commitments:scale");
    PURIFY_ASSIGN_OR_RETURN(
        out.point, point_add(out.point, scaled, secp_context),
        "batch_public_commitments:add");
    out.weights.push_back(weight);
    weight = weight * eta;
  }
  return out;
}

Result<BatchedPublicCommitment> batch_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> challenge_digest,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &eta,
      derive_nonzero_scalar(challenge_digest, kCircuitDlogBatchTaggedHash, 0),
      "batch_public_commitments:eta");
  return batch_public_commitments_with_eta(public_commitments, eta,
                                           secp_context);
}

Result<FieldElement> dlog_challenge(
    std::span<const unsigned char> challenge_digest,
    const PointBytes &batched_commitment,
    const std::array<unsigned char, 32> &nonce_xonly) {
  Bytes seed(challenge_digest.begin(), challenge_digest.end());
  seed.insert(seed.end(), batched_commitment.begin(), batched_commitment.end());
  seed.insert(seed.end(), nonce_xonly.begin(), nonce_xonly.end());
  return derive_nonzero_scalar(seed, kCircuitDlogChallengeTaggedHash, 0);
}

struct PublicCommitmentDlogProof {
  std::array<unsigned char, 32> nonce_xonly{};
  ScalarBytes response{};
};

Result<PublicCommitmentDlogProof> prove_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const FieldElement> commitment_values,
    std::span<const unsigned char> challenge_digest,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context) {
  if (batched.weights.size() != commitment_values.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "prove_public_commitment_dlog:values");
  }
  FieldElement value = FieldElement::zero();
  WipeObjectOnDestruction value_wiper(value);
  for (std::size_t i = 0; i < commitment_values.size(); ++i) {
    FieldElement term = batched.weights[i] * commitment_values[i];
    WipeObjectOnDestruction term_wiper(term);
    FieldElement next = value + term;
    WipeObjectOnDestruction next_wiper(next);
    value = next;
  }

  SecretScalarBytes value_bytes;
  purify_scalar_get_b32(
      value_bytes.value.data(),
      &::purify::detail::FieldElementAccess::raw(value));
  SecretBytes nonce_seed;
  nonce_seed.value.reserve(secret_prover_seed.size() + value_bytes.value.size() +
                           challenge_digest.size());
  nonce_seed.value.insert(nonce_seed.value.end(), secret_prover_seed.begin(),
                          secret_prover_seed.end());
  nonce_seed.value.insert(nonce_seed.value.end(), value_bytes.value.begin(),
                          value_bytes.value.end());
  nonce_seed.value.insert(nonce_seed.value.end(), challenge_digest.begin(),
                          challenge_digest.end());
  FieldElement nonce = FieldElement::zero();
  WipeObjectOnDestruction nonce_wiper(nonce);
  PURIFY_RETURN_IF_ERROR(
      derive_secret_nonzero_scalar(nonce, nonce_seed.value,
                                   kCircuitDlogNonceTaggedHash, 0),
      "prove_public_commitment_dlog:nonce");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &nonce_point, point_from_scalar_base(nonce, secp_context),
      "prove_public_commitment_dlog:nonce_point");

  PublicCommitmentDlogProof out;
  int parity = 0;
  if (purify_bip340_xonly_from_point(
          secp_context, nonce_point.data(), out.nonce_xonly.data(), &parity) ==
      0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_public_commitment_dlog:nonce_xonly");
  }
  FieldElement negated_nonce = nonce.negate();
  WipeObjectOnDestruction negated_nonce_wiper(negated_nonce);
  nonce.conditional_assign(negated_nonce, parity != 0);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      dlog_challenge(challenge_digest, batched.point, out.nonce_xonly),
      "prove_public_commitment_dlog:challenge");
  FieldElement challenge_value = challenge * value;
  WipeObjectOnDestruction challenge_value_wiper(challenge_value);
  const FieldElement response = nonce + challenge_value;
  if (response.is_zero()) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_public_commitment_dlog:zero_response");
  }
  out.response = scalar_bytes(response);
  return out;
}

template <typename ChallengeCallback>
Result<PublicCommitmentDlogProof> prove_public_commitment_dlog_v4(
    const BatchedPublicCommitment &batched,
    std::span<const FieldElement> commitment_values,
    std::span<const unsigned char> nonce_binding,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    ChallengeCallback &&challenge_callback) {
  if (batched.weights.size() != commitment_values.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "prove_public_commitment_dlog_v4:values");
  }
  FieldElement value = FieldElement::zero();
  WipeObjectOnDestruction value_wiper(value);
  for (std::size_t i = 0; i < commitment_values.size(); ++i) {
    FieldElement term = batched.weights[i] * commitment_values[i];
    WipeObjectOnDestruction term_wiper(term);
    FieldElement next = value + term;
    WipeObjectOnDestruction next_wiper(next);
    value = next;
  }

  SecretScalarBytes value_bytes;
  purify_scalar_get_b32(
      value_bytes.value.data(),
      &::purify::detail::FieldElementAccess::raw(value));
  SecretBytes nonce_seed;
  nonce_seed.value.reserve(secret_prover_seed.size() +
                           value_bytes.value.size() + nonce_binding.size());
  nonce_seed.value.insert(nonce_seed.value.end(), secret_prover_seed.begin(),
                          secret_prover_seed.end());
  nonce_seed.value.insert(nonce_seed.value.end(), value_bytes.value.begin(),
                          value_bytes.value.end());
  nonce_seed.value.insert(nonce_seed.value.end(), nonce_binding.begin(),
                          nonce_binding.end());
  FieldElement nonce = FieldElement::zero();
  WipeObjectOnDestruction nonce_wiper(nonce);
  PURIFY_RETURN_IF_ERROR(
      derive_secret_nonzero_scalar(nonce, nonce_seed.value,
                                   kCircuitDlogNonceV4TaggedHash, 0),
      "prove_public_commitment_dlog_v4:nonce");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &nonce_point, point_from_scalar_base(nonce, secp_context),
      "prove_public_commitment_dlog_v4:nonce_point");

  PublicCommitmentDlogProof out;
  int parity = 0;
  if (purify_bip340_xonly_from_point(
          secp_context, nonce_point.data(), out.nonce_xonly.data(), &parity) ==
      0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_public_commitment_dlog_v4:nonce_xonly");
  }
  FieldElement negated_nonce = nonce.negate();
  WipeObjectOnDestruction negated_nonce_wiper(negated_nonce);
  nonce.conditional_assign(negated_nonce, parity != 0);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge, challenge_callback(out.nonce_xonly),
      "prove_public_commitment_dlog_v4:challenge");
  FieldElement challenge_value = challenge * value;
  WipeObjectOnDestruction challenge_value_wiper(challenge_value);
  const FieldElement response = nonce + challenge_value;
  if (response.is_zero()) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_public_commitment_dlog_v4:zero_response");
  }
  out.response = scalar_bytes(response);
  return out;
}

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    const FieldElement &challenge,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &response, FieldElement::try_from_bytes32(proof.response),
      "verify_public_commitment_dlog:response");
  if (response.is_zero()) {
    return false;
  }
  PointBytes nonce_point{};
  nonce_point[0] = 0x02;
  std::copy(proof.nonce_xonly.begin(), proof.nonce_xonly.end(),
            nonce_point.begin() + 1);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &lhs, point_from_scalar_base(response, secp_context),
      "verify_public_commitment_dlog:lhs");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &scaled_commitment,
      point_scale(batched.point, challenge, secp_context),
      "verify_public_commitment_dlog:scale_commitment");
  Result<PointBytes> rhs =
      point_add(nonce_point, scaled_commitment, secp_context);
  return rhs.has_value() && lhs == *rhs;
}

Result<bool> verify_public_commitment_dlog(
    const BatchedPublicCommitment &batched,
    std::span<const unsigned char> challenge_digest,
    const PublicCommitmentDlogProof &proof,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      dlog_challenge(challenge_digest, batched.point, proof.nonce_xonly),
      "verify_public_commitment_dlog:challenge");
  return verify_public_commitment_dlog(batched, challenge, proof,
                                       secp_context);
}

Result<Bytes> bind_public_commitments(
    std::span<const PointBytes> public_commitments,
    std::span<const unsigned char> statement_binding) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &encoded_commitment_count,
      narrow_size_to_u64(public_commitments.size(),
                         "bind_public_commitments:count"),
      "bind_public_commitments:count");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &encoded_binding_size,
      narrow_size_to_u64(statement_binding.size(),
                         "bind_public_commitments:statement_binding"),
      "bind_public_commitments:statement_binding");

  std::size_t point_bytes = 0;
  std::size_t total_size = 0;
  Bytes out = bytes_from_ascii(kCircuitNormArgPublicCommitmentTag);
  if (!checked_mul_size(public_commitments.size(), sizeof(PointBytes),
                        point_bytes) ||
      !checked_add_size(out.size(), 8, total_size) ||
      !checked_add_size(total_size, point_bytes, total_size) ||
      !checked_add_size(total_size, 8, total_size) ||
      !checked_add_size(total_size, statement_binding.size(), total_size)) {
    return unexpected_error(ErrorCode::Overflow,
                            "bind_public_commitments:reserve");
  }
  out.reserve(total_size);
  append_u64_le(out, encoded_commitment_count);
  for (const PointBytes &point : public_commitments) {
    out.insert(out.end(), point.begin(), point.end());
  }
  append_u64_le(out, encoded_binding_size);
  out.insert(out.end(), statement_binding.begin(), statement_binding.end());
  return out;
}

Status
validate_public_commitments(std::span<const PointBytes> public_commitments,
                            std::span<const FieldElement> commitments,
                            purify_secp_context *secp_context) {
  if (public_commitments.size() != commitments.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "validate_public_commitments:size");
  }
  for (std::size_t i = 0; i < commitments.size(); ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &expected, point_from_scalar_base(commitments[i], secp_context),
        "validate_public_commitments:point_from_scalar_base");
    if (expected != public_commitments[i]) {
      return unexpected_error(ErrorCode::BindingMismatch,
                              "validate_public_commitments:mismatch");
    }
  }
  return {};
}

Result<PointBytes> add_scaled_points_allow_infinity(
    const PointBytes &base_commitment,
    std::span<const PointBytes> points,
    std::span<const FieldElement> scalars,
    purify_secp_context *secp_context) {
  if (points.size() != scalars.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "add_scaled_points_allow_infinity:size");
  }
  PointBytes out = base_commitment;
  for (std::size_t i = 0; i < points.size(); ++i) {
    if (scalars[i].is_zero()) {
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &scaled,
        point_scale(points[i], scalars[i], secp_context),
        "add_scaled_points_allow_infinity:scale");
    PURIFY_ASSIGN_OR_RETURN(
        out, point_add_allow_infinity(out, scaled, secp_context),
        "add_scaled_points_allow_infinity:add");
  }
  return out;
}

Result<PointBytes> circuit_anchored_offset_v4(
    const CircuitNormArgPublicData &public_data,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  if (public_commitments.size() !=
      public_data.public_commitment_coeffs.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "circuit_anchored_offset_v4:public_size");
  }

  std::vector<PointBytes> points;
  std::vector<FieldElement> scalars;
  points.reserve(public_data.plus_shift.size() * 2 +
                 public_commitments.size() + 1);
  scalars.reserve(points.capacity());
  for (std::size_t i = 0; i < public_data.plus_shift.size(); ++i) {
    points.push_back(public_data.raw_generator_points[2 * i]);
    scalars.push_back(public_data.plus_shift[i]);
    points.push_back(public_data.raw_generator_points[2 * i + 1]);
    scalars.push_back(public_data.minus_shift[i]);
  }
  if (!public_data.target.is_zero()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto target,
        point_from_scalar_base(public_data.target, secp_context),
        "circuit_anchored_offset_v4:target");
    points.push_back(std::move(target));
    scalars.push_back(FieldElement::one());
  }
  for (std::size_t i = 0; i < public_commitments.size(); ++i) {
    points.push_back(public_commitments[i]);
    scalars.push_back(
        public_data.public_commitment_coeffs[i].negate());
  }
  return add_scaled_points_allow_infinity(
      PointBytes{}, points, scalars, secp_context);
}

Result<PointBytes>
anchor_zk_a_commitment(const PointBytes &a_witness_commitment,
                       const CircuitNormArgPublicData &public_data,
                       std::span<const PointBytes> public_commitments,
                       purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &offset,
      circuit_anchored_offset_v4(public_data, public_commitments,
                                 secp_context),
      "anchor_zk_a_commitment:offset");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored,
      point_add_allow_infinity(a_witness_commitment, offset,
                               secp_context),
      "anchor_zk_a_commitment:add");
  if (anchored == PointBytes{}) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "anchor_zk_a_commitment:identity");
  }
  return anchored;
}

Result<PointBytes> coefficient_commitment_v4(
    const CircuitNormArgPublicData &public_data,
    purify_secp_context *secp_context) {
  const bool all_zero =
      std::all_of(public_data.c_vec.begin(), public_data.c_vec.end(),
                  [](const FieldElement &value) { return value.is_zero(); });
  if (all_zero) {
    return PointBytes{};
  }

  NormArgInputs inputs;
  inputs.generators = public_data.raw_generators;
  inputs.n_vec.assign(public_data.n_vec_len, ScalarBytes{});
  inputs.l_vec = public_data.c_vec_bytes;
  return commit_norm_arg_witness_only(inputs, secp_context, nullptr);
}

Result<PointBytes>
commit_explicit_norm_arg(const NormArgInputs &inputs, const FieldElement &value,
                         purify_secp_context *secp_context,
                         ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &witness_commitment, commit_norm_arg_witness_only(inputs, secp_context, cache),
      "commit_explicit_norm_arg:witness_commitment");
  return offset_commitment(witness_commitment, value, secp_context);
}

Result<PointBytes> combine_zk_commitments(const PointBytes &a_commitment,
                                          const PointBytes &s_commitment,
                                          const FieldElement &challenge,
                                          const FieldElement &t2,
                                          purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(const auto &scaled_s, point_scale(s_commitment, challenge, secp_context),
                          "combine_zk_commitments:scale_s");
  PURIFY_ASSIGN_OR_RETURN(const auto &combined, point_add(a_commitment, scaled_s, secp_context),
                          "combine_zk_commitments:add");
  return offset_commitment(combined, challenge * challenge * t2, secp_context);
}

template <typename Inputs>
Result<NormArgProof>
prove_norm_arg_impl(Inputs &&inputs,
                    purify_secp_context *secp_context,
                    ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "prove_norm_arg:secp_context"),
                         "prove_norm_arg:secp_context");
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "prove_norm_arg:empty_vectors");
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "prove_norm_arg:l_c_size_mismatch");
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated, create_generators(inputs.n_vec.size() + inputs.l_vec.size(), secp_context),
        "prove_norm_arg:create_generators");
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }
  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  std::size_t proof_len =
      purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
  PointBytes commitment{};
  Bytes proof(proof_len);

  if (proof_len == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "prove_norm_arg:proof_len_zero");
  }
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_prove_norm_arg_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data(),
                proof.data(), &proof_len)
          : purify_bppp_prove_norm_arg(
                secp_context, inputs.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data(), proof.data(),
                &proof_len);
  if (!require_ok(ok)) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_norm_arg:backend");
  }
  proof.resize(proof_len);

  std::vector<PointBytes> proof_generators;
  if (!generated_generators.empty()) {
    proof_generators = std::move(generated_generators);
  } else if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> &&
                       std::is_rvalue_reference_v<Inputs &&>) {
    proof_generators = std::move(inputs.generators);
  } else {
    proof_generators = inputs.generators;
  }

  std::vector<ScalarBytes> proof_c_vec;
  if constexpr (!std::is_const_v<std::remove_reference_t<Inputs>> &&
                std::is_rvalue_reference_v<Inputs &&>) {
    proof_c_vec = std::move(inputs.c_vec);
  } else {
    proof_c_vec = inputs.c_vec;
  }

  return NormArgProof{inputs.rho,
                      std::move(proof_generators),
                      std::move(proof_c_vec),
                      inputs.n_vec.size(),
                      commitment,
                      std::move(proof)};
}

Result<FieldElement>
derive_zk_challenge(std::span<const unsigned char> binding_digest,
                    const PointBytes &a_commitment,
                    const PointBytes &s_commitment, const FieldElement &t2) {
  Bytes seed(binding_digest.begin(), binding_digest.end());
  seed.insert(seed.end(), a_commitment.begin(), a_commitment.end());
  seed.insert(seed.end(), s_commitment.begin(), s_commitment.end());
  ScalarBytes t2_bytes = scalar_bytes(t2);
  seed.insert(seed.end(), t2_bytes.begin(), t2_bytes.end());
  return derive_nonzero_scalar(seed, kCircuitZkChallengeTaggedHash, 0);
}

} // namespace

GeneratorBytes base_generator(purify_secp_context *secp_context) {
  GeneratorBytes out{};
  bool ok = secp_context != nullptr
            && require_ok(purify_bppp_base_generator(secp_context, out.data()));
  assert(ok && "base_generator() requires a functioning backend");
  (void)ok;
  return out;
}

GeneratorBytes value_generator_h(purify_secp_context *secp_context) {
  GeneratorBytes out{};
  bool ok = secp_context != nullptr
            && require_ok(
                purify_bppp_value_generator_h(secp_context, out.data()));
  assert(ok && "value_generator_h() requires a functioning backend");
  (void)ok;
  return out;
}

Result<std::vector<PointBytes>> create_generators(std::size_t count,
                                                  purify_secp_context *secp_context) {
  std::vector<PointBytes> out(count);
  if (count == 0) {
    return out;
  }
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "create_generators:secp_context"),
                         "create_generators:secp_context");
  std::span<unsigned char> serialized = writable_byte_span(out);
  std::size_t serialized_len = serialized.size();
  if (!require_ok(purify_bppp_create_generators(secp_context, count,
                                                serialized.data(),
                                                &serialized_len))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "create_generators:backend");
  }
  if (serialized_len != serialized.size()) {
    return unexpected_error(ErrorCode::UnexpectedSize,
                            "create_generators:serialized_len");
  }
  return out;
}

Result<PointBytes>
commit_norm_arg_with_cache(const NormArgInputs &inputs,
                           purify_secp_context *secp_context,
                           ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "commit_norm_arg:secp_context"),
                         "commit_norm_arg:secp_context");
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "commit_norm_arg:empty_vectors");
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "commit_norm_arg:l_c_size_mismatch");
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated, create_generators(inputs.n_vec.size() + inputs.l_vec.size(), secp_context),
        "commit_norm_arg:create_generators");
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  PointBytes commitment{};
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_commit_norm_arg_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data())
          : purify_bppp_commit_norm_arg(
                secp_context, inputs.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data());
  if (!require_ok(ok)) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "commit_norm_arg:backend");
  }
  return commitment;
}

Result<PointBytes> pedersen_commit_char(const ScalarBytes &blind,
                                        const ScalarBytes &value,
                                        purify_secp_context *secp_context) {
  return pedersen_commit_char(blind, value, secp_context,
                              value_generator_h(secp_context),
                              base_generator(secp_context));
}

Result<PointBytes> pedersen_commit_char(const ScalarBytes &blind,
                                        const ScalarBytes &value,
                                        purify_secp_context *secp_context,
                                        const GeneratorBytes &value_gen,
                                        const GeneratorBytes &blind_gen) {
  PointBytes commitment{};
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "pedersen_commit_char:secp_context"),
                         "pedersen_commit_char:secp_context");
  if (!require_ok(purify_pedersen_commit_char(
          secp_context, blind.data(), value.data(), value_gen.data(), blind_gen.data(),
          commitment.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "pedersen_commit_char:backend");
  }
  return commitment;
}

Result<NormArgProof> prove_norm_arg(const NormArgInputs &inputs,
                                    purify_secp_context *secp_context) {
  return prove_norm_arg_impl(inputs, secp_context, nullptr);
}

Result<NormArgProof> prove_norm_arg(NormArgInputs &&inputs,
                                    purify_secp_context *secp_context) {
  return prove_norm_arg_impl(std::move(inputs), secp_context, nullptr);
}

Result<NormArgProof> prove_norm_arg_to_commitment_with_cache(
    const NormArgInputs &inputs, const PointBytes &commitment,
    purify_secp_context *secp_context,
    ExperimentalCircuitBackend *cache = nullptr) {
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context, "prove_norm_arg_to_commitment:secp_context"),
      "prove_norm_arg_to_commitment:secp_context");
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "prove_norm_arg_to_commitment:empty_vectors");
  }
  if (inputs.l_vec.size() != inputs.c_vec.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "prove_norm_arg_to_commitment:l_c_size_mismatch");
  }

  const std::vector<PointBytes> *generators = &inputs.generators;
  std::vector<PointBytes> generated_generators;
  if (generators->empty()) {
    PURIFY_ASSIGN_OR_RETURN(
        auto generated, create_generators(inputs.n_vec.size() + inputs.l_vec.size(), secp_context),
        "prove_norm_arg_to_commitment:create_generators");
    generated_generators = std::move(generated);
    generators = &generated_generators;
  }

  std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, *generators, secp_context);
  std::size_t proof_len =
      purify_bppp_required_proof_size(inputs.n_vec.size(), inputs.c_vec.size());
  Bytes proof(proof_len);
  if (proof_len == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "prove_norm_arg_to_commitment:proof_len_zero");
  }
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_prove_norm_arg_to_commitment_with_resources(
                resolved.backend_resources, inputs.rho.data(), n_vec.data(),
                inputs.n_vec.size(), l_vec.data(), inputs.l_vec.size(),
                c_vec.data(), inputs.c_vec.size(), commitment.data(),
                proof.data(), &proof_len)
          : purify_bppp_prove_norm_arg_to_commitment(
                secp_context, inputs.rho.data(),
                resolved.serialized_bytes.data(),
                resolved.generator_count, n_vec.data(), inputs.n_vec.size(),
                l_vec.data(), inputs.l_vec.size(), c_vec.data(),
                inputs.c_vec.size(), commitment.data(), proof.data(),
                &proof_len);
  if (!require_ok(ok)) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_norm_arg_to_commitment:backend");
  }
  proof.resize(proof_len);

  std::vector<PointBytes> proof_generators;
  if (!generated_generators.empty()) {
    proof_generators = std::move(generated_generators);
  } else {
    proof_generators = inputs.generators;
  }
  return NormArgProof{inputs.rho,   std::move(proof_generators),
                      inputs.c_vec, inputs.n_vec.size(),
                      commitment,   std::move(proof)};
}

struct CircuitNormRoundCallback {
  candidate::CircuitProofTranscriptV4 *transcript = nullptr;
  purify_secp_context *secp_context = nullptr;
  std::vector<candidate::PackedPointPairV4> rounds;
  std::optional<Error> error;
};

int append_circuit_norm_round(void *callback_data,
                              const unsigned char point_pair65[65],
                              size_t round,
                              unsigned char challenge32[32]) {
  auto &callback = *static_cast<CircuitNormRoundCallback *>(callback_data);
  if (round != callback.rounds.size()) {
    return 0;
  }
  candidate::PackedPointPairV4 pair{};
  std::copy_n(point_pair65, pair.size(), pair.begin());
  auto challenge =
      callback.transcript->append_round(pair, callback.secp_context);
  if (!challenge.has_value()) {
    callback.error = challenge.error();
    return 0;
  }
  const ScalarBytes encoded = challenge->scalar.to_bytes_be();
  std::copy(encoded.begin(), encoded.end(), challenge32);
  callback.rounds.push_back(pair);
  return 1;
}

Result<NormArgProof> prove_norm_arg_to_commitment_v4(
    const NormArgInputs &inputs, const PointBytes &commitment,
    candidate::CircuitProofTranscriptV4 &transcript,
    purify_secp_context *secp_context) {
  if (inputs.n_vec.empty() || inputs.l_vec.empty() || inputs.c_vec.empty() ||
      inputs.l_vec.size() != inputs.c_vec.size() ||
      inputs.generators.size() !=
          inputs.n_vec.size() + inputs.l_vec.size()) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "prove_norm_arg_to_commitment_v4:inputs");
  }
  const std::size_t proof_capacity = purify_bppp_required_proof_size(
      inputs.n_vec.size(), inputs.c_vec.size());
  if (proof_capacity == 0) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "prove_norm_arg_to_commitment_v4:proof_size");
  }

  Bytes proof(proof_capacity);
  std::size_t proof_len = proof.size();
  CircuitNormRoundCallback callback{&transcript, secp_context, {}, {}};
  const std::span<const unsigned char> generators =
      byte_span(inputs.generators);
  const std::span<const unsigned char> n_vec = byte_span(inputs.n_vec);
  const std::span<const unsigned char> l_vec = byte_span(inputs.l_vec);
  const std::span<const unsigned char> c_vec = byte_span(inputs.c_vec);
  const int ok = purify_bppp_prove_norm_arg_to_commitment_with_callback(
      secp_context, inputs.rho.data(), generators.data(),
      inputs.generators.size(), n_vec.data(), inputs.n_vec.size(),
      l_vec.data(), inputs.l_vec.size(), c_vec.data(), inputs.c_vec.size(),
      commitment.data(), append_circuit_norm_round, &callback, proof.data(),
      &proof_len);
  if (ok == 0) {
    if (callback.error.has_value()) {
      return unexpected_error(*callback.error,
                              "prove_norm_arg_to_commitment_v4:transcript");
    }
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_norm_arg_to_commitment_v4:backend");
  }
  if (callback.rounds.size() != transcript.shape().round_count()) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "prove_norm_arg_to_commitment_v4:rounds");
  }
  proof.resize(proof_len);
  return NormArgProof{inputs.rho, inputs.generators, inputs.c_vec,
                      inputs.n_vec.size(), commitment, std::move(proof)};
}

bool verify_norm_arg_with_cache(const NormArgProof &proof,
                                purify_secp_context *secp_context,
                                ExperimentalCircuitBackend *cache = nullptr) {
  if (secp_context == nullptr) {
    return false;
  }
  if (proof.n_vec_len == 0 || proof.c_vec.empty()) {
    return false;
  }

  std::span<const unsigned char> c_vec = byte_span(proof.c_vec);
  ResolvedBpppGeneratorBackend resolved =
      resolve_bppp_generator_backend(cache, proof.generators, secp_context);
  const int ok =
      resolved.backend_resources != nullptr
          ? purify_bppp_verify_norm_arg_with_resources(
                resolved.backend_resources, proof.rho.data(), c_vec.data(),
                proof.c_vec.size(), proof.n_vec_len, proof.commitment.data(),
                proof.proof.data(), proof.proof.size())
          : purify_bppp_verify_norm_arg(
                secp_context, proof.rho.data(), resolved.serialized_bytes.data(),
                resolved.generator_count, c_vec.data(), proof.c_vec.size(),
                proof.n_vec_len, proof.commitment.data(), proof.proof.data(),
                proof.proof.size());
  return ok != 0;
}

Result<std::vector<candidate::PackedPointPairV4>>
parse_norm_rounds_v4(const Bytes &proof, std::size_t round_count,
                     ScalarBytes &terminal_n, ScalarBytes &terminal_l) {
  std::size_t pair_bytes = 0;
  std::size_t expected_size = 0;
  if (!checked_mul_size(round_count,
                        sizeof(candidate::PackedPointPairV4), pair_bytes) ||
      !checked_add_size(pair_bytes, 2 * sizeof(ScalarBytes), expected_size) ||
      proof.size() != expected_size) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "parse_norm_rounds_v4:proof_size");
  }
  std::vector<candidate::PackedPointPairV4> rounds(round_count);
  for (std::size_t i = 0; i < rounds.size(); ++i) {
    std::copy_n(proof.begin() + i * rounds[i].size(), rounds[i].size(),
                rounds[i].begin());
  }
  std::copy_n(proof.begin() + pair_bytes, terminal_n.size(),
              terminal_n.begin());
  std::copy_n(proof.begin() + pair_bytes + terminal_n.size(),
              terminal_l.size(), terminal_l.begin());
  return rounds;
}

std::vector<ScalarBytes> scalar_challenges(
    std::span<const candidate::CircuitChallengeV4> challenges) {
  std::vector<ScalarBytes> out;
  out.reserve(challenges.size());
  for (const auto &challenge : challenges) {
    out.push_back(challenge.scalar.to_bytes_be());
  }
  return out;
}

Result<PointBytes> prepare_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    ScalarBytes &terminal_n, ScalarBytes &terminal_l,
    purify_secp_context *secp_context) {
  const std::vector<ScalarBytes> encoded_gammas = scalar_challenges(gammas);
  PointBytes residual{};
  const std::span<const unsigned char> generators =
      byte_span(norm.generators);
  const std::span<const unsigned char> c_vec = byte_span(norm.c_vec);
  if (purify_bppp_prepare_norm_arg_claim_with_challenges(
          secp_context, norm.rho.data(), generators.data(),
          norm.generators.size(), c_vec.data(), norm.c_vec.size(),
          norm.n_vec_len, norm.commitment.data(), norm.proof.data(),
          norm.proof.size(),
          reinterpret_cast<const unsigned char *>(encoded_gammas.data()),
          encoded_gammas.size(), terminal_n.data(), terminal_l.data(),
          residual.data()) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prepare_norm_arg_v4:backend");
  }
  return residual;
}

bool verify_norm_arg_v4(
    const NormArgProof &norm,
    std::span<const candidate::CircuitChallengeV4> gammas,
    purify_secp_context *secp_context) {
  const std::vector<ScalarBytes> encoded_gammas = scalar_challenges(gammas);
  const std::span<const unsigned char> generators =
      byte_span(norm.generators);
  const std::span<const unsigned char> c_vec = byte_span(norm.c_vec);
  return purify_bppp_verify_norm_arg_with_challenges(
             secp_context, norm.rho.data(), generators.data(),
             norm.generators.size(), c_vec.data(), norm.c_vec.size(),
             norm.n_vec_len, norm.commitment.data(), norm.proof.data(),
             norm.proof.size(),
             reinterpret_cast<const unsigned char *>(encoded_gammas.data()),
             encoded_gammas.size()) != 0;
}

Result<PointBytes> commit_norm_arg(const NormArgInputs &inputs,
                                   purify_secp_context *secp_context) {
  return commit_norm_arg_with_cache(inputs, secp_context, nullptr);
}

Result<NormArgProof>
prove_norm_arg_to_commitment(const NormArgInputs &inputs,
                             const PointBytes &commitment,
                             purify_secp_context *secp_context) {
  return prove_norm_arg_to_commitment_with_cache(inputs, commitment, secp_context, nullptr);
}

bool verify_norm_arg(const NormArgProof &proof,
                     purify_secp_context *secp_context) {
  return verify_norm_arg_with_cache(proof, secp_context, nullptr);
}

Result<PointBytes> commit_experimental_circuit_witness(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto raw_inputs,
      build_raw_circuit_norm_arg_inputs(circuit, assignment, {}, false,
                                        secp_context),
      "commit_experimental_circuit_witness:raw_inputs");
  WipeVectorOnDestruction raw_n_wiper(raw_inputs.n_vec);
  WipeVectorOnDestruction raw_l_wiper(raw_inputs.l_vec);
  return commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
}

Result<ExperimentalCircuitNormArgProof>
prove_experimental_circuit_norm_arg_to_commitment(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &witness_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "prove_experimental_circuit_norm_arg_to_commitment:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "prove_experimental_circuit_norm_arg_to_commitment:"
                            "n_gates_power_of_two");
  }
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "prove_experimental_circuit_norm_arg_to_commitment:assignment_shape");
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(
        ErrorCode::EquationMismatch,
        "prove_experimental_circuit_norm_arg_to_commitment:assignment_invalid");
  }

  PURIFY_ASSIGN_OR_RETURN(
      auto raw_inputs,
      build_raw_circuit_norm_arg_inputs(circuit, assignment, {}, false,
                                        secp_context),
      "prove_experimental_circuit_norm_arg_to_commitment:raw_inputs");
  WipeVectorOnDestruction raw_n_wiper(raw_inputs.n_vec);
  WipeVectorOnDestruction raw_l_wiper(raw_inputs.l_vec);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &computed_witness_commitment,
      commit_norm_arg_witness_only(raw_inputs, secp_context, cache),
      "prove_experimental_circuit_norm_arg_to_commitment:commit_witness");
  if (computed_witness_commitment != witness_commitment) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_experimental_circuit_norm_arg_to_commitment:"
                            "witness_commitment_mismatch");
  }

  PURIFY_ASSIGN_OR_RETURN(
      auto reduction,
      reduce_experimental_circuit_to_norm_arg(
          circuit, assignment, witness_commitment, secp_context,
          statement_binding, false, cache),
      "prove_experimental_circuit_norm_arg_to_commitment:reduce");
  WipeVectorOnDestruction reduction_n_wiper(reduction.n_vec);
  WipeVectorOnDestruction reduction_l_wiper(reduction.l_vec);

  NormArgInputs inputs = build_norm_arg_inputs(reduction);
  WipeVectorOnDestruction input_n_wiper(inputs.n_vec);
  WipeVectorOnDestruction input_l_wiper(inputs.l_vec);

  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      anchor_zk_a_commitment(witness_commitment, *reduction.public_data, {},
                             secp_context),
      "prove_experimental_circuit_norm_arg_to_commitment:anchor");

  PURIFY_ASSIGN_OR_RETURN(
      auto proof,
      prove_norm_arg_to_commitment_with_cache(inputs, anchored_commitment,
                                              secp_context, nullptr),
      "prove_experimental_circuit_norm_arg_to_commitment:prove");
  return ExperimentalCircuitNormArgProof{witness_commitment,
                                         std::move(proof.proof)};
}

Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &witness_commitment,
      commit_experimental_circuit_witness(circuit, assignment, secp_context,
                                          cache),
      "prove_experimental_circuit_norm_arg:commit_witness");
  return prove_experimental_circuit_norm_arg_to_commitment(
      circuit, assignment, witness_commitment, secp_context, statement_binding, cache);
}

Result<bool> verify_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "verify_experimental_circuit_norm_arg:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "verify_experimental_circuit_norm_arg:n_gates_power_of_two");
  }
  if (proof.proof.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "verify_experimental_circuit_norm_arg:proof_empty");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(circuit, statement_binding,
                                         proof.witness_commitment, secp_context,
                                         false, cache),
      "verify_experimental_circuit_norm_arg:public_data");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      anchor_zk_a_commitment(proof.witness_commitment, *public_data, {},
                             secp_context),
      "verify_experimental_circuit_norm_arg:anchor");

  NormArgProof bundle;
  bundle.rho = public_data->rho_bytes;
  bundle.generators = public_data->generators;
  bundle.c_vec = public_data->c_vec_bytes;
  bundle.n_vec_len = public_data->n_vec_len;
  bundle.commitment = anchored_commitment;
  bundle.proof = proof.proof;
  return verify_norm_arg_with_cache(bundle, secp_context, nullptr);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "prove_experimental_circuit_zk_norm_arg_impl:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "prove_experimental_circuit_zk_norm_arg_impl:n_gates_power_of_two");
  }
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "prove_experimental_circuit_zk_norm_arg_impl:assignment_shape");
  }
  if (externalize_commitments &&
      public_commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "prove_experimental_circuit_zk_norm_arg_impl:public_commitment_count");
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(
        ErrorCode::EquationMismatch,
        "prove_experimental_circuit_zk_norm_arg_impl:assignment_invalid");
  }

  Bytes bound_statement_binding;
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(
        bound_statement_binding,
        bind_public_commitments(public_commitments, statement_binding),
        "prove_experimental_circuit_zk_norm_arg_impl:bound_statement_binding");
  } else {
    bound_statement_binding =
        Bytes(statement_binding.begin(), statement_binding.end());
  }
  if (externalize_commitments) {
    if (public_commitments.empty()) {
      return unexpected_error(
          ErrorCode::EmptyInput,
          "prove_experimental_circuit_zk_norm_arg_impl:public_commitments");
    }
    PURIFY_RETURN_IF_ERROR(
        validate_public_commitments(public_commitments, assignment.commitments, secp_context),
        "prove_experimental_circuit_zk_norm_arg_impl:"
        "validate_public_commitments");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      experimental_circuit_binding_digest(circuit, bound_statement_binding),
      "prove_experimental_circuit_zk_norm_arg_impl:binding_digest");
  SecretBytes seed;
  seed.value.reserve(binding_digest.size() + secret_prover_seed.size());
  seed.value.insert(seed.value.end(), binding_digest.begin(),
                    binding_digest.end());
  seed.value.insert(seed.value.end(), secret_prover_seed.begin(),
                    secret_prover_seed.end());
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments),
      "prove_experimental_circuit_zk_norm_arg_impl:dimensions");
  std::optional<Error> masked_failure;

  for (std::uint64_t attempt = 0; attempt < 32; ++attempt) {
    std::vector<FieldElement> padding(
        dimensions.l_vec_len - dimensions.used_l, FieldElement::zero());
    WipeVectorOnDestruction padding_wiper(padding);
    for (std::size_t i = 0; i < padding.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(padding[i], seed.value, kCircuitZkBlindTaggedHash, i,
                        attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:blind");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto raw_inputs,
        build_raw_circuit_norm_arg_inputs(circuit, assignment, padding,
                                          externalize_commitments,
                                          secp_context),
        "prove_experimental_circuit_zk_norm_arg_impl:raw_inputs");
    WipeVectorOnDestruction raw_n_wiper(raw_inputs.n_vec);
    WipeVectorOnDestruction raw_l_wiper(raw_inputs.l_vec);
    Result<PointBytes> raw_commitment =
        commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
    if (!raw_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure = unexpected_error(
                             raw_commitment.error(),
                             "prove_experimental_circuit_zk_norm_arg_impl:"
                             "raw_commitment")
                             .error();
      }
      continue;
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto hidden,
        reduce_experimental_circuit_to_norm_arg(
            circuit, assignment, *raw_commitment, secp_context,
            bound_statement_binding, externalize_commitments, cache),
        "prove_experimental_circuit_zk_norm_arg_impl:reduce");
    WipeVectorOnDestruction hidden_n_wiper(hidden.n_vec);
    WipeVectorOnDestruction hidden_l_wiper(hidden.l_vec);
    std::copy(padding.begin(), padding.end(),
              hidden.l_vec.begin() + dimensions.used_l);

    PublicCommitmentDlogProof dlog_proof;
    if (externalize_commitments) {
      Result<BatchedPublicCommitment> batched = batch_public_commitments(
          public_commitments, hidden.public_data->challenge_digest,
          secp_context);
      if (!batched.has_value()) {
        if (!masked_failure.has_value()) {
          masked_failure = unexpected_error(
                               batched.error(),
                               "prove_experimental_circuit_zk_norm_arg_impl:"
                               "batch_public_commitments")
                               .error();
        }
        continue;
      }
      Result<PublicCommitmentDlogProof> dlog =
          prove_public_commitment_dlog(
              *batched, assignment.commitments,
              hidden.public_data->challenge_digest, secret_prover_seed,
              secp_context);
      if (!dlog.has_value()) {
        if (!masked_failure.has_value()) {
          masked_failure = unexpected_error(
                               dlog.error(),
                               "prove_experimental_circuit_zk_norm_arg_impl:"
                               "prove_public_commitment_dlog")
                               .error();
        }
        continue;
      }
      dlog_proof = *dlog;
    }

    std::vector<FieldElement> mask_n(hidden.n_vec.size(), FieldElement::zero());
    WipeVectorOnDestruction mask_n_wiper(mask_n);
    for (std::size_t i = 0; i < mask_n.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(mask_n[i], seed.value, kCircuitZkMaskNTaggedHash, i,
                        attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:mask_n");
    }

    std::vector<FieldElement> mask_l(hidden.l_vec.size(), FieldElement::zero());
    WipeVectorOnDestruction mask_l_wiper(mask_l);
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(mask_l[i], seed.value, kCircuitZkMaskLTaggedHash, i,
                        attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:mask_l");
    }

    FieldElement t2 =
        weighted_bppp_inner_product(mask_n, mask_n, hidden.public_data->rho);
    WipeObjectOnDestruction t2_wiper(t2);
    if (t2.is_zero()) {
      continue;
    }
    FieldElement t1 = FieldElement::from_int(2) *
                      weighted_bppp_inner_product(hidden.n_vec, mask_n,
                                                  hidden.public_data->rho);
    WipeObjectOnDestruction t1_wiper(t1);
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      t1 = t1 + (mask_l[i] * hidden.public_data->c_vec[i]);
    }

    NormArgInputs mask_inputs;
    mask_inputs.rho = hidden.public_data->rho_bytes;
    mask_inputs.generators = hidden.public_data->generators;
    mask_inputs.n_vec = scalar_bytes(mask_n);
    mask_inputs.l_vec = scalar_bytes(mask_l);
    mask_inputs.c_vec = hidden.public_data->c_vec_bytes;
    WipeVectorOnDestruction mask_input_n_wiper(mask_inputs.n_vec);
    WipeVectorOnDestruction mask_input_l_wiper(mask_inputs.l_vec);

    Result<PointBytes> a_commitment = anchor_zk_a_commitment(
        *raw_commitment, *hidden.public_data, public_commitments, secp_context);
    if (!a_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure =
            unexpected_error(
                a_commitment.error(),
                "prove_experimental_circuit_zk_norm_arg_impl:a_commitment")
                .error();
      }
      continue;
    }
    Result<PointBytes> s_commitment =
        commit_explicit_norm_arg(mask_inputs, t1, secp_context, nullptr);
    if (!s_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure =
            unexpected_error(
                s_commitment.error(),
                "prove_experimental_circuit_zk_norm_arg_impl:s_commitment")
                .error();
      }
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &challenge,
        derive_zk_challenge(hidden.public_data->challenge_digest,
                            *a_commitment, *s_commitment, t2),
        "prove_experimental_circuit_zk_norm_arg_impl:challenge");

    CircuitNormArgReduction masked = hidden;
    WipeVectorOnDestruction masked_n_wiper(masked.n_vec);
    WipeVectorOnDestruction masked_l_wiper(masked.l_vec);
    for (std::size_t i = 0; i < masked.n_vec.size(); ++i) {
      masked.n_vec[i] = masked.n_vec[i] + (challenge * mask_n[i]);
    }
    for (std::size_t i = 0; i < masked.l_vec.size(); ++i) {
      masked.l_vec[i] = masked.l_vec[i] + (challenge * mask_l[i]);
    }
    NormArgInputs masked_inputs = build_norm_arg_inputs(masked);
    WipeVectorOnDestruction masked_input_n_wiper(masked_inputs.n_vec);
    WipeVectorOnDestruction masked_input_l_wiper(masked_inputs.l_vec);

    Result<PointBytes> combined_commitment =
        combine_zk_commitments(*a_commitment, *s_commitment, challenge, t2, secp_context);
    if (!combined_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure = unexpected_error(combined_commitment.error(),
                                          "prove_experimental_circuit_zk_norm_"
                                          "arg_impl:combined_commitment")
                             .error();
      }
      continue;
    }
    Result<PointBytes> direct_commitment =
        commit_norm_arg_with_cache(masked_inputs, secp_context, nullptr);
    if (!direct_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure =
            unexpected_error(
                direct_commitment.error(),
                "prove_experimental_circuit_zk_norm_arg_impl:direct_commitment")
                .error();
      }
      continue;
    }
    if (*combined_commitment != *direct_commitment) {
      return unexpected_error(
          ErrorCode::InternalMismatch,
          "prove_experimental_circuit_zk_norm_arg_impl:commitment_mismatch");
    }

    Result<NormArgProof> proof = prove_norm_arg_to_commitment_with_cache(
        masked_inputs, *combined_commitment, secp_context, nullptr);
    if (!proof.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure =
            unexpected_error(proof.error(),
                             "prove_experimental_circuit_zk_norm_arg_impl:"
                             "prove_norm_arg_to_commitment")
                .error();
      }
      continue;
    }
    return ExperimentalCircuitZkNormArgProof{
        *raw_commitment,
        *s_commitment,
        scalar_bytes(t2),
        dlog_proof.nonce_xonly,
        dlog_proof.response,
        std::move(proof->proof)};
  }

  if (masked_failure.has_value()) {
    return unexpected_error(
        *masked_failure,
        "prove_experimental_circuit_zk_norm_arg_impl:masking_attempts");
  }
  return unexpected_error(
      ErrorCode::BackendRejectedInput,
      "prove_experimental_circuit_zk_norm_arg_impl:masking_attempts");
}

namespace {

Status validate_prepared_circuit_proof(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "prepare_experimental_circuit_zk_norm_arg:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "prepare_experimental_circuit_zk_norm_arg:n_gates_power_of_two");
  }
  if (proof.proof.empty()) {
    return unexpected_error(
        ErrorCode::EmptyInput,
        "prepare_experimental_circuit_zk_norm_arg:proof_empty");
  }
  return {};
}

bool has_zero_public_commitment_dlog(
    const ExperimentalCircuitZkNormArgProof &proof) {
  const auto all_zero = [](const auto &bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](unsigned char byte) { return byte == 0; });
  };
  return all_zero(proof.public_commitment_dlog_nonce) &&
         all_zero(proof.public_commitment_dlog_response);
}

Result<detail::PreparedExperimentalCircuitZkNormArg>
finish_prepared_circuit_proof(
    const ExperimentalCircuitZkNormArgProof &proof,
    const CircuitNormArgPublicDataPtr &public_data,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &t2, FieldElement::try_from_bytes32(proof.t2),
      "prepare_experimental_circuit_zk_norm_arg:t2");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &a_commitment,
      anchor_zk_a_commitment(proof.a_commitment, *public_data,
                             public_commitments, secp_context),
      "prepare_experimental_circuit_zk_norm_arg:a_commitment");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      derive_zk_challenge(public_data->challenge_digest, a_commitment,
                          proof.s_commitment, t2),
      "prepare_experimental_circuit_zk_norm_arg:challenge");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &commitment,
      combine_zk_commitments(a_commitment, proof.s_commitment, challenge, t2,
                             secp_context),
      "prepare_experimental_circuit_zk_norm_arg:commitment");

  detail::PreparedExperimentalCircuitZkNormArg out;
  out.norm.rho = public_data->rho_bytes;
  out.norm.generators = public_data->generators;
  out.norm.c_vec = public_data->c_vec_bytes;
  out.norm.n_vec_len = public_data->n_vec_len;
  out.norm.commitment = commitment;
  out.norm.proof = proof.proof;
  out.raw_generator_digest =
      generator_backend_cache_key(public_data->raw_generators);
  assert(public_data->challenge_digest.size() ==
         out.challenge_digest.size());
  std::copy(public_data->challenge_digest.begin(),
            public_data->challenge_digest.end(),
            out.challenge_digest.begin());
  out.mul_scale = public_data->mul_scale;
  out.mul_ratio = public_data->mul_ratio;
  return out;
}

} // namespace

Result<std::optional<detail::PreparedExperimentalCircuitZkNormArg>>
detail::prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(validate_prepared_circuit_proof(circuit, proof),
                         "prepare_experimental_circuit_zk_norm_arg:validate");
  if (public_commitments.empty()) {
    return unexpected_error(
        ErrorCode::EmptyInput,
        "prepare_experimental_circuit_zk_norm_arg:public_commitments");
  }
  if (public_commitments.size() != circuit.n_commitments) {
    return unexpected_error(
        ErrorCode::SizeMismatch,
        "prepare_experimental_circuit_zk_norm_arg:public_commitment_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &bound_statement_binding,
      bind_public_commitments(public_commitments, statement_binding),
      "prepare_experimental_circuit_zk_norm_arg:bound_statement_binding");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(
          circuit, bound_statement_binding, proof.a_commitment, secp_context,
          true, cache),
      "prepare_experimental_circuit_zk_norm_arg:public_data");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &batched,
      batch_public_commitments(public_commitments,
                               public_data->challenge_digest, secp_context),
      "prepare_experimental_circuit_zk_norm_arg:batch_public_commitments");
  const PublicCommitmentDlogProof dlog_proof{
      proof.public_commitment_dlog_nonce,
      proof.public_commitment_dlog_response};
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dlog_ok,
      verify_public_commitment_dlog(
          batched, public_data->challenge_digest, dlog_proof,
          secp_context),
      "prepare_experimental_circuit_zk_norm_arg:verify_public_commitment_dlog");
  if (!dlog_ok) {
    return std::optional<PreparedExperimentalCircuitZkNormArg>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto out,
      finish_prepared_circuit_proof(proof, public_data, public_commitments,
                                    secp_context),
      "prepare_experimental_circuit_zk_norm_arg:finish");
  return std::optional<PreparedExperimentalCircuitZkNormArg>(std::move(out));
}

Result<std::optional<detail::PreparedExperimentalCircuitZkNormArg>>
detail::prepare_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(validate_prepared_circuit_proof(circuit, proof),
                         "prepare_experimental_circuit_zk_norm_arg:validate");

  const Bytes bound_statement_binding(statement_binding.begin(),
                                      statement_binding.end());
  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(
          circuit, bound_statement_binding, proof.a_commitment, secp_context,
          false, cache),
      "prepare_experimental_circuit_zk_norm_arg:public_data");
  if (!has_zero_public_commitment_dlog(proof)) {
    return std::optional<PreparedExperimentalCircuitZkNormArg>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto out,
      finish_prepared_circuit_proof(proof, public_data, {}, secp_context),
      "prepare_experimental_circuit_zk_norm_arg:finish");
  return std::optional<PreparedExperimentalCircuitZkNormArg>(std::move(out));
}

Result<bool> verify_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      detail::prepare_experimental_circuit_zk_norm_arg(
          circuit, proof, secp_context, statement_binding, cache),
      "verify_experimental_circuit_zk_norm_arg_impl:prepare");
  if (!prepared.has_value()) {
    return false;
  }
  return verify_norm_arg_with_cache(prepared->norm, secp_context, nullptr);
}

namespace {

Result<candidate::CircuitTranscriptShapeV4> circuit_shape_v4(
    const NativeBulletproofCircuit &circuit, bool externalize_commitments) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments),
      "circuit_shape_v4:dimensions");
  const auto mode = externalize_commitments
                        ? candidate::CircuitCommitmentModeV4::Public
                        : candidate::CircuitCommitmentModeV4::Hidden;
  return candidate::CircuitTranscriptShapeV4::create(
      mode, dimensions.gate_count, circuit.n_commitments,
      dimensions.n_vec_len, dimensions.l_vec_len);
}

Result<candidate::TranscriptDigest> circuit_binding_digest_v4(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &digest,
      experimental_circuit_binding_digest(circuit, statement_binding),
      "circuit_binding_digest_v4:digest");
  candidate::TranscriptDigest out{};
  if (digest.size() != out.size()) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_binding_digest_v4:size");
  }
  std::copy(digest.begin(), digest.end(), out.begin());
  return out;
}

Result<candidate::TranscriptDigest> raw_generator_digest_v4(
    const candidate::CircuitTranscriptShapeV4 &shape,
    purify_secp_context *secp_context) {
  std::size_t generator_count = 0;
  if (!checked_add_size(shape.n_vec_len(), shape.l_vec_len(),
                        generator_count)) {
    return unexpected_error(ErrorCode::Overflow,
                            "raw_generator_digest_v4:generator_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &generators, create_generators(generator_count, secp_context),
      "raw_generator_digest_v4:generators");
  return generator_backend_cache_key(generators);
}

bool is_identity_point_v4(const PointBytes &point) {
  return std::all_of(point.begin(), point.end(),
                     [](unsigned char byte) { return byte == 0; });
}

Status validate_circuit_proof_v4_inputs(
    const NativeBulletproofCircuit &circuit,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context,
                                              "circuit_proof_v4:context"),
                         "circuit_proof_v4:context");
  if (!circuit.has_valid_shape() ||
      !is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(ErrorCode::InvalidDimensions,
                            "circuit_proof_v4:circuit_shape");
  }
  if (externalize_commitments) {
    if (public_commitments.empty() ||
        public_commitments.size() != circuit.n_commitments) {
      return unexpected_error(ErrorCode::SizeMismatch,
                              "circuit_proof_v4:public_commitments");
    }
    if (std::any_of(public_commitments.begin(), public_commitments.end(),
                    is_identity_point_v4)) {
      return unexpected_error(ErrorCode::BackendRejectedInput,
                              "circuit_proof_v4:identity_public_commitment");
    }
  } else if (!public_commitments.empty()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "circuit_proof_v4:hidden_commitments");
  }
  return {};
}

Status validate_finite_point_v4(const PointBytes &point,
                                purify_secp_context *secp_context,
                                const char *label) {
  std::array<unsigned char, 32> xonly{};
  int parity = 0;
  if (purify_bip340_xonly_from_point(
          secp_context, point.data(), xonly.data(), &parity) == 0) {
    return unexpected_error(ErrorCode::BackendRejectedInput, label);
  }
  return {};
}

Status validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
    const candidate::CircuitZkNormArgProofV4 &proof,
    candidate::CircuitCommitmentModeV4 mode, std::size_t round_count,
    purify_secp_context *secp_context) {
  PURIFY_RETURN_IF_ERROR(
      require_secp_context(secp_context,
                           "circuit_proof_v4_encoding:context"),
      "circuit_proof_v4_encoding:context");
  PURIFY_RETURN_IF_ERROR(
      validate_finite_point_v4(proof.raw_commitment, secp_context,
                               "circuit_proof_v4_encoding:raw"),
      "circuit_proof_v4_encoding:raw");
  PURIFY_RETURN_IF_ERROR(
      validate_finite_point_v4(proof.mask_commitment, secp_context,
                               "circuit_proof_v4_encoding:mask"),
      "circuit_proof_v4_encoding:mask");
  PURIFY_ASSIGN_OR_RETURN(
      const auto t2, FieldElement::try_from_bytes32(proof.t2),
      "circuit_proof_v4_encoding:t2");
  (void)t2;

  if (mode == candidate::CircuitCommitmentModeV4::Public) {
    if (purify_bip340_validate_xonly_pubkey(
            secp_context,
            proof.public_commitment_dlog_nonce.data()) == 0) {
      return unexpected_error(
          ErrorCode::BackendRejectedInput,
          "circuit_proof_v4_encoding:dlog_nonce");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto response,
        FieldElement::try_from_bytes32(
            proof.public_commitment_dlog_response),
        "circuit_proof_v4_encoding:dlog_response");
    if (response.is_zero()) {
      return unexpected_error(
          ErrorCode::RangeViolation,
          "circuit_proof_v4_encoding:dlog_response");
    }
  } else if (mode != candidate::CircuitCommitmentModeV4::Hidden) {
    return unexpected_error(ErrorCode::UnsupportedSymbol,
                            "circuit_proof_v4_encoding:mode");
  } else if (!std::all_of(
                 proof.public_commitment_dlog_nonce.begin(),
                 proof.public_commitment_dlog_nonce.end(),
                 [](unsigned char byte) { return byte == 0; }) ||
             !std::all_of(
                 proof.public_commitment_dlog_response.begin(),
                 proof.public_commitment_dlog_response.end(),
                 [](unsigned char byte) { return byte == 0; })) {
    return unexpected_error(ErrorCode::BindingMismatch,
                            "circuit_proof_v4_encoding:hidden_dlog");
  }

  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
  PURIFY_ASSIGN_OR_RETURN(
      const auto rounds,
      parse_norm_rounds_v4(proof.norm_proof, round_count,
                           terminal_n, terminal_l),
      "circuit_proof_v4_encoding:rounds");
  for (const auto &round : rounds) {
    PURIFY_RETURN_IF_ERROR(
        candidate::validate_packed_point_pair_v4(round, secp_context),
        "circuit_proof_v4_encoding:round");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto terminal_n_scalar,
      FieldElement::try_from_bytes32(terminal_n),
      "circuit_proof_v4_encoding:terminal_n");
  PURIFY_ASSIGN_OR_RETURN(
      const auto terminal_l_scalar,
      FieldElement::try_from_bytes32(terminal_l),
      "circuit_proof_v4_encoding:terminal_l");
  (void)terminal_n_scalar;
  (void)terminal_l_scalar;
  return {};
}

Status validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitZkNormArgProofV4 &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context, bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(
      validate_circuit_proof_v4_inputs(
          circuit, public_commitments, secp_context,
          externalize_commitments),
      "circuit_proof_v4_encoding:inputs");
  PURIFY_ASSIGN_OR_RETURN(
      const auto shape,
      circuit_shape_v4(circuit, externalize_commitments),
      "circuit_proof_v4_encoding:shape");
  return validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
      proof, shape.mode(), shape.round_count(), secp_context);
}

Result<candidate::CircuitZkNormArgPublicationV4>
reconstruct_circuit_zk_norm_arg_publication_v4_impl(
    const NativeBulletproofCircuit &circuit,
    candidate::CircuitZkNormArgProofV4 proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments) {
  PURIFY_RETURN_IF_ERROR(
      validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
          circuit, proof, public_commitments, secp_context,
          externalize_commitments),
      "reconstruct_circuit_proof_v4:encoding");
  PURIFY_ASSIGN_OR_RETURN(
      const auto shape,
      circuit_shape_v4(circuit, externalize_commitments),
      "reconstruct_circuit_proof_v4:shape");
  PURIFY_ASSIGN_OR_RETURN(
      const auto binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding),
      "reconstruct_circuit_proof_v4:binding");
  PURIFY_ASSIGN_OR_RETURN(
      auto precommitment,
      candidate::derive_circuit_precommitment_v4(
          shape, binding_digest, public_commitments,
          proof.raw_commitment, secp_context),
      "reconstruct_circuit_proof_v4:precommitment");
  return candidate::CircuitZkNormArgPublicationV4{
      std::move(precommitment.digest), std::move(proof)};
}

Result<candidate::CircuitZkNormArgPublicationV4>
prove_circuit_zk_norm_arg_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(
      validate_circuit_proof_v4_inputs(circuit, public_commitments,
                                       secp_context,
                                       externalize_commitments),
      "prove_circuit_zk_norm_arg_v4:inputs");
  if (assignment.left.size() != circuit.n_gates ||
      assignment.right.size() != circuit.n_gates ||
      assignment.output.size() != circuit.n_gates ||
      assignment.commitments.size() != circuit.n_commitments) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "prove_circuit_zk_norm_arg_v4:assignment_shape");
  }
  if (!circuit.evaluate(assignment)) {
    return unexpected_error(ErrorCode::EquationMismatch,
                            "prove_circuit_zk_norm_arg_v4:assignment");
  }
  if (externalize_commitments) {
    PURIFY_RETURN_IF_ERROR(
        validate_public_commitments(public_commitments,
                                    assignment.commitments, secp_context),
        "prove_circuit_zk_norm_arg_v4:public_values");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding),
      "prove_circuit_zk_norm_arg_v4:binding_digest");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dimensions,
      circuit_norm_arg_dimensions(circuit, externalize_commitments),
      "prove_circuit_zk_norm_arg_v4:dimensions");
  PURIFY_ASSIGN_OR_RETURN(
      const auto shape, circuit_shape_v4(circuit, externalize_commitments),
      "prove_circuit_zk_norm_arg_v4:shape");

  std::size_t public_point_bytes = 0;
  std::size_t assignment_scalar_count = 0;
  std::size_t assignment_bytes = 0;
  std::size_t seed_prefix_size = 0;
  std::size_t seed_size = 0;
  if (!checked_mul_size(public_commitments.size(), sizeof(PointBytes),
                        public_point_bytes) ||
      !checked_add_size(assignment.left.size(), assignment.right.size(),
                        assignment_scalar_count) ||
      !checked_add_size(assignment_scalar_count, assignment.output.size(),
                        assignment_scalar_count) ||
      !checked_add_size(assignment_scalar_count,
                        assignment.commitments.size(),
                        assignment_scalar_count) ||
      !checked_mul_size(assignment_scalar_count, sizeof(ScalarBytes),
                        assignment_bytes) ||
      !checked_add_size(assignment_bytes, 4 * sizeof(std::uint64_t),
                        assignment_bytes) ||
      !checked_add_size(binding_digest.size(), secret_prover_seed.size(),
                        seed_prefix_size) ||
      !checked_add_size(seed_prefix_size, 1, seed_prefix_size) ||
      !checked_add_size(seed_prefix_size, public_point_bytes, seed_size) ||
      !checked_add_size(seed_size, assignment_bytes, seed_size)) {
    return unexpected_error(ErrorCode::Overflow,
                            "prove_circuit_zk_norm_arg_v4:seed_size");
  }
  SecretBytes seed;
  seed.value.reserve(seed_size);
  seed.value.insert(seed.value.end(), binding_digest.begin(),
                    binding_digest.end());
  seed.value.insert(seed.value.end(), secret_prover_seed.begin(),
                    secret_prover_seed.end());
  seed.value.push_back(externalize_commitments ? 1 : 0);
  for (const auto &point : public_commitments) {
    seed.value.insert(seed.value.end(), point.begin(), point.end());
  }
  const auto append_assignment_values =
      [&](std::span<const FieldElement> values) -> Status {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &count,
        narrow_size_to_u64(values.size(),
                           "prove_circuit_zk_norm_arg_v4:assignment_count"),
        "prove_circuit_zk_norm_arg_v4:assignment_count");
    append_u64_le(seed.value, count);
    for (const auto &value : values) {
      SecretScalarBytes encoded;
      purify_scalar_get_b32(
          encoded.value.data(),
          &::purify::detail::FieldElementAccess::raw(value));
      seed.value.insert(seed.value.end(), encoded.value.begin(),
                        encoded.value.end());
    }
    return {};
  };
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.left),
                         "prove_circuit_zk_norm_arg_v4:left_seed");
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.right),
                         "prove_circuit_zk_norm_arg_v4:right_seed");
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.output),
                         "prove_circuit_zk_norm_arg_v4:output_seed");
  PURIFY_RETURN_IF_ERROR(append_assignment_values(assignment.commitments),
                         "prove_circuit_zk_norm_arg_v4:commitment_seed");
  assert(seed.value.size() == seed_size);

  std::optional<Error> masked_failure;
  for (std::uint64_t attempt = 0; attempt < 32; ++attempt) {
    std::vector<FieldElement> padding(
        dimensions.l_vec_len - dimensions.used_l, FieldElement::zero());
    WipeVectorOnDestruction padding_wiper(padding);
    for (std::size_t i = 0; i < padding.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(padding[i], seed.value, kCircuitZkBlindV4TaggedHash,
                        i, attempt),
          "prove_circuit_zk_norm_arg_v4:blind");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto raw_inputs,
        build_raw_circuit_norm_arg_inputs(circuit, assignment, padding,
                                          externalize_commitments,
                                          secp_context),
        "prove_circuit_zk_norm_arg_v4:raw_inputs");
    WipeVectorOnDestruction raw_n_wiper(raw_inputs.n_vec);
    WipeVectorOnDestruction raw_l_wiper(raw_inputs.l_vec);
    auto raw_commitment =
        commit_norm_arg_witness_only(raw_inputs, secp_context, cache);
    if (!raw_commitment.has_value()) {
      if (!masked_failure.has_value()) masked_failure = raw_commitment.error();
      continue;
    }

    PURIFY_ASSIGN_OR_RETURN(
        const auto precommitment,
        candidate::derive_circuit_precommitment_v4(
            shape, binding_digest, public_commitments, *raw_commitment,
            secp_context),
        "prove_circuit_zk_norm_arg_v4:precommitment");
    const candidate::TranscriptDigest raw_generator_digest =
        generator_backend_cache_key(raw_inputs.generators);
    PURIFY_ASSIGN_OR_RETURN(
        auto transcript,
        candidate::CircuitProofTranscriptV4::create(
            shape, precommitment.digest, raw_generator_digest),
        "prove_circuit_zk_norm_arg_v4:transcript");
    const CircuitNormArgChallenges challenges{
        transcript.rho().scalar, transcript.mul_scale().scalar,
        transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
    PURIFY_ASSIGN_OR_RETURN(
        auto hidden,
        reduce_experimental_circuit_to_norm_arg(
            circuit, assignment, *raw_commitment, secp_context,
            statement_binding, externalize_commitments, cache, &challenges),
        "prove_circuit_zk_norm_arg_v4:reduce");
    if (generator_backend_cache_key(hidden.public_data->raw_generators) !=
        raw_generator_digest) {
      return unexpected_error(ErrorCode::InternalMismatch,
                              "prove_circuit_zk_norm_arg_v4:raw_basis");
    }
    WipeVectorOnDestruction hidden_n_wiper(hidden.n_vec);
    WipeVectorOnDestruction hidden_l_wiper(hidden.l_vec);
    std::copy(padding.begin(), padding.end(),
              hidden.l_vec.begin() + dimensions.used_l);

    PURIFY_ASSIGN_OR_RETURN(
        const auto &anchored_commitment,
        anchor_zk_a_commitment(*raw_commitment, *hidden.public_data,
                               public_commitments, secp_context),
        "prove_circuit_zk_norm_arg_v4:anchored_commitment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto &anchored_offset,
        point_subtract_allow_infinity(anchored_commitment, *raw_commitment,
                                      secp_context),
        "prove_circuit_zk_norm_arg_v4:anchored_offset");
    PURIFY_ASSIGN_OR_RETURN(
        const auto &coefficient_commitment,
        coefficient_commitment_v4(*hidden.public_data, secp_context),
        "prove_circuit_zk_norm_arg_v4:coefficient_commitment");
    PURIFY_ASSIGN_OR_RETURN(
        const auto &eta,
        transcript.append_anchored_commitments(
            coefficient_commitment, anchored_offset, anchored_commitment,
            secp_context),
        "prove_circuit_zk_norm_arg_v4:eta");

    PublicCommitmentDlogProof dlog_proof;
    if (externalize_commitments) {
      PURIFY_ASSIGN_OR_RETURN(
          const auto &batched,
          batch_public_commitments_with_eta(public_commitments, eta.scalar,
                                            secp_context),
          "prove_circuit_zk_norm_arg_v4:batch_public");
      const ScalarBytes nonce_binding = precommitment.digest.bytes();
      auto dlog = prove_public_commitment_dlog_v4(
          batched, assignment.commitments, nonce_binding,
          secret_prover_seed, secp_context,
          [&](const std::array<unsigned char, 32> &nonce)
              -> Result<FieldElement> {
            auto challenge = transcript.append_public_opening(
                batched.point, nonce, secp_context);
            if (!challenge.has_value()) {
              return unexpected_error(
                  challenge.error(),
                  "prove_circuit_zk_norm_arg_v4:dlog_e");
            }
            return challenge->scalar;
          });
      if (!dlog.has_value()) {
        if (!masked_failure.has_value()) masked_failure = dlog.error();
        continue;
      }
      dlog_proof = *dlog;
    } else {
      PURIFY_ASSIGN_OR_RETURN(
          const auto ignored,
          transcript.append_public_opening(
              PointBytes{}, dlog_proof.nonce_xonly, secp_context),
          "prove_circuit_zk_norm_arg_v4:hidden_dlog");
      (void)ignored;
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &dlog_response,
        FieldElement::try_from_bytes32(dlog_proof.response),
        "prove_circuit_zk_norm_arg_v4:dlog_response_scalar");
    PURIFY_RETURN_IF_ERROR(
        transcript.append_dlog_response(dlog_response),
        "prove_circuit_zk_norm_arg_v4:dlog_response");

    const ScalarBytes precommitment_bytes = precommitment.digest.bytes();
    std::size_t mask_seed_size = 0;
    if (!checked_add_size(seed.value.size(), precommitment_bytes.size(),
                          mask_seed_size)) {
      return unexpected_error(ErrorCode::Overflow,
                              "prove_circuit_zk_norm_arg_v4:mask_seed_size");
    }
    SecretBytes mask_seed;
    mask_seed.value.reserve(mask_seed_size);
    mask_seed.value.insert(mask_seed.value.end(), seed.value.begin(),
                           seed.value.end());
    mask_seed.value.insert(mask_seed.value.end(), precommitment_bytes.begin(),
                           precommitment_bytes.end());
    assert(mask_seed.value.size() == mask_seed_size);
    std::vector<FieldElement> mask_n(hidden.n_vec.size(),
                                     FieldElement::zero());
    WipeVectorOnDestruction mask_n_wiper(mask_n);
    for (std::size_t i = 0; i < mask_n.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(mask_n[i], mask_seed.value,
                        kCircuitZkMaskNV4TaggedHash, i, attempt),
          "prove_circuit_zk_norm_arg_v4:mask_n");
    }
    std::vector<FieldElement> mask_l(hidden.l_vec.size(),
                                     FieldElement::zero());
    WipeVectorOnDestruction mask_l_wiper(mask_l);
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      PURIFY_RETURN_IF_ERROR(
          derive_scalar(mask_l[i], mask_seed.value,
                        kCircuitZkMaskLV4TaggedHash, i, attempt),
          "prove_circuit_zk_norm_arg_v4:mask_l");
    }

    FieldElement t2 = weighted_bppp_inner_product(
        mask_n, mask_n, hidden.public_data->rho);
    WipeObjectOnDestruction t2_wiper(t2);
    if (t2.is_zero()) continue;
    FieldElement t1 =
        FieldElement::from_int(2) *
        weighted_bppp_inner_product(hidden.n_vec, mask_n,
                                    hidden.public_data->rho);
    WipeObjectOnDestruction t1_wiper(t1);
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      t1 = t1 + mask_l[i] * hidden.public_data->c_vec[i];
    }

    NormArgInputs mask_inputs;
    mask_inputs.rho = hidden.public_data->rho_bytes;
    mask_inputs.generators = hidden.public_data->generators;
    mask_inputs.n_vec = scalar_bytes(mask_n);
    mask_inputs.l_vec = scalar_bytes(mask_l);
    mask_inputs.c_vec = hidden.public_data->c_vec_bytes;
    WipeVectorOnDestruction mask_input_n_wiper(mask_inputs.n_vec);
    WipeVectorOnDestruction mask_input_l_wiper(mask_inputs.l_vec);
    auto mask_commitment =
        commit_explicit_norm_arg(mask_inputs, t1, secp_context, nullptr);
    if (!mask_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure = mask_commitment.error();
      }
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &alpha,
        transcript.append_mask(*mask_commitment, t2, secp_context),
        "prove_circuit_zk_norm_arg_v4:alpha");

    CircuitNormArgReduction masked = hidden;
    WipeVectorOnDestruction masked_n_wiper(masked.n_vec);
    WipeVectorOnDestruction masked_l_wiper(masked.l_vec);
    for (std::size_t i = 0; i < masked.n_vec.size(); ++i) {
      masked.n_vec[i] = masked.n_vec[i] + alpha.scalar * mask_n[i];
    }
    for (std::size_t i = 0; i < masked.l_vec.size(); ++i) {
      masked.l_vec[i] = masked.l_vec[i] + alpha.scalar * mask_l[i];
    }
    NormArgInputs masked_inputs = build_norm_arg_inputs(masked);
    WipeVectorOnDestruction masked_input_n_wiper(masked_inputs.n_vec);
    WipeVectorOnDestruction masked_input_l_wiper(masked_inputs.l_vec);
    auto combined_commitment = combine_zk_commitments(
        anchored_commitment, *mask_commitment, alpha.scalar, t2,
        secp_context);
    if (!combined_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure = combined_commitment.error();
      }
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto &direct_commitment,
        commit_norm_arg_with_cache(masked_inputs, secp_context, nullptr),
        "prove_circuit_zk_norm_arg_v4:direct_commitment");
    if (*combined_commitment != direct_commitment) {
      return unexpected_error(ErrorCode::InternalMismatch,
                              "prove_circuit_zk_norm_arg_v4:commitment");
    }
    PURIFY_RETURN_IF_ERROR(
        transcript.append_combined_commitment(*combined_commitment,
                                              secp_context),
        "prove_circuit_zk_norm_arg_v4:combined_transcript");

    auto norm = prove_norm_arg_to_commitment_v4(
        masked_inputs, *combined_commitment, transcript, secp_context);
    if (!norm.has_value()) {
      if (!masked_failure.has_value()) masked_failure = norm.error();
      continue;
    }
    ScalarBytes terminal_n{};
    ScalarBytes terminal_l{};
    PURIFY_ASSIGN_OR_RETURN(
        const auto &rounds,
        parse_norm_rounds_v4(norm->proof, shape.round_count(), terminal_n,
                             terminal_l),
        "prove_circuit_zk_norm_arg_v4:parse_norm");
    (void)rounds;
    PURIFY_ASSIGN_OR_RETURN(
        const auto &terminal_n_scalar,
        FieldElement::try_from_bytes32(terminal_n),
        "prove_circuit_zk_norm_arg_v4:terminal_n");
    PURIFY_ASSIGN_OR_RETURN(
        const auto &terminal_l_scalar,
        FieldElement::try_from_bytes32(terminal_l),
        "prove_circuit_zk_norm_arg_v4:terminal_l");
    PURIFY_ASSIGN_OR_RETURN(
        const auto finished,
        transcript.finish(terminal_n_scalar, terminal_l_scalar),
        "prove_circuit_zk_norm_arg_v4:finish_transcript");
    (void)finished;

    candidate::CircuitZkNormArgProofV4 proof{
        *raw_commitment,
        *mask_commitment,
        scalar_bytes(t2),
        dlog_proof.nonce_xonly,
        dlog_proof.response,
        std::move(norm->proof)};
    return candidate::CircuitZkNormArgPublicationV4{
        precommitment.digest, std::move(proof)};
  }

  if (masked_failure.has_value()) {
    return unexpected_error(*masked_failure,
                            "prove_circuit_zk_norm_arg_v4:attempts");
  }
  return unexpected_error(ErrorCode::BackendRejectedInput,
                          "prove_circuit_zk_norm_arg_v4:attempts");
}

} // namespace

Status candidate::validate_circuit_zk_norm_arg_proof_v4_fixed_encoding(
    const CircuitZkNormArgProofV4 &proof,
    CircuitCommitmentModeV4 mode, std::size_t round_count,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_fixed_encoding_impl(
      proof, mode, round_count, secp_context);
}

Status candidate::validate_circuit_zk_norm_arg_proof_v4_encoding(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgProofV4 &proof,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
      circuit, proof, {}, secp_context, false);
}

Status candidate::
validate_circuit_zk_norm_arg_proof_v4_encoding_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgProofV4 &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context) {
  return validate_circuit_zk_norm_arg_proof_v4_encoding_impl(
      circuit, proof, public_commitments, secp_context, true);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::reconstruct_circuit_zk_norm_arg_publication_v4(
    const NativeBulletproofCircuit &circuit,
    CircuitZkNormArgProofV4 proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  return reconstruct_circuit_zk_norm_arg_publication_v4_impl(
      circuit, std::move(proof), {}, secp_context, statement_binding,
      false);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::
reconstruct_circuit_zk_norm_arg_publication_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    CircuitZkNormArgProofV4 proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding) {
  return reconstruct_circuit_zk_norm_arg_publication_v4_impl(
      circuit, std::move(proof), public_commitments, secp_context,
      statement_binding, true);
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(
      validate_circuit_proof_v4_inputs(circuit, public_commitments,
                                       secp_context,
                                       externalize_commitments),
      "prepare_circuit_zk_norm_arg_v4:inputs");
  if (publication.proof.norm_proof.empty()) {
    return unexpected_error(ErrorCode::EmptyInput,
                            "prepare_circuit_zk_norm_arg_v4:proof");
  }
  if (is_identity_point_v4(publication.proof.raw_commitment) ||
      is_identity_point_v4(publication.proof.mask_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto shape, circuit_shape_v4(circuit, externalize_commitments),
      "prepare_circuit_zk_norm_arg_v4:shape");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding),
      "prepare_circuit_zk_norm_arg_v4:binding_digest");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &expected_precommitment,
      candidate::derive_circuit_precommitment_v4(
          shape, binding_digest, public_commitments,
          publication.proof.raw_commitment, secp_context),
      "prepare_circuit_zk_norm_arg_v4:precommitment");
  if (expected_precommitment.digest.bytes() !=
      publication.precommitment.bytes()) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &raw_generator_digest,
      raw_generator_digest_v4(shape, secp_context),
      "prepare_circuit_zk_norm_arg_v4:raw_generator_digest");
  PURIFY_ASSIGN_OR_RETURN(
      auto transcript,
      candidate::CircuitProofTranscriptV4::create(
          shape, publication.precommitment, raw_generator_digest),
      "prepare_circuit_zk_norm_arg_v4:transcript");
  const CircuitNormArgChallenges challenges{
      transcript.rho().scalar, transcript.mul_scale().scalar,
      transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(
          circuit, statement_binding, publication.proof.raw_commitment,
          secp_context, externalize_commitments, cache, &challenges),
      "prepare_circuit_zk_norm_arg_v4:public_data");
  if (generator_backend_cache_key(public_data->raw_generators) !=
      raw_generator_digest) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "prepare_circuit_zk_norm_arg_v4:raw_basis");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      anchor_zk_a_commitment(publication.proof.raw_commitment, *public_data,
                             public_commitments, secp_context),
      "prepare_circuit_zk_norm_arg_v4:anchored_commitment");
  if (is_identity_point_v4(anchored_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_offset,
      point_subtract_allow_infinity(anchored_commitment,
                                    publication.proof.raw_commitment,
                                    secp_context),
      "prepare_circuit_zk_norm_arg_v4:anchored_offset");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &coefficient_commitment,
      coefficient_commitment_v4(*public_data, secp_context),
      "prepare_circuit_zk_norm_arg_v4:coefficient_commitment");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &eta,
      transcript.append_anchored_commitments(
          coefficient_commitment, anchored_offset, anchored_commitment,
          secp_context),
      "prepare_circuit_zk_norm_arg_v4:eta");

  PointBytes batched_public_commitment{};
  std::optional<candidate::CircuitChallengeV4> staged_dlog_challenge;
  PublicCommitmentDlogProof dlog_proof{
      publication.proof.public_commitment_dlog_nonce,
      publication.proof.public_commitment_dlog_response};
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &batched,
        batch_public_commitments_with_eta(public_commitments, eta.scalar,
                                          secp_context),
        "prepare_circuit_zk_norm_arg_v4:batch_public");
    batched_public_commitment = batched.point;
    PURIFY_ASSIGN_OR_RETURN(
        const auto &dlog_challenge,
        transcript.append_public_opening(
            batched.point, dlog_proof.nonce_xonly, secp_context),
        "prepare_circuit_zk_norm_arg_v4:dlog_e");
    staged_dlog_challenge = dlog_challenge;
    PURIFY_ASSIGN_OR_RETURN(
        const bool dlog_valid,
        verify_public_commitment_dlog(batched, dlog_challenge.scalar,
                                      dlog_proof, secp_context),
        "prepare_circuit_zk_norm_arg_v4:dlog");
    if (!dlog_valid) {
      return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
    }
  } else {
    const auto all_zero = [](const auto &bytes) {
      return std::all_of(bytes.begin(), bytes.end(),
                         [](unsigned char byte) { return byte == 0; });
    };
    if (!all_zero(dlog_proof.nonce_xonly) ||
        !all_zero(dlog_proof.response)) {
      return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto hidden_dlog_challenge,
        transcript.append_public_opening(
            batched_public_commitment, dlog_proof.nonce_xonly, secp_context),
        "prepare_circuit_zk_norm_arg_v4:hidden_dlog");
    staged_dlog_challenge = hidden_dlog_challenge;
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &dlog_response,
      FieldElement::try_from_bytes32(dlog_proof.response),
      "prepare_circuit_zk_norm_arg_v4:dlog_response_scalar");
  PURIFY_RETURN_IF_ERROR(
      transcript.append_dlog_response(dlog_response),
      "prepare_circuit_zk_norm_arg_v4:dlog_response");

  PURIFY_ASSIGN_OR_RETURN(
      const auto &t2,
      FieldElement::try_from_bytes32(publication.proof.t2),
      "prepare_circuit_zk_norm_arg_v4:t2");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &alpha,
      transcript.append_mask(publication.proof.mask_commitment,
                             t2, secp_context),
      "prepare_circuit_zk_norm_arg_v4:alpha");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &combined_commitment,
      combine_zk_commitments(anchored_commitment,
                             publication.proof.mask_commitment,
                             alpha.scalar, t2, secp_context),
      "prepare_circuit_zk_norm_arg_v4:combined_commitment");
  if (is_identity_point_v4(combined_commitment)) {
    return std::optional<candidate::PreparedCircuitZkNormArgV4>{};
  }
  PURIFY_RETURN_IF_ERROR(
      transcript.append_combined_commitment(combined_commitment,
                                            secp_context),
      "prepare_circuit_zk_norm_arg_v4:combined_transcript");

  ScalarBytes terminal_n{};
  ScalarBytes terminal_l{};
  PURIFY_ASSIGN_OR_RETURN(
      const auto &rounds,
      parse_norm_rounds_v4(publication.proof.norm_proof,
                           shape.round_count(), terminal_n, terminal_l),
      "prepare_circuit_zk_norm_arg_v4:rounds");
  std::vector<candidate::CircuitChallengeV4> staged_gammas;
  staged_gammas.reserve(rounds.size());
  for (const auto &round : rounds) {
    PURIFY_ASSIGN_OR_RETURN(
        auto gamma, transcript.append_round(round, secp_context),
        "prepare_circuit_zk_norm_arg_v4:gamma");
    staged_gammas.push_back(std::move(gamma));
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &terminal_n_scalar,
      FieldElement::try_from_bytes32(terminal_n),
      "prepare_circuit_zk_norm_arg_v4:terminal_n");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &terminal_l_scalar,
      FieldElement::try_from_bytes32(terminal_l),
      "prepare_circuit_zk_norm_arg_v4:terminal_l");
  PURIFY_ASSIGN_OR_RETURN(
      const auto prepared_binding,
      transcript.finish(terminal_n_scalar, terminal_l_scalar),
      "prepare_circuit_zk_norm_arg_v4:finish");

  NormArgProof norm{public_data->rho_bytes,
                    public_data->generators,
                    public_data->c_vec_bytes,
                    public_data->n_vec_len,
                    combined_commitment,
                    publication.proof.norm_proof};
  ScalarBytes prepared_n{};
  ScalarBytes prepared_l{};
  candidate::CircuitProofTranscriptInputV4 transcript_input{
      raw_generator_digest,
      coefficient_commitment,
      anchored_offset,
      anchored_commitment,
      batched_public_commitment,
      dlog_proof.nonce_xonly,
      dlog_proof.response,
      publication.proof.mask_commitment,
      publication.proof.t2,
      combined_commitment,
      rounds,
      terminal_n,
      terminal_l};
  PURIFY_ASSIGN_OR_RETURN(
      auto transcript_result,
      candidate::derive_circuit_proof_transcript_v4(
          shape, publication.precommitment, transcript_input, secp_context),
      "prepare_circuit_zk_norm_arg_v4:replay");
  const auto same_challenge = [](const auto &lhs, const auto &rhs) {
    return lhs.lanes == rhs.lanes && lhs.scalar == rhs.scalar;
  };
  const bool matching_gammas =
      staged_gammas.size() == transcript_result.gammas.size() &&
      std::equal(staged_gammas.begin(), staged_gammas.end(),
                 transcript_result.gammas.begin(), same_challenge);
  if (!staged_dlog_challenge.has_value() ||
      !same_challenge(transcript.rho(), transcript_result.rho) ||
      !same_challenge(transcript.mul_scale(), transcript_result.mul_scale) ||
      !same_challenge(transcript.mul_ratio(), transcript_result.mul_ratio) ||
      !same_challenge(transcript.row_ratio(), transcript_result.row_ratio) ||
      !same_challenge(eta, transcript_result.eta) ||
      !same_challenge(*staged_dlog_challenge,
                      transcript_result.dlog_challenge) ||
      !same_challenge(alpha, transcript_result.alpha) || !matching_gammas ||
      !same_challenge(prepared_binding,
                      transcript_result.prepared_binding)) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "prepare_circuit_zk_norm_arg_v4:replay");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &residual,
      prepare_norm_arg_v4(norm, transcript_result.gammas, prepared_n,
                          prepared_l, secp_context),
      "prepare_circuit_zk_norm_arg_v4:norm");
  if (prepared_n != terminal_n || prepared_l != terminal_l) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "prepare_circuit_zk_norm_arg_v4:terminal");
  }
  return std::optional<candidate::PreparedCircuitZkNormArgV4>(
      candidate::PreparedCircuitZkNormArgV4(
          publication.precommitment, shape, binding_digest,
          publication.proof.raw_commitment,
          std::vector<PointBytes>(public_commitments.begin(),
                                  public_commitments.end()),
          public_data->raw_generators,
          std::move(transcript_input),
          std::move(transcript_result), std::move(norm), residual));
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::prove_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_circuit_zk_norm_arg_v4_impl(
      circuit, assignment, secret_prover_seed, {}, secp_context,
      statement_binding, false, cache);
}

Result<candidate::CircuitZkNormArgPublicationV4>
candidate::prove_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_circuit_zk_norm_arg_v4_impl(
      circuit, assignment, secret_prover_seed, public_commitments,
      secp_context, statement_binding, true, cache);
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prepare_circuit_zk_norm_arg_v4_impl(
      circuit, publication, {}, secp_context, statement_binding, false,
      cache);
}

Result<std::optional<candidate::PreparedCircuitZkNormArgV4>>
candidate::prepare_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prepare_circuit_zk_norm_arg_v4_impl(
      circuit, publication, public_commitments, secp_context,
      statement_binding, true, cache);
}

namespace {

Result<candidate::CircuitNormParentConstantsV4>
derive_circuit_norm_parent_constants_v4_impl(
    const NativeBulletproofCircuit &circuit,
    const candidate::CircuitPrecommitmentDigestV4 &precommitment,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitBackend *cache) {
  PURIFY_RETURN_IF_ERROR(
      validate_circuit_proof_v4_inputs(
          circuit, public_commitments, secp_context,
          externalize_commitments),
      "circuit_parent_constants_v4:inputs");
  for (const auto &point : public_commitments) {
    PURIFY_RETURN_IF_ERROR(
        validate_finite_point_v4(
            point, secp_context,
            "circuit_parent_constants_v4:public_commitment"),
        "circuit_parent_constants_v4:public_commitment");
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto binding_digest,
      circuit_binding_digest_v4(circuit, statement_binding),
      "circuit_parent_constants_v4:binding");
  PURIFY_ASSIGN_OR_RETURN(
      const auto shape,
      circuit_shape_v4(circuit, externalize_commitments),
      "circuit_parent_constants_v4:shape");
  PURIFY_ASSIGN_OR_RETURN(
      const auto raw_generator_digest,
      raw_generator_digest_v4(shape, secp_context),
      "circuit_parent_constants_v4:raw_basis");
  PURIFY_ASSIGN_OR_RETURN(
      const auto transcript,
      candidate::CircuitProofTranscriptV4::create(
          shape, precommitment, raw_generator_digest),
      "circuit_parent_constants_v4:transcript");
  const CircuitNormArgChallenges challenges{
      transcript.rho().scalar, transcript.mul_scale().scalar,
      transcript.mul_ratio().scalar, transcript.row_ratio().scalar};
  PURIFY_ASSIGN_OR_RETURN(
      const auto public_data,
      build_circuit_norm_arg_public_data_from_challenges(
          circuit, secp_context, externalize_commitments, cache,
          challenges),
      "circuit_parent_constants_v4:public_data");
  if (generator_backend_cache_key(public_data->raw_generators) !=
      raw_generator_digest) {
    return unexpected_error(ErrorCode::InternalMismatch,
                            "circuit_parent_constants_v4:raw_digest");
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto coefficient_commitment,
      coefficient_commitment_v4(*public_data, secp_context),
      "circuit_parent_constants_v4:coefficient_commitment");
  PURIFY_ASSIGN_OR_RETURN(
      auto anchored_offset,
      circuit_anchored_offset_v4(*public_data, public_commitments,
                                 secp_context),
      "circuit_parent_constants_v4:anchored_offset");
  return candidate::CircuitNormParentConstantsV4{
      std::move(binding_digest), std::move(coefficient_commitment),
      std::move(anchored_offset)};
}

} // namespace

Result<candidate::CircuitNormParentConstantsV4>
candidate::derive_circuit_norm_parent_constants_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitPrecommitmentDigestV4 &precommitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return derive_circuit_norm_parent_constants_v4_impl(
      circuit, precommitment, {}, secp_context, statement_binding, false,
      cache);
}

Result<candidate::CircuitNormParentConstantsV4>
candidate::derive_circuit_norm_parent_constants_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitPrecommitmentDigestV4 &precommitment,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return derive_circuit_norm_parent_constants_v4_impl(
      circuit, precommitment, public_commitments, secp_context,
      statement_binding, true, cache);
}

Result<bool> candidate::verify_circuit_zk_norm_arg_v4(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      prepare_circuit_zk_norm_arg_v4(circuit, publication, secp_context,
                                     statement_binding, cache),
      "verify_circuit_zk_norm_arg_v4:prepare");
  return prepared.has_value() &&
         verify_norm_arg_v4(prepared->norm(), prepared->transcript().gammas,
                            secp_context);
}

Result<bool>
candidate::verify_circuit_zk_norm_arg_v4_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const CircuitZkNormArgPublicationV4 &publication,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      prepare_circuit_zk_norm_arg_v4_with_public_commitments(
          circuit, publication, public_commitments, secp_context,
          statement_binding, cache),
      "verify_circuit_zk_norm_arg_v4_public:prepare");
  return prepared.has_value() &&
         verify_norm_arg_v4(prepared->norm(), prepared->transcript().gammas,
                            secp_context);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, secret_prover_seed, {}, secp_context,
      statement_binding, false, cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return verify_experimental_circuit_zk_norm_arg_impl(
      circuit, proof, secp_context, statement_binding, cache);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const ScalarBytes &secret_prover_seed,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, secret_prover_seed, public_commitments,
      secp_context, statement_binding, true, cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitBackend *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      auto prepared,
      detail::prepare_experimental_circuit_zk_norm_arg_with_public_commitments(
          circuit, proof, public_commitments, secp_context, statement_binding,
          cache),
      "verify_experimental_circuit_zk_norm_arg_with_public_commitments:prepare");
  if (!prepared.has_value()) {
    return false;
  }
  return verify_norm_arg_with_cache(prepared->norm, secp_context, nullptr);
}

Result<CommittedPurifyWitness>
commit_output_witness(const Bytes &message, const SecretKey &secret,
                      const ScalarBytes &blind, purify_secp_context *secp_context) {
  return commit_output_witness(message, secret, blind, secp_context,
                               value_generator_h(secp_context),
                               base_generator(secp_context));
}

Result<CommittedPurifyWitness>
commit_output_witness(const Bytes &message, const SecretKey &secret,
                      const ScalarBytes &blind, purify_secp_context *secp_context,
                      const GeneratorBytes &value_gen,
                      const GeneratorBytes &blind_gen) {
  PURIFY_ASSIGN_OR_RETURN(auto witness, prove_assignment_data(message, secret),
                          "commit_output_witness:prove_assignment_data");
  SecretScalarBytes output;
  purify_scalar_get_b32(
      output.value.data(),
      &::purify::detail::FieldElementAccess::raw(witness.output));
  PURIFY_ASSIGN_OR_RETURN(
      const auto &commitment,
      pedersen_commit_char(blind, output.value, secp_context, value_gen,
                           blind_gen),
      "commit_output_witness:pedersen_commit_char");
  return CommittedPurifyWitness{witness.public_key, witness.output,
                                std::move(witness.assignment), commitment};
}

} // namespace purify::bppp
