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

struct ExperimentalCircuitCache::Impl {
  std::unordered_map<CircuitNormArgPublicDataCacheKey,
                     std::shared_ptr<const void>,
                     CircuitNormArgPublicDataCacheKeyHash>
      public_data;
  std::unordered_map<GeneratorBackendCacheKey, OwnedBpppBackendResources,
                     GeneratorBackendCacheKeyHash>
      backend_resources;
};

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

std::shared_ptr<const void> ExperimentalCircuitCache::find_public_data(
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

void ExperimentalCircuitCache::insert_public_data(
    std::array<unsigned char, 32> key,
    std::shared_ptr<const void> value) {
  if (impl_ == nullptr) {
    return;
  }
  impl_->public_data.emplace(std::move(key), std::move(value));
}

purify_bppp_backend_resources *
ExperimentalCircuitCache::get_or_create_backend_resources(
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

  GeneratorBackendCacheKey key{};
  purify_sha256(key.data(), serialized, serialized_view.size());

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
    "Purify/BPPP/CircuitNormArg/Rho";
constexpr std::string_view kCircuitNormArgMulTag =
    "Purify/BPPP/CircuitNormArg/Mul";
constexpr std::string_view kCircuitNormArgConstraintTag =
    "Purify/BPPP/CircuitNormArg/Constraint";
constexpr std::string_view kCircuitNormArgPublicCommitmentTag =
    "Purify/BPPP/CircuitNormArg/PublicCommitments";
constexpr std::string_view kCircuitZkBlindTag =
    "Purify/BPPP/CircuitNormArg/ZKBlind";
constexpr std::string_view kCircuitZkMaskNTag =
    "Purify/BPPP/CircuitNormArg/ZKMaskN";
constexpr std::string_view kCircuitZkMaskLTag =
    "Purify/BPPP/CircuitNormArg/ZKMaskL";
constexpr std::string_view kCircuitZkChallengeTag =
    "Purify/BPPP/CircuitNormArg/ZKChallenge";
const TaggedHash kCircuitNormArgRhoTaggedHash(kCircuitNormArgRhoTag);
const TaggedHash kCircuitNormArgMulTaggedHash(kCircuitNormArgMulTag);
const TaggedHash kCircuitNormArgConstraintTaggedHash(kCircuitNormArgConstraintTag);
const TaggedHash kCircuitZkBlindTaggedHash(kCircuitZkBlindTag);
const TaggedHash kCircuitZkMaskNTaggedHash(kCircuitZkMaskNTag);
const TaggedHash kCircuitZkMaskLTaggedHash(kCircuitZkMaskLTag);
const TaggedHash kCircuitZkChallengeTaggedHash(kCircuitZkChallengeTag);

struct ResolvedBpppGeneratorBackend {
  std::span<const unsigned char> serialized_bytes{};
  std::size_t generator_count = 0;
  purify_bppp_backend_resources *backend_resources = nullptr;
};

ResolvedBpppGeneratorBackend resolve_bppp_generator_backend(
    ExperimentalCircuitCache *cache,
    const std::vector<PointBytes> &serialized_generators,
    purify_secp_context *secp_context) {
  ResolvedBpppGeneratorBackend out;
  out.serialized_bytes = byte_span(serialized_generators);
  out.generator_count = serialized_generators.size();

  if (cache == nullptr || serialized_generators.empty()) {
    return out;
  }
  out.backend_resources =
      cache->get_or_create_backend_resources(serialized_generators, secp_context);
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

CircuitNormArgPublicDataCacheKey circuit_norm_arg_public_data_cache_key(
    std::span<const unsigned char> binding_digest,
    bool externalize_commitments) {
  CircuitNormArgPublicDataCacheKey key{};
  const unsigned char mode = externalize_commitments ? '\x01' : '\x00';
  const std::array<const unsigned char *, 2> items{
      {&mode, binding_digest.data()}};
  const std::array<size_t, 2> item_lens{{1, binding_digest.size()}};
  const int ok = purify_sha256_many(key.data(), items.data(), item_lens.data(),
                                    items.size());
  assert(ok != 0 &&
         "circuit norm arg public data cache key generation must succeed");
  (void)ok;
  return key;
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

Result<FieldElement> derive_scalar(std::span<const unsigned char> seed,
                                   const TaggedHash& tag, std::size_t index,
                                   std::uint64_t attempt = 0) {
  Bytes prefix(seed.begin(), seed.end());
  PURIFY_ASSIGN_OR_RETURN(const auto &encoded_index,
                          narrow_size_to_u64(index, "derive_scalar:index"),
                          "derive_scalar:index");
  append_u64_le(prefix, encoded_index);
  append_u64_le(prefix, attempt);
  for (std::uint64_t counter = 0; counter < 256; ++counter) {
    Bytes input = prefix;
    append_u64_le(input, counter);
    ScalarBytes candidate_bytes{};
    candidate_bytes =
        tag.digest(std::span<const unsigned char>(input.data(), input.size()));
    Result<FieldElement> candidate =
        FieldElement::try_from_bytes32(candidate_bytes);
    if (candidate.has_value()) {
      return candidate;
    }
  }
  return unexpected_error(ErrorCode::InternalMismatch,
                          "derive_scalar:exhausted");
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
  ScalarBytes rho_bytes{};
  FieldElement target = FieldElement::zero();
  std::vector<PointBytes> generators;
  std::vector<FieldElement> c_vec;
  std::vector<ScalarBytes> c_vec_bytes;
  std::vector<FieldElement> public_commitment_coeffs;
  std::vector<std::array<FieldElement, 2>> plus_terms;
  std::vector<std::array<FieldElement, 2>> minus_terms;
  std::vector<FieldElement> plus_shift;
  std::vector<FieldElement> minus_shift;
};

using CircuitNormArgPublicDataPtr =
    std::shared_ptr<const CircuitNormArgPublicData>;

struct CircuitNormArgReduction {
  CircuitNormArgPublicDataPtr public_data;
  std::vector<FieldElement> n_vec;
  std::vector<FieldElement> l_vec;
};

Result<CircuitNormArgPublicDataPtr> build_circuit_norm_arg_public_data(
    const NativeBulletproofCircuit &circuit,
    std::span<const unsigned char> statement_binding,
    purify_secp_context *secp_context,
    bool externalize_commitments = false,
    ExperimentalCircuitCache *cache = nullptr) {
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

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      experimental_circuit_binding_digest(circuit, statement_binding),
      "build_circuit_norm_arg_public_data:binding_digest");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &rho,
      derive_nonzero_scalar(binding_digest, kCircuitNormArgRhoTaggedHash, 0),
      "build_circuit_norm_arg_public_data:rho");
  CircuitNormArgPublicDataCacheKey cache_key =
      circuit_norm_arg_public_data_cache_key(binding_digest,
                                             externalize_commitments);
  if (std::shared_ptr<const void> cached =
          cache != nullptr ? cache->find_public_data(cache_key)
                           : std::shared_ptr<const void>{}) {
    return std::static_pointer_cast<const CircuitNormArgPublicData>(cached);
  }

  std::optional<FieldElement> sqrt_minus_one =
      FieldElement::one().negate().sqrt();
  if (!sqrt_minus_one.has_value()) {
    return unexpected_error(
        ErrorCode::InternalMismatch,
        "build_circuit_norm_arg_public_data:sqrt_minus_one");
  }

  const FieldElement zero = FieldElement::zero();
  const FieldElement one = FieldElement::one();
  const FieldElement two = FieldElement::from_int(2);
  const FieldElement four = FieldElement::from_int(4);
  const FieldElement inv2 = two.inverse();
  const FieldElement inv4 = four.inverse();

  std::vector<FieldElement> mul_weights(circuit.n_gates, zero);
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &challenge,
        derive_nonzero_scalar(binding_digest, kCircuitNormArgMulTaggedHash, i),
        "build_circuit_norm_arg_public_data:mul_weight");
    mul_weights[i] = challenge;
  }

  std::vector<FieldElement> row_weights(circuit.c.size(), zero);
  for (std::size_t i = 0; i < circuit.c.size(); ++i) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto &challenge,
        derive_nonzero_scalar(binding_digest, kCircuitNormArgConstraintTaggedHash,
                              i),
        "build_circuit_norm_arg_public_data:constraint_weight");
    row_weights[i] = challenge;
  }

  std::vector<FieldElement> left_coeffs(circuit.n_gates, zero);
  std::vector<FieldElement> right_coeffs(circuit.n_gates, zero);
  std::vector<FieldElement> output_coeffs(circuit.n_gates, zero);
  std::vector<FieldElement> commitment_coeffs(circuit.n_commitments, zero);
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
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
  out->plus_terms.resize(circuit.n_gates);
  out->minus_terms.resize(circuit.n_gates);
  out->plus_shift.resize(circuit.n_gates, zero);
  out->minus_shift.resize(circuit.n_gates, zero);

  auto two_square_terms = [&](const FieldElement &coefficient) {
    const FieldElement first = (coefficient + one) * inv2;
    const FieldElement second = *sqrt_minus_one * (coefficient - one) * inv2;
    return std::array<FieldElement, 2>{first, second};
  };

  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    const FieldElement d_plus = mul_weights[i] * inv4;
    const FieldElement d_minus = d_plus.negate();
    const FieldElement e_plus = (left_coeffs[i] + right_coeffs[i]) * inv2;
    const FieldElement e_minus = (left_coeffs[i] - right_coeffs[i]) * inv2;

    out->plus_shift[i] = e_plus * (two * d_plus).inverse();
    out->minus_shift[i] = e_minus * (two * d_minus).inverse();
    constant = constant - ((e_plus * e_plus) * (four * d_plus).inverse());
    constant = constant - ((e_minus * e_minus) * (four * d_minus).inverse());
    out->plus_terms[i] = two_square_terms(d_plus);
    out->minus_terms[i] = two_square_terms(d_minus);
  }

  std::size_t l_value_count = 0;
  if (!checked_add_size(circuit.n_gates,
                        externalize_commitments ? 0 : circuit.n_commitments,
                        l_value_count) ||
      !checked_add_size(l_value_count, 1, l_value_count)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "build_circuit_norm_arg_public_data:l_value_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &l_vec_len,
      round_up_power_of_two(std::max<std::size_t>(1, l_value_count),
                            "build_circuit_norm_arg_public_data:l_vec_len"),
      "build_circuit_norm_arg_public_data:l_vec_len");
  out->c_vec.assign(l_vec_len, zero);
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    out->c_vec[i] = output_coeffs[i];
  }
  if (externalize_commitments) {
    out->public_commitment_coeffs = std::move(commitment_coeffs);
  } else {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out->c_vec[circuit.n_gates + i] = commitment_coeffs[i];
    }
  }
  out->target = constant.negate();
  out->c_vec_bytes = scalar_bytes(out->c_vec);

  std::size_t witness_generator_count = 0;
  std::size_t generator_count = 0;
  if (!checked_mul_size(circuit.n_gates, 4, witness_generator_count) ||
      !checked_add_size(witness_generator_count, out->c_vec.size(),
                        generator_count)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "build_circuit_norm_arg_public_data:generator_count");
  }
  PURIFY_ASSIGN_OR_RETURN(
      auto generators, create_generators(generator_count, secp_context),
      "build_circuit_norm_arg_public_data:create_generators");
  out->generators = std::move(generators);
  CircuitNormArgPublicDataPtr shared = out;
  if (cache != nullptr) {
    cache->insert_public_data(cache_key, shared);
  }
  return shared;
}

Result<CircuitNormArgReduction> reduce_experimental_circuit_to_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments = false,
    ExperimentalCircuitCache *cache = nullptr) {
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
      build_circuit_norm_arg_public_data(circuit, statement_binding, secp_context,
                                         externalize_commitments, cache),
      "reduce_experimental_circuit_to_norm_arg:public_data");

  CircuitNormArgReduction out;
  out.public_data = public_data;
  std::size_t n_vec_capacity = 0;
  if (!checked_mul_size(circuit.n_gates, 4, n_vec_capacity)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "reduce_experimental_circuit_to_norm_arg:n_vec_capacity");
  }
  out.n_vec.reserve(n_vec_capacity);
  out.l_vec.assign(out.public_data->c_vec.size(), FieldElement::zero());

  const FieldElement rho_inv = out.public_data->rho.inverse();
  FieldElement rho_weight_inv = rho_inv;
  for (std::size_t i = 0; i < circuit.n_gates; ++i) {
    const FieldElement plus_value = assignment.left[i] + assignment.right[i] +
                                    out.public_data->plus_shift[i];
    for (const FieldElement &term : out.public_data->plus_terms[i]) {
      out.n_vec.push_back(term * plus_value * rho_weight_inv);
      rho_weight_inv = rho_weight_inv * rho_inv;
    }

    const FieldElement minus_value = assignment.left[i] - assignment.right[i] +
                                     out.public_data->minus_shift[i];
    for (const FieldElement &term : out.public_data->minus_terms[i]) {
      out.n_vec.push_back(term * minus_value * rho_weight_inv);
      rho_weight_inv = rho_weight_inv * rho_inv;
    }

    out.l_vec[i] = assignment.output[i];
  }
  if (!externalize_commitments) {
    for (std::size_t i = 0; i < circuit.n_commitments; ++i) {
      out.l_vec[circuit.n_gates + i] = assignment.commitments[i];
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
                             ExperimentalCircuitCache *cache = nullptr) {
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
  ScalarBytes scalar32 = scalar_bytes(scalar);
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "offset_commitment:secp_context"),
                         "offset_commitment:secp_context");
  if (!require_ok(purify_bppp_offset_commitment(secp_context, commitment.data(),
                                                scalar32.data(), out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "offset_commitment:backend");
  }
  return out;
}

Result<PointBytes> point_scale(const PointBytes &point,
                               const FieldElement &scalar,
                               purify_secp_context *secp_context) {
  PointBytes out{};
  ScalarBytes scalar32 = scalar_bytes(scalar);
  PURIFY_RETURN_IF_ERROR(require_secp_context(secp_context, "point_scale:secp_context"),
                         "point_scale:secp_context");
  if (!require_ok(
          purify_point_scale(secp_context, point.data(), scalar32.data(),
                             out.data()))) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "point_scale:backend");
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

Result<PointBytes> point_from_scalar_base(const FieldElement &scalar,
                                          purify_secp_context *secp_context) {
  ScalarBytes blind{};
  return pedersen_commit_char(blind, scalar_bytes(scalar), secp_context,
                              base_generator(secp_context),
                              base_generator(secp_context));
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

Result<PointBytes> add_scaled_points(const PointBytes &base_commitment,
                                     std::span<const PointBytes> points,
                                     std::span<const FieldElement> scalars,
                                     purify_secp_context *secp_context) {
  if (points.size() != scalars.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "add_scaled_points:size_mismatch");
  }

  PointBytes out = base_commitment;
  for (std::size_t i = 0; i < points.size(); ++i) {
    if (scalars[i].is_zero()) {
      continue;
    }
    PURIFY_ASSIGN_OR_RETURN(const auto &scaled, point_scale(points[i], scalars[i], secp_context),
                            "add_scaled_points:scale");
    PURIFY_ASSIGN_OR_RETURN(const auto &combined, point_add(out, scaled, secp_context),
                            "add_scaled_points:add");
    out = combined;
  }
  return out;
}

Result<PointBytes>
anchor_zk_a_commitment(const PointBytes &a_witness_commitment,
                       const CircuitNormArgPublicData &public_data,
                       std::span<const PointBytes> public_commitments,
                       purify_secp_context *secp_context) {
  if (public_commitments.size() !=
      public_data.public_commitment_coeffs.size()) {
    return unexpected_error(ErrorCode::SizeMismatch,
                            "anchor_zk_a_commitment:public_commitment_size");
  }

  PURIFY_ASSIGN_OR_RETURN(
      auto anchored, offset_commitment(a_witness_commitment, public_data.target, secp_context),
      "anchor_zk_a_commitment:target");
  if (public_commitments.empty()) {
    return anchored;
  }

  std::vector<FieldElement> negated_coeffs;
  negated_coeffs.reserve(public_data.public_commitment_coeffs.size());
  for (const FieldElement &coeff : public_data.public_commitment_coeffs) {
    negated_coeffs.push_back(coeff.negate());
  }
  return add_scaled_points(anchored, public_commitments, negated_coeffs, secp_context);
}

Result<PointBytes>
commit_explicit_norm_arg(const NormArgInputs &inputs, const FieldElement &value,
                         purify_secp_context *secp_context,
                         ExperimentalCircuitCache *cache = nullptr) {
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
                    ExperimentalCircuitCache *cache = nullptr) {
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
                           ExperimentalCircuitCache *cache = nullptr) {
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
    ExperimentalCircuitCache *cache = nullptr) {
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

bool verify_norm_arg_with_cache(const NormArgProof &proof,
                                purify_secp_context *secp_context,
                                ExperimentalCircuitCache *cache = nullptr) {
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
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &reduction,
      reduce_experimental_circuit_to_norm_arg(circuit, assignment, secp_context,
                                              statement_binding, false, cache),
      "commit_experimental_circuit_witness:reduce");
  return commit_norm_arg_witness_only(build_norm_arg_inputs(reduction), secp_context, cache);
}

Result<ExperimentalCircuitNormArgProof>
prove_experimental_circuit_norm_arg_to_commitment(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    const PointBytes &witness_commitment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
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
      const auto &reduction,
      reduce_experimental_circuit_to_norm_arg(circuit, assignment, secp_context,
                                              statement_binding, false, cache),
      "prove_experimental_circuit_norm_arg_to_commitment:reduce");

  NormArgInputs inputs = build_norm_arg_inputs(reduction);
  PURIFY_ASSIGN_OR_RETURN(
      const auto &computed_witness_commitment,
      commit_norm_arg_witness_only(inputs, secp_context, cache),
      "prove_experimental_circuit_norm_arg_to_commitment:commit_witness");
  if (computed_witness_commitment != witness_commitment) {
    return unexpected_error(ErrorCode::BackendRejectedInput,
                            "prove_experimental_circuit_norm_arg_to_commitment:"
                            "witness_commitment_mismatch");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      offset_commitment(witness_commitment, reduction.public_data->target, secp_context),
      "prove_experimental_circuit_norm_arg_to_commitment:anchor");

  PURIFY_ASSIGN_OR_RETURN(
      auto proof,
      prove_norm_arg_to_commitment_with_cache(inputs, anchored_commitment, secp_context, cache),
      "prove_experimental_circuit_norm_arg_to_commitment:prove");
  return ExperimentalCircuitNormArgProof{witness_commitment,
                                         std::move(proof.proof)};
}

Result<ExperimentalCircuitNormArgProof> prove_experimental_circuit_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  PURIFY_ASSIGN_OR_RETURN(
      const auto &witness_commitment,
      commit_experimental_circuit_witness(circuit, assignment, secp_context, statement_binding,
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
    ExperimentalCircuitCache *cache) {
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
      build_circuit_norm_arg_public_data(circuit, statement_binding, secp_context, false,
                                         cache),
      "verify_experimental_circuit_norm_arg:public_data");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &anchored_commitment,
      offset_commitment(proof.witness_commitment, public_data->target, secp_context),
      "verify_experimental_circuit_norm_arg:anchor");

  NormArgProof bundle;
  bundle.rho = public_data->rho_bytes;
  bundle.generators = public_data->generators;
  bundle.c_vec = public_data->c_vec_bytes;
  if (!checked_mul_size(circuit.n_gates, 4, bundle.n_vec_len)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "verify_experimental_circuit_norm_arg:n_vec_len");
  }
  bundle.commitment = anchored_commitment;
  bundle.proof = proof.proof;
  return verify_norm_arg_with_cache(bundle, secp_context, cache);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment, const ScalarBytes &nonce,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitCache *cache) {
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
    PURIFY_RETURN_IF_ERROR(
        validate_public_commitments(public_commitments, assignment.commitments, secp_context),
        "prove_experimental_circuit_zk_norm_arg_impl:"
        "validate_public_commitments");
  }

  PURIFY_ASSIGN_OR_RETURN(
      const auto &base_reduction,
      reduce_experimental_circuit_to_norm_arg(circuit, assignment, secp_context,
                                              bound_statement_binding,
                                              externalize_commitments, cache),
      "prove_experimental_circuit_zk_norm_arg_impl:reduce");

  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      experimental_circuit_binding_digest(circuit, bound_statement_binding),
      "prove_experimental_circuit_zk_norm_arg_impl:binding_digest");
  Bytes seed = binding_digest;
  seed.insert(seed.end(), nonce.begin(), nonce.end());
  std::size_t used_l = 0;
  if (!checked_add_size(circuit.n_gates,
                        externalize_commitments ? 0 : circuit.n_commitments,
                        used_l)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "prove_experimental_circuit_zk_norm_arg_impl:used_l");
  }
  std::optional<Error> masked_failure;

  for (std::uint64_t attempt = 0; attempt < 32; ++attempt) {
    CircuitNormArgReduction hidden = base_reduction;
    for (std::size_t i = used_l; i < hidden.l_vec.size(); ++i) {
      PURIFY_ASSIGN_OR_RETURN(
          const auto &blind,
          derive_scalar(seed, kCircuitZkBlindTaggedHash, i - used_l, attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:blind");
      hidden.l_vec[i] = blind;
    }

    std::vector<FieldElement> mask_n(hidden.n_vec.size(), FieldElement::zero());
    for (std::size_t i = 0; i < mask_n.size(); ++i) {
      PURIFY_ASSIGN_OR_RETURN(
          const auto &value,
          derive_scalar(seed, kCircuitZkMaskNTaggedHash, i, attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:mask_n");
      mask_n[i] = value;
    }

    std::vector<FieldElement> mask_l(hidden.l_vec.size(), FieldElement::zero());
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      PURIFY_ASSIGN_OR_RETURN(
          const auto &value,
          derive_scalar(seed, kCircuitZkMaskLTaggedHash, i, attempt),
          "prove_experimental_circuit_zk_norm_arg_impl:mask_l");
      mask_l[i] = value;
    }

    const FieldElement t2 =
        weighted_bppp_inner_product(mask_n, mask_n, hidden.public_data->rho);
    if (t2.is_zero()) {
      continue;
    }
    FieldElement t1 = FieldElement::from_int(2) *
                      weighted_bppp_inner_product(hidden.n_vec, mask_n,
                                                  hidden.public_data->rho);
    for (std::size_t i = 0; i < mask_l.size(); ++i) {
      t1 = t1 + (mask_l[i] * hidden.public_data->c_vec[i]);
    }

    NormArgInputs hidden_inputs = build_norm_arg_inputs(hidden);
    NormArgInputs mask_inputs;
    mask_inputs.rho = hidden.public_data->rho_bytes;
    mask_inputs.generators = hidden.public_data->generators;
    mask_inputs.n_vec = scalar_bytes(mask_n);
    mask_inputs.l_vec = scalar_bytes(mask_l);
    mask_inputs.c_vec = hidden.public_data->c_vec_bytes;

    Result<PointBytes> a_witness_commitment =
        commit_norm_arg_witness_only(hidden_inputs, secp_context, cache);
    if (!a_witness_commitment.has_value()) {
      if (!masked_failure.has_value()) {
        masked_failure = unexpected_error(a_witness_commitment.error(),
                                          "prove_experimental_circuit_zk_norm_"
                                          "arg_impl:a_witness_commitment")
                             .error();
      }
      continue;
    }
    Result<PointBytes> a_commitment = anchor_zk_a_commitment(
        *a_witness_commitment, *hidden.public_data, public_commitments, secp_context);
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
        commit_explicit_norm_arg(mask_inputs, t1, secp_context, cache);
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
        derive_zk_challenge(binding_digest, *a_commitment, *s_commitment, t2),
        "prove_experimental_circuit_zk_norm_arg_impl:challenge");

    CircuitNormArgReduction masked = hidden;
    for (std::size_t i = 0; i < masked.n_vec.size(); ++i) {
      masked.n_vec[i] = masked.n_vec[i] + (challenge * mask_n[i]);
    }
    for (std::size_t i = 0; i < masked.l_vec.size(); ++i) {
      masked.l_vec[i] = masked.l_vec[i] + (challenge * mask_l[i]);
    }
    NormArgInputs masked_inputs = build_norm_arg_inputs(masked);

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
        commit_norm_arg_with_cache(masked_inputs, secp_context, cache);
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
        masked_inputs, *combined_commitment, secp_context, cache);
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
    return ExperimentalCircuitZkNormArgProof{*a_witness_commitment,
                                             *s_commitment, scalar_bytes(t2),
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

Result<bool> verify_experimental_circuit_zk_norm_arg_impl(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    bool externalize_commitments, ExperimentalCircuitCache *cache) {
  if (!circuit.has_valid_shape()) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "verify_experimental_circuit_zk_norm_arg_impl:circuit_shape");
  }
  if (!is_power_of_two_size(circuit.n_gates)) {
    return unexpected_error(
        ErrorCode::InvalidDimensions,
        "verify_experimental_circuit_zk_norm_arg_impl:n_gates_power_of_two");
  }
  if (proof.proof.empty()) {
    return unexpected_error(
        ErrorCode::EmptyInput,
        "verify_experimental_circuit_zk_norm_arg_impl:proof_empty");
  }

  Bytes bound_statement_binding;
  if (externalize_commitments) {
    PURIFY_ASSIGN_OR_RETURN(
        bound_statement_binding,
        bind_public_commitments(public_commitments, statement_binding),
        "verify_experimental_circuit_zk_norm_arg_impl:bound_statement_binding");
  } else {
    bound_statement_binding =
        Bytes(statement_binding.begin(), statement_binding.end());
  }
  PURIFY_ASSIGN_OR_RETURN(
      const auto &public_data,
      build_circuit_norm_arg_public_data(circuit, bound_statement_binding, secp_context,
                                         externalize_commitments, cache),
      "verify_experimental_circuit_zk_norm_arg_impl:public_data");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &t2, FieldElement::try_from_bytes32(proof.t2),
      "verify_experimental_circuit_zk_norm_arg_impl:t2");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &a_commitment,
      anchor_zk_a_commitment(proof.a_commitment, *public_data, public_commitments, secp_context),
      "verify_experimental_circuit_zk_norm_arg_impl:a_commitment");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &binding_digest,
      experimental_circuit_binding_digest(circuit, bound_statement_binding),
      "verify_experimental_circuit_zk_norm_arg_impl:binding_digest");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &challenge,
      derive_zk_challenge(binding_digest, a_commitment, proof.s_commitment, t2),
      "verify_experimental_circuit_zk_norm_arg_impl:challenge");
  PURIFY_ASSIGN_OR_RETURN(
      const auto &commitment,
      combine_zk_commitments(a_commitment, proof.s_commitment, challenge, t2, secp_context),
      "verify_experimental_circuit_zk_norm_arg_impl:commitment");

  NormArgProof bundle;
  bundle.rho = public_data->rho_bytes;
  bundle.generators = public_data->generators;
  bundle.c_vec = public_data->c_vec_bytes;
  if (!checked_mul_size(circuit.n_gates, 4, bundle.n_vec_len)) {
    return unexpected_error(
        ErrorCode::Overflow,
        "verify_experimental_circuit_zk_norm_arg_impl:n_vec_len");
  }
  bundle.commitment = commitment;
  bundle.proof = proof.proof;
  return verify_norm_arg_with_cache(bundle, secp_context, cache);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment, const ScalarBytes &nonce,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, nonce, {}, secp_context, statement_binding, false, cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  return verify_experimental_circuit_zk_norm_arg_impl(
      circuit, proof, {}, secp_context, statement_binding, false, cache);
}

Result<ExperimentalCircuitZkNormArgProof>
prove_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const BulletproofAssignmentData &assignment, const ScalarBytes &nonce,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  return prove_experimental_circuit_zk_norm_arg_impl(
      circuit, assignment, nonce, public_commitments, secp_context, statement_binding, true,
      cache);
}

Result<bool> verify_experimental_circuit_zk_norm_arg_with_public_commitments(
    const NativeBulletproofCircuit &circuit,
    const ExperimentalCircuitZkNormArgProof &proof,
    std::span<const PointBytes> public_commitments,
    purify_secp_context *secp_context,
    std::span<const unsigned char> statement_binding,
    ExperimentalCircuitCache *cache) {
  return verify_experimental_circuit_zk_norm_arg_impl(
      circuit, proof, public_commitments, secp_context, statement_binding, true, cache);
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
  PURIFY_ASSIGN_OR_RETURN(
      const auto &commitment,
      pedersen_commit_char(blind, scalar_bytes(witness.output), secp_context, value_gen,
                           blind_gen),
      "commit_output_witness:pedersen_commit_char");
  return CommittedPurifyWitness{witness.public_key, witness.output,
                                std::move(witness.assignment), commitment};
}

} // namespace purify::bppp
