// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_support.hpp
 * @brief Secret buffers, byte views and scalar derivation shared by the BPPP translation units.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

#include "bppp_bridge.h"
#include "checked_size.hpp"
#include "purify/bppp.hpp"
#include "secure_cleanup.hpp"

namespace purify::bppp {

namespace detail {

using ::purify::detail::SecretVector;

using SecretBytes = SecretVector<unsigned char>;

using SecretScalarBytes = ::purify::detail::Secret<ScalarBytes>;

/** Norm-argument inputs whose witness vectors are erased on destruction. */
struct SecretNormArgInputs : NormArgInputs {
  SecretNormArgInputs() = default;
  SecretNormArgInputs(const SecretNormArgInputs &) = delete;
  SecretNormArgInputs &operator=(const SecretNormArgInputs &) = delete;
  SecretNormArgInputs(SecretNormArgInputs &&) noexcept = default;
  SecretNormArgInputs &operator=(SecretNormArgInputs &&) = delete;
  ~SecretNormArgInputs() {
    ::purify::detail::secure_erase(n_vec);
    ::purify::detail::secure_erase(l_vec);
  }
};

using ::purify::detail::CheckedSize;

using ::purify::detail::WipeOnDestruction;

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

struct ResolvedBpppGeneratorBackend {
  std::span<const unsigned char> serialized_bytes{};
  std::size_t generator_count = 0;
  purify_bppp_backend_resources *backend_resources = nullptr;
};

ResolvedBpppGeneratorBackend resolve_bppp_generator_backend(
    ExperimentalCircuitBackend *cache,
    const std::vector<PointBytes> &serialized_generators,
    purify_secp_context *secp_context);

Result<std::size_t> round_up_power_of_two(std::size_t value);

template <typename Allocator>
void append_u64_le(std::vector<unsigned char, Allocator> &out,
                   std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xffU));
  }
}

Result<FieldElement> derive_nonzero_scalar(std::span<const unsigned char> seed,
                                           const TaggedHash& tag,
                                           std::size_t index);

Status derive_scalar(FieldElement &out, std::span<const unsigned char> seed,
                     const TaggedHash &tag, std::size_t index,
                     std::uint64_t attempt = 0);

Status derive_secret_nonzero_scalar(FieldElement &out,
                                    std::span<const unsigned char> seed,
                                    const TaggedHash &tag,
                                    std::size_t index);

FieldElement weighted_bppp_inner_product(std::span<const FieldElement> lhs,
                                         std::span<const FieldElement> rhs,
                                         const FieldElement &rho);

} // namespace detail

} // namespace purify::bppp
