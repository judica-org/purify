// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_backend_cache.cpp
 * @brief Reusable BPPP backend resources and reduced-circuit public data, keyed by generator set.
 */

#include "purify/bppp.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <unordered_map>
#include <utility>

#include "bppp_backend_cache.hpp"
#include "bppp_bridge.h"
#include "purify/secp_bridge.h"

namespace purify::bppp {

struct BpppBackendResourcesDeleter {
  void operator()(purify_bppp_backend_resources *resources) const noexcept {
    purify_bppp_backend_resources_destroy(resources);
  }
};

using OwnedBpppBackendResources =
    std::unique_ptr<purify_bppp_backend_resources, BpppBackendResourcesDeleter>;

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
    return unexpected_error(ErrorCode::BackendRejectedInput);
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

} // namespace purify::bppp
