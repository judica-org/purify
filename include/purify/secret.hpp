// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file secret.hpp
 * @brief Secret-owning Purify key material wrappers.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

#include "purify/curve.hpp"

namespace purify::detail {

inline void secure_clear_bytes(void* data, std::size_t size) noexcept {
    volatile unsigned char* out = reinterpret_cast<volatile unsigned char*>(data);
    while (size != 0) {
        *out = 0;
        ++out;
        --size;
    }
}

struct SecureUInt512Deleter {
    void operator()(UInt512* value) const noexcept {
        if (value == nullptr) {
            return;
        }
        static_assert(std::is_trivially_destructible_v<UInt512>);
        secure_clear_bytes(value, sizeof(UInt512));
        delete value;
    }
};

}  // namespace purify::detail

namespace purify {

/**
 * @brief Move-only packed Purify secret stored in dedicated heap memory.
 *
 * The packed secret is validated on construction, zeroized on destruction, and never copied
 * implicitly. Call `clone()` when an additional owned copy is intentionally required.
 */
class SecretKey {
public:
    SecretKey() = delete;
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    SecretKey(SecretKey&&) noexcept = default;
    SecretKey& operator=(SecretKey&&) noexcept = default;
    ~SecretKey() = default;

    /**
     * @brief Constructs a validated secret key from packed Purify secret bytes.
     * @param packed Packed secret scalar pair.
     * @return Owned secret key on success, or `ErrorCode::RangeViolation` if `packed` is invalid.
     */
    [[nodiscard]] static Result<SecretKey> from_packed(const UInt512& packed) {
        Status status = validate_secret_key(packed);
        if (!status.has_value()) {
            return unexpected_error(status.error(), "SecretKey::from_packed:validate_secret_key");
        }
        return SecretKey(std::unique_ptr<UInt512, detail::SecureUInt512Deleter>(new UInt512(packed)));
    }

    /**
     * @brief Parses and validates a packed Purify secret from hexadecimal text.
     * @param hex Hex string containing exactly one packed secret.
     * @return Owned secret key on success, or a parsing/validation error.
     */
    [[nodiscard]] static Result<SecretKey> from_hex(std::string_view hex) {
        Result<UInt512> packed = UInt512::try_from_hex(hex);
        if (!packed.has_value()) {
            return unexpected_error(packed.error(), "SecretKey::from_hex:try_from_hex");
        }
        return from_packed(*packed);
    }

    /**
     * @brief Creates a second owned copy of this secret key.
     * @return Independent owned secret key with the same packed value.
     */
    [[nodiscard]] Result<SecretKey> clone() const {
        return from_packed(packed());
    }

    /**
     * @brief Exposes the packed secret for lower-level cryptographic operations.
     * @return Reference to the validated packed Purify secret.
     */
    [[nodiscard]] const UInt512& packed() const noexcept {
        return *packed_;
    }

    /**
     * @brief Compares two owned secrets by their packed values.
     * @param other Secret to compare against.
     * @return `true` when both secrets encode the same packed value.
     */
    [[nodiscard]] bool operator==(const SecretKey& other) const noexcept {
        return packed() == other.packed();
    }

private:
    explicit SecretKey(std::unique_ptr<UInt512, detail::SecureUInt512Deleter>&& packed) noexcept
        : packed_(std::move(packed)) {}

    std::unique_ptr<UInt512, detail::SecureUInt512Deleter> packed_;
};

}  // namespace purify
