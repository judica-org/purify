// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file api.hpp
 * @brief High-level Purify key generation, evaluation, witness generation, and circuit helpers.
 */

#pragma once

#include <array>
#include <concepts>
#include <span>
#include <type_traits>
#include <utility>

#include "purify/bulletproof.hpp"

namespace purify {

/** @brief Derived Purify keypair in packed integer form. */
struct GeneratedKey {
    UInt512 secret;
    UInt512 public_key;
};

/**
 * @brief Canonical BIP340 keypair derived deterministically from a packed Purify secret.
 *
 * `seckey` is normalized to the even-Y representative corresponding to `xonly_pubkey`, so the
 * returned pair is the canonical secp256k1/BIP340 encoding for this derivation.
 */
struct Bip340Key {
    std::array<unsigned char, 32> seckey;
    std::array<unsigned char, 32> xonly_pubkey;
};

/** @brief Complete witness bundle for evaluating and proving a Purify instance. */
struct BulletproofWitnessData {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
};

/** @brief Derives the packed public key corresponding to a packed secret. */
Result<GeneratedKey> derive_key(const UInt512& secret);

/**
 * @brief Derives a canonical BIP340 signing keypair from a packed Purify secret.
 *
 * The derivation is deterministic and domain-separated from the Purify public key derivation.
 */
Result<Bip340Key> derive_bip340_key(const UInt512& secret);

/** @brief Returns the size of the packed Purify secret-key space. */
inline UInt512 key_space_size() {
    return packed_secret_key_space_size();
}

/** @brief Callable concept for byte-fill RNG adapters that cannot fail. */
template <typename FillRandom>
concept NoexceptByteFill = requires(FillRandom&& fill, std::span<unsigned char> bytes) {
    { std::forward<FillRandom>(fill)(bytes) } noexcept -> std::same_as<void>;
};

/** @brief Callable concept for byte-fill RNG adapters that report failure via `Status`. */
template <typename FillRandom>
concept NoexceptCheckedByteFill = requires(FillRandom&& fill, std::span<unsigned char> bytes) {
    { std::forward<FillRandom>(fill)(bytes) } noexcept -> std::same_as<Status>;
};

/**
 * @brief Fills a buffer with operating-system randomness.
 * @param bytes Buffer to fill.
 * @return Success or `ErrorCode::EntropyUnavailable`.
 */
Status fill_secure_random(std::span<unsigned char> bytes) noexcept;

/**
 * @brief Samples a uniformly random packed secret below a range using a checked byte-fill source.
 * @param range Exclusive upper bound.
 * @param fill_random Callable with signature `Status(std::span<unsigned char>) noexcept`.
 * @return Random integer in `[0, range)`.
 */
template <typename FillRandom>
requires NoexceptCheckedByteFill<FillRandom>
Result<UInt512> random_below(const UInt512& range, FillRandom&& fill_random) {
    if (range.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation, "random_below:zero_range");
    }
    std::size_t bits = range.bit_length();
    std::size_t bytes_needed = (bits + 7) / 8;
    std::array<unsigned char, 64> bytes{};
    std::span<unsigned char> out(bytes.data(), bytes_needed);
    while (true) {
        Status status = std::forward<FillRandom>(fill_random)(out);
        if (!status.has_value()) {
            return unexpected_error(status.error(), "random_below:fill_random");
        }
        UInt512 candidate = UInt512::from_bytes_be(bytes.data(), bytes_needed);
        candidate.mask_bits(bits);
        if (candidate.compare(range) < 0) {
            return candidate;
        }
    }
}

/**
 * @brief Samples a uniformly random packed secret below a range using a no-fail byte-fill source.
 * @param range Exclusive upper bound.
 * @param fill_random Callable with signature `void(std::span<unsigned char>) noexcept`.
 * @return Random integer in `[0, range)`.
 */
template <typename FillRandom>
requires NoexceptByteFill<FillRandom>
Result<UInt512> random_below(const UInt512& range, FillRandom&& fill_random) {
    if (range.is_zero()) {
        return unexpected_error(ErrorCode::RangeViolation, "random_below:zero_range");
    }
    std::size_t bits = range.bit_length();
    std::size_t bytes_needed = (bits + 7) / 8;
    std::array<unsigned char, 64> bytes{};
    std::span<unsigned char> out(bytes.data(), bytes_needed);
    while (true) {
        std::forward<FillRandom>(fill_random)(out);
        UInt512 candidate = UInt512::from_bytes_be(bytes.data(), bytes_needed);
        candidate.mask_bits(bits);
        if (candidate.compare(range) < 0) {
            return candidate;
        }
    }
}

/**
 * @brief Samples a uniformly random packed secret below a range using the built-in OS RNG.
 * @param range Exclusive upper bound.
 * @return Random integer in `[0, range)`.
 */
Result<UInt512> random_below(const UInt512& range);

/**
 * @brief Generates a random Purify keypair using the built-in OS RNG.
 * @return Generated keypair bundle.
 */
Result<GeneratedKey> generate_key();

/**
 * @brief Deterministically derives a Purify keypair from seed material.
 * @param seed Arbitrary seed bytes.
 * @return Generated keypair bundle.
 */
Result<GeneratedKey> generate_key(std::span<const unsigned char> seed);

/**
 * @brief Generates a random Purify keypair using a caller-supplied byte-fill routine.
 * @param fill_random Callable that fills the supplied byte span.
 * @return Generated keypair bundle.
 */
template <typename FillRandom>
requires(NoexceptByteFill<FillRandom> || NoexceptCheckedByteFill<FillRandom>)
Result<GeneratedKey> generate_key(FillRandom&& fill_random) {
    Result<UInt512> secret = random_below(key_space_size(), std::forward<FillRandom>(fill_random));
    if (!secret.has_value()) {
        return unexpected_error(secret.error(), "generate_key:random_below_custom");
    }
    return derive_key(*secret);
}

/**
 * @brief Evaluates the Purify PRF for a packed secret and message.
 * @param secret Packed secret scalar pair.
 * @param message Message bytes to evaluate.
 * @return Purify output as a field element, or `ErrorCode::HashToCurveExhausted`.
 */
Result<FieldElement> eval(const UInt512& secret, const Bytes& message);

/**
 * @brief Builds the legacy serialized verifier description for a message and public key.
 * @param message Message bytes baked into the verifier.
 * @param pubkey Packed public key.
 * @return Serialized verifier program, or `ErrorCode::HashToCurveExhausted`.
 */
Result<std::string> verifier(const Bytes& message, const UInt512& pubkey);

/**
 * @brief Builds the native verifier circuit for a message and public key.
 * @param message Message bytes baked into the circuit.
 * @param pubkey Packed public key.
 * @return Native circuit object ready for evaluation or proving, or `ErrorCode::HashToCurveExhausted`.
 */
Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey);

/**
 * @brief Computes the native Purify witness for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Witness bundle containing public key, output, and assignment columns, or `ErrorCode::HashToCurveExhausted`.
 */
Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const UInt512& secret);

/**
 * @brief Evaluates the generated verifier circuit against an explicit witness.
 * @param message Message baked into the verifier circuit.
 * @param witness Witness bundle to validate.
 * @return True when the witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
Result<bool> evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness);

/**
 * @brief Evaluates the generated verifier circuit using a witness derived from a secret.
 * @param message Message baked into the verifier circuit.
 * @param secret Packed secret scalar pair.
 * @return True when the derived witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
Result<bool> evaluate_verifier_circuit(const Bytes& message, const UInt512& secret);

/**
 * @brief Serializes the witness assignment produced for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Serialized witness blob compatible with the legacy assignment format, or `ErrorCode::HashToCurveExhausted`.
 */
Result<Bytes> prove_assignment(const Bytes& message, const UInt512& secret);

}  // namespace purify
