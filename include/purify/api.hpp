// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file api.hpp
 * @brief High-level Purify key generation, evaluation, witness generation, and circuit helpers.
 */

#pragma once

#include <cerrno>
#include <concepts>
#include <cstdlib>
#include <fstream>
#include <span>
#include <type_traits>

#if defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <unistd.h>
#else
#include <unistd.h>
#endif

#include "purify/bulletproof.hpp"

namespace purify {

/** @brief Derived Purify keypair in packed integer form. */
struct GeneratedKey {
    UInt512 secret;
    UInt512 public_key;
};

/** @brief Complete witness bundle for evaluating and proving a Purify instance. */
struct BulletproofWitnessData {
    UInt512 public_key;
    FieldElement output;
    BulletproofAssignmentData assignment;
};

/** @brief Derives the packed public key corresponding to a packed secret. */
inline Result<GeneratedKey> derive_key(const UInt512& secret);

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
inline Status fill_secure_random(std::span<unsigned char> bytes) noexcept {
#if defined(_WIN32)
    unsigned char* out = bytes.data();
    std::size_t size = bytes.size();
    while (size != 0) {
        ULONG chunk = static_cast<ULONG>(std::min<std::size_t>(size, static_cast<std::size_t>(0xFFFFFFFFu)));
        NTSTATUS status = BCryptGenRandom(nullptr, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:bcrypt");
        }
        out += chunk;
        size -= chunk;
    }
    return {};
#elif defined(__linux__)
    unsigned char* out = bytes.data();
    std::size_t size = bytes.size();
    while (size != 0) {
        ssize_t written = getrandom(out, size, 0);
        if (written > 0) {
            out += static_cast<std::size_t>(written);
            size -= static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:getrandom");
    }
    return {};
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    arc4random_buf(bytes.data(), bytes.size());
    return {};
#else
    std::ifstream file("/dev/urandom", std::ios::binary);
    if (!file) {
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:open_urandom");
    }
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        return unexpected_error(ErrorCode::EntropyUnavailable, "fill_secure_random:read_urandom");
    }
    return {};
#endif
}

/**
 * @brief Samples a uniformly random packed secret below a range using a checked byte-fill source.
 * @param range Exclusive upper bound.
 * @param fill_random Callable with signature `Status(std::span<unsigned char>) noexcept`.
 * @return Random integer in `[0, range)`.
 */
template <typename FillRandom>
requires NoexceptCheckedByteFill<FillRandom>
inline Result<UInt512> random_below(const UInt512& range, FillRandom&& fill_random) {
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
inline Result<UInt512> random_below(const UInt512& range, FillRandom&& fill_random) {
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
inline Result<UInt512> random_below(const UInt512& range) {
    return random_below(range, fill_secure_random);
}

/**
 * @brief Generates a random Purify keypair using the built-in OS RNG.
 * @return Generated keypair bundle.
 */
inline Result<GeneratedKey> generate_key() {
    Result<UInt512> secret = random_below(key_space_size());
    if (!secret.has_value()) {
        return unexpected_error(secret.error(), "generate_key:random_below");
    }
    return derive_key(*secret);
}

/**
 * @brief Deterministically derives a Purify keypair from seed material.
 * @param seed Arbitrary seed bytes.
 * @return Generated keypair bundle.
 */
inline Result<GeneratedKey> generate_key(std::span<const unsigned char> seed) {
    if (seed.empty()) {
        return unexpected_error(ErrorCode::EmptyInput, "generate_key:empty_seed");
    }
    Bytes seed_bytes(seed.begin(), seed.end());
    std::optional<UInt512> secret = hash_to_int<8>(seed_bytes, key_space_size(), bytes_from_ascii("Purify/KeyGen"));
    if (!secret.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "generate_key:hash_to_int_seed");
    }
    return derive_key(*secret);
}

/**
 * @brief Generates a random Purify keypair using a caller-supplied byte-fill routine.
 * @param fill_random Callable that fills the supplied byte span.
 * @return Generated keypair bundle.
 */
template <typename FillRandom>
requires(NoexceptByteFill<FillRandom> || NoexceptCheckedByteFill<FillRandom>)
inline Result<GeneratedKey> generate_key(FillRandom&& fill_random) {
    Result<UInt512> secret = random_below(key_space_size(), std::forward<FillRandom>(fill_random));
    if (!secret.has_value()) {
        return unexpected_error(secret.error(), "generate_key:random_below_custom");
    }
    return derive_key(*secret);
}

/**
 * @brief Derives the packed public key corresponding to a packed secret.
 * @param secret Packed secret scalar pair.
 * @return Derived keypair bundle.
 */
inline Result<GeneratedKey> derive_key(const UInt512& secret) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "derive_key:unpack_secret");
    }
    Result<AffinePoint> p1 = curve1().mul_secret_affine(generator1(), unpacked->first);
    if (!p1.has_value()) {
        return unexpected_error(p1.error(), "derive_key:mul_secret_affine_p1");
    }
    Result<AffinePoint> p2 = curve2().mul_secret_affine(generator2(), unpacked->second);
    if (!p2.has_value()) {
        return unexpected_error(p2.error(), "derive_key:mul_secret_affine_p2");
    }
    return GeneratedKey{secret, pack_public(p1->x.to_uint256(), p2->x.to_uint256())};
}

/**
 * @brief Evaluates the Purify PRF for a packed secret and message.
 * @param secret Packed secret scalar pair.
 * @param message Message bytes to evaluate.
 * @return Purify output as a field element, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<FieldElement> eval(const UInt512& secret, const Bytes& message) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "eval:unpack_secret");
    }
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "eval:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "eval:hash_to_curve_m2");
    }
    Result<AffinePoint> q1 = curve1().mul_secret_affine(*m1, unpacked->first);
    if (!q1.has_value()) {
        return unexpected_error(q1.error(), "eval:mul_secret_affine_q1");
    }
    Result<AffinePoint> q2 = curve2().mul_secret_affine(*m2, unpacked->second);
    if (!q2.has_value()) {
        return unexpected_error(q2.error(), "eval:mul_secret_affine_q2");
    }
    return combine(q1->x, q2->x);
}

/**
 * @brief Builds the legacy serialized verifier description for a message and public key.
 * @param message Message bytes baked into the verifier.
 * @param pubkey Packed public key.
 * @return Serialized verifier program, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<std::string> verifier(const Bytes& message, const UInt512& pubkey) {
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier:hash_to_curve_m2");
    }
    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "verifier:circuit_main");
    }
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "verifier:from_transcript");
    }
    Status pubkey_status = bp.add_pubkey_and_out(pubkey, result->p1x, result->p2x, result->out);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "verifier:add_pubkey_and_out");
    }
    return bp.to_string();
}

/**
 * @brief Builds the native verifier circuit for a message and public key.
 * @param message Message bytes baked into the circuit.
 * @param pubkey Packed public key.
 * @return Native circuit object ready for evaluation or proving, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<NativeBulletproofCircuit> verifier_circuit(const Bytes& message, const UInt512& pubkey) {
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "verifier_circuit:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "verifier_circuit:hash_to_curve_m2");
    }
    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "verifier_circuit:circuit_main");
    }
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "verifier_circuit:from_transcript");
    }
    Status pubkey_status = bp.add_pubkey_and_out(pubkey, result->p1x, result->p2x, result->out);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "verifier_circuit:add_pubkey_and_out");
    }
    return bp.native_circuit();
}

/**
 * @brief Computes the native Purify witness for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Witness bundle containing public key, output, and assignment columns, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<BulletproofWitnessData> prove_assignment_data(const Bytes& message, const UInt512& secret) {
    Result<std::pair<UInt256, UInt256>> unpacked = unpack_secret(secret);
    if (!unpacked.has_value()) {
        return unexpected_error(unpacked.error(), "prove_assignment_data:unpack_secret");
    }
    Result<JacobianPoint> m1 = hash_to_curve(bytes_from_ascii("Eval/1/") + message, curve1());
    if (!m1.has_value()) {
        return unexpected_error(m1.error(), "prove_assignment_data:hash_to_curve_m1");
    }
    Result<JacobianPoint> m2 = hash_to_curve(bytes_from_ascii("Eval/2/") + message, curve2());
    if (!m2.has_value()) {
        return unexpected_error(m2.error(), "prove_assignment_data:hash_to_curve_m2");
    }
    Result<AffinePoint> p1 = curve1().mul_secret_affine(generator1(), unpacked->first);
    if (!p1.has_value()) {
        return unexpected_error(p1.error(), "prove_assignment_data:mul_secret_affine_p1");
    }
    Result<AffinePoint> p2 = curve2().mul_secret_affine(generator2(), unpacked->second);
    if (!p2.has_value()) {
        return unexpected_error(p2.error(), "prove_assignment_data:mul_secret_affine_p2");
    }
    Result<AffinePoint> q1 = curve1().mul_secret_affine(*m1, unpacked->first);
    if (!q1.has_value()) {
        return unexpected_error(q1.error(), "prove_assignment_data:mul_secret_affine_q1");
    }
    Result<AffinePoint> q2 = curve2().mul_secret_affine(*m2, unpacked->second);
    if (!q2.has_value()) {
        return unexpected_error(q2.error(), "prove_assignment_data:mul_secret_affine_q2");
    }
    FieldElement native_out = combine(q1->x, q2->x);

    Transcript transcript;
    Result<CircuitMainResult> result = circuit_main(transcript, *m1, *m2, unpacked->first, unpacked->second);
    if (!result.has_value()) {
        return unexpected_error(result.error(), "prove_assignment_data:circuit_main");
    }
    if (transcript.evaluate(result->p1x) != std::optional<FieldElement>(p1->x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p1x_mismatch");
    }
    if (transcript.evaluate(result->p2x) != std::optional<FieldElement>(p2->x)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:p2x_mismatch");
    }
    if (transcript.evaluate(result->out) != std::optional<FieldElement>(native_out)) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:output_mismatch");
    }

    UInt512 pubkey = pack_public(p1->x.to_uint256(), p2->x.to_uint256());
    BulletproofTranscript bp;
    Status transcript_status = bp.from_transcript(transcript, result->n_bits);
    if (!transcript_status.has_value()) {
        return unexpected_error(transcript_status.error(), "prove_assignment_data:from_transcript");
    }
    Status pubkey_status = bp.add_pubkey_and_out(pubkey, result->p1x, result->p2x, result->out);
    if (!pubkey_status.has_value()) {
        return unexpected_error(pubkey_status.error(), "prove_assignment_data:add_pubkey_and_out");
    }
    if (!bp.evaluate(transcript.varmap(), native_out)) {
        return unexpected_error(ErrorCode::TranscriptCheckFailed, "prove_assignment_data:transcript_check");
    }

    auto vars = transcript.varmap();
    auto it = vars.find("V0");
    if (it == vars.end()) {
        vars.insert({"V0", native_out});
    } else {
        vars["V0"] = native_out;
    }
    Result<BulletproofAssignmentData> assignment = bp.assignment_data(vars);
    assert(assignment.has_value() && "prove_assignment_data() should materialize a complete assignment");
    if (!assignment.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment_data:assignment_data");
    }
    return BulletproofWitnessData{pubkey, native_out, std::move(*assignment)};
}

/**
 * @brief Evaluates the generated verifier circuit against an explicit witness.
 * @param message Message baked into the verifier circuit.
 * @param witness Witness bundle to validate.
 * @return True when the witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<bool> evaluate_verifier_circuit(const Bytes& message, const BulletproofWitnessData& witness) {
    Result<NativeBulletproofCircuit> circuit = verifier_circuit(message, witness.public_key);
    if (!circuit.has_value()) {
        return unexpected_error(circuit.error(), "evaluate_verifier_circuit:verifier_circuit");
    }
    return circuit->evaluate(witness.assignment);
}

/**
 * @brief Evaluates the generated verifier circuit using a witness derived from a secret.
 * @param message Message baked into the verifier circuit.
 * @param secret Packed secret scalar pair.
 * @return True when the derived witness satisfies the circuit, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<bool> evaluate_verifier_circuit(const Bytes& message, const UInt512& secret) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "evaluate_verifier_circuit:prove_assignment_data");
    }
    return evaluate_verifier_circuit(message, *witness);
}

/**
 * @brief Serializes the witness assignment produced for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @return Serialized witness blob compatible with the legacy assignment format, or `ErrorCode::HashToCurveExhausted`.
 */
inline Result<Bytes> prove_assignment(const Bytes& message, const UInt512& secret) {
    Result<BulletproofWitnessData> witness = prove_assignment_data(message, secret);
    if (!witness.has_value()) {
        return unexpected_error(witness.error(), "prove_assignment:prove_assignment_data");
    }
    Result<Bytes> serialized = witness->assignment.serialize();
    assert(serialized.has_value() && "prove_assignment() should serialize a well-formed assignment");
    if (!serialized.has_value()) {
        return unexpected_error(ErrorCode::InternalMismatch, "prove_assignment:serialize_assignment");
    }
    return serialized;
}

}  // namespace purify
