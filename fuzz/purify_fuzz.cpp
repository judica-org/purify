// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>

#include "purify.hpp"
#include "purify/bppp.hpp"

namespace {

using purify::Bytes;
using purify::GeneratedKey;
using purify::NativeBulletproofCircuit;
using purify::Result;

struct SplitMix64 {
    std::uint64_t state;

    explicit SplitMix64(std::uint64_t seed) : state(seed) {}

    std::uint64_t next_u64() {
        std::uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    std::size_t bounded(std::size_t upper_bound) {
        return upper_bound == 0 ? 0 : static_cast<std::size_t>(next_u64() % upper_bound);
    }

    unsigned char next_byte() {
        return static_cast<unsigned char>(next_u64() & 0xffU);
    }
};

struct FuzzConfig {
    std::uint64_t seed = 1;
    std::size_t iterations = 8;
    std::size_t max_message_bytes = 64;
    std::size_t proof_every = 4;
};

bool parse_u64(std::string_view text, std::uint64_t& out) {
    auto result = std::from_chars(text.data(), text.data() + text.size(), out);
    return result.ec == std::errc() && result.ptr == text.data() + text.size();
}

bool parse_size(std::string_view text, std::size_t& out) {
    std::uint64_t parsed = 0;
    if (!parse_u64(text, parsed)) {
        return false;
    }
    out = static_cast<std::size_t>(parsed);
    return true;
}

std::optional<FuzzConfig> parse_args(int argc, char** argv, int& exit_code) {
    exit_code = -1;
    FuzzConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto consume_value = [&](const char* name, std::string_view& value) {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                exit_code = 1;
                return false;
            }
            value = argv[++i];
            return true;
        };

        if (arg == "--seed") {
            std::string_view value;
            if (!consume_value("--seed", value) || !parse_u64(value, config.seed)) {
                std::cerr << "Invalid value for --seed\n";
                exit_code = 1;
                return std::nullopt;
            }
        } else if (arg == "--iterations") {
            std::string_view value;
            if (!consume_value("--iterations", value) || !parse_size(value, config.iterations)) {
                std::cerr << "Invalid value for --iterations\n";
                exit_code = 1;
                return std::nullopt;
            }
        } else if (arg == "--max-message-bytes") {
            std::string_view value;
            if (!consume_value("--max-message-bytes", value) || !parse_size(value, config.max_message_bytes)) {
                std::cerr << "Invalid value for --max-message-bytes\n";
                exit_code = 1;
                return std::nullopt;
            }
        } else if (arg == "--proof-every") {
            std::string_view value;
            if (!consume_value("--proof-every", value) || !parse_size(value, config.proof_every)) {
                std::cerr << "Invalid value for --proof-every\n";
                exit_code = 1;
                return std::nullopt;
            }
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0]
                      << " [--seed N] [--iterations N] [--max-message-bytes N] [--proof-every N]\n";
            exit_code = 0;
            return std::nullopt;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            exit_code = 1;
            return std::nullopt;
        }
    }

    return config;
}

Bytes random_bytes(SplitMix64& rng, std::size_t min_size, std::size_t max_size) {
    const std::size_t width = max_size >= min_size ? (max_size - min_size + 1) : 1;
    const std::size_t size = min_size + rng.bounded(width);
    Bytes out(size);
    for (unsigned char& byte : out) {
        byte = rng.next_byte();
    }
    return out;
}

template <std::size_t N>
std::array<unsigned char, N> random_array(SplitMix64& rng) {
    std::array<unsigned char, N> out{};
    for (unsigned char& byte : out) {
        byte = rng.next_byte();
    }
    return out;
}

Result<GeneratedKey> random_key(SplitMix64& rng) {
    Bytes seed = random_bytes(rng, 16, 64);
    return purify::generate_key(seed);
}

template <typename T>
bool require_result(const Result<T>& result, const char* step, std::size_t iteration, std::uint64_t case_seed) {
    if (result.has_value()) {
        return true;
    }
    std::cerr << "fuzz failure"
              << " iteration=" << iteration
              << " case_seed=" << case_seed
              << " step=" << step
              << " error=" << result.error().name()
              << "\n";
    return false;
}

bool require_true(const Result<bool>& result, const char* step, std::size_t iteration, std::uint64_t case_seed) {
    if (!require_result(result, step, iteration, case_seed)) {
        return false;
    }
    if (*result) {
        return true;
    }
    std::cerr << "fuzz failure"
              << " iteration=" << iteration
              << " case_seed=" << case_seed
              << " step=" << step
              << " error=false_result\n";
    return false;
}

bool run_iteration(const FuzzConfig& config,
                   purify_secp_context* secp_context,
                   std::size_t iteration,
                   std::uint64_t case_seed) {
    SplitMix64 rng(case_seed);

    Bytes short_seed = random_bytes(rng, 0, 15);
    Result<GeneratedKey> short_seed_key = purify::generate_key(short_seed);
    if (short_seed_key.has_value() || short_seed_key.error().code != purify::ErrorCode::RangeViolation) {
        std::cerr << "fuzz failure iteration=" << iteration
                  << " case_seed=" << case_seed
                  << " step=short_seed_rejection\n";
        return false;
    }

    Result<GeneratedKey> key = random_key(rng);
    if (!require_result(key, "generate_key", iteration, case_seed)) {
        return false;
    }

    Bytes message = random_bytes(rng, 0, config.max_message_bytes);
    Bytes topic = random_bytes(rng, 1, config.max_message_bytes == 0 ? 1 : config.max_message_bytes);

    Result<purify::FieldElement> value = purify::eval(key->secret, message);
    if (!require_result(value, "eval", iteration, case_seed)) {
        return false;
    }

    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, key->secret);
    if (!require_result(witness, "prove_assignment_data", iteration, case_seed)) {
        return false;
    }
    if (witness->public_key != key->public_key || witness->output != *value) {
        std::cerr << "fuzz failure iteration=" << iteration
                  << " case_seed=" << case_seed
                  << " step=witness_consistency\n";
        return false;
    }

    Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(message, key->public_key);
    if (!require_result(circuit, "verifier_circuit", iteration, case_seed)) {
        return false;
    }
    if (!circuit->evaluate(witness->assignment)) {
        std::cerr << "fuzz failure iteration=" << iteration
                  << " case_seed=" << case_seed
                  << " step=native_circuit_evaluate\n";
        return false;
    }
    if (!require_true(purify::evaluate_verifier_circuit(message, *witness), "evaluate_verifier_circuit", iteration, case_seed)) {
        return false;
    }

    Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(key->secret, secp_context);
    if (!require_result(key_pair, "KeyPair::from_secret", iteration, case_seed)) {
        return false;
    }
    const purify::puresign::PublicKey& public_key = key_pair->public_key();

    Result<purify::puresign::Signature> signature = key_pair->sign_message(message, secp_context);
    if (!require_result(signature, "KeyPair::sign_message", iteration, case_seed)) {
        return false;
    }
    if (!require_true(public_key.verify_signature(message, *signature, secp_context),
                      "PublicKey::verify_signature", iteration, case_seed)) {
        return false;
    }

    const bool do_proof = config.proof_every != 0 && (iteration % config.proof_every == 0);
    if (!do_proof) {
        return true;
    }

    Result<purify::puresign::ProvenSignature> proven = key_pair->sign_message_with_proof(message, secp_context);
    if (!require_result(proven, "KeyPair::sign_message_with_proof", iteration, case_seed)) {
        return false;
    }
    if (!require_true(public_key.verify_message_signature_with_proof(message, *proven, secp_context),
                      "PublicKey::verify_message_signature_with_proof", iteration, case_seed)) {
        return false;
    }
    Result<bool> wrong_message =
        public_key.verify_message_signature_with_proof(random_bytes(rng, 1, 16), *proven, secp_context);
    if (!require_result(wrong_message,
                        "PublicKey::verify_message_signature_with_proof_wrong_message",
                        iteration, case_seed)) {
        return false;
    }
    if (*wrong_message) {
        std::cerr << "fuzz failure iteration=" << iteration
                  << " case_seed=" << case_seed
                  << " step=wrong_message_accepted\n";
        return false;
    }

    Result<purify::puresign::ProvenSignature> topic_signature =
        key_pair->sign_with_topic_proof(message, topic, secp_context);
    if (!require_result(topic_signature, "KeyPair::sign_with_topic_proof", iteration, case_seed)) {
        return false;
    }
    if (!require_true(public_key.verify_topic_signature_with_proof(message, topic, *topic_signature, secp_context),
                      "PublicKey::verify_topic_signature_with_proof", iteration, case_seed)) {
        return false;
    }
    Result<bool> wrong_topic =
        public_key.verify_topic_signature_with_proof(message, random_bytes(rng, 1, 16), *topic_signature,
                                                     secp_context);
    if (!require_result(wrong_topic,
                        "PublicKey::verify_topic_signature_with_proof_wrong_topic",
                        iteration, case_seed)) {
        return false;
    }
    if (*wrong_topic) {
        std::cerr << "fuzz failure iteration=" << iteration
                  << " case_seed=" << case_seed
                  << " step=wrong_topic_accepted\n";
        return false;
    }

    std::array<unsigned char, 32> nonce = random_array<32>(rng);
    Bytes binding = random_bytes(rng, 0, 24);
    Result<purify::ExperimentalBulletproofProof> proof =
        purify::prove_experimental_circuit(*circuit, witness->assignment, nonce,
                                           purify::bppp::base_generator(secp_context), secp_context, binding);
    if (!require_result(proof, "prove_experimental_circuit", iteration, case_seed)) {
        return false;
    }
    if (!require_true(purify::verify_experimental_circuit(*circuit, *proof,
                                                          purify::bppp::base_generator(secp_context),
                                                          secp_context, binding),
                      "verify_experimental_circuit", iteration, case_seed)) {
        return false;
    }

    return true;
}

}  // namespace

int main(int argc, char** argv) {
    int parse_exit_code = -1;
    std::optional<FuzzConfig> config = parse_args(argc, argv, parse_exit_code);
    if (!config.has_value()) {
        return parse_exit_code < 0 ? 1 : parse_exit_code;
    }

    purify::SecpContextPtr secp_context = purify::make_secp_context();
    if (secp_context == nullptr) {
        std::cerr << "failed to create secp context\n";
        return 1;
    }

    SplitMix64 master(config->seed);
    for (std::size_t iteration = 0; iteration < config->iterations; ++iteration) {
        std::uint64_t case_seed = master.next_u64();
        if (!run_iteration(*config, secp_context.get(), iteration, case_seed)) {
            return 1;
        }
    }

    std::cout << "fuzz harness completed"
              << " seed=" << config->seed
              << " iterations=" << config->iterations
              << " proof_every=" << config->proof_every
              << "\n";
    return 0;
}
